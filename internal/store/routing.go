package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

// RoutingRules select which changes a destination receives. The zero value
// routes every change, which is also how destinations created before schema
// v14 are migrated. System notifications (collector health and release
// updates) are not changes and always reach every enabled destination.
type RoutingRules struct {
	// MinSeverity is the lowest severity delivered; empty means low (all).
	MinSeverity model.Severity
	// IncludeCollectors limits delivery to these collectors; empty means all.
	IncludeCollectors []string
	// ExcludeCollectors never delivers these collectors.
	ExcludeCollectors []string
	// ChangeKinds limits delivery to created, changed, or removed; empty
	// means all kinds.
	ChangeKinds []string
}

var (
	routingCollectorPattern = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)
	routingChangeKinds      = map[string]struct{}{"created": {}, "changed": {}, "removed": {}}
)

// NormalizeRoutingRules validates rules and returns them in canonical form:
// sorted, de-duplicated lists and an empty minimum severity for "low".
func NormalizeRoutingRules(rules RoutingRules) (RoutingRules, error) {
	out := RoutingRules{}
	if strings.TrimSpace(string(rules.MinSeverity)) != "" {
		severity, ok := model.ParseSeverity(string(rules.MinSeverity))
		if !ok {
			return RoutingRules{}, fmt.Errorf("unknown minimum severity %q", rules.MinSeverity)
		}
		if severity != model.SeverityLow {
			out.MinSeverity = severity
		}
	}
	var err error
	if out.IncludeCollectors, err = normalizeRoutingList(rules.IncludeCollectors, "collector", func(value string) bool { return routingCollectorPattern.MatchString(value) }); err != nil {
		return RoutingRules{}, err
	}
	if out.ExcludeCollectors, err = normalizeRoutingList(rules.ExcludeCollectors, "collector", func(value string) bool { return routingCollectorPattern.MatchString(value) }); err != nil {
		return RoutingRules{}, err
	}
	if out.ChangeKinds, err = normalizeRoutingList(rules.ChangeKinds, "change kind", func(value string) bool {
		_, ok := routingChangeKinds[value]
		return ok
	}); err != nil {
		return RoutingRules{}, err
	}
	if len(out.ChangeKinds) == len(routingChangeKinds) {
		out.ChangeKinds = nil
	}
	return out, nil
}

func normalizeRoutingList(values []string, label string, valid func(string) bool) ([]string, error) {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if !valid(value) {
			return nil, fmt.Errorf("invalid %s %q", label, value)
		}
		seen[value] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

// AllChanges reports whether the rules route every change.
func (r RoutingRules) AllChanges() bool {
	return (r.MinSeverity == "" || r.MinSeverity == model.SeverityLow) && len(r.IncludeCollectors) == 0 && len(r.ExcludeCollectors) == 0 && len(r.ChangeKinds) == 0
}

// Matches reports whether a change with the given severity is routed.
func (r RoutingRules) Matches(change model.Change, severity model.Severity) bool {
	if r.MinSeverity != "" && !severity.AtLeast(r.MinSeverity) {
		return false
	}
	if len(r.IncludeCollectors) > 0 && !containsString(r.IncludeCollectors, change.Collector) {
		return false
	}
	if containsString(r.ExcludeCollectors, change.Collector) {
		return false
	}
	if len(r.ChangeKinds) > 0 && !containsString(r.ChangeKinds, change.Kind) {
		return false
	}
	return true
}

// key identifies a rule set so destinations sharing one render one digest.
func (r RoutingRules) key() string {
	return string(r.MinSeverity) + "|" + strings.Join(r.IncludeCollectors, ",") + "|" + strings.Join(r.ExcludeCollectors, ",") + "|" + strings.Join(r.ChangeKinds, ",")
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func joinRoutingList(values []string) string { return strings.Join(values, ",") }

func splitRoutingList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
}

// routingFromColumns rebuilds rules from their stored columns. Stored values
// are re-normalized so a hand-edited row cannot widen or break routing.
func routingFromColumns(minSeverity, include, exclude, kinds string) RoutingRules {
	rules, err := NormalizeRoutingRules(RoutingRules{
		MinSeverity:       model.Severity(minSeverity),
		IncludeCollectors: splitRoutingList(include),
		ExcludeCollectors: splitRoutingList(exclude),
		ChangeKinds:       splitRoutingList(kinds),
	})
	if err != nil {
		// Fail closed to the documented default rather than silently dropping
		// every change for a destination whose row cannot be interpreted.
		return RoutingRules{}
	}
	return rules
}

type routedDestination struct {
	id    int64
	rules RoutingRules
}

// enqueueDigestTx fans one change batch out to every enabled destination.
// Destinations that share a rule set share one rendered digest; a destination
// whose rules match none of the changes receives nothing.
func enqueueDigestTx(ctx context.Context, tx *sql.Tx, digest notify.DigestFunc, input notify.DigestInput, severities []model.Severity, now string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,route_min_severity,route_include_collectors,route_exclude_collectors,route_change_kinds
		FROM notification_destinations WHERE enabled=1 AND deleted_at IS NULL ORDER BY id`)
	if err != nil {
		return err
	}
	var destinations []routedDestination
	for rows.Next() {
		var destination routedDestination
		var minSeverity, include, exclude, kinds string
		if err := rows.Scan(&destination.id, &minSeverity, &include, &exclude, &kinds); err != nil {
			rows.Close()
			return err
		}
		destination.rules = routingFromColumns(minSeverity, include, exclude, kinds)
		destinations = append(destinations, destination)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	payloads := map[string]string{}
	for _, destination := range destinations {
		key := destination.rules.key()
		payload, rendered := payloads[key]
		if !rendered {
			filtered := input
			filtered.Changes = make([]model.Change, 0, len(input.Changes))
			for index, change := range input.Changes {
				if destination.rules.Matches(change, severities[index]) {
					filtered.Changes = append(filtered.Changes, change)
				}
			}
			if len(filtered.Changes) > 0 {
				payload = notify.Markdown(digest(filtered))
			}
			payloads[key] = payload
		}
		if payload == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO outbox(batch_id,destination_id,payload,status,next_attempt,first_attempt,created_at) VALUES(?,?,?,'pending',?,?,?)", input.BatchID, destination.id, payload, now, now, now); err != nil {
			return err
		}
	}
	return nil
}

// SetDestinationRouting replaces the routing rules of an active destination.
func (s *Store) SetDestinationRouting(ctx context.Context, id int64, rules RoutingRules) error {
	rules, err := NormalizeRoutingRules(rules)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE notification_destinations
		SET route_min_severity=?,route_include_collectors=?,route_exclude_collectors=?,route_change_kinds=?,updated_at=?
		WHERE id=? AND deleted_at IS NULL`, string(rules.MinSeverity), joinRoutingList(rules.IncludeCollectors), joinRoutingList(rules.ExcludeCollectors), joinRoutingList(rules.ChangeKinds), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("notification destination not found")
	}
	return nil
}
