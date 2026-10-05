package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/crypt0rr/tailstate/internal/model"
)

// Mute rule kinds. A muted change is still recorded in History and the
// signed evidence ledger, flagged as muted, but is left out of digests.
const (
	MuteCollector = "collector" // every change of one collector
	MuteField     = "field"     // one field path of one collector, e.g. devices.clientVersion
	MuteTag       = "tag"       // every change of a resource carrying a tag, e.g. tag:ci
	MuteResource  = "resource"  // one resource, by ID or exact name
)

// MaxMuteRules bounds the rule set evaluated inside every batch transaction.
const MaxMuteRules = 200

// ErrMuteRuleExists is returned when an identical rule already exists.
var ErrMuteRuleExists = errors.New("mute rule already exists")

// ErrInvalidMuteRule wraps every validation failure; its message is safe to
// show to the administrator.
var ErrInvalidMuteRule = errors.New("invalid mute rule")

func invalidMuteRule(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidMuteRule, fmt.Sprintf(format, args...))
}

// MuteRule is one administrator-managed noise control.
type MuteRule struct {
	ID        int64
	Kind      string
	Value     string
	CreatedAt time.Time
}

var muteCollectorPattern = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)

// NormalizeMuteRule validates a rule and returns its canonical value.
func NormalizeMuteRule(kind, value string) (string, string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", invalidMuteRule("a value is required")
	}
	if len(value) > 256 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", "", invalidMuteRule("the value must be at most 256 printable bytes")
	}
	switch kind {
	case MuteCollector:
		value = strings.ToLower(value)
		if !muteCollectorPattern.MatchString(value) {
			return "", "", invalidMuteRule("collector %q is not valid", value)
		}
	case MuteField:
		collector, path, found := strings.Cut(value, ".")
		collector = strings.ToLower(collector)
		path = strings.Trim(path, ".")
		if !found || !muteCollectorPattern.MatchString(collector) || path == "" || strings.ContainsAny(path, " \t") {
			return "", "", invalidMuteRule("field rules use collector.field, for example devices.clientVersion")
		}
		value = collector + "." + path
	case MuteTag:
		if !strings.HasPrefix(strings.ToLower(value), "tag:") || len(value) <= len("tag:") || strings.ContainsAny(value, " \t,") {
			return "", "", invalidMuteRule("tag rules use a tag such as tag:ci")
		}
		value = strings.ToLower(value)
	case MuteResource:
	default:
		return "", "", invalidMuteRule("unknown kind %q", kind)
	}
	return kind, value, nil
}

// ListMuteRules returns every mute rule in creation order.
func (s *Store) ListMuteRules(ctx context.Context) ([]MuteRule, error) {
	return listMuteRules(ctx, s.db)
}

type muteQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func listMuteRules(ctx context.Context, db muteQueryer) ([]MuteRule, error) {
	rows, err := db.QueryContext(ctx, "SELECT id,kind,value,created_at FROM mute_rules ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MuteRule
	for rows.Next() {
		var rule MuteRule
		var created string
		if err := rows.Scan(&rule.ID, &rule.Kind, &rule.Value, &created); err != nil {
			return nil, err
		}
		rule.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, fmt.Errorf("parse mute rule timestamp: %w", err)
		}
		out = append(out, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, rows.Close()
}

// AddMuteRule validates and stores a mute rule. It applies to batches
// recorded after it is added; History is never rewritten.
func (s *Store) AddMuteRule(ctx context.Context, kind, value string) (int64, error) {
	kind, value, err := NormalizeMuteRule(kind, value)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var count, existing int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(kind=? AND value=?),0) FROM mute_rules", kind, value).Scan(&count, &existing); err != nil {
		return 0, err
	}
	if existing > 0 {
		return 0, ErrMuteRuleExists
	}
	if count >= MaxMuteRules {
		return 0, invalidMuteRule("at most %d mute rules are supported", MaxMuteRules)
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO mute_rules(kind,value,created_at) VALUES(?,?,?)", kind, value, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// DeleteMuteRule removes a mute rule.
func (s *Store) DeleteMuteRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM mute_rules WHERE id=?", id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("mute rule not found")
	}
	return nil
}

// muteSet evaluates mute rules against recorded changes.
type muteSet struct {
	collectors map[string]struct{}
	fields     map[string][]string // collector -> compact field paths
	tags       map[string]struct{}
	resources  map[string]struct{}
}

func newMuteSet(rules []MuteRule) muteSet {
	set := muteSet{collectors: map[string]struct{}{}, fields: map[string][]string{}, tags: map[string]struct{}{}, resources: map[string]struct{}{}}
	for _, rule := range rules {
		switch rule.Kind {
		case MuteCollector:
			set.collectors[rule.Value] = struct{}{}
		case MuteField:
			collector, path, _ := strings.Cut(rule.Value, ".")
			set.fields[collector] = append(set.fields[collector], compactPath(path))
		case MuteTag:
			set.tags[strings.ToLower(rule.Value)] = struct{}{}
		case MuteResource:
			set.resources[strings.ToLower(rule.Value)] = struct{}{}
		}
	}
	return set
}

func (m muteSet) empty() bool {
	return len(m.collectors) == 0 && len(m.fields) == 0 && len(m.tags) == 0 && len(m.resources) == 0
}

func compactPath(path string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(path, "_", ""), "-", ""))
}

// fieldMuted reports whether a field path is covered by a field rule: the
// rule path equals the field or is one of its parent paths.
func (m muteSet) fieldMuted(collector, field string) bool {
	field = compactPath(field)
	for _, rule := range m.fields[collector] {
		if field == rule || strings.HasPrefix(field, rule+".") {
			return true
		}
	}
	return false
}

// evaluate returns whether a change is muted as a whole and, for a change
// that is only partly muted, the change with its muted fields removed (used
// for the digest only; History keeps every field).
func (m muteSet) evaluate(change model.Change, before, after []byte) (bool, model.Change) {
	if m.empty() {
		return false, change
	}
	if _, muted := m.collectors[change.Collector]; muted {
		return true, change
	}
	if _, muted := m.resources[strings.ToLower(change.ResourceID)]; muted {
		return true, change
	}
	if _, muted := m.resources[strings.ToLower(change.Name)]; muted && change.Name != "" {
		return true, change
	}
	if len(m.tags) > 0 && (m.hasMutedTag(before) || m.hasMutedTag(after)) {
		return true, change
	}
	if change.Kind != "changed" || len(change.Fields) == 0 || len(m.fields[change.Collector]) == 0 {
		return false, change
	}
	kept := make([]model.FieldChange, 0, len(change.Fields))
	for _, field := range change.Fields {
		if !m.fieldMuted(change.Collector, field.Field) {
			kept = append(kept, field)
		}
	}
	if len(kept) == 0 && !change.FieldsTruncated {
		return true, change
	}
	if len(kept) == len(change.Fields) {
		return false, change
	}
	stripped := change
	stripped.Fields = kept
	if !stripped.FieldsTruncated {
		stripped.TotalFields = len(kept)
	}
	return false, stripped
}

func (m muteSet) hasMutedTag(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var resource struct {
		Tags []any `json:"tags"`
	}
	if json.Unmarshal(raw, &resource) != nil {
		return false
	}
	for _, tag := range resource.Tags {
		if text, ok := tag.(string); ok {
			if _, muted := m.tags[strings.ToLower(text)]; muted {
				return true
			}
		}
	}
	return false
}
