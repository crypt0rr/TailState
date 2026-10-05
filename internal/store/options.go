package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// monitoringOptionsMeta stores non-secret monitoring options in the meta
// key/value table. Keeping them out of the settings row avoids a schema
// migration; SaveSettings writes them in the same transaction as the row, so
// the settings revision still changes whenever an option changes.
const monitoringOptionsMeta = "monitoring_options"

// Expiry warning bounds. A window is a number of whole days before a node key
// or auth key expires at which one grouped warning is sent.
const (
	MaxExpiryWarningWindows = 4
	MaxExpiryWarningDays    = 365
	MaxExpiryTagFilters     = 32
	maxExpiryTagBytes       = 128
	MaxOAuthScopes          = 32
)

// readScope accepts Tailscale read scopes such as all:read, dns:read, or
// devices:core:read. Write scopes are rejected: TailState never modifies a
// tailnet and must not hold a token that could.
var readScope = regexp.MustCompile(`^[a-z][a-z_]*(:[a-z][a-z_]*)*:read$`)

// DefaultExpiryWarningDays returns the warning windows used when an operator
// has not configured any.
func DefaultExpiryWarningDays() []int { return []int{14, 3} }

type monitoringOptions struct {
	ExpiryWarningDays []int    `json:"expiry_warning_days"`
	ExpiryTagFilter   []string `json:"expiry_tag_filter"`
	OAuthScopes       []string `json:"oauth_scopes,omitempty"`
}

// DefaultOAuthScopes returns the scopes requested when none are configured.
func DefaultOAuthScopes() []string { return []string{"all:read"} }

// NormalizeOAuthScopes validates the OAuth scopes requested for the access
// token and returns them de-duplicated and sorted. An empty list selects
// all:read. Only read scopes are accepted.
func NormalizeOAuthScopes(scopes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if len(scope) > 64 || !readScope.MatchString(scope) {
			return nil, errors.New(`OAuth scopes must be read scopes such as "all:read" or "devices:core:read"`)
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	if len(out) > MaxOAuthScopes {
		return nil, fmt.Errorf("at most %d OAuth scopes are allowed", MaxOAuthScopes)
	}
	if len(out) == 0 {
		return DefaultOAuthScopes(), nil
	}
	sort.Strings(out)
	return out, nil
}

// NormalizeExpiryWarningDays validates warning windows and returns them
// de-duplicated in descending order. A nil slice selects the defaults; an
// empty non-nil slice disables expiry warnings.
func NormalizeExpiryWarningDays(days []int) ([]int, error) {
	if days == nil {
		return DefaultExpiryWarningDays(), nil
	}
	seen := make(map[int]struct{}, len(days))
	out := make([]int, 0, len(days))
	for _, day := range days {
		if day < 1 || day > MaxExpiryWarningDays {
			return nil, fmt.Errorf("expiry warning windows must be between 1 and %d days", MaxExpiryWarningDays)
		}
		if _, duplicate := seen[day]; duplicate {
			continue
		}
		seen[day] = struct{}{}
		out = append(out, day)
	}
	if len(out) > MaxExpiryWarningWindows {
		return nil, fmt.Errorf("at most %d expiry warning windows are allowed", MaxExpiryWarningWindows)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out, nil
}

// NormalizeExpiryTagFilter validates the optional tag filter and returns it
// de-duplicated and sorted. An empty filter warns for every resource.
func NormalizeExpiryTagFilter(tags []string) ([]string, error) {
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if !strings.HasPrefix(tag, "tag:") || len(tag) == len("tag:") || len(tag) > maxExpiryTagBytes || strings.ContainsAny(tag, " \t\r\n,") {
			return nil, errors.New(`expiry tag filters must look like "tag:name"`)
		}
		key := strings.ToLower(tag)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, tag)
	}
	if len(out) > MaxExpiryTagFilters {
		return nil, fmt.Errorf("at most %d expiry tag filters are allowed", MaxExpiryTagFilters)
	}
	sort.Strings(out)
	return out, nil
}

func validateMonitoringOptions(in Settings) error {
	if _, err := NormalizeExpiryWarningDays(in.ExpiryWarningDays); err != nil {
		return err
	}
	if _, err := NormalizeExpiryTagFilter(in.ExpiryTagFilter); err != nil {
		return err
	}
	if _, err := NormalizeOAuthScopes(in.OAuthScopes); err != nil {
		return err
	}
	return nil
}

func normalizedMonitoringOptions(in Settings) (monitoringOptions, error) {
	days, err := NormalizeExpiryWarningDays(in.ExpiryWarningDays)
	if err != nil {
		return monitoringOptions{}, err
	}
	tags, err := NormalizeExpiryTagFilter(in.ExpiryTagFilter)
	if err != nil {
		return monitoringOptions{}, err
	}
	scopes, err := NormalizeOAuthScopes(in.OAuthScopes)
	if err != nil {
		return monitoringOptions{}, err
	}
	return monitoringOptions{ExpiryWarningDays: days, ExpiryTagFilter: tags, OAuthScopes: scopes}, nil
}

// saveMonitoringOptionsTx persists the options. When the requested OAuth
// scopes change, collectors currently marked unsupported in the active
// generation are made due immediately: a broadened scope must not wait out
// the six-hour unsupported window before the newly permitted collector is
// polled (its first successful poll is still a silent baseline).
func saveMonitoringOptionsTx(ctx context.Context, tx *sql.Tx, in Settings, generation int64) error {
	options, err := normalizedMonitoringOptions(in)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return err
	}
	previousScopes := DefaultOAuthScopes()
	var previous string
	switch err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", monitoringOptionsMeta).Scan(&previous); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		var stored monitoringOptions
		if json.Unmarshal([]byte(previous), &stored) == nil {
			if scopes, scopeErr := NormalizeOAuthScopes(stored.OAuthScopes); scopeErr == nil {
				previousScopes = scopes
			}
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", monitoringOptionsMeta, string(raw)); err != nil {
		return err
	}
	if strings.Join(previousScopes, " ") != strings.Join(options.OAuthScopes, " ") {
		if _, err = tx.ExecContext(ctx, "UPDATE collector_state SET next_poll=NULL WHERE generation=? AND supported=0", generation); err != nil {
			return err
		}
	}
	return nil
}

// loadMonitoringOptions fills the option fields of out. A missing row (a
// database configured by an older release) or an unreadable value selects the
// defaults so a damaged option can never stop monitoring.
func (s *Store) loadMonitoringOptions(ctx context.Context, out *Settings) error {
	out.ExpiryWarningDays = DefaultExpiryWarningDays()
	out.ExpiryTagFilter = nil
	out.OAuthScopes = DefaultOAuthScopes()
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key=?", monitoringOptionsMeta).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var stored monitoringOptions
	if json.Unmarshal([]byte(raw), &stored) != nil {
		return nil
	}
	if days, daysErr := NormalizeExpiryWarningDays(stored.ExpiryWarningDays); daysErr == nil {
		out.ExpiryWarningDays = days
	}
	if tags, tagsErr := NormalizeExpiryTagFilter(stored.ExpiryTagFilter); tagsErr == nil && len(tags) > 0 {
		out.ExpiryTagFilter = tags
	}
	if scopes, scopeErr := NormalizeOAuthScopes(stored.OAuthScopes); scopeErr == nil {
		out.OAuthScopes = scopes
	}
	return nil
}
