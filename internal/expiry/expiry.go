// Package expiry derives proactive expiry warnings for device node keys and
// auth keys from TailState's current normalized snapshots.
//
// The package is pure: callers supply snapshots, options, the current time,
// and the previously persisted warning state. Plan returns the warnings to
// send and the next state, so each resource and window alerts exactly once
// for a given expiry and the state resets when the expiry changes (for
// example after a device is re-authenticated).
package expiry

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

// Resource kinds.
const (
	KindDevice  = "device"
	KindAuthKey = "auth_key"
)

const day = 24 * time.Hour

// DefaultHorizonDays is used for the status page when warnings are disabled.
const DefaultHorizonDays = 14

// Snapshot is the subset of a stored snapshot needed here.
type Snapshot struct {
	ID   string
	Name string
	Raw  []byte
}

// Item is one resource with a future-dated expiry.
type Item struct {
	Kind    string
	ID      string
	Name    string
	Tags    []string
	Expires time.Time
}

// Key identifies the resource in the warning state.
func (i Item) Key() string { return i.Kind + "/" + i.ID }

// KindLabel is a human-readable resource kind.
func (i Item) KindLabel() string {
	if i.Kind == KindAuthKey {
		return "Auth key"
	}
	return "Device node key"
}

// DaysLeft rounds the remaining time down to whole days.
func (i Item) DaysLeft(now time.Time) int {
	remaining := i.Expires.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return int(remaining / day)
}

// Items extracts every device node key and auth key with a known expiry that
// passes the tag filter. Devices with key expiry disabled, ephemeral devices,
// and revoked or invalid keys are excluded. Expired resources are kept so
// callers can decide whether to show them; Plan only warns before expiry.
func Items(devices, keys []Snapshot, tagFilter []string) []Item {
	filter := make(map[string]struct{}, len(tagFilter))
	for _, tag := range tagFilter {
		filter[strings.ToLower(strings.TrimSpace(tag))] = struct{}{}
	}
	var out []Item
	for _, snapshot := range devices {
		if item, ok := deviceItem(snapshot); ok && matches(item.Tags, filter) {
			out = append(out, item)
		}
	}
	for _, snapshot := range keys {
		if item, ok := keyItem(snapshot); ok && matches(item.Tags, filter) {
			out = append(out, item)
		}
	}
	sortItems(out)
	return out
}

func deviceItem(snapshot Snapshot) (Item, bool) {
	var data map[string]any
	if json.Unmarshal(snapshot.Raw, &data) != nil || data == nil {
		return Item{}, false
	}
	if truthy(data["keyExpiryDisabled"]) || truthy(data["isEphemeral"]) {
		return Item{}, false
	}
	expires, ok := parseTime(data["expires"])
	if !ok {
		return Item{}, false
	}
	name := snapshot.Name
	if name == "" {
		name = firstString(data, "name", "hostname")
	}
	if name == "" {
		name = snapshot.ID
	}
	return Item{Kind: KindDevice, ID: snapshot.ID, Name: name, Tags: uniqueSorted(stringList(data["tags"])), Expires: expires}, true
}

func keyItem(snapshot Snapshot) (Item, bool) {
	var data map[string]any
	if json.Unmarshal(snapshot.Raw, &data) != nil || data == nil {
		return Item{}, false
	}
	// Only machine auth keys enrol devices. OAuth clients do not expire, and
	// API access tokens minted by OAuth clients are short-lived by design;
	// warning for them would be noise.
	if keyType, _ := data["keyType"].(string); keyType != "" && keyType != "auth" {
		return Item{}, false
	}
	if truthy(data["invalid"]) {
		return Item{}, false
	}
	if revoked, ok := data["revoked"].(string); ok && strings.TrimSpace(revoked) != "" {
		// The API may report an unset timestamp as the zero time; any other
		// value means the key was revoked.
		if when, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(revoked)); err != nil || when.Year() > 1 {
			return Item{}, false
		}
	}
	expires, ok := parseTime(data["expires"])
	if !ok {
		return Item{}, false
	}
	name := firstString(data, "description")
	if name == "" {
		name = snapshot.Name
	}
	if name == "" {
		name = snapshot.ID
	}
	var tags []string
	if capabilities, ok := data["capabilities"].(map[string]any); ok {
		if devices, ok := capabilities["devices"].(map[string]any); ok {
			if create, ok := devices["create"].(map[string]any); ok {
				tags = stringList(create["tags"])
			}
		}
	}
	tags = append(tags, stringList(data["tags"])...)
	return Item{Kind: KindAuthKey, ID: snapshot.ID, Name: name, Tags: uniqueSorted(tags), Expires: expires}, true
}

func matches(tags []string, filter map[string]struct{}) bool {
	if len(filter) == 0 {
		return true
	}
	for _, tag := range tags {
		if _, ok := filter[strings.ToLower(tag)]; ok {
			return true
		}
	}
	return false
}

// Upcoming returns the items that have not expired yet and expire within
// horizonDays, ordered by expiry.
func Upcoming(items []Item, now time.Time, horizonDays int) []Item {
	var out []Item
	limit := now.Add(time.Duration(horizonDays) * day)
	for _, item := range items {
		if item.Expires.After(now) && !item.Expires.After(limit) {
			out = append(out, item)
		}
	}
	sortItems(out)
	return out
}

// HorizonDays returns the widest configured window, or DefaultHorizonDays
// when warnings are disabled.
func HorizonDays(windows []int) int {
	horizon := 0
	for _, window := range windows {
		horizon = max(horizon, window)
	}
	if horizon == 0 {
		return DefaultHorizonDays
	}
	return horizon
}

// State records the warnings already sent in one monitoring generation.
type State struct {
	Generation int64            `json:"generation"`
	Alerts     map[string]Alert `json:"alerts"`
}

// Alert records the windows already warned for one resource expiry.
type Alert struct {
	Expires string `json:"expires"`
	Windows []int  `json:"windows"`
}

// ParseState decodes persisted state. Missing or unreadable state is empty,
// which at worst repeats a warning instead of suppressing one.
func ParseState(raw string) State {
	var state State
	if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &state) != nil {
		return State{Alerts: map[string]Alert{}}
	}
	if state.Alerts == nil {
		state.Alerts = map[string]Alert{}
	}
	return state
}

// Encode serializes the state deterministically.
func (s State) Encode() string {
	if s.Alerts == nil {
		s.Alerts = map[string]Alert{}
	}
	raw, _ := json.Marshal(s)
	return string(raw)
}

// Warning is one grouped notification for a crossed window.
type Warning struct {
	WindowDays int
	Items      []Item
}

// Plan decides which warnings to send. Windows are whole days before expiry.
// A resource inside several windows is reported once, in its tightest window,
// and every wider window it is inside is marked as warned too. A resource
// whose expiry changed since its last warning starts with a clean state; a
// resource that left every window (renewed, expired, removed, or filtered
// out) is dropped from the state.
func Plan(previous State, generation int64, items []Item, windows []int, now time.Time) ([]Warning, State) {
	next := State{Generation: generation, Alerts: map[string]Alert{}}
	if previous.Generation != generation || previous.Alerts == nil {
		previous = State{Generation: generation, Alerts: map[string]Alert{}}
	}
	windows = descendingUnique(windows)
	grouped := map[int][]Item{}
	for _, item := range items {
		remaining := item.Expires.Sub(now)
		if remaining <= 0 {
			continue
		}
		var crossed []int
		for _, window := range windows {
			if remaining <= time.Duration(window)*day {
				crossed = append(crossed, window)
			}
		}
		if len(crossed) == 0 {
			continue
		}
		expires := item.Expires.UTC().Format(time.RFC3339)
		alert := previous.Alerts[item.Key()]
		if alert.Expires != expires {
			alert = Alert{Expires: expires}
		}
		tightest := crossed[len(crossed)-1]
		if !containsInt(alert.Windows, tightest) {
			grouped[tightest] = append(grouped[tightest], item)
		}
		alert.Windows = descendingUnique(append(append([]int(nil), alert.Windows...), crossed...))
		next.Alerts[item.Key()] = alert
	}
	var warnings []Warning
	for _, window := range windows {
		if group := grouped[window]; len(group) > 0 {
			sortItems(group)
			warnings = append(warnings, Warning{WindowDays: window, Items: group})
		}
	}
	return warnings, next
}

// Message builds the grouped system notification for a warning, titled with
// the instance and tailnet from the notification context.
func Message(context notify.Context, warning Warning, now time.Time) notify.Message {
	lines := make([]notify.ExpiryLine, 0, len(warning.Items))
	for _, item := range warning.Items {
		lines = append(lines, notify.ExpiryLine{Kind: item.KindLabel(), Name: item.Name, Tags: item.Tags, Expires: item.Expires, DaysLeft: item.DaysLeft(now)})
	}
	return context.ExpiryWarning(warning.WindowDays, lines, now)
}

func sortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].Expires.Equal(items[j].Expires) {
			return items[i].Expires.Before(items[j].Expires)
		}
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].ID < items[j].ID
	})
}

func descendingUnique(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func truthy(value any) bool {
	b, ok := value.(bool)
	return ok && b
}

func parseTime(value any) (time.Time, bool) {
	raw, ok := value.(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil || parsed.Year() <= 1 {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func firstString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := data[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func stringList(value any) []string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, entry := range list {
		if text, ok := entry.(string); ok && text != "" {
			out = append(out, text)
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
