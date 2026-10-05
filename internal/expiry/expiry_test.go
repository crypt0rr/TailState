package expiry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

var testNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func deviceSnapshot(t *testing.T, id, name string, expires time.Time, extra map[string]any) Snapshot {
	t.Helper()
	data := map[string]any{"id": id, "name": name, "expires": expires.Format(time.RFC3339), "keyExpiryDisabled": false}
	for key, value := range extra {
		data[key] = value
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{ID: id, Name: name, Raw: raw}
}

func keySnapshot(t *testing.T, id string, data map[string]any) Snapshot {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{ID: id, Raw: raw}
}

func days(n float64) time.Duration { return time.Duration(n * float64(24*time.Hour)) }

func TestDeviceExpiringInTenDaysWarnsOnceForFourteenDayWindow(t *testing.T) {
	devices := []Snapshot{deviceSnapshot(t, "n1", "server.example.ts.net", testNow.Add(days(10)), map[string]any{"tags": []any{"tag:server"}})}
	items := Items(devices, nil, nil)
	warnings, state := Plan(State{}, 1, items, []int{14, 3}, testNow)
	if len(warnings) != 1 || warnings[0].WindowDays != 14 || len(warnings[0].Items) != 1 || warnings[0].Items[0].ID != "n1" {
		t.Fatalf("warnings=%#v, want exactly one 14-day warning for n1", warnings)
	}
	// Later daily checks inside the same window must not repeat it, even
	// after the state round-trips through persistence.
	for day := 1; day <= 6; day++ {
		now := testNow.Add(time.Duration(day) * 24 * time.Hour)
		warnings, state = Plan(ParseState(state.Encode()), 1, items, []int{14, 3}, now)
		if len(warnings) != 0 {
			t.Fatalf("day %d repeated a warning: %#v", day, warnings)
		}
	}
	// Crossing the 3-day window is a new, separate warning.
	warnings, state = Plan(state, 1, items, []int{14, 3}, testNow.Add(days(7.5)))
	if len(warnings) != 1 || warnings[0].WindowDays != 3 {
		t.Fatalf("3-day warnings=%#v", warnings)
	}
	warnings, _ = Plan(state, 1, items, []int{14, 3}, testNow.Add(days(8)))
	if len(warnings) != 0 {
		t.Fatalf("3-day warning repeated: %#v", warnings)
	}
}

func TestReauthenticatedDeviceClearsExpiryWarningState(t *testing.T) {
	soon := []Snapshot{deviceSnapshot(t, "n1", "server", testNow.Add(days(10)), nil)}
	_, state := Plan(State{}, 1, Items(soon, nil, nil), []int{14, 3}, testNow)
	if _, ok := state.Alerts["device/n1"]; !ok {
		t.Fatalf("warning state was not recorded: %#v", state)
	}
	renewed := []Snapshot{deviceSnapshot(t, "n1", "server", testNow.Add(days(180)), nil)}
	warnings, state := Plan(state, 1, Items(renewed, nil, nil), []int{14, 3}, testNow.Add(24*time.Hour))
	if len(warnings) != 0 || len(state.Alerts) != 0 {
		t.Fatalf("re-authentication kept warning state: warnings=%#v state=%#v", warnings, state)
	}
	// A new expiry that is again inside a window warns afresh, even when the
	// previous state is still present (expiry changed without leaving it).
	_, state = Plan(State{}, 1, Items(soon, nil, nil), []int{14, 3}, testNow)
	shortRenewal := []Snapshot{deviceSnapshot(t, "n1", "server", testNow.Add(days(12)), nil)}
	warnings, _ = Plan(state, 1, Items(shortRenewal, nil, nil), []int{14, 3}, testNow.Add(time.Hour))
	if len(warnings) != 1 || warnings[0].WindowDays != 14 {
		t.Fatalf("changed expiry did not reset the warning: %#v", warnings)
	}
}

func TestKeyExpiryDisabledDevicesNeverWarn(t *testing.T) {
	devices := []Snapshot{
		deviceSnapshot(t, "disabled", "disabled", testNow.Add(days(1)), map[string]any{"keyExpiryDisabled": true}),
		deviceSnapshot(t, "ephemeral", "ephemeral", testNow.Add(days(1)), map[string]any{"isEphemeral": true}),
		{ID: "zero", Raw: []byte(`{"expires":"0001-01-01T00:00:00Z"}`)},
		{ID: "broken", Raw: []byte(`not json`)},
		{ID: "missing", Raw: []byte(`{"name":"no expiry"}`)},
	}
	items := Items(devices, nil, nil)
	if len(items) != 0 {
		t.Fatalf("excluded devices produced items: %#v", items)
	}
	for _, now := range []time.Time{testNow, testNow.Add(-days(30))} {
		if warnings, _ := Plan(State{}, 1, items, []int{30, 14, 3, 1}, now); len(warnings) != 0 {
			t.Fatalf("excluded devices warned: %#v", warnings)
		}
	}
}

func TestDeviceInsideSeveralWindowsWarnsOnceInTightestWindow(t *testing.T) {
	items := Items([]Snapshot{deviceSnapshot(t, "n1", "server", testNow.Add(days(2)), nil)}, nil, nil)
	warnings, state := Plan(State{}, 1, items, []int{3, 14, 14}, testNow)
	if len(warnings) != 1 || warnings[0].WindowDays != 3 {
		t.Fatalf("warnings=%#v", warnings)
	}
	if got := state.Alerts["device/n1"].Windows; len(got) != 2 || got[0] != 14 || got[1] != 3 {
		t.Fatalf("both crossed windows must be recorded, got %v", got)
	}
}

func TestExpiredAndDistantResourcesDoNotWarn(t *testing.T) {
	items := Items([]Snapshot{
		deviceSnapshot(t, "expired", "expired", testNow.Add(-time.Hour), nil),
		deviceSnapshot(t, "far", "far", testNow.Add(days(60)), nil),
	}, nil, nil)
	warnings, state := Plan(State{}, 1, items, []int{14, 3}, testNow)
	if len(warnings) != 0 || len(state.Alerts) != 0 {
		t.Fatalf("warnings=%#v state=%#v", warnings, state)
	}
	if warnings, _ := Plan(State{}, 1, items, nil, testNow); len(warnings) != 0 {
		t.Fatalf("disabled windows warned: %#v", warnings)
	}
}

func TestGenerationChangeResetsExpiryState(t *testing.T) {
	items := Items([]Snapshot{deviceSnapshot(t, "n1", "server", testNow.Add(days(10)), nil)}, nil, nil)
	_, state := Plan(State{}, 1, items, []int{14}, testNow)
	warnings, next := Plan(state, 2, items, []int{14}, testNow)
	if len(warnings) != 1 || next.Generation != 2 {
		t.Fatalf("new generation must start a fresh state: %#v %#v", warnings, next)
	}
}

func TestAuthKeyExpiryItemsAndFilters(t *testing.T) {
	expires := testNow.Add(days(5)).Format(time.RFC3339)
	keys := []Snapshot{
		keySnapshot(t, "k-auth", map[string]any{"keyType": "auth", "description": "ci enrolment", "expires": expires, "capabilities": map[string]any{"devices": map[string]any{"create": map[string]any{"tags": []any{"tag:ci"}}}}}),
		keySnapshot(t, "k-legacy", map[string]any{"expires": expires}),
		keySnapshot(t, "k-api", map[string]any{"keyType": "api", "expires": expires}),
		keySnapshot(t, "k-client", map[string]any{"keyType": "client", "expires": expires}),
		keySnapshot(t, "k-revoked", map[string]any{"keyType": "auth", "expires": expires, "revoked": testNow.Format(time.RFC3339)}),
		keySnapshot(t, "k-bad-revoked", map[string]any{"keyType": "auth", "expires": expires, "revoked": "yes"}),
		keySnapshot(t, "k-zero-revoked", map[string]any{"keyType": "auth", "expires": expires, "revoked": "0001-01-01T00:00:00Z"}),
		keySnapshot(t, "k-invalid", map[string]any{"keyType": "auth", "expires": expires, "invalid": true}),
		{ID: "k-broken", Raw: []byte(`[]`)},
	}
	items := Items(nil, keys, nil)
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
		if item.Kind != KindAuthKey || item.KindLabel() != "Auth key" {
			t.Fatalf("unexpected kind: %#v", item)
		}
	}
	if strings.Join(ids, ",") != "k-auth,k-legacy,k-zero-revoked" {
		t.Fatalf("auth key items=%v", ids)
	}
	if items[0].Name != "ci enrolment" || len(items[0].Tags) != 1 || items[0].Tags[0] != "tag:ci" {
		t.Fatalf("auth key item=%#v", items[0])
	}
	if items[1].Name != "k-legacy" {
		t.Fatalf("unnamed key should fall back to its ID: %#v", items[1])
	}

	devices := []Snapshot{
		deviceSnapshot(t, "server", "", testNow.Add(days(5)), map[string]any{"tags": []any{"tag:Server"}, "hostname": "srv"}),
		deviceSnapshot(t, "laptop", "laptop", testNow.Add(days(5)), nil),
	}
	devices[0].Name = ""
	filtered := Items(devices, keys, []string{" tag:server ", "tag:ci"})
	ids = ids[:0]
	for _, item := range filtered {
		ids = append(ids, item.ID)
	}
	if strings.Join(ids, ",") != "k-auth,server" {
		t.Fatalf("tag filter items=%v", ids)
	}
	if filtered[1].Name != "srv" {
		t.Fatalf("device name fallback=%q", filtered[1].Name)
	}
}

func TestDeviceNameFallsBackToSnapshotFields(t *testing.T) {
	items := Items([]Snapshot{
		{ID: "a", Raw: []byte(`{"hostname":"host-a","expires":"2026-10-10T00:00:00Z"}`)},
		{ID: "b", Raw: []byte(`{"expires":"2026-10-10T00:00:00Z"}`)},
	}, nil, nil)
	if len(items) != 2 || items[0].Name != "host-a" || items[1].Name != "b" {
		t.Fatalf("items=%#v", items)
	}
}

func TestUpcomingHorizonAndMessage(t *testing.T) {
	items := Items([]Snapshot{
		deviceSnapshot(t, "late", "late", testNow.Add(days(13)), nil),
		deviceSnapshot(t, "soon", "soon`name", testNow.Add(days(2)), map[string]any{"tags": []any{"tag:b", "tag:a"}}),
		deviceSnapshot(t, "gone", "gone", testNow.Add(-days(1)), nil),
		deviceSnapshot(t, "far", "far", testNow.Add(days(40)), nil),
	}, nil, nil)
	upcoming := Upcoming(items, testNow, HorizonDays([]int{3, 14}))
	if len(upcoming) != 2 || upcoming[0].ID != "soon" || upcoming[1].ID != "late" {
		t.Fatalf("upcoming=%#v", upcoming)
	}
	if HorizonDays(nil) != DefaultHorizonDays {
		t.Fatalf("default horizon=%d", HorizonDays(nil))
	}
	if upcoming[0].DaysLeft(testNow) != 2 || items[0].DaysLeft(testNow) != 0 {
		t.Fatalf("days left=%d/%d", upcoming[0].DaysLeft(testNow), items[0].DaysLeft(testNow))
	}
	message := notify.Markdown(Message(notify.Context{Label: "lab", Tailnet: "example.com", PublicURL: "https://tailstate.example"}, Warning{WindowDays: 3, Items: upcoming[:1]}, testNow))
	for _, want := range []string{"within 3 day(s) · lab \\(example.com\\)", "Device node key", "`tag:a, tag:b`", "2026-10-07 12:00 UTC", "2 day(s) left", "Observed at 2026-10-05T12:00:00Z", "(https://tailstate.example/status)"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message missing %q:\n%s", want, message)
		}
	}
	if strings.Contains(message, "soon`name") {
		t.Fatalf("message did not escape a backtick: %s", message)
	}
}

func TestParseStateToleratesMissingOrDamagedValues(t *testing.T) {
	for _, raw := range []string{"", "  ", "{", `{"generation":3}`} {
		state := ParseState(raw)
		if state.Alerts == nil {
			t.Fatalf("ParseState(%q) returned nil alerts", raw)
		}
	}
	if encoded := (State{Generation: 4}).Encode(); encoded != `{"generation":4,"alerts":{}}` {
		t.Fatalf("encoded=%s", encoded)
	}
}
