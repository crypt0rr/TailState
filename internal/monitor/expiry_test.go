package monitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

func expiryDevice(id, name string, expires time.Time, extra map[string]any) model.Resource {
	data := map[string]any{"id": id, "name": name, "expires": expires.UTC().Format(time.RFC3339), "keyExpiryDisabled": false, "tags": []any{"tag:server"}}
	for key, value := range extra {
		data[key] = value
	}
	return model.Resource{ID: id, Type: "device", Name: name, Collector: "devices", Data: data}
}

func applyExpiryInventory(t *testing.T, st *store.Store, generation int64, devices, keys []model.Resource) {
	t.Helper()
	results := []model.Collected{{Collector: "devices", Resources: devices}, {Collector: "keys", Resources: keys}}
	if _, err := st.ApplyBatchWithBatch(context.Background(), generation, results, notify.Context{}.Digest); err != nil {
		t.Fatal(err)
	}
}

func pendingPayloads(t *testing.T, st *store.Store) []string {
	t.Helper()
	items, err := st.ClaimDueOutbox(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		// Render the stored message as the destination would receive it.
		rendered, err := notify.Prepare(item.PayloadFormat, item.Payload, item.Destination.ServiceURL, item.Destination.Format)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rendered)
		if err := st.DeliveredClaimed(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// A device whose node key expires in ten days triggers exactly one grouped
// 14-day warning across repeated daily checks, and re-authenticating the
// device (a new expiry) clears the warning state so the next expiry is
// warned about again.
func TestDeviceKeyExpiryWarnsOncePerWindowAndResetsOnReauthentication(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test")
	now := time.Now().UTC()
	key := model.Resource{ID: "k1", Type: "credential", Name: "ci", Collector: "keys", Data: map[string]any{"id": "k1", "keyType": "auth", "description": "ci enrolment", "expires": now.Add(10 * 24 * time.Hour).Format(time.RFC3339)}}
	applyExpiryInventory(t, st, settings.Generation, []model.Resource{
		expiryDevice("n1", "server.example.ts.net", now.Add(10*24*time.Hour), nil),
		expiryDevice("n2", "laptop.example.ts.net", now.Add(5*24*time.Hour), map[string]any{"keyExpiryDisabled": true}),
		expiryDevice("n3", "ephemeral.example.ts.net", now.Add(5*24*time.Hour), map[string]any{"isEphemeral": true}),
	}, []model.Resource{key})

	report, err := engine.CheckExpiry(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Warnings != 1 || report.Items != 2 {
		t.Fatalf("report=%#v, want one grouped warning for the device and the auth key", report)
	}
	payloads := pendingPayloads(t, st)
	if len(payloads) != 1 {
		t.Fatalf("payloads=%d, want exactly one notification", len(payloads))
	}
	for _, want := range []string{"within 14 days", "**server**", "ci enrolment", "tag:server"} {
		if !strings.Contains(payloads[0], want) {
			t.Fatalf("payload missing %q:\n%s", want, payloads[0])
		}
	}
	for _, excluded := range []string{"laptop", "ephemeral"} {
		if strings.Contains(payloads[0], excluded) {
			t.Fatalf("excluded device %q warned:\n%s", excluded, payloads[0])
		}
	}
	for day := 1; day <= 3; day++ {
		report, err = engine.CheckExpiry(ctx, now.Add(time.Duration(day)*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if report.Warnings != 0 {
			t.Fatalf("day %d repeated the 14-day warning: %#v", day, report)
		}
	}
	if repeated := pendingPayloads(t, st); len(repeated) != 0 {
		t.Fatalf("repeated payloads: %v", repeated)
	}

	// Re-authentication moves the expiry out of every window: state clears.
	applyExpiryInventory(t, st, settings.Generation, []model.Resource{expiryDevice("n1", "server.example.ts.net", now.Add(180*24*time.Hour), nil)}, []model.Resource{key})
	if _, err := engine.CheckExpiry(ctx, now.Add(4*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw, err := st.ExpiryWarningState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "device/n1") {
		t.Fatalf("re-authenticated device kept warning state: %s", raw)
	}
	// The renewed key later approaches expiry again and is warned again.
	report, err = engine.CheckExpiry(ctx, now.Add(170*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if report.Warnings != 1 || report.Items != 1 {
		t.Fatalf("renewed expiry was not warned again: %#v", report)
	}
}

func TestExpiryCheckHonorsTagFilterAndDisabledWindows(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test")
	now := time.Now().UTC()
	applyExpiryInventory(t, st, settings.Generation, []model.Resource{
		expiryDevice("n1", "server", now.Add(2*24*time.Hour), nil),
		expiryDevice("n2", "laptop", now.Add(2*24*time.Hour), map[string]any{"tags": []any{}}),
	}, nil)

	settings.ExpiryTagFilter = []string{"tag:server"}
	if _, err := st.SaveSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	report, err := engine.CheckExpiry(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Warnings != 1 || report.Items != 1 {
		t.Fatalf("tag filter report=%#v", report)
	}
	if payloads := pendingPayloads(t, st); len(payloads) != 1 || strings.Contains(payloads[0], "laptop") || !strings.Contains(payloads[0], "within 3 days") {
		t.Fatalf("filtered payloads=%v", payloads)
	}

	settings.ExpiryTagFilter = nil
	settings.ExpiryWarningDays = []int{}
	if _, err := st.SaveSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	report, err = engine.CheckExpiry(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Warnings != 0 {
		t.Fatalf("disabled windows warned: %#v", report)
	}
}

func TestExpiryCheckSkipsUnconfiguredAndStaleGeneration(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test")
	if committed, err := st.CommitExpiryWarnings(ctx, settings.Generation+1, []notify.Message{notify.Text("stale")}, "{}"); err != nil || committed {
		t.Fatalf("stale generation committed=%v err=%v", committed, err)
	}
	if payloads := pendingPayloads(t, st); len(payloads) != 0 {
		t.Fatalf("stale generation enqueued %v", payloads)
	}
	report, err := engine.CheckExpiry(ctx, time.Now())
	if err != nil || report.Warnings != 0 {
		t.Fatalf("empty inventory report=%#v err=%v", report, err)
	}
}

func TestExpiryWorkerRunsAndStops(t *testing.T) {
	st, settings := monitorTestStore(t)
	engine := New(st, "", "", "test")
	now := time.Now().UTC()
	applyExpiryInventory(t, st, settings.Generation, []model.Resource{expiryDevice("n1", "server", now.Add(24*time.Hour), nil)}, nil)
	previousInitial, previousInterval := expiryInitialDelay, expiryCheckInterval
	expiryInitialDelay, expiryCheckInterval = time.Millisecond, time.Hour
	t.Cleanup(func() { expiryInitialDelay, expiryCheckInterval = previousInitial, previousInterval })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		engine.expiryWorker(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := st.ExpiryWarningState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, "device/n1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expiry worker did not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestExpiryWorkerRetriesWhenUnconfiguredOrFailing(t *testing.T) {
	st, _, db := monitorTestStoreWithDB(t)
	engine := New(st, "", "", "test")
	previousInitial, previousRetry := expiryInitialDelay, expiryRetryInterval
	expiryInitialDelay, expiryRetryInterval = time.Millisecond, time.Millisecond
	t.Cleanup(func() { expiryInitialDelay, expiryRetryInterval = previousInitial, previousRetry })
	if _, err := db.Exec("DROP TABLE snapshots"); err != nil {
		t.Fatal(err)
	}
	failing, cancelFailing := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelFailing()
	engine.expiryWorker(failing)
	if _, err := db.Exec("DELETE FROM settings"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	engine.expiryWorker(ctx)
	if _, err := engine.CheckExpiry(context.Background(), time.Now()); err == nil {
		t.Fatal("unconfigured check did not report an error")
	}
}

// Expiry warnings are system notifications, like collector health alerts:
// they reach every enabled destination even when its routing rules accept
// only high-severity changes of another collector and a mute rule silences
// the devices collector, and they carry the instance context (instance label,
// tailnet, Observed at line, and Status link).
func TestExpiryWarningsBypassRoutingAndMutesWithInstanceContext(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) == 0 {
		t.Fatalf("destinations=%v err=%v", destinations, err)
	}
	for _, destination := range destinations {
		if err := st.SetDestinationRouting(ctx, destination.ID, store.RoutingRules{MinSeverity: model.SeverityHigh, IncludeCollectors: []string{"acl"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.AddMuteRule(ctx, "collector", "devices"); err != nil {
		t.Fatal(err)
	}
	engine := New(st, "", "", "test")
	engine.ConfigureNotifications("primary", "https://tailstate.example")
	now := time.Now().UTC()
	applyExpiryInventory(t, st, settings.Generation, []model.Resource{expiryDevice("n1", "server.example.ts.net", now.Add(2*24*time.Hour), nil)}, nil)
	if report, err := engine.CheckExpiry(ctx, now); err != nil || report.Warnings != 1 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	payloads := pendingPayloads(t, st)
	if len(payloads) != len(destinations) {
		t.Fatalf("payloads=%d, want one per enabled destination (%d)", len(payloads), len(destinations))
	}
	for _, want := range []string{"within 3 days", "primary", "default tailnet", "Observed at " + now.UTC().Format("2 Jan 2006 15:04 UTC"), "https://tailstate.example/status", "**server**"} {
		if !strings.Contains(payloads[0], want) {
			t.Fatalf("payload missing %q:\n%s", want, payloads[0])
		}
	}
}
