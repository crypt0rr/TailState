package store

import (
	"context"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

func deviceFleet(fields func(index int) map[string]any, count int) model.Collected {
	resources := make([]model.Resource, 0, count)
	for index := 0; index < count; index++ {
		data := map[string]any{"hostname": "host"}
		for key, value := range fields(index) {
			data[key] = value
		}
		resources = append(resources, model.Resource{ID: "device-" + string(rune('a'+index)), Type: "device", Name: "host-" + string(rune('a'+index)), Data: data})
	}
	return model.Collected{Collector: "devices", Resources: resources}
}

func addDestination(t *testing.T, st *Store, name string, rules RoutingRules) int64 {
	t.Helper()
	id, err := st.SaveDestination(context.Background(), NotificationDestination{Name: name, ServiceURL: "generic://notify.example/" + name, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetDestinationRouting(context.Background(), id, rules); err != nil {
		t.Fatal(err)
	}
	return id
}

func batchDeliveries(t *testing.T, st *Store, batchID int64) map[int64]string {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), "SELECT destination_id,payload_format,payload FROM outbox WHERE batch_id=? ORDER BY id", batchID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		payload := scanRenderedPayload(t, rows, &id)
		out[id] = payload
	}
	return out
}

// TestHighSeverityDestinationSkipsRoutineClientUpdates is the E-008
// acceptance guarantee: a destination with minimum severity "high" receives
// no digest for a batch of only client-version updates, while a default
// destination still receives every change.
func TestHighSeverityDestinationSkipsRoutineClientUpdates(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 || !destinations[0].Routing.AllChanges() {
		t.Fatalf("default destination routing=%+v err=%v", destinations, err)
	}
	defaultID := destinations[0].ID
	pagerID := addDestination(t, st, "pager", RoutingRules{MinSeverity: model.SeverityHigh})
	digest := notify.Context{Tailnet: "example.com"}.Digest
	version := func(v string) func(int) map[string]any {
		return func(int) map[string]any { return map[string]any{"clientVersion": v, "tags": []any{"tag:prod"}} }
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(version("1.80.0"), 3)}, digest); err != nil {
		t.Fatal(err)
	}
	upgrade, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(version("1.82.1"), 3)}, digest)
	if err != nil || upgrade.ID == 0 {
		t.Fatalf("upgrade batch=%+v err=%v", upgrade, err)
	}
	deliveries := batchDeliveries(t, st, upgrade.ID)
	if _, paged := deliveries[pagerID]; paged || len(deliveries) != 1 {
		t.Fatalf("client-version-only batch reached the high-severity destination: %v", deliveries)
	}
	if !strings.Contains(deliveries[defaultID], "⚪ ✏️ **host-a**") || !strings.Contains(deliveries[defaultID], "(device) changed") {
		t.Fatalf("default digest does not show the low severity:\n%s", deliveries[defaultID])
	}
	retag, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{deviceFleet(func(index int) map[string]any {
		tags := []any{"tag:prod"}
		if index == 0 {
			tags = []any{"tag:prod", "tag:admin"}
		}
		return map[string]any{"clientVersion": "1.82.1", "tags": tags}
	}, 3)}, digest)
	if err != nil {
		t.Fatal(err)
	}
	deliveries = batchDeliveries(t, st, retag.ID)
	if len(deliveries) != 2 || !strings.Contains(deliveries[pagerID], "🔴") {
		t.Fatalf("high-severity tag change was not routed to both destinations: %v", deliveries)
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Severity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Batches) != 1 || page.Batches[0].ID != upgrade.ID || len(page.Batches[0].Events) != 3 || page.Batches[0].Events[0].Severity != "low" {
		t.Fatalf("severity history filter returned %+v", page.Batches)
	}
	page, err = st.ListHistory(ctx, HistoryFilter{Severity: "high"})
	if err != nil || len(page.Batches) != 1 || page.Batches[0].ID != retag.ID || page.Batches[0].ChangeCount != 1 {
		t.Fatalf("high severity history filter returned %+v err=%v", page.Batches, err)
	}
}

// TestDestinationsSharingRulesShareOneDigestAndFiltersApply checks the
// fan-out: one digest per distinct rule set, collector and change-kind
// filters, and no row for a destination whose filters match nothing.
func TestDestinationsSharingRulesShareOneDigestAndFiltersApply(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	usersOnly := addDestination(t, st, "users-a", RoutingRules{IncludeCollectors: []string{"users"}})
	usersOnlyTwin := addDestination(t, st, "users-b", RoutingRules{IncludeCollectors: []string{"users", "users"}})
	noDevices := addDestination(t, st, "no-devices", RoutingRules{ExcludeCollectors: []string{"devices"}})
	removalsOnly := addDestination(t, st, "removals", RoutingRules{ChangeKinds: []string{"removed"}})
	calls := 0
	digest := func(in notify.DigestInput) notify.Message {
		calls++
		names := make([]string, 0, len(in.Changes))
		for _, change := range in.Changes {
			names = append(names, change.Collector+":"+change.Kind)
		}
		return notify.Text(strings.Join(names, ","))
	}
	users := func(name string) model.Collected {
		return model.Collected{Collector: "users", Resources: []model.Resource{{ID: "user-1", Type: "user", Name: "alice", Data: map[string]any{"displayName": name}}}}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("one", "100.64.0.1"), users("Alice")}, digest); err != nil {
		t.Fatal(err)
	}
	calls = 0
	batch, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("two", "100.64.0.1"), users("Alice B")}, digest)
	if err != nil {
		t.Fatal(err)
	}
	deliveries := batchDeliveries(t, st, batch.ID)
	if deliveries[usersOnly] != "users:changed" || deliveries[usersOnlyTwin] != "users:changed" || deliveries[noDevices] != "users:changed" {
		t.Fatalf("collector routing deliveries=%v", deliveries)
	}
	if _, delivered := deliveries[removalsOnly]; delivered {
		t.Fatalf("removal-only destination received a digest without removals: %v", deliveries)
	}
	if len(deliveries) != 4 {
		t.Fatalf("deliveries=%v, want the default destination plus three filtered ones", deliveries)
	}
	// default, users (shared by two destinations), and no-devices; the
	// removals rule set matched nothing, so it is not rendered at all.
	if calls != 3 {
		t.Fatalf("digest rendered %d times, want once per distinct non-empty rule set (3)", calls)
	}
}

func TestDestinationFormatOverride(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	id, err := st.SaveDestination(ctx, NotificationDestination{Name: "hook", ServiceURL: "generic://notify.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetDestinationFormat(ctx, id, " Slack "); err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || destinations[0].Format != notify.FormatSlack {
		t.Fatalf("format=%+v err=%v", destinations, err)
	}
	if err := st.SetDestinationFormat(ctx, id, "markdownv2"); err == nil {
		t.Fatal("unknown format saved")
	}
	if err := st.SetDestinationFormat(ctx, 999, notify.FormatPlain); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing destination format error=%v", err)
	}
	if err := st.EnqueueMessage(ctx, notify.Context{}.Update("1", "2", testTime)); err != nil {
		t.Fatal(err)
	}
	items, err := st.ClaimDueOutbox(ctx, 10)
	if err != nil || len(items) != 1 || items[0].PayloadFormat != notify.PayloadMessage || items[0].Destination.Format != notify.FormatSlack {
		t.Fatalf("claimed items=%+v err=%v", items, err)
	}
}

func TestRoutingRulesNormalizationAndErrors(t *testing.T) {
	rules, err := NormalizeRoutingRules(RoutingRules{MinSeverity: "LOW", IncludeCollectors: []string{" Users", "dns", "users", ""}, ChangeKinds: []string{"created", "changed", "removed"}})
	if err != nil {
		t.Fatal(err)
	}
	if rules.MinSeverity != "" || strings.Join(rules.IncludeCollectors, ",") != "dns,users" || rules.ChangeKinds != nil {
		t.Fatalf("normalized rules=%+v", rules)
	}
	for _, invalid := range []RoutingRules{
		{MinSeverity: "critical"},
		{IncludeCollectors: []string{"bad name"}},
		{ExcludeCollectors: []string{"DROP;"}},
		{ChangeKinds: []string{"renamed"}},
	} {
		if _, err := NormalizeRoutingRules(invalid); err == nil {
			t.Fatalf("invalid rules accepted: %+v", invalid)
		}
	}
	if got := routingFromColumns("critical", "", "", ""); !got.AllChanges() {
		t.Fatalf("unreadable stored routing did not fall back to all changes: %+v", got)
	}
	st := testStore(t)
	if err := st.SetDestinationRouting(context.Background(), 999, RoutingRules{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing destination routing error=%v", err)
	}
	if err := st.SetDestinationRouting(context.Background(), 1, RoutingRules{MinSeverity: "nope"}); err == nil {
		t.Fatal("invalid routing was saved")
	}
}
