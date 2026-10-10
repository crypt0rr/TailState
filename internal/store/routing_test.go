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

// TestPrivilegedCreationsAreHighEverywhere is E-040: a user or invite
// created with a role other than member and a device that joins tagged or
// with key expiry disabled are high in the stored event, the History
// severity filter, and the digest (so a "high only" destination receives
// them), while plain member, invite, and device creations stay medium.
func TestPrivilegedCreationsAreHighEverywhere(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	pagerID := addDestination(t, st, "pager", RoutingRules{MinSeverity: model.SeverityHigh})
	digest := notify.Context{Tailnet: "example.com"}.Digest
	resource := func(collector, id string, data map[string]any) model.Resource {
		return model.Resource{ID: id, Type: collector, Name: id, Collector: collector, Data: data}
	}
	inventory := func(created bool) []model.Collected {
		results := []model.Collected{
			{Collector: "users", Resources: []model.Resource{resource("users", "existing-user", map[string]any{"loginName": "old@example.com", "role": "member"})}},
			{Collector: "user_invites", Resources: []model.Resource{resource("user_invites", "existing-invite", map[string]any{"email": "old@example.com", "role": "member"})}},
			{Collector: "devices", Resources: []model.Resource{resource("devices", "existing-device", map[string]any{"name": "old", "tags": []any{}})}},
		}
		if created {
			results[0].Resources = append(results[0].Resources,
				resource("users", "new-admin", map[string]any{"loginName": "admin@example.com", "role": "admin"}),
				resource("users", "new-member", map[string]any{"loginName": "member@example.com", "role": "member"}))
			results[1].Resources = append(results[1].Resources,
				resource("user_invites", "invite-admin", map[string]any{"email": "admin2@example.com", "role": "it-admin"}),
				resource("user_invites", "invite-member", map[string]any{"email": "member2@example.com", "role": "member"}))
			results[2].Resources = append(results[2].Resources,
				resource("devices", "device-tagged", map[string]any{"name": "db", "tags": []any{"tag:prod"}}),
				resource("devices", "device-noexpiry", map[string]any{"name": "kiosk", "keyExpiryDisabled": true}),
				resource("devices", "device-plain", map[string]any{"name": "laptop", "tags": []any{}, "keyExpiryDisabled": false}))
		}
		return results
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, inventory(false), digest); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, inventory(true), digest)
	if err != nil || len(batch.Changes) != 7 {
		t.Fatalf("creation batch=%+v err=%v", batch, err)
	}
	want := map[string]string{
		"new-admin": "high", "invite-admin": "high", "device-tagged": "high", "device-noexpiry": "high",
		"new-member": "medium", "invite-member": "medium", "device-plain": "medium",
	}
	page, err := st.ListHistory(ctx, HistoryFilter{BatchID: batch.ID})
	if err != nil || len(page.Batches) != 1 {
		t.Fatalf("history=%+v err=%v", page, err)
	}
	for _, event := range page.Batches[0].Events {
		if event.Severity != want[event.ResourceID] {
			t.Fatalf("%s stored severity=%s, want %s", event.ResourceID, event.Severity, want[event.ResourceID])
		}
	}
	high, err := st.ListHistory(ctx, HistoryFilter{BatchID: batch.ID, Severity: "high"})
	if err != nil || len(high.Batches) != 1 || len(high.Batches[0].Events) != 4 {
		t.Fatalf("History high filter=%+v err=%v", high.Batches, err)
	}
	for _, event := range high.Batches[0].Events {
		if want[event.ResourceID] != "high" {
			t.Fatalf("History high filter returned %s", event.ResourceID)
		}
	}
	pager := batchDeliveries(t, st, batch.ID)[pagerID]
	for id, severity := range want {
		line := ""
		for _, candidate := range strings.Split(pager, "\n") {
			if strings.Contains(candidate, "**"+id+"**") {
				line = candidate
			}
		}
		switch {
		case severity == "high" && !strings.HasPrefix(strings.TrimLeft(line, "- "), "🔴"):
			t.Fatalf("high-only digest line for %s=%q, want a high-severity line:\n%s", id, line, pager)
		case severity == "medium" && line != "":
			t.Fatalf("high-only digest included medium %s:\n%s", id, pager)
		}
	}
}

// TestTagMuteNeverHidesTagging is R-057: a tag rule mutes noise on devices
// that keep a muted tag, and devices created or removed with it, but never
// a change to a device's tags: re-tagging out of the muted tag or into it
// is notified (and high).
func TestTagMuteNeverHidesTagging(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMuteRule(ctx, MuteTag, "tag:ci"); err != nil {
		t.Fatal(err)
	}
	digest := notify.Context{Tailnet: "example.com"}.Digest
	device := func(id, version string, tags ...any) model.Resource {
		return model.Resource{ID: id, Type: "device", Name: id, Data: map[string]any{"name": id, "clientVersion": version, "tags": tags}}
	}
	devices := func(resources ...model.Resource) []model.Collected {
		return []model.Collected{{Collector: "devices", Resources: resources}}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, devices(device("retagged", "1", "tag:ci"), device("runner", "1", "tag:ci"), device("prod", "1", "tag:prod"), device("leaver", "1", "tag:ci")), digest); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ApplyBatchWithBatch(ctx, generation, devices(device("retagged", "1", "tag:prod"), device("runner", "2", "tag:ci"), device("prod", "1", "tag:ci"), device("leaver", "1", "tag:ci"), device("joiner", "1", "tag:ci")), digest)
	if err != nil {
		t.Fatal(err)
	}
	wantMuted := map[string]bool{"retagged": false, "prod": false, "runner": true, "joiner": true}
	page, err := st.ListHistory(ctx, HistoryFilter{BatchID: batch.ID})
	if err != nil || len(page.Batches) != 1 || len(page.Batches[0].Events) != len(wantMuted) {
		t.Fatalf("history=%+v err=%v", page.Batches, err)
	}
	for _, event := range page.Batches[0].Events {
		if event.Muted != wantMuted[event.ResourceID] {
			t.Fatalf("%s muted=%v, want %v", event.ResourceID, event.Muted, wantMuted[event.ResourceID])
		}
		if event.ResourceID != "runner" && event.Severity != "high" {
			t.Fatalf("%s severity=%s, want high", event.ResourceID, event.Severity)
		}
	}
	payloads := pendingPayloads(t, st, batch.ID)
	if len(payloads) != 1 || !strings.Contains(payloads[0], "**retagged**") || !strings.Contains(payloads[0], "**prod**") || strings.Contains(payloads[0], "**runner**") || strings.Contains(payloads[0], "**joiner**") {
		t.Fatalf("digest=%q", payloads)
	}
	// A device removed while carrying the muted tag stays muted.
	remaining := devices(device("retagged", "1", "tag:prod"), device("runner", "2", "tag:ci"), device("prod", "1", "tag:ci"), device("joiner", "1", "tag:ci"))
	if _, err := st.ApplyBatchWithBatch(ctx, generation, remaining, digest); err != nil {
		t.Fatal(err)
	}
	removed, err := st.ApplyBatchWithBatch(ctx, generation, remaining, digest)
	if err != nil || len(removed.Changes) != 1 || removed.Changes[0].Kind != "removed" {
		t.Fatalf("removal batch=%+v err=%v", removed, err)
	}
	if payloads := pendingPayloads(t, st, removed.ID); len(payloads) != 0 {
		t.Fatalf("removed muted device was notified: %q", payloads)
	}
}
