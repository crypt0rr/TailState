package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// TestRevokedCredentialsSendOneGroupedHealthMessagePerDestination is the
// E-010 storm guarantee: when the OAuth credential is revoked, every
// collector that crosses the failure threshold in the same poll is reported
// in one "unhealthy" message per destination with the bounded reason
// "auth rejected", and recovery is likewise one grouped message.
func TestRevokedCredentialsSendOneGroupedHealthMessagePerDestination(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Second", ServiceURL: "generic://notify.example/hook", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 2 {
		t.Fatalf("destinations=%d err=%v", len(destinations), err)
	}
	var revoked atomic.Bool
	revoked.Store(true)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			if revoked.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client SECRET-DETAIL"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		switch r.URL.Path {
		case "/api/v2/tailnet/-/devices":
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test")
	engine.ConfigureNotifications("lab", "https://tailstate.example")
	collectors := []string{"devices", "users", "dns"}
	for i := 0; i < 4; i++ {
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		if engine.poll(ctx, client, settings, collectors, true) {
			t.Fatalf("poll %d with a revoked credential succeeded", i+1)
		}
	}
	var payloads []string
	rows, err := db.QueryContext(ctx, "SELECT destination_id,payload_format,payload FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	perDestination := map[int64]int{}
	for rows.Next() {
		var destination int64
		var format, stored string
		if err := rows.Scan(&destination, &format, &stored); err != nil {
			t.Fatal(err)
		}
		payload, err := notify.Prepare(format, stored, "generic://notify.example", "")
		if err != nil {
			t.Fatal(err)
		}
		perDestination[destination]++
		payloads = append(payloads, payload)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 || len(perDestination) != 2 {
		t.Fatalf("revocation queued %d messages for %d destinations, want one per destination: %q", len(payloads), len(perDestination), payloads)
	}
	for _, payload := range payloads {
		for _, want := range []string{"collectors unhealthy", "lab (default tailnet)", "`devices`: auth rejected", "`users`: auth rejected", "`dns`: auth rejected", "Observed at ", "https://tailstate.example/status"} {
			if !strings.Contains(payload, want) {
				t.Fatalf("grouped health message missing %q:\n%s", want, payload)
			}
		}
		if strings.Contains(payload, "SECRET-DETAIL") {
			t.Fatalf("provider error text leaked into the health message:\n%s", payload)
		}
	}

	revoked.Store(false)
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine.poll(ctx, client, settings, collectors, true)
	var recovered int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE payload LIKE '%collectors recovered%'").Scan(&recovered); err != nil {
		t.Fatal(err)
	}
	if recovered != 2 {
		t.Fatalf("recovery queued %d grouped messages, want one per destination", recovered)
	}
	var total int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox").Scan(&total); err != nil || total != 4 {
		t.Fatalf("outbox rows=%d err=%v, want 4", total, err)
	}
}

// renderedOutbox returns the generic rendering of every queued message.
func renderedOutbox(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "SELECT payload_format,payload FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var format, stored string
		if err := rows.Scan(&format, &stored); err != nil {
			t.Fatal(err)
		}
		payload, err := notify.Prepare(format, stored, "generic://notify.example", "")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, payload)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestBaselinedCollectorConfirmedUnsupportedIsNotified is R-056: a
// baselined collector that answers 403 on two consecutive polls queues
// exactly one health message with reason "unsupported", further 403s queue
// nothing, and its recovery queues exactly one recovery message. A
// collector that never had a baseline is demoted silently.
func TestBaselinedCollectorConfirmedUnsupportedIsNotified(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations=%d err=%v", len(destinations), err)
	}
	fake := &fakeTailnetAPI{responses: map[string]string{"/api/v2/tailnet/-/acl": `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`}}
	grant := func(scopes ...string) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		fake.granted = map[string]bool{}
		for _, scope := range scopes {
			fake.granted[scope] = true
		}
	}
	grant("policy_file:read")
	server := httptest.NewServer(fake)
	defer server.Close()
	client := tailscale.New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, server.URL+"/api/v2", server.URL+"/oauth/token", "test")
	engine.ConfigureNotifications("lab", "")
	collectors := []string{"policy", "webhooks"}
	poll := func() {
		t.Helper()
		if !engine.poll(ctx, client, settings, collectors, true) {
			t.Fatal("poll with unsupported collectors failed")
		}
	}
	poll()
	poll()
	if queued := renderedOutbox(t, db); len(queued) != 0 {
		t.Fatalf("baseline and a never-baselined unsupported collector queued %q", queued)
	}

	grant()
	poll()
	if queued := renderedOutbox(t, db); len(queued) != 0 {
		t.Fatalf("the first 403 of a baselined collector queued %q", queued)
	}
	poll()
	poll()
	queued := renderedOutbox(t, db)
	if len(queued) != 1 {
		t.Fatalf("confirmed unsupported collector queued %d messages, want 1: %q", len(queued), queued)
	}
	for _, want := range []string{"collector unhealthy", "1 collector needs attention", "`policy`: unsupported (insufficient OAuth scope or plan: HTTP 403 on two consecutive polls"} {
		if !strings.Contains(queued[0], want) {
			t.Fatalf("unsupported notice lacks %q:\n%s", want, queued[0])
		}
	}
	if strings.Contains(queued[0], "webhooks") {
		t.Fatalf("a never-baselined collector was reported:\n%s", queued[0])
	}

	grant("policy_file:read")
	poll()
	poll()
	queued = renderedOutbox(t, db)
	if len(queued) != 2 || !strings.Contains(queued[1], "collector recovered") || !strings.Contains(queued[1], "`policy`") {
		t.Fatalf("recovery queued %q, want one recovery message", queued)
	}
}

// TestMassRemovalGuardIsNotifiedAndRemovalsAttributed is R-070: removing 5
// of 8 keys engages the mass-removal guard, which queues one health notice
// on the first guarded poll (not on the next guarded one), and the removed
// events recorded after the guard releases are attributed to the DELETE
// audit entries made before the guard engaged.
func TestMassRemovalGuardIsNotifiedAndRemovalsAttributed(t *testing.T) {
	ctx := context.Background()
	api, client, engine, st, settings, path := newAuditTailnet(t)
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	keys := func(count int) string {
		items := make([]string, 0, count)
		for index := 1; index <= count; index++ {
			items = append(items, fmt.Sprintf(`{"id":"k%d","description":"key %d","keyType":"auth"}`, index, index))
		}
		return `{"keys":[` + strings.Join(items, ",") + `]}`
	}
	poll := func() store.ChangeBatchResult {
		t.Helper()
		if !engine.poll(ctx, client, settings, []string{"keys"}, true) {
			t.Fatal("keys poll failed")
		}
		page, err := st.ListHistory(ctx, store.HistoryFilter{Collector: "keys"})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Batches) == 0 {
			return store.ChangeBatchResult{}
		}
		return store.ChangeBatchResult{ChangeBatch: store.ChangeBatch{ID: page.Batches[0].ID}}
	}
	api.set("/api/v2/tailnet/-/keys", keys(8))
	poll()
	// The previous successful poll was an hour ago, and the keys were
	// deleted ten minutes after it.
	previous := time.Now().UTC().Add(-time.Hour)
	if _, err := db.ExecContext(ctx, "UPDATE collector_state SET last_success=? WHERE collector='keys'", previous.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	deleted := previous.Add(10 * time.Minute).Format(time.RFC3339Nano)
	logs := make([]string, 0, 5)
	for index := 4; index <= 8; index++ {
		logs = append(logs, fmt.Sprintf(`{"eventTime":%q,"type":"CONFIG","origin":"ADMIN_CONSOLE","actor":{"id":"uAlice","type":"USER","loginName":"alice@example.com"},"target":{"id":"k%d","type":"API_KEY"},"action":"DELETE"}`, deleted, index))
	}
	api.setBody(`{"version":"1.1","tailnet":"example.com","logs":[` + strings.Join(logs, ",") + `]}`)
	api.set("/api/v2/tailnet/-/keys", keys(3))

	guardNotices := func() int {
		count := 0
		for _, payload := range renderedOutbox(t, db) {
			if strings.Contains(payload, "possible mass removal") {
				count++
			}
		}
		return count
	}
	poll()
	if got := guardNotices(); got != 1 {
		t.Fatalf("first guarded poll queued %d guard notices, want 1: %q", got, renderedOutbox(t, db))
	}
	if queued := renderedOutbox(t, db); !strings.Contains(queued[0], "`keys`: possible mass removal (5 of 8 resources missing") {
		t.Fatalf("guard notice:\n%s", queued[0])
	}
	poll()
	if got := guardNotices(); got != 1 {
		t.Fatalf("second guarded poll queued another notice (%d)", got)
	}
	poll()
	removed := poll()
	page, err := st.ListHistory(ctx, store.HistoryFilter{BatchID: removed.ID})
	if err != nil || len(page.Batches) != 1 || len(page.Batches[0].Events) != 5 {
		t.Fatalf("removal batch=%+v err=%v", page.Batches, err)
	}
	for _, event := range page.Batches[0].Events {
		if event.EventType != "removed" || event.ChangedBy != "alice@example.com via admin console" {
			t.Fatalf("removed %s changed by %q (%s), want the DELETE entry's actor", event.ResourceID, event.ChangedBy, event.EventType)
		}
	}
	if got := guardNotices(); got != 1 {
		t.Fatalf("guard notices=%d after the removal, want 1", got)
	}
	var markers int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM meta WHERE key LIKE 'removal_guard_since:%'").Scan(&markers); err != nil || markers != 0 {
		t.Fatalf("guard attribution markers=%d err=%v after the removals were recorded", markers, err)
	}
}

// queuedNotices counts the queued messages whose rendering contains title.
func queuedNotices(t *testing.T, db *sql.DB, title string) int {
	t.Helper()
	count := 0
	for _, payload := range renderedOutbox(t, db) {
		if strings.Contains(payload, title) {
			count++
		}
	}
	return count
}

// TestCollectorUnhealthyNoticeSurvivesCancelledPoll is the first probe of issue
// #315: the poll is cancelled after the failing collector has crossed the
// failure threshold on its third failing poll. The "unhealthy" notice must
// still be queued exactly once for that episode, and the failing polls that
// follow must not queue another.
func TestCollectorUnhealthyNoticeSurvivesCancelledPoll(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	var devicesDown atomic.Bool
	devicesDown.Store(true)
	var (
		mu       sync.Mutex
		stopPoll context.CancelFunc
	)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		switch r.URL.Path {
		case "/api/v2/tailnet/-/devices":
			if devicesDown.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
		case "/api/v2/tailnet/-/users":
			mu.Lock()
			stop := stopPoll
			mu.Unlock()
			if stop != nil {
				// The shutdown arrives while the users request is in flight, after
				// devices has failed for the third time. The request is held until
				// the client gives up on it.
				stop()
				<-r.Context().Done()
				return
			}
			_, _ = w.Write([]byte(`{"users":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test")
	engine.ConfigureNotifications("lab", "")
	collectors := []string{"devices", "users"}
	poll := func(pollCtx context.Context) bool {
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		return engine.poll(pollCtx, client, settings, collectors, true)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if poll(ctx) {
			t.Fatalf("failing poll %d succeeded", attempt)
		}
	}
	pollCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	mu.Lock()
	stopPoll = cancel
	mu.Unlock()
	if poll(pollCtx) {
		t.Fatal("cancelled poll succeeded")
	}
	mu.Lock()
	stopPoll = nil
	mu.Unlock()
	if got := queuedNotices(t, db, "collector unhealthy"); got != 1 {
		t.Fatalf("cancelled third failing poll queued %d unhealthy notices, want 1: %q", got, renderedOutbox(t, db))
	}
	for attempt := 1; attempt <= 2; attempt++ {
		poll(ctx)
	}
	if got := queuedNotices(t, db, "collector unhealthy"); got != 1 {
		t.Fatalf("later failing polls of the same episode left %d unhealthy notices, want 1", got)
	}
	devicesDown.Store(false)
	if !poll(ctx) {
		t.Fatal("recovery poll failed")
	}
	if got := queuedNotices(t, db, "collector recovered"); got != 1 {
		t.Fatalf("recovery queued %d recovered notices, want 1", got)
	}
}

// TestFailedApplyBatchDoesNotSendRecoveredNotice is the second probe of issue
// #315: when ApplyBatch cannot commit the poll that would recover a collector,
// the collector stays unhealthy and no "recovered" notice is queued. The next
// poll that stores its results queues exactly one.
func TestFailedApplyBatchDoesNotSendRecoveredNotice(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	var devicesDown atomic.Bool
	devicesDown.Store(true)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
			return
		}
		if r.URL.Path != "/api/v2/tailnet/-/devices" {
			http.NotFound(w, r)
			return
		}
		if devicesDown.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[{"id":"device-1","hostname":"server"}]}`))
	}))
	defer api.Close()
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test")
	engine.ConfigureNotifications("lab", "")
	collectors := []string{"devices"}
	poll := func() bool {
		client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
		return engine.poll(ctx, client, settings, collectors, true)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if poll() {
			t.Fatalf("failing poll %d succeeded", attempt)
		}
	}
	if got := queuedNotices(t, db, "collector unhealthy"); got != 1 {
		t.Fatalf("third failing poll queued %d unhealthy notices, want 1", got)
	}

	// Refuse the collector state writes of the batch that would recover devices,
	// so ApplyBatch aborts and the collector must stay unhealthy.
	if _, err := db.ExecContext(ctx, "CREATE TRIGGER refuse_collector_state BEFORE UPDATE ON collector_state BEGIN SELECT RAISE(ABORT, 'refused'); END"); err != nil {
		t.Fatal(err)
	}
	devicesDown.Store(false)
	if poll() {
		t.Fatal("poll whose batch was refused reported success")
	}
	if got := queuedNotices(t, db, "collector recovered"); got != 0 {
		t.Fatalf("refused batch queued %d recovered notices, want none", got)
	}
	if unhealthy, err := st.CollectorWasUnhealthyWithError(ctx, settings.Generation, "devices"); err != nil || !unhealthy {
		t.Fatalf("refused batch cleared the unhealthy state: unhealthy=%v err=%v", unhealthy, err)
	}
	if _, err := db.ExecContext(ctx, "DROP TRIGGER refuse_collector_state"); err != nil {
		t.Fatal(err)
	}
	if !poll() {
		t.Fatal("recovery poll failed")
	}
	if got := queuedNotices(t, db, "collector recovered"); got != 1 {
		t.Fatalf("recovery queued %d recovered notices, want 1", got)
	}
	if got := queuedNotices(t, db, "collector unhealthy"); got != 1 {
		t.Fatalf("recovery left %d unhealthy notices in total, want 1", got)
	}
}
