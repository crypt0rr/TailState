package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

func usersHistory(t *testing.T, st *store.Store) []store.HistoryEvent {
	t.Helper()
	page, err := st.ListHistory(context.Background(), store.HistoryFilter{Collector: "users", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var events []store.HistoryEvent
	for _, batch := range page.Batches {
		events = append(events, batch.Events...)
	}
	return events
}

// TestUpgradeAbsorbsSharedUsersSilently simulates an installation whose users
// baseline was collected by a version that requested members only. The first
// users?type=all poll must not send one created event per pre-existing shared
// user, while a member added in the same poll and a shared user added later
// are still reported.
func TestUpgradeAbsorbsSharedUsersSilently(t *testing.T) {
	ctx := context.Background()
	st, settings, db := monitorTestStoreWithDB(t)
	var body atomic.Value
	var sawTypeAll atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/users":
			if r.URL.Query().Get("type") == "all" {
				sawTypeAll.Store(true)
			}
			_, _ = w.Write([]byte(body.Load().(string)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})

	// Pre-upgrade baseline: members only, and no shared-scope marker.
	body.Store(`{"users":[{"id":"m1","loginName":"alice@example.com","type":"member","role":"admin"}]}`)
	if !engine.poll(ctx, client, settings, []string{"users"}, true) {
		t.Fatal("baseline poll failed")
	}
	if !sawTypeAll.Load() {
		t.Fatal("users collector did not request type=all")
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM meta WHERE key='users_shared_scope_generation'"); err != nil {
		t.Fatal(err)
	}

	// First poll after upgrade: two existing shared users become visible and
	// one member was genuinely added.
	body.Store(`{"users":[
		{"id":"m1","loginName":"alice@example.com","type":"member","role":"admin"},
		{"id":"m2","loginName":"bob@example.com","type":"member","role":"member"},
		{"id":"s1","loginName":"ext1@other.example","type":"shared","role":"member"},
		{"id":"s2","loginName":"ext2@other.example","type":"shared","role":"member"}]}`)
	if !engine.poll(ctx, client, settings, []string{"users"}, true) {
		t.Fatal("upgrade poll failed")
	}
	events := usersHistory(t, st)
	if len(events) != 1 || events[0].ResourceID != "m2" || events[0].EventType != "created" {
		t.Fatalf("upgrade poll events=%#v, want only the new member", events)
	}
	var shared int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM snapshots WHERE generation=? AND collector='users' AND resource_id IN ('s1','s2') AND CAST(canonical_json AS TEXT) LIKE '%\"shared\"%'", settings.Generation).Scan(&shared); err != nil {
		t.Fatal(err)
	}
	if shared != 2 {
		t.Fatalf("shared users in inventory=%d, want 2 with type=shared", shared)
	}

	// A newly shared user after the upgrade produces exactly one event.
	body.Store(`{"users":[
		{"id":"m1","loginName":"alice@example.com","type":"member","role":"admin"},
		{"id":"m2","loginName":"bob@example.com","type":"member","role":"member"},
		{"id":"s1","loginName":"ext1@other.example","type":"shared","role":"member"},
		{"id":"s2","loginName":"ext2@other.example","type":"shared","role":"member"},
		{"id":"s3","loginName":"ext3@other.example","type":"shared","role":"member"}]}`)
	if !engine.poll(ctx, client, settings, []string{"users"}, true) {
		t.Fatal("post-upgrade poll failed")
	}
	events = usersHistory(t, st)
	created := 0
	for _, event := range events {
		if event.ResourceID == "s3" && event.EventType == "created" {
			created++
		}
	}
	if len(events) != 2 || created != 1 {
		t.Fatalf("post-upgrade events=%#v, want one created event for s3", events)
	}
}

// TestFreshInstallReportsSharedUsersAfterBaseline checks that a new
// installation (which records the shared-scope marker with its baseline)
// reports a newly shared user on the very next poll.
func TestFreshInstallReportsSharedUsersAfterBaseline(t *testing.T) {
	ctx := context.Background()
	st, settings := monitorTestStore(t)
	var body atomic.Value
	body.Store(`{"users":[{"id":"m1","type":"member"},{"id":"s1","type":"shared"}]}`)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case "/api/v2/tailnet/-/users":
			_, _ = w.Write([]byte(body.Load().(string)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	client := tailscale.New(api.URL+"/api/v2", api.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret"})
	engine := New(st, api.URL+"/api/v2", api.URL+"/oauth/token", "test", &scriptedSender{})
	if !engine.poll(ctx, client, settings, []string{"users"}, true) {
		t.Fatal("baseline poll failed")
	}
	if events := usersHistory(t, st); len(events) != 0 {
		t.Fatalf("baseline produced events: %#v", events)
	}
	body.Store(`{"users":[{"id":"m1","type":"member"},{"id":"s1","type":"shared"},{"id":"s2","type":"shared"}]}`)
	if !engine.poll(ctx, client, settings, []string{"users"}, true) {
		t.Fatal("second poll failed")
	}
	events := usersHistory(t, st)
	if len(events) != 1 || events[0].ResourceID != "s2" || events[0].EventType != "created" {
		t.Fatalf("new shared user events=%#v, want one created event", events)
	}
}
