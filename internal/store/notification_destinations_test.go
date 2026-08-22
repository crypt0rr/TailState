package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestNotificationDestinationFanoutAndDisable(t *testing.T) {
	ctx := context.Background()
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(filepath.Join(t.TempDir(), "tailstate.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	second, err := st.SaveDestination(ctx, NotificationDestination{Name: "backup", ServiceURL: "generic://backup.example/path", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "payload"); err != nil {
		t.Fatal(err)
	}
	items, err := testDueOutbox(st, ctx, 10)
	if err != nil || len(items) != 2 {
		t.Fatalf("expected two destination rows, got %d: %v", len(items), err)
	}
	if items[0].Destination.ServiceURL == "" || strings.Contains(items[0].Destination.ServiceURL, "enc") {
		t.Fatalf("destination URL was not decrypted: %#v", items[0].Destination)
	}
	if err := st.SetDestinationEnabled(ctx, second, false); err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Pending != 1 || status.Dead != 1 || status.EnabledDestinations != 1 {
		t.Fatalf("unexpected status after disable: %#v", status)
	}
	if err := st.EnqueueSystem(ctx, "future"); err != nil {
		t.Fatal(err)
	}
	items, err = testDueOutbox(st, ctx, 10)
	if err != nil || len(items) != 2 {
		t.Fatalf("expected one old and one future row, got %d: %v", len(items), err)
	}
}

func TestDestinationLifecycleDoesNotAllowLateDeliveryBookkeeping(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations=%#v err=%v", destinations, err)
	}
	destinationID := destinations[0].ID

	if err := st.EnqueueSystem(ctx, "disable race"); err != nil {
		t.Fatal(err)
	}
	items, err := testDueOutbox(st, ctx, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("outbox=%#v err=%v", items, err)
	}
	if err := st.SetDestinationEnabled(ctx, destinationID, false); err != nil {
		t.Fatal(err)
	}
	// Simulate a sender completing after the destination lifecycle transaction
	// has dead-lettered the pending row.
	if err := testDelivered(st, ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := testRetry(st, ctx, items[0].ID, time.Now().UTC().Add(time.Minute), "late sender failure", false); err != nil {
		t.Fatal(err)
	}
	var status, lastError string
	if err := st.db.QueryRowContext(ctx, "SELECT status,last_error FROM outbox WHERE id=?", items[0].ID).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || lastError != "destination disabled" {
		t.Fatalf("late bookkeeping changed disabled row: status=%q last_error=%q", status, lastError)
	}

	if err := st.SetDestinationEnabled(ctx, destinationID, true); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "remove race"); err != nil {
		t.Fatal(err)
	}
	items, err = testDueOutbox(st, ctx, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("outbox after re-enable=%#v err=%v", items, err)
	}
	if err := st.DeleteDestination(ctx, destinationID); err != nil {
		t.Fatal(err)
	}
	if err := testDelivered(st, ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := testRetry(st, ctx, items[0].ID, time.Now().UTC().Add(time.Minute), "late sender failure", false); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT status,last_error FROM outbox WHERE id=?", items[0].ID).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || lastError != "destination removed" {
		t.Fatalf("late bookkeeping changed removed row: status=%q last_error=%q", status, lastError)
	}
}

func TestSecondMattermostDestinationDoesNotOverwriteTheFirst(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	first, err := st.SaveDestination(ctx, NotificationDestination{Name: "Mattermost", ServiceURL: "mattermost://TailState@chat.example/first", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.SaveDestination(ctx, NotificationDestination{Name: "Mattermost", ServiceURL: "mattermost://TailState@soc.example/second", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	destinations, err := st.ListDestinations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(destinations) != 2 {
		t.Fatalf("second destination overwrote the first: ids=%d/%d destinations=%#v", first, second, destinations)
	}
}

func TestDestinationUpdateReusesCiphertextWhenURLUnchanged(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	id, err := st.SaveDestination(ctx, NotificationDestination{Name: "primary", ServiceURL: "generic://example.invalid/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var before string
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE id=?", id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(ctx, NotificationDestination{ID: id, Name: "renamed", ServiceURL: "generic://example.invalid/hook", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE id=?", id).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("unchanged destination URL was re-encrypted")
	}
}

func TestEditingDeletedDestinationDoesNotResurrectIt(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	id, err := st.SaveDestination(ctx, NotificationDestination{Name: "primary", ServiceURL: "generic://example.invalid/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteDestination(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveDestination(ctx, NotificationDestination{ID: id, Name: "renamed", ServiceURL: "generic://example.invalid/new-hook", Enabled: true}); err == nil {
		t.Fatal("editing a deleted destination unexpectedly resurrected it")
	}
	active, err := st.ListDestinations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("deleted destination returned to active list: %#v", active)
	}
}

func TestLegacyMattermostMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, settings()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// Simulate a v1 database containing only its legacy setting and outbox.
	db, err := sqlOpen(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM notification_destinations; UPDATE schema_version SET version=1"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	st, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	destinations, err := st.ListDestinations(ctx)
	if err != nil || len(destinations) != 1 {
		t.Fatalf("migration destinations: %d %v", len(destinations), err)
	}
	if !strings.HasPrefix(destinations[0].ServiceURL, "mattermost://TailState@mattermost.example/x") {
		t.Fatalf("unexpected migrated URL: %s", destinations[0].ServiceURL)
	}
}

// Keep the migration test independent from the Store's single-connection
// setup while using the same SQLite driver.
func sqlOpen(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
}
