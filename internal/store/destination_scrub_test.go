package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/secret"
)

// TestDeletedDestinationScrubsEncryptedURL asserts that deleting a
// destination removes its encrypted URL (including the freed page content)
// while History keeps the destination name for past deliveries, and that the
// scrubbed row does not break listing, rekey, or the master-key preflight.
func TestDeletedDestinationScrubsEncryptedURL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	leaked, err := st.SaveDestination(ctx, NotificationDestination{Name: "leaked hook", ServiceURL: "generic://hooks.example/path?token=leaked-token", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Later rows share the page, so the deleted cell's freed space is not
	// simply reclaimed by the shrunken row.
	for _, name := range []string{"after-1", "after-2", "after-3"} {
		if _, err := st.SaveDestination(ctx, NotificationDestination{Name: name, ServiceURL: "generic://" + name + ".example/path", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server", "100.64.0.1")}, func([]model.Change) string { return "baseline" }); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, []model.Collected{historyResource("server-new", "100.64.0.1")}, func([]model.Change) string { return "changed" }); err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE id=?", leaked).Scan(&ciphertext); err != nil || ciphertext == "" {
		t.Fatalf("ciphertext=%q err=%v", ciphertext, err)
	}
	checkpointedFile := func() []byte {
		t.Helper()
		var busy, logFrames, checkpointed int
		if err := st.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil || busy != 0 {
			t.Fatalf("checkpoint busy=%d err=%v", busy, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if !bytes.Contains(checkpointedFile(), []byte(ciphertext)) {
		t.Fatal("fixture ciphertext was not checkpointed into the database file")
	}
	if err := st.DeleteDestination(ctx, leaked); err != nil {
		t.Fatal(err)
	}
	var stored, name string
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc,name FROM notification_destinations WHERE id=?", leaked).Scan(&stored, &name); err != nil {
		t.Fatal(err)
	}
	if stored != "" || name != "leaked hook" {
		t.Fatalf("deleted destination service_url_enc=%q name=%q", stored, name)
	}
	// The shrunken row reuses part of the old cell, so look for any surviving
	// fragment rather than the full ciphertext.
	afterDelete := checkpointedFile()
	for i := 0; i+16 <= len(ciphertext); i += 8 {
		if bytes.Contains(afterDelete, []byte(ciphertext[i:i+16])) {
			t.Fatalf("deleted destination ciphertext fragment at offset %d remains in the database file", i)
		}
	}
	all, err := st.ListDestinations(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	foundDeleted := false
	for _, destination := range all {
		if destination.ID == leaked {
			foundDeleted = true
			if destination.ServiceURL != "" || destination.DeletedAt == nil {
				t.Fatalf("deleted destination listing=%+v", destination)
			}
		}
	}
	if !foundDeleted {
		t.Fatal("deleted destination missing from audit listing")
	}
	page, err := st.ListHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	labelled := false
	for _, batch := range page.Batches {
		for _, delivery := range batch.Deliveries {
			if delivery.DestinationID == leaked {
				labelled = delivery.Destination == "leaked hook"
			}
		}
	}
	if !labelled {
		t.Fatalf("history no longer names the deleted destination: %+v", page.Batches)
	}

	rotated, _ := secret.NewBox(bytes.Repeat([]byte{7}, 32))
	if err := st.Rekey(ctx, rotated); err != nil {
		t.Fatalf("rekey with a scrubbed deleted destination: %v", err)
	}
	if err := verifyLegacyMasterKey(st.db, rotated); err != nil {
		t.Fatalf("legacy master-key preflight with a scrubbed deleted destination: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path, rotated)
	if err != nil {
		t.Fatalf("reopen after rekey: %v", err)
	}
}

// TestSchemaV13MigrationScrubsDeletedDestinations upgrades a schema v12
// database through Open and asserts that destinations deleted before the
// upgrade lose their encrypted URL while active destinations keep theirs.
func TestSchemaV13MigrationScrubsDeletedDestinations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	active, err := st.SaveDestination(ctx, NotificationDestination{Name: "active", ServiceURL: "generic://active.example/path", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := st.SaveDestination(ctx, NotificationDestination{Name: "deleted", ServiceURL: "generic://deleted.example/path?token=old", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the pre-v13 soft delete, which kept the ciphertext.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE notification_destinations SET enabled=0,deleted_at=?,updated_at=? WHERE id=?", now, now, deleted); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE schema_version SET version=12"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var version int
	if err := st.db.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&version); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	var deletedEnc, activeEnc string
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE id=?", deleted).Scan(&deletedEnc); err != nil || deletedEnc != "" {
		t.Fatalf("deleted destination ciphertext=%q err=%v", deletedEnc, err)
	}
	if err := st.db.QueryRowContext(ctx, "SELECT service_url_enc FROM notification_destinations WHERE id=?", active).Scan(&activeEnc); err != nil || activeEnc == "" {
		t.Fatalf("active destination ciphertext=%q err=%v", activeEnc, err)
	}
	list, err := st.ListDestinations(ctx)
	if err != nil || len(list) != 1 || list[0].ServiceURL != "generic://active.example/path" {
		t.Fatalf("active destinations=%+v err=%v", list, err)
	}
}

func TestSchemaV12ToV13ReportsErrors(t *testing.T) {
	missing := currentSchemaMigrationDB(t, 12)
	if _, err := missing.Exec("DROP TABLE notification_destinations"); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchemaV12ToV13(missing); err == nil || !strings.Contains(err.Error(), "scrub deleted notification destinations") {
		t.Fatalf("missing destinations migration error=%v", err)
	}
	closed := currentSchemaMigrationDB(t, 12)
	closed.Close()
	if err := migrateSchemaV12ToV13(closed); err == nil || !strings.Contains(err.Error(), "persistence hardening migration") {
		t.Fatalf("closed database migration error=%v", err)
	}
	box, _ := secret.NewBox(make([]byte, 32))
	dispatched := currentSchemaMigrationDB(t, 12)
	if _, err := dispatched.Exec("DROP TABLE notification_destinations"); err != nil {
		t.Fatal(err)
	}
	if err := migrateSchema(dispatched, box); err == nil || !strings.Contains(err.Error(), "scrub deleted notification destinations") {
		t.Fatalf("dispatched migration error=%v", err)
	}
}
