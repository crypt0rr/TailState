package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestOpenReadOnlyMissingDatabaseDoesNotCreatePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenReadOnly(path, box); !errors.Is(err, ErrDatabaseNotFound) {
		t.Fatalf("OpenReadOnly error=%v, want ErrDatabaseNotFound", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only inspection created parent directory: %v", err)
	}
}

func TestOpenReadOnlyUsesConfiguredProfileAndPreservesDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := OpenWithLimits(path, box, StorageLimits{DatabaseBytes: 16 << 20})
	if err != nil {
		t.Fatalf("initial OpenWithLimits: %v", err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	configured := StorageLimits{DatabaseBytes: 32 << 20}
	inspectionStore, inspection, err := OpenReadOnly(path, box, configured)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	if inspection.SchemaVersion != currentSchemaVersion || !inspection.SchemaVersionPresent || inspection.SchemaMigrationPending {
		t.Fatalf("schema inspection=%#v", inspection)
	}
	if !inspection.PersistedStorageFound || inspection.PersistedStorageLimits.DatabaseBytes != 16<<20 {
		t.Fatalf("persisted profile=%#v found=%t", inspection.PersistedStorageLimits, inspection.PersistedStorageFound)
	}
	if inspection.ConfiguredStorageLimits.DatabaseBytes != 32<<20 || inspection.EffectiveStorageLimits.DatabaseBytes != 32<<20 {
		t.Fatalf("configured/effective profiles=%#v/%#v", inspection.ConfiguredStorageLimits, inspection.EffectiveStorageLimits)
	}
	if _, err := inspectionStore.Status(context.Background()); err != nil {
		t.Fatalf("read-only status: %v", err)
	}
	if err := inspectionStore.Close(); err != nil {
		t.Fatal(err)
	}
	inspectionStore, persistedInspection, err := OpenReadOnly(path, box)
	if err != nil {
		t.Fatalf("OpenReadOnly with persisted profile: %v", err)
	}
	if persistedInspection.EffectiveStorageLimits.DatabaseBytes != 16<<20 {
		t.Fatalf("effective persisted profile=%#v, want 16 MiB", persistedInspection.EffectiveStorageLimits)
	}
	metrics, err := inspectionStore.StorageMetrics(context.Background())
	if err != nil {
		t.Fatalf("read-only storage metrics: %v", err)
	}
	if metrics.DatabaseLimitBytes != 16<<20 {
		t.Fatalf("persisted database limit=%d, want %d", metrics.DatabaseLimitBytes, 16<<20)
	}
	if _, err := inspectionStore.store.db.ExecContext(context.Background(), "CREATE TABLE should_not_exist(id INTEGER)"); err == nil {
		t.Fatal("read-only store accepted a write")
	}
	if err := inspectionStore.Close(); err != nil {
		t.Fatal(err)
	}
	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(beforeBytes) != string(afterBytes) || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("read-only inspection changed the database file")
	}
}

func TestOpenReadOnlyRejectsInvalidTargetsWithoutMutation(t *testing.T) {
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tailstate.db")
	if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		path   string
		box    *secret.Box
		limits []StorageLimits
		want   string
	}{
		{name: "empty path", want: "database path is required"},
		{name: "missing key", path: path, want: "master key is required", box: nil},
		{name: "multiple profiles", path: path, box: box, limits: []StorageLimits{{}, {}}},
		{name: "directory target", path: t.TempDir(), box: box, want: "ping read-only database"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := OpenReadOnly(tt.path, tt.box, tt.limits...)
			if err == nil || (tt.want != "" && !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("OpenReadOnly error=%v, want %q", err, tt.want)
			}
		})
	}
}

func TestOpenReadOnlyRejectsWrongKeyWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	wrongBox, err := secret.NewBox(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenReadOnly(path, wrongBox); err == nil || !strings.Contains(err.Error(), "master key does not match") {
		t.Fatalf("wrong-key read-only error=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("wrong-key read-only inspection changed the database file")
	}
}

func TestOpenReadOnlyReportsOlderSchemaWithoutMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailstate.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(11)"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	inspectionStore, inspection, err := OpenReadOnly(path, box)
	if err != nil {
		t.Fatalf("OpenReadOnly older schema: %v", err)
	}
	if err := inspectionStore.Close(); err != nil {
		t.Fatal(err)
	}
	if inspection.SchemaVersion != 11 || !inspection.SchemaMigrationPending {
		t.Fatalf("older schema inspection=%#v", inspection)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("older-schema inspection migrated or changed the database")
	}
}
