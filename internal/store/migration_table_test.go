package store

import "testing"

// TestMigrationTableIsContiguous keeps the migration table a single upgrade
// path: every step advances one version, steps are ordered, and the last
// step reaches the version new databases are created with.
func TestMigrationTableIsContiguous(t *testing.T) {
	if len(migrations) == 0 || migrations[0].from != 1 {
		t.Fatalf("the upgrade path must start at schema version 1: %+v", migrations)
	}
	for index, step := range migrations {
		if step.to != step.from+1 {
			t.Fatalf("step %d upgrades %d to %d; each step must advance one version", index, step.from, step.to)
		}
		if index > 0 && step.from != migrations[index-1].to {
			t.Fatalf("step %d starts at %d, after a step that ends at %d", index, step.from, migrations[index-1].to)
		}
		if step.apply == nil {
			t.Fatalf("step %d has no migration function", index)
		}
		if found, ok := migrationFrom(step.from); !ok || found.to != step.to {
			t.Fatalf("migrationFrom(%d) = %+v, %v", step.from, found, ok)
		}
	}
	if last := migrations[len(migrations)-1]; last.to != currentSchemaVersion {
		t.Fatalf("the last step reaches %d, not the current schema version %d", last.to, currentSchemaVersion)
	}
	if _, ok := migrationFrom(currentSchemaVersion); ok {
		t.Fatal("a migration starts at the current schema version")
	}
}
