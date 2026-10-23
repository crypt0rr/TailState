//go:build unix

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// nobodyID is the conventional unprivileged uid and gid. Tests that run as
// root use it as the foreign owner that compaction must not hand over.
const nobodyID = 65534

// ownerIDs is the numeric owner and group of a file.
type ownerIDs struct{ uid, gid int }

func ownerOf(t *testing.T, path string) ownerIDs {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, ok := fileOwner(info)
	if !ok {
		t.Fatalf("owner of %s is unavailable", path)
	}
	return ownerIDs{uid: uid, gid: gid}
}

// groupOtherThanEffective returns a supplementary group of this process other
// than its effective group, or the effective group when there is none.
func groupOtherThanEffective() int {
	groups, _ := os.Getgroups()
	for _, group := range groups {
		if group != os.Getegid() {
			return group
		}
	}
	return os.Getegid()
}

// TestCompactKeepsOwnerAndGroup proves that compaction replaces the database
// without changing its owner or group. A root run used to leave the rewritten
// database owned by root, which a systemd DynamicUser service could then not
// open. Run as root, the test first hands the database to another account, so
// the rule is exercised. Run as any other user the owner cannot be changed, so
// the test checks that it stays as it is, and TestCopyOwnerMatchesSourceFile
// covers the mechanism.
func TestCompactKeepsOwnerAndGroup(t *testing.T) {
	path, box := backupTestStore(t)
	if os.Geteuid() == 0 {
		if err := os.Chown(path, nobodyID, nobodyID); err != nil {
			t.Fatal(err)
		}
	}
	before := ownerOf(t, path)
	if _, err := Compact(context.Background(), path, box, CompactOptions{}); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if after := ownerOf(t, path); after != before {
		t.Fatalf("compaction changed the database owner from %+v to %+v", before, after)
	}
}

// TestCopyOwnerMatchesSourceFile tests the helper that compaction uses as root
// directly, so the rule is covered when the suite does not run as root. The
// source is handed to another owner (nobody when running as root) or to a
// group this user belongs to, and the copy must take both the owner and the
// group.
func TestCopyOwnerMatchesSourceFile(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	target := filepath.Join(dir, "target.db")
	for _, name := range []string{source, target} {
		if err := os.WriteFile(name, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid := os.Getuid(), groupOtherThanEffective()
	if os.Geteuid() == 0 {
		uid, gid = nobodyID, nobodyID
	}
	if err := os.Chown(source, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := copyOwner(source, target); err != nil {
		t.Fatalf("copyOwner: %v", err)
	}
	if got, want := ownerOf(t, target), ownerOf(t, source); got != want {
		t.Fatalf("copied owner %+v, want %+v", got, want)
	}
}
