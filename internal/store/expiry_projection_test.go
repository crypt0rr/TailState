package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/expiry"
	"github.com/crypt0rr/tailstate/internal/secret"
)

func insertExpirySnapshot(tb testing.TB, st *Store, collector, id, name, raw string) {
	tb.Helper()
	if _, err := st.db.Exec(`INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,updated_at)
		VALUES(1,?,?,?,?,CAST(? AS BLOB),'hash',?)`, collector, id, collector, name, raw, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		tb.Fatal(err)
	}
}

func expiryJSON(tb testing.TB, data map[string]any) string {
	tb.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		tb.Fatal(err)
	}
	return string(raw)
}

func expiryItemsFrom(tb testing.TB, load func(context.Context, int64, string) ([]SnapshotRecord, error), filter []string) []expiry.Item {
	tb.Helper()
	convert := func(collector string) []expiry.Snapshot {
		records, err := load(context.Background(), 1, collector)
		if err != nil {
			tb.Fatal(err)
		}
		out := make([]expiry.Snapshot, 0, len(records))
		for _, record := range records {
			out = append(out, expiry.Snapshot{ID: record.ResourceID, Name: record.Name, Raw: record.Raw})
		}
		return out
	}
	return expiry.Items(convert("devices"), convert("keys"), filter)
}

// TestExpirySnapshotsMatchFullSnapshots guards R-073: projecting the expiry
// fields in SQL yields exactly the items that decoding the full snapshots
// does, including every exclusion and name fallback, and a large snapshot's
// projection stays small.
func TestExpirySnapshotsMatchFullSnapshots(t *testing.T) {
	st := testStore(t)
	expires := time.Now().UTC().Add(5 * 24 * time.Hour).Format(time.RFC3339)
	padding := strings.Repeat("x", 64<<10)
	for _, device := range []struct {
		id, name string
		data     map[string]any
	}{
		{"tagged", "tagged", map[string]any{"expires": expires, "tags": []any{"tag:Server", "tag:a", "tag:a"}, "keyExpiryDisabled": false, "padding": padding}},
		{"disabled", "disabled", map[string]any{"expires": expires, "keyExpiryDisabled": true}},
		{"ephemeral", "ephemeral", map[string]any{"expires": expires, "isEphemeral": true}},
		{"string-flag", "string-flag", map[string]any{"expires": expires, "keyExpiryDisabled": "true"}},
		{"hostname-only", "", map[string]any{"expires": expires, "hostname": "host-a", "name": ""}},
		{"name-field", "", map[string]any{"expires": expires, "name": "named.example.ts.net", "hostname": "host-b"}},
		{"unnamed", "", map[string]any{"expires": expires}},
		{"zero", "zero", map[string]any{"expires": "0001-01-01T00:00:00Z"}},
		{"missing", "missing", map[string]any{"name": "no expiry"}},
		{"numeric-expiry", "numeric-expiry", map[string]any{"expires": 12345}},
		{"unicode", "unicode", map[string]any{"expires": expires, "tags": []any{"tag:é \"quoted\""}}},
	} {
		insertExpirySnapshot(t, st, "devices", device.id, device.name, expiryJSON(t, device.data))
	}
	for id, raw := range map[string]string{"broken": "not json", "array": "[]", "null": "null", "empty": ""} {
		insertExpirySnapshot(t, st, "devices", id, id, raw)
		insertExpirySnapshot(t, st, "keys", "k-"+id, "", raw)
	}
	createTags := map[string]any{"devices": map[string]any{"create": map[string]any{"tags": []any{"tag:ci"}}}}
	for id, data := range map[string]map[string]any{
		"k-auth":         {"keyType": "auth", "description": "ci enrolment", "expires": expires, "capabilities": createTags, "tags": []any{"tag:extra"}},
		"k-legacy":       {"expires": expires},
		"k-api":          {"keyType": "api", "expires": expires},
		"k-revoked":      {"keyType": "auth", "expires": expires, "revoked": time.Now().UTC().Format(time.RFC3339)},
		"k-bad-revoked":  {"keyType": "auth", "expires": expires, "revoked": "yes"},
		"k-zero-revoked": {"keyType": "auth", "expires": expires, "revoked": "0001-01-01T00:00:00Z"},
		"k-null-revoked": {"keyType": "auth", "expires": expires, "revoked": nil},
		"k-invalid":      {"keyType": "auth", "expires": expires, "invalid": true},
		"k-odd-caps":     {"keyType": "auth", "expires": expires, "capabilities": map[string]any{"devices": []any{"create"}}},
		"k-padded":       {"keyType": "auth", "expires": expires, "description": "padded", "padding": padding},
	} {
		insertExpirySnapshot(t, st, "keys", id, "stored-"+id, expiryJSON(t, data))
	}
	// A truncated snapshot holds only a size marker and is skipped by both.
	if _, err := st.db.Exec("UPDATE snapshots SET content_truncated=1 WHERE resource_id='k-api'"); err != nil {
		t.Fatal(err)
	}
	for _, filter := range [][]string{nil, {" tag:server ", "tag:ci"}, {"tag:extra"}, {"tag:none"}} {
		full := expiryItemsFrom(t, st.CollectorSnapshots, filter)
		projected := expiryItemsFrom(t, st.ExpirySnapshots, filter)
		if !reflect.DeepEqual(full, projected) {
			t.Fatalf("filter %q: projected items differ\nfull=%#v\nprojected=%#v", filter, full, projected)
		}
		if filter == nil && len(full) != 12 {
			t.Fatalf("fixture produced %d items: %#v", len(full), full)
		}
	}
	records, err := st.ExpirySnapshots(context.Background(), 1, "devices")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if len(record.Raw) > 1024 {
			t.Fatalf("projection of %s is %d bytes", record.ResourceID, len(record.Raw))
		}
	}
}

// BenchmarkExpiryCardSnapshots measures one status render's expiry card
// reads over 10k device and 10k key snapshots, each carrying 4 KiB of
// fields the card never reads. "projected" is the path the card uses.
func BenchmarkExpiryCardSnapshots(b *testing.B) {
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(filepath.Join(b.TempDir(), "tailstate.db"), box)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	expires := time.Now().UTC().Add(5 * 24 * time.Hour).Format(time.RFC3339)
	padding := strings.Repeat("p", 4<<10)
	tx, err := st.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	for i := range 10000 {
		device := expiryJSON(b, map[string]any{"expires": expires, "tags": []any{"tag:server"}, "hostname": fmt.Sprintf("host-%d", i), "padding": padding})
		key := expiryJSON(b, map[string]any{"keyType": "auth", "expires": expires, "description": fmt.Sprintf("key-%d", i), "padding": padding})
		for _, row := range [][2]string{{"devices", device}, {"keys", key}} {
			if _, err := tx.Exec(`INSERT INTO snapshots(generation,collector,resource_id,resource_type,name,canonical_json,content_hash,updated_at)
				VALUES(1,?,?,?,'',CAST(? AS BLOB),'hash','2026-01-01T00:00:00Z')`, row[0], fmt.Sprintf("%s-%d", row[0], i), row[0], row[1]); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	for _, path := range []struct {
		name string
		load func(context.Context, int64, string) ([]SnapshotRecord, error)
	}{{"full", st.CollectorSnapshots}, {"projected", st.ExpirySnapshots}} {
		b.Run(path.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if items := expiryItemsFrom(b, path.load, nil); len(items) != 20000 {
					b.Fatalf("items=%d", len(items))
				}
			}
		})
	}
}
