package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
)

type recordingLookup struct {
	mu      sync.Mutex
	status  string
	entries []model.AuditEntry
	windows []AttributionWindow
}

func (r *recordingLookup) lookup(_ context.Context, window AttributionWindow) AttributionResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.windows = append(r.windows, window)
	return AttributionResult{Status: r.status, Entries: append([]model.AuditEntry(nil), r.entries...)}
}

func (r *recordingLookup) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.windows)
}

func attributedDevice(id, nodeID, name string, tags ...any) model.Resource {
	return model.Resource{ID: id, Type: "device", Name: name, Data: map[string]any{"id": id, "nodeId": nodeID, "name": name, "tags": tags}}
}

func nodeEntry(login, nodeID, action, property string, at time.Time) model.AuditEntry {
	return model.AuditEntry{EventTime: at, Origin: "ADMIN_CONSOLE", ActorType: "USER", ActorLogin: login, TargetType: "NODE", TargetID: nodeID, Action: action, Property: property}
}

func eventChangedBy(t *testing.T, st *Store, batchID int64) map[string]string {
	t.Helper()
	page, err := st.ListHistory(context.Background(), HistoryFilter{BatchID: batchID})
	if err != nil || len(page.Batches) != 1 {
		t.Fatalf("history batch %d: %v (%d batches)", batchID, err, len(page.Batches))
	}
	out := map[string]string{}
	for _, event := range page.Batches[0].Events {
		out[event.ResourceID] = event.ChangedBy
	}
	return out
}

// TestAttributionWindowCoversPollIntervalWithClockSkew pins the audit
// window: it starts at the previous successful poll of the affected
// collectors minus the clock-skew tolerance (and the polling interval for a
// removal, which is confirmed one poll after the resource went missing),
// ends at now plus the tolerance, and never exceeds 24 hours. Entries outside
// the window, or later than the tolerance after the observation, are not
// credited; an unchanged poll and an un-baselined collector never trigger a
// lookup.
func TestAttributionWindowCoversPollIntervalWithClockSkew(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	lookup := &recordingLookup{status: AttributionComplete}
	options := BatchOptions{Attribute: lookup.lookup, RemovalLookback: 5 * time.Minute}
	fleet := func(tags string, withSecond bool) []model.Collected {
		resources := []model.Resource{attributedDevice("d1", "n1", "db-01", tags)}
		if withSecond {
			resources = append(resources, attributedDevice("d2", "n2", "web-01"))
		}
		return []model.Collected{{Collector: "devices", Resources: resources}}
	}
	digest := notify.Context{}.Digest
	if _, err := st.ApplyBatchWithOptions(ctx, generation, fleet("tag:dev", true), digest, options); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithOptions(ctx, generation, fleet("tag:dev", true), digest, options); err != nil {
		t.Fatal(err)
	}
	if lookup.calls() != 0 {
		t.Fatalf("baseline or unchanged polls looked up the audit log %d times", lookup.calls())
	}

	previous := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	if _, err := st.db.Exec("UPDATE collector_state SET last_success=? WHERE collector='devices'", previous.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lookup.entries = []model.AuditEntry{
		nodeEntry("too-early", "n1", "UPDATE", "ACL_TAGS", previous.Add(-AttributionClockSkew-time.Second)),
		nodeEntry("skewed-before", "n1", "UPDATE", "ACL_TAGS", previous.Add(-time.Minute)),
		nodeEntry("skewed-after", "n1", "UPDATE", "ACL_TAGS", now.Add(time.Minute)),
		nodeEntry("too-late", "n1", "UPDATE", "ACL_TAGS", now.Add(AttributionClockSkew+time.Minute)),
	}
	changed, err := st.ApplyBatchWithOptions(ctx, generation, fleet("tag:prod", true), digest, options)
	if err != nil {
		t.Fatal(err)
	}
	window := lookup.windows[0]
	if !window.Start.Equal(previous.Add(-AttributionClockSkew)) {
		t.Fatalf("window start=%s, want previous success %s minus the skew", window.Start, previous)
	}
	if window.End.Before(now.Add(AttributionClockSkew)) || window.End.After(time.Now().Add(AttributionClockSkew)) {
		t.Fatalf("window end=%s, want now plus the skew", window.End)
	}
	if got := eventChangedBy(t, st, changed.ID)["d1"]; got != "skewed-after via admin console" {
		t.Fatalf("changed by=%q, want the latest entry within the skew tolerance", got)
	}
	lookup.entries = lookup.entries[:2]
	if _, err := st.db.Exec("UPDATE collector_state SET last_success=? WHERE collector='devices'", previous.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	changed, err = st.ApplyBatchWithOptions(ctx, generation, fleet("tag:dev", true), digest, options)
	if err != nil {
		t.Fatal(err)
	}
	if got := eventChangedBy(t, st, changed.ID)["d1"]; got != "skewed-before via admin console" {
		t.Fatalf("changed by=%q; an entry before the window start was credited", got)
	}

	// The first poll without d2 only counts it missing: no change, no lookup.
	calls := lookup.calls()
	if _, err := st.ApplyBatchWithOptions(ctx, generation, fleet("tag:dev", false), digest, options); err != nil {
		t.Fatal(err)
	}
	if lookup.calls() != calls {
		t.Fatal("a poll that only counted a resource missing looked up the audit log")
	}
	if _, err := st.db.Exec("UPDATE collector_state SET last_success=? WHERE collector='devices'", previous.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	lookup.entries = []model.AuditEntry{nodeEntry("remover", "n2", "DELETE", "", previous.Add(-4*time.Minute))}
	removed, err := st.ApplyBatchWithOptions(ctx, generation, fleet("tag:dev", false), digest, options)
	if err != nil || removed.ChangeCount != 1 || removed.Changes[0].Kind != "removed" {
		t.Fatalf("removal batch=%+v err=%v", removed, err)
	}
	window = lookup.windows[len(lookup.windows)-1]
	if !window.Start.Equal(previous.Add(-AttributionClockSkew - 5*time.Minute)) {
		t.Fatalf("removal window start=%s, want the removal lookback", window.Start)
	}
	if got := eventChangedBy(t, st, removed.ID)["d2"]; got != "remover via admin console" {
		t.Fatalf("removal changed by=%q", got)
	}

	// A long outage is bounded to MaxAttributionWindow.
	if _, err := st.db.Exec("UPDATE collector_state SET last_success=? WHERE collector='devices'", time.Now().Add(-72*time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithOptions(ctx, generation, fleet("tag:prod", false), digest, options); err != nil {
		t.Fatal(err)
	}
	window = lookup.windows[len(lookup.windows)-1]
	if span := window.End.Sub(window.Start); span != MaxAttributionWindow {
		t.Fatalf("window span=%s, want %s", span, MaxAttributionWindow)
	}

	// A collector without a baseline produces no change and no lookup.
	calls = lookup.calls()
	if _, err := st.ApplyBatchWithOptions(ctx, generation, []model.Collected{{Collector: "users", Resources: []model.Resource{{ID: "u1", Type: "user", Name: "alice", Data: map[string]any{"id": "u1"}}}}}, digest, options); err != nil {
		t.Fatal(err)
	}
	if lookup.calls() != calls {
		t.Fatal("an un-baselined collector looked up the audit log")
	}
}

// TestAttributionLookupFailuresNeverFailTheBatch records the batch when the
// lookup reports an unknown status, overruns its budget, or is unsupported:
// failures record "actor unknown" in History and "Attribution unavailable" in
// the digest, and unsupported renders nothing.
func TestAttributionLookupFailuresNeverFailTheBatch(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	digest := notify.Context{}.Digest
	tag := func(value string) []model.Collected {
		return []model.Collected{{Collector: "devices", Resources: []model.Resource{attributedDevice("d1", "n1", "db-01", value)}}}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, tag("a"), digest); err != nil {
		t.Fatal(err)
	}
	entry := nodeEntry("alice", "n1", "UPDATE", "ACL_TAGS", time.Now())
	for _, tc := range []struct {
		name   string
		lookup AttributionLookup
		status string
		want   string
	}{
		{name: "bogus status", lookup: func(context.Context, AttributionWindow) AttributionResult {
			return AttributionResult{Status: "weird", Entries: []model.AuditEntry{entry}}
		}, status: AttributionUnavailable, want: model.ActorUnknown},
		{name: "budget overrun", lookup: func(ctx context.Context, _ AttributionWindow) AttributionResult {
			<-ctx.Done()
			return AttributionResult{Status: AttributionComplete, Entries: []model.AuditEntry{entry}}
		}, status: AttributionUnavailable, want: model.ActorUnknown},
		{name: "unsupported", lookup: func(context.Context, AttributionWindow) AttributionResult {
			return AttributionResult{Status: AttributionUnsupported, Entries: []model.AuditEntry{entry}}
		}, status: AttributionUnsupported, want: ""},
		{name: "complete", lookup: func(context.Context, AttributionWindow) AttributionResult {
			return AttributionResult{Status: AttributionComplete, Entries: []model.AuditEntry{entry}}
		}, status: AttributionComplete, want: "alice via admin console"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := st.ApplyBatchWithOptions(ctx, generation, tag(tc.name), digest, BatchOptions{Attribute: tc.lookup, Budget: 50 * time.Millisecond})
			if err != nil || batch.ChangeCount != 1 {
				t.Fatalf("batch=%+v err=%v", batch, err)
			}
			if batch.AttributionStatus != tc.status {
				t.Fatalf("status=%q, want %q", batch.AttributionStatus, tc.status)
			}
			if got := eventChangedBy(t, st, batch.ID)["d1"]; got != tc.want {
				t.Fatalf("changed by=%q, want %q", got, tc.want)
			}
			payloads := pendingPayloads(t, st, batch.ID)
			// The digest states the lookup outcome in its header and names
			// only known actors; History keeps "actor unknown".
			header := map[string]string{AttributionUnavailable: "\nAttribution unavailable\n", AttributionComplete: "\nAttributed: 1 of 1 change\n"}[tc.status]
			if len(payloads) != 1 || strings.Contains(payloads[0], model.ActorUnknown) || strings.Contains(payloads[0], "Attribut") != (header != "") || !strings.Contains(payloads[0], header) || strings.Contains(payloads[0], "changed by alice via admin console") != (tc.status == AttributionComplete) {
				t.Fatalf("digest attribution for %s: %v", tc.name, payloads)
			}
		})
	}
	auditComplete(t, st)
}

// TestAttributionEvidenceRoundTripAndOlderVersions exports a v5 pack with
// an attributed batch, an unknown-actor batch, and a batch recorded without
// a lookup. Attribution is bound to the signed ledger payload, so tampering
// or stripping it fails; a v5 pack cannot be relabelled or replayed as v4;
// and v4/v3 packs of unattributed batches still verify.
func TestAttributionEvidenceRoundTripAndOlderVersions(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	digest := notify.Context{}.Digest
	tag := func(value string) []model.Collected {
		return []model.Collected{{Collector: "devices", Resources: []model.Resource{attributedDevice("d1", "n1", "db-01", value)}}}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, tag("a"), digest); err != nil {
		t.Fatal(err)
	}
	plain, err := st.ApplyBatchWithBatch(ctx, generation, tag("b"), digest)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := st.ApplyBatchWithOptions(ctx, generation, tag("c"), digest, BatchOptions{Attribute: (&recordingLookup{status: AttributionComplete}).lookup})
	if err != nil {
		t.Fatal(err)
	}
	lookup := &recordingLookup{status: AttributionComplete, entries: []model.AuditEntry{nodeEntry("alice@example.com", "n1", "UPDATE", "ACL_TAGS", time.Now())}}
	attributed, err := st.ApplyBatchWithOptions(ctx, generation, tag("d"), digest, BatchOptions{Attribute: lookup.lookup})
	if err != nil || attributed.Attributed != 1 {
		t.Fatalf("attributed batch=%+v err=%v", attributed, err)
	}
	encoded, err := st.ExportEvidencePack(ctx, HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidencePack(encoded); err != nil {
		t.Fatalf("v5 pack does not verify: %v", err)
	}
	public, _ := st.EvidenceSigningPublicKey(ctx)
	if err := VerifyEvidencePackWithKey(encoded, public); err != nil {
		t.Fatalf("v5 pack does not verify with the trusted key: %v", err)
	}
	decode := func(raw []byte) EvidencePack {
		t.Helper()
		var pack EvidencePack
		if err := json.Unmarshal(raw, &pack); err != nil {
			t.Fatal(err)
		}
		return pack
	}
	pack := decode(encoded)
	statuses := map[int64]string{}
	var signed *model.Attribution
	for _, batch := range pack.Batches {
		statuses[batch.ID] = batch.AttributionStatus
		if batch.ID == attributed.ID {
			signed = batch.Events[0].Attribution
		} else if batch.Events[0].Attribution != nil {
			t.Fatalf("batch %d carries attribution", batch.ID)
		}
	}
	if pack.Version != evidencePackVersion || signed == nil || signed.ActorLogin != "alice@example.com" || signed.Action != "NODE.UPDATE.ACL_TAGS" || signed.Target != "NODE:n1" || signed.OccurredAt == "" {
		t.Fatalf("pack version=%d attribution=%+v", pack.Version, signed)
	}
	if statuses[attributed.ID] != AttributionComplete || statuses[unknown.ID] != AttributionComplete || statuses[plain.ID] != "" {
		t.Fatalf("batch statuses=%v", statuses)
	}
	payload := ledgerPayloadFor(t, pack, attributed.ID)
	if !strings.Contains(payload, `"attribution":{"actor_login":"alice@example.com"`) {
		t.Fatalf("ledger payload does not sign the attribution: %s", payload)
	}
	for _, id := range []int64{plain.ID, unknown.ID} {
		if strings.Contains(ledgerPayloadFor(t, pack, id), "attribution") {
			t.Fatalf("ledger payload of unattributed batch %d mentions attribution", id)
		}
	}

	mutate := func(edit func(*EvidencePack)) []byte {
		copyPack := decode(encoded)
		edit(&copyPack)
		return resignEvidencePack(t, st, copyPack)
	}
	forEvent := func(p *EvidencePack, batchID int64, edit func(*EvidenceEvent)) {
		for index := range p.Batches {
			if p.Batches[index].ID == batchID {
				edit(&p.Batches[index].Events[0])
			}
		}
	}
	for name, tc := range map[string]struct {
		edit func(*EvidencePack)
		want string
	}{
		"forged actor": {func(p *EvidencePack) {
			forEvent(p, attributed.ID, func(e *EvidenceEvent) {
				forged := *e.Attribution
				forged.ActorLogin = "mallory@example.com"
				e.Attribution = &forged
			})
		}, "attribution mismatch"},
		"stripped attribution": {func(p *EvidencePack) {
			forEvent(p, attributed.ID, func(e *EvidenceEvent) { e.Attribution = nil })
		}, "attribution mismatch"},
		"invented attribution": {func(p *EvidencePack) {
			forEvent(p, unknown.ID, func(e *EvidenceEvent) { e.Attribution = signed })
		}, "attribution mismatch"},
		"attribution without lookup": {func(p *EvidencePack) {
			for index := range p.Batches {
				if p.Batches[index].ID == attributed.ID {
					p.Batches[index].AttributionStatus = AttributionUnavailable
				}
			}
		}, "without a complete attribution lookup"},
		"invalid status": {func(p *EvidencePack) { p.Batches[0].AttributionStatus = "maybe" }, "invalid attribution status"},
		"downgrade to v4": {func(p *EvidencePack) {
			p.Version = evidencePackVersionV4
			for index := range p.Batches {
				p.Batches[index].AttributionStatus = ""
				for event := range p.Batches[index].Events {
					p.Batches[index].Events[event].Attribution = nil
				}
			}
		}, "attribution mismatch"},
		"v4 with attribution": {func(p *EvidencePack) { p.Version = evidencePackVersionV4 }, "cannot carry attribution"},
		"v3 with attribution": {func(p *EvidencePack) {
			p.Version = evidencePackVersionV3
			for index := range p.Batches {
				p.Batches[index].AttributionStatus = ""
				for event := range p.Batches[index].Events {
					p.Batches[index].Events[event].Severity = ""
				}
			}
		}, "cannot carry attribution"},
	} {
		if err := VerifyEvidencePack(mutate(tc.edit)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error=%v, want %q", name, err, tc.want)
		}
	}

	// A v5 signature cannot be replayed as a v4 statement.
	replay := decode(encoded)
	replay.Version = evidencePackVersionV4
	content, _ := evidencePayload(replay)
	hash := sha256.Sum256(content)
	replay.ContentSHA256 = hex.EncodeToString(hash[:])
	replayed, _ := json.Marshal(replay)
	if err := VerifyEvidencePack(replayed); err == nil {
		t.Fatal("a version 5 signature verified as a version 4 pack")
	}

	// Packs of batches without attribution, as v4 and v3 releases exported
	// them, still verify.
	older, err := st.ExportEvidencePack(ctx, HistoryFilter{BatchID: plain.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{evidencePackVersionV4, evidencePackVersionV3} {
		legacy := decode(older)
		legacy.Version = version
		for index := range legacy.Batches {
			for event := range legacy.Batches[index].Events {
				if version == evidencePackVersionV3 {
					legacy.Batches[index].Events[event].Severity = ""
				}
			}
		}
		if err := VerifyEvidencePack(resignEvidencePack(t, st, legacy)); err != nil {
			t.Fatalf("version %d pack no longer verifies: %v", version, err)
		}
	}
	auditComplete(t, st)
}

func ledgerPayloadFor(t *testing.T, pack EvidencePack, batchID int64) string {
	t.Helper()
	for _, batch := range pack.Batches {
		if batch.ID == batchID {
			raw, err := base64.RawStdEncoding.DecodeString(batch.LedgerPayload)
			if err != nil {
				t.Fatal(err)
			}
			return string(raw)
		}
	}
	t.Fatalf("batch %d not in pack", batchID)
	return ""
}

// downgradeToV15 removes what schema v16 adds, reproducing a database
// written by the previous release.
func downgradeToV15(t *testing.T, st *Store) {
	t.Helper()
	for _, statement := range []string{
		"ALTER TABLE events DROP COLUMN attribution",
		"ALTER TABLE event_batches DROP COLUMN attribution_status",
		"UPDATE schema_version SET version=15",
	} {
		if _, err := st.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// TestSchemaV16MigrationKeepsLedgerBytesAndAddsAttribution upgrades a schema
// v15 database: existing events gain an empty attribution and their signed
// ledger payloads keep their exact bytes (the chain still audits), and new
// batches record attribution.
func TestSchemaV16MigrationKeepsLedgerBytesAndAddsAttribution(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tailstate.db")
	box, _ := secret.NewBox(make([]byte, 32))
	st, err := Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	tag := func(value string) []model.Collected {
		return []model.Collected{{Collector: "devices", Resources: []model.Resource{attributedDevice("d1", "n1", "db-01", value)}}}
	}
	digest := notify.Context{}.Digest
	if _, err := st.ApplyBatchWithBatch(ctx, generation, tag("a"), digest); err != nil {
		t.Fatal(err)
	}
	existing, err := st.ApplyBatchWithBatch(ctx, generation, tag("b"), digest)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := evidenceLedgerPayload(ctx, st.db, existing.ID)
	if err != nil {
		t.Fatal(err)
	}
	downgradeToV15(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path, box)
	if err != nil {
		t.Fatalf("v15 database did not migrate: %v", err)
	}
	defer st.Close()
	var version int
	if err := st.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	after, _, err := evidenceLedgerPayload(ctx, st.db, existing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("ledger payload bytes changed by the migration:\n%s\n%s", before, after)
	}
	auditComplete(t, st)
	if got := eventChangedBy(t, st, existing.ID)["d1"]; got != "" {
		t.Fatalf("a pre-upgrade event shows %q", got)
	}
	lookup := &recordingLookup{status: AttributionComplete, entries: []model.AuditEntry{nodeEntry("alice", "n1", "UPDATE", "ACL_TAGS", time.Now())}}
	attributed, err := st.ApplyBatchWithOptions(ctx, generation, tag("c"), digest, BatchOptions{Attribute: lookup.lookup})
	if err != nil {
		t.Fatal(err)
	}
	if got := eventChangedBy(t, st, attributed.ID)["d1"]; got != "alice via admin console" {
		t.Fatalf("changed by after the upgrade=%q", got)
	}
	auditComplete(t, st)
}

func TestSchemaV15ToV16ReportsErrors(t *testing.T) {
	t.Run("missing events table", func(t *testing.T) {
		db := migrationErrorDB(t)
		if err := migrateSchemaV15ToV16(db); err == nil || !strings.Contains(err.Error(), "add events.attribution") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("batch status", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 15)
		if _, err := db.Exec("DROP TABLE event_batches; CREATE VIEW event_batches AS SELECT 1 AS id"); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV15ToV16(db); err == nil || !strings.Contains(err.Error(), "add event_batches.attribution_status") {
			t.Fatalf("migration error=%v", err)
		}
	})
	t.Run("schema version", func(t *testing.T) {
		db := currentSchemaMigrationDB(t, 15)
		if _, err := db.Exec(`CREATE TRIGGER fail_v16_schema_version BEFORE UPDATE ON schema_version BEGIN SELECT RAISE(ABORT,'schema version update failed'); END`); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchemaV15ToV16(db); err == nil || !strings.Contains(err.Error(), "record change attribution migration") {
			t.Fatalf("migration error=%v", err)
		}
		var version int
		if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 15 {
			t.Fatalf("failed migration changed schema version to %d err=%v", version, err)
		}
	})
	t.Run("dispatch", func(t *testing.T) {
		box, _ := secret.NewBox(make([]byte, 32))
		db := migrationErrorDB(t)
		if _, err := db.Exec("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(15)"); err != nil {
			t.Fatal(err)
		}
		if err := migrateSchema(db, box); err == nil || !strings.Contains(err.Error(), "add events.attribution") {
			t.Fatalf("dispatch error=%v", err)
		}
	})
}

func TestAttributionSourceStateAndChangedBy(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if source, err := st.AttributionSource(ctx); err != nil || source.State != "" {
		t.Fatalf("initial source=%+v err=%v", source, err)
	}
	if err := st.RecordAttributionSource(ctx, AttributionSource{State: "maybe"}); err == nil {
		t.Fatal("an invalid source state was recorded")
	}
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	next := time.Now().Add(AttributionSourceRecheck)
	if err := st.RecordAttributionSource(ctx, AttributionSource{Generation: generation, Scopes: "all:read", State: AttributionSourceUnsupported, Reason: strings.Repeat("r", 400), CheckedAt: time.Now(), NextCheck: next}); err != nil {
		t.Fatal(err)
	}
	source, err := st.AttributionSource(ctx)
	if err != nil || !source.Checked(generation, "all:read") || source.Checked(generation, "devices:core:read") || source.Checked(generation+1, "all:read") || len(source.Reason) > 160 {
		t.Fatalf("source=%+v err=%v", source, err)
	}
	status, err := st.Status(ctx)
	if err != nil || status.Attribution.State != AttributionSourceUnsupported {
		t.Fatalf("status attribution=%+v err=%v", status.Attribution, err)
	}
	if _, err := st.db.Exec("UPDATE meta SET value='{' WHERE key=?", attributionSourceMeta); err != nil {
		t.Fatal(err)
	}
	if source, err := st.AttributionSource(ctx); err != nil || source.State != "" {
		t.Fatalf("unreadable source=%+v err=%v", source, err)
	}
	attribution := &model.Attribution{ActorLogin: "alice", Action: "NODE.UPDATE"}
	for _, tc := range []struct {
		attribution *model.Attribution
		status      string
		want        string
	}{
		{attribution, AttributionComplete, "alice"},
		{nil, AttributionComplete, model.ActorUnknown},
		{nil, AttributionUnavailable, model.ActorUnknown},
		{nil, AttributionUnsupported, ""},
		{nil, "", ""},
		{&model.Attribution{}, AttributionComplete, model.ActorUnknown},
	} {
		if got := ChangedBy(tc.attribution, tc.status); got != tc.want {
			t.Fatalf("ChangedBy(%v,%q)=%q, want %q", tc.attribution, tc.status, got, tc.want)
		}
	}
}
