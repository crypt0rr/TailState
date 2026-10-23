package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

// checkpointFixture returns an audited ledger whose checkpoint destination is
// an enabled notification destination.
func checkpointFixture(t *testing.T) (*Store, context.Context, int64) {
	t.Helper()
	st, ctx := auditFixture(t)
	destinationID, err := st.SaveDestination(ctx, NotificationDestination{Name: "Ops", ServiceURL: "mattermost://TailState@example.invalid/ops", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetEvidenceCheckpointDestination(ctx, destinationID); err != nil {
		t.Fatal(err)
	}
	return st, ctx, destinationID
}

func checkpointMessage(checkpoint LedgerCheckpoint) notify.Message {
	return notify.Context{Label: "test", Tailnet: "example.com"}.LedgerCheckpoint(checkpoint.Sequence, checkpoint.Head, checkpoint.KeyID, checkpoint.Signature, checkpoint.RecordedAt)
}

// enqueueCheckpoint enqueues a checkpoint that is due at now and returns it.
func enqueueCheckpoint(t *testing.T, st *Store, now time.Time, interval time.Duration) LedgerCheckpoint {
	t.Helper()
	var captured LedgerCheckpoint
	sent, err := st.EnqueueLedgerCheckpointIfDue(context.Background(), now, interval, func(checkpoint LedgerCheckpoint) notify.Message {
		captured = checkpoint
		return checkpointMessage(checkpoint)
	})
	if err != nil || !sent {
		t.Fatalf("checkpoint at %s sent=%t err=%v", now, sent, err)
	}
	return captured
}

// advanceLedger appends one ledger entry by changing a device's hostname. Each
// name must be new so that the poll produces a change.
func advanceLedger(t *testing.T, st *Store, name string) {
	t.Helper()
	ctx := context.Background()
	current, err := st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyBatchWithBatch(ctx, current.Generation, []model.Collected{historyResource(name, "100.64.0.1")}, notify.TextDigest(name)); err != nil {
		t.Fatal(err)
	}
}

// latestLedgerEntry returns the newest ledger sequence and its entry hash.
func latestLedgerEntry(t *testing.T, st *Store) (int64, string) {
	t.Helper()
	var sequence int64
	var head string
	if err := st.db.QueryRow("SELECT sequence,entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&sequence, &head); err != nil {
		t.Fatal(err)
	}
	return sequence, head
}

// truncateLedgerTail removes ledger entries from sequence onward and rewrites
// the stored head to the new tail, as someone with database access could do.
func truncateLedgerTail(t *testing.T, st *Store, sequence int64) {
	t.Helper()
	if _, err := st.db.Exec("DELETE FROM evidence_ledger WHERE sequence>=?", sequence); err != nil {
		t.Fatal(err)
	}
	var head string
	if err := st.db.QueryRow("SELECT entry_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1").Scan(&head); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE meta SET value=? WHERE key=?", head, evidenceLedgerHeadMeta); err != nil {
		t.Fatal(err)
	}
}

// checkpointRows counts the system notifications queued for one destination.
// Batch notifications carry a batch ID and are not counted.
func checkpointRows(t *testing.T, st *Store, destinationID int64) int {
	t.Helper()
	var count int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM outbox WHERE destination_id=? AND batch_id IS NULL", destinationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestLedgerCheckpointSignatureVerifiesWithInstanceKey(t *testing.T) {
	st, ctx, _ := checkpointFixture(t)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	checkpoint := enqueueCheckpoint(t, st, now, 6*time.Hour)
	sequence, head := latestLedgerEntry(t, st)
	if checkpoint.Sequence != sequence || checkpoint.Head != head || !checkpoint.RecordedAt.Equal(now) {
		t.Fatalf("checkpoint %+v, want sequence %d head %s recorded %s", checkpoint, sequence, head, now)
	}
	public, err := st.EvidenceSigningPublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLedgerCheckpoint(checkpoint, public); err != nil {
		t.Fatalf("checkpoint does not verify with the instance public key: %v", err)
	}
	// Every signed field is covered: changing any one of them breaks the signature.
	for name, mutate := range map[string]func(*LedgerCheckpoint){
		"sequence":    func(c *LedgerCheckpoint) { c.Sequence++ },
		"head":        func(c *LedgerCheckpoint) { c.Head = strings.Repeat("0", 64) },
		"recorded_at": func(c *LedgerCheckpoint) { c.RecordedAt = c.RecordedAt.Add(time.Second) },
	} {
		tampered := checkpoint
		mutate(&tampered)
		if err := VerifyLedgerCheckpoint(tampered, public); err == nil {
			t.Fatalf("checkpoint with a changed %s still verified", name)
		}
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLedgerCheckpoint(checkpoint, other); err == nil {
		t.Fatal("checkpoint verified against a different public key")
	}
}

func TestLedgerCheckpointEnqueuedOncePerIntervalNotResent(t *testing.T) {
	st, ctx, destinationID := checkpointFixture(t)
	const interval = 6 * time.Hour
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	enqueue := func(at time.Time) (bool, LedgerCheckpoint) {
		t.Helper()
		var captured LedgerCheckpoint
		sent, err := st.EnqueueLedgerCheckpointIfDue(ctx, at, interval, func(checkpoint LedgerCheckpoint) notify.Message {
			captured = checkpoint
			return checkpointMessage(checkpoint)
		})
		if err != nil {
			t.Fatalf("checkpoint at %s: %v", at, err)
		}
		return sent, captured
	}
	sent, first := enqueue(start)
	if !sent {
		t.Fatal("first checkpoint was not enqueued")
	}
	if sequence, _ := latestLedgerEntry(t, st); first.Sequence != sequence {
		t.Fatalf("first checkpoint sequence=%d, want %d", first.Sequence, sequence)
	}
	// The ledger advances, but the interval has not passed since the checkpoint.
	advanceLedger(t, st, "advance-one")
	if sent, _ := enqueue(start.Add(time.Hour)); sent {
		t.Fatal("checkpoint was enqueued before the interval passed")
	}
	// The interval has passed and the ledger advanced: the newest head is anchored.
	sent, second := enqueue(start.Add(interval))
	sequence, _ := latestLedgerEntry(t, st)
	if !sent || second.Sequence != sequence || second.Sequence <= first.Sequence {
		t.Fatalf("second checkpoint sent=%t sequence=%d, want %d after %d", sent, second.Sequence, sequence, first.Sequence)
	}
	// The ledger has not advanced. Later checks, including after the next
	// interval, must not resend the same sequence.
	for _, offset := range []time.Duration{interval + time.Minute, 2 * interval} {
		if sent, _ := enqueue(start.Add(offset)); sent {
			t.Fatalf("checkpoint resent at offset %s without a new ledger entry", offset)
		}
	}
	// A new entry is anchored once the interval since the last checkpoint has passed.
	advanceLedger(t, st, "advance-two")
	sent, third := enqueue(start.Add(2*interval + 30*time.Minute))
	sequence, _ = latestLedgerEntry(t, st)
	if !sent || third.Sequence != sequence {
		t.Fatalf("third checkpoint sent=%t sequence=%d, want %d", sent, third.Sequence, sequence)
	}
	if got := checkpointRows(t, st, destinationID); got != 3 {
		t.Fatalf("checkpoint notifications queued=%d, want 3", got)
	}
	// Checkpoints go only to the chosen destination, not to a later-added one.
	other, err := st.SaveDestination(ctx, NotificationDestination{Name: "Other", ServiceURL: "mattermost://TailState@example.invalid/other", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := checkpointRows(t, st, other); got != 0 {
		t.Fatalf("unchosen destination received %d checkpoints", got)
	}
}

func TestLedgerCheckpointWaitsWhileDestinationIsDisabled(t *testing.T) {
	st, ctx, destinationID := checkpointFixture(t)
	if err := st.SetDestinationEnabled(ctx, destinationID, false); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	sent, err := st.EnqueueLedgerCheckpointIfDue(ctx, now, time.Hour, checkpointMessage)
	if sent || !errors.Is(err, ErrEvidenceCheckpointDestinationUnavailable) {
		t.Fatalf("disabled destination sent=%t err=%v", sent, err)
	}
	if err := st.SetEvidenceCheckpointDestination(ctx, destinationID); !errors.Is(err, ErrDestinationDisabled) {
		t.Fatalf("choosing a disabled destination err=%v", err)
	}
	// The unsent checkpoint is still due once the destination is enabled again.
	if err := st.SetDestinationEnabled(ctx, destinationID, true); err != nil {
		t.Fatal(err)
	}
	if sent, err := st.EnqueueLedgerCheckpointIfDue(ctx, now, time.Hour, checkpointMessage); !sent || err != nil {
		t.Fatalf("re-enabled destination sent=%t err=%v", sent, err)
	}
	if err := st.ClearEvidenceCheckpointDestination(ctx); err != nil {
		t.Fatal(err)
	}
	advanceLedger(t, st, "after-clear")
	if sent, err := st.EnqueueLedgerCheckpointIfDue(ctx, now.Add(2*time.Hour), time.Hour, checkpointMessage); sent || err != nil {
		t.Fatalf("checkpoints off sent=%t err=%v", sent, err)
	}
}

func TestEvidenceLedgerCheckpointDetectsTruncationAfterAnchor(t *testing.T) {
	st, ctx, _ := checkpointFixture(t)
	checkpoint := enqueueCheckpoint(t, st, time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), time.Hour)
	options := EvidenceAuditOptions{Limit: 10, MinSequence: checkpoint.Sequence, ExpectHead: checkpoint.Head}
	// The unmodified ledger audits with the checkpoint supplied.
	result, err := st.AuditEvidenceLedger(ctx, options)
	if err != nil || !result.Complete || !result.CheckpointVerified {
		t.Fatalf("unmodified ledger audit=%+v err=%v", result, err)
	}
	// Truncate after the anchor and rewrite the stored head to match, which is
	// the attack a database-only audit cannot see.
	truncateLedgerTail(t, st, checkpoint.Sequence)
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 10}); err != nil {
		t.Fatalf("database-only audit of the truncated ledger failed: %v", err)
	}
	_, err = st.AuditEvidenceLedger(ctx, options)
	var auditErr *EvidenceAuditError
	if !errors.As(err, &auditErr) || auditErr.Check != "checkpoint length" {
		t.Fatalf("truncated ledger with the checkpoint supplied err=%v, want a checkpoint length failure", err)
	}
}

func TestEvidenceLedgerCheckpointRejectsRewrittenTail(t *testing.T) {
	st, ctx, _ := checkpointFixture(t)
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	checkpoint := enqueueCheckpoint(t, st, now, time.Hour)
	// Remove the anchored entry and reuse its sequence for a different batch,
	// which a party holding the instance key could produce.
	truncateLedgerTail(t, st, checkpoint.Sequence)
	if _, err := st.db.Exec("UPDATE sqlite_sequence SET seq=? WHERE name='evidence_ledger'", checkpoint.Sequence-1); err != nil {
		t.Fatal(err)
	}
	advanceLedger(t, st, "rewritten-tail")
	sequence, head := latestLedgerEntry(t, st)
	if sequence != checkpoint.Sequence || head == checkpoint.Head {
		t.Fatalf("rewrite did not reuse sequence %d: got sequence %d", checkpoint.Sequence, sequence)
	}
	// The rewritten chain is self-consistent, so only the checkpoint exposes it.
	if _, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 10}); err != nil {
		t.Fatalf("rewritten ledger is not self-consistent: %v", err)
	}
	_, err := st.AuditEvidenceLedger(ctx, EvidenceAuditOptions{Limit: 10, MinSequence: checkpoint.Sequence, ExpectHead: checkpoint.Head})
	var auditErr *EvidenceAuditError
	if !errors.As(err, &auditErr) || auditErr.Check != "checkpoint head" {
		t.Fatalf("rewritten tail with the checkpoint head err=%v, want a checkpoint head failure", err)
	}
	// The scheduler also refuses to anchor on top of the rewritten chain.
	sent, err := st.EnqueueLedgerCheckpointIfDue(ctx, now.Add(2*time.Hour), time.Hour, checkpointMessage)
	if sent || err == nil || !strings.Contains(err.Error(), "changed since it was anchored") {
		t.Fatalf("scheduler on rewritten chain sent=%t err=%v", sent, err)
	}
}

func TestEvidenceAuditRejectsMalformedCheckpointOptions(t *testing.T) {
	st, ctx := auditFixture(t)
	head := strings.Repeat("a", 64)
	for name, options := range map[string]EvidenceAuditOptions{
		"negative sequence":     {MinSequence: -1},
		"head without sequence": {ExpectHead: head},
		"short head":            {MinSequence: 1, ExpectHead: "abc"},
		"non-hex head":          {MinSequence: 1, ExpectHead: strings.Repeat("g", 64)},
	} {
		if _, err := st.AuditEvidenceLedger(ctx, options); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	normalized, err := NormalizeLedgerHead(fmt.Sprintf("  %s \n", strings.ToUpper(head)))
	if err != nil || normalized != head {
		t.Fatalf("normalized head=%q err=%v", normalized, err)
	}
}
