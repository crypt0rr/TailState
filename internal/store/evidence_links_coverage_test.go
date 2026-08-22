package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestVerifyLedgerLinksRejectsMalformedLinks exercises the structural checks
// that protect offline evidence verification from accepting a partial or
// forged ledger chain. These inputs are intentionally built below the
// database/export layer so each rejection remains isolated to the verifier.
func TestVerifyLedgerLinksRejectsMalformedLinks(t *testing.T) {
	base, public, private := malformedLedgerPackFixture(t)
	clone := func(pack EvidencePack) EvidencePack {
		pack.Batches = append([]EvidenceBatch(nil), pack.Batches...)
		pack.LedgerLinks = append([]EvidenceLedgerLink(nil), pack.LedgerLinks...)
		return pack
	}
	secondLink := func(sequence int64, previous, entry []byte) EvidenceLedgerLink {
		hash := hex.EncodeToString(entry)
		return EvidenceLedgerLink{
			Sequence:  sequence,
			BatchID:   sequence,
			PrevHash:  hex.EncodeToString(previous),
			EntryHash: hash,
			Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, entry)),
			KeyID:     evidenceKeyID(public),
		}
	}
	tests := []struct {
		name string
		edit func(EvidencePack) EvidencePack
		want string
	}{
		{
			name: "links without exported batches",
			edit: func(pack EvidencePack) EvidencePack {
				pack.Batches = nil
				return pack
			},
			want: "ledger links have no exported batches",
		},
		{
			name: "missing links",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks = nil
				return pack
			},
			want: "evidence ledger links are missing",
		},
		{
			name: "duplicate batch sequence",
			edit: func(pack EvidencePack) EvidencePack {
				pack.Batches = append(pack.Batches, pack.Batches[0])
				return pack
			},
			want: "duplicate evidence ledger sequence",
		},
		{
			name: "invalid batch previous hash length",
			edit: func(pack EvidencePack) EvidencePack {
				pack.Batches[0].LedgerPrevHash = "short"
				return pack
			},
			want: "invalid ledger previous hash",
		},
		{
			name: "invalid batch previous hash encoding",
			edit: func(pack EvidencePack) EvidencePack {
				pack.Batches[0].LedgerPrevHash = strings.Repeat("z", 64)
				return pack
			},
			want: "invalid ledger previous hash",
		},
		{
			name: "invalid link hash length",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks[0].EntryHash = "short"
				return pack
			},
			want: "invalid ledger link at sequence",
		},
		{
			name: "duplicate link sequence",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks = append(pack.LedgerLinks, pack.LedgerLinks[0])
				return pack
			},
			want: "duplicate evidence ledger sequence",
		},
		{
			name: "link key mismatch",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks[0].KeyID = "ed25519:other"
				return pack
			},
			want: "ledger signing key mismatch at sequence",
		},
		{
			name: "invalid link previous hash length",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks[0].PrevHash = "short"
				return pack
			},
			want: "invalid ledger link previous hash",
		},
		{
			name: "invalid link previous hash encoding",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks[0].PrevHash = strings.Repeat("z", 64)
				return pack
			},
			want: "invalid ledger link previous hash",
		},
		{
			name: "missing link signature",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks[0].Signature = ""
				return pack
			},
			want: "ledger signature is missing",
		},
		{
			name: "invalid link signature",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks[0].Signature = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				return pack
			},
			want: "ledger signature verification failed",
		},
		{
			name: "link batch mismatch",
			edit: func(pack EvidencePack) EvidencePack {
				pack.LedgerLinks[0].BatchID = 999
				return pack
			},
			want: "evidence ledger link does not match batch",
		},
		{
			name: "missing ledger payload",
			edit: func(pack EvidencePack) EvidencePack { return pack },
			want: "ledger payload is missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyLedgerLinks(tt.edit(clone(base))); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	// Link ordering and continuity are checked independently from batch
	// matching. Use a checkpoint plus a selected sequence to reach those
	// branches without requiring a complete payload for the selected batch.
	entryTwo := []byte(strings.Repeat("b", 32))
	checkpoint := base.LedgerLinks[0]
	selected := secondLink(2, []byte(strings.Repeat("c", 32)), entryTwo)
	gap := clone(base)
	gap.Batches = []EvidenceBatch{{ID: 2, LedgerSequence: 2, LedgerHash: selected.EntryHash, LedgerKeyID: base.SigningKeyID}}
	gap.LedgerLinks = []EvidenceLedgerLink{checkpoint, selected}
	if err := verifyLedgerLinks(gap); err == nil || !strings.Contains(err.Error(), "evidence ledger chain mismatch between sequences") {
		t.Fatalf("link chain mismatch error = %v", err)
	}

	sequenceGap := clone(base)
	sequenceThree := secondLink(3, []byte(strings.Repeat("d", 32)), entryTwo)
	sequenceGap.Batches = []EvidenceBatch{
		{ID: 1, LedgerSequence: 1, LedgerHash: base.Batches[0].LedgerHash, LedgerSignature: base.Batches[0].LedgerSignature, LedgerKeyID: base.SigningKeyID},
		{ID: 3, LedgerSequence: 3, LedgerHash: sequenceThree.EntryHash, LedgerSignature: sequenceThree.Signature, LedgerKeyID: base.SigningKeyID},
	}
	sequenceGap.LedgerLinks = []EvidenceLedgerLink{checkpoint, sequenceThree}
	if err := verifyLedgerLinks(sequenceGap); err == nil || !strings.Contains(err.Error(), "evidence ledger sequence gap") {
		t.Fatalf("sequence gap error = %v", err)
	}
}

func malformedLedgerPackFixture(t *testing.T) (EvidencePack, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := []byte(strings.Repeat("a", 32))
	hash := hex.EncodeToString(entry)
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, entry))
	keyID := evidenceKeyID(public)
	return EvidencePack{
		SigningKeyID:     keyID,
		SigningPublicKey: base64.RawStdEncoding.EncodeToString(public),
		Batches: []EvidenceBatch{{
			ID:              1,
			LedgerSequence:  1,
			LedgerHash:      hash,
			LedgerSignature: signature,
			LedgerKeyID:     keyID,
		}},
		LedgerLinks: []EvidenceLedgerLink{{
			Sequence:  1,
			BatchID:   1,
			EntryHash: hash,
			Signature: signature,
			KeyID:     keyID,
		}},
	}, public, private
}
