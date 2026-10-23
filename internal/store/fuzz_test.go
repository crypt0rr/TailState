package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// FuzzVerifyEvidencePack passes arbitrary bytes to the offline evidence-pack
// verifier, which must not panic. The signed fixture from signing_edge_test.go
// seeds the decoder and signature checks with a structurally valid pack.
func FuzzVerifyEvidencePack(f *testing.F) {
	pack, _ := signedEvidencePackFixture(f)
	f.Add(pack)
	f.Add([]byte("{"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"format":"x"} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = VerifyEvidencePack(data)
	})
}

// FuzzParseEvidencePublicKey passes arbitrary key material to the public-key
// parser. It must not panic, must return exactly one Ed25519 key when it
// succeeds, and must reject material over the size limit. Every 32-byte key
// must survive a round trip through each encoding the parser accepts.
func FuzzParseEvidencePublicKey(f *testing.F) {
	public := make([]byte, ed25519.PublicKeySize)
	for index := range public {
		public[index] = byte(index + 1)
	}
	f.Add(public)
	f.Add([]byte(base64.RawStdEncoding.EncodeToString(public)))
	f.Add([]byte(base64.StdEncoding.EncodeToString(public)))
	f.Add([]byte(base64.RawURLEncoding.EncodeToString(public)))
	f.Add([]byte(base64.URLEncoding.EncodeToString(public)))
	f.Add([]byte(hex.EncodeToString(public)))
	f.Add([]byte("  \n" + base64.RawStdEncoding.EncodeToString(public) + "\n\t"))
	f.Add([]byte("not-a-key"))
	f.Add([]byte(strings.Repeat("0", 62)))
	f.Add(make([]byte, ed25519.PublicKeySize-1))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := ParseEvidencePublicKey(raw)
		if err == nil && len(got) != ed25519.PublicKeySize {
			t.Fatalf("parsed key has %d bytes", len(got))
		}
		if err == nil && len(raw) > EvidencePublicKeyLimitBytes {
			t.Fatalf("accepted %d bytes above the %d-byte limit", len(raw), EvidencePublicKeyLimitBytes)
		}
		if len(raw) != ed25519.PublicKeySize {
			return
		}
		encodings := []struct{ name, text string }{
			{"raw", string(raw)},
			{"raw base64", base64.RawStdEncoding.EncodeToString(raw)},
			{"base64", base64.StdEncoding.EncodeToString(raw)},
			{"raw url", base64.RawURLEncoding.EncodeToString(raw)},
			{"url", base64.URLEncoding.EncodeToString(raw)},
			{"hex", hex.EncodeToString(raw)},
			{"padded", " \t" + base64.RawStdEncoding.EncodeToString(raw) + "\n"},
		}
		for _, encoding := range encodings {
			decoded, err := ParseEvidencePublicKey([]byte(encoding.text))
			if err != nil || !bytes.Equal(decoded, raw) {
				t.Fatalf("%s encoding of a 32-byte key parsed as (%x, %v)", encoding.name, decoded, err)
			}
		}
	})
}
