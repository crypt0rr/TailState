package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The fuzz targets use a fixed secret and clock so that every corpus entry
// means the same thing on every run.
const fuzzWebhookSecret = "fuzz-webhook-secret"

var fuzzWebhookNow = time.Unix(1_786_000_000, 0)

// fuzzWebhookBodies are the event arrays from webhook_test.go, so the seed
// corpus starts from the documented shapes.
var fuzzWebhookBodies = []string{
	`[{"timestamp":"2026-08-05T10:00:00Z","version":1,"type":"policyUpdate","tailnet":"example.ts.net","data":{"actor":"user"}}]`,
	`[{"type":"nodeCreated"}]`,
	`[{"type":"newProviderEvent"}]`,
	`[]`,
	`[{"type":"   "},{"type":"policyUpdate"}]`,
	`[{"type":"node\u0001Created"},{"type":"policyUpdate"}]`,
	`{"type":"nodeCreated"}`,
}

// FuzzVerify passes arbitrary bodies and signature headers to Verify. It must
// not panic. A delivery it accepts must carry an HMAC over the body that
// matches a v1 value in the header, a timestamp inside the accepted window,
// and bounded metadata.
func FuzzVerify(f *testing.F) {
	for _, body := range fuzzWebhookBodies {
		f.Add([]byte(body), SignatureForTest([]byte(body), fuzzWebhookSecret, fuzzWebhookNow.Unix()))
	}
	f.Add([]byte(`[{"type":"nodeCreated"}]`), "t=1,v1=00")
	f.Add([]byte(`[{"type":"nodeCreated"}]`), "t=1,t=2,v1=deadbeef")
	f.Fuzz(func(t *testing.T, body []byte, signature string) {
		delivery, err := Verify(body, signature, fuzzWebhookSecret, fuzzWebhookNow)
		if err != nil {
			return
		}
		requireAuthenticSignature(t, body, signature)
		sum := sha256.Sum256(body)
		if delivery.BodyHash != hex.EncodeToString(sum[:]) {
			t.Fatalf("body hash %q does not describe the verified body", delivery.BodyHash)
		}
		if len(delivery.EventTypes) > maxEvents {
			t.Fatalf("%d event types exceed the bound of %d", len(delivery.EventTypes), maxEvents)
		}
		for _, eventType := range delivery.EventTypes {
			if len(eventType) > maxEventTypeLen {
				t.Fatalf("event type of %d bytes exceeds the bound of %d", len(eventType), maxEventTypeLen)
			}
		}
		if delivery.FallbackReason != "" && delivery.Collectors != nil {
			t.Fatal("a fallback delivery requested targeted collectors")
		}
	})
}

// FuzzVerifyRejectsMutatedBody signs a body with the fixed secret and flips
// bits in one byte. The signature covers the original bytes, so the original
// must authenticate and every mutated body must fail authentication.
func FuzzVerifyRejectsMutatedBody(f *testing.F) {
	for _, body := range fuzzWebhookBodies {
		f.Add([]byte(body), uint(0), byte(0x01))
		f.Add([]byte(body), uint(len(body)-1), byte(0x80))
	}
	f.Fuzz(func(t *testing.T, body []byte, position uint, mask byte) {
		if len(body) == 0 || len(body) > MaxBodyBytes || mask == 0 {
			return
		}
		signature := SignatureForTest(body, fuzzWebhookSecret, fuzzWebhookNow.Unix())
		if _, err := Verify(body, signature, fuzzWebhookSecret, fuzzWebhookNow); errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("the signed body failed authentication: %v", err)
		}
		mutated := bytes.Clone(body)
		mutated[position%uint(len(mutated))] ^= mask
		if _, err := Verify(mutated, signature, fuzzWebhookSecret, fuzzWebhookNow); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("mutated body was not rejected as unauthenticated: %v", err)
		}
	})
}

// FuzzParseSignature parses arbitrary header text. An accepted header must
// carry a positive timestamp and unpadded, non-empty signature values. A
// header built from a timestamp and a digest must parse back to exactly those
// parts.
func FuzzParseSignature(f *testing.F) {
	f.Add("t=1786000000,v1=00ff", int64(1786000000), []byte{0x00, 0xff})
	f.Add("garbage,t=1786000000,v1=deadbeef", int64(1), []byte("a"))
	f.Add("t=1,t=2,v1=deadbeef", int64(-1), []byte{})
	f.Add("v1=deadbeef", int64(0), []byte{0x01})
	f.Add("t=bad,v1=deadbeef", int64(1), []byte{0x01})
	f.Fuzz(func(t *testing.T, header string, timestamp int64, digest []byte) {
		if parsed, signatures, err := parseSignature(header); err == nil {
			if parsed <= 0 || len(signatures) == 0 {
				t.Fatalf("accepted timestamp %d with %d signatures", parsed, len(signatures))
			}
			for _, signature := range signatures {
				if signature == "" || strings.TrimSpace(signature) != signature {
					t.Fatalf("accepted signature value %q", signature)
				}
			}
		}
		if timestamp <= 0 || len(digest) == 0 {
			return
		}
		encoded := hex.EncodeToString(digest)
		built := "t=" + strconv.FormatInt(timestamp, 10) + ",v1=" + encoded
		parsed, signatures, err := parseSignature(built)
		if err != nil || parsed != timestamp || len(signatures) != 1 || signatures[0] != encoded {
			t.Fatalf("well-formed header %q parsed as (%d, %v, %v)", built, parsed, signatures, err)
		}
	})
}

// requireAuthenticSignature recomputes the documented HMAC over the accepted
// body and checks that a v1 value in the header matches it. The check is
// independent of Verify's own comparison.
func requireAuthenticSignature(t *testing.T, body []byte, signature string) {
	t.Helper()
	timestamp, signatures, err := parseSignature(signature)
	if err != nil {
		t.Fatalf("accepted a header that does not parse: %v", err)
	}
	when := time.Unix(timestamp, 0)
	if when.After(fuzzWebhookNow.Add(maxFutureSkew)) || fuzzWebhookNow.Sub(when) > maxSignatureAge {
		t.Fatalf("accepted timestamp %d outside the window", timestamp)
	}
	mac := hmac.New(sha256.New, []byte(fuzzWebhookSecret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "." + string(body)))
	want := mac.Sum(nil)
	for _, encoded := range signatures {
		if provided, err := hex.DecodeString(encoded); err == nil && hmac.Equal(provided, want) {
			return
		}
	}
	t.Fatal("accepted a delivery with no matching v1 signature")
}
