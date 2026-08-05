package webhook

import (
	"strings"
	"testing"
	"time"
)

func TestVerifyAcceptsSignedEventArrayAndClassifiesCollectors(t *testing.T) {
	body := []byte(`[{"timestamp":"2026-08-05T10:00:00Z","version":1,"type":"policyUpdate","tailnet":"example.ts.net","data":{"actor":"user"}}]`)
	now := time.Unix(1_786_000_000, 0)
	signature := SignatureForTest(body, "secret", now.Unix())
	delivery, err := Verify(body, signature, "secret", now)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.BodyHash == "" || len(delivery.Events) != 1 || len(delivery.Collectors) != 1 || delivery.Collectors[0] != "policy" {
		t.Fatalf("unexpected delivery: %#v", delivery)
	}
	if delivery.EventTypes[0] != "policyUpdate" {
		t.Fatalf("unexpected event types: %#v", delivery.EventTypes)
	}
}

func TestVerifyRejectsInvalidAndStaleSignatures(t *testing.T) {
	body := []byte(`[{"type":"nodeCreated"}]`)
	now := time.Unix(1_786_000_000, 0)
	if _, err := Verify(body, SignatureForTest(body, "wrong", now.Unix()), "secret", now); err == nil {
		t.Fatal("invalid signature was accepted")
	}
	if _, err := Verify(body, SignatureForTest(body, "secret", now.Add(-25*time.Hour).Unix()), "secret", now); err == nil {
		t.Fatal("stale signature was accepted")
	}
}

func TestVerifyUnknownEventRequestsBroadReconciliation(t *testing.T) {
	body := []byte(`[{"type":"newProviderEvent"}]`)
	now := time.Unix(1_786_000_000, 0)
	delivery, err := Verify(body, SignatureForTest(body, "secret", now.Unix()), "secret", now)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Collectors != nil {
		t.Fatalf("unknown events should request broad reconciliation: %#v", delivery.Collectors)
	}
}

func TestVerifyRejectsNonArrayAndOversizedBody(t *testing.T) {
	now := time.Unix(1_786_000_000, 0)
	object := []byte(`{"type":"nodeCreated"}`)
	if _, err := Verify(object, SignatureForTest(object, "secret", now.Unix()), "secret", now); err == nil || !strings.Contains(err.Error(), "event array") {
		t.Fatalf("unexpected object error: %v", err)
	}
	large := make([]byte, MaxBodyBytes+1)
	if _, err := Verify(large, SignatureForTest(large, "secret", now.Unix()), "secret", now); err == nil {
		t.Fatal("oversized body was accepted")
	}
}
