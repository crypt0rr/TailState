package webhook

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMethodOnlyAcceptsPOST(t *testing.T) {
	if !Method(http.MethodPost) {
		t.Fatal("POST was rejected")
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if Method(method) {
			t.Fatalf("%s was accepted", method)
		}
	}
}

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

func TestCollectorsForCoversDocumentedEventFamilies(t *testing.T) {
	tests := []struct {
		event string
		want  string
	}{
		{event: "nodeCreated", want: "device_details,devices"},
		{event: "userRoleUpdated", want: "user_invites,users"},
		{event: "policyUpdate", want: "policy"},
		{event: "webhookDeleted", want: "webhooks"},
	}
	for _, tt := range tests {
		collectors := CollectorsFor([]Event{{Type: tt.event}})
		if strings.Join(collectors, ",") != tt.want {
			t.Fatalf("%s collectors=%v, want %s", tt.event, collectors, tt.want)
		}
	}
	if got := CollectorsFor(nil); len(got) != 0 {
		t.Fatalf("empty event list collectors=%v, want empty", got)
	}
}

func TestVerifyRejectsMalformedHeadersAndEvents(t *testing.T) {
	now := time.Unix(1_786_000_000, 0)
	body := []byte(`[{"type":"nodeCreated"}]`)
	cases := []struct {
		name, signature, secret, want string
	}{
		{"empty body", "", "secret", "body is empty"},
		{"missing secret", SignatureForTest(body, "secret", now.Unix()), "", "secret is not configured"},
		{"missing timestamp", "v1=deadbeef", "secret", "signature is missing"},
		{"duplicate timestamp", "t=1,t=2,v1=deadbeef", "secret", "duplicate timestamp"},
		{"bad timestamp", "t=bad,v1=deadbeef", "secret", "timestamp is invalid"},
		{"future timestamp", SignatureForTest(body, "secret", now.Add(6*time.Minute).Unix()), "secret", "outside the accepted window"},
		{"bad encoding", "t=" + fmt.Sprint(now.Unix()) + ",v1=not-hex", "secret", "signature is invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(func() []byte {
				if tc.name == "empty body" {
					return nil
				}
				return body
			}(), tc.signature, tc.secret, now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyFallsBackForOutOfBoundsAuthenticContent(t *testing.T) {
	now := time.Unix(1_786_000_000, 0)
	many := make([]string, maxEvents+1)
	for i := range many {
		many[i] = `{"type":"nodeCreated"}`
	}
	cases := []struct {
		name, body, reason string
		types              []string
	}{
		{"empty array", `[]`, FallbackEventCount, []string{}},
		{"too many events", "[" + strings.Join(many, ",") + "]", FallbackEventCount, []string{"nodeCreated"}},
		{"missing type", `[{"type":"   "},{"type":"policyUpdate"}]`, FallbackEventTypeMissing, []string{"policyUpdate"}},
		{"long type", `[{"type":"` + strings.Repeat("x", maxEventTypeLen+1) + `"}]`, FallbackEventTypeLength, []string{strings.Repeat("x", maxEventTypeLen-3) + "…"}},
		{"control character", `[{"type":"node\u0001Created"},{"type":"policyUpdate"}]`, FallbackEventTypeInvalid, []string{"policyUpdate"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			delivery, err := Verify(body, SignatureForTest(body, "secret", now.Unix()), "secret", now)
			if err != nil {
				t.Fatalf("authentic out-of-bounds content was rejected: %v", err)
			}
			if delivery.FallbackReason != tc.reason || delivery.Collectors != nil || delivery.BodyHash == "" {
				t.Fatalf("delivery=%#v, want fallback %q with full reconciliation", delivery, tc.reason)
			}
			if strings.Join(delivery.EventTypes, ",") != strings.Join(tc.types, ",") {
				t.Fatalf("event types=%q, want %q", delivery.EventTypes, tc.types)
			}
			for _, eventType := range delivery.EventTypes {
				if len(eventType) > maxEventTypeLen {
					t.Fatalf("event type metadata exceeds %d bytes", maxEventTypeLen)
				}
			}
		})
	}
	valid := []byte(`[{"type":"nodeCreated"}]`)
	signature := "garbage," + SignatureForTest(valid, "secret", now.Unix())
	if _, _, err := parseSignature(signature); err != nil {
		t.Fatalf("signature parser rejected an ignorable segment: %v", err)
	}
}

func TestVerifyClassifiesErrors(t *testing.T) {
	now := time.Unix(1_786_000_000, 0)
	body := []byte(`[{"type":"nodeCreated"}]`)
	if _, err := Verify(body, "t=1,v1=00", "secret", now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("bad signature error=%v", err)
	}
	if _, err := Verify(make([]byte, MaxBodyBytes+1), "", "secret", now); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversized body error=%v", err)
	}
	object := []byte(`{"type":"nodeCreated"}`)
	if _, err := Verify(object, SignatureForTest(object, "secret", now.Unix()), "secret", now); !errors.Is(err, ErrMalformedBody) {
		t.Fatalf("non-array body error=%v", err)
	}
	if _, err := Verify(nil, "", "secret", now); !errors.Is(err, ErrMalformedBody) {
		t.Fatalf("empty body error=%v", err)
	}
	// Unauthenticated content must never be parsed or classified as malformed.
	if _, err := Verify(object, "t=1,v1=00", "secret", now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unsigned malformed body error=%v", err)
	}
}
