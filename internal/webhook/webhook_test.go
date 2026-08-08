package webhook

import (
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

func TestVerifyRejectsEmptyAndUntypedEvents(t *testing.T) {
	now := time.Unix(1_786_000_000, 0)
	for _, body := range [][]byte{[]byte(`[]`), []byte(`[{"type":"   "}]`)} {
		signature := SignatureForTest(body, "secret", now.Unix())
		if _, err := Verify(body, signature, "secret", now); err == nil {
			t.Fatalf("invalid event body %s was accepted", body)
		}
	}
	valid := []byte(`[{"type":"nodeCreated"}]`)
	signature := "garbage," + SignatureForTest(valid, "secret", now.Unix())
	if _, _, err := parseSignature(signature); err != nil {
		t.Fatalf("signature parser rejected an ignorable segment: %v", err)
	}
}
