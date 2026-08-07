package store

import (
	"strings"
	"testing"
)

func TestEvidenceJSONNormalizesEmptyAndInvalidValues(t *testing.T) {
	if got := evidenceJSON(""); got != nil {
		t.Fatalf("empty evidence JSON=%s", got)
	}
	if got := string(evidenceJSON(`{"field":true}`)); got != `{"field":true}` {
		t.Fatalf("valid evidence JSON=%q", got)
	}
	invalid := evidenceJSON("not-json")
	if string(invalid) != `"not-json"` {
		t.Fatalf("invalid evidence JSON=%q", invalid)
	}
	long := strings.Repeat("x", 32)
	if string(evidenceJSON(long)) != `"`+long+`"` {
		t.Fatalf("plain evidence value=%q", evidenceJSON(long))
	}
}
