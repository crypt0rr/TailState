package web

import (
	"context"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestHistoryAndAPIShowListElementPaths guards R-049 for the read paths: an
// invite field change recorded at its element path is listed verbatim by
// the History page, the History API, and the evidence API.
func TestHistoryAndAPIShowListElementPaths(t *testing.T) {
	f := newAPIFixture(t, 0)
	ctx := context.Background()
	generation, err := f.st.SettingsGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	details := func(tailnetID string) []model.Collected {
		return []model.Collected{{Collector: "device_details", Resources: []model.Resource{{ID: "654495373136127", Type: "device_details", Name: "ludus", Data: map[string]any{
			"deviceInvites": []any{map[string]any{"id": "5861427050514914", "tailnetId": tailnetID, "accepted": true}},
		}}}}}
	}
	for _, tailnetID := range []string{"T1000EXAMPLE", "T2000EXAMPLE"} {
		if _, err := f.st.ApplyBatchWithBatch(ctx, generation, details(tailnetID), notify.TextDigest("digest")); err != nil {
			t.Fatal(err)
		}
	}
	const path = "deviceInvites[5861427050514914].tailnetId"
	if page := authenticatedGet(t, f.server, "/history?collector=device_details", f.cookies).Body.String(); !strings.Contains(page, path) {
		t.Fatal("History page does not show the element path")
	}
	token := f.createToken(t, store.ScopeHistoryRead, store.ScopeEvidenceRead)
	batches, _ := parseNDJSON(t, apiGet(f.server, "/api/v1/history?collector=device_details&event_type=changed", token).Body.String())
	if len(batches) != 1 || len(batches[0].Events) != 1 || len(batches[0].Events[0].Fields) != 1 || batches[0].Events[0].Fields[0].Field != path {
		t.Fatalf("History API lost the element path: %+v", batches)
	}
	evidence := apiGet(f.server, "/api/v1/evidence?collector=device_details", token)
	if !strings.Contains(evidence.Body.String(), `"`+path+`"`) {
		t.Fatalf("evidence API lost the element path: %d", evidence.Code)
	}
	if err := store.VerifyEvidencePack(evidence.Body.Bytes()); err != nil {
		t.Fatalf("evidence API pack with an element path did not verify: %v", err)
	}
}
