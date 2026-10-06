package web

import (
	"bufio"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestChangedByIsShownInHistoryAPIAndStatus records an attributed batch and
// checks the operator surfaces: History shows "Changed by" with the audit
// action (and "actor unknown" for the unmatched change), /api/v1/history
// carries changed_by, the attribution record, and the batch status, and
// Status, /api/v1/status, and /metrics report the audit log source.
func TestChangedByIsShownInHistoryAPIAndStatus(t *testing.T) {
	ctx := context.Background()
	f := newAPIFixture(t, 0)
	settings, err := f.st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	collected := []model.Collected{{Collector: "devices", Resources: []model.Resource{
		{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": "server-renamed"}},
		{ID: "device-2", Type: "device", Name: "laptop", Data: map[string]any{"hostname": "laptop"}},
	}}}
	lookup := func(context.Context, store.AttributionWindow) store.AttributionResult {
		return store.AttributionResult{Status: store.AttributionComplete, Entries: []model.AuditEntry{{
			EventTime: time.Now(), Origin: "ADMIN_CONSOLE", ActorType: "USER", ActorLogin: "alice@example.com", ActorName: "Alice",
			TargetType: "NODE", TargetID: "device-2", Action: "CREATE",
		}}}
	}
	batch, err := f.st.ApplyBatchWithOptions(ctx, settings.Generation, collected, notify.TextDigest("digest"), store.BatchOptions{Attribute: lookup})
	if err != nil || batch.Attributed != 1 {
		t.Fatalf("batch=%+v err=%v", batch, err)
	}
	if err := f.st.RecordAttributionSource(ctx, store.AttributionSource{Generation: settings.Generation, State: store.AttributionSourceSupported, CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	page := html.UnescapeString(authenticatedGet(t, f.server, "/history?batch="+strconv.FormatInt(batch.ID, 10), f.cookies).Body.String())
	for _, text := range []string{"Changed by:</strong> alice@example.com (Alice) via admin console", "<code>NODE.CREATE</code>", "Changed by:</strong> actor unknown"} {
		if !strings.Contains(page, text) {
			t.Fatalf("history page is missing %q:\n%s", text, page)
		}
	}

	token := f.createToken(t, store.ScopeHistoryRead, store.ScopeStatusRead)
	response := apiGet(f.server, "/api/v1/history?batch="+strconv.FormatInt(batch.ID, 10), token)
	if response.Code != http.StatusOK {
		t.Fatalf("history API status=%d", response.Code)
	}
	var line struct {
		AttributionStatus string `json:"attribution_status"`
		Events            []struct {
			ResourceID  string             `json:"resource_id"`
			ChangedBy   string             `json:"changed_by"`
			Attribution *model.Attribution `json:"attribution"`
		} `json:"events"`
	}
	scanner := bufio.NewScanner(strings.NewReader(response.Body.String()))
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &line) != nil {
		t.Fatalf("history API body=%s", response.Body.String())
	}
	got := map[string]string{}
	for _, event := range line.Events {
		got[event.ResourceID] = event.ChangedBy
		if event.ResourceID == "device-2" && (event.Attribution == nil || event.Attribution.Action != "NODE.CREATE" || event.Attribution.Target != "NODE:device-2") {
			t.Fatalf("history API attribution=%+v", event.Attribution)
		}
	}
	if line.AttributionStatus != store.AttributionComplete || got["device-2"] != "alice@example.com (Alice) via admin console" || got["device-1"] != model.ActorUnknown {
		t.Fatalf("history API status=%q changed by=%v", line.AttributionStatus, got)
	}

	var status struct {
		Attribution struct {
			State     string     `json:"state"`
			CheckedAt *time.Time `json:"checked_at"`
		} `json:"attribution"`
	}
	statusResponse := apiGet(f.server, "/api/v1/status", token)
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil || status.Attribution.State != store.AttributionSourceSupported || status.Attribution.CheckedAt == nil {
		t.Fatalf("status API attribution=%+v err=%v body=%s", status.Attribution, err, statusResponse.Body.String())
	}
	statusPage := authenticatedGet(t, f.server, "/status", f.cookies).Body.String()
	if !strings.Contains(statusPage, "Change attribution") || !strings.Contains(statusPage, "Supported") {
		t.Fatalf("status page does not report the audit log source:\n%s", statusPage)
	}
	if err := f.st.RecordAttributionSource(ctx, store.AttributionSource{Generation: settings.Generation, State: store.AttributionSourceUnsupported, Reason: "unsupported (not available for this tailnet: HTTP 404)", CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	statusPage = html.UnescapeString(authenticatedGet(t, f.server, "/status", f.cookies).Body.String())
	if !strings.Contains(statusPage, "Unsupported</strong>") || !strings.Contains(statusPage, "HTTP 404") {
		t.Fatalf("status page does not show the unsupported audit log:\n%s", statusPage)
	}
	metrics := scrapeMetrics(t, f.server).Body.String()
	for _, sample := range []string{`tailstate_attribution_lookups_total{outcome="failed"} 0`, `tailstate_attribution_changes_total{result="unknown"} 0`} {
		if !strings.Contains(metrics, sample) {
			t.Fatalf("metrics missing %q", sample)
		}
	}
	lintExposition(t, metrics)
}

func TestStatusAPIReportsUncheckedAttribution(t *testing.T) {
	f := newAPIFixture(t, 0)
	token := f.createToken(t, store.ScopeStatusRead)
	response := apiGet(f.server, "/api/v1/status", token)
	if !strings.Contains(response.Body.String(), `"attribution":{"state":"unchecked"}`) {
		t.Fatalf("status API body=%s", response.Body.String())
	}
	if page := authenticatedGet(t, f.server, "/status", f.cookies).Body.String(); !strings.Contains(page, "Not checked yet") {
		t.Fatalf("status page body=%s", page)
	}
}
