package tailscale

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

func auditServer(t *testing.T, status *atomic.Int32, body *atomic.Value, queries chan<- string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			_, _ = w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			return
		}
		if r.URL.Path != "/api/v2/tailnet/example.com/logging/configuration" {
			http.NotFound(w, r)
			return
		}
		if queries != nil {
			queries <- r.URL.RawQuery
		}
		if code := int(status.Load()); code != 0 && code != http.StatusOK {
			http.Error(w, `{"message":"denied"}`, code)
			return
		}
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(server.Close)
	return New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", Credentials{Tailnet: "example.com", ClientID: "id", ClientSecret: "secret"})
}

// TestConfigurationAuditLogsFollowTheOfficialSchema requests
// listConfigurationAuditLogs with an RFC 3339 window widened to whole
// seconds, decodes the documented ConfigurationAuditLog fields, discards
// old/new values and details, skips unparsable and non-CONFIG entries, marks
// failed changes, and keeps only the newest MaxAuditEntries entries.
func TestConfigurationAuditLogsFollowTheOfficialSchema(t *testing.T) {
	var status atomic.Int32
	var body atomic.Value
	body.Store(`{"version":"1.1","tailnet":"example.com","logs":[
{"eventTime":"2024-06-06T15:25:26.583893Z","type":"CONFIG","deferredAt":"0001-01-01T00:00:00Z","eventGroupID":"0378d8f57300d172ef7ae3826e097ef0","origin":"ADMIN_CONSOLE","actor":{"id":"uZKk3KSfrH11DEVEL","type":"USER","loginName":"lion.dahlia.armadillo@example.com","displayName":"Lion Dahlia Armadillo"},"target":{"id":"nBLYviWLGB21DEVEL","name":"silver-robin.taile18a.ts.net","type":"NODE","isEphemeral":true,"property":"ACL_TAGS"},"action":"UPDATE","old":["tag:a"],"new":{"secret":"policy text"},"actionDetails":"reason"},
{"eventTime":"not a time","type":"CONFIG","actor":{},"target":{},"action":"UPDATE"},
{"eventTime":"2024-06-06T15:25:27Z","type":"OTHER","actor":{},"target":{},"action":"UPDATE"},
{"eventTime":"2024-06-06T15:25:28Z","origin":"CONFIG_API","actor":{"type":"OAUTH_CLIENT","loginName":"k1"},"target":{"id":"T1","type":"TAILNET","property":"ACL"},"action":"UPDATE","error":"invalid policy"}
]}`)
	queries := make(chan string, 4)
	client := auditServer(t, &status, &body, queries)
	start := time.Date(2026, 10, 6, 11, 59, 30, 500, time.UTC)
	end := time.Date(2026, 10, 6, 13, 2, 0, 1, time.FixedZone("x", 3600))
	entries, err := client.ConfigurationAuditLogs(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	if query := <-queries; query != "end=2026-10-06T12%3A02%3A01Z&start=2026-10-06T11%3A59%3A30Z" {
		t.Fatalf("query=%s", query)
	}
	want := []model.AuditEntry{
		{EventTime: time.Date(2024, 6, 6, 15, 25, 26, 583893000, time.UTC), Origin: "ADMIN_CONSOLE", ActorType: "USER", ActorLogin: "lion.dahlia.armadillo@example.com", ActorName: "Lion Dahlia Armadillo", TargetID: "nBLYviWLGB21DEVEL", TargetName: "silver-robin.taile18a.ts.net", TargetType: "NODE", Property: "ACL_TAGS", Action: "UPDATE"},
		{EventTime: time.Date(2024, 6, 6, 15, 25, 28, 0, time.UTC), Origin: "CONFIG_API", ActorType: "OAUTH_CLIENT", ActorLogin: "k1", TargetID: "T1", TargetType: "TAILNET", Property: "ACL", Action: "UPDATE", Failed: true},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries=%#v", entries)
	}
	if strings.Contains(fmt.Sprintf("%#v", entries), "policy text") || strings.Contains(fmt.Sprintf("%#v", entries), "reason") {
		t.Fatal("audit values or details were decoded")
	}

	var many strings.Builder
	many.WriteString(`{"logs":[`)
	for index := range MaxAuditEntries + 10 {
		if index > 0 {
			many.WriteString(",")
		}
		fmt.Fprintf(&many, `{"eventTime":"2026-10-06T12:00:00Z","type":"CONFIG","actor":{"loginName":"user%d"},"target":{},"action":"UPDATE"}`, index)
	}
	many.WriteString(`]}`)
	body.Store(many.String())
	entries, err = client.ConfigurationAuditLogs(context.Background(), start, end)
	if err != nil || len(entries) != MaxAuditEntries || entries[0].ActorLogin != "user10" {
		t.Fatalf("bounded entries=%d first=%v err=%v", len(entries), entries[0].ActorLogin, err)
	}
	<-queries
}

func TestConfigurationAuditLogsReportUnsupportedAndInvalidResponses(t *testing.T) {
	var status atomic.Int32
	var body atomic.Value
	body.Store(`{"logs":[]}`)
	client := auditServer(t, &status, &body, nil)
	ctx := context.Background()
	start := time.Now().Add(-time.Hour)
	end := time.Now()
	if entries, err := client.ConfigurationAuditLogs(ctx, start, end); err != nil || len(entries) != 0 {
		t.Fatalf("empty log entries=%v err=%v", entries, err)
	}
	for _, code := range []int32{http.StatusForbidden, http.StatusNotFound} {
		status.Store(code)
		_, err := client.ConfigurationAuditLogs(ctx, start, end)
		if !IsUnsupported(err) || strings.Contains(UnsupportedReason(err), "denied") {
			t.Fatalf("status %d error=%v", code, err)
		}
	}
	status.Store(http.StatusOK)
	for _, invalid := range []string{"", "[1]", `{"logs":{}}`} {
		body.Store(invalid)
		if _, err := client.ConfigurationAuditLogs(ctx, start, end); err == nil || IsUnsupported(err) {
			t.Fatalf("invalid body %q error=%v", invalid, err)
		}
	}
	if _, err := client.ConfigurationAuditLogs(ctx, end, start); err == nil {
		t.Fatal("an empty window was requested")
	}
}
