package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// auditLogAPI serves the configuration audit log endpoint in front of a
// fakeTailnetAPI. A nil body leaves the request to the fake (404 unless set,
// 403 without the scope); hang blocks until the client gives up.
type auditLogAPI struct {
	*fakeTailnetAPI
	mu       sync.Mutex
	body     string
	hang     bool
	requests []string
}

func (a *auditLogAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v2/tailnet/-/logging/configuration" {
		a.fakeTailnetAPI.ServeHTTP(w, r)
		return
	}
	a.mu.Lock()
	a.requests = append(a.requests, r.URL.RawQuery)
	body, hang := a.body, a.hang
	a.mu.Unlock()
	if hang {
		<-r.Context().Done()
		return
	}
	if body == "" {
		a.fakeTailnetAPI.ServeHTTP(w, r)
		return
	}
	if a.fakeTailnetAPI.granted != nil && !a.fakeTailnetAPI.granted[tailscale.ConfigurationAuditScope] {
		http.Error(w, `{"message":"insufficient scope"}`, http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func (a *auditLogAPI) setBody(body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.body = body
}

func (a *auditLogAPI) requestCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

func newAuditTailnet(t *testing.T, scopes ...string) (*auditLogAPI, *tailscale.Client, *Engine, *store.Store, store.Settings, string) {
	t.Helper()
	st, settings, path := openMonitorTestStore(t)
	fake := &fakeTailnetAPI{responses: map[string]string{}}
	if len(scopes) > 0 {
		fake.granted = map[string]bool{}
		for _, scope := range scopes {
			fake.granted[scope] = true
		}
	}
	api := &auditLogAPI{fakeTailnetAPI: fake}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	client := tailscale.New(server.URL+"/api/v2", server.URL+"/oauth/token", "test", tailscale.Credentials{Tailnet: "-", ClientID: "client", ClientSecret: "secret", Scopes: scopes})
	settings.OAuthScopes = scopes
	engine := New(st, server.URL+"/api/v2", server.URL+"/oauth/token", "test")
	return api, client, engine, st, settings, path
}

const (
	auditDevicesBaseline = `{"devices":[{"id":"101","nodeId":"nDB01","name":"db-01.example.ts.net","tags":["tag:dev"],"clientVersion":"1.80.0"},{"id":"102","nodeId":"nWEB01","name":"web-01.example.ts.net","clientVersion":"1.80.0"}]}`
	auditDevicesChanged  = `{"devices":[{"id":"101","nodeId":"nDB01","name":"db-01.example.ts.net","tags":["tag:prod"],"clientVersion":"1.80.0"},{"id":"102","nodeId":"nWEB01","name":"web-01.example.ts.net","clientVersion":"1.82.0"}]}`
	auditPolicyBaseline  = `{"acls":[{"action":"accept","src":["group:dev"],"dst":["*:*"]}]}`
	auditPolicyChanged   = `{"acls":[{"action":"accept","src":["group:ops"],"dst":["*:*"]}]}`
	// auditSentinel marks audit-log values that must never be persisted.
	auditSentinel = "SENTINEL-AUDIT-VALUE"
)

// auditLogBody is a ConfigurationAuditLog response (the official schema)
// for the device tag change and the policy edit. Old/new values and action
// details carry the sentinel, which must never reach the database.
func auditLogBody(at time.Time) string {
	stamp := at.UTC().Format(time.RFC3339Nano)
	return fmt.Sprintf(`{"version":"1.1","tailnet":"example.com","logs":[
{"eventTime":%[1]q,"type":"CONFIG","deferredAt":"0001-01-01T00:00:00Z","eventGroupID":"g1","origin":"ADMIN_CONSOLE","actor":{"id":"uAlice","type":"USER","loginName":"alice@example.com","displayName":"Alice Example"},"target":{"id":"nDB01","name":"db-01.example.ts.net","type":"NODE","property":"ACL_TAGS"},"action":"UPDATE","old":["tag:dev"],"new":["%[2]s"],"actionDetails":"%[2]s"},
{"eventTime":%[1]q,"type":"CONFIG","eventGroupID":"g2","origin":"CONFIG_API","actor":{"id":"kClient","type":"OAUTH_CLIENT","loginName":"kCIclient"},"target":{"id":"T1234","name":"example.com","type":"TAILNET","property":"ACL"},"action":"UPDATE","old":"// %[2]s policy text","new":{"acls":"%[2]s"}},
{"eventTime":%[1]q,"type":"CONFIG","eventGroupID":"g3","origin":"ADMIN_CONSOLE","actor":{"id":"uMallory","type":"USER","loginName":"mallory@example.com"},"target":{"id":"nWEB01","type":"NODE","property":"ACL_TAGS"},"action":"UPDATE","error":"%[2]s permission denied"}
]}`, stamp, auditSentinel)
}

// TestChangeAttributionNamesActorInHistoryDigestAndEvidence drives the
// configuration audit source end to end with spec-shaped fixtures: a device
// tag change and a policy edit are attributed in History, in every digest
// renderer, and in the signed evidence pack; a client upgrade without an
// audit entry is "actor unknown" in History (and names no actor in the
// digest) in the same batch; and no audit-log
// old/new value, action detail, or error text reaches the database.
func TestChangeAttributionNamesActorInHistoryDigestAndEvidence(t *testing.T) {
	ctx := context.Background()
	api, client, engine, st, settings, path := newAuditTailnet(t)
	for format, serviceURL := range map[string]string{"slack": "generic://notify.example/slack", "plain": "generic://notify.example/plain"} {
		id, err := st.SaveDestination(ctx, store.NotificationDestination{Name: format, ServiceURL: serviceURL, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetDestinationFormat(ctx, id, format); err != nil {
			t.Fatal(err)
		}
	}
	api.set("/api/v2/tailnet/-/devices", auditDevicesBaseline)
	api.set("/api/v2/tailnet/-/acl", auditPolicyBaseline)
	collectors := []string{"devices", "policy"}
	if !engine.poll(ctx, client, settings, collectors, true) {
		t.Fatal("baseline poll failed")
	}
	if api.requestCount() != 0 {
		t.Fatal("the baseline consulted the audit log")
	}
	if !engine.poll(ctx, client, settings, collectors, true) || api.requestCount() != 0 {
		t.Fatalf("an unchanged poll consulted the audit log (%d requests)", api.requestCount())
	}
	baselineAt := time.Now().UTC()

	api.setBody(auditLogBody(time.Now()))
	api.set("/api/v2/tailnet/-/devices", auditDevicesChanged)
	api.set("/api/v2/tailnet/-/acl", auditPolicyChanged)
	if !engine.poll(ctx, client, settings, collectors, true) {
		t.Fatal("change poll failed")
	}
	if api.requestCount() != 1 {
		t.Fatalf("audit log requests=%d, want one per change batch", api.requestCount())
	}
	query := api.requests[0]
	values, err := parseAuditQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	if !values.start.Before(baselineAt.Add(-store.AttributionClockSkew).Add(time.Second)) || values.start.Before(baselineAt.Add(-time.Hour)) || values.end.Before(time.Now()) {
		t.Fatalf("audit window %s..%s does not cover the poll interval (baseline %s)", values.start, values.end, baselineAt)
	}

	changedBy := map[string]string{}
	for _, collector := range collectors {
		for _, event := range collectorEvents(t, st, collector) {
			changedBy[event.ResourceID] = event.ChangedBy
		}
	}
	want := map[string]string{
		"101":    "alice@example.com (Alice Example) via admin console",
		"102":    "actor unknown",
		"policy": "kCIclient [OAuth client] via API",
	}
	for resource, text := range want {
		if changedBy[resource] != text {
			t.Fatalf("History changed by for %s=%q, want %q (all: %v)", resource, changedBy[resource], text, changedBy)
		}
	}

	sender := &capturingSender{}
	engine.sender = sender
	items, err := st.ClaimDueOutbox(ctx, 20, time.Minute)
	if err != nil || len(items) != 3 {
		t.Fatalf("claimed %d digests err=%v", len(items), err)
	}
	for _, item := range items {
		engine.deliverItemWithLease(ctx, item, nil)
	}
	sender.mu.Lock()
	for serviceURL, messages := range sender.messages {
		if len(messages) != 1 {
			t.Fatalf("%s received %d digests", serviceURL, len(messages))
		}
		for _, text := range []string{"changed by alice@example.com", "Alice Example", "via admin console", "changed by kCIclient", "via API", "Attributed: 2 of 3 changes"} {
			if !strings.Contains(messages[0], text) {
				t.Fatalf("%s digest is missing %q:\n%s", serviceURL, text, messages[0])
			}
		}
		if strings.Contains(messages[0], "actor unknown") {
			t.Fatalf("%s digest names an unknown actor:\n%s", serviceURL, messages[0])
		}
	}
	sender.mu.Unlock()

	encoded, err := st.ExportEvidencePack(ctx, store.HistoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyEvidencePack(encoded); err != nil {
		t.Fatalf("evidence pack with attribution does not verify: %v", err)
	}
	var pack store.EvidencePack
	if err := json.Unmarshal(encoded, &pack); err != nil {
		t.Fatal(err)
	}
	attributed := map[string]string{}
	for _, event := range pack.Batches[0].Events {
		if event.Attribution != nil {
			attributed[event.ResourceID] = event.Attribution.ActorLogin + " " + event.Attribution.Action
		}
	}
	if pack.Version != 5 || pack.Batches[0].AttributionStatus != store.AttributionComplete || attributed["101"] != "alice@example.com NODE.UPDATE.ACL_TAGS" || attributed["policy"] != "kCIclient TAILNET.UPDATE.ACL" || len(attributed) != 2 {
		t.Fatalf("evidence pack version=%d status=%q attribution=%v", pack.Version, pack.Batches[0].AttributionStatus, attributed)
	}

	metrics := engine.AttributionMetrics()
	if metrics.LookupsComplete != 1 || metrics.ChangesMatched != 2 || metrics.ChangesUnknown != 1 || metrics.LookupsFailed != 0 {
		t.Fatalf("attribution metrics=%+v", metrics)
	}
	status, err := st.Status(ctx)
	if err != nil || status.Attribution.State != store.AttributionSourceSupported {
		t.Fatalf("status attribution=%+v err=%v", status.Attribution, err)
	}
	for _, file := range []string{path, path + "-wal"} {
		raw, readErr := os.ReadFile(file)
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		if strings.Contains(string(raw), auditSentinel) || strings.Contains(string(raw), "mallory") {
			t.Fatalf("%s contains audit-log values, details, or failed entries", file)
		}
	}
}

type auditQuery struct{ start, end time.Time }

func parseAuditQuery(raw string) (auditQuery, error) {
	var out auditQuery
	for _, part := range strings.Split(raw, "&") {
		key, value, _ := strings.Cut(part, "=")
		value = strings.ReplaceAll(value, "%3A", ":")
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return out, fmt.Errorf("audit query %q: %w", raw, err)
		}
		switch key {
		case "start":
			out.start = parsed
		case "end":
			out.end = parsed
		}
	}
	if out.start.IsZero() || out.end.IsZero() || !out.end.After(out.start) {
		return out, fmt.Errorf("audit query %q has no valid window", raw)
	}
	return out, nil
}

// TestUnsupportedAuditLogDegradesSilently covers both unsupported answers: a
// 404 (logging not available) and a 403 (no logs:configuration:read scope
// in a least-privilege OAuth client). The change batch is recorded and
// notified without any "Changed by" line, the status page reports the source
// as unsupported, collector health and readiness are unaffected, and the
// audit log is not asked again on the next change until its recheck time.
func TestUnsupportedAuditLogDegradesSilently(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scopes []string
		body   string
		reason string
	}{
		{name: "not available", reason: "HTTP 404"},
		{name: "missing scope", scopes: []string{"devices:core:read"}, body: auditLogBody(time.Now()), reason: "HTTP 403"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			api, client, engine, st, settings, _ := newAuditTailnet(t, tc.scopes...)
			api.setBody(tc.body)
			api.set("/api/v2/tailnet/-/devices", auditDevicesBaseline)
			if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
				t.Fatal("baseline poll failed")
			}
			api.set("/api/v2/tailnet/-/devices", auditDevicesChanged)
			if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
				t.Fatal("a change with an unsupported audit log failed the poll")
			}
			events := collectorEvents(t, st, "devices")
			if len(events) != 2 {
				t.Fatalf("events=%d", len(events))
			}
			for _, event := range events {
				if event.ChangedBy != "" || event.Attribution != nil {
					t.Fatalf("unsupported audit log rendered %q", event.ChangedBy)
				}
			}
			status, err := st.Status(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if status.Attribution.State != store.AttributionSourceUnsupported || !strings.Contains(status.Attribution.Reason, tc.reason) {
				t.Fatalf("status attribution=%+v", status.Attribution)
			}
			if status.BaselineDegraded {
				t.Fatalf("an unsupported audit log degraded readiness: %s", status.BaselineReason)
			}
			for _, collector := range status.Collectors {
				if collector.Name == "config_audit" || !collector.Supported || collector.FailureCount != 0 {
					t.Fatalf("the audit log affected collector health: %+v", collector)
				}
			}
			items, err := st.ClaimDueOutbox(ctx, 10, time.Minute)
			if err != nil || len(items) != 1 {
				t.Fatalf("digests=%d err=%v", len(items), err)
			}
			if strings.Contains(items[0].Payload, "Changed by") {
				t.Fatalf("unsupported audit log added attribution to the digest: %s", items[0].Payload)
			}
			requests := api.requestCount()
			api.set("/api/v2/tailnet/-/devices", auditDevicesBaseline)
			if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
				t.Fatal("second change poll failed")
			}
			if api.requestCount() != requests {
				t.Fatal("an unsupported audit log was asked again before its recheck time")
			}
			if metrics := engine.AttributionMetrics(); metrics.LookupsUnsupported != 1 || metrics.ChangesMatched+metrics.ChangesUnknown != 0 {
				t.Fatalf("attribution metrics=%+v", metrics)
			}
		})
	}
}

// TestAuditLookupFailureNeverDelaysOrFailsDriftDetection hangs the audit
// endpoint: the batch is still recorded and notified within the lookup
// budget, every change is "actor unknown" in History, the digest says
// "Attribution unavailable", the failure is counted in the
// metrics, and the status page reports the source as unavailable.
func TestAuditLookupFailureNeverDelaysOrFailsDriftDetection(t *testing.T) {
	previous := attributionLookupBudget
	attributionLookupBudget = 200 * time.Millisecond
	t.Cleanup(func() { attributionLookupBudget = previous })
	ctx := context.Background()
	api, client, engine, st, settings, _ := newAuditTailnet(t)
	api.set("/api/v2/tailnet/-/devices", auditDevicesBaseline)
	if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
		t.Fatal("baseline poll failed")
	}
	api.mu.Lock()
	api.hang = true
	api.mu.Unlock()
	api.set("/api/v2/tailnet/-/devices", auditDevicesChanged)
	started := time.Now()
	if !engine.poll(ctx, client, settings, []string{"devices"}, true) {
		t.Fatal("a failed audit lookup failed the poll")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("a hanging audit log delayed the batch by %s", elapsed)
	}
	events := collectorEvents(t, st, "devices")
	if len(events) != 2 {
		t.Fatalf("events=%d", len(events))
	}
	for _, event := range events {
		if event.ChangedBy != "actor unknown" {
			t.Fatalf("failed lookup rendered %q", event.ChangedBy)
		}
	}
	items, err := st.ClaimDueOutbox(ctx, 10, time.Minute)
	if err != nil || len(items) != 1 || !strings.Contains(items[0].Payload, "Attribution unavailable") || strings.Contains(items[0].Payload, "actor unknown") {
		t.Fatalf("digest after failed lookup=%v err=%v", items, err)
	}
	if metrics := engine.AttributionMetrics(); metrics.LookupsFailed != 1 || metrics.ChangesUnknown != 2 {
		t.Fatalf("attribution metrics=%+v", metrics)
	}
	status, err := st.Status(ctx)
	if err != nil || status.Attribution.State != store.AttributionSourceFailing || status.Attribution.Reason != tailscale.FailureTimeout {
		t.Fatalf("status attribution=%+v err=%v", status.Attribution, err)
	}
}
