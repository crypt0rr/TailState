package web

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

const (
	apiDestinationSecret = "api-hook-credential-9f8e7d"
	apiOAuthSecret       = "api-oauth-secret-1a2b3c"
	apiWebhookSecret     = "api-webhook-secret-4d5e6f"
)

type apiFixture struct {
	path    string
	server  *Server
	st      *store.Store
	cookies []*http.Cookie
	batches int
}

// newAPIFixture configures monitoring with secrets and an encrypted
// destination URL, records batches change batches with delivery rows, and
// signs in an administrator. The History page budget is the minimum (4 KiB)
// so pagination by bytes is exercised.
func newAPIFixture(t *testing.T, batches int) *apiFixture {
	t.Helper()
	box, _ := secret.NewBox(make([]byte, 32))
	path := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := store.OpenWithLimits(path, box, store.StorageLimits{HistoryPageBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	config := boot.Config{ListenAddr: "127.0.0.1:0", TailscaleBase: "http://example.invalid", OAuthTokenURL: "http://example.invalid/oauth", Version: "test"}
	server, err := New(config, st, monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version))
	if err != nil {
		t.Fatal(err)
	}
	server.noticeSender = &recordingSender{}
	ctx := context.Background()
	setup, err := st.NewSetupToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cookies := sessionOnly(claimCoverageAdmin(t, server, setup))
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Paging", ServiceURL: "mattermost://TailState@hooks.example.invalid/" + apiDestinationSecret, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: apiOAuthSecret, WebhookSecret: apiWebhookSecret, DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	padding := strings.Repeat("x", 600)
	for i := 0; i <= batches; i++ {
		collected := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": fmt.Sprintf("server-%d-%s", i, padding)}}}}}
		if _, err := st.ApplyBatchWithBatch(ctx, generation, collected, notify.TextDigest("digest")); err != nil {
			t.Fatal(err)
		}
	}
	return &apiFixture{path: path, server: server, st: st, cookies: cookies, batches: batches}
}

// createToken creates a token through the Settings form and reads the
// secret from the page the Post/Redirect/Get redirect leads to.
func (f *apiFixture) createToken(t *testing.T, scopes ...string) string {
	t.Helper()
	form := url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "action": {"create"}, "name": {"SIEM"}, "expires_days": {"30"}, "scopes": scopes}
	response := coveragePost(t, f.server, "/settings/api-tokens", form, f.cookies)
	if response.Code != http.StatusSeeOther || strings.Contains(response.Header().Get("Location"), store.APITokenPrefix) {
		t.Fatalf("token creation %d %q", response.Code, response.Header().Get("Location"))
	}
	body := followFlash(t, f.server, f.cookies, response)
	return revealedToken(t, body)
}

func revealedToken(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, store.APITokenPrefix)
	if start < 0 {
		t.Fatalf("page does not show the new token: %s", body)
	}
	end := strings.IndexByte(body[start:], '"')
	return body[start : start+end]
}

func apiGet(server *Server, target, token string, headers ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

type ndjsonLine struct {
	Type       string `json:"type"`
	ID         int64  `json:"id"`
	HasNext    bool   `json:"has_next"`
	Next       string `json:"next"`
	Truncated  bool   `json:"truncated"`
	BytesRead  int64  `json:"bytes_read"`
	ByteLimit  int64  `json:"byte_limit"`
	Batches    int    `json:"batches"`
	NextCursor int64  `json:"next_cursor"`
	Events     []struct {
		Name   string          `json:"name"`
		After  json.RawMessage `json:"after"`
		Fields []struct {
			Field string `json:"field"`
		} `json:"fields"`
	} `json:"events"`
	Deliveries []struct {
		DestinationID int64  `json:"destination_id"`
		Destination   string `json:"destination"`
		Status        string `json:"status"`
	} `json:"deliveries"`
}

func parseNDJSON(t *testing.T, body string) ([]ndjsonLine, ndjsonLine) {
	t.Helper()
	var batches []ndjsonLine
	var page ndjsonLine
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for scanner.Scan() {
		var line ndjsonLine
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("invalid NDJSON line %q: %v", scanner.Text(), err)
		}
		switch line.Type {
		case "batch":
			batches = append(batches, line)
		case "page":
			page = line
		default:
			t.Fatalf("unknown line type %q", line.Type)
		}
	}
	if page.Type != "page" {
		t.Fatal("NDJSON page has no trailer")
	}
	return batches, page
}

// TestAPITokensAreScopedAndRevocationIsImmediate guards E-030: a token works
// only for its scopes, only as a bearer token, and stops working on the very
// next request after revocation.
func TestAPITokensAreScopedAndRevocationIsImmediate(t *testing.T) {
	f := newAPIFixture(t, 1)
	statusToken := f.createToken(t, store.ScopeStatusRead)
	if response := apiGet(f.server, "/api/v1/status", statusToken); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"configured":true`) {
		t.Fatalf("status with status:read: %d %s", response.Code, response.Body.String())
	}
	for _, path := range []string{"/api/v1/history", "/api/v1/evidence"} {
		response := apiGet(f.server, path, statusToken)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Header().Get("WWW-Authenticate"), "insufficient_scope") {
			t.Fatalf("%s with status:read only: %d", path, response.Code)
		}
	}
	// Browser sessions do not authenticate the API.
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	for _, cookie := range f.cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("session cookie authenticated the API: %d", response.Code)
	}
	if response := apiGet(f.server, "/api/v1/status", "", "Authorization", "Basic "+statusToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("non-bearer authorization accepted: %d", response.Code)
	}
	if response := apiGet(f.server, "/api/v1/status", statusToken+"x"); response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "invalid_token") {
		t.Fatalf("altered token accepted: %d", response.Code)
	}

	tokens, err := f.st.ListAPITokens(context.Background())
	if err != nil || len(tokens) != 1 {
		t.Fatalf("tokens=%v err=%v", tokens, err)
	}
	page := authenticatedGet(t, f.server, "/settings", f.cookies).Body.String()
	if strings.Contains(page, statusToken) || !strings.Contains(page, "SIEM") || !strings.Contains(page, "status:read") {
		t.Fatal("settings shows the token secret again, or does not list the token")
	}
	revoke := coveragePost(t, f.server, "/settings/api-tokens", url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "action": {"revoke"}, "id": {strconv.FormatInt(tokens[0].ID, 10)}}, f.cookies)
	if revoke.Code != http.StatusSeeOther {
		t.Fatalf("revoke %d: %s", revoke.Code, revoke.Body.String())
	}
	if response := apiGet(f.server, "/api/v1/status", statusToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token still works: %d", response.Code)
	}
	entries, _ := f.st.RecentAdminAudit(context.Background(), 10)
	if entries[0].Event != store.AuditAPITokenRevoked || entries[1].Event != store.AuditAPITokenCreated || entries[1].Target != "api_token:"+strconv.FormatInt(tokens[0].ID, 10) {
		t.Fatalf("token lifecycle not audited: %+v", entries[:2])
	}
	if response := coveragePost(t, f.server, "/settings/api-tokens", url.Values{"action": {"create"}, "name": {"x"}, "scopes": {store.ScopeStatusRead}, "expires_days": {"30"}}, f.cookies); response.Code != http.StatusForbidden {
		t.Fatalf("token creation without CSRF: %d", response.Code)
	}
	if response := coveragePost(t, f.server, "/settings/api-tokens", url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "action": {"create"}, "name": {"x"}, "expires_days": {"30"}}, f.cookies); !strings.Contains(followFlash(t, f.server, f.cookies, response), "choose at least one scope") {
		t.Fatal("token without scopes was not refused with a message")
	}
	if response := coveragePost(t, f.server, "/settings/api-tokens", url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "action": {"revoke"}, "id": {"999"}}, f.cookies); !strings.Contains(followFlash(t, f.server, f.cookies, response), "not found") {
		t.Fatal("revoking an unknown token was not reported")
	}
	if response := coveragePost(t, f.server, "/settings/api-tokens", url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "action": {"other"}}, f.cookies); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: %d", response.Code)
	}
}

// TestAPIHistoryPagesAreBoundedAndResumable guards E-030: NDJSON history
// pages honor the History byte budget and the UI filters, and following the
// trailer's next link visits every batch exactly once.
func TestAPIHistoryPagesAreBoundedAndResumable(t *testing.T) {
	f := newAPIFixture(t, 6)
	token := f.createToken(t, store.ScopeHistoryRead)
	seen := map[int64]bool{}
	target := "/api/v1/history?event_type=changed&limit=100"
	pages := 0
	for target != "" {
		pages++
		if pages > 20 {
			t.Fatal("pagination did not terminate")
		}
		response := apiGet(f.server, target, token)
		if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/x-ndjson") {
			t.Fatalf("history %d %q", response.Code, response.Header().Get("Content-Type"))
		}
		batches, page := parseNDJSON(t, response.Body.String())
		if page.ByteLimit != 4096 || page.BytesRead > page.ByteLimit || page.Batches != len(batches) {
			t.Fatalf("page not bounded by the History budget: %+v", page)
		}
		for _, batch := range batches {
			if seen[batch.ID] {
				t.Fatalf("batch %d returned twice", batch.ID)
			}
			seen[batch.ID] = true
			if len(batch.Events) == 0 || len(batch.Deliveries) != 1 || batch.Deliveries[0].Destination != "Paging" {
				t.Fatalf("batch lacks events or deliveries: %+v", batch)
			}
		}
		if page.HasNext && (page.Next == "" || !strings.Contains(page.Next, "event_type=changed") || !strings.Contains(page.Next, "cursor=")) {
			t.Fatalf("next link loses filters or cursor: %q", page.Next)
		}
		target = page.Next
	}
	if len(seen) != f.batches || pages < 2 {
		t.Fatalf("visited %d of %d batches in %d pages", len(seen), f.batches, pages)
	}
	batches, _ := parseNDJSON(t, apiGet(f.server, "/api/v1/history?event_type=removed", token).Body.String())
	if len(batches) != 0 {
		t.Fatal("history filter ignored")
	}
	batches, page := parseNDJSON(t, apiGet(f.server, "/api/v1/history?limit=1", token).Body.String())
	if len(batches) != 1 || !page.HasNext || !strings.Contains(page.Next, "limit=1") {
		t.Fatalf("limit not applied or not carried forward: %d %+v", len(batches), page)
	}
}

// TestAPIResponsesNeverContainDestinationURLsOrSecrets guards E-030's
// redaction requirement for every endpoint.
func TestAPIResponsesNeverContainDestinationURLsOrSecrets(t *testing.T) {
	f := newAPIFixture(t, 2)
	token := f.createToken(t, store.ScopeStatusRead, store.ScopeHistoryRead, store.ScopeEvidenceRead)
	for _, path := range []string{"/api/v1/status", "/api/v1/history", "/api/v1/evidence"} {
		response := apiGet(f.server, path, token)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
		body := response.Body.String()
		for _, secretValue := range []string{apiDestinationSecret, apiOAuthSecret, apiWebhookSecret, "hooks.example.invalid", "mattermost://", token, strings.TrimPrefix(token, store.APITokenPrefix), testAdminPassword} {
			if strings.Contains(body, secretValue) {
				t.Fatalf("%s response contains %q", path, secretValue)
			}
		}
	}
	evidence := apiGet(f.server, "/api/v1/evidence", token)
	if err := store.VerifyEvidencePack(evidence.Body.Bytes()); err != nil {
		t.Fatalf("API evidence pack does not verify: %v", err)
	}
}

// TestAPIRateLimitsTokensAndFailedAuthentication guards E-030's rate limits:
// each token has a request budget, and failed authentications are throttled
// per client without blocking valid tokens.
func TestAPIRateLimitsTokensAndFailedAuthentication(t *testing.T) {
	f := newAPIFixture(t, 1)
	token := f.createToken(t, store.ScopeStatusRead)
	for i := 0; i < apiRequestsPerWindow; i++ {
		if response := apiGet(f.server, "/api/v1/status", token); response.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, response.Code)
		}
	}
	limited := apiGet(f.server, "/api/v1/status", token)
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit not enforced: %d", limited.Code)
	}
	other := f.createToken(t, store.ScopeStatusRead)
	for i := 0; i < loginFailuresPerClient; i++ {
		if response := apiGet(f.server, "/api/v1/status", store.APITokenPrefix+"guess"); response.Code != http.StatusUnauthorized {
			t.Fatalf("failed authentication %d: %d", i, response.Code)
		}
	}
	if response := apiGet(f.server, "/api/v1/status", store.APITokenPrefix+"guess"); response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("failed authentications not throttled: %d", response.Code)
	}
	if response := apiGet(f.server, "/api/v1/status", other); response.Code != http.StatusOK {
		t.Fatalf("failed guesses blocked a valid token: %d", response.Code)
	}
	if wait, limited := f.server.apiRateLimit(1<<40, time.Now()); limited || wait != 0 {
		t.Fatal("a fresh token started rate limited")
	}
}

// TestAPIStorageErrorsAreCleanFailures checks that storage failures produce
// JSON errors without internal detail, never a partial body.
func TestAPIStorageErrorsAreCleanFailures(t *testing.T) {
	f := newAPIFixture(t, 1)
	token := f.createToken(t, store.ScopeStatusRead, store.ScopeHistoryRead, store.ScopeEvidenceRead)
	db, err := sql.Open("sqlite", "file:"+f.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{"ALTER TABLE collector_state RENAME TO collector_state_broken", "ALTER TABLE event_batches RENAME TO event_batches_broken"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/history", "/api/v1/evidence"} {
		response := apiGet(f.server, path, token)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"error":"unavailable"`) || strings.Contains(response.Body.String(), "broken") {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
	}
	if _, err := db.Exec("ALTER TABLE api_tokens RENAME TO api_tokens_broken"); err != nil {
		t.Fatal(err)
	}
	if response := apiGet(f.server, "/api/v1/status", token); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("token storage failure: %d", response.Code)
	}
	response := coveragePost(t, f.server, "/settings/api-tokens", url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "action": {"create"}, "name": {"x"}, "scopes": {store.ScopeStatusRead}, "expires_days": {"30"}}, f.cookies)
	if body := followFlash(t, f.server, f.cookies, response); !strings.Contains(body, "the token could not be stored") || strings.Contains(body, "api_tokens") {
		t.Fatalf("token storage failure leaked detail: %s", body)
	}
	if got := rawJSON("not json"); string(got) != `"not json"` {
		t.Fatalf("rawJSON(non-JSON)=%s", got)
	}
	if rawJSON("") != nil {
		t.Fatal("rawJSON(empty) is not omitted")
	}
}

func batchIDs(lines []ndjsonLine) []int64 {
	ids := make([]int64, 0, len(lines))
	for _, line := range lines {
		ids = append(ids, line.ID)
	}
	return ids
}

type apiPageLinks struct {
	HasPrev bool   `json:"has_prev"`
	Prev    string `json:"prev"`
}

func pageLinks(t *testing.T, body string) apiPageLinks {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	var links apiPageLinks
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &links); err != nil {
		t.Fatal(err)
	}
	return links
}

// TestAPIHistoryFiltersAndCursorsMatchHistoryPage guards E-030 together with
// the History page's filters: every History filter (collector, change type,
// severity, batch, from/to date) selects exactly the batches the History page
// shows for the same query, the trailer links page both towards older
// (cursor) and newer (after) batches with the filters intact, and an invalid
// date is refused instead of silently widening the result.
func TestAPIHistoryFiltersAndCursorsMatchHistoryPage(t *testing.T) {
	f := newAPIFixture(t, 5)
	token := f.createToken(t, store.ScopeHistoryRead, store.ScopeEvidenceRead)
	// The fixture's 4 KiB History budget holds about one batch per page.
	var all []ndjsonLine
	for target := "/api/v1/history?limit=100"; target != ""; {
		batches, page := parseNDJSON(t, apiGet(f.server, target, token).Body.String())
		all = append(all, batches...)
		target = page.Next
	}
	if len(all) != f.batches {
		t.Fatalf("history returned %d of %d batches", len(all), f.batches)
	}
	today := time.Now().UTC()
	for _, query := range []string{
		"collector=devices",
		"collector=users",
		"event_type=changed",
		"severity=high",
		"severity=low",
		"batch=" + strconv.FormatInt(all[2].ID, 10),
		"from=" + today.Format(historyDateLayout),
		"from=" + today.AddDate(0, 0, 1).Format(historyDateLayout),
		"to=" + today.AddDate(0, 0, -1).Format(historyDateLayout),
		"from=" + today.AddDate(0, 0, -1).Format(historyDateLayout) + "&to=" + today.Format(historyDateLayout),
		"cursor=" + strconv.FormatInt(all[1].ID, 10),
		"after=" + strconv.FormatInt(all[3].ID, 10),
	} {
		uiPage, err := f.st.ListHistory(context.Background(), historyFilter(httptest.NewRequest(http.MethodGet, "/history?"+query, nil)))
		if err != nil {
			t.Fatal(err)
		}
		var want []int64
		for _, batch := range uiPage.Batches {
			want = append(want, batch.ID)
		}
		response := apiGet(f.server, "/api/v1/history?"+query, token)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, response.Code, response.Body.String())
		}
		got, _ := parseNDJSON(t, response.Body.String())
		if fmt.Sprint(batchIDs(got)) != fmt.Sprint(want) {
			t.Fatalf("%s: API batches %v, History page batches %v", query, batchIDs(got), want)
		}
	}
	if batches, _ := parseNDJSON(t, apiGet(f.server, "/api/v1/history?batch="+strconv.FormatInt(all[2].ID, 10), token).Body.String()); len(batches) != 1 || batches[0].ID != all[2].ID {
		t.Fatalf("batch filter returned %v", batchIDs(batches))
	}
	if batches, _ := parseNDJSON(t, apiGet(f.server, "/api/v1/history?from="+today.AddDate(0, 0, 1).Format(historyDateLayout), token).Body.String()); len(batches) != 0 {
		t.Fatal("a future start date matched batches")
	}

	// Walk to the oldest page through "next", then back through "prev".
	var forward [][]int64
	target := "/api/v1/history?collector=devices&limit=2"
	for target != "" {
		body := apiGet(f.server, target, token).Body.String()
		batches, page := parseNDJSON(t, body)
		forward = append(forward, batchIDs(batches))
		if page.HasNext && (!strings.Contains(page.Next, "collector=devices") || !strings.Contains(page.Next, "limit=2")) {
			t.Fatalf("next link lost filters: %q", page.Next)
		}
		if len(forward) == 1 && pageLinks(t, body).HasPrev {
			t.Fatal("the newest page offers a newer page")
		}
		if !page.HasNext {
			links := pageLinks(t, body)
			if !links.HasPrev || !strings.Contains(links.Prev, "after=") || !strings.Contains(links.Prev, "collector=devices") {
				t.Fatalf("oldest page has no usable prev link: %+v", links)
			}
			target = links.Prev
			break
		}
		target = page.Next
	}
	if len(forward) < 3 {
		t.Fatalf("expected several pages, got %v", forward)
	}
	for index := len(forward) - 2; index >= 0; index-- {
		body := apiGet(f.server, target, token).Body.String()
		batches, _ := parseNDJSON(t, body)
		if fmt.Sprint(batchIDs(batches)) != fmt.Sprint(forward[index]) {
			t.Fatalf("prev page %d = %v, want %v", index, batchIDs(batches), forward[index])
		}
		target = pageLinks(t, body).Prev
	}
	if target != "" {
		t.Fatalf("the newest page reached through prev links still links to %q", target)
	}
	for _, path := range []string{"/api/v1/history?from=yesterday", "/api/v1/evidence?to=2026-13-40"} {
		if response := apiGet(f.server, path, token); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request") {
			t.Fatalf("%s: invalid date answered %d", path, response.Code)
		}
	}
}

// TestNewAPITokenIsShownOnceAfterRedirect guards E-030 under
// Post/Redirect/Get: the secret appears only on the first page view after
// the redirect, only for the session that created it, and is never placed
// in the redirect URL, a cookie, or the database.
func TestNewAPITokenIsShownOnceAfterRedirect(t *testing.T) {
	f := newAPIFixture(t, 0)
	other := loginCookies(t, f.server, testAdminPassword)
	form := url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "action": {"create"}, "name": {"SIEM"}, "expires_days": {"30"}, "scopes": {store.ScopeStatusRead}}
	response := coveragePost(t, f.server, "/settings/api-tokens", form, f.cookies)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings#new-api-token" {
		t.Fatalf("creation answered %d %q", response.Code, response.Header().Get("Location"))
	}
	if strings.Contains(response.Body.String(), store.APITokenPrefix) {
		t.Fatal("the redirect body contains the token")
	}
	var flash *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == flashCookieName {
			flash = cookie
		}
	}
	if flash == nil {
		t.Fatal("no flash cookie")
	}
	payload, _, _ := strings.Cut(flash.Value, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || strings.Contains(string(decoded), store.APITokenPrefix) {
		t.Fatalf("the flash cookie carries the token: %q %v", decoded, err)
	}

	// Another session presenting the same flash cookie gets nothing, and
	// does not consume the reveal.
	stolen := authGet(t, f.server, "/settings", append(append([]*http.Cookie(nil), other...), flash)).Body.String()
	if strings.Contains(stolen, store.APITokenPrefix) || !strings.Contains(stolen, "can no longer be displayed") {
		t.Fatal("another session redeemed the new token")
	}
	page := followFlash(t, f.server, f.cookies, response)
	secretValue := revealedToken(t, page)
	if !strings.Contains(page, "created. Copy it now") {
		t.Fatal("creation message missing")
	}
	assertAccessiblePage(t, "settings", page)
	if reload := authGet(t, f.server, "/settings", mergeCookies(f.cookies, response)).Body.String(); strings.Contains(reload, store.APITokenPrefix) {
		t.Fatal("reloading the page shows the token again")
	}
	if replay := authGet(t, f.server, "/settings", append(append([]*http.Cookie(nil), f.cookies...), flash)).Body.String(); strings.Contains(replay, store.APITokenPrefix) {
		t.Fatal("replaying the flash cookie shows the token again")
	}
	db, err := sql.Open("sqlite", "file:"+f.path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hash, name string
	if err := db.QueryRow("SELECT token_hash,name FROM api_tokens").Scan(&hash, &name); err != nil {
		t.Fatal(err)
	}
	if hash != secret.HashToken(secretValue) || strings.Contains(hash, secretValue) {
		t.Fatal("the database does not hold only the token hash")
	}
	if response := apiGet(f.server, "/api/v1/status", secretValue); response.Code != http.StatusOK {
		t.Fatalf("the displayed token does not authenticate: %d", response.Code)
	}
}

func TestRevealStoreExpiresAndBoundsPendingSecrets(t *testing.T) {
	reveals := newRevealStore()
	now := time.Now()
	reference, err := reveals.put("secret", "session", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reveals.take(reference, "", now); ok {
		t.Fatal("a request without a session redeemed a reveal")
	}
	if _, ok := reveals.take(reference, "session", now.Add(revealLifetime)); ok {
		t.Fatal("an expired reveal was redeemed")
	}
	for i := 0; i < maxReveals; i++ {
		if _, err := reveals.put("secret", "session", now); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if _, err := reveals.put("secret", "session", now); err == nil {
		t.Fatal("the reveal store is unbounded")
	}
	if _, err := reveals.put("secret", "session", now.Add(revealLifetime)); err != nil {
		t.Fatalf("expired reveals were not pruned: %v", err)
	}
}

// TestAPIEvidenceHonorsLimitLikeHistoryExport guards R-066: the API evidence
// pack uses the History download's pack size by default and honors a
// positive limit, with truncated and next_cursor set when more batches match.
func TestAPIEvidenceHonorsLimitLikeHistoryExport(t *testing.T) {
	f := newAPIFixture(t, 25)
	token := f.createToken(t, store.ScopeEvidenceRead)
	type pack struct {
		Batches    []json.RawMessage `json:"batches"`
		Truncated  bool              `json:"truncated"`
		NextCursor int64             `json:"next_cursor"`
	}
	decode := func(response *httptest.ResponseRecorder) pack {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("evidence status %d: %s", response.Code, response.Body.String())
		}
		var out pack
		if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	api := decode(apiGet(f.server, "/api/v1/evidence?collector=devices", token))
	download := decode(authGet(t, f.server, "/history/export?collector=devices", f.cookies))
	if len(api.Batches) != f.batches || len(api.Batches) != len(download.Batches) || api.Truncated != download.Truncated {
		t.Fatalf("API pack has %d batches (truncated=%v), History download %d (truncated=%v), want %d", len(api.Batches), api.Truncated, len(download.Batches), download.Truncated, f.batches)
	}
	limited := decode(apiGet(f.server, "/api/v1/evidence?collector=devices&limit=5", token))
	if len(limited.Batches) != 5 || !limited.Truncated || limited.NextCursor <= 0 {
		t.Fatalf("limit=5 returned %d batches, truncated=%v next_cursor=%d", len(limited.Batches), limited.Truncated, limited.NextCursor)
	}
}

// TestPasswordRecoveryRevokesAPITokens guards R-052: a password change and a
// token reset both revoke every active API token, so a token created with a
// stolen session does not outlive the recovery, and the audit record names
// the revocation.
func TestPasswordRecoveryRevokesAPITokens(t *testing.T) {
	f := newAPIFixture(t, 1)
	token := f.createToken(t, store.ScopeStatusRead)
	const changed = "violet harbor lantern"
	response := coveragePost(t, f.server, "/settings/password", url.Values{"_csrf": {csrfFrom(t, f.cookies)}, "current_password": {testAdminPassword}, "password": {changed}, "confirm": {changed}}, f.cookies)
	f.cookies = sessionOnly(response.Result().Cookies())
	if body := followFlash(t, f.server, f.cookies, response); !strings.Contains(body, "every active API token was revoked") {
		t.Fatalf("password change does not report the token revocation: %s", body)
	}
	if response := apiGet(f.server, "/api/v1/status", token); response.Code != http.StatusUnauthorized {
		t.Fatalf("API token survived a password change: %d", response.Code)
	}
	entries, err := f.st.RecentAdminAudit(context.Background(), 1)
	if err != nil || len(entries) != 1 || entries[0].Event != store.AuditPasswordChanged || strings.Join(entries[0].Fields, ",") != "api_tokens_revoked" {
		t.Fatalf("password change audit %+v err=%v", entries, err)
	}

	token = f.createToken(t, store.ScopeHistoryRead, store.ScopeEvidenceRead)
	reset, err := f.st.NewResetToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const recovered = "amber meadow compass"
	if response := coveragePost(t, f.server, "/reset", url.Values{"token": {reset}, "password": {recovered}, "confirm": {recovered}}, nil); response.Code != http.StatusSeeOther {
		t.Fatalf("reset %d: %s", response.Code, response.Body.String())
	}
	if response := apiGet(f.server, "/api/v1/evidence", token); response.Code != http.StatusUnauthorized {
		t.Fatalf("API token survived a password reset: %d", response.Code)
	}
	entries, err = f.st.RecentAdminAudit(context.Background(), 1)
	if err != nil || len(entries) != 1 || entries[0].Event != store.AuditPasswordReset || strings.Join(entries[0].Fields, ",") != "api_tokens_revoked" {
		t.Fatalf("password reset audit %+v err=%v", entries, err)
	}
}
