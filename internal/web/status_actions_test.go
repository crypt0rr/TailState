package web

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

func newWebTestEngine(st *store.Store, config boot.Config) *monitor.Engine {
	return monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version)
}

func base64URL(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }

// authGet performs an authenticated GET with the given cookies.
func authGet(t *testing.T, server *Server, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

// mergeCookies applies a response's Set-Cookie headers to a browser-like
// cookie list: same-name cookies are replaced and expired ones dropped.
func mergeCookies(existing []*http.Cookie, response *httptest.ResponseRecorder) []*http.Cookie {
	byName := map[string]*http.Cookie{}
	order := []string{}
	for _, cookie := range existing {
		if _, seen := byName[cookie.Name]; !seen {
			order = append(order, cookie.Name)
		}
		byName[cookie.Name] = cookie
	}
	for _, cookie := range response.Result().Cookies() {
		if _, seen := byName[cookie.Name]; !seen {
			order = append(order, cookie.Name)
		}
		if cookie.MaxAge < 0 {
			byName[cookie.Name] = nil
			continue
		}
		byName[cookie.Name] = &http.Cookie{Name: cookie.Name, Value: cookie.Value}
	}
	var out []*http.Cookie
	for _, name := range order {
		if cookie := byName[name]; cookie != nil {
			out = append(out, cookie)
		}
	}
	return out
}

func configureMonitoring(t *testing.T, st *store.Store, webhookSecret string) int64 {
	t.Helper()
	destinations, err := st.ListDestinations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(destinations) == 0 {
		if _, err := st.SaveDestination(context.Background(), store.NotificationDestination{Name: "Default", ServiceURL: "generic://default.example/hook", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	generation, err := st.SaveSettings(context.Background(), store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", WebhookSecret: webhookSecret, DeviceInterval: time.Hour, InventoryInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func flashText(t *testing.T, body, class string) string {
	t.Helper()
	nodes := htmlElements(htmlDocument(t, body), func(node *html.Node) bool { return htmlHasClass(node, class) })
	if len(nodes) == 0 {
		return ""
	}
	return htmlText(nodes[0])
}

func TestStatusColumnsMatchDataAndTimesShowTimezone(t *testing.T) {
	server, _, _ := testServer(t)
	data := accessibilityFixtures()["status"]
	response := httptest.NewRecorder()
	server.render(response, "status", data)
	document := htmlDocument(t, response.Body.String())
	table := htmlElements(document, func(node *html.Node) bool { return htmlHasClass(node, "collector-table") })[0]
	var columns []string
	for _, header := range htmlElements(htmlElements(table, htmlTag("thead"))[0], htmlTag("th")) {
		columns = append(columns, htmlText(header))
	}
	if got := strings.Join(columns, "|"); got != "Collector|State|Last success|Next poll|Poll duration|Failures|Details" {
		t.Fatalf("collector columns=%s", got)
	}
	cells := map[string]string{}
	firstRow := htmlElements(htmlElements(table, htmlTag("tbody"))[0], htmlTag("tr"))[0]
	for cell := firstRow.FirstChild; cell != nil; cell = cell.NextSibling {
		if label, ok := htmlAttr(cell, "data-label"); ok {
			cells[label] = htmlText(cell)
		}
	}
	if cells["Poll duration"] != "12 ms" || cells["Failures"] != "0" {
		t.Fatalf("duration/failure cells=%v", cells)
	}
	if !strings.HasSuffix(strings.SplitN(cells["Last success"], " (", 2)[0], " UTC") || !strings.Contains(cells["Last success"], "3 min ago") {
		t.Fatalf("last success is not labelled UTC with a relative hint: %q", cells["Last success"])
	}
	if !strings.Contains(cells["Next poll"], "UTC") {
		t.Fatalf("next poll lacks a timezone: %q", cells["Next poll"])
	}
	secondRow := htmlElements(htmlElements(table, htmlTag("tbody"))[0], htmlTag("tr"))[1]
	for cell := secondRow.FirstChild; cell != nil; cell = cell.NextSibling {
		if label, _ := htmlAttr(cell, "data-label"); label == "Failures" && htmlText(cell) != "4" {
			t.Fatalf("failure count cell=%q", htmlText(cell))
		}
		if label, _ := htmlAttr(cell, "data-label"); label == "Next poll" && htmlText(cell) != "Due now" {
			t.Fatalf("missing next poll cell=%q", htmlText(cell))
		}
	}
	times := htmlElements(document, htmlTag("time"))
	if len(times) < 3 {
		t.Fatalf("expected baseline, last success and next poll times, got %d", len(times))
	}
	for _, element := range times {
		datetime, _ := htmlAttr(element, "datetime")
		if !strings.HasSuffix(htmlText(element), " UTC") || !strings.HasSuffix(datetime, "Z") {
			t.Fatalf("time %q (datetime %q) does not show its timezone", htmlText(element), datetime)
		}
	}
}

func TestTemplateTimeAndSizeHelpers(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		at   time.Time
		want string
	}{
		{now.Add(-2 * time.Second), "just now"},
		{now.Add(-42 * time.Second), "42 s ago"},
		{now.Add(-3 * time.Minute), "3 min ago"},
		{now.Add(-5 * time.Hour), "5 h ago"},
		{now.Add(-72 * time.Hour), "3 days ago"},
		{now.Add(90 * time.Second), "in 1 min"},
	} {
		if got := relativeTime(test.at, now); got != test.want {
			t.Fatalf("relativeTime(%s)=%q, want %q", now.Sub(test.at), got, test.want)
		}
	}
	local := time.Date(2026, 10, 5, 14, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	if view := when(local, now); !view.Valid || view.UTC != "2026-10-05 12:00:00 UTC" || view.ISO != "2026-10-05T12:00:00Z" || view.Relative != "just now" {
		t.Fatalf("when(local)=%#v", view)
	}
	var missing *time.Time
	if when(missing, now).Valid || when(time.Time{}, now).Valid || when("not a time", now).Valid {
		t.Fatal("missing times must render as a dash")
	}
	if got := formatMiB(176128); got != "0.17 MiB" {
		t.Fatalf("formatMiB=%q", got)
	}
	if got := formatPercent(0.25); got != "25.0%" {
		t.Fatalf("formatPercent=%q", got)
	}
}

func TestReconcileNowTriggersPollWithinSecondsAndRequiresCSRF(t *testing.T) {
	var devicePolls atomic.Int64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth/token":
			_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600}`))
		case r.URL.Path == "/api/v2/tailnet/-/devices":
			devicePolls.Add(1)
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	server, st, setupToken := testServer(t)
	server.config.TailscaleBase = api.URL + "/api/v2"
	server.config.OAuthTokenURL = api.URL + "/oauth/token"
	server.engine = newWebTestEngine(st, server.config)
	cookies := claimCoverageAdmin(t, server, setupToken)
	csrf := coverageCSRF(t, cookies)

	unconfigured := coveragePost(t, server, "/status/reconcile", url.Values{"_csrf": {csrf}}, cookies)
	if unconfigured.Code != http.StatusSeeOther || unconfigured.Header().Get("Location") != "/status" {
		t.Fatalf("unconfigured reconcile status=%d", unconfigured.Code)
	}
	page := authGet(t, server, "/status", mergeCookies(cookies, unconfigured))
	if !strings.Contains(flashText(t, page.Body.String(), "error"), "Save the monitoring settings") {
		t.Fatalf("unconfigured reconcile did not explain itself: %s", page.Body.String())
	}

	configureMonitoring(t, st, "")
	ctx, cancel := context.WithCancel(context.Background())
	server.engine.Run(ctx)
	t.Cleanup(func() { cancel(); server.engine.Wait() })
	waitFor(t, 10*time.Second, func() bool { return devicePolls.Load() >= 1 })
	// The device interval is one hour; let the initial poll settle.
	time.Sleep(300 * time.Millisecond)
	before := devicePolls.Load()

	forged := coveragePost(t, server, "/status/reconcile", url.Values{"_csrf": {"wrong"}}, cookies)
	if forged.Code == http.StatusSeeOther && forged.Header().Get("Location") == "/status" {
		t.Fatal("reconcile accepted a request without the CSRF token")
	}
	missing := coveragePost(t, server, "/status/reconcile", url.Values{}, cookies)
	if missing.Code == http.StatusSeeOther && missing.Header().Get("Location") == "/status" {
		t.Fatal("reconcile accepted a request with no CSRF token")
	}
	time.Sleep(500 * time.Millisecond)
	if devicePolls.Load() != before {
		t.Fatal("a rejected reconcile request still polled Tailscale")
	}

	accepted := coveragePost(t, server, "/status/reconcile", url.Values{"_csrf": {csrf}}, cookies)
	if accepted.Code != http.StatusSeeOther || accepted.Header().Get("Location") != "/status" {
		t.Fatalf("reconcile status=%d location=%q", accepted.Code, accepted.Header().Get("Location"))
	}
	waitFor(t, 5*time.Second, func() bool { return devicePolls.Load() > before })

	withFlash := mergeCookies(cookies, accepted)
	shown := authGet(t, server, "/status", withFlash)
	if !strings.Contains(flashText(t, shown.Body.String(), "success"), "Reconciliation requested") {
		t.Fatalf("reconcile confirmation missing: %s", shown.Body.String())
	}
	if again := authGet(t, server, "/status", mergeCookies(withFlash, shown)); flashText(t, again.Body.String(), "success") != "" {
		t.Fatal("flash message was shown twice")
	}

	limited := coveragePost(t, server, "/status/reconcile", url.Values{"_csrf": {csrf}}, cookies)
	limitedPage := authGet(t, server, "/status", mergeCookies(cookies, limited))
	if !strings.Contains(flashText(t, limitedPage.Body.String(), "error"), "Try again in") {
		t.Fatalf("second reconcile inside the cooldown was not rate-limited: %s", limitedPage.Body.String())
	}
}

func TestReconcileCooldownExpires(t *testing.T) {
	server, _, _ := testServer(t)
	server.reconcileCooldown = time.Minute
	start := time.Now()
	if _, limited := server.reserveReconcile(start); limited {
		t.Fatal("first reconcile was limited")
	}
	if wait, limited := server.reserveReconcile(start.Add(20 * time.Second)); !limited || wait != 40*time.Second {
		t.Fatalf("wait=%s limited=%v", wait, limited)
	}
	if _, limited := server.reserveReconcile(start.Add(time.Minute)); limited {
		t.Fatal("reconcile still limited after the cooldown")
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func seedDeadDelivery(t *testing.T, db *sql.DB, destinationID int64, lastError string) int64 {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := db.Exec("INSERT INTO outbox(destination_id,payload,status,attempts,next_attempt,first_attempt,last_error,created_at) VALUES(?,?,'dead',5,?,?,?,?)", destinationID, "payload", now, now, lastError, now)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	return id
}

func TestRetryDeadLettersFromStatusPage(t *testing.T) {
	server, st, db, cookies := webServerWithDatabase(t)
	ctx := context.Background()
	csrf := coverageCSRF(t, cookies)
	configureMonitoring(t, st, "")
	pager, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Pager", ServiceURL: "generic://pager.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	chat, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Chat", ServiceURL: "generic://chat.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dead := seedDeadDelivery(t, db, pager, "delivery retry window expired")
	seedDeadDelivery(t, db, chat, "delivery retry window expired")
	if err := st.SetDestinationEnabled(ctx, chat, false); err != nil {
		t.Fatal(err)
	}

	page := authGet(t, server, "/status", cookies)
	document := assertAccessiblePage(t, "status", page.Body.String())
	buttons := htmlElements(document, func(node *html.Node) bool {
		label, _ := htmlAttr(node, "aria-label")
		return node.Data == "button" && strings.HasPrefix(label, "Retry ")
	})
	if len(buttons) != 1 || accessibleName(buttons[0]) != "Retry 1 dead letters for Pager" {
		t.Fatalf("retry buttons=%d body=%s", len(buttons), page.Body.String())
	}
	if !strings.Contains(page.Body.String(), "Enable to retry") {
		t.Fatal("disabled destination with dead letters should explain how to retry")
	}

	forged := coveragePost(t, server, "/status/destinations/retry", url.Values{"id": {strconv.FormatInt(pager, 10)}}, cookies)
	if forged.Code == http.StatusSeeOther && forged.Header().Get("Location") == "/status" {
		t.Fatal("retry accepted a request without the CSRF token")
	}
	var status string
	if err := db.QueryRow("SELECT status FROM outbox WHERE id=?", dead).Scan(&status); err != nil || status != "dead" {
		t.Fatalf("forged retry changed the row: status=%s err=%v", status, err)
	}

	retried := coveragePost(t, server, "/status/destinations/retry", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(pager, 10)}}, cookies)
	if retried.Code != http.StatusSeeOther || retried.Header().Get("Location") != "/status" {
		t.Fatalf("retry status=%d", retried.Code)
	}
	if err := db.QueryRow("SELECT status FROM outbox WHERE id=?", dead).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("retried row status=%s err=%v", status, err)
	}
	if text := flashText(t, authGet(t, server, "/status", mergeCookies(cookies, retried)).Body.String(), "success"); text != "Requeued 1 dead notification for delivery." {
		t.Fatalf("retry confirmation=%q", text)
	}

	for _, test := range []struct {
		id   int64
		want string
	}{
		{chat, "Enable the destination before retrying"},
		{999999, "Notification destination not found."},
	} {
		response := coveragePost(t, server, "/status/destinations/retry", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(test.id, 10)}}, cookies)
		if text := flashText(t, authGet(t, server, "/status", mergeCookies(cookies, response)).Body.String(), "error"); !strings.Contains(text, test.want) {
			t.Fatalf("retry %d error=%q, want %q", test.id, text, test.want)
		}
	}
	empty := coveragePost(t, server, "/status/destinations/retry", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(pager, 10)}}, cookies)
	if text := flashText(t, authGet(t, server, "/status", mergeCookies(cookies, empty)).Body.String(), "success"); text != "Requeued 0 dead notifications for delivery." {
		t.Fatalf("empty retry confirmation=%q", text)
	}
}

func TestStatusActionsReportStoreFailures(t *testing.T) {
	server, st, _, cookies := webServerWithDatabase(t)
	csrf := coverageCSRF(t, cookies)
	configureMonitoring(t, st, "")
	// Closing the store after authentication would also break the session
	// check, so exercise the failure paths through the handlers directly.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/status/reconcile", "/status/destinations/retry"} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"_csrf": {csrf}, "id": {"1"}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		if path == "/status/reconcile" {
			server.reconcileAuthorized(response, request, "")
		} else {
			server.retryDeadLettersAuthorized(response, request, "")
		}
		if response.Code != http.StatusSeeOther {
			t.Fatalf("%s with a closed store status=%d", path, response.Code)
		}
		page := httptest.NewRecorder()
		data := pageData{}
		requestWithFlash := httptest.NewRequest(http.MethodGet, "/status", nil)
		for _, cookie := range response.Result().Cookies() {
			requestWithFlash.AddCookie(cookie)
		}
		server.applyFlash(page, requestWithFlash, &data)
		if data.Error == "" || strings.Contains(data.Error, "sql") {
			t.Fatalf("%s failure message=%q", path, data.Error)
		}
	}
}

func TestSettingsShowWebhookAccelerationAndStorageUnits(t *testing.T) {
	server, st, _, cookies := webServerWithDatabase(t)
	ctx := context.Background()
	configureMonitoring(t, st, "")
	page := authGet(t, server, "/settings", cookies)
	body := page.Body.String()
	document := assertAccessiblePage(t, "settings", body)
	state := htmlElements(document, func(node *html.Node) bool { id, _ := htmlAttr(node, "id"); return id == "webhook-state" })
	if len(state) != 1 || !strings.Contains(htmlText(state[0]), "Webhook acceleration: disabled") {
		t.Fatalf("webhook state without a secret: %s", body)
	}
	if strings.Contains(body, `name="clear_webhook_secret"`) {
		t.Fatal("remove-secret checkbox shown although no webhook secret exists")
	}
	if !strings.Contains(body, `placeholder="Optional"`) {
		t.Fatal("webhook secret placeholder implies a stored secret")
	}
	for _, want := range []string{" MiB of ", "% used)", "Files on disk", "WAL ", "SHM "} {
		if !strings.Contains(body, want) {
			t.Fatalf("storage diagnostics missing %q", want)
		}
	}
	if strings.Contains(body, " bytes</strong>") {
		t.Fatal("storage is still shown in raw bytes")
	}

	configureMonitoring(t, st, "whsec-distinct-value")
	if _, _, err := st.RecordWebhookTrigger(ctx, strings.Repeat("b", 64), []string{"nodeCreated"}, nil); err != nil {
		t.Fatal(err)
	}
	body = authGet(t, server, "/settings", cookies).Body.String()
	document = htmlDocument(t, body)
	state = htmlElements(document, func(node *html.Node) bool { id, _ := htmlAttr(node, "id"); return id == "webhook-state" })
	text := htmlText(state[0])
	if !strings.Contains(text, "Webhook acceleration: enabled") || !strings.Contains(text, "last accepted delivery") || !strings.Contains(text, " UTC") {
		t.Fatalf("webhook state with a secret: %q", text)
	}
	if !strings.Contains(body, `name="clear_webhook_secret"`) || !strings.Contains(body, "Leave blank to keep current secret") {
		t.Fatal("remove-secret checkbox missing although a webhook secret exists")
	}
	if strings.Contains(body, "whsec-distinct-value") {
		t.Fatal("settings page rendered the webhook secret")
	}
}

func TestHistoryDateFilterAndBidirectionalPaging(t *testing.T) {
	server, st, _, cookies := webServerWithDatabase(t)
	ctx := context.Background()
	generation := configureMonitoring(t, st, "")
	device := func(hostname string) []model.Collected {
		return []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: "server", Data: map[string]any{"hostname": hostname}}}}}
	}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, device("server"), notify.TextDigest("baseline")); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for index := range 23 {
		batch, err := st.ApplyBatchWithBatch(ctx, generation, device(fmt.Sprintf("server-%d", index)), notify.TextDigest("change"))
		if err != nil || batch.ID == 0 {
			t.Fatalf("batch %d err=%v", index, err)
		}
		ids = append(ids, batch.ID)
	}
	today := time.Now().UTC().Format(historyDateLayout)
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(historyDateLayout)
	batchCount := func(body string) int {
		return len(htmlElements(htmlDocument(t, body), func(node *html.Node) bool { return htmlHasClass(node, "history-batch") }))
	}
	link := func(body, rel string) string {
		for _, anchor := range htmlElements(htmlDocument(t, body), htmlTag("a")) {
			if value, _ := htmlAttr(anchor, "rel"); value == rel {
				href, _ := htmlAttr(anchor, "href")
				return href
			}
		}
		return ""
	}

	first := authGet(t, server, "/history?from="+yesterday+"&to="+today, cookies).Body.String()
	assertAccessiblePage(t, "history", first)
	if batchCount(first) != 20 || link(first, "prev") != "" {
		t.Fatalf("first page batches=%d prev=%q", batchCount(first), link(first, "prev"))
	}
	if !strings.Contains(first, `value="`+yesterday+`"`) || !strings.Contains(first, `value="`+today+`"`) {
		t.Fatal("date filters are not preserved in the form")
	}
	older := link(first, "next")
	if !strings.Contains(older, "from="+yesterday) || !strings.Contains(older, "to="+today) || !strings.Contains(older, "cursor=") {
		t.Fatalf("older link loses the date range: %q", older)
	}
	second := authGet(t, server, older, cookies).Body.String()
	if batchCount(second) != 3 || link(second, "next") != "" {
		t.Fatalf("second page batches=%d next=%q", batchCount(second), link(second, "next"))
	}
	newer := link(second, "prev")
	if !strings.Contains(newer, "after=") || !strings.Contains(newer, "from="+yesterday) {
		t.Fatalf("newer link=%q", newer)
	}
	back := authGet(t, server, newer, cookies).Body.String()
	if batchCount(back) != 20 || link(back, "prev") != "" || link(back, "next") == "" {
		t.Fatalf("paging back returned %d batches prev=%q next=%q", batchCount(back), link(back, "prev"), link(back, "next"))
	}
	if !strings.Contains(back, fmt.Sprintf("Batch #%d", ids[len(ids)-1])) {
		t.Fatal("paging back did not return to the newest batch")
	}

	excluded := authGet(t, server, "/history?to="+yesterday, cookies).Body.String()
	if batchCount(excluded) != 0 || !strings.Contains(excluded, "No changes match these filters") {
		t.Fatalf("date range before every batch returned %d batches", batchCount(excluded))
	}
	invalid := authGet(t, server, "/history?from=05/10/2026", cookies).Body.String()
	assertAccessiblePage(t, "history", invalid)
	if !strings.Contains(flashText(t, invalid, "error"), "YYYY-MM-DD") || batchCount(invalid) != 20 {
		t.Fatalf("invalid date was not reported: %s", flashText(t, invalid, "error"))
	}
	reversed := authGet(t, server, "/history?from="+today+"&to="+yesterday, cookies).Body.String()
	if !strings.Contains(flashText(t, reversed, "error"), "end date is before the start date") || batchCount(reversed) != 0 {
		t.Fatal("reversed range was not reported")
	}
	export := authGet(t, server, "/history/export?from="+today+"&to="+today, cookies)
	if export.Code != http.StatusOK || !strings.Contains(export.Body.String(), `"from": "`+today+`T00:00:00Z"`) {
		t.Fatalf("ranged export status=%d body=%.300s", export.Code, export.Body.String())
	}
	if err := store.VerifyEvidencePack(export.Body.Bytes()); err != nil {
		t.Fatalf("ranged web export did not verify: %v", err)
	}
}

func TestHistoryDateAndPagingHelpers(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/history?from=2026-10-01&to=2026-10-03&after=7", nil)
	filter := historyFilter(request)
	if !filter.From.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || !filter.Until.Equal(time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)) || filter.After != 7 {
		t.Fatalf("date filter=%#v", filter)
	}
	if from, to := historyDateValues(filter); from != "2026-10-01" || to != "2026-10-03" {
		t.Fatalf("date values=%q %q", from, to)
	}
	if got := historyNewerURL(filter, 9); !strings.Contains(got, "after=9") || !strings.Contains(got, "from=2026-10-01") || !strings.Contains(got, "to=2026-10-03") {
		t.Fatalf("newer URL=%q", got)
	}
	if got := historyExportURL(filter); !strings.Contains(got, "from=2026-10-01") || strings.Contains(got, "after=") {
		t.Fatalf("export URL=%q", got)
	}
	if cursorWins := historyFilter(httptest.NewRequest(http.MethodGet, "/history?cursor=5&after=7", nil)); cursorWins.Cursor != 5 || cursorWins.After != 0 {
		t.Fatalf("cursor and after both set: %#v", cursorWins)
	}
	for _, query := range []string{"from=yesterday", "to=2026-13-01", "from=2026-10-01&to=bad"} {
		if historyDateError(httptest.NewRequest(http.MethodGet, "/history?"+query, nil)) == "" {
			t.Fatalf("invalid date %q accepted silently", query)
		}
	}
	if message := historyDateError(httptest.NewRequest(http.MethodGet, "/history?from=2026-10-01&to=2026-10-01", nil)); message != "" {
		t.Fatalf("single-day range rejected: %q", message)
	}
}

func TestFlashMessagesAreSignedAndOneTime(t *testing.T) {
	server, _, _ := testServer(t)
	response := httptest.NewRecorder()
	server.setFlash(response, flashKindSuccess, "Saved.")
	cookie := response.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != flashMaxAge {
		t.Fatalf("flash cookie attributes=%#v", cookie)
	}
	read := func(value string) (flashMessage, bool, *httptest.ResponseRecorder) {
		request := httptest.NewRequest(http.MethodGet, "/settings", nil)
		request.AddCookie(&http.Cookie{Name: flashCookieName, Value: value})
		recorder := httptest.NewRecorder()
		message, ok := server.takeFlash(recorder, request)
		return message, ok, recorder
	}
	message, ok, recorder := read(cookie.Value)
	if !ok || message.Message != "Saved." || message.Kind != flashKindSuccess {
		t.Fatalf("flash=%#v ok=%v", message, ok)
	}
	if cleared := recorder.Result().Cookies(); len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatal("reading a flash message must clear it")
	}
	payload, _, _ := strings.Cut(cookie.Value, ".")
	other, _ := New(server.config, server.store, server.engine)
	forgedResponse := httptest.NewRecorder()
	other.setFlash(forgedResponse, flashKindError, "Planted text")
	for _, value := range []string{
		"no-signature",
		payload + ".!!!",
		payload + ".AAAA",
		forgedResponse.Result().Cookies()[0].Value, // signed by another key
		"!!!." + strings.SplitN(cookie.Value, ".", 2)[1],
	} {
		if _, ok, _ := read(value); ok {
			t.Fatalf("flash value %q was accepted", value)
		}
	}
	signedJunk := func(raw string) string {
		encoded := base64URL(raw)
		return encoded + "." + base64URL(string(server.flashSignature(encoded)))
	}
	for _, raw := range []string{"not json", `{"k":"info","m":"x"}`, `{"k":"success","m":""}`} {
		if _, ok, _ := read(signedJunk(raw)); ok {
			t.Fatalf("flash payload %q was accepted", raw)
		}
	}
	if _, ok := server.takeFlash(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("flash reported without a cookie")
	}
}
