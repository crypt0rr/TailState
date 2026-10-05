package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/crypt0rr/tailstate/internal/store"
)

// followFlash loads the page a Post/Redirect/Get response points at, as a
// browser would, and returns its body.
func followFlash(t *testing.T, server *Server, cookies []*http.Cookie, response *httptest.ResponseRecorder) string {
	t.Helper()
	location := response.Header().Get("Location")
	if location == "" {
		t.Fatalf("response %d is not a redirect: %s", response.Code, response.Body.String())
	}
	return authGet(t, server, location, mergeCookies(cookies, response)).Body.String()
}

func cookieCleared(response *httptest.ResponseRecorder, name string) bool {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestSafeReturnPathRejectsOffSiteTargets(t *testing.T) {
	for _, raw := range []string{
		"",
		"//evil.example",
		"///evil.example",
		"https://evil.example",
		"http://evil.example/status",
		"HTTPS://evil.example",
		"javascript:alert(1)",
		"evil.example",
		"/\\evil.example",
		"\\\\evil.example",
		"/\\/evil.example",
		"%2F%2Fevil.example",
		"/%2F%2Fevil.example",
		"/%2fevil.example",
		"/%5Cevil.example",
		"/%5c%5cevil.example",
		"/\t/evil.example",
		"/\n/evil.example",
		" //evil.example",
		"/status/../..//evil.example",
		"/status/%2e%2e/%2e%2e//evil.example",
		"/%73tatus",
		"/login",
		"/logout",
		"/setup",
		"/history/export",
		"/metrics",
		"/status?" + strings.Repeat("a", maxReturnPathBytes),
	} {
		if got, ok := safeReturnPath(raw); ok {
			t.Fatalf("safeReturnPath(%q) accepted %q", raw, got)
		}
		if location := loginURL(raw); location != "/login" {
			t.Fatalf("loginURL(%q)=%q", raw, location)
		}
	}
	for raw, want := range map[string]string{
		"/status":                              "/status",
		"/settings":                            "/settings",
		"/history?resource=a%2Fb&cursor=3":     "/history?resource=a%2Fb&cursor=3",
		"/history?next=https://evil.example":   "/history?next=https://evil.example",
		"/status#fragment":                     "/status",
		"/history?collector=devices&from=2026": "/history?collector=devices&from=2026",
	} {
		if got, ok := safeReturnPath(raw); !ok || got != want {
			t.Fatalf("safeReturnPath(%q)=%q,%v want %q", raw, got, ok, want)
		}
	}
	if got := loginURL("/history?resource=x"); got != "/login?next=%2Fhistory%3Fresource%3Dx" {
		t.Fatalf("loginURL=%q", got)
	}
	for path, want := range map[string]string{"/settings/destinations/test": "/settings", "/settings": "/settings", "/status/reconcile": "/status", "/logout": "", "/settingsx": ""} {
		if got := postReturnPage(path); got != want {
			t.Fatalf("postReturnPage(%q)=%q want %q", path, got, want)
		}
	}
}

func loginWithNext(t *testing.T, server *Server, next string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"password": {"a secure password"}}
	if next != "" {
		form.Set("next", next)
	}
	return coveragePost(t, server, "/login", form, nil)
}

func TestLoginNeverRedirectsOffSite(t *testing.T) {
	server, _, setupToken := testServer(t)
	claimCoverageAdmin(t, server, setupToken)
	for _, next := range []string{"//evil.example", "https://evil.example", "/\\evil.example", "/%2F%2Fevil.example", "\\\\evil.example"} {
		page := httptest.NewRecorder()
		server.Handler().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/login?next="+url.QueryEscape(next), nil))
		if strings.Contains(page.Body.String(), `name="next"`) {
			t.Fatalf("login page carried unsafe next %q", next)
		}
		response := loginWithNext(t, server, next)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
			t.Fatalf("login with next=%q redirected to %q", next, response.Header().Get("Location"))
		}
	}
	page := httptest.NewRecorder()
	server.Handler().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/login?next="+url.QueryEscape("/history?resource=laptop"), nil))
	inputs := htmlElements(htmlDocument(t, page.Body.String()), func(node *html.Node) bool {
		name, _ := htmlAttr(node, "name")
		return node.Data == "input" && name == "next"
	})
	if len(inputs) != 1 {
		t.Fatal("login page did not carry a safe next target")
	}
	if value, _ := htmlAttr(inputs[0], "value"); value != "/history?resource=laptop" {
		t.Fatalf("next value=%q", value)
	}
	failed := coveragePost(t, server, "/login", url.Values{"password": {"wrong password"}, "next": {"/settings"}}, nil)
	if !strings.Contains(failed.Body.String(), `name="next" value="/settings"`) {
		t.Fatal("a failed login dropped the return target")
	}
	response := loginWithNext(t, server, "/history?resource=laptop")
	if response.Header().Get("Location") != "/history?resource=laptop" {
		t.Fatalf("login returned to %q", response.Header().Get("Location"))
	}
	// An already authenticated visit to the login page follows next too.
	again := authGet(t, server, "/login?next=%2Fsettings", response.Result().Cookies())
	if again.Code != http.StatusSeeOther || again.Header().Get("Location") != "/settings" {
		t.Fatalf("authenticated login page redirected to %q", again.Header().Get("Location"))
	}
	if home := authGet(t, server, "/login?next=%2F%2Fevil.example", response.Result().Cookies()); home.Header().Get("Location") != "/status" {
		t.Fatalf("authenticated login page followed an unsafe next: %q", home.Header().Get("Location"))
	}
}

func TestStaleSessionPostReturnsToPageAfterLogin(t *testing.T) {
	server, st, setupToken := testServer(t)
	cookies := claimCoverageAdmin(t, server, setupToken)
	csrf := coverageCSRF(t, cookies)
	var session string
	for _, cookie := range cookies {
		if cookie.Name == "tailstate_session" {
			session = cookie.Value
		}
	}
	// The session ends (expiry, logout elsewhere, or a password reset) while
	// the settings page is still open in the browser.
	st.DeleteSession(context.Background(), session)

	stale := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "id": {"1"}}, cookies)
	if stale.Code != http.StatusSeeOther || stale.Header().Get("Location") != "/login?next=%2Fsettings" {
		t.Fatalf("stale POST status=%d location=%q body=%s", stale.Code, stale.Header().Get("Location"), stale.Body.String())
	}
	if !cookieCleared(stale, "tailstate_session") || !cookieCleared(stale, "tailstate_csrf") {
		t.Fatal("stale session cookies were not cleared")
	}
	loginPage := authGet(t, server, stale.Header().Get("Location"), mergeCookies(cookies, stale))
	if loginPage.Code != http.StatusOK || !strings.Contains(loginPage.Body.String(), `name="next" value="/settings"`) {
		t.Fatalf("login page status=%d does not carry the return page", loginPage.Code)
	}
	login := loginWithNext(t, server, "/settings")
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != "/settings" {
		t.Fatalf("login after a stale POST returned to %q", login.Header().Get("Location"))
	}
	if page := authGet(t, server, "/settings", login.Result().Cookies()); page.Code != http.StatusOK {
		t.Fatalf("returned settings page status=%d", page.Code)
	}

	// Deep links survive the login round trip as well.
	deep := authGet(t, server, "/history?resource=laptop", nil)
	if deep.Header().Get("Location") != "/login?next=%2Fhistory%3Fresource%3Dlaptop" {
		t.Fatalf("deep link redirected to %q", deep.Header().Get("Location"))
	}

	// A request without any session cookie (for example a cross-site form,
	// which SameSite=Strict strips) is sent to login without touching cookies.
	anonymous := coveragePost(t, server, "/status/reconcile", url.Values{}, nil)
	if anonymous.Code != http.StatusSeeOther || anonymous.Header().Get("Location") != "/login?next=%2Fstatus" || len(anonymous.Result().Cookies()) != 0 {
		t.Fatalf("anonymous POST status=%d location=%q cookies=%v", anonymous.Code, anonymous.Header().Get("Location"), anonymous.Result().Cookies())
	}
	staleLogout := coveragePost(t, server, "/logout", url.Values{"_csrf": {csrf}}, cookies)
	if staleLogout.Code != http.StatusSeeOther || staleLogout.Header().Get("Location") != "/login" || !cookieCleared(staleLogout, "tailstate_session") {
		t.Fatalf("stale logout status=%d location=%q", staleLogout.Code, staleLogout.Header().Get("Location"))
	}
}

func TestForgedCSRFKeepsSessionAndChangesNothing(t *testing.T) {
	server, st, _, cookies := webServerWithDatabase(t)
	configureMonitoring(t, st, "")
	destinations, err := st.ListDestinations(context.Background())
	if err != nil || len(destinations) != 1 {
		t.Fatalf("destinations=%v err=%v", destinations, err)
	}
	id := strconv.FormatInt(destinations[0].ID, 10)
	for _, test := range []struct{ path, id string }{
		{"/settings/destinations/remove", id},
		{"/settings/destinations/disable", id},
		{"/settings/destinations/test", id},
		{"/status/reconcile", ""},
		{"/status/destinations/retry", id},
		{"/settings", ""},
		{"/logout", ""},
	} {
		response := coveragePost(t, server, test.path, url.Values{"_csrf": {"forged"}, "id": {test.id}, "confirm": {"remove"}}, cookies)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s with a forged CSRF token status=%d", test.path, response.Code)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatalf("%s with a forged CSRF token changed cookies", test.path)
		}
	}
	after, err := st.ListDestinations(context.Background())
	if err != nil || len(after) != 1 || !after[0].Enabled {
		t.Fatalf("forged requests changed destinations: %v err=%v", after, err)
	}
	if page := authGet(t, server, "/settings", cookies); page.Code != http.StatusOK {
		t.Fatalf("session did not survive forged requests: %d", page.Code)
	}
}

func TestSendTestReloadNeverResends(t *testing.T) {
	var sent atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	server, st, _, cookies := webServerWithDatabase(t)
	csrf := coverageCSRF(t, cookies)
	id, err := st.SaveDestination(context.Background(), store.NotificationDestination{Name: "Webhook", ServiceURL: strings.Replace(upstream.URL, "http://", "generic://", 1) + "?disabletls=true", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	response := coveragePost(t, server, "/settings/destinations/test", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(id, 10)}}, cookies)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings" {
		t.Fatalf("send test status=%d location=%q; it must redirect instead of rendering", response.Code, response.Header().Get("Location"))
	}
	if sent.Load() != 1 {
		t.Fatalf("test notifications sent=%d", sent.Load())
	}
	browser := mergeCookies(cookies, response)
	first := authGet(t, server, "/settings", browser)
	if flashText(t, first.Body.String(), "success") != "Notification test sent." {
		t.Fatalf("test result not shown after redirect: %s", first.Body.String())
	}
	browser = mergeCookies(browser, first)
	for range 2 { // reloads
		reload := authGet(t, server, "/settings", browser)
		if flashText(t, reload.Body.String(), "success") != "" {
			t.Fatal("test result was shown again on reload")
		}
		browser = mergeCookies(browser, reload)
	}
	if sent.Load() != 1 {
		t.Fatalf("reloading the result page resent the test: sent=%d", sent.Load())
	}

	saved := coveragePost(t, server, "/settings/destinations", url.Values{"_csrf": {csrf}, "action": {"save"}, "name": {"Second"}, "service_url": {"generic://second.example/hook"}, "enabled": {"on"}}, cookies)
	if text := flashText(t, followFlash(t, server, cookies, saved), "success"); text != "Notification destination saved." {
		t.Fatalf("save flash=%q", text)
	}
	disabled := coveragePost(t, server, "/settings/destinations/disable", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(id, 10)}}, cookies)
	if text := flashText(t, followFlash(t, server, cookies, disabled), "success"); !strings.HasPrefix(text, "Notification destination disabled") {
		t.Fatalf("disable flash=%q", text)
	}
	enabled := coveragePost(t, server, "/settings/destinations/enable", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(id, 10)}}, cookies)
	if text := flashText(t, followFlash(t, server, cookies, enabled), "success"); text != "Notification destination enabled." {
		t.Fatalf("enable flash=%q", text)
	}
}

func seedPendingDelivery(t *testing.T, db *sql.DB, destinationID int64) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec("INSERT INTO outbox(destination_id,payload,status,next_attempt,first_attempt,created_at) VALUES(?,?,'pending',?,?,?)", destinationID, "payload", time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), now, now); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveDestinationRequiresConfirmation(t *testing.T) {
	server, st, db, cookies := webServerWithDatabase(t)
	csrf := coverageCSRF(t, cookies)
	id, err := st.SaveDestination(context.Background(), store.NotificationDestination{Name: "Pager", ServiceURL: "generic://pager.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	seedPendingDelivery(t, db, id)
	seedPendingDelivery(t, db, id)

	page := authGet(t, server, "/settings", cookies)
	document := assertAccessiblePage(t, "settings", page.Body.String())
	removeForms := htmlElements(document, func(node *html.Node) bool {
		action, _ := htmlAttr(node, "action")
		return node.Data == "form" && strings.HasPrefix(action, "/settings/destinations/") && (strings.HasSuffix(action, "/delete") || strings.HasSuffix(action, "/remove"))
	})
	if len(removeForms) != 1 {
		t.Fatalf("remove forms=%d", len(removeForms))
	}
	confirmation := htmlAncestor(removeForms[0], "details")
	if confirmation == nil || !htmlHasClass(confirmation, "destination-remove") {
		t.Fatal("the remove form is not behind a confirmation step")
	}
	if _, open := htmlAttr(confirmation, "open"); open {
		t.Fatal("the confirmation step must start closed")
	}
	if text := htmlText(confirmation); !strings.Contains(text, "2 pending notifications for this destination will be dead-lettered") {
		t.Fatalf("confirmation does not state the pending notifications: %q", text)
	}

	unconfirmed := coveragePost(t, server, "/settings/destinations/remove", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(id, 10)}}, cookies)
	if text := flashText(t, followFlash(t, server, cookies, unconfirmed), "error"); !strings.Contains(text, "was not removed") {
		t.Fatalf("unconfirmed removal flash=%q", text)
	}
	if active, err := st.ListDestinations(context.Background()); err != nil || len(active) != 1 {
		t.Fatalf("unconfirmed removal deleted the destination: %v err=%v", active, err)
	}
	confirmed := coveragePost(t, server, "/settings/destinations/delete", url.Values{"_csrf": {csrf}, "id": {strconv.FormatInt(id, 10)}, "confirm": {"remove"}}, cookies)
	if text := flashText(t, followFlash(t, server, cookies, confirmed), "success"); text != "Removed Pager; 2 pending notifications were dead-lettered." {
		t.Fatalf("confirmed removal flash=%q", text)
	}
	if active, err := st.ListDestinations(context.Background()); err != nil || len(active) != 0 {
		t.Fatalf("confirmed removal kept the destination: %v err=%v", active, err)
	}
	var dead int
	if err := db.QueryRow("SELECT COUNT(*) FROM outbox WHERE destination_id=? AND status='dead'", id).Scan(&dead); err != nil || dead != 2 {
		t.Fatalf("dead-lettered=%d err=%v", dead, err)
	}
}

func TestDestinationActionsSurviveDeliveryStateErrors(t *testing.T) {
	server, st, db, cookies := webServerWithDatabase(t)
	id, err := st.SaveDestination(context.Background(), store.NotificationDestination{Name: "Pager", ServiceURL: "generic://pager.example/hook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if name, pending := server.destinationPending(context.Background(), id+100); name != "the destination" || pending != 0 {
		t.Fatalf("unknown destination pending=%q/%d", name, pending)
	}
	// Without the outbox the delivery summary fails; the settings and status
	// pages still render and removal still reports a generic name.
	if _, err := db.Exec("DROP TABLE outbox"); err != nil {
		t.Fatal(err)
	}
	if page := authGet(t, server, "/settings", cookies); page.Code != http.StatusOK {
		t.Fatalf("settings without delivery state status=%d", page.Code)
	}
	if page := authGet(t, server, "/status", cookies); page.Code == http.StatusOK && strings.Contains(page.Body.String(), "Retry dead letters") {
		t.Fatal("status offered a retry without delivery state")
	}
	if name, pending := server.destinationPending(context.Background(), id); name != "the destination" || pending != 0 {
		t.Fatalf("pending without outbox=%q/%d", name, pending)
	}
	if got := server.storedDestinationURL(context.Background(), id+100); got != "" {
		t.Fatalf("unknown destination URL=%q", got)
	}
}
