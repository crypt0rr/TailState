package web

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

const testAdminPassword = "a secure password"

// accountServer returns a server with config, its store, a raw database
// handle for adjusting timestamps, and a fresh setup token.
func accountServer(t *testing.T, config boot.Config) (*Server, *store.Store, *sql.DB, string) {
	t.Helper()
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tailstate.db")
	st, err := store.Open(path, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	config.ListenAddr = "127.0.0.1:0"
	config.TailscaleBase = "http://example.invalid"
	config.OAuthTokenURL = "http://example.invalid/oauth"
	config.Version = "test"
	server, err := New(config, st, monitor.New(st, config.TailscaleBase, config.OAuthTokenURL, config.Version))
	if err != nil {
		t.Fatal(err)
	}
	server.noticeSender = &recordingSender{}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	token, err := st.NewSetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return server, st, db, token
}

func loginCookies(t *testing.T, server *Server, password string) []*http.Cookie {
	t.Helper()
	response := coveragePost(t, server, "/login", url.Values{"password": {password}}, nil)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("login status %d: %s", response.Code, response.Body.String())
	}
	return sessionOnly(response.Result().Cookies())
}

// sessionOnly drops credential-challenge cookies so a cookie jar contains
// exactly the session generation under test.
func sessionOnly(cookies []*http.Cookie) []*http.Cookie {
	var out []*http.Cookie
	for _, cookie := range cookies {
		if strings.HasSuffix(cookie.Name, sessionCookieBase) || strings.HasSuffix(cookie.Name, csrfCookieBase) {
			if cookie.MaxAge >= 0 && cookie.Value != "" {
				out = append(out, cookie)
			}
		}
	}
	return out
}

func csrfFrom(t *testing.T, cookies []*http.Cookie) string {
	t.Helper()
	for _, cookie := range cookies {
		if strings.HasSuffix(cookie.Name, csrfCookieBase) {
			return cookie.Value
		}
	}
	t.Fatal("no CSRF cookie")
	return ""
}

func sessionFrom(t *testing.T, cookies []*http.Cookie) string {
	t.Helper()
	for _, cookie := range cookies {
		if strings.HasSuffix(cookie.Name, sessionCookieBase) {
			return cookie.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func signedIn(t *testing.T, server *Server, cookies []*http.Cookie) bool {
	t.Helper()
	response := authenticatedGet(t, server, "/settings", cookies)
	return response.Code == http.StatusOK
}

// TestPasswordPolicyErrorsAreSpecificBeforeTokenCheck guards E-023: setup and
// reset report the password rule that failed, not the generic token error,
// and the policy is checked before the token.
func TestPasswordPolicyErrorsAreSpecificBeforeTokenCheck(t *testing.T) {
	server, st, _, _ := accountServer(t, boot.Config{})
	for _, tc := range []struct {
		password string
		want     string
	}{
		{"twelve chars", "at least 15 characters"},
		{"PasswordPassword", "too common"},
	} {
		form := url.Values{"token": {"not-the-token"}, "password": {tc.password}, "confirm": {tc.password}}
		response := coveragePost(t, server, "/setup/claim", form, nil)
		body := response.Body.String()
		if !strings.Contains(body, tc.want) || strings.Contains(body, "Check the setup token") {
			t.Fatalf("setup with %q: status %d, body lacks %q or shows the token error", tc.password, response.Code, tc.want)
		}
	}
	if exists, _ := st.AdminExists(context.Background()); exists {
		t.Fatal("a policy failure created the administrator")
	}
	// A valid password with a wrong token still gets the generic token error.
	response := coveragePost(t, server, "/setup/claim", url.Values{"token": {"wrong"}, "password": {testAdminPassword}, "confirm": {testAdminPassword}}, nil)
	if !strings.Contains(response.Body.String(), "Check the setup token") {
		t.Fatalf("token error missing: %s", response.Body.String())
	}

	server, st, _, token := accountServer(t, boot.Config{})
	claimCoverageAdmin(t, server, token)
	if _, err := st.NewResetToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	response = coveragePost(t, server, "/reset", url.Values{"token": {"wrong"}, "password": {"short"}, "confirm": {"short"}}, nil)
	if body := response.Body.String(); !strings.Contains(body, "at least 15 characters") || strings.Contains(body, "invalid or expired") {
		t.Fatalf("reset policy error not specific: %s", body)
	}
	if page := authenticatedGet(t, server, "/reset", nil); !strings.Contains(page.Body.String(), `minlength="15"`) {
		t.Fatal("reset form does not advertise the 15-character minimum")
	}
}

// TestExistingShortPasswordStillSignsIn proves the policy applies only to new
// passwords: an administrator whose 12-character password was set by an
// older release can still sign in.
func TestExistingShortPasswordStillSignsIn(t *testing.T) {
	server, _, db, token := accountServer(t, boot.Config{})
	claimCoverageAdmin(t, server, token)
	const legacy = "twelve chars"
	salt := []byte("0123456789abcdef")
	sum := argon2.IDKey([]byte(legacy), salt, 3, 64*1024, 2, 32)
	encoded := fmt.Sprintf("argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
	if _, err := db.Exec("UPDATE admin SET password_hash=? WHERE id=1", encoded); err != nil {
		t.Fatal(err)
	}
	if cookies := loginCookies(t, server, legacy); !signedIn(t, server, cookies) {
		t.Fatal("legacy short password no longer signs in")
	}
}

// TestPasswordChangeRequiresCurrentPasswordAndRevokesOtherSessions guards
// E-023: the authenticated change form needs the current password, applies
// the policy with a specific message, and signs out every other session
// while keeping the one that made the change.
func TestPasswordChangeRequiresCurrentPasswordAndRevokesOtherSessions(t *testing.T) {
	server, _, _, token := accountServer(t, boot.Config{})
	current := sessionOnly(claimCoverageAdmin(t, server, token))
	other := loginCookies(t, server, testAdminPassword)
	const next = "violet harbor lantern"
	// Every outcome is a Post/Redirect/Get with a one-time flash message.
	post := func(form url.Values) string {
		form.Set("_csrf", csrfFrom(t, current))
		response := coveragePost(t, server, "/settings/password", form, current)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != accountSection {
			t.Fatalf("password form answered %d %q, want a redirect to Settings", response.Code, response.Header().Get("Location"))
		}
		return followFlash(t, server, current, response)
	}
	if response := coveragePost(t, server, "/settings/password", url.Values{"current_password": {testAdminPassword}, "password": {next}, "confirm": {next}}, current); response.Code != http.StatusForbidden {
		t.Fatalf("password change without CSRF returned %d", response.Code)
	}
	if body := post(url.Values{"current_password": {"wrong password!!"}, "password": {next}, "confirm": {next}}); !strings.Contains(body, "current password is incorrect") {
		t.Fatalf("wrong current password not reported: %s", body)
	}
	if body := post(url.Values{"current_password": {testAdminPassword}, "password": {"short"}, "confirm": {"short"}}); !strings.Contains(body, "at least 15 characters") {
		t.Fatalf("policy error not specific: %s", body)
	}
	if body := post(url.Values{"current_password": {testAdminPassword}, "password": {next}, "confirm": {"different passphrase"}}); !strings.Contains(body, "do not match") {
		t.Fatalf("mismatch not reported: %s", body)
	}
	if !signedIn(t, server, other) {
		t.Fatal("a rejected change signed out another session")
	}
	if body := post(url.Values{"current_password": {testAdminPassword}, "password": {next}, "confirm": {next}}); !strings.Contains(body, "Password changed") {
		t.Fatalf("password change failed: %s", body)
	}
	if reload := authenticatedGet(t, server, "/settings", current).Body.String(); strings.Contains(reload, "Password changed. Every other session") {
		t.Fatal("the password change message is shown again on reload")
	}
	if signedIn(t, server, other) {
		t.Fatal("changing the password did not revoke the other session")
	}
	if !signedIn(t, server, current) {
		t.Fatal("changing the password signed out the session that made the change")
	}
	if failed := coveragePost(t, server, "/login", url.Values{"password": {testAdminPassword}}, nil); failed.Code == http.StatusSeeOther {
		t.Fatal("the old password still signs in")
	}
	loginCookies(t, server, next)
}

func TestPasswordChangeThrottlesWrongCurrentPassword(t *testing.T) {
	server, _, _, token := accountServer(t, boot.Config{})
	cookies := sessionOnly(claimCoverageAdmin(t, server, token))
	form := url.Values{"_csrf": {csrfFrom(t, cookies)}, "current_password": {"wrong password!!"}, "password": {"violet harbor lantern"}, "confirm": {"violet harbor lantern"}}
	for i := 0; i < loginFailuresPerClient; i++ {
		response := coveragePost(t, server, "/settings/password", form, cookies)
		if body := followFlash(t, server, cookies, response); !strings.Contains(body, "current password is incorrect") {
			t.Fatalf("attempt %d: %s", i, body)
		}
	}
	response := coveragePost(t, server, "/settings/password", form, cookies)
	if body := followFlash(t, server, cookies, response); !strings.Contains(body, "Too many incorrect current passwords") {
		t.Fatalf("throttled attempt not reported: %s", body)
	}
	// The throttled attempt is refused before the password is checked, so
	// even the right current password is not accepted until the window ends.
	form.Set("current_password", testAdminPassword)
	response = coveragePost(t, server, "/settings/password", form, cookies)
	if body := followFlash(t, server, cookies, response); strings.Contains(body, "Password changed") {
		t.Fatal("a throttled client changed the password")
	}
}

// TestStatusAutoRefreshDoesNotExtendIdleSession guards E-023: the status
// page refreshes itself through a marked URL, which is authenticated but not
// counted as activity, so an unattended tab still reaches the idle timeout.
func TestStatusAutoRefreshDoesNotExtendIdleSession(t *testing.T) {
	server, _, db, token := accountServer(t, boot.Config{})
	cookies := sessionOnly(claimCoverageAdmin(t, server, token))
	page := authenticatedGet(t, server, "/status", cookies)
	if !strings.Contains(page.Body.String(), `content="30;url=/status?refresh=1"`) {
		t.Fatal("status page does not mark its automatic refresh")
	}
	setLastSeen := func(at time.Time) {
		t.Helper()
		if _, err := db.Exec("UPDATE sessions SET last_seen_at=?", at.UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	lastSeen := func() time.Time {
		t.Helper()
		var value string
		if err := db.QueryRow("SELECT last_seen_at FROM sessions").Scan(&value); err != nil {
			t.Fatal(err)
		}
		parsed, _ := time.Parse(time.RFC3339Nano, value)
		return parsed
	}
	idle := time.Now().Add(-50 * time.Minute)
	setLastSeen(idle)
	if response := authenticatedGet(t, server, "/status?refresh=1", cookies); response.Code != http.StatusOK {
		t.Fatalf("auto refresh within the idle window returned %d", response.Code)
	}
	if lastSeen().Sub(idle) > time.Second {
		t.Fatal("an automatic refresh extended the idle window")
	}
	setLastSeen(time.Now().Add(-store.SessionIdleTimeout - time.Minute))
	if response := authenticatedGet(t, server, "/status?refresh=1", cookies); response.Code != http.StatusSeeOther || response.Header().Get("Location") != loginURL("/status") {
		t.Fatalf("idle session survived an automatic refresh: %d %q", response.Code, response.Header().Get("Location"))
	}
	if signedIn(t, server, cookies) {
		t.Fatal("idle session is still valid")
	}

	// A user-initiated request inside the window extends it.
	cookies = loginCookies(t, server, testAdminPassword)
	setLastSeen(time.Now().Add(-50 * time.Minute))
	if response := authenticatedGet(t, server, "/status", cookies); response.Code != http.StatusOK {
		t.Fatalf("status returned %d", response.Code)
	}
	if time.Since(lastSeen()) > time.Minute {
		t.Fatal("user activity did not extend the idle window")
	}
}

// TestSessionListAndSignOutOtherSessions guards E-023's session management.
func TestSessionListAndSignOutOtherSessions(t *testing.T) {
	server, _, _, token := accountServer(t, boot.Config{})
	current := sessionOnly(claimCoverageAdmin(t, server, token))
	other := loginCookies(t, server, testAdminPassword)
	page := authenticatedGet(t, server, "/settings", current).Body.String()
	if !strings.Contains(page, "<code>"+store.SessionRef(sessionFrom(t, other))+"</code>") {
		t.Fatal("settings does not list the other session")
	}
	if !strings.Contains(page, "This session") || !strings.Contains(page, "Sign out all other sessions") {
		t.Fatal("settings does not mark the current session or offer sign-out")
	}
	if response := coveragePost(t, server, "/settings/sessions/revoke-others", url.Values{}, current); response.Code != http.StatusForbidden {
		t.Fatalf("revoke without CSRF returned %d", response.Code)
	}
	if !signedIn(t, server, other) {
		t.Fatal("a forged sign-out request revoked another session")
	}
	response := coveragePost(t, server, "/settings/sessions/revoke-others", url.Values{"_csrf": {csrfFrom(t, current)}}, current)
	if body := followFlash(t, server, current, response); !strings.Contains(body, "Signed out every other session") {
		t.Fatalf("revoke response: %s", body)
	}
	if signedIn(t, server, other) || !signedIn(t, server, current) {
		t.Fatal("sign out all other sessions did not keep exactly the current session")
	}
	response = coveragePost(t, server, "/settings/sessions/revoke-others", url.Values{"_csrf": {csrfFrom(t, current)}}, current)
	if body := followFlash(t, server, current, response); !strings.Contains(body, "No other session was active") {
		t.Fatalf("second revoke response: %s", body)
	}
}

// TestHSTSOnlyOnTrustedHTTPSRequests guards E-023: Strict-Transport-Security
// is sent only when the request reached TailState over HTTPS, either
// directly or through a trusted proxy; a forwarded-proto header from any
// other peer is ignored.
func TestHSTSOnlyOnTrustedHTTPSRequests(t *testing.T) {
	config := boot.Config{CookieSecure: true, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	server, _, _, _ := accountServer(t, config)
	for _, tc := range []struct {
		name   string
		remote string
		proto  string
		tls    bool
		want   bool
	}{
		{"trusted https proxy", "127.0.0.1:4000", "https", false, true},
		{"trusted proxy chain ends in https", "127.0.0.1:4000", "http, https", false, true},
		{"trusted http proxy", "127.0.0.1:4000", "http", false, false},
		{"untrusted peer claiming https", "192.0.2.10:4000", "https", false, false},
		{"plain request", "127.0.0.1:4000", "", false, false},
		{"direct TLS", "192.0.2.10:4000", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			request.RemoteAddr = tc.remote
			if tc.proto != "" {
				request.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			if tc.tls {
				request.TLS = &tls.ConnectionState{}
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			got := response.Header().Get("Strict-Transport-Security")
			if (got == hstsValue) != tc.want || (!tc.want && got != "") {
				t.Fatalf("HSTS header %q, want present=%v", got, tc.want)
			}
		})
	}
}

// TestSecureCookiesUseHostPrefixWithLegacyRollout guards E-023: with secure
// cookies, sessions use __Host- names, while sessions issued under the old
// names keep working until they expire; the two namings are never mixed.
func TestSecureCookiesUseHostPrefixWithLegacyRollout(t *testing.T) {
	config := boot.Config{CookieSecure: true, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	server, st, _, token := accountServer(t, config)
	claim := claimCoverageAdmin(t, server, token)
	cookies := sessionOnly(claim)
	if len(cookies) != 2 {
		t.Fatalf("expected two session cookies, got %v", cookies)
	}
	for _, cookie := range cookies {
		if !strings.HasPrefix(cookie.Name, hostCookiePrefix) || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatalf("cookie %q does not satisfy the __Host- rules: %+v", cookie.Name, cookie)
		}
	}
	if !signedIn(t, server, cookies) {
		t.Fatal("__Host- session cookies are not accepted")
	}
	legacyToken, legacyCSRF, err := st.CreateSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []*http.Cookie{{Name: sessionCookieBase, Value: legacyToken}, {Name: csrfCookieBase, Value: legacyCSRF}}
	if !signedIn(t, server, legacy) {
		t.Fatal("a session issued under the legacy cookie names was signed out by the rollout")
	}
	mixed := []*http.Cookie{{Name: hostCookiePrefix + sessionCookieBase, Value: legacyToken}, {Name: csrfCookieBase, Value: legacyCSRF}}
	if signedIn(t, server, mixed) {
		t.Fatal("a session cookie of one naming was accepted with a CSRF cookie of the other")
	}
	logout := coveragePost(t, server, "/logout", url.Values{"_csrf": {legacyCSRF}}, legacy)
	if logout.Code != http.StatusSeeOther {
		t.Fatalf("legacy logout status %d", logout.Code)
	}
	cleared := map[string]bool{}
	for _, cookie := range logout.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	for _, name := range []string{sessionCookieBase, csrfCookieBase, hostCookiePrefix + sessionCookieBase, hostCookiePrefix + csrfCookieBase} {
		if !cleared[name] {
			t.Fatalf("logout did not clear %q", name)
		}
	}
	// A new sign-in expires the legacy names so one generation remains.
	login := coveragePost(t, server, "/login", url.Values{"password": {testAdminPassword}}, legacy)
	expired := map[string]bool{}
	for _, cookie := range login.Result().Cookies() {
		if cookie.MaxAge < 0 {
			expired[cookie.Name] = true
		}
	}
	if !expired[sessionCookieBase] || !expired[csrfCookieBase] {
		t.Fatal("sign-in with secure cookies did not expire the legacy cookie names")
	}
}

// TestIdleSessionReturnsToPageAfterLoginWithHostCookies guards the
// interaction of E-023 with the login return flow: a session that reached
// the idle timeout (under either cookie naming) is sent to the login page
// with the page it was on, a stale form post clears both cookie namings,
// and signing in returns to that page under __Host- cookies.
func TestIdleSessionReturnsToPageAfterLoginWithHostCookies(t *testing.T) {
	config := boot.Config{CookieSecure: true, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	server, st, db, token := accountServer(t, config)
	cookies := sessionOnly(claimCoverageAdmin(t, server, token))
	legacyToken, legacyCSRF, err := st.CreateSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []*http.Cookie{{Name: sessionCookieBase, Value: legacyToken}, {Name: csrfCookieBase, Value: legacyCSRF}}
	if _, err := db.Exec("UPDATE sessions SET last_seen_at=?", time.Now().Add(-store.SessionIdleTimeout-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	const page = "/history?collector=devices"
	for name, jar := range map[string][]*http.Cookie{"__Host-": cookies, "legacy": legacy} {
		if response := authenticatedGet(t, server, page, jar); response.Code != http.StatusSeeOther || response.Header().Get("Location") != loginURL(page) {
			t.Fatalf("%s idle GET answered %d %q", name, response.Code, response.Header().Get("Location"))
		}
	}
	// The automatic refresh marker is not carried into the return target.
	if response := authenticatedGet(t, server, "/status?refresh=1", cookies); response.Header().Get("Location") != loginURL("/status") {
		t.Fatalf("idle auto-refresh return target %q", response.Header().Get("Location"))
	}
	stale := coveragePost(t, server, "/settings/password", url.Values{"_csrf": {legacyCSRF}, "current_password": {testAdminPassword}, "password": {"violet harbor lantern"}, "confirm": {"violet harbor lantern"}}, legacy)
	if stale.Code != http.StatusSeeOther || stale.Header().Get("Location") != loginURL("/settings") {
		t.Fatalf("stale password form answered %d %q", stale.Code, stale.Header().Get("Location"))
	}
	for _, name := range []string{sessionCookieBase, hostCookiePrefix + sessionCookieBase} {
		if !cookieCleared(stale, name) {
			t.Fatalf("stale form post did not clear %q", name)
		}
	}
	if !st.Authenticate(context.Background(), testAdminPassword) {
		t.Fatal("a stale form changed the password")
	}
	login := coveragePost(t, server, "/login", url.Values{"password": {testAdminPassword}, "next": {page}}, nil)
	if login.Code != http.StatusSeeOther || login.Header().Get("Location") != page {
		t.Fatalf("login with next answered %d %q", login.Code, login.Header().Get("Location"))
	}
	fresh := sessionOnly(login.Result().Cookies())
	if len(fresh) != 2 || !strings.HasPrefix(fresh[0].Name, hostCookiePrefix) || !strings.HasPrefix(fresh[1].Name, hostCookiePrefix) {
		t.Fatalf("login did not issue __Host- cookies: %v", fresh)
	}
	if response := authenticatedGet(t, server, page, fresh); response.Code != http.StatusOK {
		t.Fatalf("returned page answered %d", response.Code)
	}
}
