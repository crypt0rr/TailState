package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/secret"
)

func TestCredentialPagesIssueBoundChallenges(t *testing.T) {
	server, _, token := testServer(t)
	setupPage := httptest.NewRecorder()
	server.Handler().ServeHTTP(setupPage, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if setupPage.Code != http.StatusOK {
		t.Fatalf("setup page status=%d body=%s", setupPage.Code, setupPage.Body.String())
	}
	assertCredentialPageChallenge(t, setupPage, credentialActionSetup)

	if response := coveragePost(t, server, "/setup/claim", url.Values{
		"token":    {token},
		"password": {"a secure password"},
		"confirm":  {"a secure password"},
	}, nil); response.Code != http.StatusSeeOther {
		t.Fatalf("claim status=%d body=%s", response.Code, response.Body.String())
	}
	for _, action := range []credentialAction{credentialActionLogin, credentialActionReset} {
		page := httptest.NewRecorder()
		server.Handler().ServeHTTP(page, httptest.NewRequest(http.MethodGet, action.pagePath(), nil))
		if page.Code != http.StatusOK {
			t.Fatalf("%s page status=%d body=%s", action, page.Code, page.Body.String())
		}
		assertCredentialPageChallenge(t, page, action)
	}
}

func assertCredentialPageChallenge(t *testing.T, response *httptest.ResponseRecorder, action credentialAction) {
	t.Helper()
	body := response.Body.String()
	const marker = `name="_challenge" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("%s page has no hidden challenge field: %s", action, body)
	}
	start += len(marker)
	end := strings.IndexByte(body[start:], '"')
	if end <= 0 {
		t.Fatalf("%s page has an empty or malformed challenge field", action)
	}
	value := body[start : start+end]
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		t.Fatalf("%s challenge has %d parts", action, len(parts))
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		t.Fatalf("%s challenge payload is not base64url: %v", action, err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		t.Fatalf("%s challenge signature is not base64url: %v", action, err)
	}
	var challengeCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == action.cookieName() {
			challengeCookie = cookie
			break
		}
	}
	if challengeCookie == nil {
		t.Fatalf("%s page did not set its challenge cookie", action)
	}
	if challengeCookie.Path != action.pagePath() || !challengeCookie.HttpOnly || challengeCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("%s challenge cookie has unsafe attributes: %#v", action, challengeCookie)
	}
	if challengeCookie.MaxAge <= 0 || challengeCookie.MaxAge > int(credentialChallengeLifetime/time.Second) {
		t.Fatalf("%s challenge cookie max age=%d", action, challengeCookie.MaxAge)
	}
}

func TestCredentialChallengeRejectsMissingCrossSiteSubmission(t *testing.T) {
	server, st, token := testServer(t)
	missingSetup := url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}
	setupResponse := credentialPostWithoutChallenge(t, server, "/setup/claim", missingSetup, "https://attacker.example")
	if setupResponse.Code != http.StatusOK || !strings.Contains(setupResponse.Body.String(), credentialChallengeError) {
		t.Fatalf("missing setup challenge status=%d body=%s", setupResponse.Code, setupResponse.Body.String())
	}
	if exists, err := st.AdminExists(t.Context()); err != nil || exists {
		t.Fatalf("missing challenge changed admin state: exists=%v err=%v", exists, err)
	}
	if got := server.credentialChallengeCount(credentialActionSetup, challengeOutcomeMissing); got != 1 {
		t.Fatalf("missing setup challenge count=%d", got)
	}

	if response := coveragePost(t, server, "/setup/claim", url.Values{
		"token":    {token},
		"password": {"a secure password"},
		"confirm":  {"a secure password"},
	}, nil); response.Code != http.StatusSeeOther {
		t.Fatalf("claim status=%d body=%s", response.Code, response.Body.String())
	}
	for _, test := range []struct {
		action credentialAction
		form   url.Values
	}{
		{credentialActionLogin, url.Values{"password": {"a secure password"}}},
		{credentialActionReset, url.Values{"token": {"unknown"}, "password": {"another secure password"}, "confirm": {"another secure password"}}},
	} {
		response := credentialPostWithoutChallenge(t, server, test.action.postPath(), test.form, "https://attacker.example")
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), credentialChallengeError) {
			t.Fatalf("missing %s challenge status=%d body=%s", test.action, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "unknown") || strings.Contains(response.Body.String(), "another secure password") {
			t.Fatalf("missing %s challenge response echoed a credential value", test.action)
		}
		if got := server.credentialChallengeCount(test.action, challengeOutcomeMissing); got != 1 {
			t.Fatalf("missing %s challenge count=%d", test.action, got)
		}
	}
}

func credentialPostWithoutChallenge(t *testing.T, server *Server, path string, form url.Values, origin string) *httptest.ResponseRecorder {
	t.Helper()
	return coveragePostWithRequest(t, server, path, form, nil, "", "", http.Header{"Origin": {origin}})
}

func TestCredentialChallengeIsOneUseAndRejectsTampering(t *testing.T) {
	server, _, token := testServer(t)
	if response := coveragePost(t, server, "/setup/claim", url.Values{
		"token":    {token},
		"password": {"a secure password"},
		"confirm":  {"a secure password"},
	}, nil); response.Code != http.StatusSeeOther {
		t.Fatalf("claim status=%d body=%s", response.Code, response.Body.String())
	}

	challenge, cookie, available := coverageCredentialChallenge(t, server, credentialActionLogin)
	if !available {
		t.Fatal("login page did not issue a challenge")
	}
	form := url.Values{"password": {"wrong password"}, "_challenge": {challenge}}
	first := coveragePostWithRequest(t, server, "/login", form, []*http.Cookie{cookie}, "", "", nil)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "Invalid password") {
		t.Fatalf("first login status=%d body=%s", first.Code, first.Body.String())
	}
	replay := coveragePostWithRequest(t, server, "/login", form, []*http.Cookie{cookie}, "", "", nil)
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), credentialChallengeError) || strings.Contains(replay.Body.String(), "wrong password") {
		t.Fatalf("replayed login status=%d body=%s", replay.Code, replay.Body.String())
	}
	if got := server.credentialChallengeCount(credentialActionLogin, challengeOutcomeAccepted); got != 1 {
		t.Fatalf("accepted login challenge count=%d", got)
	}
	if got := server.credentialRejectionCount(credentialActionLogin); got != 1 {
		t.Fatalf("credential rejection count=%d", got)
	}

	tampered, tamperedCookie, available := coverageCredentialChallenge(t, server, credentialActionLogin)
	if !available {
		t.Fatal("login page did not issue a second challenge")
	}
	tamperedBytes := []byte(tampered)
	if tamperedBytes[0] == 'A' {
		tamperedBytes[0] = 'B'
	} else {
		tamperedBytes[0] = 'A'
	}
	form.Set("_challenge", string(tamperedBytes))
	response := coveragePostWithRequest(t, server, "/login", form, []*http.Cookie{tamperedCookie}, "", "", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), credentialChallengeError) {
		t.Fatalf("tampered login status=%d body=%s", response.Code, response.Body.String())
	}
	if got := server.credentialChallengeCount(credentialActionLogin, challengeOutcomeInvalid); got != 2 {
		t.Fatalf("invalid login challenge count=%d", got)
	}
	metrics := httptest.NewRecorder()
	metricsRequest := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRequest.RemoteAddr = "127.0.0.1:1234"
	server.Handler().ServeHTTP(metrics, metricsRequest)
	metricsBody := metrics.Body.String()
	for _, want := range []string{
		`tailstate_credential_challenge_total{action="login",outcome="accepted"} 1`,
		`tailstate_credential_challenge_total{action="login",outcome="invalid"} 2`,
		`tailstate_credential_rejections_total{action="login"} 1`,
	} {
		if !strings.Contains(metricsBody, want) {
			t.Fatalf("credential metric %q missing: %s", want, metricsBody)
		}
	}
	for _, secret := range []string{"wrong password", tampered} {
		if strings.Contains(metricsBody, secret) {
			t.Fatalf("credential value leaked into metrics: %q", secret)
		}
	}
}

func TestCredentialChallengeExpiryAndActionBinding(t *testing.T) {
	server, _, _ := testServer(t)
	nonce, err := secret.Token(32)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser-binding"
	expiresUnix := time.Now().UTC().Add(-time.Second).Unix()
	challenge := signedCredentialChallenge(server, credentialActionLogin, nonce, binding, expiresUnix)
	cookieValue := server.credentialChallengeCookieValue(credentialActionLogin, binding, strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	expiredRequest := credentialChallengeRequest("/login", challenge, credentialActionLogin.cookieName(), cookieValue)
	if server.validateCredentialChallenge(expiredRequest, credentialActionLogin) {
		t.Fatal("expired challenge was accepted")
	}
	if got := server.credentialChallengeCount(credentialActionLogin, challengeOutcomeExpired); got != 1 {
		t.Fatalf("expired challenge count=%d", got)
	}

	issued := httptest.NewRecorder()
	setupChallenge, err := server.issueCredentialChallenge(issued, nil, credentialActionSetup)
	if err != nil {
		t.Fatal(err)
	}
	setupCookie := issued.Result().Cookies()[0]
	// The cookie name is intentionally bound to the endpoint as well as the
	// signed payload. Supplying a setup cookie to the login endpoint must not
	// turn the setup challenge into a login challenge.
	actionRequest := credentialChallengeRequest("/login", setupChallenge, credentialActionLogin.cookieName(), setupCookie.Value)
	if server.validateCredentialChallenge(actionRequest, credentialActionLogin) {
		t.Fatal("cross-action challenge was accepted")
	}
	if got := server.credentialChallengeCount(credentialActionLogin, challengeOutcomeInvalid); got != 1 {
		t.Fatalf("cross-action invalid challenge count=%d", got)
	}
}

func TestCredentialChallengeBoundsAndUnsupportedActions(t *testing.T) {
	server, _, _ := testServer(t)
	if _, err := server.issueCredentialChallenge(httptest.NewRecorder(), nil, credentialAction("unsupported")); err == nil {
		t.Fatal("unsupported credential action was accepted")
	}
	if got := credentialAction("unsupported").pagePath(); got != "/" {
		t.Fatalf("unsupported action page path=%q", got)
	}
	if got := credentialAction("unsupported").postPath(); got != "/" {
		t.Fatalf("unsupported action post path=%q", got)
	}

	now := time.Now().UTC()
	future := now.Add(time.Hour)
	server.challengeMu.Lock()
	server.consumedChallenges["expired"] = now.Add(-time.Second)
	for i := 0; i < maxConsumedCredentialChallenges-1; i++ {
		server.consumedChallenges["filled-"+strconv.Itoa(i)] = future
	}
	server.challengeMu.Unlock()
	// The expired entry is pruned, leaving room for exactly one new nonce.
	if !server.consumeCredentialChallenge("fresh", future, now) {
		t.Fatal("consumed challenge cache did not prune expired entries")
	}
	if server.consumeCredentialChallenge("fresh", future, now) {
		t.Fatal("consumed nonce was accepted twice")
	}
	// A full cache of unexpired nonces fails closed rather than evicting a
	// nonce that would then become replayable.
	if server.consumeCredentialChallenge("overflow", future, now) {
		t.Fatal("full consumed challenge cache accepted a new nonce")
	}
	server.challengeMu.Lock()
	count := len(server.consumedChallenges)
	server.challengeMu.Unlock()
	if count != maxConsumedCredentialChallenges {
		t.Fatalf("consumed challenge cache size=%d, want %d", count, maxConsumedCredentialChallenges)
	}
}

// TestCredentialChallengeSurvivesUnauthenticatedPageFlood proves that page
// views cannot evict or exhaust challenge state: issuance is stateless, so a
// legitimate form still validates after a flood of challenge GETs from other
// addresses.
func TestCredentialChallengeSurvivesUnauthenticatedPageFlood(t *testing.T) {
	server, _, token := testServer(t)
	claimCoverageAdmin(t, server, token)
	challenge, cookie, available := coverageCredentialChallenge(t, server, credentialActionLogin)
	if !available {
		t.Fatal("login page did not issue a challenge")
	}
	server.challengeMu.Lock()
	before := len(server.consumedChallenges)
	server.challengeMu.Unlock()
	handler := server.Handler()
	for i := 0; i < 10_001; i++ {
		request := httptest.NewRequest(http.MethodGet, "/login", nil)
		request.RemoteAddr = "203.0.113." + strconv.Itoa(i%250+1) + ":1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("flood GET %d status=%d", i, response.Code)
		}
	}
	server.challengeMu.Lock()
	retained := len(server.consumedChallenges)
	server.challengeMu.Unlock()
	if retained != before {
		t.Fatalf("unauthenticated GETs retained %d server-side challenge entries", retained)
	}
	form := url.Values{"password": {"a secure password"}, "_challenge": {challenge}}
	response := coveragePostWithRequest(t, server, "/login", form, []*http.Cookie{cookie}, "", "198.51.100.1:1234", nil)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("legitimate login after flood status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestCredentialChallengeSupportsMultipleTabs opens two login tabs in
// sequence in the same browser; both forms must remain valid.
func TestCredentialChallengeSupportsMultipleTabs(t *testing.T) {
	server, _, token := testServer(t)
	claimCoverageAdmin(t, server, token)
	handler := server.Handler()

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/login", nil))
	firstChallenge := hiddenChallenge(t, first)
	firstCookie := findCookie(t, first, credentialActionLogin.cookieName())

	secondRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	secondRequest.AddCookie(firstCookie)
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, secondRequest)
	secondChallenge := hiddenChallenge(t, second)
	browserCookie := findCookie(t, second, credentialActionLogin.cookieName())
	if firstChallenge == secondChallenge {
		t.Fatal("second tab reused the first tab's nonce")
	}

	// The browser now holds only the refreshed cookie; the first tab's form
	// must still validate against it.
	wrong := coveragePostWithRequest(t, server, "/login", url.Values{"password": {"wrong password"}, "_challenge": {firstChallenge}}, []*http.Cookie{browserCookie}, "", "", nil)
	if wrong.Code != http.StatusOK || !strings.Contains(wrong.Body.String(), "Invalid password") {
		t.Fatalf("first tab submission status=%d body=%s", wrong.Code, wrong.Body.String())
	}
	right := coveragePostWithRequest(t, server, "/login", url.Values{"password": {"a secure password"}, "_challenge": {secondChallenge}}, []*http.Cookie{browserCookie}, "", "", nil)
	if right.Code != http.StatusSeeOther {
		t.Fatalf("second tab submission status=%d body=%s", right.Code, right.Body.String())
	}

	// A different browser (no or another binding cookie) cannot use the form.
	otherPage := httptest.NewRecorder()
	handler.ServeHTTP(otherPage, httptest.NewRequest(http.MethodGet, "/login", nil))
	otherCookie := findCookie(t, otherPage, credentialActionLogin.cookieName())
	_, _, freshAvailable := coverageCredentialChallenge(t, server, credentialActionLogin)
	if !freshAvailable {
		t.Fatal("login page unavailable")
	}
	thirdRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	thirdRequest.AddCookie(browserCookie)
	third := httptest.NewRecorder()
	handler.ServeHTTP(third, thirdRequest)
	crossBrowser := coveragePostWithRequest(t, server, "/login", url.Values{"password": {"a secure password"}, "_challenge": {hiddenChallenge(t, third)}}, []*http.Cookie{otherCookie}, "", "", nil)
	if crossBrowser.Code != http.StatusOK || !strings.Contains(crossBrowser.Body.String(), credentialChallengeError) {
		t.Fatalf("cross-browser submission status=%d body=%s", crossBrowser.Code, crossBrowser.Body.String())
	}
}

func TestCredentialChallengeIsRejectedAfterRestart(t *testing.T) {
	server, st, token := testServer(t)
	claimCoverageAdmin(t, server, token)
	challenge, cookie, available := coverageCredentialChallenge(t, server, credentialActionLogin)
	if !available {
		t.Fatal("login page did not issue a challenge")
	}
	restarted, err := New(server.config, st, server.engine)
	if err != nil {
		t.Fatal(err)
	}
	response := coveragePostWithRequest(t, restarted, "/login", url.Values{"password": {"a secure password"}, "_challenge": {challenge}}, []*http.Cookie{cookie}, "", "", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), credentialChallengeError) {
		t.Fatalf("challenge from previous process status=%d body=%s", response.Code, response.Body.String())
	}
}

func hiddenChallenge(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	const marker = `name="_challenge" value="`
	body := response.Body.String()
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("page has no challenge field: status=%d", response.Code)
	}
	start += len(marker)
	end := strings.IndexByte(body[start:], '"')
	return body[start : start+end]
}

func findCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not set cookie %q", name)
	return nil
}

func TestCredentialChallengeRejectsMalformedValues(t *testing.T) {
	server, _, _ := testServer(t)
	future := time.Now().UTC().Add(10 * time.Minute).Unix()
	nonce, err := secret.Token(32)
	if err != nil {
		t.Fatal(err)
	}
	const binding = "binding"
	cookie := server.credentialChallengeCookieValue(credentialActionLogin, binding, strconv.FormatInt(future, 10))
	valid := signedCredentialChallenge(server, credentialActionLogin, nonce, binding, future)
	cases := []struct {
		name      string
		challenge string
		cookie    string
		consumed  bool
	}{
		{name: "oversized", challenge: strings.Repeat("x", maxCredentialChallengeBytes+1), cookie: cookie},
		{name: "missing separator", challenge: "not-a-challenge", cookie: cookie},
		{name: "invalid base64", challenge: "!.c2hvcnQ", cookie: cookie},
		{name: "short signature", challenge: base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{"login", nonce, binding, strconv.FormatInt(future, 10)}, "."))) + ".c2hvcnQ", cookie: cookie},
		{name: "malformed payload", challenge: signedCredentialPayload(server, "login."+nonce+"."+binding), cookie: cookie},
		{name: "empty nonce", challenge: signedCredentialPayload(server, "login.."+binding+"."+strconv.FormatInt(future, 10)), cookie: cookie},
		{name: "invalid expiry", challenge: signedCredentialPayload(server, "login."+nonce+"."+binding+".not-a-number"), cookie: cookie},
		{name: "unsigned cookie", challenge: valid, cookie: binding},
		{name: "oversized cookie", challenge: valid, cookie: strings.Repeat("x", maxCredentialChallengeBytes+1)},
		{name: "cookie bad signature encoding", challenge: valid, cookie: binding + ".1.!"},
		{name: "cookie forged signature", challenge: valid, cookie: binding + "." + strconv.FormatInt(future, 10) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		{name: "cookie for another binding", challenge: valid, cookie: server.credentialChallengeCookieValue(credentialActionLogin, "other", strconv.FormatInt(future, 10))},
		{name: "cookie invalid expiry", challenge: valid, cookie: server.credentialChallengeCookieValue(credentialActionLogin, binding, "soon")},
		{name: "consumed nonce", challenge: valid, cookie: cookie, consumed: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if test.consumed {
				server.challengeMu.Lock()
				server.consumedChallenges[nonce] = time.Unix(future, 0)
				server.challengeMu.Unlock()
			}
			request := credentialChallengeRequest("/login", test.challenge, credentialActionLogin.cookieName(), test.cookie)
			if server.validateCredentialChallenge(request, credentialActionLogin) {
				t.Fatal("malformed challenge was accepted")
			}
		})
	}
	// An expired or forged cookie is never reused as the browser binding.
	if _, ok := server.credentialChallengeBinding(credentialActionLogin, server.credentialChallengeCookieValue(credentialActionLogin, binding, "1"), time.Now()); ok {
		t.Fatal("expired binding cookie was reused")
	}
	stale := httptest.NewRequest(http.MethodGet, "/login", nil)
	stale.AddCookie(&http.Cookie{Name: credentialActionLogin.cookieName(), Value: server.credentialChallengeCookieValue(credentialActionLogin, binding, "1")})
	issued := httptest.NewRecorder()
	if _, err := server.issueCredentialChallenge(issued, stale, credentialActionLogin); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(findCookie(t, issued, credentialActionLogin.cookieName()).Value, binding+".") {
		t.Fatal("expired binding cookie was refreshed instead of replaced")
	}

	server.challengeKey = nil
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/reset", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "temporarily unavailable") {
		t.Fatalf("unavailable challenge status=%d body=%s", response.Code, response.Body.String())
	}
}

func signedCredentialPayload(server *Server, payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(server.signCredentialChallenge([]byte(payload)))
}

func signedCredentialChallenge(server *Server, action credentialAction, nonce, binding string, expiresUnix int64) string {
	return signedCredentialPayload(server, strings.Join([]string{string(action), nonce, binding, strconv.FormatInt(expiresUnix, 10)}, "."))
}

func credentialChallengeRequest(path, challenge, cookieName, cookieValue string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"_challenge": {challenge}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	return request
}

// TestRejectedNewPasswordsDoNotConsumeChallenges guards R-051: setup and
// reset check the password policy before the challenge, so a flood of
// policy-failing submissions cannot fill the shared replay cache, while a
// mismatched confirmation still spends its challenge and counts as a failure.
func TestRejectedNewPasswordsDoNotConsumeChallenges(t *testing.T) {
	server, st, token := testServer(t)
	consumed := func() int {
		server.challengeMu.Lock()
		defer server.challengeMu.Unlock()
		return len(server.consumedChallenges)
	}
	weak := url.Values{"token": {"not-the-token"}, "password": {"short"}, "confirm": {"short"}}
	for _, action := range []credentialAction{credentialActionSetup, credentialActionReset} {
		if action == credentialActionReset {
			claimCoverageAdmin(t, server, token)
			if _, err := st.NewResetToken(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		before := consumed()
		for i := 0; i < 2*loginFailuresPerClient; i++ {
			response := coverageCredentialPost(t, server, action.postPath(), weak, nil, "", "", nil)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "at least 15 characters") {
				t.Fatalf("weak %s %d: status=%d body=%s", action, i, response.Code, response.Body.String())
			}
		}
		if got := consumed(); got != before {
			t.Fatalf("policy-failing %s submissions consumed %d challenges", action, got-before)
		}
	}
	if got := server.credentialChallengeCount(credentialActionReset, challengeOutcomeAccepted); got != 0 {
		t.Fatalf("policy-failing reset submissions validated %d challenges", got)
	}

	before := consumed()
	mismatch := url.Values{"token": {"not-the-token"}, "password": {"another secure password"}, "confirm": {"a different passphrase"}}
	for i := 0; i < loginFailuresPerClient; i++ {
		response := coverageCredentialPost(t, server, "/reset", mismatch, nil, "", "", nil)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Passwords do not match") {
			t.Fatalf("mismatched reset %d: status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	if got := consumed(); got != before+loginFailuresPerClient {
		t.Fatalf("mismatched submissions consumed %d challenges, want %d", got-before, loginFailuresPerClient)
	}
	if response := coverageCredentialPost(t, server, "/reset", mismatch, nil, "", "", nil); response.Code != http.StatusTooManyRequests {
		t.Fatalf("repeated mismatches were not throttled: status=%d", response.Code)
	}
}
