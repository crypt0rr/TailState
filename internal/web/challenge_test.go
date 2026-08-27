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
	if tamperedBytes[len(tamperedBytes)-1] == 'A' {
		tamperedBytes[len(tamperedBytes)-1] = 'B'
	} else {
		tamperedBytes[len(tamperedBytes)-1] = 'A'
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
	expiresUnix := time.Now().UTC().Add(-time.Second).Unix()
	payload := strings.Join([]string{string(credentialActionLogin), nonce, strconv.FormatInt(expiresUnix, 10)}, ".")
	challenge := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(server.signCredentialChallenge([]byte(payload)))
	cookie := &http.Cookie{Name: credentialActionLogin.cookieName(), Value: nonce}
	server.challengeMu.Lock()
	server.challenges[nonce] = credentialChallengeRecord{action: credentialActionLogin, expiresAt: time.Unix(expiresUnix, 0).UTC()}
	server.challengeMu.Unlock()
	expiredRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"_challenge": {challenge}}.Encode()))
	expiredRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	expiredRequest.AddCookie(cookie)
	if server.validateCredentialChallenge(expiredRequest, credentialActionLogin) {
		t.Fatal("expired challenge was accepted")
	}
	if got := server.credentialChallengeCount(credentialActionLogin, challengeOutcomeExpired); got != 1 {
		t.Fatalf("expired challenge count=%d", got)
	}

	issued := httptest.NewRecorder()
	setupChallenge, err := server.issueCredentialChallenge(issued, credentialActionSetup)
	if err != nil {
		t.Fatal(err)
	}
	setupCookie := issued.Result().Cookies()[0]
	actionRequest := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"_challenge": {setupChallenge}}.Encode()))
	actionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The cookie name is intentionally bound to the endpoint as well as the
	// signed payload. Supplying a setup cookie to the login endpoint must not
	// turn the setup challenge into a login challenge.
	actionRequest.AddCookie(&http.Cookie{Name: credentialActionLogin.cookieName(), Value: setupCookie.Value})
	if server.validateCredentialChallenge(actionRequest, credentialActionLogin) {
		t.Fatal("cross-action challenge was accepted")
	}
	if got := server.credentialChallengeCount(credentialActionLogin, challengeOutcomeInvalid); got != 1 {
		t.Fatalf("cross-action invalid challenge count=%d", got)
	}
}

func TestCredentialChallengeBoundsAndUnsupportedActions(t *testing.T) {
	server, _, _ := testServer(t)
	if _, err := server.issueCredentialChallenge(httptest.NewRecorder(), credentialAction("unsupported")); err == nil {
		t.Fatal("unsupported credential action was accepted")
	}
	if got := credentialAction("unsupported").pagePath(); got != "/" {
		t.Fatalf("unsupported action page path=%q", got)
	}
	if got := credentialAction("unsupported").postPath(); got != "/" {
		t.Fatalf("unsupported action post path=%q", got)
	}

	now := time.Now().UTC().Add(time.Hour)
	server.challengeMu.Lock()
	for i := 0; i < maxCredentialChallenges; i++ {
		server.challenges["filled-"+url.QueryEscape(string(rune(i)))] = credentialChallengeRecord{action: credentialActionLogin, expiresAt: now}
	}
	server.challengeMu.Unlock()
	if _, err := server.issueCredentialChallenge(httptest.NewRecorder(), credentialActionLogin); err != nil {
		t.Fatal(err)
	}
	server.challengeMu.Lock()
	count := len(server.challenges)
	server.challengeMu.Unlock()
	if count != maxCredentialChallenges {
		t.Fatalf("challenge map size=%d, want %d", count, maxCredentialChallenges)
	}
}
