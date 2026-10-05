package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func wrongLogin(t *testing.T, server *Server, remoteAddr string) (int, string, string) {
	t.Helper()
	response := coverageCredentialPost(t, server, "/login", url.Values{"password": {"wrong password"}}, nil, "", remoteAddr, nil)
	return response.Code, response.Header().Get("Retry-After"), response.Body.String()
}

// TestLoginThrottleAggregatesIPv6Slash64 proves that one IPv6 host cannot
// obtain fresh guess budgets by rotating addresses inside its /64, while IPv4
// clients keep one bucket per address.
func TestLoginThrottleAggregatesIPv6Slash64(t *testing.T) {
	server, _, token := testServer(t)
	claimCoverageAdmin(t, server, token)
	for i := 1; i <= loginFailuresPerClient; i++ {
		if code, _, body := wrongLogin(t, server, "[2001:db8::"+strconv.Itoa(i)+"]:1234"); code != http.StatusOK || !strings.Contains(body, "Invalid password") {
			t.Fatalf("IPv6 failure %d status=%d", i, code)
		}
	}
	code, retry, body := wrongLogin(t, server, "[2001:db8::ffff]:1234")
	if code != http.StatusTooManyRequests || retry == "" || !strings.Contains(body, "Too many login attempts") {
		t.Fatalf("same /64 was not throttled: status=%d retry=%q", code, retry)
	}
	if code, _, _ := wrongLogin(t, server, "[2001:db8:0:1::1]:1234"); code != http.StatusOK {
		t.Fatalf("a different /64 shared the bucket: status=%d", code)
	}

	for i := 0; i < loginFailuresPerClient; i++ {
		if code, _, _ := wrongLogin(t, server, "192.0.2.1:1234"); code != http.StatusOK {
			t.Fatalf("IPv4 failure %d status=%d", i, code)
		}
	}
	if code, _, _ := wrongLogin(t, server, "192.0.2.1:4321"); code != http.StatusTooManyRequests {
		t.Fatalf("IPv4 client was not throttled: status=%d", code)
	}
	if code, _, _ := wrongLogin(t, server, "192.0.2.2:1234"); code != http.StatusOK {
		t.Fatalf("neighbouring IPv4 address shared the bucket: status=%d", code)
	}

	for raw, want := range map[string]string{
		"192.0.2.1":          "192.0.2.1",
		"::ffff:192.0.2.1":   "192.0.2.1",
		"2001:db8::1":        "2001:db8::/64",
		"2001:db8::abcd:1":   "2001:db8::/64",
		"fe80::1%eth0":       "fe80::/64",
		"not-an-address":     "not-an-address",
		"2001:db8:1:2:3::99": "2001:db8:1:2::/64",
	} {
		if got := limiterAddress(raw); got != want {
			t.Fatalf("limiterAddress(%q)=%q, want %q", raw, got, want)
		}
	}
}

// TestLoginGlobalBackoffAcrossSources proves that failures from many distinct
// clients exhaust a global budget that then backs off exponentially, and
// that throttled responses are 429 with Retry-After.
func TestLoginGlobalBackoffAcrossSources(t *testing.T) {
	server, _, token := testServer(t)
	claimCoverageAdmin(t, server, token)
	for i := 0; i < loginGlobalFailureBudget-1; i++ {
		client := "198.51.100." + strconv.Itoa(i+1)
		server.recordFailure(credentialActionLogin, server.throttleKey(credentialActionLogin, client))
	}
	// The last failure in the budget arrives through the real handler.
	if code, _, _ := wrongLogin(t, server, "203.0.113.200:1234"); code != http.StatusOK {
		t.Fatalf("failure within the global budget status=%d", code)
	}
	code, retry, body := wrongLogin(t, server, "203.0.113.201:1234")
	if code != http.StatusTooManyRequests || !strings.Contains(body, "Too many login attempts") {
		t.Fatalf("global budget did not throttle a fresh client: status=%d", code)
	}
	if seconds, err := strconv.Atoi(retry); err != nil || seconds < 1 || seconds > int(loginGlobalBackoffMax/time.Second) {
		t.Fatalf("Retry-After=%q", retry)
	}
	// Other actions keep their own budget.
	if _, limited := server.throttled(credentialActionReset, server.throttleKey(credentialActionReset, "203.0.113.201")); limited {
		t.Fatal("login failures throttled password reset")
	}

	// Once the backoff elapses, one more failure doubles the next wait.
	age := func(by time.Duration) {
		server.loginMu.Lock()
		for i := range server.globalFailures[credentialActionLogin] {
			server.globalFailures[credentialActionLogin][i] = server.globalFailures[credentialActionLogin][i].Add(-by)
		}
		server.loginMu.Unlock()
	}
	age(2 * time.Second)
	if _, limited := server.throttled(credentialActionLogin, server.throttleKey(credentialActionLogin, "203.0.113.202")); limited {
		t.Fatal("global backoff did not expire")
	}
	server.recordFailure(credentialActionLogin, server.throttleKey(credentialActionLogin, "203.0.113.202"))
	wait, limited := server.throttled(credentialActionLogin, server.throttleKey(credentialActionLogin, "203.0.113.203"))
	if !limited || wait <= time.Second || wait > 2*time.Second {
		t.Fatalf("second global backoff=%s limited=%v, want about 2s", wait, limited)
	}
	for excess, want := range map[int]time.Duration{0: time.Second, 1: 2 * time.Second, 3: 8 * time.Second, 8: 256 * time.Second, 9: loginGlobalBackoffMax, 64: loginGlobalBackoffMax} {
		if got := globalBackoff(excess); got != want {
			t.Fatalf("globalBackoff(%d)=%s, want %s", excess, got, want)
		}
	}

	// Failures outside the window are forgotten entirely.
	age(loginFailureWindow)
	if _, limited := server.throttled(credentialActionLogin, server.throttleKey(credentialActionLogin, "203.0.113.204")); limited {
		t.Fatal("expired global failures still throttled")
	}
	server.loginMu.Lock()
	remaining := len(server.globalFailures)
	server.loginMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expired global failures retained: %d", remaining)
	}

	// The retained history is bounded no matter how many failures arrive.
	for i := 0; i < loginGlobalFailureBudget*4; i++ {
		server.recordFailure(credentialActionSetup, "setup:x")
	}
	server.loginMu.Lock()
	retained := len(server.globalFailures[credentialActionSetup])
	server.loginMu.Unlock()
	if retained > loginGlobalFailureBudget+17 {
		t.Fatalf("global failure history grew to %d", retained)
	}
}

func TestThrottledCredentialFormsReturn429(t *testing.T) {
	server, st, token := testServer(t)
	setupKey := server.throttleKey(credentialActionSetup, "192.0.2.50")
	for i := 0; i < loginFailuresPerClient; i++ {
		server.recordFailure(credentialActionSetup, setupKey)
	}
	setup := coverageCredentialPost(t, server, "/setup/claim", url.Values{"token": {token}, "password": {"a secure password"}, "confirm": {"a secure password"}}, nil, "", "192.0.2.50:1234", nil)
	if setup.Code != http.StatusTooManyRequests || setup.Header().Get("Retry-After") == "" || !strings.Contains(setup.Body.String(), "Too many setup attempts") {
		t.Fatalf("throttled setup status=%d retry=%q", setup.Code, setup.Header().Get("Retry-After"))
	}
	claimCoverageAdmin(t, server, token)
	resetToken, err := st.NewResetToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	resetKey := server.throttleKey(credentialActionReset, "192.0.2.51")
	for i := 0; i < loginFailuresPerClient; i++ {
		server.recordFailure(credentialActionReset, resetKey)
	}
	reset := coverageCredentialPost(t, server, "/reset", url.Values{"token": {resetToken}, "password": {"another secure password"}, "confirm": {"another secure password"}}, nil, "", "192.0.2.51:1234", nil)
	if reset.Code != http.StatusTooManyRequests || reset.Header().Get("Retry-After") == "" || !strings.Contains(reset.Body.String(), "Too many reset attempts") {
		t.Fatalf("throttled reset status=%d retry=%q", reset.Code, reset.Header().Get("Retry-After"))
	}
	// The client bucket reopens when its oldest counted failure leaves the
	// window, so Retry-After never exceeds the window.
	retry, _ := strconv.Atoi(reset.Header().Get("Retry-After"))
	if retry < 1 || retry > int(loginFailureWindow/time.Second) {
		t.Fatalf("client Retry-After=%d", retry)
	}
}
