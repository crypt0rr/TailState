package web

import (
	"net/http"
	"net/url"
	"strings"
)

// returnPages are the only destinations a login may return to. Anything
// else, including credential pages, logout, exports, and every absolute,
// scheme-relative, backslash, or percent-encoded variant, falls back to the
// default landing page, so ?next= can never become an open redirect.
var returnPages = map[string]bool{
	"/status":   true,
	"/history":  true,
	"/settings": true,
}

const maxReturnPathBytes = 2048

// safeReturnPath validates a post-login return target and returns its
// normalized same-site form (path plus query, never a scheme, host, or
// fragment).
func safeReturnPath(raw string) (string, bool) {
	if raw == "" || len(raw) > maxReturnPathBytes || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "", false
	}
	for _, character := range raw {
		// Browsers treat "\" like "/", and control characters are stripped
		// before resolution; either can turn "/\evil" into "//evil".
		if character == '\\' || character < 0x20 || character == 0x7f {
			return "", false
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" {
		return "", false
	}
	// Path is the decoded form, so "/%2Fevil" or "/status%2F..%2F" cannot
	// slip past the exact allowlist match.
	if !returnPages[parsed.Path] || parsed.RawPath != "" {
		return "", false
	}
	if parsed.RawQuery != "" {
		return parsed.Path + "?" + parsed.RawQuery, true
	}
	return parsed.Path, true
}

// loginURL returns the login page, carrying next when it is a safe return
// target.
func loginURL(next string) string {
	if safe, ok := safeReturnPath(next); ok {
		return "/login?" + url.Values{"next": {safe}}.Encode()
	}
	return "/login"
}

// postReturnPage maps a form action to the page that rendered the form, so
// a POST with a stale session returns the operator to that page after login.
func postReturnPage(path string) string {
	for _, page := range []string{"/settings", "/status"} {
		if path == page || strings.HasPrefix(path, page+"/") {
			return page
		}
	}
	return ""
}

// returnTarget is the page to return to after login. The status page's
// auto-refresh marker is dropped: the page the operator returns to after
// signing in is user activity, not an automatic refresh.
func returnTarget(u *url.URL) string {
	if u.Path != "/status" || !u.Query().Has(refreshParameter) {
		return u.RequestURI()
	}
	query := u.Query()
	query.Del(refreshParameter)
	if encoded := query.Encode(); encoded != "" {
		return u.Path + "?" + encoded
	}
	return u.Path
}

// rejectUnauthenticated answers a request whose session or form token did
// not validate.
//
//   - GET: redirect to the login page, returning to the requested page.
//   - POST with a valid session but a missing or wrong CSRF token: 403. The
//     session is kept, so a forged cross-site form cannot log the operator
//     out.
//   - POST with an expired, reset, or unknown session: clear the cookies and
//     redirect to the login page, returning to the page that held the form.
//     Cookies are only cleared when the browser actually sent a session
//     cookie; SameSite=Strict withholds it from cross-site requests.
func (s *Server) rejectUnauthenticated(w http.ResponseWriter, r *http.Request, csrf bool) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		http.Redirect(w, r, loginURL(returnTarget(r.URL)), http.StatusSeeOther)
		return
	}
	if csrf {
		// The probe is not user activity: a forged cross-site form must
		// not extend the idle timeout.
		if _, valid := s.session(r, false, false); valid {
			http.Error(w, "This form has expired or is invalid. Reload the page and try again.", http.StatusForbidden)
			return
		}
	}
	if s.hasSessionCookie(r) {
		s.clearCookies(w)
	}
	http.Redirect(w, r, loginURL(postReturnPage(r.URL.Path)), http.StatusSeeOther)
}
