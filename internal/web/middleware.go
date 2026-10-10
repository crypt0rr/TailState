package web

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.requestIsHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", hstsValue)
		}
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) clientIP(r *http.Request) string {
	remote := remoteIP(r)
	if !s.isTrustedProxy(remote) {
		return remote
	}
	// Several X-Forwarded-For lines form one list in order (RFC 9110 section
	// 5.3); a proxy that appends its own line must not hide it behind a
	// client-supplied first line.
	forwarded := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for index := len(forwarded) - 1; index >= 0; index-- {
		candidate, err := netip.ParseAddr(strings.TrimSpace(forwarded[index]))
		if err != nil {
			continue
		}
		if !s.isTrustedProxy(candidate.String()) {
			return candidate.String()
		}
	}
	for _, value := range forwarded {
		if candidate, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
			return candidate.String()
		}
	}
	return remote
}

func (s *Server) isTrustedProxy(value string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	for _, prefix := range s.config.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
