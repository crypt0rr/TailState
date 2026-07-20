package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/mattermost"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	config        boot.Config
	store         *store.Store
	engine        *monitor.Engine
	templates     map[string]*template.Template
	loginMu       sync.Mutex
	loginAttempts map[string][]time.Time
}

type pageData struct {
	Error, Message, CSRF            string
	Configured                      bool
	Settings                        store.Settings
	DeviceSeconds, InventorySeconds int64
	Status                          store.Status
}

func New(config boot.Config, st *store.Store, engine *monitor.Engine) (*Server, error) {
	templates := map[string]*template.Template{}
	for _, name := range []string{"setup", "login", "reset", "settings", "status"} {
		parsed, err := template.ParseFS(assets, "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		templates[name] = parsed
	}
	return &Server{config: config, store: st, engine: engine, templates: templates, loginAttempts: map[string][]time.Time{}}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /", s.home)
	mux.HandleFunc("GET /setup", s.setup)
	mux.HandleFunc("POST /setup/claim", s.claim)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /reset", s.reset)
	mux.HandleFunc("POST /reset", s.resetPost)
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("GET /settings", s.settings)
	mux.HandleFunc("POST /settings", s.settingsPost)
	return s.security(mux)
}

func (s *Server) Serve(ctx context.Context) error {
	server := &http.Server{Addr: s.config.ListenAddr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("TailState web server listening", "address", s.config.ListenAddr)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates[name].Execute(w, data); err != nil {
		slog.Error("render template", "template", name, "error", err)
	}
}
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	exists, _ := s.store.AdminExists(r.Context())
	if !exists {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if !s.authenticated(r, false) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	status, _ := s.store.Status(r.Context())
	if !status.Configured {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	exists, _ := s.store.AdminExists(r.Context())
	if exists {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	s.render(w, "setup", pageData{})
}
func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	exists, _ := s.store.AdminExists(r.Context())
	if exists {
		http.Error(w, "installation already claimed", http.StatusConflict)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	if r.FormValue("password") != r.FormValue("confirm") {
		s.render(w, "setup", pageData{Error: "Passwords do not match."})
		return
	}
	if err := s.store.Claim(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.render(w, "setup", pageData{Error: err.Error()})
		return
	}
	s.startSession(w, r)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	exists, _ := s.store.AdminExists(r.Context())
	if !exists {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.authenticated(r, false) {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	s.render(w, "login", pageData{})
}
func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if s.rateLimited(ip) {
		s.render(w, "login", pageData{Error: "Too many login attempts. Try again later."})
		return
	}
	_ = r.ParseForm()
	if !s.store.Authenticate(r.Context(), r.FormValue("password")) {
		s.recordFailure(ip)
		s.render(w, "login", pageData{Error: "Invalid password."})
		return
	}
	s.clearFailures(ip)
	s.startSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.authenticated(r, true) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if cookie, err := r.Cookie("tailstate_session"); err == nil {
		s.store.DeleteSession(r.Context(), cookie.Value)
	}
	s.clearCookies(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) reset(w http.ResponseWriter, r *http.Request) { s.render(w, "reset", pageData{}) }
func (s *Server) resetPost(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.FormValue("password") != r.FormValue("confirm") {
		s.render(w, "reset", pageData{Error: "Passwords do not match."})
		return
	}
	if err := s.store.ResetWithToken(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.render(w, "reset", pageData{Error: err.Error()})
		return
	}
	s.clearCookies(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, false)
	if !ok {
		return
	}
	status, err := s.store.Status(r.Context())
	if err != nil {
		http.Error(w, "load status", 500)
		return
	}
	s.render(w, "status", pageData{CSRF: csrf, Status: status})
}
func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, false)
	if !ok {
		return
	}
	current, err := s.store.Settings(r.Context())
	configured := err == nil
	if !configured {
		current = store.Settings{Tailnet: "-", DeviceInterval: 60 * time.Second, InventoryInterval: 5 * time.Minute}
	}
	s.render(w, "settings", pageData{CSRF: csrf, Configured: configured, Settings: current, DeviceSeconds: int64(current.DeviceInterval.Seconds()), InventorySeconds: int64(current.InventoryInterval.Seconds())})
}
func (s *Server) settingsPost(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, true)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	device, err1 := strconv.ParseInt(r.FormValue("device_interval"), 10, 64)
	inventory, err2 := strconv.ParseInt(r.FormValue("inventory_interval"), 10, 64)
	current, currentErr := s.store.Settings(r.Context())
	configured := currentErr == nil
	input := store.Settings{Tailnet: strings.TrimSpace(r.FormValue("tailnet")), OAuthClientID: strings.TrimSpace(r.FormValue("client_id")), OAuthClientSecret: r.FormValue("client_secret"), MattermostURL: r.FormValue("mattermost_url"), DeviceInterval: time.Duration(device) * time.Second, InventoryInterval: time.Duration(inventory) * time.Second}
	if configured {
		if input.OAuthClientSecret == "" {
			input.OAuthClientSecret = current.OAuthClientSecret
		}
		if input.MattermostURL == "" {
			input.MattermostURL = current.MattermostURL
		}
	}
	data := pageData{CSRF: csrf, Configured: configured, Settings: input, DeviceSeconds: device, InventorySeconds: inventory}
	if err1 != nil || err2 != nil {
		data.Error = "Poll intervals must be whole seconds."
		s.render(w, "settings", data)
		return
	}
	client := tailscale.New(s.config.TailscaleBase, s.config.OAuthTokenURL, s.config.Version, tailscale.Credentials{Tailnet: input.Tailnet, ClientID: input.OAuthClientID, ClientSecret: input.OAuthClientSecret})
	testCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := client.Test(testCtx); err != nil {
		data.Error = "Tailscale test failed: " + err.Error()
		s.render(w, "settings", data)
		return
	}
	if err := mattermost.New().Test(testCtx, input.MattermostURL); err != nil {
		data.Error = "Mattermost test failed: " + err.Error()
		s.render(w, "settings", data)
		return
	}
	if _, err := s.store.SaveSettings(r.Context(), input); err != nil {
		data.Error = err.Error()
		s.render(w, "settings", data)
		return
	}
	s.engine.Wake()
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unhealthy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	status, err := s.store.Status(r.Context())
	if err != nil || !status.Configured || status.BaselineAt == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "configured": status.Configured, "baseline": status.BaselineAt != nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	status, err := s.store.Status(r.Context())
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	ready := 0
	if status.Configured && status.BaselineAt != nil {
		ready = 1
	}
	fmt.Fprintf(w, "# HELP tailstate_ready Whether setup and baseline are complete.\n# TYPE tailstate_ready gauge\ntailstate_ready %d\n", ready)
	fmt.Fprintf(w, "# TYPE tailstate_outbox_pending gauge\ntailstate_outbox_pending %d\n# TYPE tailstate_outbox_dead gauge\ntailstate_outbox_dead %d\n", status.Pending, status.Dead)
	for collector, count := range status.ResourceCounts {
		fmt.Fprintf(w, "tailstate_resources{collector=%q} %d\n", collector, count)
	}
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) {
	token, csrf, err := s.store.CreateSession(r.Context())
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "tailstate_session", Value: token, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "tailstate_csrf", Value: csrf, Path: "/", MaxAge: 43200, HttpOnly: false, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
}
func (s *Server) clearCookies(w http.ResponseWriter) {
	for _, name := range []string{"tailstate_session", "tailstate_csrf"} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: name == "tailstate_session", Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	}
}
func (s *Server) authenticated(r *http.Request, requireCSRF bool) bool {
	session, err1 := r.Cookie("tailstate_session")
	csrf, err2 := r.Cookie("tailstate_csrf")
	if err1 != nil || err2 != nil {
		return false
	}
	provided := csrf.Value
	if requireCSRF {
		provided = r.FormValue("_csrf")
		if provided == "" || provided != csrf.Value {
			return false
		}
	}
	return s.store.ValidateSession(r.Context(), session.Value, provided, requireCSRF)
}
func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request, csrf bool) (string, bool) {
	if csrf {
		_ = r.ParseForm()
	}
	if !s.authenticated(r, csrf) {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
		return "", false
	}
	cookie, _ := r.Cookie("tailstate_csrf")
	return cookie.Value, true
}
func (s *Server) rateLimited(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	attempts := s.loginAttempts[ip]
	kept := attempts[:0]
	for _, at := range attempts {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	s.loginAttempts[ip] = kept
	return len(kept) >= 5
}
func (s *Server) recordFailure(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.loginAttempts[ip] = append(s.loginAttempts[ip], time.Now())
}
func (s *Server) clearFailures(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginAttempts, ip)
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
