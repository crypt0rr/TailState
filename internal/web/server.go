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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/notify"
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

const maxTrackedLoginIPs = 4096

type pageData struct {
	Error, Message, CSRF            string
	Configured                      bool
	Settings                        store.Settings
	DeviceSeconds, InventorySeconds int64
	Status                          store.Status
	History                         store.HistoryPage
	HistoryFilter                   store.HistoryFilter
	HistoryCollectors               []string
	HistoryEventTypes               []string
	HistoryNextURL                  string
	Destinations                    []destinationPage
	NotificationsPaused             bool
}

type destinationPage struct {
	ID         int64
	Name       string
	DisplayURL string
	Enabled    bool
}

func New(config boot.Config, st *store.Store, engine *monitor.Engine) (*Server, error) {
	templates := map[string]*template.Template{}
	for _, name := range []string{"setup", "login", "reset", "settings", "status", "history"} {
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
	mux.HandleFunc("GET /history", s.history)
	mux.HandleFunc("GET /settings", s.settings)
	mux.HandleFunc("POST /settings", s.settingsPost)
	mux.HandleFunc("POST /settings/destinations", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/add", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/edit", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/save", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/test", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/toggle", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/enable", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/disable", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/delete", s.destinationPost)
	mux.HandleFunc("POST /settings/destinations/remove", s.destinationPost)
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
	if !s.startSession(w, r) {
		return
	}
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
	if !s.startSession(w, r) {
		return
	}
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

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, false)
	if !ok {
		return
	}
	filter := historyFilter(r)
	history, err := s.store.ListHistory(r.Context(), filter)
	if err != nil {
		http.Error(w, "load history", http.StatusInternalServerError)
		return
	}
	collectors := append([]string{}, tailscale.CoreCollectors...)
	collectors = append(collectors, tailscale.InventoryCollectors...)
	data := pageData{
		CSRF:              csrf,
		History:           history,
		HistoryFilter:     filter,
		HistoryCollectors: collectors,
		HistoryEventTypes: []string{"created", "changed", "removed"},
	}
	if history.HasNext {
		data.HistoryNextURL = historyURL(filter, history.NextCursor)
	}
	s.render(w, "history", data)
}

func historyFilter(r *http.Request) store.HistoryFilter {
	filter := store.HistoryFilter{
		Collector:  strings.TrimSpace(r.URL.Query().Get("collector")),
		EventType:  strings.TrimSpace(r.URL.Query().Get("event_type")),
		ResourceID: strings.TrimSpace(r.URL.Query().Get("resource")),
		Limit:      20,
	}
	if cursor, err := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64); err == nil && cursor > 0 {
		filter.Cursor = cursor
	}
	return filter
}

func historyURL(filter store.HistoryFilter, cursor int64) string {
	values := url.Values{}
	if filter.Collector != "" {
		values.Set("collector", filter.Collector)
	}
	if filter.EventType != "" {
		values.Set("event_type", filter.EventType)
	}
	if filter.ResourceID != "" {
		values.Set("resource", filter.ResourceID)
	}
	values.Set("cursor", strconv.FormatInt(cursor, 10))
	return "/history?" + values.Encode()
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
	data := s.settingsData(r.Context(), csrf, configured, current)
	s.render(w, "settings", data)
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
	input := store.Settings{Tailnet: strings.TrimSpace(r.FormValue("tailnet")), OAuthClientID: strings.TrimSpace(r.FormValue("client_id")), OAuthClientSecret: r.FormValue("client_secret"), DeviceInterval: time.Duration(device) * time.Second, InventoryInterval: time.Duration(inventory) * time.Second}
	if configured {
		if input.OAuthClientSecret == "" {
			input.OAuthClientSecret = current.OAuthClientSecret
		}
	}
	data := s.settingsData(r.Context(), csrf, configured, input)
	data.DeviceSeconds, data.InventorySeconds = device, inventory
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
	if destinations, err := s.store.ListDestinations(r.Context()); err != nil {
		data.Error = "load notification destinations failed: " + err.Error()
		s.render(w, "settings", data)
		return
	} else {
		enabled := 0
		for _, destination := range destinations {
			if destination.Enabled {
				enabled++
			}
		}
		if !configured && enabled == 0 {
			data.Error = "Add at least one enabled notification destination before saving the initial configuration."
			s.render(w, "settings", data)
			return
		}
	}
	if _, err := s.store.SaveSettings(r.Context(), input); err != nil {
		data.Error = err.Error()
		s.render(w, "settings", data)
		return
	}
	s.engine.Wake()
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) settingsData(ctx context.Context, csrf string, configured bool, settings store.Settings) pageData {
	data := pageData{CSRF: csrf, Configured: configured, Settings: settings, DeviceSeconds: int64(settings.DeviceInterval.Seconds()), InventorySeconds: int64(settings.InventoryInterval.Seconds())}
	destinations, err := s.store.ListDestinations(ctx)
	if err == nil {
		data.Destinations = make([]destinationPage, 0, len(destinations))
		for _, destination := range destinations {
			data.Destinations = append(data.Destinations, destinationPage{ID: destination.ID, Name: destination.Name, DisplayURL: notify.RedactURL(destination.ServiceURL), Enabled: destination.Enabled})
		}
		data.NotificationsPaused = configured
		for _, destination := range data.Destinations {
			if destination.Enabled {
				data.NotificationsPaused = false
				break
			}
		}
	}
	return data
}

func (s *Server) currentSettingsData(ctx context.Context, csrf string) pageData {
	settings, err := s.store.Settings(ctx)
	if err != nil {
		settings = store.Settings{Tailnet: "-", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}
		return s.settingsData(ctx, csrf, false, settings)
	}
	return s.settingsData(ctx, csrf, true, settings)
}

func (s *Server) destinationPost(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, true)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	if action == "" {
		switch r.URL.Path {
		case "/settings/destinations/test":
			action = "test"
		case "/settings/destinations/toggle", "/settings/destinations/enable", "/settings/destinations/disable":
			action = "toggle"
		case "/settings/destinations/delete", "/settings/destinations/remove":
			action = "delete"
		default:
			action = "save"
		}
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	ctx := r.Context()
	switch action {
	case "save":
		serviceURL := strings.TrimSpace(r.FormValue("service_url"))
		if serviceURL == "" && id > 0 {
			if existing, err := s.store.ListDestinations(ctx); err == nil {
				for _, destination := range existing {
					if destination.ID == id {
						serviceURL = destination.ServiceURL
						break
					}
				}
			}
		}
		enabled := r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"
		if _, err := s.store.SaveDestination(ctx, store.NotificationDestination{ID: id, Name: r.FormValue("name"), ServiceURL: serviceURL, Enabled: enabled}); err != nil {
			data := s.currentSettingsData(ctx, csrf)
			data.Error = "Notification destination was not saved: " + err.Error()
			s.render(w, "settings", data)
			return
		}
		s.engine.Wake()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	case "test":
		serviceURL := strings.TrimSpace(r.FormValue("service_url"))
		if serviceURL == "" && id > 0 {
			if existing, err := s.store.ListDestinations(ctx); err == nil {
				for _, destination := range existing {
					if destination.ID == id {
						serviceURL = destination.ServiceURL
						break
					}
				}
			}
		}
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		data := s.currentSettingsData(ctx, csrf)
		if err := notify.New().Test(testCtx, serviceURL); err != nil {
			data.Error = "Notification test failed: " + err.Error()
		} else {
			data.Message = "Notification test sent."
		}
		s.render(w, "settings", data)
	case "toggle":
		enabled := r.FormValue("enabled") == "true" || r.FormValue("enabled") == "on"
		if r.URL.Path == "/settings/destinations/enable" {
			enabled = true
		} else if r.URL.Path == "/settings/destinations/disable" {
			enabled = false
		}
		if err := s.store.SetDestinationEnabled(ctx, id, enabled); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.engine.Wake()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	case "delete":
		if err := s.store.DeleteDestination(ctx, id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.engine.Wake()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	default:
		http.Error(w, "unknown destination action", http.StatusBadRequest)
	}
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
	fmt.Fprint(w, "# TYPE tailstate_collector_supported gauge\n# TYPE tailstate_collector_baseline gauge\n# TYPE tailstate_collector_failures gauge\n# TYPE tailstate_collector_last_success_timestamp_seconds gauge\n# TYPE tailstate_collector_next_poll_timestamp_seconds gauge\n")
	for _, collector := range status.Collectors {
		supported, baseline := 0, 0
		if collector.Supported {
			supported = 1
		}
		if collector.Baseline {
			baseline = 1
		}
		fmt.Fprintf(w, "tailstate_collector_supported{collector=%q} %d\ntailstate_collector_baseline{collector=%q} %d\ntailstate_collector_failures{collector=%q} %d\n", collector.Name, supported, collector.Name, baseline, collector.Name, collector.FailureCount)
		if collector.LastSuccess != nil {
			fmt.Fprintf(w, "tailstate_collector_last_success_timestamp_seconds{collector=%q} %d\n", collector.Name, collector.LastSuccess.Unix())
		}
		if collector.NextPoll != nil {
			fmt.Fprintf(w, "tailstate_collector_next_poll_timestamp_seconds{collector=%q} %d\n", collector.Name, collector.NextPoll.Unix())
		}
	}
	for collector, count := range status.ResourceCounts {
		fmt.Fprintf(w, "tailstate_resources{collector=%q} %d\n", collector, count)
	}
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) bool {
	token, csrf, err := s.store.CreateSession(r.Context())
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return false
	}
	http.SetCookie(w, &http.Cookie{Name: "tailstate_session", Value: token, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: "tailstate_csrf", Value: csrf, Path: "/", MaxAge: 43200, HttpOnly: false, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	return true
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
	now := time.Now()
	cutoff := now.Add(-15 * time.Minute)
	s.pruneLoginAttemptsLocked(cutoff)
	attempts, exists := s.loginAttempts[ip]
	if !exists {
		return false
	}
	kept := attempts[:0]
	for _, at := range attempts {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(s.loginAttempts, ip)
	} else {
		s.loginAttempts[ip] = kept
	}
	return len(kept) >= 5
}
func (s *Server) recordFailure(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	s.pruneLoginAttemptsLocked(now.Add(-15 * time.Minute))
	s.loginAttempts[ip] = append(s.loginAttempts[ip], now)
	// Keep the map bounded even when this is called without a preceding
	// rateLimited check (for example, from a future authentication flow).
	s.pruneLoginAttemptsLocked(now.Add(-15 * time.Minute))
}
func (s *Server) clearFailures(ip string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginAttempts, ip)
}

func (s *Server) pruneLoginAttemptsLocked(cutoff time.Time) {
	for ip, attempts := range s.loginAttempts {
		kept := attempts[:0]
		for _, at := range attempts {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(s.loginAttempts, ip)
			continue
		}
		s.loginAttempts[ip] = kept
	}
	for len(s.loginAttempts) > maxTrackedLoginIPs {
		var oldestIP string
		var oldest time.Time
		for ip, attempts := range s.loginAttempts {
			candidate := attempts[0]
			if oldestIP == "" || candidate.Before(oldest) {
				oldestIP, oldest = ip, candidate
			}
		}
		delete(s.loginAttempts, oldestIP)
	}
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
