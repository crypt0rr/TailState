package web

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
	"github.com/crypt0rr/tailstate/internal/webhook"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	config               boot.Config
	store                *store.Store
	engine               *monitor.Engine
	templates            map[string]*template.Template
	loginMu              sync.Mutex
	loginAttempts        map[string][]time.Time
	authWork             chan struct{}
	challengeKey         []byte
	challengeMu          sync.Mutex
	challenges           map[string]credentialChallengeRecord
	metricsMu            sync.Mutex
	challengeCounts      map[credentialChallengeMetric]uint64
	credentialRejections map[string]uint64
}

const maxTrackedLoginIPs = 4096

type pageData struct {
	Error, Message, CSRF, Challenge string
	Version                         string
	Configured                      bool
	Settings                        store.Settings
	DeviceSeconds, InventorySeconds int64
	Status                          store.Status
	History                         store.HistoryPage
	HistoryFilter                   store.HistoryFilter
	HistoryCollectors               []string
	HistoryEventTypes               []string
	HistoryNextURL                  string
	HistoryExportURL                string
	EvidenceSigningKeyID            string
	Destinations                    []destinationPage
	NotificationsPaused             bool
	Diagnostics                     diagnostics.Report
}

type destinationPage struct {
	ID         int64
	Name       string
	DisplayURL string
	Enabled    bool
}

type readinessCollector struct {
	Name              string `json:"name"`
	Supported         bool   `json:"supported"`
	Baseline          bool   `json:"baseline"`
	Partial           bool   `json:"partial"`
	PartialErrorCount int    `json:"partial_error_count"`
	PollDuration      int64  `json:"poll_duration_ms"`
	FailureCount      int    `json:"failure_count"`
	Reason            string `json:"reason,omitempty"`
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
	challengeKey, err := newCredentialChallengeKey()
	if err != nil {
		return nil, fmt.Errorf("initialize credential form challenges: %w", err)
	}
	return &Server{
		config:               config,
		store:                st,
		engine:               engine,
		templates:            templates,
		loginAttempts:        map[string][]time.Time{},
		authWork:             make(chan struct{}, 2),
		challengeKey:         challengeKey,
		challenges:           map[string]credentialChallengeRecord{},
		challengeCounts:      map[credentialChallengeMetric]uint64{},
		credentialRejections: map[string]uint64{},
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("POST /webhooks/tailscale", s.tailscaleWebhook)
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
	mux.HandleFunc("GET /history/export", s.historyExport)
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
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data.Version = s.config.Version
	if err := s.templates[name].Execute(w, data); err != nil {
		slog.Error("render template", "template", name, "error", err)
	}
}
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if !exists {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if !s.authenticated(r, false) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	status, err := s.store.Status(r.Context())
	if err != nil {
		slog.Error("load status for home redirect", "error", err)
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if !status.Configured {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if exists {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	s.renderCredential(w, "setup", credentialActionSetup, pageData{})
}
func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if exists {
		http.Error(w, "installation already claimed", http.StatusConflict)
		return
	}
	ip := "setup:" + s.clientIP(r)
	if s.rateLimited(ip) {
		s.renderCredential(w, "setup", credentialActionSetup, pageData{Error: "Too many setup attempts. Try again later."})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionSetup) {
		s.renderCredential(w, "setup", credentialActionSetup, pageData{Error: credentialChallengeError})
		return
	}
	select {
	case s.authWork <- struct{}{}:
		defer func() { <-s.authWork }()
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return
	}
	if r.FormValue("password") != r.FormValue("confirm") {
		// Password confirmation is part of the unauthenticated setup surface.
		// Count mismatches as failed claims so an attacker cannot bypass the
		// endpoint throttle by repeatedly submitting different confirmations.
		s.recordFailure(ip)
		s.recordCredentialRejection(credentialActionSetup)
		s.renderCredential(w, "setup", credentialActionSetup, pageData{Error: "Passwords do not match."})
		return
	}
	if err := s.store.Claim(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.recordFailure(ip)
		s.recordCredentialRejection(credentialActionSetup)
		// Setup is unauthenticated. Keep storage, token, and migration details
		// out of the response so this endpoint cannot become an oracle.
		slog.Debug("setup claim rejected", "error", err)
		s.renderCredential(w, "setup", credentialActionSetup, pageData{Error: "Setup could not be completed. Check the setup token and try again."})
		return
	}
	s.clearFailures(ip)
	s.clearCredentialChallengeCookie(w, credentialActionSetup)
	if !s.startSession(w, r) {
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	exists, ok := s.adminExists(w, r)
	if !ok {
		return
	}
	if !exists {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.authenticated(r, false) {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	s.renderCredential(w, "login", credentialActionLogin, pageData{})
}

func (s *Server) adminExists(w http.ResponseWriter, r *http.Request) (bool, bool) {
	exists, err := s.store.AdminExists(r.Context())
	if err != nil {
		slog.Error("check administrator state", "error", err)
		http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
		return false, false
	}
	return exists, true
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.rateLimited(ip) {
		s.renderCredential(w, "login", credentialActionLogin, pageData{Error: "Too many login attempts. Try again later."})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionLogin) {
		s.renderCredential(w, "login", credentialActionLogin, pageData{Error: credentialChallengeError})
		return
	}
	select {
	case s.authWork <- struct{}{}:
		defer func() { <-s.authWork }()
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return
	}
	if !s.store.Authenticate(r.Context(), r.FormValue("password")) {
		s.recordFailure(ip)
		s.recordCredentialRejection(credentialActionLogin)
		s.renderCredential(w, "login", credentialActionLogin, pageData{Error: "Invalid password."})
		return
	}
	s.clearFailures(ip)
	s.clearCredentialChallengeCookie(w, credentialActionLogin)
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
func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	s.renderCredential(w, "reset", credentialActionReset, pageData{})
}
func (s *Server) resetPost(w http.ResponseWriter, r *http.Request) {
	ip := "reset:" + s.clientIP(r)
	if s.rateLimited(ip) {
		s.renderCredential(w, "reset", credentialActionReset, pageData{Error: "Too many reset attempts. Try again later."})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionReset) {
		s.renderCredential(w, "reset", credentialActionReset, pageData{Error: credentialChallengeError})
		return
	}
	select {
	case s.authWork <- struct{}{}:
		defer func() { <-s.authWork }()
	default:
		http.Error(w, "authentication busy", http.StatusServiceUnavailable)
		return
	}
	if r.FormValue("password") != r.FormValue("confirm") {
		s.recordFailure(ip)
		s.recordCredentialRejection(credentialActionReset)
		s.renderCredential(w, "reset", credentialActionReset, pageData{Error: "Passwords do not match."})
		return
	}
	if err := s.store.ResetWithToken(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.recordFailure(ip)
		s.recordCredentialRejection(credentialActionReset)
		// Do not disclose whether a reset token is missing, invalid, expired,
		// or temporarily unreadable. The token is deliberately a single
		// generic oracle to unauthenticated callers.
		slog.Debug("password reset rejected", "error", err)
		s.renderCredential(w, "reset", credentialActionReset, pageData{Error: "The reset token is invalid or expired."})
		return
	}
	s.clearFailures(ip)
	s.clearCredentialChallengeCookie(w, credentialActionReset)
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
	for i := range status.Collectors {
		collector := &status.Collectors[i]
		if collector.Partial && collector.PartialErrorCount > 0 {
			if collector.LastError == "" {
				collector.LastError = fmt.Sprintf("%d related requests failed", collector.PartialErrorCount)
			} else {
				collector.LastError = fmt.Sprintf("%s (%d related requests failed)", collector.LastError, collector.PartialErrorCount)
			}
		}
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
	data.EvidenceSigningKeyID, _ = s.store.EvidenceSigningKeyID(r.Context())
	if history.HasNext {
		data.HistoryNextURL = historyURL(filter, history.NextCursor)
	}
	data.HistoryExportURL = historyExportURL(filter)
	s.render(w, "history", data)
}

func (s *Server) historyExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r, false); !ok {
		return
	}
	pack, err := s.store.ExportEvidencePack(r.Context(), historyFilter(r))
	if err != nil {
		if errors.Is(err, store.ErrEvidencePackTooLarge) {
			http.Error(w, "history export is too large; narrow the filters and try again", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "export history", http.StatusInternalServerError)
		return
	}
	filename := "tailstate-drift-evidence-" + time.Now().UTC().Format("20060102T150405Z") + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pack)
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

func historyExportURL(filter store.HistoryFilter) string {
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
	if filter.Cursor > 0 {
		values.Set("cursor", strconv.FormatInt(filter.Cursor, 10))
	}
	if encoded := values.Encode(); encoded != "" {
		return "/history/export?" + encoded
	}
	return "/history/export"
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, false)
	if !ok {
		return
	}
	current, err := s.store.Settings(r.Context())
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// An unreadable settings row is a backend failure, not an
		// unconfigured installation. Rendering the setup form here invites an
		// operator to overwrite a database they cannot currently read.
		slog.Error("load settings", "error", err)
		http.Error(w, "settings temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	configured := err == nil
	if !configured {
		current = store.Settings{Tailnet: "-", DeviceInterval: 60 * time.Second, InventoryInterval: 5 * time.Minute}
	}
	if _, err := s.store.ListDestinations(r.Context()); err != nil {
		slog.Error("load notification destinations", "error", err)
		http.Error(w, "settings temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	data := s.settingsData(r.Context(), csrf, configured, current, r)
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
	if currentErr != nil && !errors.Is(currentErr, sql.ErrNoRows) {
		slog.Error("load settings for update", "error", currentErr)
		http.Error(w, "settings temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	configured := currentErr == nil
	clearWebhookSecret := r.FormValue("clear_webhook_secret") == "on" || r.FormValue("clear_webhook_secret") == "true"
	input := store.Settings{Tailnet: strings.TrimSpace(r.FormValue("tailnet")), OAuthClientID: strings.TrimSpace(r.FormValue("client_id")), OAuthClientSecret: r.FormValue("client_secret"), WebhookSecret: strings.TrimSpace(r.FormValue("webhook_secret")), ClearWebhookSecret: clearWebhookSecret, DeviceInterval: time.Duration(device) * time.Second, InventoryInterval: time.Duration(inventory) * time.Second}
	if configured {
		if input.OAuthClientSecret == "" {
			input.OAuthClientSecret = current.OAuthClientSecret
		}
		if input.WebhookSecret == "" && !input.ClearWebhookSecret {
			input.WebhookSecret = current.WebhookSecret
		}
	}
	data := s.settingsData(r.Context(), csrf, configured, input, r)
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
		data.Error = "Tailscale test failed: " + tailscale.SafeError(err)
		s.render(w, "settings", data)
		return
	}
	if destinations, err := s.store.ListDestinations(r.Context()); err != nil {
		// Storage failures may include table names, driver details, or future
		// provider-specific context. Keep those details in server logs only;
		// the authenticated settings page should not become an internal error
		// oracle.
		slog.Error("load notification destinations for settings update", "error", err)
		data.Error = "Notification destinations are temporarily unavailable. Try again."
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
		slog.Error("save settings", "error", err)
		data.Error = "Settings could not be saved. Check the values and try again."
		s.render(w, "settings", data)
		return
	}
	s.engine.Wake()
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) settingsData(ctx context.Context, csrf string, configured bool, settings store.Settings, request *http.Request) pageData {
	data := pageData{CSRF: csrf, Configured: configured, Settings: settings, DeviceSeconds: int64(settings.DeviceInterval.Seconds()), InventorySeconds: int64(settings.InventoryInterval.Seconds()), Diagnostics: s.diagnosticReport(ctx, request)}
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

func (s *Server) currentSettingsData(ctx context.Context, csrf string, requests ...*http.Request) pageData {
	var request *http.Request
	if len(requests) > 0 {
		request = requests[0]
	}
	settings, err := s.store.Settings(ctx)
	if err != nil {
		settings = store.Settings{Tailnet: "-", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute}
		return s.settingsData(ctx, csrf, false, settings, request)
	}
	return s.settingsData(ctx, csrf, true, settings, request)
}

func (s *Server) diagnosticReport(ctx context.Context, request *http.Request) diagnostics.Report {
	runtime := diagnostics.Runtime{}
	if status, err := s.store.Status(ctx); err == nil {
		runtime.Configured = status.Configured
		runtime.BaselineReady = status.BaselineReady
		runtime.BaselineDegraded = status.BaselineDegraded
		runtime.BaselineReason = status.BaselineReason
		runtime.Destinations = status.Destinations
		runtime.EnabledDestinations = status.EnabledDestinations
	}
	if metrics, err := s.store.StorageMetrics(ctx); err == nil {
		limits := s.store.StorageLimits()
		runtime.Storage = diagnostics.StorageRuntime{
			SnapshotLimitBytes:      limits.SnapshotBytes,
			EventValueLimitBytes:    limits.EventValueBytes,
			HistoryPageLimitBytes:   limits.HistoryPageBytes,
			RejectLimitBytes:        limits.RejectBytes,
			DatabaseLimitBytes:      metrics.DatabaseLimitBytes,
			DatabaseBytes:           metrics.DatabaseBytes,
			DatabaseFileBytes:       metrics.DatabaseFileBytes,
			DatabaseWALBytes:        metrics.DatabaseWALBytes,
			DatabaseSHMBytes:        metrics.DatabaseSHMBytes,
			DatabasePhysicalBytes:   metrics.DatabasePhysicalBytes,
			StoragePressure:         metrics.PressureRatio(),
			SnapshotTruncations:     metrics.SnapshotTruncations,
			EventValueTruncations:   metrics.EventValueTruncations,
			HistoryPageTruncations:  metrics.HistoryPageTruncations,
			OversizedWritesRejected: metrics.OversizedWritesRejected,
		}
	}
	return diagnostics.Build(s.config, runtime, request)
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
			slog.Error("save notification destination", "error", err)
			data := s.currentSettingsData(ctx, csrf, r)
			data.Error = destinationMutationMessage("save", err)
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
		data := s.currentSettingsData(ctx, csrf, r)
		if err := notify.New().Test(testCtx, serviceURL); err != nil {
			data.Error = "Notification test failed: " + notify.SafeTestError(err, serviceURL)
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
			slog.Error("update notification destination", "error", err)
			http.Error(w, destinationMutationMessage("update", err), http.StatusBadRequest)
			return
		}
		s.engine.Wake()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	case "delete":
		if err := s.store.DeleteDestination(ctx, id); err != nil {
			slog.Error("remove notification destination", "error", err)
			http.Error(w, destinationMutationMessage("remove", err), http.StatusBadRequest)
			return
		}
		s.engine.Wake()
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	default:
		http.Error(w, "unknown destination action", http.StatusBadRequest)
	}
}

func destinationMutationMessage(action string, err error) string {
	if strings.EqualFold(strings.TrimSpace(err.Error()), "notification destination not found") {
		return "Notification destination not found."
	}
	switch action {
	case "save":
		return "Notification destination was not saved. Check the name and URL."
	case "update":
		return "Notification destination could not be updated."
	case "remove":
		return "Notification destination could not be removed."
	default:
		return "Notification destination operation failed."
	}
}

func (s *Server) tailscaleWebhook(w http.ResponseWriter, r *http.Request) {
	if !webhook.Method(r.Method) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	secret, err := s.store.WebhookSecret(r.Context())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "webhook not configured", http.StatusNotFound)
			return
		}
		http.Error(w, "webhook unavailable", http.StatusServiceUnavailable)
		return
	}
	if secret == "" {
		http.Error(w, "webhook not configured", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid webhook body", http.StatusRequestEntityTooLarge)
		return
	}
	delivery, err := webhook.Verify(body, r.Header.Get("Tailscale-Webhook-Signature"), secret, time.Now().UTC())
	if err != nil {
		// Keep verification details out of responses and logs; callers only need
		// to know that Tailscale should not retry this malformed delivery.
		http.Error(w, "invalid webhook signature or body", http.StatusUnauthorized)
		return
	}
	trigger, created, err := s.store.RecordWebhookTrigger(r.Context(), delivery.BodyHash, delivery.EventTypes, delivery.Collectors)
	if err != nil {
		http.Error(w, "record webhook", http.StatusInternalServerError)
		return
	}
	if created && s.engine != nil {
		s.engine.Trigger(monitor.ReconcileRequest{TriggerID: trigger.ID, Collectors: delivery.Collectors})
	}
	w.Header().Set("Cache-Control", "no-store")
	status := "accepted"
	if !created {
		status = "duplicate"
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": status, "trigger_id": trigger.ID})
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
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "configured": false, "baseline": false})
		return
	}
	collectors := make([]readinessCollector, 0, len(status.Collectors))
	for _, collector := range status.Collectors {
		collectors = append(collectors, readinessCollector{
			Name:              collector.Name,
			Supported:         collector.Supported,
			Baseline:          collector.Baseline,
			Partial:           collector.Partial,
			PartialErrorCount: collector.PartialErrorCount,
			PollDuration:      collector.PollDurationMS,
			FailureCount:      collector.FailureCount,
			Reason:            readinessCollectorReason(collector),
		})
	}
	state := "not_ready"
	code := http.StatusServiceUnavailable
	if status.Configured && status.BaselineReady {
		state = "ready"
		code = http.StatusOK
		if status.BaselineDegraded {
			state = "degraded"
		}
	}
	response := map[string]any{
		"status":          state,
		"configured":      status.Configured,
		"baseline":        status.BaselineReady,
		"degraded":        status.BaselineDegraded,
		"collectors":      collectors,
		"baseline_reason": status.BaselineReason,
	}
	if status.BaselineGraceUntil != nil {
		response["baseline_grace_until"] = status.BaselineGraceUntil.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, code, response)
}

// readinessCollectorReason is intentionally a bounded vocabulary. Collector
// errors can contain upstream response text, credentials, or tenant-controlled
// values; /readyz is unauthenticated and must never echo those details.
func readinessCollectorReason(collector store.CollectorState) string {
	switch {
	case !collector.Supported:
		return "unsupported"
	case collector.Partial:
		return "partial"
	case collector.FailureCount >= 1:
		return "retrying"
	case !collector.Baseline:
		return "baseline pending"
	default:
		return "healthy"
	}
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsAuthorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tailstate-metrics"`)
		http.Error(w, "metrics authorization required", http.StatusUnauthorized)
		return
	}
	status, err := s.store.Status(r.Context())
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	ready := 0
	if status.Configured && status.BaselineReady {
		ready = 1
	}
	fmt.Fprintf(w, "# HELP tailstate_ready Whether setup and baseline are complete.\n# TYPE tailstate_ready gauge\ntailstate_ready %d\n", ready)
	degraded := 0
	if status.BaselineDegraded {
		degraded = 1
	}
	fmt.Fprintf(w, "# TYPE tailstate_baseline_degraded gauge\ntailstate_baseline_degraded %d\n", degraded)
	dueErrors := uint64(0)
	if s.engine != nil {
		dueErrors = s.engine.CollectorDueErrors()
	}
	fmt.Fprintf(w, "# TYPE tailstate_collector_due_errors_total counter\ntailstate_collector_due_errors_total %d\n", dueErrors)
	fmt.Fprintln(w, "# HELP tailstate_credential_challenge_total Credential form challenge outcomes by action.")
	fmt.Fprintln(w, "# TYPE tailstate_credential_challenge_total counter")
	for _, action := range credentialActions {
		for _, outcome := range credentialChallengeOutcomes {
			fmt.Fprintf(w, "tailstate_credential_challenge_total{action=%q,outcome=%q} %d\n", action, outcome, s.credentialChallengeCount(action, outcome))
		}
	}
	fmt.Fprintln(w, "# HELP tailstate_credential_rejections_total Credential form submissions rejected after challenge validation.")
	fmt.Fprintln(w, "# TYPE tailstate_credential_rejections_total counter")
	for _, action := range credentialActions {
		fmt.Fprintf(w, "tailstate_credential_rejections_total{action=%q} %d\n", action, s.credentialRejectionCount(action))
	}
	fmt.Fprintf(w, "# TYPE tailstate_outbox_pending gauge\ntailstate_outbox_pending %d\n# TYPE tailstate_outbox_processing gauge\ntailstate_outbox_processing %d\n# TYPE tailstate_outbox_dead gauge\ntailstate_outbox_dead %d\n", status.Pending, status.Processing, status.Dead)
	if s.engine != nil {
		delivery := s.engine.DeliveryMetrics()
		fmt.Fprintf(w, "# TYPE tailstate_outbox_delivery_attempts_total counter\ntailstate_outbox_delivery_attempts_total %d\n# TYPE tailstate_outbox_delivery_success_total counter\ntailstate_outbox_delivery_success_total %d\n# TYPE tailstate_outbox_delivery_failure_total counter\ntailstate_outbox_delivery_failure_total %d\n# TYPE tailstate_outbox_lease_renewals_total counter\ntailstate_outbox_lease_renewals_total %d\n# TYPE tailstate_outbox_lease_renewal_failures_total counter\ntailstate_outbox_lease_renewal_failures_total %d\n# TYPE tailstate_outbox_lease_losses_total counter\ntailstate_outbox_lease_losses_total %d\n", delivery.Attempts, delivery.Successes, delivery.Failures, delivery.LeaseRenewals, delivery.LeaseRenewalFailures, delivery.LeaseLosses)
		fmt.Fprintln(w, "# TYPE tailstate_outbox_delivery_duration_seconds histogram")
		for i, bound := range monitor.DeliveryDurationBucketBounds() {
			fmt.Fprintf(w, "tailstate_outbox_delivery_duration_seconds_bucket{le=\"%.3g\"} %d\n", bound, delivery.DurationBuckets[i])
		}
		fmt.Fprintf(w, "tailstate_outbox_delivery_duration_seconds_bucket{le=\"+Inf\"} %d\ntailstate_outbox_delivery_duration_seconds_sum %.6f\ntailstate_outbox_delivery_duration_seconds_count %d\n", delivery.DurationCount, delivery.DurationSeconds, delivery.DurationCount)
		cleanup := s.engine.CleanupMetrics()
		remaining := 0
		if cleanup.Remaining {
			remaining = 1
		}
		fmt.Fprintf(w, "# TYPE tailstate_cleanup_runs_total counter\ntailstate_cleanup_runs_total %d\n# TYPE tailstate_cleanup_failures_total counter\ntailstate_cleanup_failures_total %d\n# TYPE tailstate_cleanup_remaining gauge\ntailstate_cleanup_remaining %d\n# TYPE tailstate_cleanup_remaining_passes_total counter\ntailstate_cleanup_remaining_passes_total %d\n# TYPE tailstate_cleanup_transactions_total counter\ntailstate_cleanup_transactions_total %d\n# TYPE tailstate_cleanup_duration_seconds_sum counter\ntailstate_cleanup_duration_seconds_sum %.6f\n# TYPE tailstate_cleanup_duration_seconds_count counter\ntailstate_cleanup_duration_seconds_count %d\n", cleanup.Runs, cleanup.Failures, remaining, cleanup.RemainingPasses, cleanup.Transactions, cleanup.DurationSeconds, cleanup.Runs)
		fmt.Fprintf(w, "# TYPE tailstate_cleanup_rows_total counter\ntailstate_cleanup_rows_total{table=\"sessions\"} %d\ntailstate_cleanup_rows_total{table=\"auth_tokens\"} %d\ntailstate_cleanup_rows_total{table=\"meta\"} %d\ntailstate_cleanup_rows_total{table=\"outbox_dead_letter\"} %d\ntailstate_cleanup_rows_total{table=\"webhook_dead_letter\"} %d\ntailstate_cleanup_rows_total{table=\"events\"} %d\ntailstate_cleanup_rows_total{table=\"event_batches\"} %d\ntailstate_cleanup_rows_total{table=\"event_batch_triggers\"} %d\ntailstate_cleanup_rows_total{table=\"webhook_triggers\"} %d\ntailstate_cleanup_rows_total{table=\"delivered_outbox\"} %d\ntailstate_cleanup_rows_total{table=\"dead_outbox\"} %d\n", cleanup.SessionsDeleted, cleanup.AuthTokensDeleted, cleanup.MetaDeleted, cleanup.OutboxDeadLettered, cleanup.WebhookDeadLettered, cleanup.EventsDeleted, cleanup.EventBatchesDeleted, cleanup.EventBatchTriggersDeleted, cleanup.WebhookTriggersDeleted, cleanup.DeliveredOutboxDeleted, cleanup.DeadOutboxDeleted)
	}
	storage, err := s.store.StorageMetrics(r.Context())
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	limits := s.store.StorageLimits()
	fmt.Fprintf(w, "# TYPE tailstate_storage_bytes gauge\ntailstate_storage_bytes %d\n# TYPE tailstate_storage_limit_bytes gauge\ntailstate_storage_limit_bytes %d\n# TYPE tailstate_storage_pressure_ratio gauge\ntailstate_storage_pressure_ratio %.6f\n# HELP tailstate_storage_database_file_bytes Physical bytes used by the main SQLite database file.\n# TYPE tailstate_storage_database_file_bytes gauge\ntailstate_storage_database_file_bytes %d\n# HELP tailstate_storage_wal_bytes Physical bytes used by the SQLite WAL sidecar.\n# TYPE tailstate_storage_wal_bytes gauge\ntailstate_storage_wal_bytes %d\n# HELP tailstate_storage_shm_bytes Physical bytes used by the SQLite shared-memory sidecar.\n# TYPE tailstate_storage_shm_bytes gauge\ntailstate_storage_shm_bytes %d\n# HELP tailstate_storage_physical_bytes Total physical bytes used by the SQLite database and sidecars.\n# TYPE tailstate_storage_physical_bytes gauge\ntailstate_storage_physical_bytes %d\n# TYPE tailstate_snapshot_truncations_total counter\ntailstate_snapshot_truncations_total %d\n# TYPE tailstate_event_value_truncations_total counter\ntailstate_event_value_truncations_total %d\n# TYPE tailstate_history_page_truncations_total counter\ntailstate_history_page_truncations_total %d\n# TYPE tailstate_oversized_writes_rejected_total counter\ntailstate_oversized_writes_rejected_total %d\n", storage.DatabaseBytes, storage.DatabaseLimitBytes, storage.PressureRatio(), storage.DatabaseFileBytes, storage.DatabaseWALBytes, storage.DatabaseSHMBytes, storage.DatabasePhysicalBytes, storage.SnapshotTruncations, storage.EventValueTruncations, storage.HistoryPageTruncations, storage.OversizedWritesRejected)
	fmt.Fprintf(w, "# TYPE tailstate_snapshot_limit_bytes gauge\ntailstate_snapshot_limit_bytes %d\n# TYPE tailstate_event_value_limit_bytes gauge\ntailstate_event_value_limit_bytes %d\n# TYPE tailstate_history_page_limit_bytes gauge\ntailstate_history_page_limit_bytes %d\n# TYPE tailstate_reject_limit_bytes gauge\ntailstate_reject_limit_bytes %d\n", limits.SnapshotBytes, limits.EventValueBytes, limits.HistoryPageBytes, limits.RejectBytes)
	fmt.Fprintf(w, "# TYPE tailstate_webhook_triggers_pending gauge\ntailstate_webhook_triggers_pending %d\n# TYPE tailstate_webhook_triggers_processing gauge\ntailstate_webhook_triggers_processing %d\n# TYPE tailstate_webhook_triggers_dead gauge\ntailstate_webhook_triggers_dead %d\n", status.WebhookPending, status.WebhookProcessing, status.WebhookDead)
	paused := 0
	if status.Configured && status.EnabledDestinations == 0 {
		paused = 1
	}
	fmt.Fprintf(w, "# TYPE tailstate_notification_destinations gauge\ntailstate_notification_destinations %d\n# TYPE tailstate_notification_destinations_enabled gauge\ntailstate_notification_destinations_enabled %d\n# TYPE tailstate_notifications_paused gauge\ntailstate_notifications_paused %d\n", status.Destinations, status.EnabledDestinations, paused)
	fmt.Fprint(w, "# TYPE tailstate_collector_supported gauge\n# TYPE tailstate_collector_baseline gauge\n# TYPE tailstate_collector_partial gauge\n# TYPE tailstate_collector_partial_errors gauge\n# TYPE tailstate_collector_failures gauge\n# TYPE tailstate_collector_poll_duration_seconds gauge\n# TYPE tailstate_collector_last_success_timestamp_seconds gauge\n# TYPE tailstate_collector_next_poll_timestamp_seconds gauge\n")
	for _, collector := range status.Collectors {
		supported, baseline := 0, 0
		if collector.Supported {
			supported = 1
		}
		if collector.Baseline {
			baseline = 1
		}
		partial := 0
		if collector.Partial {
			partial = 1
		}
		fmt.Fprintf(w, "tailstate_collector_supported{collector=%q} %d\ntailstate_collector_baseline{collector=%q} %d\ntailstate_collector_partial{collector=%q} %d\ntailstate_collector_partial_errors{collector=%q} %d\ntailstate_collector_failures{collector=%q} %d\ntailstate_collector_poll_duration_seconds{collector=%q} %.3f\n", collector.Name, supported, collector.Name, baseline, collector.Name, partial, collector.Name, collector.PartialErrorCount, collector.Name, collector.FailureCount, collector.Name, float64(collector.PollDurationMS)/1000)
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

func (s *Server) metricsAuthorized(r *http.Request) bool {
	if s.config.MetricsToken != "" {
		const prefix = "Bearer "
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, prefix) {
			return false
		}
		provided := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
		if provided == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(provided), []byte(s.config.MetricsToken)) == 1
	}
	// A blank token is useful for local development, but is only valid on a
	// direct loopback connection. A reverse proxy is never a safe substitute:
	// forwarded headers can be omitted, malformed, or supplied by an untrusted
	// peer, so tokenless metrics fail closed whenever proxy provenance exists.
	remote := strings.TrimSpace(remoteIP(r))
	addr, err := netip.ParseAddr(remote)
	if err != nil || !addr.IsLoopback() || s.isTrustedProxy(remote) {
		return false
	}
	return strings.TrimSpace(r.Header.Get("X-Forwarded-For")) == "" && strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")) == ""
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

func (s *Server) clientIP(r *http.Request) string {
	remote := remoteIP(r)
	if !s.isTrustedProxy(remote) {
		return remote
	}
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
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
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
