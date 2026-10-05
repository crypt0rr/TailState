package web

import (
	"bytes"
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
	"sort"
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
	globalFailures       map[credentialAction][]time.Time
	settingsTestTimeout  time.Duration
	authWork             chan struct{}
	challengeKey         []byte
	challengeMu          sync.Mutex
	consumedChallenges   map[string]time.Time
	consumedPrunedAt     time.Time
	metricsMu            sync.Mutex
	challengeCounts      map[credentialChallengeMetric]uint64
	credentialRejections map[string]uint64
}

const (
	// serverWriteTimeout is the default per-response write deadline.
	serverWriteTimeout = 30 * time.Second
	// defaultSettingsTestTimeout bounds the Tailscale connection test run by
	// a settings save. settingsRenderAllowance is the time left afterwards to
	// render the result; together they stay below serverWriteTimeout.
	defaultSettingsTestTimeout = 20 * time.Second
	settingsRenderAllowance    = 5 * time.Second
	maxTrackedLoginIPs         = 4096
	// loginFailureWindow and loginFailuresPerClient define the per-client
	// credential throttle.
	loginFailureWindow     = 15 * time.Minute
	loginFailuresPerClient = 5
	// loginIPv6PrefixBits aggregates IPv6 clients by network rather than by
	// address, because one host can usually choose any address in its /64.
	loginIPv6PrefixBits = 64
	// loginGlobalFailureBudget failures per action and window from any mix of
	// sources engage an exponential backoff of loginGlobalBackoffBase,
	// doubling per further failure up to loginGlobalBackoffMax.
	loginGlobalFailureBudget = 30
	loginGlobalBackoffBase   = time.Second
	loginGlobalBackoffMax    = 5 * time.Minute
)

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
	NotificationState               diagnostics.NotificationState
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
		globalFailures:       map[credentialAction][]time.Time{},
		settingsTestTimeout:  defaultSettingsTestTimeout,
		authWork:             make(chan struct{}, 2),
		challengeKey:         challengeKey,
		consumedChallenges:   map[string]time.Time{},
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
	server := &http.Server{Addr: s.config.ListenAddr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: serverWriteTimeout, IdleTimeout: 60 * time.Second}
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
	s.renderStatus(w, name, data, http.StatusOK)
}

func (s *Server) renderStatus(w http.ResponseWriter, name string, data pageData, code int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data.Version = s.config.Version
	if code != http.StatusOK {
		w.WriteHeader(code)
	}
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
	s.renderCredential(w, r, "setup", credentialActionSetup, pageData{})
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
	ip := s.throttleKey(credentialActionSetup, s.clientIP(r))
	if retry, limited := s.throttled(credentialActionSetup, ip); limited {
		s.renderThrottled(w, r, "setup", credentialActionSetup, "Too many setup attempts. Try again later.", retry)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionSetup) {
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: credentialChallengeError})
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
		s.recordFailure(credentialActionSetup, ip)
		s.recordCredentialRejection(credentialActionSetup)
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: "Passwords do not match."})
		return
	}
	if err := s.store.Claim(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.recordFailure(credentialActionSetup, ip)
		s.recordCredentialRejection(credentialActionSetup)
		// Setup is unauthenticated. Keep storage, token, and migration details
		// out of the response so this endpoint cannot become an oracle.
		slog.Debug("setup claim rejected", "error", err)
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: "Setup could not be completed. Check the setup token and try again."})
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
	s.renderCredential(w, r, "login", credentialActionLogin, pageData{})
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
	ip := s.throttleKey(credentialActionLogin, s.clientIP(r))
	if retry, limited := s.throttled(credentialActionLogin, ip); limited {
		s.renderThrottled(w, r, "login", credentialActionLogin, "Too many login attempts. Try again later.", retry)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionLogin) {
		s.renderCredential(w, r, "login", credentialActionLogin, pageData{Error: credentialChallengeError})
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
		s.recordFailure(credentialActionLogin, ip)
		s.recordCredentialRejection(credentialActionLogin)
		s.renderCredential(w, r, "login", credentialActionLogin, pageData{Error: "Invalid password."})
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
	s.renderCredential(w, r, "reset", credentialActionReset, pageData{})
}
func (s *Server) resetPost(w http.ResponseWriter, r *http.Request) {
	ip := s.throttleKey(credentialActionReset, s.clientIP(r))
	if retry, limited := s.throttled(credentialActionReset, ip); limited {
		s.renderThrottled(w, r, "reset", credentialActionReset, "Too many reset attempts. Try again later.", retry)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.validateCredentialChallenge(r, credentialActionReset) {
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: credentialChallengeError})
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
		s.recordFailure(credentialActionReset, ip)
		s.recordCredentialRejection(credentialActionReset)
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: "Passwords do not match."})
		return
	}
	if err := s.store.ResetWithToken(r.Context(), r.FormValue("token"), r.FormValue("password")); err != nil {
		s.recordFailure(credentialActionReset, ip)
		s.recordCredentialRejection(credentialActionReset)
		// Do not disclose whether a reset token is missing, invalid, expired,
		// or temporarily unreadable. The token is deliberately a single
		// generic oracle to unauthenticated callers.
		slog.Debug("password reset rejected", "error", err)
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: "The reset token is invalid or expired."})
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
	device, err1 := strconv.ParseInt(strings.TrimSpace(r.FormValue("device_interval")), 10, 64)
	inventory, err2 := strconv.ParseInt(strings.TrimSpace(r.FormValue("inventory_interval")), 10, 64)
	current, currentErr := s.store.Settings(r.Context())
	if currentErr != nil && !errors.Is(currentErr, sql.ErrNoRows) {
		slog.Error("load settings for update", "error", currentErr)
		http.Error(w, "settings temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	configured := currentErr == nil
	clearWebhookSecret := r.FormValue("clear_webhook_secret") == "on" || r.FormValue("clear_webhook_secret") == "true"
	input := store.Settings{Tailnet: strings.TrimSpace(r.FormValue("tailnet")), OAuthClientID: strings.TrimSpace(r.FormValue("client_id")), OAuthClientSecret: r.FormValue("client_secret"), WebhookSecret: strings.TrimSpace(r.FormValue("webhook_secret")), ClearWebhookSecret: clearWebhookSecret}
	if input.Tailnet == "" {
		input.Tailnet = "-"
	}
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
	// Validate everything that needs no I/O before contacting Tailscale, so
	// an invalid form fails instantly with a specific message.
	if message := settingsInputError(&input, device, inventory, err1, err2); message != "" {
		data.Error = message
		s.render(w, "settings", data)
		return
	}
	client := tailscale.New(s.config.TailscaleBase, s.config.OAuthTokenURL, s.config.Version, tailscale.Credentials{Tailnet: input.Tailnet, ClientID: input.OAuthClientID, ClientSecret: input.OAuthClientSecret})
	// The connection test must finish, and its result page render, before
	// the server's write deadline; otherwise a slow API produces a blank
	// connection reset instead of "Tailscale test failed". Bound the test
	// below the deadline and extend this response's deadline to cover it.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.settingsTestTimeout + settingsRenderAllowance))
	testCtx, cancel := context.WithTimeout(r.Context(), s.settingsTestTimeout)
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

// settingsInputError validates the settings form locally and, when valid,
// stores the parsed intervals in input. Seconds are range-checked before they
// are converted to a time.Duration so huge values cannot overflow.
func settingsInputError(input *store.Settings, device, inventory int64, deviceErr, inventoryErr error) string {
	maxSeconds := int64(store.MaxPollInterval / time.Second)
	for _, field := range []struct {
		label   string
		seconds int64
		err     error
		min     time.Duration
	}{
		{"Device", device, deviceErr, store.MinDevicePollInterval},
		{"Inventory", inventory, inventoryErr, store.MinInventoryPollInterval},
	} {
		minSeconds := int64(field.min / time.Second)
		if field.err != nil && !errors.Is(field.err, strconv.ErrRange) {
			return field.label + " poll interval must be a whole number of seconds."
		}
		if field.err != nil || field.seconds < minSeconds || field.seconds > maxSeconds {
			return fmt.Sprintf("%s poll interval must be between %d and %d seconds.", field.label, minSeconds, maxSeconds)
		}
	}
	input.DeviceInterval = time.Duration(device) * time.Second
	input.InventoryInterval = time.Duration(inventory) * time.Second
	if input.OAuthClientID == "" || input.OAuthClientSecret == "" {
		return "OAuth client ID and secret are required."
	}
	if len(input.WebhookSecret) > store.MaxWebhookSecretBytes {
		return fmt.Sprintf("Webhook secret must be at most %d bytes.", store.MaxWebhookSecretBytes)
	}
	if err := store.ValidateSettings(*input); err != nil {
		return "Tailnet must be \"-\" or a tailnet name without spaces, slashes, or URL syntax."
	}
	return ""
}

func (s *Server) settingsData(ctx context.Context, csrf string, configured bool, settings store.Settings, request *http.Request) pageData {
	data := pageData{CSRF: csrf, Configured: configured, Settings: settings, DeviceSeconds: int64(settings.DeviceInterval.Seconds()), InventorySeconds: int64(settings.InventoryInterval.Seconds()), Diagnostics: s.diagnosticReport(ctx, request)}
	destinations, err := s.store.ListDestinations(ctx)
	if err == nil {
		data.Destinations = make([]destinationPage, 0, len(destinations))
		for _, destination := range destinations {
			data.Destinations = append(data.Destinations, destinationPage{ID: destination.ID, Name: destination.Name, DisplayURL: notify.RedactURL(destination.ServiceURL), Enabled: destination.Enabled})
		}
		enabled := 0
		for _, destination := range data.Destinations {
			if destination.Enabled {
				enabled++
			}
		}
		data.NotificationState = diagnostics.NotificationStateFor(configured, len(data.Destinations), enabled)
		data.NotificationsPaused = data.NotificationState.Paused()
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
			LimitNotEnforced:        !metrics.LimitEnforced(),
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
	// Collect everything that can fail before writing a single byte, and
	// render into a buffer: a scrape either receives a complete exposition
	// or a clean 500, never a 200 with a truncated or corrupted body.
	status, err := s.store.Status(r.Context())
	if err != nil {
		slog.Error("load status for metrics", "error", err)
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	storage, err := s.store.StorageMetrics(r.Context())
	if err != nil {
		slog.Error("load storage metrics", "error", err)
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	var body bytes.Buffer
	s.writeMetrics(&body, status, storage, s.store.StorageLimits())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	_, _ = w.Write(body.Bytes())
}

// metricFamily writes the HELP and TYPE header that must precede every
// family's samples in the Prometheus text exposition format.
func metricFamily(b *bytes.Buffer, name, kind, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

// metricValue writes a single unlabelled family.
func metricValue(b *bytes.Buffer, name, kind, help string, value any) {
	metricFamily(b, name, kind, help)
	switch v := value.(type) {
	case float64:
		fmt.Fprintf(b, "%s %.6f\n", name, v)
	default:
		fmt.Fprintf(b, "%s %d\n", name, v)
	}
}

func (s *Server) writeMetrics(b *bytes.Buffer, status store.Status, storage store.StorageMetrics, limits store.StorageLimits) {
	metricValue(b, "tailstate_ready", "gauge", "Whether setup and baseline are complete.", boolMetric(status.Configured && status.BaselineReady))
	metricValue(b, "tailstate_baseline_degraded", "gauge", "Whether the baseline is ready but one or more collectors are degraded.", boolMetric(status.BaselineDegraded))
	dueErrors := uint64(0)
	if s.engine != nil {
		dueErrors = s.engine.CollectorDueErrors()
	}
	metricValue(b, "tailstate_collector_due_errors_total", "counter", "Scheduler database errors while selecting due collectors.", dueErrors)
	metricFamily(b, "tailstate_credential_challenge_total", "counter", "Credential form challenge outcomes by action.")
	for _, action := range credentialActions {
		for _, outcome := range credentialChallengeOutcomes {
			fmt.Fprintf(b, "tailstate_credential_challenge_total{action=%q,outcome=%q} %d\n", action, outcome, s.credentialChallengeCount(action, outcome))
		}
	}
	metricFamily(b, "tailstate_credential_rejections_total", "counter", "Credential form submissions rejected after challenge validation.")
	for _, action := range credentialActions {
		fmt.Fprintf(b, "tailstate_credential_rejections_total{action=%q} %d\n", action, s.credentialRejectionCount(action))
	}
	metricValue(b, "tailstate_outbox_pending", "gauge", "Notifications waiting for delivery.", status.Pending)
	metricValue(b, "tailstate_outbox_processing", "gauge", "Notifications currently leased for delivery.", status.Processing)
	metricValue(b, "tailstate_outbox_dead", "gauge", "Notifications that exhausted their delivery window.", status.Dead)
	if s.engine != nil {
		delivery := s.engine.DeliveryMetrics()
		metricValue(b, "tailstate_outbox_delivery_attempts_total", "counter", "Notification delivery attempts.", delivery.Attempts)
		metricValue(b, "tailstate_outbox_delivery_success_total", "counter", "Successful notification deliveries.", delivery.Successes)
		metricValue(b, "tailstate_outbox_delivery_failure_total", "counter", "Failed notification delivery attempts.", delivery.Failures)
		metricValue(b, "tailstate_outbox_lease_renewals_total", "counter", "Delivery lease renewals.", delivery.LeaseRenewals)
		metricValue(b, "tailstate_outbox_lease_renewal_failures_total", "counter", "Delivery lease renewal failures.", delivery.LeaseRenewalFailures)
		metricValue(b, "tailstate_outbox_lease_losses_total", "counter", "Delivery leases lost before completion.", delivery.LeaseLosses)
		metricFamily(b, "tailstate_outbox_delivery_duration_seconds", "histogram", "Notification delivery attempt duration.")
		for i, bound := range monitor.DeliveryDurationBucketBounds() {
			fmt.Fprintf(b, "tailstate_outbox_delivery_duration_seconds_bucket{le=\"%.3g\"} %d\n", bound, delivery.DurationBuckets[i])
		}
		fmt.Fprintf(b, "tailstate_outbox_delivery_duration_seconds_bucket{le=\"+Inf\"} %d\ntailstate_outbox_delivery_duration_seconds_sum %.6f\ntailstate_outbox_delivery_duration_seconds_count %d\n", delivery.DurationCount, delivery.DurationSeconds, delivery.DurationCount)
		cleanup := s.engine.CleanupMetrics()
		metricValue(b, "tailstate_cleanup_runs_total", "counter", "Retention cleanup runs.", cleanup.Runs)
		metricValue(b, "tailstate_cleanup_failures_total", "counter", "Retention cleanup runs that failed.", cleanup.Failures)
		metricValue(b, "tailstate_cleanup_remaining", "gauge", "Whether the last cleanup run left work for a further pass.", boolMetric(cleanup.Remaining))
		metricValue(b, "tailstate_cleanup_remaining_passes_total", "counter", "Cleanup runs that left work for a further pass.", cleanup.RemainingPasses)
		metricValue(b, "tailstate_cleanup_transactions_total", "counter", "Cleanup transactions committed.", cleanup.Transactions)
		metricFamily(b, "tailstate_cleanup_duration_seconds", "summary", "Retention cleanup run duration.")
		fmt.Fprintf(b, "tailstate_cleanup_duration_seconds_sum %.6f\ntailstate_cleanup_duration_seconds_count %d\n", cleanup.DurationSeconds, cleanup.Runs)
		metricFamily(b, "tailstate_cleanup_rows_total", "counter", "Rows removed or dead-lettered by retention cleanup, by table.")
		for _, row := range []struct {
			table string
			count uint64
		}{
			{"sessions", cleanup.SessionsDeleted},
			{"auth_tokens", cleanup.AuthTokensDeleted},
			{"meta", cleanup.MetaDeleted},
			{"outbox_dead_letter", cleanup.OutboxDeadLettered},
			{"webhook_dead_letter", cleanup.WebhookDeadLettered},
			{"events", cleanup.EventsDeleted},
			{"event_batches", cleanup.EventBatchesDeleted},
			{"event_batch_triggers", cleanup.EventBatchTriggersDeleted},
			{"webhook_triggers", cleanup.WebhookTriggersDeleted},
			{"delivered_outbox", cleanup.DeliveredOutboxDeleted},
			{"dead_outbox", cleanup.DeadOutboxDeleted},
		} {
			fmt.Fprintf(b, "tailstate_cleanup_rows_total{table=%q} %d\n", row.table, row.count)
		}
	}
	metricValue(b, "tailstate_storage_bytes", "gauge", "Logical bytes used by the SQLite database.", storage.DatabaseBytes)
	metricValue(b, "tailstate_storage_limit_bytes", "gauge", "Configured database budget.", storage.DatabaseLimitBytes)
	metricValue(b, "tailstate_storage_pressure_ratio", "gauge", "Database bytes divided by the configured budget.", storage.PressureRatio())
	metricValue(b, "tailstate_storage_enforced_limit_bytes", "gauge", "Page ceiling SQLite enforces on the active connection.", storage.DatabaseEnforcedLimitBytes)
	metricValue(b, "tailstate_storage_limit_enforced", "gauge", "Whether the enforced page ceiling is within the configured database budget.", boolMetric(storage.LimitEnforced()))
	metricValue(b, "tailstate_storage_database_file_bytes", "gauge", "Physical bytes used by the main SQLite database file.", storage.DatabaseFileBytes)
	metricValue(b, "tailstate_storage_wal_bytes", "gauge", "Physical bytes used by the SQLite WAL sidecar.", storage.DatabaseWALBytes)
	metricValue(b, "tailstate_storage_shm_bytes", "gauge", "Physical bytes used by the SQLite shared-memory sidecar.", storage.DatabaseSHMBytes)
	metricValue(b, "tailstate_storage_physical_bytes", "gauge", "Total physical bytes used by the SQLite database and sidecars.", storage.DatabasePhysicalBytes)
	metricValue(b, "tailstate_snapshot_truncations_total", "counter", "Snapshots stored as a truncation marker.", storage.SnapshotTruncations)
	metricValue(b, "tailstate_event_value_truncations_total", "counter", "Event values stored as a truncation marker.", storage.EventValueTruncations)
	metricValue(b, "tailstate_history_page_truncations_total", "counter", "History pages truncated at the page byte limit.", storage.HistoryPageTruncations)
	metricValue(b, "tailstate_oversized_writes_rejected_total", "counter", "Oversized raw writes replaced by a metadata marker.", storage.OversizedWritesRejected)
	metricValue(b, "tailstate_snapshot_limit_bytes", "gauge", "Configured per-snapshot byte limit.", limits.SnapshotBytes)
	metricValue(b, "tailstate_event_value_limit_bytes", "gauge", "Configured per-event-value byte limit.", limits.EventValueBytes)
	metricValue(b, "tailstate_history_page_limit_bytes", "gauge", "Configured history page byte limit.", limits.HistoryPageBytes)
	metricValue(b, "tailstate_reject_limit_bytes", "gauge", "Configured raw-write rejection byte limit.", limits.RejectBytes)
	metricValue(b, "tailstate_webhook_triggers_pending", "gauge", "Verified webhook deliveries waiting for reconciliation.", status.WebhookPending)
	metricValue(b, "tailstate_webhook_triggers_processing", "gauge", "Verified webhook deliveries currently being reconciled.", status.WebhookProcessing)
	metricValue(b, "tailstate_webhook_triggers_dead", "gauge", "Verified webhook deliveries that exhausted their retry window.", status.WebhookDead)
	state := diagnostics.NotificationStateFor(status.Configured, status.Destinations, status.EnabledDestinations)
	metricValue(b, "tailstate_notification_destinations", "gauge", "Notification destinations configured.", status.Destinations)
	metricValue(b, "tailstate_notification_destinations_enabled", "gauge", "Notification destinations enabled.", status.EnabledDestinations)
	metricValue(b, "tailstate_notifications_paused", "gauge", "Whether a configured installation is not delivering notifications (no destination, or every destination disabled).", boolMetric(state.Paused()))
	metricFamily(b, "tailstate_notification_state", "gauge", "Notification delivery state; exactly one state is 1.")
	for _, candidate := range diagnostics.NotificationStates {
		fmt.Fprintf(b, "tailstate_notification_state{state=%q} %d\n", candidate, boolMetric(candidate == state))
	}
	collectorFamilies := []struct{ name, help string }{
		{"tailstate_collector_supported", "Whether the collector is supported by the tailnet and credentials."},
		{"tailstate_collector_baseline", "Whether the collector has a baseline."},
		{"tailstate_collector_partial", "Whether the collector's last result was partial."},
		{"tailstate_collector_partial_errors", "Failed related requests in the collector's last partial result."},
		{"tailstate_collector_failures", "Consecutive collector failures."},
		{"tailstate_collector_poll_duration_seconds", "Duration of the collector's last poll."},
		{"tailstate_collector_last_success_timestamp_seconds", "Unix time of the collector's last successful poll."},
		{"tailstate_collector_next_poll_timestamp_seconds", "Unix time of the collector's next scheduled poll."},
	}
	for index, family := range collectorFamilies {
		metricFamily(b, family.name, "gauge", family.help)
		for _, collector := range status.Collectors {
			switch index {
			case 0:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, boolMetric(collector.Supported))
			case 1:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, boolMetric(collector.Baseline))
			case 2:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, boolMetric(collector.Partial))
			case 3:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.PartialErrorCount)
			case 4:
				fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.FailureCount)
			case 5:
				fmt.Fprintf(b, "%s{collector=%q} %.3f\n", family.name, collector.Name, float64(collector.PollDurationMS)/1000)
			case 6:
				if collector.LastSuccess != nil {
					fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.LastSuccess.Unix())
				}
			case 7:
				if collector.NextPoll != nil {
					fmt.Fprintf(b, "%s{collector=%q} %d\n", family.name, collector.Name, collector.NextPoll.Unix())
				}
			}
		}
	}
	metricFamily(b, "tailstate_resources", "gauge", "Resources in the current baseline, by collector.")
	collectors := make([]string, 0, len(status.ResourceCounts))
	for collector := range status.ResourceCounts {
		collectors = append(collectors, collector)
	}
	sort.Strings(collectors)
	for _, collector := range collectors {
		fmt.Fprintf(b, "tailstate_resources{collector=%q} %d\n", collector, status.ResourceCounts[collector])
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

// throttleKey returns the per-client limiter bucket for action. IPv6 clients
// are aggregated by their /64, which a single host or customer site usually
// controls in full; IPv4 (including IPv4-mapped IPv6) keeps one bucket per
// address.
func (s *Server) throttleKey(action credentialAction, client string) string {
	return string(action) + ":" + limiterAddress(client)
}

func limiterAddress(client string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(client))
	if err != nil {
		return client
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(loginIPv6PrefixBits)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}

// throttled reports whether a credential submission must be refused, and for
// how long. Two independent limits apply: each client bucket allows
// loginFailuresPerClient failures per loginFailureWindow, and every action has
// a global failure budget across all sources. Once the global budget is spent,
// each further failure doubles the wait (capped at loginGlobalBackoffMax), so
// distributed guessing slows down exponentially instead of being bounded only
// by the password hash cost.
func (s *Server) throttled(action credentialAction, key string) (time.Duration, bool) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	s.pruneLoginAttemptsLocked(now.Add(-loginFailureWindow))
	var retry time.Duration
	if attempts := s.loginAttempts[key]; len(attempts) >= loginFailuresPerClient {
		// The bucket reopens when its oldest counted failure leaves the window.
		retry = attempts[len(attempts)-loginFailuresPerClient].Add(loginFailureWindow).Sub(now)
	}
	if global := s.globalFailures[action]; len(global) >= loginGlobalFailureBudget {
		until := global[len(global)-1].Add(globalBackoff(len(global) - loginGlobalFailureBudget))
		if wait := until.Sub(now); wait > retry {
			retry = wait
		}
	}
	return retry, retry > 0
}

// globalBackoff returns the delay after the excess-th failure beyond the
// global budget: 1s, 2s, 4s, ... capped at loginGlobalBackoffMax.
func globalBackoff(excess int) time.Duration {
	if excess > 16 {
		excess = 16
	}
	delay := loginGlobalBackoffBase << excess
	if delay > loginGlobalBackoffMax {
		delay = loginGlobalBackoffMax
	}
	return delay
}

func (s *Server) recordFailure(action credentialAction, key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	s.pruneLoginAttemptsLocked(now.Add(-loginFailureWindow))
	s.loginAttempts[key] = append(s.loginAttempts[key], now)
	global := append(s.globalFailures[action], now)
	// Beyond the budget only the count up to the backoff cap matters.
	if limit := loginGlobalFailureBudget + 17; len(global) > limit {
		global = append(global[:0:0], global[len(global)-limit:]...)
	}
	s.globalFailures[action] = global
	// Keep the map bounded even when this is called without a preceding
	// throttled check (for example, from a future authentication flow).
	s.pruneLoginAttemptsLocked(now.Add(-loginFailureWindow))
}

// clearFailures resets one client bucket after a successful submission. The
// global budget is deliberately left alone: it measures failures from every
// source and must not be reset by the success it is protecting.
func (s *Server) clearFailures(key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginAttempts, key)
}

func (s *Server) pruneLoginAttemptsLocked(cutoff time.Time) {
	for key, attempts := range s.loginAttempts {
		kept := attempts[:0]
		for _, at := range attempts {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(s.loginAttempts, key)
			continue
		}
		s.loginAttempts[key] = kept
	}
	for len(s.loginAttempts) > maxTrackedLoginIPs {
		var oldestKey string
		var oldest time.Time
		for key, attempts := range s.loginAttempts {
			candidate := attempts[0]
			if oldestKey == "" || candidate.Before(oldest) {
				oldestKey, oldest = key, candidate
			}
		}
		delete(s.loginAttempts, oldestKey)
	}
	for action, failures := range s.globalFailures {
		kept := failures[:0]
		for _, at := range failures {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(s.globalFailures, action)
			continue
		}
		s.globalFailures[action] = kept
	}
}

// renderThrottled answers a throttled credential submission with 429 and a
// Retry-After header (whole seconds, rounded up) while still rendering the
// form so a browser user sees the reason.
func (s *Server) renderThrottled(w http.ResponseWriter, r *http.Request, name string, action credentialAction, message string, retry time.Duration) {
	seconds := int64((retry + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	s.renderCredentialStatus(w, r, name, action, pageData{Error: message}, http.StatusTooManyRequests)
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

func boolMetric(value bool) int {
	if value {
		return 1
	}
	return 0
}
