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
	"unicode"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/expiry"
	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
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
	webhookOutcomes      map[string]uint64
	reconcileMu          sync.Mutex
	lastReconcile        time.Time
	reconcileCooldown    time.Duration
	// noticeSender delivers administrative notices that must reach a
	// destination before a change disables, removes, or redirects it.
	noticeSender  notify.Sender
	noticeTimeout time.Duration
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
	// defaultReconcileCooldown rate-limits the status page's "Reconcile
	// now" action so repeated clicks cannot turn into an API request storm.
	defaultReconcileCooldown = 30 * time.Second
)

type pageData struct {
	Error, Message, CSRF, Challenge string
	Version                         string
	// Next is a validated same-site page to return to after login.
	Next string
	// Page names the template being rendered. The shared layout uses it to
	// choose the navigation and mark the active link.
	Page string
	// Now is the render time used for relative timestamps.
	Now                             time.Time
	Configured                      bool
	Settings                        store.Settings
	DeviceSeconds, InventorySeconds int64
	Status                          store.Status
	History                         store.HistoryPage
	HistoryFilter                   store.HistoryFilter
	HistoryCollectors               []string
	HistoryEventTypes               []string
	HistorySeverities               []string
	Collectors                      []string
	MuteRules                       []store.MuteRule
	HistoryNextURL                  string
	HistoryPrevURL                  string
	HistoryFrom, HistoryTo          string
	HistoryExportURL                string
	HistoryExportFields             []historyExportField
	EvidenceSigningKeyID            string
	Destinations                    []destinationPage
	NotificationsPaused             bool
	NotificationState               diagnostics.NotificationState
	Diagnostics                     diagnostics.Report
	ExpiryDays, ExpiryTags          string
	OAuthScopes                     string
	Expiring                        []expiringResource
	ExpiryHorizonDays               int
	ExpiryFiltered                  bool
	Webhook                         store.WebhookState
	WebhookUnavailable              bool
	DestinationDeliveries           []store.DestinationDelivery
	Sessions                        []store.SessionInfo
	AdminActivity                   []store.AdminAuditEntry
	SessionIdleMinutes              int
	MinPasswordLength               int
}

// expiringResource is one row of the status page's "Expiring soon" card.
type expiringResource struct {
	Kind     string
	Name     string
	Tags     string
	Expires  time.Time
	DaysLeft int
}

type destinationPage struct {
	ID         int64
	Name       string
	DisplayURL string
	Enabled    bool
	// Routing fields are pre-rendered for the edit form.
	MinSeverity       string
	IncludeCollectors string
	ExcludeCollectors string
	ChangeKinds       map[string]bool
	RoutingSummary    string
	// Format is the saved override; EffectiveFormat is what is sent.
	Format          string
	EffectiveFormat string
	// Pending counts the pending and in-flight notifications that removing
	// the destination would dead-letter.
	Pending int
}

// routingSummary describes a destination's rules in one line.
func routingSummary(rules store.RoutingRules) string {
	if rules.AllChanges() {
		return "All changes"
	}
	parts := []string{}
	if rules.MinSeverity != "" {
		parts = append(parts, "severity "+string(rules.MinSeverity)+" or higher")
	}
	if len(rules.IncludeCollectors) > 0 {
		parts = append(parts, "only "+strings.Join(rules.IncludeCollectors, ", "))
	}
	if len(rules.ExcludeCollectors) > 0 {
		parts = append(parts, "excluding "+strings.Join(rules.ExcludeCollectors, ", "))
	}
	if len(rules.ChangeKinds) > 0 {
		parts = append(parts, strings.Join(rules.ChangeKinds, ", ")+" changes")
	}
	return strings.Join(parts, "; ")
}

func knownCollectors() []string {
	collectors := append([]string{}, tailscale.CoreCollectors...)
	return append(collectors, tailscale.InventoryCollectors...)
}

// splitCollectorList parses a comma- or space-separated collector list and
// rejects names this release does not monitor, so a typo cannot silently
// route nothing.
func splitCollectorList(value string) ([]string, error) {
	known := map[string]bool{}
	for _, collector := range knownCollectors() {
		known[collector] = true
	}
	var out []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		part = strings.ToLower(part)
		if !known[part] {
			return nil, fmt.Errorf("unknown collector %q", part)
		}
		out = append(out, part)
	}
	return out, nil
}

// routingFromForm parses the destination routing fields.
func routingFromForm(r *http.Request) (store.RoutingRules, error) {
	include, err := splitCollectorList(r.FormValue("include_collectors"))
	if err != nil {
		return store.RoutingRules{}, err
	}
	exclude, err := splitCollectorList(r.FormValue("exclude_collectors"))
	if err != nil {
		return store.RoutingRules{}, err
	}
	return store.NormalizeRoutingRules(store.RoutingRules{
		MinSeverity:       model.Severity(strings.TrimSpace(r.FormValue("min_severity"))),
		IncludeCollectors: include,
		ExcludeCollectors: exclude,
		ChangeKinds:       r.Form["change_kinds"],
	})
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
		parsed, err := template.New(name).Funcs(templateFuncs()).ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
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
		webhookOutcomes:      map[string]uint64{},
		reconcileCooldown:    defaultReconcileCooldown,
		noticeSender:         notify.New(),
		noticeTimeout:        defaultNoticeTimeout,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticFiles(http.FileServer(http.FS(staticFS)))))
	mux.HandleFunc("GET /favicon.ico", favicon)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("POST /webhooks/tailscale", s.tailscaleWebhook)
	// "/{$}" matches only the root. A bare "GET /" would be a catch-all that
	// turned every typo (and every browser favicon probe) into a status
	// lookup and redirect; unknown paths now return 404.
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /setup", s.setup)
	mux.HandleFunc("POST /setup/claim", s.claim)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /reset", s.reset)
	mux.HandleFunc("POST /reset", s.resetPost)
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("POST /status/reconcile", s.reconcile)
	mux.HandleFunc("POST /status/destinations/retry", s.retryDeadLetters)
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
	mux.HandleFunc("POST /settings/mutes", s.mutePost)
	mux.HandleFunc("POST /settings/password", s.passwordPost)
	mux.HandleFunc("POST /settings/sessions/revoke-others", s.sessionsPost)
	return s.security(mux)
}

// staticFiles serves embedded assets but never a directory listing.
func staticFiles(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// favicon answers the browser's automatic favicon probe without touching the
// store. TailState ships no icon, so the response is an empty, cacheable 204.
func favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusNoContent)
}

// Serve binds the configured listener and serves until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	listener, err := s.Listen()
	if err != nil {
		return err
	}
	return s.ServeListener(ctx, listener)
}

// Listen binds the configured address without serving it. The serve command
// binds before it starts the monitor engine, so an address conflict stops
// startup before any collector poll or notification delivery.
func (s *Server) Listen() (net.Listener, error) {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", s.config.ListenAddr, err)
	}
	return listener, nil
}

// ServeListener serves an already bound listener until ctx is canceled and
// closes the listener on return.
func (s *Server) ServeListener(ctx context.Context, listener net.Listener) error {
	server := &http.Server{Addr: s.config.ListenAddr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: serverWriteTimeout, IdleTimeout: 60 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("TailState web server listening", "address", listener.Addr().String())
		errCh <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := server.Shutdown(shutdown)
		// Serve returns ErrServerClosed once Shutdown has closed the
		// listener; drain it so the goroutine never outlives the call.
		<-errCh
		return err
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
func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	s.renderStatus(w, name, data, http.StatusOK)
}

func (s *Server) renderStatus(w http.ResponseWriter, name string, data pageData, code int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data.Version = s.config.Version
	data.Page = name
	data.MinPasswordLength = secret.MinPasswordRunes
	if data.Now.IsZero() {
		data.Now = time.Now().UTC()
	}
	if code != http.StatusOK {
		w.WriteHeader(code)
	}
	if err := s.templates[name].ExecuteTemplate(w, "layout", data); err != nil {
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
	// The policy is checked before the token so a weak password gets a
	// specific explanation instead of the generic token error. It reveals
	// nothing about the token.
	if err := secret.CheckPasswordPolicy(r.FormValue("password")); err != nil {
		s.renderCredential(w, r, "setup", credentialActionSetup, pageData{Error: secret.PasswordPolicyMessage(err)})
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
	token, ok := s.startSession(w, r)
	if !ok {
		return
	}
	s.recordAdmin(r, store.SessionRef(token), adminChange{event: store.AuditSetupClaim}, nil, 0)
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
	next, _ := safeReturnPath(r.URL.Query().Get("next"))
	if s.authenticated(r, false) {
		if next == "" {
			next = "/status"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.renderCredential(w, r, "login", credentialActionLogin, pageData{Next: next})
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
	next, _ := safeReturnPath(r.FormValue("next"))
	if !s.validateCredentialChallenge(r, credentialActionLogin) {
		s.renderCredential(w, r, "login", credentialActionLogin, pageData{Error: credentialChallengeError, Next: next})
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
		s.recordAdmin(r, "", adminChange{event: store.AuditLoginFailure, outcome: store.AuditFailure}, nil, 0)
		s.renderCredential(w, r, "login", credentialActionLogin, pageData{Error: "Invalid password.", Next: next})
		return
	}
	s.clearFailures(ip)
	s.clearCredentialChallengeCookie(w, credentialActionLogin)
	token, ok := s.startSession(w, r)
	if !ok {
		return
	}
	s.recordAdmin(r, store.SessionRef(token), adminChange{event: store.AuditLoginSuccess}, nil, 0)
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.session(r, true, true)
	if !ok {
		s.rejectUnauthenticated(w, r, true)
		return
	}
	s.store.DeleteSession(r.Context(), auth.token)
	s.recordAdmin(r, auth.ref, adminChange{event: store.AuditLogout}, nil, 0)
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
	if err := secret.CheckPasswordPolicy(r.FormValue("password")); err != nil {
		s.renderCredential(w, r, "reset", credentialActionReset, pageData{Error: secret.PasswordPolicyMessage(err)})
		return
	}
	before := s.enabledDestinations(r.Context())
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
	s.recordAdmin(r, "", adminChange{event: store.AuditPasswordReset, highRisk: true}, before, 0)
	s.clearCookies(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	// The page's meta refresh adds ?refresh=1. That request is not user
	// activity, so an unattended status tab cannot defeat the idle timeout.
	auth, ok := s.requireSession(w, r, false, r.URL.Query().Get(refreshParameter) != "1")
	if !ok {
		return
	}
	csrf := auth.csrf
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
	data := pageData{CSRF: csrf, Status: status}
	data.Expiring, data.ExpiryHorizonDays, data.ExpiryFiltered = s.expiringSoon(r.Context(), time.Now().UTC())
	if deliveries, err := s.store.DestinationDeliveries(r.Context()); err == nil {
		data.DestinationDeliveries = deliveries
	} else {
		slog.Error("load destination delivery state", "error", err)
	}
	s.applyFlash(w, r, &data)
	s.render(w, "status", data)
}

// reconcile requests an immediate broad poll of every collector. It is a
// CSRF-protected POST, rate-limited to one request per reconcileCooldown,
// and answers with Post/Redirect/Get so a reload cannot repeat it.
func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
	if !ok {
		return
	}
	s.reconcileAuthorized(w, r, auth.ref)
}

// reconcileAuthorized handles an authenticated reconcile request; an
// accepted request is recorded in the administrative audit trail.
func (s *Server) reconcileAuthorized(w http.ResponseWriter, r *http.Request, sessionRef string) {
	status, err := s.store.Status(r.Context())
	if err != nil {
		slog.Error("load status for reconcile", "error", err)
		s.redirectWithFlash(w, r, "/status", flashKindError, "Reconciliation could not be requested. Try again.")
		return
	}
	if !status.Configured {
		s.redirectWithFlash(w, r, "/status", flashKindError, "Save the monitoring settings before requesting a reconciliation.")
		return
	}
	if wait, limited := s.reserveReconcile(time.Now()); limited {
		seconds := int64((wait + time.Second - 1) / time.Second)
		s.redirectWithFlash(w, r, "/status", flashKindError, fmt.Sprintf("A reconciliation was requested recently. Try again in %d seconds.", seconds))
		return
	}
	s.engine.Trigger(monitor.ReconcileRequest{})
	s.recordAdmin(r, sessionRef, adminChange{event: store.AuditReconcileRequested}, nil, 0)
	s.redirectWithFlash(w, r, "/status", flashKindSuccess, "Reconciliation requested. Every collector will be polled within a few seconds.")
}

// reserveReconcile records a reconcile request unless one was accepted
// within the cooldown, in which case it returns the remaining wait.
func (s *Server) reserveReconcile(now time.Time) (time.Duration, bool) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if !s.lastReconcile.IsZero() {
		if wait := s.lastReconcile.Add(s.reconcileCooldown).Sub(now); wait > 0 {
			return wait, true
		}
	}
	s.lastReconcile = now
	return 0, false
}

// retryDeadLetters requeues one destination's retryable dead letters with a
// fresh delivery window.
func (s *Server) retryDeadLetters(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
	if !ok {
		return
	}
	s.retryDeadLettersAuthorized(w, r, auth.ref)
}

// retryDeadLettersAuthorized handles an authenticated retry; a retry that
// requeued anything is recorded in the administrative audit trail.
func (s *Server) retryDeadLettersAuthorized(w http.ResponseWriter, r *http.Request, sessionRef string) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	requeued, err := s.store.RetryDeadOutbox(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrDestinationDisabled):
		s.redirectWithFlash(w, r, "/status", flashKindError, "Enable the destination before retrying its dead letters.")
		return
	case err != nil:
		slog.Error("retry dead notifications", "error", err)
		s.redirectWithFlash(w, r, "/status", flashKindError, destinationMutationMessage("retry", err))
		return
	}
	if requeued > 0 {
		s.recordAdmin(r, sessionRef, adminChange{event: store.AuditDeadLettersRetried, target: destinationTarget(id)}, nil, 0)
	}
	s.engine.Wake()
	noun := "notifications"
	if requeued == 1 {
		noun = "notification"
	}
	s.redirectWithFlash(w, r, "/status", flashKindSuccess, fmt.Sprintf("Requeued %d dead %s for delivery.", requeued, noun))
}

// expiringSoon lists device node keys and auth keys that expire within the
// widest configured warning window, using the same filters as the warnings.
// A read failure only hides the card; it never fails the status page.
// Every read uses the store's read-only pool.
func (s *Server) expiringSoon(ctx context.Context, now time.Time) ([]expiringResource, int, bool) {
	settings, err := s.store.ExpiryOptions(ctx)
	if err != nil {
		return nil, expiry.DefaultHorizonDays, false
	}
	horizon := expiry.HorizonDays(settings.WarningDays)
	filtered := len(settings.TagFilter) > 0
	devices, err := s.store.CollectorSnapshots(ctx, settings.Generation, "devices")
	if err != nil {
		slog.Error("load device snapshots for expiry card", "error", err)
		return nil, horizon, filtered
	}
	keys, err := s.store.CollectorSnapshots(ctx, settings.Generation, "keys")
	if err != nil {
		slog.Error("load key snapshots for expiry card", "error", err)
		return nil, horizon, filtered
	}
	items := expiry.Upcoming(expiry.Items(expirySnapshots(devices), expirySnapshots(keys), settings.TagFilter), now, horizon)
	out := make([]expiringResource, 0, len(items))
	for _, item := range items {
		out = append(out, expiringResource{Kind: item.KindLabel(), Name: item.Name, Tags: strings.Join(item.Tags, ", "), Expires: item.Expires, DaysLeft: item.DaysLeft(now)})
	}
	return out, horizon, filtered
}

func expirySnapshots(records []store.SnapshotRecord) []expiry.Snapshot {
	out := make([]expiry.Snapshot, 0, len(records))
	for _, record := range records {
		out = append(out, expiry.Snapshot{ID: record.ResourceID, Name: record.Name, Raw: record.Raw})
	}
	return out
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAuth(w, r, false)
	if !ok {
		return
	}
	filter := historyFilter(r)
	dateError := historyDateError(r)
	history, err := s.store.ListHistory(r.Context(), filter)
	if err != nil {
		http.Error(w, "load history", http.StatusInternalServerError)
		return
	}
	data := pageData{
		CSRF:              csrf,
		History:           history,
		HistoryFilter:     filter,
		HistoryCollectors: knownCollectors(),
		HistoryEventTypes: []string{"created", "changed", "removed"},
		HistorySeverities: []string{string(model.SeverityHigh), string(model.SeverityMedium), string(model.SeverityLow)},
		Error:             dateError,
	}
	data.HistoryFrom, data.HistoryTo = historyDateValues(filter)
	data.EvidenceSigningKeyID, _ = s.store.EvidenceSigningKeyID(r.Context())
	if history.HasNext {
		data.HistoryNextURL = historyURL(filter, history.NextCursor)
	}
	if history.HasPrev {
		data.HistoryPrevURL = historyNewerURL(filter, history.PrevCursor)
	}
	data.HistoryExportURL = historyExportURL(filter)
	data.HistoryExportFields = historyExportFields(filter)
	s.render(w, "history", data)
}

func (s *Server) historyExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r, false); !ok {
		return
	}
	filter := historyFilter(r)
	// Exports default to the largest pack; a smaller "limit" is honored so a
	// script can request smaller parts.
	filter.Limit = 0
	if limit, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit"))); err == nil && limit > 0 {
		filter.Limit = limit
	}
	pack, err := s.store.ExportEvidencePack(r.Context(), filter)
	if err != nil {
		if errors.Is(err, store.ErrEvidencePackTooLarge) {
			http.Error(w, "history export is too large: the newest matching batch alone exceeds the evidence pack size limit; narrow the filters and try again", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "export history", http.StatusInternalServerError)
		return
	}
	filename := "tailstate-drift-evidence-" + time.Now().UTC().Format("20060102T150405Z")
	var part struct {
		Truncated  bool  `json:"truncated"`
		NextCursor int64 `json:"next_cursor"`
	}
	if err := json.Unmarshal(pack, &part); err == nil && part.Truncated && part.NextCursor > 0 {
		// A partial pack names its continuation cursor in the file name and
		// in headers, so the operator (or a script following rel="next") can
		// request the next part with the same filters.
		next := strconv.FormatInt(part.NextCursor, 10)
		filename += "-next-" + next
		w.Header().Set("X-TailState-Evidence-Next-Cursor", next)
		w.Header().Set("Link", "<"+historyExportPartURL(filter, part.NextCursor, filter.Limit)+`>; rel="next"`)
	}
	filename += ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pack)
}

// historyDateLayout is the format of the History page's from/to date
// filters (an HTML date input). Dates are whole UTC days; "to" is inclusive.
const historyDateLayout = "2006-01-02"

func historyFilter(r *http.Request) store.HistoryFilter {
	query := r.URL.Query()
	filter := store.HistoryFilter{
		Collector:  strings.TrimSpace(query.Get("collector")),
		EventType:  strings.TrimSpace(query.Get("event_type")),
		ResourceID: strings.TrimSpace(query.Get("resource")),
		Limit:      20,
	}
	if cursor, err := strconv.ParseInt(query.Get("cursor"), 10, 64); err == nil && cursor > 0 {
		filter.Cursor = cursor
	}
	if batch, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("batch")), 10, 64); err == nil && batch > 0 {
		filter.BatchID = batch
	}
	if severity, ok := model.ParseSeverity(r.URL.Query().Get("severity")); ok {
		filter.Severity = string(severity)
	}
	if after, err := strconv.ParseInt(query.Get("after"), 10, 64); err == nil && after > 0 && filter.Cursor == 0 {
		filter.After = after
	}
	if from, err := time.Parse(historyDateLayout, strings.TrimSpace(query.Get("from"))); err == nil {
		filter.From = from
	}
	if to, err := time.Parse(historyDateLayout, strings.TrimSpace(query.Get("to"))); err == nil {
		filter.Until = to.AddDate(0, 0, 1)
	}
	return filter
}

// historyDateError explains a date filter that historyFilter ignored or
// that cannot match anything.
func historyDateError(r *http.Request) string {
	query := r.URL.Query()
	var parsed [2]time.Time
	for index, name := range []string{"from", "to"} {
		value := strings.TrimSpace(query.Get(name))
		if value == "" {
			continue
		}
		date, err := time.Parse(historyDateLayout, value)
		if err != nil {
			return "Dates must use the YYYY-MM-DD format; the invalid date was ignored."
		}
		parsed[index] = date
	}
	if !parsed[0].IsZero() && !parsed[1].IsZero() && parsed[1].Before(parsed[0]) {
		return "The end date is before the start date, so no changes can match."
	}
	return ""
}

// historyDateValues returns the from/to form values for a filter.
func historyDateValues(filter store.HistoryFilter) (string, string) {
	var from, to string
	if !filter.From.IsZero() {
		from = filter.From.UTC().Format(historyDateLayout)
	}
	if !filter.Until.IsZero() {
		to = filter.Until.UTC().AddDate(0, 0, -1).Format(historyDateLayout)
	}
	return from, to
}

// historyQuery encodes the filters shared by page links and exports.
func historyQuery(filter store.HistoryFilter) url.Values {
	values := url.Values{}
	if filter.BatchID > 0 {
		values.Set("batch", strconv.FormatInt(filter.BatchID, 10))
	}
	if filter.Collector != "" {
		values.Set("collector", filter.Collector)
	}
	if filter.EventType != "" {
		values.Set("event_type", filter.EventType)
	}
	if filter.ResourceID != "" {
		values.Set("resource", filter.ResourceID)
	}
	if filter.Severity != "" {
		values.Set("severity", filter.Severity)
	}
	from, to := historyDateValues(filter)
	if from != "" {
		values.Set("from", from)
	}
	if to != "" {
		values.Set("to", to)
	}
	return values
}

// historyURL links to the page of batches older than cursor.
func historyURL(filter store.HistoryFilter, cursor int64) string {
	values := historyQuery(filter)
	values.Set("cursor", strconv.FormatInt(cursor, 10))
	return "/history?" + values.Encode()
}

// historyNewerURL links to the page of batches newer than after.
func historyNewerURL(filter store.HistoryFilter, after int64) string {
	values := historyQuery(filter)
	values.Set("after", strconv.FormatInt(after, 10))
	return "/history?" + values.Encode()
}

// historyExportPartURL requests the evidence pack part that follows a
// partial pack whose next_cursor is cursor, keeping the same filters.
func historyExportPartURL(filter store.HistoryFilter, cursor int64, limit int) string {
	values := historyQuery(filter)
	values.Set("cursor", strconv.FormatInt(cursor, 10))
	if limit > 0 {
		values.Set("limit", strconv.Itoa(limit))
	}
	return "/history/export?" + values.Encode()
}

// historyExportField is a hidden form field that carries a History filter
// into the "Download next part" form.
type historyExportField struct {
	Name  string
	Value string
}

func historyExportFields(filter store.HistoryFilter) []historyExportField {
	values := historyQuery(filter)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make([]historyExportField, 0, len(names))
	for _, name := range names {
		fields = append(fields, historyExportField{Name: name, Value: values.Get(name)})
	}
	return fields
}

func historyExportURL(filter store.HistoryFilter) string {
	values := historyQuery(filter)
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
	s.applyFlash(w, r, &data)
	s.render(w, "settings", data)
}
func (s *Server) settingsPost(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
	if !ok {
		return
	}
	csrf := auth.csrf
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
	// A form that omits an option (for example a script written for an older
	// release) keeps the current value instead of disabling it.
	expiryDaysOK := true
	if _, present := r.PostForm["expiry_warning_days"]; present {
		input.ExpiryWarningDays, expiryDaysOK = parseExpiryDays(r.PostForm.Get("expiry_warning_days"))
	} else if configured {
		input.ExpiryWarningDays = current.ExpiryWarningDays
	}
	if _, present := r.PostForm["expiry_tag_filter"]; present {
		input.ExpiryTagFilter = splitList(r.PostForm.Get("expiry_tag_filter"))
	} else if configured {
		input.ExpiryTagFilter = current.ExpiryTagFilter
	}
	if _, present := r.PostForm["oauth_scopes"]; present {
		input.OAuthScopes = splitList(r.PostForm.Get("oauth_scopes"))
	} else if configured {
		input.OAuthScopes = current.OAuthScopes
	}
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
	if _, present := r.PostForm["expiry_warning_days"]; present {
		data.ExpiryDays = strings.TrimSpace(r.PostForm.Get("expiry_warning_days"))
	}
	if _, present := r.PostForm["expiry_tag_filter"]; present {
		data.ExpiryTags = strings.TrimSpace(r.PostForm.Get("expiry_tag_filter"))
	}
	if _, present := r.PostForm["oauth_scopes"]; present {
		data.OAuthScopes = strings.TrimSpace(r.PostForm.Get("oauth_scopes"))
	}
	// Validate everything that needs no I/O before contacting Tailscale, so
	// an invalid form fails instantly with a specific message.
	if !expiryDaysOK {
		data.Error = "Expiry warning windows must be whole numbers of days, for example \"14, 3\"."
		s.render(w, "settings", data)
		return
	}
	if message := settingsInputError(&input, device, inventory, err1, err2); message != "" {
		data.Error = message
		s.render(w, "settings", data)
		return
	}
	client := tailscale.New(s.config.TailscaleBase, s.config.OAuthTokenURL, s.config.Version, tailscale.Credentials{Tailnet: input.Tailnet, ClientID: input.OAuthClientID, ClientSecret: input.OAuthClientSecret, Scopes: input.OAuthScopes})
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
	// The notice for a settings change (including an OAuth identity change,
	// which dead-letters queued change digests) goes to every destination
	// that is enabled now. System notices are not tied to a change batch, so
	// the identity change does not dead-letter them.
	before := s.enabledDestinations(r.Context())
	fields := settingsChangeFields(configured, current, input)
	if _, err := s.store.SaveSettings(r.Context(), input); err != nil {
		slog.Error("save settings", "error", err)
		data.Error = "Settings could not be saved. Check the values and try again."
		s.render(w, "settings", data)
		return
	}
	if len(fields) > 0 {
		s.recordAdmin(r, auth.ref, adminChange{event: store.AuditSettingsChanged, fields: fields, highRisk: true}, before, 0)
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
	if _, err := store.NormalizeExpiryWarningDays(input.ExpiryWarningDays); err != nil {
		return fmt.Sprintf("Expiry warning windows must be at most %d whole numbers of days between 1 and %d.", store.MaxExpiryWarningWindows, store.MaxExpiryWarningDays)
	}
	if _, err := store.NormalizeExpiryTagFilter(input.ExpiryTagFilter); err != nil {
		return fmt.Sprintf("Expiry tag filter must be a comma-separated list of at most %d tags such as tag:server.", store.MaxExpiryTagFilters)
	}
	if _, err := store.NormalizeOAuthScopes(input.OAuthScopes); err != nil {
		return fmt.Sprintf("OAuth scopes must be at most %d read scopes such as all:read or devices:core:read; write scopes are not accepted.", store.MaxOAuthScopes)
	}
	if err := store.ValidateSettings(*input); err != nil {
		return "Tailnet must be \"-\" or a tailnet name without spaces, slashes, or URL syntax."
	}
	return ""
}

// parseExpiryDays parses a comma- or space-separated list of whole days. A
// blank value disables expiry warnings and is returned as an empty, non-nil
// slice (nil would select the defaults).
func parseExpiryDays(raw string) ([]int, bool) {
	fields := splitList(raw)
	days := make([]int, 0, len(fields))
	for _, field := range fields {
		value, err := strconv.Atoi(field)
		if err != nil {
			return nil, false
		}
		days = append(days, value)
	}
	return days, true
}

func splitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ", ")
}

func (s *Server) settingsData(ctx context.Context, csrf string, configured bool, settings store.Settings, request *http.Request) pageData {
	data := pageData{CSRF: csrf, Configured: configured, Settings: settings, DeviceSeconds: int64(settings.DeviceInterval.Seconds()), InventorySeconds: int64(settings.InventoryInterval.Seconds()), Diagnostics: s.diagnosticReport(ctx, request), Collectors: knownCollectors(), HistoryEventTypes: []string{"created", "changed", "removed"}, SessionIdleMinutes: int(store.SessionIdleTimeout / time.Minute)}
	expiryDays := settings.ExpiryWarningDays
	if expiryDays == nil {
		expiryDays = store.DefaultExpiryWarningDays()
	}
	data.ExpiryDays, data.ExpiryTags = joinInts(expiryDays), strings.Join(settings.ExpiryTagFilter, ", ")
	scopes := settings.OAuthScopes
	if len(scopes) == 0 {
		scopes = store.DefaultOAuthScopes()
	}
	data.OAuthScopes = strings.Join(scopes, " ")
	// The webhook state reflects what is stored, not the submitted form, so
	// a failed save never claims a secret that was not persisted.
	if webhookState, err := s.store.WebhookStatus(ctx); err == nil {
		data.Webhook = webhookState
	} else {
		slog.Error("load webhook acceleration state", "error", err)
		data.WebhookUnavailable = true
	}
	if request != nil {
		current := ""
		if session, _, ok := s.sessionCookies(request); ok {
			current = session.Value
		}
		if sessions, err := s.store.ListSessions(ctx, current); err == nil {
			data.Sessions = sessions
		} else {
			slog.Error("load sessions", "error", err)
		}
	}
	destinations, err := s.store.ListDestinations(ctx)
	if err == nil {
		pending := map[int64]int{}
		if deliveries, deliveryErr := s.store.DestinationDeliveries(ctx); deliveryErr == nil {
			for _, delivery := range deliveries {
				pending[delivery.ID] = delivery.Pending + delivery.Processing
			}
		} else {
			slog.Error("load destination delivery state", "error", deliveryErr)
		}
		data.Destinations = make([]destinationPage, 0, len(destinations))
		for _, destination := range destinations {
			kinds := map[string]bool{}
			for _, kind := range destination.Routing.ChangeKinds {
				kinds[kind] = true
			}
			data.Destinations = append(data.Destinations, destinationPage{
				ID: destination.ID, Name: destination.Name, DisplayURL: notify.RedactURL(destination.ServiceURL), Enabled: destination.Enabled,
				MinSeverity:       string(destination.Routing.MinSeverity),
				IncludeCollectors: strings.Join(destination.Routing.IncludeCollectors, ", "),
				ExcludeCollectors: strings.Join(destination.Routing.ExcludeCollectors, ", "),
				ChangeKinds:       kinds,
				RoutingSummary:    routingSummary(destination.Routing),
				Format:            destination.Format,
				EffectiveFormat:   notify.FormatFor(destination.ServiceURL, destination.Format),
				Pending:           pending[destination.ID],
			})
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
	if rules, err := s.store.ListMuteRules(ctx); err == nil {
		data.MuteRules = rules
	} else {
		slog.Error("load mute rules", "error", err)
	}
	if activity, err := s.store.RecentAdminAudit(ctx, recentAdminActivity); err == nil {
		data.AdminActivity = activity
	} else {
		slog.Error("load administrative activity", "error", err)
	}
	return data
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
			DatabaseUsedBytes:       metrics.DatabaseUsedBytes,
			DatabaseFreelistPages:   metrics.DatabaseFreelistPages,
			DatabaseFreeBytes:       metrics.DatabaseFreeBytes,
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

// destinationPost handles every destination form. Each outcome, success or
// failure, is reported with Post/Redirect/Get and a one-time flash message,
// so reloading the resulting page never repeats a test notification, a
// toggle, or a removal.
func (s *Server) destinationPost(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
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
			serviceURL = s.storedDestinationURL(ctx, id)
		}
		enabled := r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"
		// Forms that carry routing fields mark themselves with routing=1, so a
		// save without them never resets a destination's rules.
		withRouting := r.FormValue("routing") == "1"
		var rules store.RoutingRules
		var format string
		if withRouting {
			var err error
			if rules, err = routingFromForm(r); err == nil {
				format, err = notify.ValidateFormat(r.FormValue("message_format"))
			}
			if err != nil {
				s.redirectWithFlash(w, r, "/settings", flashKindError, "Notification routing was not saved: "+err.Error()+".")
				return
			}
		}
		before := s.enabledDestinations(ctx)
		change, notified := s.prepareDestinationSave(ctx, r, id, serviceURL, enabled, withRouting, rules, format)
		savedID, err := s.store.SaveDestination(ctx, store.NotificationDestination{ID: id, Name: r.FormValue("name"), ServiceURL: serviceURL, Enabled: enabled})
		if err == nil && withRouting {
			err = s.store.SetDestinationRouting(ctx, savedID, rules)
		}
		if err == nil && withRouting {
			err = s.store.SetDestinationFormat(ctx, savedID, format)
		}
		if err != nil {
			slog.Error("save notification destination", "error", err)
			s.redirectWithFlash(w, r, "/settings", flashKindError, destinationMutationMessage("save", err))
			return
		}
		if change.event != "" {
			change.target = destinationTarget(savedID)
			s.recordAdmin(r, auth.ref, change, before, notified)
		}
		s.engine.Wake()
		s.redirectWithFlash(w, r, "/settings", flashKindSuccess, "Notification destination saved.")
	case "test":
		serviceURL := strings.TrimSpace(r.FormValue("service_url"))
		if serviceURL == "" && id > 0 {
			serviceURL = s.storedDestinationURL(ctx, id)
		}
		// Render the test exactly as deliveries to this destination are
		// rendered: by URL scheme, or by the saved or submitted override.
		override := strings.TrimSpace(r.FormValue("message_format"))
		if override == "" && id > 0 {
			if existing, err := s.store.ListDestinations(ctx); err == nil {
				for _, destination := range existing {
					if destination.ID == id {
						override = destination.Format
						break
					}
				}
			}
		}
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		format := notify.FormatFor(serviceURL, override)
		message := notify.FitMessageFor(notify.Render(s.notificationContext(ctx).Test(time.Now()), format), notify.MessageLimit(serviceURL), format)
		if err := notify.New().Send(testCtx, serviceURL, message); err != nil {
			s.redirectWithFlash(w, r, "/settings", flashKindError, "Notification test failed: "+notify.SafeTestError(err, serviceURL))
			return
		}
		s.redirectWithFlash(w, r, "/settings", flashKindSuccess, "Notification test sent.")
	case "toggle":
		enabled := r.FormValue("enabled") == "true" || r.FormValue("enabled") == "on"
		if r.URL.Path == "/settings/destinations/enable" {
			enabled = true
		} else if r.URL.Path == "/settings/destinations/disable" {
			enabled = false
		}
		before := s.enabledDestinations(ctx)
		old, found := findDestination(before, id)
		var change adminChange
		var notified int64
		if enabled {
			change = adminChange{event: store.AuditDestinationEnabled, target: destinationTarget(id), fields: []string{"enabled"}}
		} else if found {
			// Disabling an enabled destination: tell it first, because a
			// disabled destination receives nothing afterwards.
			change = adminChange{event: store.AuditDestinationDisabled, target: destinationTarget(id), fields: []string{"enabled"}, highRisk: true}
			s.noticeBeforeChange(ctx, old, s.adminMessage(ctx, r, change))
			notified = id
		}
		if err := s.store.SetDestinationEnabled(ctx, id, enabled); err != nil {
			slog.Error("update notification destination", "error", err)
			s.redirectWithFlash(w, r, "/settings", flashKindError, destinationMutationMessage("update", err))
			return
		}
		// Re-enabling an enabled destination, or disabling a disabled one,
		// changes nothing and is not recorded.
		if change.event != "" && (!enabled || !found) {
			s.recordAdmin(r, auth.ref, change, before, notified)
		}
		s.engine.Wake()
		message := "Notification destination enabled."
		if !enabled {
			message = "Notification destination disabled; its pending notifications were dead-lettered."
		}
		s.redirectWithFlash(w, r, "/settings", flashKindSuccess, message)
	case "delete":
		// Removal is irreversible (the encrypted URL is erased), so the form
		// must carry the explicit confirmation from the confirmation step.
		if r.FormValue("confirm") != "remove" {
			s.redirectWithFlash(w, r, "/settings", flashKindError, "The destination was not removed. Open \"Remove\" and confirm the removal.")
			return
		}
		name, pending := s.destinationPending(ctx, id)
		before := s.enabledDestinations(ctx)
		change := adminChange{event: store.AuditDestinationDeleted, target: destinationTarget(id), highRisk: true}
		var notified int64
		if old, found := findDestination(before, id); found {
			// The URL is erased by the removal, so this is the last chance
			// to reach the destination.
			s.noticeBeforeChange(ctx, old, s.adminMessage(ctx, r, change))
			notified = id
		}
		if err := s.store.DeleteDestination(ctx, id); err != nil {
			slog.Error("remove notification destination", "error", err)
			s.redirectWithFlash(w, r, "/settings", flashKindError, destinationMutationMessage("remove", err))
			return
		}
		s.recordAdmin(r, auth.ref, change, before, notified)
		s.engine.Wake()
		noun := "notifications were"
		if pending == 1 {
			noun = "notification was"
		}
		s.redirectWithFlash(w, r, "/settings", flashKindSuccess, fmt.Sprintf("Removed %s; %d pending %s dead-lettered.", name, pending, noun))
	default:
		http.Error(w, "unknown destination action", http.StatusBadRequest)
	}
}

// mutePost adds or removes a mute rule. Collector and field rules must name
// a collector this release monitors. Like the destination forms, every
// outcome is reported with Post/Redirect/Get and a one-time flash message.
func (s *Server) mutePost(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.requireSession(w, r, true, true)
	if !ok {
		return
	}
	ctx := r.Context()
	switch r.FormValue("action") {
	case "add":
		kind, value := strings.TrimSpace(r.FormValue("kind")), strings.TrimSpace(r.FormValue("value"))
		if kind == store.MuteCollector || kind == store.MuteField {
			collector, _, _ := strings.Cut(value, ".")
			if _, err := splitCollectorList(collector); err != nil || collector == "" {
				s.redirectWithFlash(w, r, "/settings", flashKindError, "Mute rule was not saved: unknown collector.")
				return
			}
		}
		before := s.enabledDestinations(ctx)
		ruleID, err := s.store.AddMuteRule(ctx, kind, value)
		if err != nil {
			s.redirectWithFlash(w, r, "/settings", flashKindError, "Mute rule was not saved: "+muteRuleMessage(err)+".")
			return
		}
		// A mute rule can silence alerts, so it is a high-risk change.
		s.recordAdmin(r, auth.ref, adminChange{event: store.AuditMuteAdded, target: "mute:" + strconv.FormatInt(ruleID, 10), fields: []string{"kind", "value"}, highRisk: true}, before, 0)
		s.redirectWithFlash(w, r, "/settings", flashKindSuccess, "Mute rule added.")
	case "delete":
		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err := s.store.DeleteMuteRule(ctx, id); err != nil {
			s.redirectWithFlash(w, r, "/settings", flashKindError, "Mute rule not found.")
			return
		}
		s.recordAdmin(r, auth.ref, adminChange{event: store.AuditMuteRemoved, target: "mute:" + strconv.FormatInt(id, 10)}, nil, 0)
		s.redirectWithFlash(w, r, "/settings", flashKindSuccess, "Mute rule removed.")
	default:
		http.Error(w, "unknown mute rule action", http.StatusBadRequest)
	}
}

// muteRuleMessage keeps validation messages and hides storage details.
func muteRuleMessage(err error) string {
	if errors.Is(err, store.ErrMuteRuleExists) {
		return "an identical rule already exists"
	}
	if errors.Is(err, store.ErrInvalidMuteRule) {
		return err.Error()
	}
	slog.Error("save mute rule", "error", err)
	return "the rule could not be stored"
}

// notificationContext identifies this instance in notifications sent from the
// web UI. An unconfigured installation is shown as the default tailnet.
func (s *Server) notificationContext(ctx context.Context) notify.Context {
	messages := notify.Context{Label: s.config.InstanceLabel, PublicURL: s.config.PublicURL, Version: s.config.Version}
	if settings, err := s.store.Settings(ctx); err == nil {
		messages.Tailnet = settings.Tailnet
	}
	return messages
}

// storedDestinationURL returns the saved URL of an active destination, or
// "" when it cannot be read.
func (s *Server) storedDestinationURL(ctx context.Context, id int64) string {
	existing, err := s.store.ListDestinations(ctx)
	if err != nil {
		return ""
	}
	for _, destination := range existing {
		if destination.ID == id {
			return destination.ServiceURL
		}
	}
	return ""
}

// destinationPending returns a destination's display name and the number of
// pending or in-flight notifications that removing it would dead-letter.
func (s *Server) destinationPending(ctx context.Context, id int64) (string, int) {
	deliveries, err := s.store.DestinationDeliveries(ctx)
	if err == nil {
		for _, delivery := range deliveries {
			if delivery.ID == id {
				return delivery.Name, delivery.Pending + delivery.Processing
			}
		}
	}
	return "the destination", 0
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
	case "retry":
		return "Dead notifications could not be requeued."
	default:
		return "Notification destination operation failed."
	}
}

// Webhook request outcomes, exported as tailstate_webhook_requests_total.
// Signature failures and content-bounds fallbacks are deliberately distinct.
const (
	webhookOutcomeAccepted         = "accepted"
	webhookOutcomeContentFallback  = "content_fallback"
	webhookOutcomeDuplicate        = "duplicate"
	webhookOutcomeInvalidSignature = "invalid_signature"
	webhookOutcomeMalformed        = "malformed"
	webhookOutcomeTooLarge         = "too_large"
	webhookOutcomeNotConfigured    = "not_configured"
	webhookOutcomeUnavailable      = "unavailable"
)

var webhookOutcomes = []string{
	webhookOutcomeAccepted,
	webhookOutcomeContentFallback,
	webhookOutcomeDuplicate,
	webhookOutcomeInvalidSignature,
	webhookOutcomeMalformed,
	webhookOutcomeTooLarge,
	webhookOutcomeNotConfigured,
	webhookOutcomeUnavailable,
}

func (s *Server) recordWebhookOutcome(outcome string) {
	s.metricsMu.Lock()
	s.webhookOutcomes[outcome]++
	s.metricsMu.Unlock()
}

func (s *Server) webhookOutcomeCount(outcome string) uint64 {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	return s.webhookOutcomes[outcome]
}

func (s *Server) tailscaleWebhook(w http.ResponseWriter, r *http.Request) {
	if !webhook.Method(r.Method) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	secret, err := s.store.WebhookSecret(r.Context())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.recordWebhookOutcome(webhookOutcomeNotConfigured)
			http.Error(w, "webhook not configured", http.StatusNotFound)
			return
		}
		s.recordWebhookOutcome(webhookOutcomeUnavailable)
		http.Error(w, "webhook unavailable", http.StatusServiceUnavailable)
		return
	}
	if secret == "" {
		s.recordWebhookOutcome(webhookOutcomeNotConfigured)
		http.Error(w, "webhook not configured", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.recordWebhookOutcome(webhookOutcomeTooLarge)
			http.Error(w, "webhook body too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.recordWebhookOutcome(webhookOutcomeMalformed)
		http.Error(w, "invalid webhook body", http.StatusBadRequest)
		return
	}
	delivery, err := webhook.Verify(body, r.Header.Get("Tailscale-Webhook-Signature"), secret, time.Now().UTC())
	if err != nil {
		// Keep verification details out of responses and logs. 401 is reserved
		// for signature and timestamp failures; size and shape problems get
		// their own status so operators debug the right thing.
		switch {
		case errors.Is(err, webhook.ErrBodyTooLarge):
			s.recordWebhookOutcome(webhookOutcomeTooLarge)
			http.Error(w, "webhook body too large", http.StatusRequestEntityTooLarge)
		case errors.Is(err, webhook.ErrMalformedBody):
			s.recordWebhookOutcome(webhookOutcomeMalformed)
			http.Error(w, "invalid webhook body", http.StatusBadRequest)
		default:
			s.recordWebhookOutcome(webhookOutcomeInvalidSignature)
			http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		}
		return
	}
	trigger, created, err := s.store.RecordWebhookTrigger(r.Context(), delivery.BodyHash, delivery.EventTypes, delivery.Collectors)
	if err != nil {
		s.recordWebhookOutcome(webhookOutcomeUnavailable)
		http.Error(w, "record webhook", http.StatusInternalServerError)
		return
	}
	if created && s.engine != nil {
		s.engine.Trigger(monitor.ReconcileRequest{TriggerID: trigger.ID, Collectors: delivery.Collectors})
	}
	w.Header().Set("Cache-Control", "no-store")
	status := "accepted"
	outcome := webhookOutcomeAccepted
	if delivery.FallbackReason != "" {
		outcome = webhookOutcomeContentFallback
		// The reason is a fixed vocabulary; no provider content is logged.
		slog.Warn("authentic webhook content exceeded TailState bounds; requesting full reconciliation", "reason", delivery.FallbackReason, "events", len(delivery.Events), "trigger_id", trigger.ID)
	}
	if !created {
		status = "duplicate"
		outcome = webhookOutcomeDuplicate
	}
	s.recordWebhookOutcome(outcome)
	response := map[string]any{"status": status, "trigger_id": trigger.ID}
	if len(delivery.Collectors) == 0 {
		response["reconciliation"] = "full"
	} else {
		response["reconciliation"] = "targeted"
	}
	writeJSON(w, http.StatusAccepted, response)
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
			{"admin_audit", cleanup.AdminAuditDeleted},
		} {
			fmt.Fprintf(b, "tailstate_cleanup_rows_total{table=%q} %d\n", row.table, row.count)
		}
	}
	metricValue(b, "tailstate_storage_bytes", "gauge", "Logical bytes allocated by the SQLite database, including free pages.", storage.DatabaseBytes)
	metricValue(b, "tailstate_storage_used_bytes", "gauge", "Logical bytes in use by the SQLite database, excluding free pages.", storage.DatabaseUsedBytes)
	metricValue(b, "tailstate_storage_freelist_pages", "gauge", "Free SQLite pages awaiting reuse or compaction.", storage.DatabaseFreelistPages)
	metricValue(b, "tailstate_storage_free_bytes", "gauge", "Bytes held by free SQLite pages.", storage.DatabaseFreeBytes)
	metricValue(b, "tailstate_storage_limit_bytes", "gauge", "Configured database budget.", storage.DatabaseLimitBytes)
	metricValue(b, "tailstate_storage_pressure_ratio", "gauge", "Used database bytes (excluding free pages) divided by the configured budget.", storage.PressureRatio())
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
	metricFamily(b, "tailstate_webhook_requests_total", "counter", "Tailscale webhook requests by outcome; content_fallback is an authentic delivery outside TailState's bounds that requested a full reconciliation.")
	for _, outcome := range webhookOutcomes {
		fmt.Fprintf(b, "tailstate_webhook_requests_total{outcome=%q} %d\n", outcome, s.webhookOutcomeCount(outcome))
	}
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

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	token, csrf, err := s.store.CreateSession(r.Context())
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return "", false
	}
	// With secure cookies a sign-in expires the unprefixed cookies of an
	// earlier sign-in, so the browser holds one generation only.
	if s.config.CookieSecure {
		for _, name := range []string{sessionCookieBase, csrfCookieBase} {
			http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: name == sessionCookieBase, Secure: true, SameSite: http.SameSiteStrictMode})
		}
	}
	maxAge := int(store.SessionLifetime / time.Second)
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(sessionCookieBase), Value: token, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(csrfCookieBase), Value: csrf, Path: "/", MaxAge: maxAge, HttpOnly: false, Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	return token, true
}

// clearCookies expires the session cookies under both namings.
func (s *Server) clearCookies(w http.ResponseWriter) {
	names := []string{sessionCookieBase, csrfCookieBase}
	if s.config.CookieSecure {
		names = append(names, hostCookiePrefix+sessionCookieBase, hostCookiePrefix+csrfCookieBase)
	}
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: strings.HasSuffix(name, sessionCookieBase), Secure: s.config.CookieSecure, SameSite: http.SameSiteStrictMode})
	}
}
func (s *Server) authenticated(r *http.Request, requireCSRF bool) bool {
	_, ok := s.session(r, requireCSRF, true)
	return ok
}
func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request, csrf bool) (string, bool) {
	auth, ok := s.requireSession(w, r, csrf, true)
	return auth.csrf, ok
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
