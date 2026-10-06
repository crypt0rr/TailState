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
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/boot"
	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
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
	// destinationTester sends the Settings "Send test" message.
	destinationTester notify.PreparedSender
	// apiWindows holds each API token's current rate-limit window.
	apiMu      sync.Mutex
	apiWindows map[int64]apiWindow
	// tokenReveals holds newly created API token secrets, in memory only,
	// until the Settings page that follows the creation shows them once.
	tokenReveals *revealStore
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
	APITokens                       []store.APIToken
	APIScopes                       []string
	APITokenLifetimes               []int
	NewAPIToken                     string
	SessionIdleMinutes              int
	MinPasswordLength               int
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
		destinationTester:    notify.New(),
		apiWindows:           map[int64]apiWindow{},
		tokenReveals:         newRevealStore(),
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
	mux.HandleFunc("POST /settings/api-tokens", s.apiTokenPost)
	mux.HandleFunc("GET /api/v1/status", s.apiStatus)
	mux.HandleFunc("GET /api/v1/history", s.apiHistory)
	mux.HandleFunc("GET /api/v1/evidence", s.apiEvidence)
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

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
