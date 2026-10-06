package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/diagnostics"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

// defaultTailnet selects the tailnet that owns the OAuth client.
const defaultTailnet = "-"

// defaultSettings is the single source of the values an unconfigured
// installation shows on the Settings form.
func defaultSettings() store.Settings {
	return store.Settings{Tailnet: defaultTailnet, DeviceInterval: 60 * time.Second, InventoryInterval: 5 * time.Minute}
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
		current = defaultSettings()
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
		input.Tailnet = defaultTailnet
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
	data.APIScopes, data.APITokenLifetimes = store.APIScopes, apiTokenLifetimes
	if tokens, err := s.store.ListAPITokens(ctx); err == nil {
		data.APITokens = tokens
	} else {
		slog.Error("load API tokens", "error", err)
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
