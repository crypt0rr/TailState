package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
	"github.com/crypt0rr/tailstate/internal/tailscale"
)

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
	// ServiceURLUnreadable flags a URL that cannot be decrypted with the
	// current master key; DisplayURL is then empty.
	ServiceURLUnreadable bool
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
		all, ok := s.destinationsBeforeChange(w, r)
		if !ok {
			return
		}
		serviceURL := strings.TrimSpace(r.FormValue("service_url"))
		if serviceURL == "" && id > 0 {
			stored, _ := findDestination(all, id)
			serviceURL = stored.ServiceURL
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
		before := onlyEnabled(all)
		change, notified := s.prepareDestinationSave(ctx, r, all, id, serviceURL, enabled, withRouting, rules, format)
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
		// A blank URL tests the saved destination. The test is rendered
		// exactly as deliveries to it are: by URL scheme, or by the saved or
		// submitted format override.
		serviceURL := strings.TrimSpace(r.FormValue("service_url"))
		override := strings.TrimSpace(r.FormValue("message_format"))
		if id > 0 && (serviceURL == "" || override == "") {
			stored, _ := s.storedDestination(ctx, id)
			if serviceURL == "" {
				serviceURL = stored.ServiceURL
			}
			if override == "" {
				override = stored.Format
			}
		}
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		message := notify.PrepareMessage(s.notificationContext(ctx).Test(time.Now()), serviceURL, override)
		if err := s.destinationTester.SendPrepared(testCtx, serviceURL, message); err != nil {
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
		all, ok := s.destinationsBeforeChange(w, r)
		if !ok {
			return
		}
		before := onlyEnabled(all)
		old, found := findDestination(all, id)
		var change adminChange
		var notified int64
		switch {
		case !found || old.Enabled == enabled:
			// Re-enabling an enabled destination, or disabling a disabled
			// one, changes nothing and is not recorded; an unknown
			// destination is refused below.
		case enabled:
			// Re-enabling resumes deliveries to the destination, so the
			// destinations already enabled are told.
			change = adminChange{event: store.AuditDestinationEnabled, target: destinationTarget(id), fields: []string{"enabled"}, highRisk: true}
		default:
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
		if change.event != "" {
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
		all, ok := s.destinationsBeforeChange(w, r)
		if !ok {
			return
		}
		name, pending := s.destinationPending(ctx, id)
		before := onlyEnabled(all)
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

// notificationContext identifies this instance in notifications sent from the
// web UI. An unconfigured installation is shown as the default tailnet.
func (s *Server) notificationContext(ctx context.Context) notify.Context {
	messages := notify.Context{Label: s.config.InstanceLabel, PublicURL: s.config.PublicURL, Version: s.config.Version}
	if settings, err := s.store.Settings(ctx); err == nil {
		messages.Tailnet = settings.Tailnet
	}
	return messages
}

// destinationsBeforeChange reads every destination before a mutation. The
// read decides what the change is, which destinations are told about it, and
// whether the destination itself is notified first, so when it fails the
// mutation is refused rather than applied unaudited or unannounced.
func (s *Server) destinationsBeforeChange(w http.ResponseWriter, r *http.Request) ([]store.NotificationDestination, bool) {
	destinations, err := s.store.ListDestinations(r.Context())
	if err != nil {
		slog.Error("load notification destinations before a change", "error", err)
		s.redirectWithFlash(w, r, "/settings", flashKindError, "Notification destinations could not be read, so nothing was changed. Try again.")
		return nil, false
	}
	return destinations, true
}

// storedDestination returns a saved, active destination. found is false
// (and the zero destination is returned) when it does not exist or cannot be
// read.
func (s *Server) storedDestination(ctx context.Context, id int64) (destination store.NotificationDestination, found bool) {
	existing, err := s.store.ListDestinations(ctx)
	if err != nil {
		return store.NotificationDestination{}, false
	}
	for _, candidate := range existing {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return store.NotificationDestination{}, false
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
