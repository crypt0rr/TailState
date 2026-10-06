package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

const (
	// defaultNoticeTimeout bounds a direct administrative notice, sent
	// synchronously to a destination that the change is about to disable,
	// remove, or redirect.
	defaultNoticeTimeout = 10 * time.Second
	// recentAdminActivity is the number of audit records shown in Settings.
	recentAdminActivity = 25
)

// adminChange describes one administrative action for the audit trail and,
// when highRisk is set, for the system notification sent to the
// destinations that were enabled before the change.
type adminChange struct {
	event    string
	outcome  string
	target   string
	fields   []string
	highRisk bool
}

func destinationTarget(id int64) string { return "destination:" + strconv.FormatInt(id, 10) }

// auditClientIP returns the proxy-aware client address, or "" when it is
// not an IP address (for example a test or Unix-socket peer).
func (s *Server) auditClientIP(r *http.Request) string {
	addr, err := netip.ParseAddr(s.clientIP(r))
	if err != nil {
		return ""
	}
	return addr.Unmap().WithZone("").String()
}

// enabledDestinations returns the destinations that are enabled right now.
// Handlers capture it before a change, because the notice for a change must
// reach the destinations that were active before it.
func (s *Server) enabledDestinations(ctx context.Context) []store.NotificationDestination {
	destinations, err := s.store.ListDestinations(ctx)
	if err != nil {
		slog.Error("load notification destinations for administrative notice", "error", err)
		return nil
	}
	enabled := destinations[:0]
	for _, destination := range destinations {
		if destination.Enabled {
			enabled = append(enabled, destination)
		}
	}
	return enabled
}

func (s *Server) adminMessage(ctx context.Context, r *http.Request, change adminChange) notify.Message {
	return s.notificationContext(ctx).AdminChange(store.AdminAuditLabel(change.event), change.fields, change.target, s.auditClientIP(r), time.Now())
}

// noticeBeforeChange sends the change notice synchronously to destination
// before a change that stops it from receiving later notifications
// (disabling, removing, or redirecting it). Delivery is bounded and best
// effort: a failure is logged but does not block the change, because an
// unreachable destination must still be removable. The durable notice queued
// by recordAdmin skips this destination.
func (s *Server) noticeBeforeChange(ctx context.Context, destination store.NotificationDestination, message notify.Message) {
	prepared := notify.PrepareMessage(message, destination.ServiceURL, destination.Format)
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.noticeTimeout)
	defer cancel()
	if err := notify.Deliver(sendCtx, s.noticeSender, destination.ServiceURL, prepared); err != nil {
		slog.Warn("administrative notice could not be delivered before the change", "destination_id", destination.ID, "reason", notify.SafeDeliveryError(err))
		return
	}
	slog.Info("administrative notice delivered before the change", "destination_id", destination.ID)
}

// recordAdmin writes the audit record for a completed change. For a
// high-risk change it also queues the notice, in the same transaction, for
// every destination in before that was not already notified directly.
func (s *Server) recordAdmin(r *http.Request, sessionRef string, change adminChange, before []store.NotificationDestination, notifiedDirectly int64) {
	ctx := r.Context()
	entry := store.AdminAuditEntry{Event: change.event, Outcome: change.outcome, ClientIP: s.auditClientIP(r), SessionRef: sessionRef, Target: change.target, Fields: change.fields}
	var notice *store.AdminNotice
	if change.highRisk {
		recipients := make([]int64, 0, len(before))
		for _, destination := range before {
			if destination.ID != notifiedDirectly {
				recipients = append(recipients, destination.ID)
			}
		}
		notice = &store.AdminNotice{Message: s.adminMessage(ctx, r, change), Recipients: recipients}
	}
	if _, err := s.store.RecordAdminAudit(context.WithoutCancel(ctx), entry, notice); err != nil {
		slog.Error("record administrative action", "event", change.event, "error", err)
		return
	}
	if notice != nil && s.engine != nil {
		s.engine.Wake()
	}
}

// settingsChangeFields lists the settings a save changes, by name. Secret
// values are compared but never recorded.
func settingsChangeFields(configured bool, current, input store.Settings) []string {
	var fields []string
	add := func(changed bool, name string) {
		if changed || !configured {
			fields = append(fields, name)
		}
	}
	add(input.Tailnet != current.Tailnet, "tailnet")
	add(input.OAuthClientID != current.OAuthClientID, "oauth_client_id")
	add(input.OAuthClientSecret != current.OAuthClientSecret, "oauth_client_secret")
	add(input.DeviceInterval != current.DeviceInterval, "device_interval")
	add(input.InventoryInterval != current.InventoryInterval, "inventory_interval")
	add(!sameNormalized(store.NormalizeOAuthScopes, current.OAuthScopes, input.OAuthScopes), "oauth_scopes")
	add(!sameNormalized(store.NormalizeExpiryWarningDays, current.ExpiryWarningDays, input.ExpiryWarningDays), "expiry_warning_days")
	add(!sameNormalized(store.NormalizeExpiryTagFilter, current.ExpiryTagFilter, input.ExpiryTagFilter), "expiry_tag_filter")
	switch {
	case input.ClearWebhookSecret:
		if current.WebhookSecret != "" {
			fields = append(fields, "webhook_secret_cleared")
		}
	case input.WebhookSecret != "" && input.WebhookSecret != current.WebhookSecret:
		fields = append(fields, "webhook_secret")
	}
	return fields
}

// sameNormalized reports whether two option lists select the same
// behaviour once defaults, ordering, and duplicates are normalized (nil
// expiry windows mean the defaults; no scopes mean all:read).
func sameNormalized[T comparable](normalize func([]T) ([]T, error), current, input []T) bool {
	a, errA := normalize(current)
	b, errB := normalize(input)
	if errA != nil || errB != nil {
		return reflect.DeepEqual(current, input)
	}
	return slices.Equal(a, b)
}

// destinationChangeFields lists what a destination save changes. format and
// rules are compared only when the form carried them.
func destinationChangeFields(old store.NotificationDestination, name, serviceURL string, enabled, withRouting bool, rules store.RoutingRules, format string) []string {
	var fields []string
	if name != old.Name {
		fields = append(fields, "name")
	}
	if serviceURL != old.ServiceURL {
		fields = append(fields, "service_url")
	}
	if enabled != old.Enabled {
		fields = append(fields, "enabled")
	}
	if withRouting && !reflect.DeepEqual(normalizedRules(rules), normalizedRules(old.Routing)) {
		fields = append(fields, "routing")
	}
	if withRouting && format != old.Format {
		fields = append(fields, "message_format")
	}
	return fields
}

func normalizedRules(rules store.RoutingRules) store.RoutingRules {
	normalized, err := store.NormalizeRoutingRules(rules)
	if err != nil {
		return rules
	}
	for _, list := range []*[]string{&normalized.IncludeCollectors, &normalized.ExcludeCollectors, &normalized.ChangeKinds} {
		if len(*list) == 0 {
			*list = nil
		}
	}
	return normalized
}

func findDestination(destinations []store.NotificationDestination, id int64) (store.NotificationDestination, bool) {
	for _, destination := range destinations {
		if destination.ID == id {
			return destination, true
		}
	}
	return store.NotificationDestination{}, false
}

// prepareDestinationSave works out the audit record for a destination save.
// When the save would stop an enabled destination from receiving notices at
// its current URL (disabling it or replacing the URL), the notice is sent
// there first and the destination ID is returned so the durable notice skips
// it. A save that changes nothing returns an empty change.
func (s *Server) prepareDestinationSave(ctx context.Context, r *http.Request, id int64, serviceURL string, enabled, withRouting bool, rules store.RoutingRules, format string) (adminChange, int64) {
	if id <= 0 {
		return adminChange{event: store.AuditDestinationAdded, fields: []string{"enabled", "name", "service_url"}}, 0
	}
	destinations, err := s.store.ListDestinations(ctx)
	if err != nil {
		return adminChange{}, 0
	}
	old, found := findDestination(destinations, id)
	if !found {
		return adminChange{}, 0
	}
	name := strings.TrimSpace(r.FormValue("name"))
	fields := destinationChangeFields(old, name, serviceURL, enabled, withRouting, rules, format)
	if len(fields) == 0 {
		return adminChange{}, 0
	}
	disabling := old.Enabled && !enabled
	redirecting := containsField(fields, "service_url")
	change := adminChange{event: store.AuditDestinationEdited, target: destinationTarget(id), fields: fields, highRisk: disabling || redirecting || containsField(fields, "routing")}
	if old.Enabled && (disabling || redirecting) && name != "" && notify.Validate(serviceURL) == nil {
		s.noticeBeforeChange(ctx, old, s.adminMessage(ctx, r, change))
		return change, id
	}
	return change, 0
}

func containsField(fields []string, name string) bool {
	for _, field := range fields {
		if field == name {
			return true
		}
	}
	return false
}
