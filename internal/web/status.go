package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/expiry"
	"github.com/crypt0rr/tailstate/internal/monitor"
	"github.com/crypt0rr/tailstate/internal/store"
)

// expiringResource is one row of the status page's "Expiring soon" card.
type expiringResource struct {
	Kind     string
	Name     string
	Tags     string
	Expires  time.Time
	DaysLeft int
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
