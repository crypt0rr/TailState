package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/crypt0rr/tailstate/internal/store"
)

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
