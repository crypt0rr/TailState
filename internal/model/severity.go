package model

import (
	"encoding/json"
	"strings"
)

// Severity is the built-in importance of a Change. It drives per-destination
// routing (a minimum severity), the digest prefix, and the History filter.
type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Severities lists the severities from lowest to highest.
var Severities = []Severity{SeverityLow, SeverityMedium, SeverityHigh}

// Rank orders severities; an unknown or empty severity ranks as low so that
// a missing classification is never dropped by a minimum-severity rule set to
// "low" (the "all changes" default).
func (s Severity) Rank() int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	default:
		return 1
	}
}

// AtLeast reports whether s is at least minimum.
func (s Severity) AtLeast(minimum Severity) bool { return s.Rank() >= minimum.Rank() }

// ParseSeverity accepts the canonical lower-case severity names.
func ParseSeverity(value string) (Severity, bool) {
	switch Severity(strings.ToLower(strings.TrimSpace(value))) {
	case SeverityLow:
		return SeverityLow, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityHigh:
		return SeverityHigh, true
	}
	return "", false
}

// highImpactCollectors are collectors whose every change is high severity:
// the access policy, log streaming, tailnet settings, webhook endpoints, and
// OAuth applications (which, like keys, grant API access).
var highImpactCollectors = map[string]struct{}{
	"policy":        {},
	"log_streaming": {},
	"settings":      {},
	"webhooks":      {},
	"oauth_apps":    {},
}

// lowImpactDeviceFields are device fields that change during routine client
// upgrades. A device change that touches only these fields is low severity.
var lowImpactDeviceFields = map[string]struct{}{
	"clientversion":   {},
	"updateavailable": {},
	"os":              {},
	"distro":          {},
}

// CreatedState is the part of a created resource's first snapshot that
// decides its severity: the role of a user or user invite, and whether a
// device joined tagged or with key expiry disabled.
type CreatedState struct {
	Role              string
	Tagged            bool
	KeyExpiryDisabled bool
}

// CreatedStateOf reads the CreatedState of a created resource from its
// canonical snapshot. It returns nil for collectors whose creations are
// classified on their kind alone and for a snapshot that is not an object.
func CreatedStateOf(collector string, raw []byte) *CreatedState {
	switch collector {
	case "users", "user_invites", "devices":
	default:
		return nil
	}
	var snapshot map[string]any
	if json.Unmarshal(raw, &snapshot) != nil || snapshot == nil {
		return nil
	}
	state := &CreatedState{KeyExpiryDisabled: isTrue(snapshot["keyExpiryDisabled"])}
	role, _ := snapshot["role"].(string)
	state.Role = strings.TrimSpace(role)
	tags, _ := snapshot["tags"].([]any)
	state.Tagged = len(tags) > 0
	return state
}

// privileged reports whether a created resource starts in a state whose
// later edit would be high severity: a user or invite with a role other
// than member, or a device that joined tagged or with key expiry disabled.
func (s *CreatedState) privileged(collector string) bool {
	if s == nil {
		return false
	}
	switch collector {
	case "users", "user_invites":
		return s.Role != "" && !strings.EqualFold(s.Role, "member")
	case "devices":
		return s.Tagged || s.KeyExpiryDisabled
	}
	return false
}

// Classify returns the built-in severity of a change. The table is
// documented in docs/notifications.md ("Severity and routing") and is evaluated as:
//
//   - high: any policy, log_streaming, settings, webhooks, or oauth_apps
//     change; a keys resource created; a users or user_invites resource
//     created with a role other than member; a devices resource created
//     with tags or with key expiry disabled; a users change touching role;
//     a devices change to tags, authorized false→true, or keyExpiryDisabled
//     false→true; a device share created multi-use, with the exit node
//     allowed, or already accepted, accepted, or newly allowed to use the
//     exit node.
//   - low: a devices change whose fields are all clientVersion,
//     updateAvailable, os, or distro; a device_details change whose fields
//     are all share bookkeeping (see ShareTransition.Severity).
//   - medium: everything else, including member users, member invites, and
//     untagged devices created, devices removed, route changes, and other
//     user invite changes.
//
// A created resource is classified on its initial state (Change.Created);
// without one it is classified on its kind alone.
//
// A changed resource takes the highest severity of its fields. A change
// whose field list was truncated is at least medium, because the omitted
// fields cannot be shown to be routine.
func Classify(change Change) Severity {
	if _, high := highImpactCollectors[change.Collector]; high {
		return SeverityHigh
	}
	if change.Kind == "created" && change.Created.privileged(change.Collector) {
		return SeverityHigh
	}
	switch change.Collector {
	case "keys":
		if change.Kind == "created" {
			return SeverityHigh
		}
	case "users":
		if change.Kind == "changed" {
			for _, field := range change.Fields {
				if fieldRoot(field.Field) == "role" {
					return SeverityHigh
				}
			}
		}
	case "devices":
		if change.Kind == "changed" {
			return classifyDeviceFields(change)
		}
	case "device_details":
		if change.Kind == "changed" {
			return classifyDeviceDetails(change)
		}
	}
	return SeverityMedium
}

func classifyDeviceFields(change Change) Severity {
	if len(change.Fields) == 0 {
		return SeverityMedium
	}
	severity := SeverityLow
	for _, field := range change.Fields {
		root := fieldRoot(field.Field)
		switch {
		case root == "tags":
			return SeverityHigh
		case (root == "authorized" || root == "keyexpirydisabled") && isFalse(field.Old, field.OldPresent) && isTrue(field.New):
			return SeverityHigh
		}
		if _, low := lowImpactDeviceFields[root]; !low {
			severity = SeverityMedium
		}
	}
	if change.FieldsTruncated && severity == SeverityLow {
		return SeverityMedium
	}
	return severity
}

// fieldRoot returns the compact, lower-case first segment of a field path;
// the root of an element path such as "deviceInvites[123].tailnetId" is
// "deviceinvites".
func fieldRoot(path string) string {
	root := FieldRoot(path)
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(root, "_", ""), "-", ""))
}

// isFalse treats an absent value as false: a field that appears as true for
// the first time has been switched on.
func isFalse(value any, present bool) bool {
	if !present && value == nil {
		return true
	}
	flag, ok := value.(bool)
	return ok && !flag
}

func isTrue(value any) bool {
	flag, ok := value.(bool)
	return ok && flag
}
