package model

import "strings"

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
// the access policy, log streaming, tailnet settings, and webhook endpoints.
var highImpactCollectors = map[string]struct{}{
	"policy":        {},
	"log_streaming": {},
	"settings":      {},
	"webhooks":      {},
}

// lowImpactDeviceFields are device fields that change during routine client
// upgrades. A device change that touches only these fields is low severity.
var lowImpactDeviceFields = map[string]struct{}{
	"clientversion":   {},
	"updateavailable": {},
	"os":              {},
	"distro":          {},
}

// Classify returns the built-in severity of a change. The table is
// documented in the README ("Severity and routing") and is evaluated as:
//
//   - high: any policy, log_streaming, settings, or webhooks change; a keys
//     resource created; a users change touching role; a devices change to
//     tags, authorized false→true, or keyExpiryDisabled false→true.
//   - low: a devices change whose fields are all clientVersion,
//     updateAvailable, os, or distro.
//   - medium: everything else, including devices created or removed, route
//     changes, and user invites.
//
// A changed resource takes the highest severity of its fields. A change
// whose field list was truncated is at least medium, because the omitted
// fields cannot be shown to be routine.
func Classify(change Change) Severity {
	if _, high := highImpactCollectors[change.Collector]; high {
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

// fieldRoot returns the compact, lower-case first segment of a field path.
func fieldRoot(path string) string {
	root, _, _ := strings.Cut(path, ".")
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
