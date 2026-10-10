package model

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/crypt0rr/tailstate/internal/textutil"
)

// ActorUnknown is shown for a change whose configuration audit log lookup
// succeeded (or failed) without a matching entry.
const ActorUnknown = "actor unknown"

// Attribution field bounds. Only these identifying fields are ever stored;
// audit log old/new values, action details, and error text never are.
const (
	maxAttributionLogin  = 254
	maxAttributionName   = 128
	maxAttributionToken  = 48
	maxAttributionAction = 96
	maxAttributionTarget = 160
)

// AuditEntry is one Tailscale configuration audit log entry reduced to the
// fields TailState correlates. The provider's old and new values (which may
// contain policy text), the action details, and the error text are never
// decoded into it.
type AuditEntry struct {
	EventTime  time.Time
	Origin     string
	ActorType  string
	ActorLogin string
	ActorName  string
	TargetID   string
	TargetName string
	TargetType string
	Property   string
	Action     string
	// Failed marks an entry for a change that did not complete. Failed
	// attempts never attribute a change.
	Failed bool
}

// Attribution is the bounded, redacted record of who made a change: the
// actor's login and display name, the actor type, the origin (admin console,
// API, ...), the audit action, the target, and the audit timestamp.
type Attribution struct {
	ActorLogin string `json:"actor_login,omitempty"`
	ActorName  string `json:"actor_name,omitempty"`
	ActorType  string `json:"actor_type,omitempty"`
	Origin     string `json:"origin,omitempty"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	OccurredAt string `json:"occurred_at"`
}

// NewAttribution builds the bounded record for an audit entry.
func NewAttribution(entry AuditEntry) Attribution {
	action := make([]string, 0, 3)
	for _, part := range []string{entry.TargetType, entry.Action, entry.Property} {
		if part = strings.TrimSpace(part); part != "" {
			action = append(action, part)
		}
	}
	target := strings.TrimSpace(entry.TargetType)
	if id := strings.TrimSpace(entry.TargetID); id != "" {
		target += ":" + id
	}
	occurred := ""
	if !entry.EventTime.IsZero() {
		occurred = entry.EventTime.UTC().Format(time.RFC3339Nano)
	}
	return Attribution{
		ActorLogin: entry.ActorLogin,
		ActorName:  entry.ActorName,
		ActorType:  entry.ActorType,
		Origin:     entry.Origin,
		Action:     strings.Join(action, "."),
		Target:     target,
		OccurredAt: occurred,
	}.Bounded()
}

// Bounded returns the record with control characters removed and every field
// cut to its documented bound. It is applied when a record is built, stored,
// and read, so a hand-edited row cannot carry an unbounded value.
func (a Attribution) Bounded() Attribution {
	return Attribution{
		ActorLogin: boundText(a.ActorLogin, maxAttributionLogin),
		ActorName:  boundText(a.ActorName, maxAttributionName),
		ActorType:  boundToken(a.ActorType, maxAttributionToken),
		Origin:     boundToken(a.Origin, maxAttributionToken),
		Action:     boundToken(a.Action, maxAttributionAction),
		Target:     boundToken(a.Target, maxAttributionTarget),
		OccurredAt: boundToken(a.OccurredAt, maxAttributionToken),
	}
}

// IsZero reports whether the record carries no attribution.
func (a Attribution) IsZero() bool { return a == Attribution{} }

// Actor names who made the change: the login name, followed by the display
// name when it differs, or the actor type when neither is known.
func (a Attribution) Actor() string {
	login, name := strings.TrimSpace(a.ActorLogin), strings.TrimSpace(a.ActorName)
	switch {
	case login != "" && name != "" && !strings.EqualFold(login, name):
		return login + " (" + name + ")"
	case login != "":
		return login
	case name != "":
		return name
	}
	if label := actorTypeLabel(a.ActorType); label != "" {
		return label
	}
	return ActorUnknown
}

// Display is the one-line "Changed by" text, for example
// "alice@example.com (Alice) via admin console" or
// "k123 [OAuth client] via API".
func (a Attribution) Display() string {
	out := a.Actor()
	if label := actorTypeLabel(a.ActorType); label != "" && !strings.EqualFold(a.ActorType, "USER") && out != label {
		out += " [" + label + "]"
	}
	if origin := OriginLabel(a.Origin); origin != "" {
		out += " via " + origin
	}
	return out
}

// MarshalAttribution encodes a record for storage; a zero record is stored
// as the empty string.
func MarshalAttribution(a Attribution) string {
	a = a.Bounded()
	if a.IsZero() {
		return ""
	}
	raw, _ := json.Marshal(a)
	return string(raw)
}

// UnmarshalAttribution decodes a stored record. An empty or undecodable
// value has no attribution.
func UnmarshalAttribution(raw string) (Attribution, bool) {
	if strings.TrimSpace(raw) == "" {
		return Attribution{}, false
	}
	var a Attribution
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return Attribution{}, false
	}
	a = a.Bounded()
	return a, !a.IsZero()
}

var originLabels = map[string]string{
	"ADMIN_CONSOLE":     "admin console",
	"CONFIG_API":        "API",
	"CONTROL":           "control plane",
	"IDENTITY_PROVIDER": "identity provider",
	"NODE":              "node",
	"SUPPORT_REQUEST":   "support request",
}

// OriginLabel is the operator-facing name of an audit log origin.
func OriginLabel(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}
	if label, ok := originLabels[strings.ToUpper(origin)]; ok {
		return label
	}
	return strings.ToLower(strings.ReplaceAll(origin, "_", " "))
}

var actorTypeLabels = map[string]string{
	"USER":                "user",
	"NODE":                "node",
	"AUTOMATED_WORKER":    "automation",
	"OAUTH_CLIENT":        "OAuth client",
	"SCIM":                "SCIM",
	"PAM_SERVICE_ACCOUNT": "service account",
}

func actorTypeLabel(actorType string) string {
	actorType = strings.TrimSpace(actorType)
	if actorType == "" {
		return ""
	}
	if label, ok := actorTypeLabels[strings.ToUpper(actorType)]; ok {
		return label
	}
	return strings.ToLower(strings.ReplaceAll(actorType, "_", " "))
}

func boundText(value string, limit int) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, value)
	return textutil.Truncate(strings.Join(strings.Fields(cleaned), " "), limit)
}

// boundToken keeps identifier-shaped values: letters, digits, and the
// separators used by audit vocabularies, IDs, and timestamps.
func boundToken(value string, limit int) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case strings.ContainsRune("._:-+@", r):
			return r
		}
		return -1
	}, value)
	if len(cleaned) > limit {
		cleaned = cleaned[:limit]
	}
	return cleaned
}

// Audit target types and actions used for correlation (Tailscale's
// ConfigurationAuditLog vocabulary).
const (
	auditTargetNode    = "NODE"
	auditTargetUser    = "USER"
	auditTargetTailnet = "TAILNET"
	auditTargetKey     = "API_KEY"
	auditTargetInvite  = "INVITE"
	auditTargetWebhook = "WEBHOOK_ENDPOINT"
)

// idTargets maps collectors to the audit target types whose ID identifies
// one of their resources. Collectors not listed match a target of any type
// by ID.
var idTargets = map[string]map[string]bool{
	"devices":        {auditTargetNode: true},
	"device_details": {auditTargetNode: true},
	"users":          {auditTargetUser: true},
	"user_invites":   {auditTargetInvite: true, auditTargetUser: true},
	"keys":           {auditTargetKey: true},
	"webhooks":       {auditTargetWebhook: true},
}

// tailnetProperties maps tailnet-wide collectors to the TAILNET properties
// that change them.
var tailnetProperties = map[string]map[string]bool{
	"policy":        {"ACL": true},
	"dns":           {"DNS_CONFIG": true, "MAGIC_DNS": true},
	"contacts":      {"ACCOUNT_EMAIL": true, "SECURITY_EMAIL": true, "SUPPORT_EMAIL": true},
	"log_streaming": {"LOGSTREAM_ENDPOINT": true},
	"posture":       {"POSTURE_INTEGRATION": true},
	"settings": {
		"FILE_SHARING": true, "HTTPS": true, "MACHINE_APPROVAL_NEEDED": true, "MACHINE_AUTH_NEEDED": true,
		"USER_APPROVAL_REQUIRED": true, "MAX_KEY_DURATION": true, "NETWORK_FLOW_LOGGING": true,
		"LOG_EXIT_FLOWS": true, "COLLECT_SERVICES": true, "COLLECT_POSTURE_IDENTITY": true,
		"MULLVAD_VPN": true, "GEOSTEERING": true,
	},
}

// tailnetFieldProperties maps the changed fields of tailnet-wide collectors,
// by compact path (see CompactField) or, failing that, by compact top-level
// field, to the TAILNET properties an administrator changes them with, so an
// entry for one setting is never credited with a change to another. A field
// without an entry may be changed by any of the collector's properties.
var tailnetFieldProperties = map[string]map[string][]string{
	"settings": {
		"devicesapprovalon":           {"MACHINE_APPROVAL_NEEDED", "MACHINE_AUTH_NEEDED"},
		"usersapprovalon":             {"USER_APPROVAL_REQUIRED"},
		"deviceskeydurationdays":      {"MAX_KEY_DURATION"},
		"networkflowloggingon":        {"NETWORK_FLOW_LOGGING", "LOG_EXIT_FLOWS"},
		"postureidentitycollectionon": {"COLLECT_POSTURE_IDENTITY"},
		"httpsenabled":                {"HTTPS"},
	},
	"dns": {
		// magicDNS is the field of a change between the legacy and
		// configuration shapes (see ShapeTransition).
		"preferences.magicdns": {"MAGIC_DNS"},
		"magicdns":             {"MAGIC_DNS"},
		"nameservers":          {"DNS_CONFIG"},
		"searchpaths":          {"DNS_CONFIG"},
		"splitdns":             {"DNS_CONFIG"},
	},
}

// deviceFieldProperties maps changed device fields to the NODE properties an
// administrator changes them with. Fields reported by the node itself (client
// version, OS, addresses) have no entry: a concurrent administrative edit
// must not be credited with them.
var deviceFieldProperties = map[string][]string{
	"tags":              {"ACL_TAGS"},
	"enabledRoutes":     {"ALLOWED_IPS", "AUTO_APPROVED_ROUTES", "EXIT_NODE"},
	"advertisedRoutes":  {"ALLOWED_IPS", "AUTO_APPROVED_ROUTES", "EXIT_NODE"},
	"keyExpiryDisabled": {"KEY_EXPIRY"},
	"expires":           {"KEY_EXPIRY_TIME", "KEY_EXPIRY"},
	"name":              {"MACHINE_NAME"},
	"postureIdentity":   {"POSTURE_IDENTITY"},
	"tailnetLockKey":    {"TKA"},
	"tailnetLockError":  {"TKA"},
	"postureAttributes": {"ATTRIBUTES"},
}

var (
	createActions = map[string]bool{"CREATE": true, "APPROVE": true, "INVITE": true, "LOGIN": true, "RESTORE": true, "JOIN": true, "ACCEPT": true, "ENABLE": true}
	removeActions = map[string]bool{"DELETE": true, "REVOKE": true, "EXPIRED": true, "CANCEL": true, "LEAVE": true, "DISABLE": true, "SUSPEND": true}
)

// Attribute finds the audit entry that explains a change: the latest
// successful entry at or before notAfter whose target is the changed
// resource and whose action fits the kind of change. before and after are the
// normalized snapshots; their top-level id and nodeId identify a device by
// its audit target ID. It reports false when no entry matches, which is
// rendered as ActorUnknown.
func Attribute(change Change, before, after []byte, entries []AuditEntry, notAfter time.Time) (Attribution, bool) {
	ids := resourceIDs(change, before, after)
	candidates := make([]AuditEntry, 0, 4)
	for _, entry := range entries {
		if entry.Failed || (!notAfter.IsZero() && entry.EventTime.After(notAfter)) {
			continue
		}
		if !entryTargetsChange(change, ids, entry) || !entryFitsKind(change, entry) {
			continue
		}
		candidates = append(candidates, entry)
	}
	if len(candidates) == 0 {
		return Attribution{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := kindRank(change, candidates[i]), kindRank(change, candidates[j])
		if left != right {
			return left > right
		}
		return candidates[i].EventTime.After(candidates[j].EventTime)
	})
	return NewAttribution(candidates[0]), true
}

func resourceIDs(change Change, before, after []byte) map[string]bool {
	ids := map[string]bool{}
	if id := strings.TrimSpace(change.ResourceID); id != "" {
		ids[id] = true
	}
	for _, raw := range [][]byte{before, after} {
		var object map[string]any
		if len(raw) == 0 || json.Unmarshal(raw, &object) != nil {
			continue
		}
		for _, key := range []string{"id", "nodeId", "nodeID", "keyId", "userId"} {
			if value, ok := object[key].(string); ok && strings.TrimSpace(value) != "" {
				ids[strings.TrimSpace(value)] = true
			}
		}
	}
	return ids
}

func entryTargetsChange(change Change, ids map[string]bool, entry AuditEntry) bool {
	targetType := strings.ToUpper(strings.TrimSpace(entry.TargetType))
	if properties, tailnetWide := tailnetProperties[change.Collector]; tailnetWide {
		if targetType == auditTargetTailnet && properties[strings.ToUpper(strings.TrimSpace(entry.Property))] {
			return true
		}
		if change.Collector != "posture" {
			return false
		}
	}
	if types, typed := idTargets[change.Collector]; typed && !types[targetType] {
		return false
	}
	return entry.TargetID != "" && ids[strings.TrimSpace(entry.TargetID)]
}

func entryFitsKind(change Change, entry AuditEntry) bool {
	action := strings.ToUpper(strings.TrimSpace(entry.Action))
	if _, tailnetWide := tailnetProperties[change.Collector]; tailnetWide && strings.EqualFold(entry.TargetType, auditTargetTailnet) {
		return action != "LOGIN" && action != "LOGOUT" && tailnetEntryFitsFields(change, entry)
	}
	switch change.Kind {
	case "created":
		return createActions[action]
	case "removed":
		return removeActions[action]
	}
	if action == "LOGIN" || action == "LOGOUT" {
		return false
	}
	if change.Collector != "devices" && change.Collector != "device_details" {
		return true
	}
	if change.FieldsTruncated {
		return true
	}
	property := strings.ToUpper(strings.TrimSpace(entry.Property))
	for _, field := range change.Fields {
		top := field.Field
		if index := strings.IndexAny(top, ".["); index >= 0 {
			top = top[:index]
		}
		if top == "authorized" && action == "APPROVE" {
			return true
		}
		for _, candidate := range deviceFieldProperties[top] {
			if property == candidate {
				return true
			}
		}
	}
	return false
}

// tailnetEntryFitsFields reports whether a TAILNET entry's property can
// explain a changed field of a tailnet-wide collector (see
// tailnetFieldProperties). A change whose field list is unknown or truncated
// accepts any of the collector's properties.
func tailnetEntryFitsFields(change Change, entry AuditEntry) bool {
	fields, mapped := tailnetFieldProperties[change.Collector]
	if !mapped || change.Kind != "changed" || change.FieldsTruncated || len(change.Fields) == 0 {
		return true
	}
	property := strings.ToUpper(strings.TrimSpace(entry.Property))
	for _, field := range change.Fields {
		candidates, known := fields[CompactField(field.Field)]
		if !known {
			candidates, known = fields[CompactField(FieldRoot(field.Field))]
		}
		if !known {
			return true
		}
		for _, candidate := range candidates {
			if property == candidate {
				return true
			}
		}
	}
	return false
}

// kindRank prefers the action that best explains the change kind: a CREATE
// for a created resource and a DELETE for a removed one.
func kindRank(change Change, entry AuditEntry) int {
	action := strings.ToUpper(strings.TrimSpace(entry.Action))
	switch {
	case change.Kind == "created" && action == "CREATE", change.Kind == "removed" && action == "DELETE":
		return 1
	}
	return 0
}
