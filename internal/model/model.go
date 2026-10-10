package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/crypt0rr/tailstate/internal/textutil"
)

type Resource struct {
	ID        string
	Type      string
	Name      string
	Collector string
	Data      any
}

type Collected struct {
	Collector   string
	Resources   []Resource
	Unsupported bool
	// UnsupportedReason is a bounded label (never provider text) recorded as
	// the collector's status when Unsupported is set.
	UnsupportedReason string
	Partial           bool
	PartialError      string
	PartialErrorCount int
	Error             error
	ObservedAt        time.Time
}

type FieldChange struct {
	Field      string `json:"field"`
	Old        any    `json:"old,omitempty"`
	New        any    `json:"new,omitempty"`
	OldPresent bool   `json:"old_present,omitempty"`
	NewPresent bool   `json:"new_present,omitempty"`
}

type Change struct {
	Kind            string        `json:"kind"`
	Collector       string        `json:"collector"`
	ResourceID      string        `json:"resource_id"`
	Type            string        `json:"resource_type"`
	Name            string        `json:"name"`
	Fields          []FieldChange `json:"fields,omitempty"`
	FieldsTruncated bool          `json:"fields_truncated,omitempty"`
	TotalFields     int           `json:"total_fields,omitempty"`
	// Attribution names who made the change when the configuration audit
	// log explained it. It is set only on changes handed to notifications.
	Attribution *Attribution `json:"attribution,omitempty"`
	// Invites describes the share invites of a changed device_details
	// resource by invite ID (see DeviceInvites), so severity and
	// notifications can name the recipient of an invite whose recorded
	// fields do not. It is never persisted or exported.
	Invites map[string]DeviceInvite `json:"-"`
	// Created is the severity-relevant initial state of a created users,
	// user_invites, or devices resource (see CreatedStateOf), so a
	// privileged creation is classified like the equivalent later edit. It
	// is never persisted or exported.
	Created *CreatedState `json:"-"`
}

var ignored = map[string]struct{}{
	"lastseen": {}, "connectedtocontrol": {}, "clientconnectivity": {}, "endpoints": {}, "lastupdated": {},
	"createdat": {}, "updatedat": {}, "timestamp": {}, "requestedat": {},
	"profilepicurl": {},
}

// redactedFields are schema-level secret identities. These are deliberately
// exact matches: arbitrary tenant-controlled dictionary keys may contain words
// such as "secret" or "token" and must remain visible to drift detection.
var redactedFields = map[string]struct{}{
	"accesstoken":   {},
	"clientsecret":  {},
	"secret":        {},
	"signingsecret": {},
	"token":         {},
	"tokenvalue":    {},
	"password":      {},
	"webhooksecret": {},
	// Log-streaming destination credentials. The API documents
	// s3SecretAccessKey as write-only but does not mark gcsCredentials that
	// way; neither may ever be stored or diffed in clear text.
	"gcscredentials":    {},
	"s3secretaccesskey": {},
}

var collectorFields = map[string]map[string]struct{}{
	"devices": fieldSet(
		"addresses", "id", "nodeid", "user", "name", "hostname", "clientversion", "updateavailable", "os",
		"created", "keyexpirydisabled", "expires", "authorized", "isexternal", "blocksincomingconnections",
		"enabledroutes", "advertisedroutes", "tags", "tailnetlockerror", "tailnetlockkey", "sshenabled",
		"postureidentity", "isephemeral", "distro",
	),
	"users": fieldSet(
		"id", "displayname", "loginname", "profilepicurl", "tailnetid", "created", "type", "role", "status",
	),
	// Routes are reported by the devices collector (fields=all). Dropping the
	// legacy "routes" key here also re-normalizes snapshots stored by older
	// releases, so upgrading does not report the removal as drift.
	"device_details": fieldSet("postureattributes", "deviceinvites"),
	"posture":        fieldSet("provider", "cloudid", "clientid", "tenantid", "id", "configupdated", "status"),
	"log_streaming":  fieldSet("configuration", "network"),
	// Tailscale Services (VIPServiceInfo). Addresses, ports, and tags are the
	// exposure surface; the display name and comment identify the service.
	"services": fieldSet("name", "displayname", "addrs", "comment", "ports", "tags"),
	// OAuth apps. clientSecret is only returned at creation and is excluded
	// along with the volatile created/updated timestamps.
	"oauth_apps": fieldSet("id", "name", "description", "redirecturis", "scopes", "allowednodeattributes"),
}

func fieldSet(fields ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		out[field] = struct{}{}
	}
	return out
}

func Normalize(value any) any {
	return NormalizeFor("", value)
}

func NormalizeFor(collector string, value any) any {
	return normalizeFor(collector, value, true, false, "")
}

func normalizeFor(collector string, value any, root, tenantKeys bool, path string) any {
	switch v := value.(type) {
	case map[string]any:
		openKeys := tenantKeys || (root && collector == "policy")
		out := make(map[string]any, len(v))
		for key, child := range v {
			compact := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
			if root && !openKeys && !collectorFieldAllowed(collector, compact) {
				continue
			}
			if collector == "device_details" && compact == "detail" {
				continue
			}
			if collector == "device_details" && devicePostureDuplicate(path, compact) {
				continue
			}
			if collector == "device_details" && postureExpiries(path, compact) {
				// The attributes endpoint returns per-attribute expiry
				// timestamps next to the values. Integrations refresh them
				// on every sync, so they would report drift on each poll.
				continue
			}
			if collector == "log_streaming" && root && legacyUnsupportedLogStream(child) {
				// Releases before v0.11.16 stored a 404 ("not configured")
				// as {"unsupported": true}; read it as the current
				// explicit state so upgrading does not report drift.
				out[key] = map[string]any{"configured": false}
				continue
			}
			if !tenantKeys {
				if _, redact := redactedFields[compact]; redact {
					out[key] = redactedValue(child)
					continue
				}
				if _, drop := ignored[compact]; drop || ignoredForCollector(collector, compact) {
					continue
				}
				if collector == "users" && compact == "status" {
					out[key] = normalizeUserStatus(child)
					continue
				}
				if (collector == "posture" || collector == "log_streaming") && compact == "status" {
					out[key] = normalizeHealthStatus(child)
					continue
				}
				if strings.Contains(compact, "url") || compact == "endpoint" {
					if fingerprint, ok := redactedFingerprint(child); ok {
						out[key] = map[string]any{"redacted_sha256": fingerprint}
						continue
					}
					raw, _ := json.Marshal(child)
					sum := sha256.Sum256(raw)
					out[key] = map[string]any{"redacted_sha256": hex.EncodeToString(sum[:])}
					continue
				}
			}
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			out[key] = normalizeFor(collector, child, false, tenantKeySection(collector, compact), childPath)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = normalizeFor(collector, v[i], false, false, path)
		}
		if !orderedArray(collector, path) {
			sort.SliceStable(out, func(i, j int) bool {
				a, _ := json.Marshal(out[i])
				b, _ := json.Marshal(out[j])
				return string(a) < string(b)
			})
		}
		return out
	default:
		return value
	}
}

// devicePostureDuplicates are built-in posture attributes that repeat the
// devices collector's clientVersion and os fields. Reporting them again under
// device_details would turn one client upgrade into two notifications.
var devicePostureDuplicates = map[string]struct{}{
	"node:tsversion": {},
	"node:os":        {},
	"node:osversion": {},
}

func devicePostureDuplicate(path, key string) bool {
	if _, duplicate := devicePostureDuplicates[key]; !duplicate {
		return false
	}
	section, _, _ := strings.Cut(path, ".")
	return strings.EqualFold(section, "postureAttributes")
}

// postureExpiries reports the expiries map of a device's posture attributes
// response, which holds {"attributes": ..., "expiries": ...}.
func postureExpiries(path, key string) bool {
	return key == "expiries" && strings.EqualFold(path, "postureAttributes")
}

func tenantKeySection(collector, key string) bool {
	switch collector {
	case "policy":
		return key == "groups" || key == "tagowners" || key == "hosts"
	case "dns":
		return key == "splitdns" || key == "nameservers" || key == "searchpaths"
	default:
		return false
	}
}

func orderedArray(collector, path string) bool {
	if collector != "dns" {
		return false
	}
	compactPath := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(path, "_", ""), "-", ""))
	for _, segment := range strings.Split(compactPath, ".") {
		if segment == "nameservers" || segment == "searchpaths" {
			return true
		}
	}
	return false
}

func redactedFingerprint(value any) (string, bool) {
	fingerprint, ok := value.(map[string]any)
	if !ok || len(fingerprint) != 1 {
		return "", false
	}
	encoded, ok := fingerprint["redacted_sha256"].(string)
	if !ok || len(encoded) != sha256.Size*2 {
		return "", false
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return "", false
	}
	return strings.ToLower(encoded), true
}

func redactedValue(value any) map[string]any {
	if fingerprint, ok := redactedFingerprint(value); ok {
		return map[string]any{"redacted_sha256": fingerprint}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		raw = []byte("<unserializable>")
	}
	sum := sha256.Sum256(raw)
	return map[string]any{"redacted_sha256": hex.EncodeToString(sum[:])}
}

func collectorFieldAllowed(collector, field string) bool {
	fields, restricted := collectorFields[collector]
	if !restricted {
		return true
	}
	_, allowed := fields[field]
	return allowed
}

func ignoredForCollector(collector, key string) bool {
	switch collector {
	case "devices":
		return key == "multipleconnections" || key == "machinekey" || key == "nodekey"
	case "users":
		return key == "currentlyconnected"
	default:
		return false
	}
}

func normalizeUserStatus(value any) any {
	status, ok := value.(string)
	if ok && (status == "active" || status == "idle") {
		return "enabled"
	}
	return value
}

func legacyUnsupportedLogStream(value any) bool {
	stream, ok := value.(map[string]any)
	if !ok || len(stream) != 1 {
		return false
	}
	unsupported, ok := stream["unsupported"].(bool)
	return ok && unsupported
}

// HealthStatusUnavailable records that a collector could read a resource's
// configuration but not its health status (for example a log stream whose
// logging backend is unreachable).
const HealthStatusUnavailable = "unavailable"

func normalizeHealthStatus(value any) any {
	status, ok := value.(map[string]any)
	if !ok {
		return value
	}
	if state, ok := status["state"].(string); ok && state == HealthStatusUnavailable && len(status) == 1 {
		return map[string]any{"state": HealthStatusUnavailable}
	}
	errorMessage, _ := status["error"].(string)
	if errorMessage == "" {
		errorMessage, _ = status["lastError"].(string)
	}
	state := "healthy"
	if strings.TrimSpace(errorMessage) != "" {
		state = "error"
	}
	return map[string]any{"state": state}
}

func Canonical(value any) ([]byte, string, error) {
	return CanonicalFor("", value)
}

func CanonicalFor(collector string, value any) ([]byte, string, error) {
	return canonical(normalizeFor(collector, value, true, false, ""))
}

// CanonicalForSection canonicalizes a collector section while retaining the
// section's schema identity. This matters for open-ended sections such as
// policy groups and DNS split-dns maps: their keys are tenant-controlled
// names, not secret field names, even when a key happens to be "secret" or
// "token".
func CanonicalForSection(collector, section string, value any) ([]byte, string, error) {
	compactSection := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(section, "_", ""), "-", ""))
	return canonical(normalizeFor(collector, value, true, tenantKeySection(collector, compactSection), section))
}

func canonical(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, "", err
	}
	raw, err = json.Marshal(normalized)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func Diff(oldRaw, newRaw []byte) []FieldChange {
	return DiffDetailed(oldRaw, newRaw).Fields
}

type DiffResult struct {
	Fields          []FieldChange
	FieldsTruncated bool
	TotalFields     int
}

// DiffDetailed returns the field changes between two canonical JSON values.
// Objects are compared field by field. Arrays of objects that carry a
// usable identity (see arrayIdentity) are compared element by element: a
// changed element reports its fields at paths such as
// "deviceInvites[5861427050514914].tailnetId", and an added or removed
// element is one change at "deviceInvites[5861427050514914]". Any other
// array is compared as one value.
func DiffDetailed(oldRaw, newRaw []byte) DiffResult {
	return DiffDetailedFor("", oldRaw, newRaw)
}

// DiffDetailedFor is DiffDetailed for one collector's canonical values.
// Arrays whose order the collector keeps (DNS resolvers and search paths)
// are always compared as one value, so a reorder is still reported.
func DiffDetailedFor(collector string, oldRaw, newRaw []byte) DiffResult {
	d := differ{collector: collector}
	var oldValue, newValue any
	if json.Unmarshal(oldRaw, &oldValue) != nil || json.Unmarshal(newRaw, &newValue) != nil {
		d.result.Fields = []FieldChange{valueChange("value", string(oldRaw), true, string(newRaw), true)}
		d.result.TotalFields = 1
		return d.result
	}
	d.diff("", oldValue, true, newValue, true)
	return d.result
}

const maxDiffFields = 24

// differ accumulates the field changes of one comparison.
type differ struct {
	collector string
	result    DiffResult
}

func (d *differ) diff(path string, oldValue any, oldPresent bool, newValue any, newPresent bool) {
	result := &d.result
	oldMap, oldOK := oldValue.(map[string]any)
	newMap, newOK := newValue.(map[string]any)
	if oldPresent && newPresent && oldOK && newOK {
		keys := make(map[string]struct{}, len(oldMap)+len(newMap))
		for k := range oldMap {
			keys[k] = struct{}{}
		}
		for k := range newMap {
			keys[k] = struct{}{}
		}
		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			child := key
			if path != "" {
				child = path + "." + key
			}
			oldChild, oldExists := oldMap[key]
			newChild, newExists := newMap[key]
			d.diff(child, oldChild, oldExists, newChild, newExists)
		}
		return
	}
	oldList, oldIsList := oldValue.([]any)
	newList, newIsList := newValue.([]any)
	if !orderedArray(d.collector, path) {
		// A non-empty identified list that appears from null or absence (or
		// disappears into it) is compared with an empty list, so each of
		// its elements is one added or removed element rather than one
		// opaque, possibly truncated, list value.
		switch {
		case path == "" || (oldIsList && newIsList):
		case oldValue == nil && newIsList && len(newList) > 0:
			oldList, oldIsList = []any{}, true
		case newValue == nil && oldIsList && len(oldList) > 0:
			newList, newIsList = []any{}, true
		}
		if oldIsList && newIsList {
			if key, ok := arrayIdentity(oldList, newList); ok {
				d.diffKeyed(path, key, oldList, newList)
				return
			}
		}
	}
	oldJSON := diffJSON(oldValue, oldPresent)
	newJSON := diffJSON(newValue, newPresent)
	if string(oldJSON) == string(newJSON) {
		return
	}
	if path == "" {
		path = "value"
	}
	result.TotalFields++
	if len(result.Fields) < maxDiffFields {
		result.Fields = append(result.Fields, valueChange(path, oldValue, oldPresent, newValue, newPresent))
	} else {
		result.FieldsTruncated = true
	}
}

func diffJSON(value any, present bool) []byte {
	if !present {
		return []byte("<missing>")
	}
	raw, _ := json.Marshal(value)
	return raw
}

func valueChange(path string, oldValue any, oldPresent bool, newValue any, newPresent bool) FieldChange {
	change := FieldChange{Field: path, OldPresent: oldPresent, NewPresent: newPresent}
	if oldPresent {
		change.Old = compactPreservingNull(oldValue)
	}
	if newPresent {
		change.New = compactPreservingNull(newValue)
	}
	return change
}

func compactPreservingNull(value any) any {
	if value == nil {
		return json.RawMessage("null")
	}
	return compact(value)
}

func compact(value any) any {
	raw, _ := json.Marshal(value)
	if len(raw) <= 240 {
		return value
	}
	return textutil.Truncate(string(raw), 240)
}

// identityKeys are the element fields that identify an object in an array,
// in order of preference: Tailscale's resource "id" (device invites), a
// device's "nodeId", and a resolver's "address".
var identityKeys = []string{"id", "nodeId", "address"}

// maxIdentityBytes bounds an element identity used in a field path.
const maxIdentityBytes = 128

// arrayIdentity returns the identity key shared by every element of both
// arrays: each element must be an object whose value for the key is a
// usable scalar, unique within its array. Arrays of scalars, mixed arrays,
// and arrays with missing or duplicate identities have none and are compared
// as one value.
func arrayIdentity(oldList, newList []any) (string, bool) {
	for _, key := range identityKeys {
		if identifiedBy(key, oldList) && identifiedBy(key, newList) {
			return key, true
		}
	}
	return "", false
}

func identifiedBy(key string, list []any) bool {
	seen := make(map[string]struct{}, len(list))
	for _, element := range list {
		id, ok := elementIdentity(key, element)
		if !ok {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

// elementIdentity returns the path text of an element's identity: a
// non-empty string or a number, bounded and without brackets or control
// characters, so the path "list[<id>].field" stays unambiguous.
func elementIdentity(key string, element any) (string, bool) {
	object, ok := element.(map[string]any)
	if !ok {
		return "", false
	}
	var id string
	switch value := object[key].(type) {
	case string:
		id = value
	case float64:
		id = strconv.FormatFloat(value, 'f', -1, 64)
	default:
		return "", false
	}
	if id == "" || len(id) > maxIdentityBytes || strings.ContainsAny(id, "[]") || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return "", false
	}
	return id, true
}

// diffKeyed compares two arrays element by element, matching elements by
// their identity. Identities are visited in sorted order, so the field
// order does not depend on the arrays' order.
func (d *differ) diffKeyed(path, key string, oldList, newList []any) {
	oldByID := make(map[string]any, len(oldList))
	newByID := make(map[string]any, len(newList))
	ids := make([]string, 0, len(oldList)+len(newList))
	for _, element := range oldList {
		id, _ := elementIdentity(key, element)
		oldByID[id] = element
		ids = append(ids, id)
	}
	for _, element := range newList {
		id, _ := elementIdentity(key, element)
		newByID[id] = element
		if _, matched := oldByID[id]; !matched {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		oldElement, oldExists := oldByID[id]
		newElement, newExists := newByID[id]
		d.diff(ElementPath(path, id), oldElement, oldExists, newElement, newExists)
	}
}

// ElementPath is the field path of one identified array element, for
// example "deviceInvites[5861427050514914]".
func ElementPath(path, id string) string {
	return path + "[" + id + "]"
}

// ElementPathParts splits an element path such as
// "deviceInvites[5861427050514914]" into the list path and the identity. It
// reports false for any other path, including a field inside an element.
func ElementPathParts(path string) (list, id string, ok bool) {
	if !strings.HasSuffix(path, "]") {
		return "", "", false
	}
	open := strings.LastIndexByte(path, '[')
	if open <= 0 || open == len(path)-2 {
		return "", "", false
	}
	return path[:open], path[open+1 : len(path)-1], true
}

// GenericPath replaces the element identities of a field path with "[]":
// "deviceInvites[5861427050514914].tailnetId" becomes
// "deviceInvites[].tailnetId". Paths of the same field in different elements
// share their generic path.
func GenericPath(path string) string {
	if !strings.Contains(path, "[") {
		return path
	}
	var b strings.Builder
	inside := false
	for _, r := range path {
		switch {
		case r == '[':
			inside = true
			b.WriteRune(r)
		case r == ']':
			inside = false
			b.WriteRune(r)
		case !inside:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// FieldRoot returns the first segment of a field path: "deviceInvites" for
// "deviceInvites[5861427050514914].tailnetId" and "tags" for "tags".
func FieldRoot(path string) string {
	if index := strings.IndexAny(path, ".["); index >= 0 {
		return path[:index]
	}
	return path
}
