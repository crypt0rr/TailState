package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
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
	Error       error
	ObservedAt  time.Time
}

type FieldChange struct {
	Field string `json:"field"`
	Old   any    `json:"old,omitempty"`
	New   any    `json:"new,omitempty"`
}

type Change struct {
	Kind       string        `json:"kind"`
	Collector  string        `json:"collector"`
	ResourceID string        `json:"resource_id"`
	Type       string        `json:"resource_type"`
	Name       string        `json:"name"`
	Fields     []FieldChange `json:"fields,omitempty"`
}

var ignored = map[string]struct{}{
	"lastseen": {}, "connectedtocontrol": {}, "clientconnectivity": {}, "endpoints": {}, "lastupdated": {},
	"createdat": {}, "updatedat": {}, "timestamp": {}, "requestedat": {},
	"accesstoken": {}, "clientsecret": {}, "secret": {}, "token": {}, "password": {},
	"profilepicurl": {},
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
	"device_details": fieldSet("routes", "postureattributes", "deviceinvites"),
	"posture":        fieldSet("provider", "cloudid", "clientid", "tenantid", "id", "configupdated", "status"),
	"log_streaming":  fieldSet("configuration", "network"),
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
	return normalizeFor(collector, value, true)
}

func normalizeFor(collector string, value any, root bool) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			compact := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
			if root && !collectorFieldAllowed(collector, compact) {
				continue
			}
			if collector == "device_details" && compact == "detail" {
				continue
			}
			if _, drop := ignored[compact]; drop || ignoredForCollector(collector, compact) || strings.Contains(compact, "secret") || strings.Contains(compact, "tokenvalue") {
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
				raw, _ := json.Marshal(child)
				sum := sha256.Sum256(raw)
				out[key] = map[string]any{"redacted_sha256": hex.EncodeToString(sum[:])}
				continue
			}
			out[key] = normalizeFor(collector, child, false)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = normalizeFor(collector, v[i], false)
		}
		sort.SliceStable(out, func(i, j int) bool {
			a, _ := json.Marshal(out[i])
			b, _ := json.Marshal(out[j])
			return string(a) < string(b)
		})
		return out
	default:
		return value
	}
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

func normalizeHealthStatus(value any) any {
	status, ok := value.(map[string]any)
	if !ok {
		return value
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
	raw, err := json.Marshal(NormalizeFor(collector, value))
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
	var oldValue, newValue any
	if json.Unmarshal(oldRaw, &oldValue) != nil || json.Unmarshal(newRaw, &newValue) != nil {
		return []FieldChange{{Field: "value", Old: string(oldRaw), New: string(newRaw)}}
	}
	var changes []FieldChange
	diffValue("", oldValue, newValue, &changes)
	if len(changes) > 24 {
		changes = changes[:24]
	}
	return changes
}

func diffValue(path string, oldValue, newValue any, changes *[]FieldChange) {
	if len(*changes) >= 25 {
		return
	}
	oldMap, oldOK := oldValue.(map[string]any)
	newMap, newOK := newValue.(map[string]any)
	if oldOK && newOK {
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
			diffValue(child, oldMap[key], newMap[key], changes)
		}
		return
	}
	oldJSON, _ := json.Marshal(oldValue)
	newJSON, _ := json.Marshal(newValue)
	if string(oldJSON) != string(newJSON) {
		if path == "" {
			path = "value"
		}
		*changes = append(*changes, FieldChange{Field: path, Old: compact(oldValue), New: compact(newValue)})
	}
}

func compact(value any) any {
	raw, _ := json.Marshal(value)
	if len(raw) <= 240 {
		return value
	}
	return fmt.Sprintf("%s…", string(raw[:239]))
}
