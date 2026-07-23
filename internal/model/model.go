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

func Normalize(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			compact := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
			if _, drop := ignored[compact]; drop || strings.Contains(compact, "secret") || strings.Contains(compact, "tokenvalue") {
				continue
			}
			if strings.Contains(compact, "url") || compact == "endpoint" {
				raw, _ := json.Marshal(child)
				sum := sha256.Sum256(raw)
				out[key] = map[string]any{"redacted_sha256": hex.EncodeToString(sum[:])}
				continue
			}
			out[key] = Normalize(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = Normalize(v[i])
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

func Canonical(value any) ([]byte, string, error) {
	raw, err := json.Marshal(Normalize(value))
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
