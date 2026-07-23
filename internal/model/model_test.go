package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalIgnoresVolatileAndOrder(t *testing.T) {
	a := map[string]any{"addresses": []any{"fd7a::1", "100.64.0.1"}, "lastSeen": "now", "connectedToControl": false, "clientConnectivity": map[string]any{"endpoints": []any{"1.2.3.4:5"}}}
	b := map[string]any{"addresses": []any{"100.64.0.1", "fd7a::1"}, "lastSeen": "later", "connectedToControl": true}
	_, ha, err := Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	_, hb, _ := Canonical(b)
	if ha != hb {
		t.Fatalf("volatile/order differences changed hash: %s != %s", ha, hb)
	}
}
func TestTailnetAddressChangeDetected(t *testing.T) {
	a, _, _ := Canonical(map[string]any{"addresses": []any{"100.64.0.1"}})
	b, _, _ := Canonical(map[string]any{"addresses": []any{"100.64.0.2"}})
	changes := Diff(a, b)
	if len(changes) != 1 || changes[0].Field != "addresses" {
		t.Fatalf("unexpected changes: %#v", changes)
	}
}
func TestSensitiveURLIsHashed(t *testing.T) {
	raw, _, _ := Canonical(map[string]any{"url": "https://mattermost.example/hooks/super-secret"})
	if strings.Contains(string(raw), "super-secret") {
		t.Fatal("URL leaked into canonical snapshot")
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["url"] == nil {
		t.Fatal("URL fingerprint missing")
	}

	_, firstHash, err := Canonical(map[string]any{"url": "https://mattermost.example/hooks/first"})
	if err != nil {
		t.Fatal(err)
	}
	_, secondHash, err := Canonical(map[string]any{"url": "https://mattermost.example/hooks/second"})
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == secondHash {
		t.Fatal("configuration URL changes must remain detectable")
	}
}

func TestCanonicalIgnoresProfilePictureURL(t *testing.T) {
	before := map[string]any{
		"deviceInvites": []any{
			map[string]any{
				"accepted": true,
				"acceptedBy": map[string]any{
					"id":            float64(123),
					"loginName":     "user@example.com",
					"profilePicUrl": "https://avatars.example.com/old",
				},
			},
		},
	}
	after := map[string]any{
		"deviceInvites": []any{
			map[string]any{
				"accepted": true,
				"acceptedBy": map[string]any{
					"id":            float64(123),
					"loginName":     "user@example.com",
					"profilePicUrl": "https://avatars.example.com/new",
				},
			},
		},
	}

	beforeRaw, beforeHash, err := Canonical(before)
	if err != nil {
		t.Fatal(err)
	}
	afterRaw, afterHash, err := Canonical(after)
	if err != nil {
		t.Fatal(err)
	}
	if beforeHash != afterHash {
		t.Fatalf("profile picture URL changed canonical hash:\n%s\n%s", beforeRaw, afterRaw)
	}
	if strings.Contains(string(beforeRaw), "profilePicUrl") {
		t.Fatalf("profile picture URL retained in canonical snapshot: %s", beforeRaw)
	}
}

func TestDeviceRuntimeFieldsIgnoredButUpdateAvailabilityAlerted(t *testing.T) {
	before := map[string]any{
		"hostname":            "server",
		"connectedToControl":  false,
		"multipleConnections": false,
		"machineKey":          "machine:old",
		"nodeKey":             "node:old",
		"futureAPIMetadata":   "old",
		"updateAvailable":     false,
	}
	runtimeOnly := map[string]any{
		"hostname":            "server",
		"connectedToControl":  true,
		"multipleConnections": true,
		"machineKey":          "machine:new",
		"nodeKey":             "node:new",
		"futureAPIMetadata":   "new",
		"updateAvailable":     false,
	}
	updateAvailable := map[string]any{
		"hostname":            "server",
		"connectedToControl":  true,
		"multipleConnections": true,
		"machineKey":          "machine:new",
		"nodeKey":             "node:new",
		"futureAPIMetadata":   "newer",
		"updateAvailable":     true,
	}

	_, beforeHash, err := CanonicalFor("devices", before)
	if err != nil {
		t.Fatal(err)
	}
	_, runtimeHash, err := CanonicalFor("devices", runtimeOnly)
	if err != nil {
		t.Fatal(err)
	}
	if beforeHash != runtimeHash {
		t.Fatal("runtime-only device fields changed the canonical hash")
	}
	beforeRaw, _, _ := CanonicalFor("devices", runtimeOnly)
	updateRaw, updateHash, err := CanonicalFor("devices", updateAvailable)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeHash == updateHash {
		t.Fatal("updateAvailable change was ignored")
	}
	changes := Diff(beforeRaw, updateRaw)
	if len(changes) != 1 || changes[0].Field != "updateAvailable" {
		t.Fatalf("unexpected client update changes: %#v", changes)
	}
}

func TestUserConnectivityStateIsStable(t *testing.T) {
	active := map[string]any{"loginName": "user@example.com", "status": "active", "currentlyConnected": true, "lastSeen": "now"}
	idle := map[string]any{"loginName": "user@example.com", "status": "idle", "currentlyConnected": false, "lastSeen": "later"}
	suspended := map[string]any{"loginName": "user@example.com", "status": "suspended", "currentlyConnected": false}

	_, activeHash, err := CanonicalFor("users", active)
	if err != nil {
		t.Fatal(err)
	}
	_, idleHash, err := CanonicalFor("users", idle)
	if err != nil {
		t.Fatal(err)
	}
	if activeHash != idleHash {
		t.Fatal("active/idle connectivity state changed the user hash")
	}
	_, suspendedHash, err := CanonicalFor("users", suspended)
	if err != nil {
		t.Fatal(err)
	}
	if idleHash == suspendedHash {
		t.Fatal("suspended user status was ignored")
	}
}

func TestOperationalStatusUsesStableHealthState(t *testing.T) {
	before := map[string]any{
		"configuration": map[string]any{
			"status": map[string]any{
				"lastActivity":    "2026-07-23T20:00:00Z",
				"numBytesSent":    float64(100),
				"numEntriesSent":  float64(10),
				"rateEntriesSent": 1.5,
				"lastError":       "",
			},
		},
	}
	after := map[string]any{
		"configuration": map[string]any{
			"status": map[string]any{
				"lastActivity":    "2026-07-23T20:05:00Z",
				"numBytesSent":    float64(200),
				"numEntriesSent":  float64(20),
				"rateEntriesSent": 2.5,
				"lastError":       "",
			},
		},
	}
	failed := map[string]any{
		"configuration": map[string]any{
			"status": map[string]any{
				"lastActivity": "2026-07-23T20:10:00Z",
				"lastError":    "temporary provider error with changing request ID",
			},
		},
	}

	_, beforeHash, err := CanonicalFor("log_streaming", before)
	if err != nil {
		t.Fatal(err)
	}
	_, afterHash, err := CanonicalFor("log_streaming", after)
	if err != nil {
		t.Fatal(err)
	}
	if beforeHash != afterHash {
		t.Fatal("operational counters changed the log-streaming hash")
	}
	_, failedHash, err := CanonicalFor("log_streaming", failed)
	if err != nil {
		t.Fatal(err)
	}
	if afterHash == failedHash {
		t.Fatal("log-streaming health transition was ignored")
	}

	postureA := map[string]any{"status": map[string]any{"lastSync": "first", "matchedCount": float64(1), "error": ""}}
	postureB := map[string]any{"status": map[string]any{"lastSync": "second", "matchedCount": float64(2), "error": ""}}
	_, postureAHash, _ := CanonicalFor("posture", postureA)
	_, postureBHash, _ := CanonicalFor("posture", postureB)
	if postureAHash != postureBHash {
		t.Fatal("posture synchronization telemetry changed the hash")
	}
}

func TestDeviceDetailsExcludeDuplicatedCoreDevice(t *testing.T) {
	value := map[string]any{
		"detail":  map[string]any{"hostname": "server", "addresses": []any{"100.64.0.1"}},
		"routes":  map[string]any{"enabledRoutes": []any{"10.0.0.0/24"}},
		"invites": []any{},
	}
	raw, _, err := CanonicalFor("device_details", value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "detail") || strings.Contains(string(raw), "hostname") {
		t.Fatalf("duplicated core device retained: %s", raw)
	}
	if !strings.Contains(string(raw), "enabledRoutes") {
		t.Fatalf("secondary device details were removed: %s", raw)
	}
}
