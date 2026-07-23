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
