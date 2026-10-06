package notify

import (
	"fmt"

	"github.com/crypt0rr/tailstate/internal/model"
)

// sampleContext and sampleDigest reproduce the notification assessment's
// sample batch: 19 changes with attribution and mutes, a 12-device client
// rollout, and policy, secret, tag, role, key, device, and DNS changes.
var sampleContext = Context{Label: "prod", Tailnet: "example.com", PublicURL: "https://tailstate.example"}

func sampleDigest() Message {
	alice := &model.Attribution{ActorLogin: "alice@example.com", ActorType: "USER", Action: "update", Target: "policy"}
	ci := &model.Attribution{ActorLogin: "ci-bot", ActorType: "API_KEY", Action: "update", Target: "devices"}
	changes := []model.Change{
		{Kind: "created", Collector: "devices", ResourceID: "n1", Name: "laptop-new.tail1234.ts.net"},
		{Kind: "changed", Collector: "dns", ResourceID: "dns", Name: "DNS configuration", Fields: []model.FieldChange{
			{Field: "searchPaths", Old: []any{"corp.example.com", "example.com"}, New: []any{"example.com", "corp.example.com"}, OldPresent: true, NewPresent: true},
		}},
		{Kind: "changed", Collector: "policy", ResourceID: "policy", Name: "Tailnet policy", Attribution: alice, Fields: []model.FieldChange{
			{Field: "acls", Old: "3f9a1c0e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7", New: "c41b7e2a9d0f3c6b8e1a4d7f0c3b6e9a2d5f8c1b4e7a0d3f6c9b2e5a8d1f4c7b", OldPresent: true, NewPresent: true},
			{Field: "ssh", New: "9e8d7c6b5a49382716f5e4d3c2b1a0f9e8d7c6b5a49382716f5e4d3c2b1a0f9", NewPresent: true},
		}},
		{Kind: "changed", Collector: "users", ResourceID: "u2", Name: "bob@example.com", Attribution: alice, Fields: []model.FieldChange{
			{Field: "role", Old: "member", New: "admin", OldPresent: true, NewPresent: true},
		}},
		{Kind: "changed", Collector: "devices", ResourceID: "w2", Name: "web-02.tail1234.ts.net", Attribution: ci, Fields: []model.FieldChange{
			{Field: "tags", Old: []any{"tag:prod"}, New: []any{"tag:db", "tag:prod"}, OldPresent: true, NewPresent: true},
		}},
		{Kind: "changed", Collector: "webhooks", ResourceID: "wh1", Name: "SIEM webhook", Fields: []model.FieldChange{
			{Field: "endpointUrl", Old: map[string]any{"redacted_sha256": "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899"}, New: map[string]any{"redacted_sha256": "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"}, OldPresent: true, NewPresent: true},
		}},
		{Kind: "created", Collector: "keys", ResourceID: "k9", Name: "kAbc123CNTRL", Attribution: alice},
	}
	for i := 1; i <= 12; i++ {
		changes = append(changes, model.Change{Kind: "changed", Collector: "devices", ResourceID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("node-%02d.tail1234.ts.net", i), Fields: []model.FieldChange{
			{Field: "clientVersion", Old: "1.80.2", New: "1.82.1", OldPresent: true, NewPresent: true},
		}})
	}
	return sampleContext.Digest(DigestInput{BatchID: 1842, ObservedAt: testObservedAt, Changes: changes, MutedCount: 3, Attributed: true})
}
