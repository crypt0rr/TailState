package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestEvidenceVerifyAcceptsEveryPartOfAChain exports a signed history as a
// chain of partial packs and runs `tailstate evidence verify` on each saved
// part, with both the embedded and an independently trusted key.
func TestEvidenceVerifyAcceptsEveryPartOfAChain(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	configureCommandEnvironment(t, dataDir)
	_, st, err := load()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	generation, err := st.SaveSettings(ctx, store.Settings{Tailnet: "-", OAuthClientID: "client", OAuthClientSecret: "secret", MattermostURL: "https://mattermost.example/hooks/x", DeviceInterval: time.Minute, InventoryInterval: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 6; index++ {
		name := fmt.Sprintf("server-%d", index)
		collected := []model.Collected{{Collector: "devices", Resources: []model.Resource{{ID: "device-1", Type: "device", Name: name, Data: map[string]any{"hostname": name}}}}}
		if _, err := st.ApplyBatchWithBatch(ctx, generation, collected, notify.TextDigest(name)); err != nil {
			t.Fatal(err)
		}
	}
	public, err := st.EvidenceSigningPublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dataDir, "evidence.key")
	if err := os.WriteFile(keyPath, []byte(base64.RawStdEncoding.EncodeToString(public)), 0o600); err != nil {
		t.Fatal(err)
	}
	filter := store.HistoryFilter{Limit: 2}
	seen := map[int64]bool{}
	parts := 0
	for ; parts < 10; parts++ {
		data, err := st.ExportEvidencePack(ctx, filter)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dataDir, fmt.Sprintf("part-%d.json", parts))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := evidenceVerify([]string{"-file", path}); err != nil {
			t.Fatalf("part %d failed embedded-key verification: %v", parts, err)
		}
		if err := evidenceVerify([]string{"-file", path, "-public-key", keyPath}); err != nil {
			t.Fatalf("part %d failed trusted-key verification: %v", parts, err)
		}
		var pack store.EvidencePack
		if err := json.Unmarshal(data, &pack); err != nil {
			t.Fatal(err)
		}
		for _, batch := range pack.Batches {
			if seen[batch.ID] {
				t.Fatalf("batch %d appears in more than one part", batch.ID)
			}
			seen[batch.ID] = true
		}
		if !pack.Truncated {
			break
		}
		filter.Cursor = pack.NextCursor
	}
	// The first poll is a silent baseline, so five batches carry changes.
	if parts != 2 || len(seen) != 5 {
		t.Fatalf("chain had %d continuation parts and %d batches, want 2 and 5", parts, len(seen))
	}
}
