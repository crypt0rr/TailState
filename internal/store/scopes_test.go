package store

import (
	"context"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/notify"
)

func TestOAuthScopesPersistAndOnlyReadScopesAreAccepted(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := st.Settings(ctx)
	if err != nil || strings.Join(loaded.OAuthScopes, " ") != "all:read" {
		t.Fatalf("default scopes=%v err=%v", loaded.OAuthScopes, err)
	}
	for _, scopes := range [][]string{{"devices:core"}, {"all"}, {"dns:read", "auth_keys"}, {"DNS:READ"}, {"dns:read;rm"}, {strings.Repeat("a", 70) + ":read"}} {
		in := settings()
		in.OAuthScopes = scopes
		if err := ValidateSettings(in); err == nil {
			t.Fatalf("scopes %v were accepted", scopes)
		}
	}
	tooMany := make([]string, MaxOAuthScopes+1)
	for i := range tooMany {
		tooMany[i] = "s" + strings.Repeat("x", i+1) + ":read"
	}
	if _, err := NormalizeOAuthScopes(tooMany); err == nil {
		t.Fatal("too many scopes were accepted")
	}

	// An unsupported collector is recorded with its bounded reason label.
	results := []model.Collected{{Collector: "services", Unsupported: true, UnsupportedReason: "unsupported (insufficient OAuth scope or plan: HTTP 403)"}, {Collector: "oauth_apps", Unsupported: true}}
	if _, err := st.ApplyBatchWithBatch(ctx, generation, results, notify.TextDigest("")); err != nil {
		t.Fatal(err)
	}
	status, err := st.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, collector := range status.Collectors {
		reasons[collector.Name] = collector.LastError
	}
	if !strings.Contains(reasons["services"], "insufficient OAuth scope") || reasons["oauth_apps"] != "unsupported" {
		t.Fatalf("reasons=%v", reasons)
	}

	// Saving the same scopes keeps the unsupported deadline; changing them
	// makes unsupported collectors due immediately.
	if _, err := st.SaveSettings(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	if due, err := st.CollectorDueWithError(ctx, generation, "services"); err != nil || due {
		t.Fatalf("unchanged scopes made the collector due=%v err=%v", due, err)
	}
	loaded.OAuthScopes = []string{"services:read", "devices:core:read", "services:read"}
	if _, err := st.SaveSettings(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	if due, err := st.CollectorDueWithError(ctx, generation, "services"); err != nil || !due {
		t.Fatalf("changed scopes did not make the collector due=%v err=%v", due, err)
	}
	if updated, err := st.Settings(ctx); err != nil || strings.Join(updated.OAuthScopes, " ") != "devices:core:read services:read" {
		t.Fatalf("scopes=%v err=%v", updated.OAuthScopes, err)
	}
	// A damaged options row is replaced on the next save.
	if _, err := st.db.Exec("UPDATE meta SET value='{' WHERE key=?", monitoringOptionsMeta); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	if repaired, err := st.Settings(ctx); err != nil || len(repaired.OAuthScopes) != 2 {
		t.Fatalf("repaired scopes=%v err=%v", repaired.OAuthScopes, err)
	}
}
