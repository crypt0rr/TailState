package secret

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// TestBoundEnvelopeRejectsMovedCiphertext asserts that a v2 ciphertext only
// authenticates for the binding it was sealed with, so copying it to another
// row or column fails, while legacy v1 values remain readable.
func TestBoundEnvelopeRejectsMovedCiphertext(t *testing.T) {
	box, err := NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal("notification_destinations.service_url_enc:2", "generic://b.example/hook")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v2:") || !IsCurrentEnvelope(sealed) {
		t.Fatalf("sealed envelope=%q, want v2", sealed)
	}
	plain, err := box.Open("notification_destinations.service_url_enc:2", sealed)
	if err != nil || plain != "generic://b.example/hook" {
		t.Fatalf("bound round trip=%q err=%v", plain, err)
	}
	for _, other := range []string{
		"notification_destinations.service_url_enc:1",
		"settings.oauth_secret_enc:1",
		"meta.value:evidence_signing_private_key_enc",
	} {
		if _, err := box.Open(other, sealed); err == nil {
			t.Fatalf("ciphertext sealed for row 2 opened as %q", other)
		}
	}
	if _, err := box.Open("", sealed); err == nil {
		t.Fatal("v2 ciphertext opened without a binding")
	}
	if _, err := box.Seal("", "value"); err == nil {
		t.Fatal("Seal accepted an empty binding")
	}

	legacy, err := box.EncryptLegacy("legacy value")
	if err != nil {
		t.Fatal(err)
	}
	if IsCurrentEnvelope(legacy) || !strings.HasPrefix(legacy, "v1:") {
		t.Fatalf("legacy envelope=%q, want v1", legacy)
	}
	for _, binding := range []string{"", "settings.oauth_secret_enc:1"} {
		if plain, err := box.Open(binding, legacy); err != nil || plain != "legacy value" {
			t.Fatalf("legacy value with binding %q=%q err=%v", binding, plain, err)
		}
	}

	// A v1 body relabelled as v2 (or the reverse) must not authenticate.
	if _, err := box.Open("settings.oauth_secret_enc:1", "v2:"+strings.TrimPrefix(legacy, "v1:")); err == nil {
		t.Fatal("v1 body accepted as v2")
	}
	if _, err := box.Open("", "v1:"+strings.TrimPrefix(sealed, "v2:")); err == nil {
		t.Fatal("v2 body accepted as v1")
	}
}

func TestBoundEnvelopeErrorPaths(t *testing.T) {
	box := &Box{key: make([]byte, 31)}
	if _, err := box.Seal("binding", "secret"); err == nil {
		t.Fatal("Seal accepted an invalid internal key")
	}
	if _, err := box.Open("binding", "v2:"+base64.RawURLEncoding.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("Open accepted an invalid internal key")
	}
	valid, _ := NewBox(make([]byte, 32))
	for _, malformed := range []string{"v2:not base64", "v2:", "v3:abc"} {
		if _, err := valid.Open("binding", malformed); err == nil {
			t.Fatalf("malformed envelope accepted: %q", malformed)
		}
	}
	original := rand.Reader
	rand.Reader = failingRandomReader{}
	t.Cleanup(func() { rand.Reader = original })
	if _, err := valid.Seal("binding", "secret"); err == nil {
		t.Fatal("Seal hid a random source failure")
	}
}
