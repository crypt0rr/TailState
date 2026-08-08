package secret

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTokenHashAndMalformedPasswordValues(t *testing.T) {
	token, err := Token(24)
	if err != nil || len(token) < 24 || strings.ContainsAny(token, "+/=") {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if got := HashToken("token"); got != HashToken("token") || got == HashToken("other") {
		t.Fatalf("hash token is not deterministic or distinct: %q", got)
	}
	hash, err := PasswordHash("a secure password")
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{"", "argon2id", "wrong$v=19$m=1,t=1,p=1$bad$bad", "argon2id$v=19$m=65536,t=3,p=2$%%%$%%%", "argon2id$v=19$m=65536,t=3,p=2$YWJj$YWJj"} {
		if PasswordMatches(malformed, "a secure password") {
			t.Fatalf("malformed password hash matched: %q", malformed)
		}
	}
	if !PasswordMatches(hash, "a secure password") {
		t.Fatal("valid password hash no longer matches")
	}
}

func TestNewBoxAndDecryptRejectMalformedCiphertexts(t *testing.T) {
	if _, err := NewBox(make([]byte, 31)); err == nil {
		t.Fatal("invalid AES key length was accepted")
	}
	box, err := NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{"", "v2:value", "v1:not-base64", "v1:"} {
		if _, err := box.Decrypt(malformed); err == nil {
			t.Fatalf("malformed ciphertext accepted: %q", malformed)
		}
	}
	encrypted, err := box.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	replacement := byte('A')
	if encrypted[3] == replacement {
		replacement = 'B'
	}
	tampered := encrypted[:3] + string(replacement) + encrypted[4:]
	if _, err := box.Decrypt(tampered); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}

func TestBoxRejectsInvalidInternalKey(t *testing.T) {
	box := &Box{key: make([]byte, 31)}
	if _, err := box.Encrypt("secret"); err == nil {
		t.Fatal("Encrypt accepted an invalid internal key")
	}
	encoded := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	if _, err := box.Decrypt(envelopeVersion + ":" + encoded); err == nil {
		t.Fatal("Decrypt accepted an invalid internal key")
	}
}
