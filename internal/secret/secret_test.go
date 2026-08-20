package secret

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestBoxRoundTripAndWrongKey(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	box, _ := NewBox(key)
	encrypted, err := box.Encrypt("sensitive")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt(encrypted)
	if err != nil || plain != "sensitive" {
		t.Fatalf("round trip: %q %v", plain, err)
	}
	other, _ := NewBox(make([]byte, 32))
	if _, err := other.Decrypt(encrypted); err == nil {
		t.Fatal("wrong key decrypted value")
	}
}
func TestPassword(t *testing.T) {
	hash, err := PasswordHash("a secure password")
	if err != nil {
		t.Fatal(err)
	}
	if !PasswordMatches(hash, "a secure password") {
		t.Fatal("password did not match")
	}
	if PasswordMatches(hash, "wrong password") {
		t.Fatal("wrong password matched")
	}
	if _, err := PasswordHash("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestPasswordMatchesUsesEncodedParameters(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, 16)
	hash := argon2.IDKey([]byte("a secure password"), salt, 1, 8192, 1, 32)
	encoded := fmt.Sprintf("argon2id$v=19$m=8192,t=1,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
	if !PasswordMatches(encoded, "a secure password") {
		t.Fatal("password with encoded Argon2 parameters did not match")
	}
	if PasswordMatches(encoded, "wrong password") {
		t.Fatal("wrong password matched encoded Argon2 parameters")
	}
	for _, malformed := range []string{
		strings.Replace(encoded, "m=8192,t=1,p=1", "m=8192,t=1,p=1,x=1", 1),
		strings.Replace(encoded, "m=8192,t=1,p=1", "m=8192,t=1", 1),
		strings.Replace(encoded, "m=8192,t=1,p=1", "m=8192,t=1,p=0", 1),
	} {
		if PasswordMatches(malformed, "a secure password") {
			t.Fatalf("malformed Argon2 parameters were accepted: %q", malformed)
		}
	}
}
