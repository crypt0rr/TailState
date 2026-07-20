package secret

import "testing"

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
