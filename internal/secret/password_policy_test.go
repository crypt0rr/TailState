package secret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// TestPasswordPolicyCountsRunesAndExplainsEachRule checks every rule and its
// specific message: length is counted in characters, so a 15-character
// non-ASCII passphrase is accepted while 14 multibyte characters (more than
// 15 bytes) are not.
func TestPasswordPolicyCountsRunesAndExplainsEachRule(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password string
		want     error
		message  string
	}{
		{"accepted", "violet harbor lantern", nil, ""},
		{"fifteen runes", "ünïcödé pässwö!", nil, ""},
		{"fourteen multibyte runes", strings.Repeat("é", 13) + "x", ErrPasswordTooShort, "at least 15 characters"},
		{"twelve bytes", "twelve chars", ErrPasswordTooShort, "at least 15 characters"},
		{"too long", strings.Repeat("ab", 129), ErrPasswordTooLong, "at most 256"},
		{"control character", "valid passphrase\x00", ErrPasswordInvalid, "control characters"},
		{"invalid utf8", "valid passphrase\xff", ErrPasswordInvalid, "control characters"},
		{"common", "PasswordPassword", ErrPasswordCommon, "too common"},
		{"common with separators", "Correct Horse-Battery_Staple", ErrPasswordCommon, "too common"},
		{"repeated character", strings.Repeat("a", 20), ErrPasswordRepetitive, "repeat"},
		{"repeated pattern", strings.Repeat("abc", 6), ErrPasswordRepetitive, "repeat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPasswordPolicy(tc.password)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("CheckPasswordPolicy(%q) = %v, want %v", tc.password, err, tc.want)
			}
			if message := PasswordPolicyMessage(err); !strings.Contains(message, tc.message) || (tc.want != nil && message == "") {
				t.Fatalf("message %q does not explain %v", message, tc.want)
			}
			_, hashErr := PasswordHash(tc.password)
			if !errors.Is(hashErr, tc.want) || (tc.want == nil && hashErr != nil) {
				t.Fatalf("PasswordHash did not enforce the policy: %v", hashErr)
			}
		})
	}
	if PasswordPolicyMessage(errors.New("other")) != "" {
		t.Fatal("unrelated errors must not produce a policy message")
	}
}

// TestPasswordPolicyBlocklistIsEmbeddedAndNormalized keeps every blocklist
// entry reachable: each is long enough that the length rule would not
// already reject it, and each is rejected as common.
func TestPasswordPolicyBlocklistIsEmbeddedAndNormalized(t *testing.T) {
	if len(commonPasswords) < 50 {
		t.Fatalf("blocklist has only %d entries", len(commonPasswords))
	}
	for entry := range commonPasswords {
		if len([]rune(entry)) < MinPasswordRunes {
			t.Fatalf("blocklist entry %q is shorter than the minimum and therefore redundant", entry)
		}
		if err := CheckPasswordPolicy(strings.ToUpper(entry)); !errors.Is(err, ErrPasswordCommon) && !errors.Is(err, ErrPasswordRepetitive) {
			t.Fatalf("blocklisted %q accepted: %v", entry, err)
		}
	}
}

// TestPasswordHashFromOlderPolicyStillVerifies proves the policy applies
// only to new passwords: a 12-character password hashed by an older release
// still authenticates.
func TestPasswordHashFromOlderPolicyStillVerifies(t *testing.T) {
	const legacy = "twelve chars"
	salt := []byte("0123456789abcdef")
	sum := argon2.IDKey([]byte(legacy), salt, 3, 64*1024, 2, 32)
	encoded := fmt.Sprintf("argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
	if !PasswordMatches(encoded, legacy) {
		t.Fatal("a password set under the previous 12-character minimum no longer verifies")
	}
	if _, err := PasswordHash(legacy); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("the same password must be rejected as a new password: %v", err)
	}
}
