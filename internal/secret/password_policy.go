package secret

import (
	_ "embed"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Password policy for new administrator passwords, following NIST SP
// 800-63B-4 for single-factor passwords: a minimum length counted in
// characters (runes, not bytes), a generous maximum, and a blocklist of
// commonly used values. Existing password hashes are never re-evaluated, so
// an administrator whose password predates the policy can still sign in.
const (
	MinPasswordRunes = 15
	MaxPasswordRunes = 256
)

// Policy violations. PasswordPolicyMessage turns each into a sentence that is
// safe to show to the user.
var (
	ErrPasswordTooShort   = errors.New("password must be at least 15 characters long")
	ErrPasswordTooLong    = errors.New("password must be at most 256 characters long")
	ErrPasswordInvalid    = errors.New("password must be valid text without control characters")
	ErrPasswordCommon     = errors.New("password is too common")
	ErrPasswordRepetitive = errors.New("password repeats a single character or short pattern")
)

// PasswordPolicyMessage returns the user-facing explanation of a policy
// violation, or "" when err is not one.
func PasswordPolicyMessage(err error) string {
	switch {
	case errors.Is(err, ErrPasswordTooShort):
		return "Password must be at least 15 characters long. A passphrase of several words is easiest to remember."
	case errors.Is(err, ErrPasswordTooLong):
		return "Password must be at most 256 characters long."
	case errors.Is(err, ErrPasswordInvalid):
		return "Password must be valid text without control characters."
	case errors.Is(err, ErrPasswordCommon):
		return "This password is too common. Choose a less predictable passphrase."
	case errors.Is(err, ErrPasswordRepetitive):
		return "Password must not repeat a single character or short pattern."
	default:
		return ""
	}
}

//go:embed common_passwords.txt
var commonPasswordList string

var commonPasswords = func() map[string]bool {
	out := map[string]bool{}
	for _, entry := range strings.Split(commonPasswordList, "\n") {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		out[normalizePasswordForBlocklist(entry)] = true
	}
	return out
}()

// normalizePasswordForBlocklist folds case and drops common separators so
// "Correct Horse Battery Staple" matches the blocklisted
// "correcthorsebatterystaple".
func normalizePasswordForBlocklist(password string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(password) {
		if unicode.IsSpace(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CheckPasswordPolicy reports the first policy rule a new password breaks,
// or nil. It is the single source of the policy: setup, reset, and the
// authenticated password change all call it before anything else.
func CheckPasswordPolicy(password string) error {
	if !utf8.ValidString(password) {
		return ErrPasswordInvalid
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return ErrPasswordInvalid
		}
	}
	runes := utf8.RuneCountInString(password)
	if runes < MinPasswordRunes {
		return ErrPasswordTooShort
	}
	if runes > MaxPasswordRunes {
		return ErrPasswordTooLong
	}
	normalized := normalizePasswordForBlocklist(password)
	if repetitive(normalized) {
		return ErrPasswordRepetitive
	}
	if commonPasswords[normalized] {
		return ErrPasswordCommon
	}
	return nil
}

// repetitive reports whether value is one pattern of at most three runes
// repeated, such as "aaaaaaaaaaaaaaa" or "abcabcabcabcabc".
func repetitive(value string) bool {
	runes := []rune(value)
	for period := 1; period <= 3 && period < len(runes); period++ {
		if len(runes)%period != 0 {
			continue
		}
		same := true
		for i := period; i < len(runes); i++ {
			if runes[i] != runes[i-period] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}
