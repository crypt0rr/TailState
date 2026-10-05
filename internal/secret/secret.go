package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Envelope versions. A v1 envelope authenticates only the constant "v1", so
// a v1 ciphertext stays valid when it is copied to another row or column. A
// v2 envelope also authenticates a caller-supplied binding that names where
// the value is stored (for example "notification_destinations.service_url_enc:7"),
// so a moved ciphertext fails authentication. v1 values remain readable.
const (
	envelopeVersion   = "v1"
	envelopeVersionV2 = "v2"
)

// Password hashes are stored in the database and therefore are not an
// appropriate place to accept unbounded Argon2 resource requests. These
// bounds include the parameters emitted by PasswordHash and the lower-cost
// parameters used by older hashes, while preventing a tampered row from
// turning one login into a multi-gigabyte allocation.
const (
	minArgon2MemoryKiB = 8 * 1024
	maxArgon2MemoryKiB = 64 * 1024
	maxArgon2Time      = 3
	maxArgon2Parallel  = 2
	minArgon2SaltBytes = 8
	maxArgon2SaltBytes = 64
)

type Box struct{ key []byte }

func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be 32 bytes")
	}
	return &Box{key: append([]byte(nil), key...)}, nil
}

// Seal encrypts plaintext into a v2 envelope bound to binding, a stable
// description of the storage location such as "table.column:rowkey". The same
// binding must be supplied to Open.
func (b *Box) Seal(binding, plaintext string) (string, error) {
	if binding == "" {
		return "", errors.New("encryption binding is required")
	}
	return b.seal(envelopeVersionV2, v2AdditionalData(binding), plaintext)
}

// EncryptLegacy produces a v1 envelope that is not bound to a storage
// location. It exists only to construct values written by older releases
// (for upgrade tests and tooling); new values must use Seal.
func (b *Box) EncryptLegacy(plaintext string) (string, error) {
	return b.seal(envelopeVersion, []byte(envelopeVersion), plaintext)
}

// Open decrypts a v2 envelope sealed for binding, or a legacy v1 envelope
// (whose binding cannot be checked). A v2 envelope sealed for a different
// binding fails authentication.
func (b *Box) Open(binding, envelope string) (string, error) {
	version, encoded, ok := strings.Cut(envelope, ":")
	var additional []byte
	switch {
	case !ok:
		return "", errors.New("unsupported encrypted value")
	case version == envelopeVersion:
		additional = []byte(envelopeVersion)
	case version == envelopeVersionV2:
		if binding == "" {
			return "", errors.New("encryption binding is required")
		}
		additional = v2AdditionalData(binding)
	default:
		return "", errors.New("unsupported encrypted value")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encrypted value: %w", err)
	}
	gcm, err := b.aead()
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted value is truncated")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], additional)
	if err != nil {
		return "", errors.New("decrypt encrypted value")
	}
	return string(plain), nil
}

// IsCurrentEnvelope reports whether envelope already uses the bound v2
// format. It does not authenticate the value.
func IsCurrentEnvelope(envelope string) bool {
	return strings.HasPrefix(envelope, envelopeVersionV2+":")
}

func v2AdditionalData(binding string) []byte {
	return []byte(envelopeVersionV2 + ":" + binding)
}

func (b *Box) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (b *Box) seal(version string, additional []byte, plaintext string) (string, error) {
	gcm, err := b.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), additional)
	return version + ":" + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func PasswordHash(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func PasswordMatches(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" || parts[1] != "v=19" {
		return false
	}
	params := map[string]uint64{}
	for _, part := range strings.Split(parts[2], ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || (key != "m" && key != "t" && key != "p") {
			return false
		}
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || parsed == 0 {
			return false
		}
		if _, exists := params[key]; exists {
			return false
		}
		params[key] = parsed
	}
	if len(params) != 3 ||
		params["m"] < minArgon2MemoryKiB || params["m"] > maxArgon2MemoryKiB ||
		params["t"] > maxArgon2Time || params["p"] > maxArgon2Parallel {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[3])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil || len(salt) < minArgon2SaltBytes || len(salt) > maxArgon2SaltBytes || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(params["t"]), uint32(params["m"]), uint8(params["p"]), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func Token(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
