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

const envelopeVersion = "v1"

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

func (b *Box) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), []byte(envelopeVersion))
	return envelopeVersion + ":" + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

func (b *Box) Decrypt(envelope string) (string, error) {
	version, encoded, ok := strings.Cut(envelope, ":")
	if !ok || version != envelopeVersion {
		return "", errors.New("unsupported encrypted value")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encrypted value: %w", err)
	}
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted value is truncated")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(envelopeVersion))
	if err != nil {
		return "", errors.New("decrypt encrypted value")
	}
	return string(plain), nil
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
