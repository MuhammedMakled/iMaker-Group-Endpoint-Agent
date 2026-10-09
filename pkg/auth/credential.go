// Package auth implements the application-level "global admin" credential and
// login sessions that gate every privileged action, on top of the Windows
// token check the IPC layer already enforces.
//
// The password is stored only as an Argon2id hash (never recoverable), in an
// ACL-protected file. Logging in yields a short-lived session token that is
// re-validated on each privileged call and expires after an idle timeout.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. 64 MiB / 1 pass / 4 lanes is a sensible desktop default.
const (
	argonMemory  = 64 * 1024
	argonTime    = 1
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns a self-describing encoded hash:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<saltB64>$<hashB64>
func HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword checks password against an encoded hash in constant time.
func VerifyPassword(encoded, password string) bool {
	m, t, p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decodeHash(encoded string) (m, t uint32, p uint8, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("invalid hash format")
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	if hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	return m, t, p, salt, hash, nil
}

// CredentialStore persists the single global-admin password hash.
type CredentialStore struct {
	path string
}

func NewCredentialStore(dir string) (*CredentialStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &CredentialStore{path: filepath.Join(dir, "admin.cred")}, nil
}

// IsSet reports whether a global admin password has been configured.
func (c *CredentialStore) IsSet() bool {
	b, err := os.ReadFile(c.path)
	return err == nil && len(strings.TrimSpace(string(b))) > 0
}

// Set writes a new password hash atomically. If a password already exists,
// the caller must have verified the current one first (enforced by the service).
func (c *CredentialStore) Set(password string) error {
	if err := ValidatePasswordStrength(password); err != nil {
		return err
	}
	enc, err := HashPassword(password)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(enc), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Verify checks a password against the stored hash.
func (c *CredentialStore) Verify(password string) bool {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return false
	}
	return VerifyPassword(strings.TrimSpace(string(b)), password)
}

// ValidatePasswordStrength enforces a floor for the global admin password.
func ValidatePasswordStrength(pw string) error {
	if len(pw) < 10 {
		return errors.New("the global admin password must be at least 10 characters")
	}
	if len(pw) > 256 {
		return errors.New("password too long")
	}
	var upper, lower, digit, other bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, ok := range []bool{upper, lower, digit, other} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return errors.New("use at least three of: uppercase, lowercase, digits, symbols")
	}
	return nil
}
