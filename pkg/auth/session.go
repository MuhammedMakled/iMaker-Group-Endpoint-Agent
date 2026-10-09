package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrLockedOut is returned while a brute-force lockout is in effect.
var ErrLockedOut = errors.New("too many failed attempts; locked out, try again later")

// ErrBadPassword is returned for a wrong password (indistinguishable timing).
var ErrBadPassword = errors.New("incorrect global admin password")

// Verifier checks a candidate password (implemented by CredentialStore).
type Verifier interface {
	Verify(password string) bool
	IsSet() bool
}

type session struct {
	user     string
	lastUsed time.Time
}

// Manager issues and validates login sessions with an idle timeout, and
// throttles failed logins with a lockout.
type Manager struct {
	mu          sync.Mutex
	verifier    Verifier
	sessions    map[string]*session
	idleTimeout time.Duration

	// lockout
	maxFails    int
	failWindow  time.Duration
	lockoutFor  time.Duration
	fails       int
	firstFail   time.Time
	lockedUntil time.Time

	now func() time.Time
}

// ManagerConfig configures the session manager.
type ManagerConfig struct {
	IdleTimeout time.Duration // re-prompt after this much inactivity (default 15m)
	MaxFails    int           // failed logins before lockout (default 5)
	FailWindow  time.Duration // window the fails are counted over (default 10m)
	LockoutFor  time.Duration // lockout duration (default 15m)
}

func NewManager(v Verifier, cfg ManagerConfig) *Manager {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 15 * time.Minute
	}
	if cfg.MaxFails <= 0 {
		cfg.MaxFails = 5
	}
	if cfg.FailWindow <= 0 {
		cfg.FailWindow = 10 * time.Minute
	}
	if cfg.LockoutFor <= 0 {
		cfg.LockoutFor = 15 * time.Minute
	}
	return &Manager{
		verifier: v, sessions: map[string]*session{},
		idleTimeout: cfg.IdleTimeout, maxFails: cfg.MaxFails,
		failWindow: cfg.FailWindow, lockoutFor: cfg.LockoutFor,
		now: time.Now,
	}
}

// Login verifies the password and returns a session token + its idle expiry.
func (m *Manager) Login(user, password string) (token string, expires time.Time, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()

	if now.Before(m.lockedUntil) {
		return "", time.Time{}, ErrLockedOut
	}
	if !m.verifier.IsSet() {
		return "", time.Time{}, errors.New("no global admin password has been set yet")
	}
	if !m.verifier.Verify(password) {
		m.registerFailLocked(now)
		return "", time.Time{}, ErrBadPassword
	}
	// success resets the failure counter
	m.fails, m.firstFail, m.lockedUntil = 0, time.Time{}, time.Time{}

	tok := newToken()
	m.sessions[tok] = &session{user: user, lastUsed: now}
	return tok, now.Add(m.idleTimeout), nil
}

func (m *Manager) registerFailLocked(now time.Time) {
	if m.fails == 0 || now.Sub(m.firstFail) > m.failWindow {
		m.firstFail = now
		m.fails = 0
	}
	m.fails++
	if m.fails >= m.maxFails {
		m.lockedUntil = now.Add(m.lockoutFor)
		m.fails = 0
	}
}

// Validate checks a token, refreshing its idle timer. Returns the user.
func (m *Manager) Validate(token string) (user string, ok bool) {
	if token == "" {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, exists := m.sessions[token]
	if !exists {
		return "", false
	}
	now := m.now()
	if now.Sub(s.lastUsed) > m.idleTimeout {
		delete(m.sessions, token)
		return "", false
	}
	s.lastUsed = now // sliding idle window
	return s.user, true
}

// Logout invalidates a token.
func (m *Manager) Logout(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

// LockedUntil reports the current lockout expiry (zero if not locked).
func (m *Manager) LockedUntil() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.now().Before(m.lockedUntil) {
		return m.lockedUntil
	}
	return time.Time{}
}

// IdleTimeout exposes the configured timeout.
func (m *Manager) IdleTimeout() time.Duration { return m.idleTimeout }

func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
