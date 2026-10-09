package auth

import (
	"testing"
	"time"
)

func TestHashVerify(t *testing.T) {
	enc, err := HashPassword("S3cret-Pass!")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(enc, "S3cret-Pass!") {
		t.Fatal("correct password should verify")
	}
	if VerifyPassword(enc, "wrong") {
		t.Fatal("wrong password must not verify")
	}
	if VerifyPassword("garbage", "x") {
		t.Fatal("garbage hash must not verify")
	}
	// Two hashes of the same password differ (random salt).
	enc2, _ := HashPassword("S3cret-Pass!")
	if enc == enc2 {
		t.Fatal("salt should make hashes unique")
	}
}

func TestPasswordStrength(t *testing.T) {
	if err := ValidatePasswordStrength("Str0ng-Pass!"); err != nil {
		t.Errorf("strong password rejected: %v", err)
	}
	for _, w := range []string{"short1A", "alllowercase", "ALLUPPER123", "nocomplexity"} {
		if ValidatePasswordStrength(w) == nil {
			t.Errorf("%q should be rejected", w)
		}
	}
}

type fakeVerifier struct {
	pw  string
	set bool
}

func (f fakeVerifier) Verify(p string) bool { return f.set && p == f.pw }
func (f fakeVerifier) IsSet() bool          { return f.set }

func TestSessionsAndIdleTimeout(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	m := NewManager(fakeVerifier{pw: "pw", set: true}, ManagerConfig{IdleTimeout: 15 * time.Minute})
	m.now = func() time.Time { return now }

	tok, exp, err := m.Login("IMAKER\\it", "pw")
	if err != nil || tok == "" {
		t.Fatalf("login: %v", err)
	}
	if !exp.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expiry: %v", exp)
	}
	if u, ok := m.Validate(tok); !ok || u != "IMAKER\\it" {
		t.Fatal("token should validate")
	}
	// 10 min later: still valid, and the idle window slides.
	now = now.Add(10 * time.Minute)
	if _, ok := m.Validate(tok); !ok {
		t.Fatal("should still be valid within idle window")
	}
	// 10 more min (20 total, but only 10 since last use): still valid.
	now = now.Add(10 * time.Minute)
	if _, ok := m.Validate(tok); !ok {
		t.Fatal("sliding window should keep it alive")
	}
	// 16 min of inactivity: expired.
	now = now.Add(16 * time.Minute)
	if _, ok := m.Validate(tok); ok {
		t.Fatal("token should expire after idle timeout")
	}
	// Logout invalidates immediately.
	tok2, _, _ := m.Login("u", "pw")
	m.Logout(tok2)
	if _, ok := m.Validate(tok2); ok {
		t.Fatal("logged-out token must be invalid")
	}
}

func TestLockout(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	m := NewManager(fakeVerifier{pw: "pw", set: true}, ManagerConfig{MaxFails: 3, FailWindow: 10 * time.Minute, LockoutFor: 15 * time.Minute})
	m.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if _, _, err := m.Login("u", "bad"); err != ErrBadPassword {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Now locked, even with the correct password.
	if _, _, err := m.Login("u", "pw"); err != ErrLockedOut {
		t.Fatalf("should be locked out, got %v", err)
	}
	if m.LockedUntil().IsZero() {
		t.Fatal("LockedUntil should be set")
	}
	// After the lockout window, correct password works again.
	now = now.Add(16 * time.Minute)
	if _, _, err := m.Login("u", "pw"); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
}
