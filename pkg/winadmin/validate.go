// Package winadmin implements the agent's privileged administrative actions
// (rename PC, create local user, reset/wipe). Every exported action is called
// only from the service's admin-only RPC handlers, which authorise the caller
// from their Windows token before dispatch.
//
// The validation helpers here are OS-independent and unit-tested; the actual
// Win32/NetAPI calls live in winadmin_windows.go.
package winadmin

import (
	"fmt"
	"regexp"
	"strings"
)

// validComputerName allows letters, digits and hyphens, 1–15 chars, not all
// digits, and not starting/ending with a hyphen (NetBIOS rules).
var validComputerName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$`)

// ValidateComputerName checks a proposed computer name against Windows rules.
func ValidateComputerName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 15 {
		return fmt.Errorf("computer name must be 1–15 characters")
	}
	if !validComputerName.MatchString(name) {
		return fmt.Errorf("computer name may use only letters, digits and hyphens (not at the ends)")
	}
	if strings.IndexFunc(name, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return fmt.Errorf("computer name cannot be all digits")
	}
	return nil
}

// usernameBad are characters Windows forbids in account names.
const usernameBad = `"/\[]:;|=,+*?<>@`

// ValidateUsername checks a local account name.
func ValidateUsername(name string) error {
	name = strings.TrimSpace(name)
	if len(name) == 0 || len(name) > 20 {
		return fmt.Errorf("username must be 1–20 characters")
	}
	if strings.ContainsAny(name, usernameBad) {
		return fmt.Errorf("username contains an invalid character")
	}
	if strings.TrimRight(name, ". ") != name {
		return fmt.Errorf("username cannot end with a space or period")
	}
	return nil
}

// ValidatePassword applies a basic strength floor (the OS enforces its own
// policy on top). We never log or store the password itself.
func ValidatePassword(pw string) error {
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(pw) > 127 {
		return fmt.Errorf("password too long")
	}
	return nil
}

// ResetConfirmToken is the exact string a caller must send to authorise a
// reset of the named host. Tying it to the hostname makes a mis-targeted or
// broadcast wipe impossible.
func ResetConfirmToken(hostname string) string {
	return "RESET " + strings.ToUpper(strings.TrimSpace(hostname))
}

// CheckResetConfirm verifies the caller's confirmation matches this host.
func CheckResetConfirm(confirm, hostname string) error {
	want := ResetConfirmToken(hostname)
	if strings.ToUpper(strings.TrimSpace(confirm)) != want {
		return fmt.Errorf("confirmation must be exactly %q for this computer", want)
	}
	return nil
}
