// Package sysctl implements the agent's system-control features: listing and
// controlling Windows services, startup apps, processes, and Bluetooth.
//
// Read operations (list) are harmless; the state-changing operations are only
// ever reached through the service's privileged (global-admin) RPC handlers.
// Pure helpers here are unit-tested; Win32/WMI/registry calls live in the
// *_windows.go files.
package sysctl

import (
	"encoding/base64"
	"errors"
	"strings"
)

// NormalizeStartMode maps WMI Win32_Service.StartMode to a friendly label.
func NormalizeStartMode(mode string, delayed bool) string {
	switch strings.ToLower(mode) {
	case "auto":
		if delayed {
			return "Automatic (Delayed)"
		}
		return "Automatic"
	case "manual":
		return "Manual"
	case "disabled":
		return "Disabled"
	case "boot":
		return "Boot"
	case "system":
		return "System"
	}
	return mode
}

// Startup item locations.
const (
	LocHKLMRun     = "HKLM Run"
	LocHKCURun     = "HKCU Run"
	LocStartupMenu = "Startup folder"
	LocHKLMRun32   = "HKLM Run (WOW64)"
)

// EncodeStartupID builds an opaque, reversible ID for a startup item so a
// toggle call can locate exactly the same entry. Format: <loc>|<name>, base64.
func EncodeStartupID(location, name string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(location + "\x1f" + name))
}

// DecodeStartupID reverses EncodeStartupID.
func DecodeStartupID(id string) (location, name string, err error) {
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(b), "\x1f", 2)
	if len(parts) != 2 {
		return "", "", errors.New("malformed startup id")
	}
	return parts[0], parts[1], nil
}

// ValidateServiceAction checks a requested service action.
func ValidateServiceAction(action string) error {
	switch action {
	case "start", "stop", "restart":
		return nil
	}
	return errors.New("action must be start, stop or restart")
}

// criticalServices are never stoppable through the agent, to avoid bricking a
// remote machine (stopping these can make the PC unmanageable or unbootable).
var criticalServices = map[string]bool{
	"rpcss":                true, // RPC
	"dcomlaunch":           true, // DCOM
	"lsm":                  true, // Local Session Manager
	"plugplay":             true,
	"power":                true,
	"brokerinfrastructure": true,
	"dcomserver":           true,
	"samss":                true, // Security Accounts Manager
	"winmgmt":              true, // WMI — the agent itself relies on it
	"eventlog":             true,
	"schedule":             true, // Task Scheduler
	"imakeragentservice":   true, // never let the agent stop itself this way
}

// IsCriticalService reports whether a service is protected from stop/restart.
func IsCriticalService(name string) bool {
	return criticalServices[strings.ToLower(strings.TrimSpace(name))]
}
