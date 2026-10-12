// Package update implements the self-update flow for the endpoint agent:
// request validation, strict SHA-256 verification, bundle extraction, the
// on-disk state/health files, and the updater's apply-or-rollback sequence.
//
// Everything here is OS-independent so it can be unit-tested anywhere. The
// Windows-specific operations (SCM, file replace, Authenticode, spawning the
// updater) live in ops_windows.go and are injected through the Ops interface.
package update

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Final and in-flight statuses. The two final ones are what gets reported to
// the IT Command Center.
const (
	StatusAccepted = "UPGRADE_ACCEPTED"
	StatusSuccess  = "UPGRADE_SUCCESS"
	StatusFailed   = "UPGRADE_FAILED"
)

// State phases stored in updates\state.json.
const (
	PhaseApplying = "applying"
	PhaseSuccess  = "success"
	PhaseFailed   = "failed"
)

// The bundle must contain exactly these two files, and they replace the
// installed binaries of the same name.
const (
	ServiceExe = "ImakerAgentService.exe"
	TrayExe    = "ImakerTrayApp.exe"
)

// BundleFiles is the complete, fixed set of files a bundle may contain.
var BundleFiles = []string{ServiceExe, TrayExe}

const (
	// HealthTimeout is how long the updater waits for the new service to
	// report healthy before rolling back.
	HealthTimeout = 15 * time.Second
	// MaxBundleBytes caps the downloaded zip and each extracted binary.
	MaxBundleBytes = 200 << 20
	// MaxRedirects bounds the redirect chain on the download.
	MaxRedirects = 3
)

// Request is the upgrade-agent payload after JSON decoding.
type Request struct {
	DownloadURL   string
	TargetVersion string
	SHA256        string
}

// Policy is the local policy a request must satisfy.
type Policy struct {
	AllowedHosts []string // exact hostnames from agent.json; empty = refuse all
	Current      string   // running agent version
}

// Validate checks a request against the local policy before anything is
// downloaded. It fails closed: no allowed hosts means no updates.
func (r Request) Validate(p Policy) error {
	if len(p.AllowedHosts) == 0 {
		return errors.New("self-update is disabled: update_allowed_hosts is empty in agent.json")
	}
	u, err := url.Parse(r.DownloadURL)
	if err != nil {
		return fmt.Errorf("download_url is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("download_url must use https")
	}
	if u.User != nil {
		return errors.New("download_url must not contain credentials")
	}
	if port := u.Port(); port != "" && port != "443" {
		return errors.New("download_url must use the default https port")
	}
	if !HostAllowed(u.Hostname(), p.AllowedHosts) {
		return fmt.Errorf("host %q is not in update_allowed_hosts", u.Hostname())
	}
	if !strings.HasSuffix(strings.ToLower(u.Path), ".zip") {
		return errors.New("download_url must point to a .zip bundle")
	}
	if _, err := NormalizeSHA256(r.SHA256); err != nil {
		return err
	}
	target, err := ParseVersion(r.TargetVersion)
	if err != nil {
		return fmt.Errorf("target_version: %w", err)
	}
	cur, err := ParseVersion(p.Current)
	if err != nil {
		return fmt.Errorf("running version: %w", err)
	}
	if CompareParsed(target, cur) <= 0 {
		return fmt.Errorf("target %s is not newer than the running version %s", r.TargetVersion, p.Current)
	}
	return nil
}

// HostAllowed reports whether host exactly matches one of the allowed names
// (case-insensitive). Wildcards are deliberately not supported.
func HostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range allowed {
		if host != "" && host == strings.ToLower(strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

// NormalizeSHA256 validates a 64-character hex digest and returns it lower-cased.
func NormalizeSHA256(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != sha256.Size*2 {
		return "", errors.New("sha256_hash must be 64 hex characters")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", errors.New("sha256_hash must be hexadecimal")
	}
	return s, nil
}

// FileSHA256 streams a file through SHA-256 and returns the lower-case hex digest.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifySHA256 fails unless the file's digest equals expected. The comparison
// is constant-time, though this is an integrity check rather than a secret.
func VerifySHA256(path, expected string) error {
	want, err := NormalizeSHA256(expected)
	if err != nil {
		return err
	}
	got, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("SHA-256 mismatch: got %s, expected %s", got, want)
	}
	return nil
}

// ParsedVersion is a numeric version. Pre-release/build suffixes are ignored
// for ordering, so "1.5.0-abc1234" compares as 1.5.0.
type ParsedVersion [4]int

// ParseVersion accepts 1 to 4 dot-separated numeric parts.
func ParseVersion(s string) (ParsedVersion, error) {
	var v ParsedVersion
	core := s
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return v, fmt.Errorf("invalid version %q", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("invalid version %q", s)
		}
		v[i] = n
	}
	return v, nil
}

// CompareVersions returns -1, 0 or 1 for a < b, a == b, a > b.
func CompareVersions(a, b string) (int, error) {
	pa, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	return CompareParsed(pa, pb), nil
}

// CompareParsed compares two parsed versions.
func CompareParsed(a, b ParsedVersion) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// Dirs locates everything under %ProgramData%\Imaker\updates.
type Dirs struct{ Root string }

// Incoming holds the downloaded zip.
func (d Dirs) Incoming() string { return filepath.Join(d.Root, "incoming") }

// Staged holds the verified, extracted binaries for one target version.
func (d Dirs) Staged(version string) string { return filepath.Join(d.Root, "staged", version) }

// Backup holds copies of the binaries that were running before the update.
func (d Dirs) Backup() string { return filepath.Join(d.Root, "backup") }

// Updater is the copy of the agent binary that performs the apply step.
func (d Dirs) Updater() string { return filepath.Join(d.Root, "updater.exe") }

// StatePath is the update state file.
func (d Dirs) StatePath() string { return filepath.Join(d.Root, "state.json") }

// HealthPath is written by a freshly started service once it is running.
func (d Dirs) HealthPath() string { return filepath.Join(d.Root, "health.json") }

// State is the persisted record of the most recent upgrade.
type State struct {
	Phase         string    `json:"phase"`
	Status        string    `json:"status,omitempty"`
	FromVersion   string    `json:"from_version"`
	TargetVersion string    `json:"target_version"`
	InstallDir    string    `json:"install_dir"`
	Caller        string    `json:"caller,omitempty"`
	RequestedAt   time.Time `json:"requested_at"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	Error         string    `json:"error,omitempty"`
	Reported      bool      `json:"reported"`
}

// Health is written by the service once it has started successfully.
type Health struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
}

// ErrNoState means no upgrade has ever been requested on this PC.
var ErrNoState = errors.New("no upgrade state")

// ReadState loads the state file. It returns ErrNoState when absent.
func ReadState(d Dirs) (State, error) {
	var st State
	b, err := os.ReadFile(d.StatePath())
	if errors.Is(err, os.ErrNotExist) {
		return st, ErrNoState
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// WriteState saves the state file atomically.
func WriteState(d Dirs, st State) error { return writeJSONAtomic(d.StatePath(), st) }

// WriteHealth records that the service at version started successfully.
func WriteHealth(d Dirs, version string, now time.Time) error {
	return writeJSONAtomic(d.HealthPath(), Health{Version: version, StartedAt: now})
}

// WaitForHealth polls for a health record of the target version that was
// written at or after since, failing after timeout.
func WaitForHealth(d Dirs, target string, since time.Time, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var h Health
		if b, err := os.ReadFile(d.HealthPath()); err == nil && json.Unmarshal(b, &h) == nil {
			if h.Version == target && !h.StartedAt.Before(since) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("version %s did not report healthy within %s", target, timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
