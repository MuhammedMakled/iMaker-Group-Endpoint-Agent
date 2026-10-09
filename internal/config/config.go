// Package config loads the agent configuration shared by the tray app and
// the system service. The file lives at %ProgramData%\Imaker\agent.json so
// IT can push it via GPO/Intune; every field has a safe default.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Version is overridden at build time:
//
//	go build -ldflags "-X github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config.Version=1.0.3"
var Version = "1.0.0-dev"

const (
	DefaultPipeName = `\\.\pipe\imaker_agent_ipc`
	ServiceName     = "ImakerAgentService"
	ServiceDisplay  = "IMAKER Endpoint Agent"
	TrayAppName     = "ImakerTrayApp"
)

// Duration is a time.Duration that marshals as a Go duration string ("5m").
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// Allow raw integers as seconds.
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return fmt.Errorf("duration must be a string like \"5m\": %w", err)
		}
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Config is the full agent configuration.
type Config struct {
	// ---- Activity tracker (tray app) ----
	PollInterval        Duration `json:"poll_interval"`
	IdleThreshold       Duration `json:"idle_threshold"`
	MinSessionDuration  Duration `json:"min_session_duration"`
	MaxHeartbeatGap     Duration `json:"max_heartbeat_gap"`
	ProjectCodePatterns []string `json:"project_code_patterns"`

	// File watcher
	WatchPaths          []string `json:"watch_paths"`
	AutoDiscoverDropbox bool     `json:"auto_discover_dropbox"`
	WatchedExtensions   []string `json:"watched_extensions"`
	FileEventDebounce   Duration `json:"file_event_debounce"`

	// Browser privacy filter
	TrackBrowsers         bool              `json:"track_browsers"`
	WorkDomains           []string          `json:"work_domains"`
	PersonalDomains       []string          `json:"personal_domains"`
	WorkTitleKeywords     map[string]string `json:"work_title_keywords"` // keyword -> label/domain
	PersonalTitleKeywords []string          `json:"personal_title_keywords"`
	RecordUnlistedDomains bool              `json:"record_unlisted_domains"`

	// Tray behaviour
	AllowUserPause bool     `json:"allow_user_pause"`
	MaxPause       Duration `json:"max_pause"`
	AllowUserQuit  bool     `json:"allow_user_quit"`
	SubmitInterval Duration `json:"submit_interval"`

	// Timesheet suggestions
	RoundToMinutes int `json:"round_to_minutes"`

	// Security / global admin
	AdminIdleTimeout Duration `json:"admin_idle_timeout"` // re-prompt after this idle time

	// Notifications
	NotificationPollInterval Duration `json:"notification_poll_interval"`
	ToastAppID               string   `json:"toast_app_id"`
	HealthAlerts             bool     `json:"health_alerts"`          // disk full / restart needed / failing disk
	RestartReminderAfter     Duration `json:"restart_reminder_after"` // uptime before "please restart" when updates are pending
	SupportURL               string   `json:"support_url"`            // optional "Contact IT" link on alerts

	// ---- System service ----
	TelemetryInterval           Duration `json:"telemetry_interval"`
	SoftwareInterval            Duration `json:"software_interval"`
	TelemetryRefreshMinGap      Duration `json:"telemetry_refresh_min_gap"`
	CollectWindowsUpdateHistory bool     `json:"collect_windows_update_history"`
	DetectPublicIP              bool     `json:"detect_public_ip"`
	PublicIPEndpoint            string   `json:"public_ip_endpoint"`

	// ---- Shared ----
	PipeName      string `json:"pipe_name"`
	RetentionDays int    `json:"retention_days"`
	LogLevel      string `json:"log_level"` // debug | info | warn | error

	// compiled
	projectRe []*regexp.Regexp
}

// Default returns the baseline configuration.
func Default() *Config {
	return &Config{
		PollInterval:       Duration(2 * time.Second),
		IdleThreshold:      Duration(5 * time.Minute),
		MinSessionDuration: Duration(15 * time.Second),
		MaxHeartbeatGap:    Duration(30 * time.Second),
		// "_" counts as a separator so "P-1023_Model.rvt" yields "P-1023".
		ProjectCodePatterns: []string{`(?:^|[^A-Za-z0-9])(P-[A-Z0-9]+)(?:[^A-Za-z0-9]|$)`},

		AutoDiscoverDropbox: true,
		WatchedExtensions:   []string{".dwg", ".rvt", ".rfa", ".max", ".skp", ".layout"},
		FileEventDebounce:   Duration(3 * time.Second),

		TrackBrowsers: true,
		WorkDomains: []string{
			"imaker-group.co", "odoo.com", "dropbox.com", "autodesk.com",
			"acc.autodesk.com", "sketchup.com", "chaos.com", "office.com",
			"sharepoint.com", "teams.microsoft.com",
		},
		PersonalDomains: []string{
			"gmail.com", "mail.google.com", "outlook.live.com", "yahoo.com",
			"facebook.com", "instagram.com", "tiktok.com", "netflix.com",
			"youtube.com", "whatsapp.com", "web.whatsapp.com",
		},
		WorkTitleKeywords: map[string]string{
			"Odoo":       "odoo",
			"Dropbox":    "dropbox.com",
			"Autodesk":   "autodesk.com",
			"SharePoint": "sharepoint.com",
		},
		PersonalTitleKeywords: []string{
			"Gmail", "WhatsApp", "Facebook", "Instagram", "YouTube", "Netflix",
			"Bank", "Banking", "Emirates NBD", "ADCB", "FAB ", "Mashreq",
		},
		RecordUnlistedDomains: false,

		AllowUserPause: true,
		MaxPause:       Duration(60 * time.Minute),
		AllowUserQuit:  false,
		SubmitInterval: Duration(30 * time.Second),

		RoundToMinutes: 15,

		AdminIdleTimeout: Duration(15 * time.Minute),

		NotificationPollInterval: Duration(30 * time.Second),
		ToastAppID:               "IMAKER.EndpointAgent",
		HealthAlerts:             true,
		RestartReminderAfter:     Duration(72 * time.Hour),

		TelemetryInterval:           Duration(6 * time.Hour),
		SoftwareInterval:            Duration(24 * time.Hour),
		TelemetryRefreshMinGap:      Duration(60 * time.Second),
		CollectWindowsUpdateHistory: true,
		DetectPublicIP:              true,
		PublicIPEndpoint:            "https://api.ipify.org",

		PipeName:      DefaultPipeName,
		RetentionDays: 90,
		LogLevel:      "info",
	}
}

// ProgramDataDir returns %ProgramData%\Imaker (machine-wide, service-owned).
func ProgramDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = filepath.Join(os.TempDir(), "ProgramData")
	}
	return filepath.Join(base, "Imaker")
}

// UserDataDir returns %LOCALAPPDATA%\Imaker (per-user, tray-owned).
func UserDataDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		if h, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(h, ".local", "share")
		} else {
			base = os.TempDir()
		}
	}
	return filepath.Join(base, "Imaker")
}

// DefaultPath is the machine-wide config path.
func DefaultPath() string { return filepath.Join(ProgramDataDir(), "agent.json") }

// Load reads the config at path, applying defaults for missing fields.
// A missing file is not an error.
func Load(path string) (*Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// defaults
	case err != nil:
		return nil, fmt.Errorf("read config: %w", err)
	default:
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate normalises values and compiles regexes.
func (c *Config) Validate() error {
	if c.PollInterval.D() < 500*time.Millisecond {
		c.PollInterval = Duration(2 * time.Second)
	}
	if c.IdleThreshold.D() < 30*time.Second {
		return fmt.Errorf("idle_threshold must be >= 30s")
	}
	if c.MaxHeartbeatGap.D() < 3*c.PollInterval.D() {
		c.MaxHeartbeatGap = Duration(3 * c.PollInterval.D())
	}
	if c.NotificationPollInterval.D() < 5*time.Second {
		c.NotificationPollInterval = Duration(30 * time.Second)
	}
	if c.ToastAppID == "" {
		c.ToastAppID = "IMAKER.EndpointAgent"
	}
	if c.RoundToMinutes <= 0 {
		c.RoundToMinutes = 15
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = 90
	}
	if c.PipeName == "" {
		c.PipeName = DefaultPipeName
	}
	for i, e := range c.WatchedExtensions {
		e = strings.ToLower(strings.TrimSpace(e))
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		c.WatchedExtensions[i] = e
	}
	c.projectRe = c.projectRe[:0]
	for _, p := range c.ProjectCodePatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("invalid project_code_patterns entry %q: %w", p, err)
		}
		c.projectRe = append(c.projectRe, re)
	}
	return nil
}

// ProjectRegexps returns the compiled project-code patterns.
func (c *Config) ProjectRegexps() []*regexp.Regexp { return c.projectRe }

// WriteExample writes the defaults to path (used by `service install` so IT
// has a file to edit). Existing files are left untouched.
func WriteExample(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(Default(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
