package service

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/tracker"
)

const (
	defaultNotifyTTL = 72 * time.Hour
	maxNotifyTTL     = 30 * 24 * time.Hour
	keepAfterExpiry  = 7 * 24 * time.Hour
	maxNotifications = 500
)

// NotificationCenter is the service-side queue of user notifications. It is
// persisted to disk so messages survive service restarts and reach users
// who sign in later (until they expire).
type NotificationCenter struct {
	mu    sync.Mutex
	path  string
	state notifyState
	now   func() time.Time
}

type notifyState struct {
	Items     []protocol.Notification `json:"items"`
	Delivered map[string][]string     `json:"delivered"`  // id -> lower-case users
	RuleFired map[string]time.Time    `json:"rule_fired"` // health-rule cooldowns
}

// NewNotificationCenter loads (or creates) the state file in dir.
func NewNotificationCenter(dir string) (*NotificationCenter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	nc := &NotificationCenter{path: filepath.Join(dir, "notifications.json"), now: time.Now}
	if err := readJSON(nc.path, &nc.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Corrupt file: start fresh rather than failing the service.
		nc.state = notifyState{}
	}
	if nc.state.Delivered == nil {
		nc.state.Delivered = map[string][]string{}
	}
	if nc.state.RuleFired == nil {
		nc.state.RuleFired = map[string]time.Time{}
	}
	return nc, nil
}

// Send validates and queues a notification, returning the stored copy.
func (nc *NotificationCenter) Send(p protocol.NotifySendParams) (protocol.Notification, error) {
	n := p.Notification
	n.Title = strings.TrimSpace(n.Title)
	n.Message = strings.TrimSpace(n.Message)
	if n.Title == "" || n.Message == "" {
		return n, errors.New("title and message are required")
	}
	if len(n.Title) > 120 || len(n.Message) > 1000 {
		return n, errors.New("title max 120 chars, message max 1000 chars")
	}
	switch n.Severity {
	case "":
		n.Severity = protocol.SeverityInfo
	case protocol.SeverityInfo, protocol.SeverityWarning, protocol.SeverityCritical:
	default:
		return n, fmt.Errorf("severity must be info, warning or critical")
	}
	if n.URL != "" {
		u, err := url.Parse(n.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return n, errors.New("url must be an http(s) link")
		}
	}
	now := nc.now()
	ttl := defaultNotifyTTL
	if p.TTL != "" {
		d, err := time.ParseDuration(p.TTL)
		if err != nil || d <= 0 {
			return n, errors.New("ttl must be a duration like 24h")
		}
		ttl = d
	}
	if ttl > maxNotifyTTL {
		ttl = maxNotifyTTL
	}
	if n.ID == "" {
		n.ID = "n-" + now.UTC().Format("20060102150405") + "-" + randHex(4)
	}
	n.CreatedAt = now
	if n.ExpiresAt.IsZero() || p.TTL != "" {
		n.ExpiresAt = now.Add(ttl)
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()
	for _, existing := range nc.state.Items {
		if existing.ID == n.ID {
			return existing, nil // idempotent
		}
	}
	nc.state.Items = append(nc.state.Items, n)
	nc.pruneLocked(now)
	return n, nc.saveLocked()
}

// Pending returns undelivered, unexpired notifications for user (oldest first).
func (nc *NotificationCenter) Pending(user string) []protocol.Notification {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	now := nc.now()
	lu := strings.ToLower(user)
	var out []protocol.Notification
	for _, n := range nc.state.Items {
		if now.After(n.ExpiresAt) || !targets(n, lu) || contains(nc.state.Delivered[n.ID], lu) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// Ack marks notifications as shown to user.
func (nc *NotificationCenter) Ack(user string, ids []string) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	lu := strings.ToLower(user)
	changed := false
	for _, id := range ids {
		if !contains(nc.state.Delivered[id], lu) {
			nc.state.Delivered[id] = append(nc.state.Delivered[id], lu)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return nc.saveLocked()
}

// List returns everything with delivery status, newest first.
func (nc *NotificationCenter) List() []protocol.NotificationStatus {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	now := nc.now()
	out := make([]protocol.NotificationStatus, 0, len(nc.state.Items))
	for _, n := range nc.state.Items {
		out = append(out, protocol.NotificationStatus{
			Notification: n,
			DeliveredTo:  append([]string{}, nc.state.Delivered[n.ID]...),
			Expired:      now.After(n.ExpiresAt),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// FireRule queues n unless rule fired within cooldown. Used by health alerts.
func (nc *NotificationCenter) FireRule(rule string, cooldown time.Duration, n protocol.Notification) (bool, error) {
	nc.mu.Lock()
	last, ok := nc.state.RuleFired[rule]
	now := nc.now()
	if ok && now.Sub(last) < cooldown {
		nc.mu.Unlock()
		return false, nil
	}
	nc.state.RuleFired[rule] = now
	nc.mu.Unlock()
	n.Source = "agent"
	_, err := nc.Send(protocol.NotifySendParams{Notification: n, TTL: cooldown.String()})
	return err == nil, err
}

func (nc *NotificationCenter) pruneLocked(now time.Time) {
	kept := nc.state.Items[:0]
	for _, n := range nc.state.Items {
		if now.Sub(n.ExpiresAt) > keepAfterExpiry {
			delete(nc.state.Delivered, n.ID)
			continue
		}
		kept = append(kept, n)
	}
	nc.state.Items = kept
	if len(nc.state.Items) > maxNotifications {
		drop := nc.state.Items[:len(nc.state.Items)-maxNotifications]
		for _, n := range drop {
			delete(nc.state.Delivered, n.ID)
		}
		nc.state.Items = append([]protocol.Notification{}, nc.state.Items[len(nc.state.Items)-maxNotifications:]...)
	}
}

func (nc *NotificationCenter) saveLocked() error { return writeJSON(nc.path, nc.state) }

func targets(n protocol.Notification, lowerUser string) bool {
	if len(n.Users) == 0 {
		return true
	}
	for _, u := range n.Users {
		u = strings.ToLower(strings.TrimSpace(u))
		// Accept "DOMAIN\user" or just "user".
		if u == lowerUser || (!strings.Contains(u, `\`) && strings.HasSuffix(lowerUser, `\`+u)) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func randHex(n int) string {
	// Reuse the tracker's random ID generator (crypto/rand) and trim it.
	id := tracker.NewID()
	if len(id) > n*2 {
		return id[:n*2]
	}
	return id
}

// ---------------------------------------------------------------------------

// HealthAlertConfig controls the automatic user-facing health alerts.
type HealthAlertConfig struct {
	Enabled           bool
	RestartAfterHours float64
	Cooldown          time.Duration
	SupportURL        string
}

// EvaluateHealth turns a telemetry snapshot into user notifications:
// almost-full drives, a pending restart after updates, and failing disks.
func EvaluateHealth(nc *NotificationCenter, cfg HealthAlertConfig, s protocol.TelemetrySnapshot) []string {
	if !cfg.Enabled || nc == nil {
		return nil
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 24 * time.Hour
	}
	var fired []string
	fire := func(rule string, n protocol.Notification) {
		n.Category = protocol.CategoryHealth
		if n.URL == "" && cfg.SupportURL != "" {
			n.URL, n.ButtonLabel = cfg.SupportURL, "Contact IT"
		}
		if ok, _ := nc.FireRule(rule, cfg.Cooldown, n); ok {
			fired = append(fired, rule)
		}
	}

	for _, v := range s.Volumes {
		if v.LowSpace {
			fire("lowdisk:"+v.DriveLetter, protocol.Notification{
				Title:    fmt.Sprintf("Drive %s is almost full", v.DriveLetter),
				Message:  fmt.Sprintf("Only %.1f GB of %.0f GB is free. Please delete or archive old files (Downloads, Desktop, old renders) so your design apps keep running smoothly.", v.FreeGB, v.SizeGB),
				Severity: protocol.SeverityWarning,
			})
		}
	}
	if s.Updates.RebootPending && cfg.RestartAfterHours > 0 && s.OS.UptimeHours >= cfg.RestartAfterHours {
		fire("restart", protocol.Notification{
			Title:    "Please restart your PC",
			Message:  fmt.Sprintf("Windows has installed updates that need a restart. Your PC has been running for %.0f days — save your work and restart when convenient today.", s.OS.UptimeHours/24),
			Severity: protocol.SeverityWarning,
		})
	}
	for _, d := range s.PhysicalDisks {
		bad := d.Health == "Unhealthy" || (d.SmartPredictFailure != nil && *d.SmartPredictFailure)
		if bad || d.Health == "Warning" {
			fire("disk:"+d.SerialNumber, protocol.Notification{
				Title:    "Your disk is reporting problems",
				Message:  fmt.Sprintf("The disk \"%s\" reports health status %s. Make sure your project files are saved to Dropbox and contact IT so the disk can be checked.", d.Model, d.Health),
				Severity: protocol.SeverityCritical,
			})
		}
	}
	return fired
}
