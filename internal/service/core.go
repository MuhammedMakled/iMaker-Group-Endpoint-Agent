// Package service contains the SYSTEM service core: the RPC handlers exposed
// on the named pipe, the telemetry/software schedulers and the machine-wide
// activity store. The Windows SCM wrapper lives in service_windows.go; this
// file is OS-independent so the handlers can be tested anywhere.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/store"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/telemetry"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/tracker"
)

// TelemetrySource abstracts the (Windows-only) collectors.
type TelemetrySource interface {
	Collect(ctx context.Context) protocol.TelemetrySnapshot
	Software(ctx context.Context) protocol.SoftwareInventory
	// Identity is the fast asset-identity lookup (serial, asset tag).
	Identity(ctx context.Context) protocol.AssetIdentity
}

// Core is the service's state and business logic.
type Core struct {
	cfg       *config.Config
	log       *slog.Logger
	src       TelemetrySource
	dataDir   string
	startedAt time.Time
	hostname  string

	sessions  *store.DailyLog
	files     *store.DailyLog
	telemHist *store.DailyLog

	mu          sync.Mutex
	latest      *protocol.TelemetrySnapshot
	software    *protocol.SoftwareInventory
	lastRefresh time.Time
	collecting  sync.Mutex // serialises WMI collections

	seenMu  sync.Mutex
	seenIDs map[string]time.Time // de-dupes resubmitted sessions

	Notify     *NotificationCenter
	identity   *protocol.AssetIdentity
	identityAt time.Time
}

// NewCore opens the stores under dataDir (normally %ProgramData%\Imaker\data).
func NewCore(cfg *config.Config, log *slog.Logger, src TelemetrySource, dataDir string) (*Core, error) {
	c := &Core{cfg: cfg, log: log, src: src, dataDir: dataDir, startedAt: time.Now(), seenIDs: map[string]time.Time{}}
	c.hostname, _ = os.Hostname()
	var err error
	if c.sessions, err = store.NewDailyLog(filepath.Join(dataDir, "activity"), "sessions"); err != nil {
		return nil, err
	}
	if c.files, err = store.NewDailyLog(filepath.Join(dataDir, "activity"), "file-events"); err != nil {
		return nil, err
	}
	if c.telemHist, err = store.NewDailyLog(filepath.Join(dataDir, "telemetry"), "telemetry"); err != nil {
		return nil, err
	}
	if c.Notify, err = NewNotificationCenter(filepath.Join(dataDir, "notifications")); err != nil {
		return nil, err
	}
	c.loadCached()
	return c, nil
}

// Register wires RPC handlers into the mux.
func (c *Core) Register(m *ipc.Mux) {
	m.Handle(protocol.MethodPing, c.handlePing)
	m.Handle(protocol.MethodActivitySubmit, c.handleActivitySubmit)
	m.Handle(protocol.MethodActivityQuery, c.handleActivityQuery)
	m.Handle(protocol.MethodActivitySummary, c.handleActivitySummary)
	m.Handle(protocol.MethodTelemetryGet, c.handleTelemetryGet)
	m.Handle(protocol.MethodSoftwareList, c.handleSoftwareList)
	m.Handle(protocol.MethodIdentity, c.handleIdentity)
	m.Handle(protocol.MethodNotifyPoll, c.handleNotifyPoll)
	m.Handle(protocol.MethodNotifyAck, c.handleNotifyAck)
	m.HandleAdmin(protocol.MethodNotifySend, c.handleNotifySend)
	m.HandleAdmin(protocol.MethodNotifyList, c.handleNotifyList)
	// Phase 3: m.HandleAdmin("action.restart", ...), "action.rename", "deploy.install"
}

// RunSchedulers collects telemetry/software on their intervals and prunes
// old data daily. Blocks until ctx is cancelled.
func (c *Core) RunSchedulers(ctx context.Context) {
	// Stagger the first run so boot isn't slowed down.
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}
	c.refreshTelemetry(ctx)
	c.refreshSoftware(ctx)

	tt := time.NewTicker(c.cfg.TelemetryInterval.D())
	st := time.NewTicker(c.cfg.SoftwareInterval.D())
	pt := time.NewTicker(24 * time.Hour)
	defer tt.Stop()
	defer st.Stop()
	defer pt.Stop()
	c.prune()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tt.C:
			c.refreshTelemetry(ctx)
		case <-st.C:
			c.refreshSoftware(ctx)
		case <-pt.C:
			c.prune()
		}
	}
}

func (c *Core) prune() {
	for _, l := range []*store.DailyLog{c.sessions, c.files, c.telemHist} {
		if n, err := l.Prune(c.cfg.RetentionDays); err == nil && n > 0 {
			c.log.Info("pruned old data files", "count", n)
		}
	}
}

func (c *Core) refreshTelemetry(ctx context.Context) protocol.TelemetrySnapshot {
	c.collecting.Lock()
	defer c.collecting.Unlock()
	snap := c.src.Collect(ctx)
	c.mu.Lock()
	c.latest = &snap
	c.lastRefresh = time.Now()
	c.mu.Unlock()
	if err := writeJSON(filepath.Join(c.dataDir, "telemetry", "latest.json"), snap); err != nil {
		c.log.Warn("persist telemetry", "err", err)
	}
	_ = c.telemHist.Append(snap.CollectedAt, snap)
	c.log.Info("telemetry collected", "ms", snap.DurationMs, "errors", len(snap.Errors))
	if fired := EvaluateHealth(c.Notify, HealthAlertConfig{
		Enabled:           c.cfg.HealthAlerts,
		RestartAfterHours: c.cfg.RestartReminderAfter.D().Hours(),
		SupportURL:        c.cfg.SupportURL,
	}, snap); len(fired) > 0 {
		c.log.Info("health alerts queued", "rules", fired)
	}
	return snap
}

func (c *Core) refreshSoftware(ctx context.Context) protocol.SoftwareInventory {
	c.collecting.Lock()
	defer c.collecting.Unlock()
	inv := c.src.Software(ctx)
	c.mu.Lock()
	c.software = &inv
	c.mu.Unlock()
	if err := writeJSON(filepath.Join(c.dataDir, "software", "latest.json"), inv); err != nil {
		c.log.Warn("persist software inventory", "err", err)
	}
	c.log.Info("software inventory collected", "count", inv.Count)
	return inv
}

func (c *Core) loadCached() {
	var snap protocol.TelemetrySnapshot
	if readJSON(filepath.Join(c.dataDir, "telemetry", "latest.json"), &snap) == nil {
		c.latest = &snap
	}
	var inv protocol.SoftwareInventory
	if readJSON(filepath.Join(c.dataDir, "software", "latest.json"), &inv) == nil {
		c.software = &inv
	}
}

// ---- RPC handlers ----

func (c *Core) handlePing(ctx context.Context, _ json.RawMessage) (any, error) {
	caller := ipc.CallerFrom(ctx)
	return protocol.PingResult{
		AgentVersion:  config.Version,
		SchemaVersion: protocol.SchemaVersion,
		Hostname:      c.hostname,
		StartedAt:     c.startedAt,
		Caller:        caller.User,
		CallerIsAdmin: caller.IsAdmin,
	}, nil
}

const maxSessionLength = 24 * time.Hour

func (c *Core) handleActivitySubmit(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.ActivitySubmitParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if len(p.Sessions)+len(p.FileEvents) > 5000 {
		return nil, ipc.InvalidParams("batch too large")
	}
	caller := ipc.CallerFrom(ctx)
	now := time.Now()
	var res protocol.ActivitySubmitResult

	for _, s := range p.Sessions {
		if s.ID == "" || s.End.Before(s.Start) || s.End.Sub(s.Start) > maxSessionLength || s.Start.After(now.Add(5*time.Minute)) {
			continue
		}
		if c.alreadySeen(s.ID, now) {
			res.AcceptedSessions++ // idempotent: treat a resend as success
			continue
		}
		// Identity comes from the pipe client's token, never from the payload,
		// unless the caller is SYSTEM/admin (e.g. a migration tool).
		if caller.User != "" && !caller.IsAdmin {
			s.User, s.UserSID = caller.User, caller.SID
		}
		if s.Hostname == "" {
			s.Hostname = c.hostname
		}
		s.Duration = s.End.Sub(s.Start)
		s.DurationSec = int64(s.Duration / time.Second)
		if err := c.sessions.Append(s.Start, s); err != nil {
			return nil, err
		}
		res.AcceptedSessions++
	}
	for _, f := range p.FileEvents {
		if f.Path == "" || f.Time.IsZero() {
			continue
		}
		if caller.User != "" && !caller.IsAdmin {
			f.User = caller.User
		}
		if err := c.files.Append(f.Time, f); err != nil {
			return nil, err
		}
		res.AcceptedFileEvents++
	}
	return res, nil
}

func (c *Core) alreadySeen(id string, now time.Time) bool {
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	if _, ok := c.seenIDs[id]; ok {
		return true
	}
	c.seenIDs[id] = now
	if len(c.seenIDs) > 20000 {
		for k, t := range c.seenIDs {
			if now.Sub(t) > 2*time.Hour {
				delete(c.seenIDs, k)
			}
		}
	}
	return false
}

// effectiveUser enforces that non-admins can only read their own activity.
func effectiveUser(caller ipc.Caller, requested string) (string, error) {
	if caller.IsAdmin {
		return requested, nil
	}
	if caller.User == "" {
		return "", &protocol.RPCError{Code: protocol.ErrUnauthorized, Message: "caller identity unknown"}
	}
	if requested != "" && !strings.EqualFold(requested, caller.User) {
		return "", &protocol.RPCError{Code: protocol.ErrUnauthorized, Message: "you can only view your own activity"}
	}
	return caller.User, nil
}

func (c *Core) loadActivity(from, to time.Time, user string) ([]protocol.WorkSession, []protocol.FileEvent, error) {
	rawS, err := c.sessions.ReadRange(from, to)
	if err != nil {
		return nil, nil, err
	}
	rawF, err := c.files.ReadRange(from, to)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	var sessions []protocol.WorkSession
	for _, s := range store.DecodeAll[protocol.WorkSession](rawS) {
		if seen[s.ID] || s.End.Before(from) || s.Start.After(to) {
			continue
		}
		if user != "" && !strings.EqualFold(s.User, user) {
			continue
		}
		seen[s.ID] = true
		sessions = append(sessions, s)
	}
	var files []protocol.FileEvent
	for _, f := range store.DecodeAll[protocol.FileEvent](rawF) {
		if f.Time.Before(from) || f.Time.After(to) {
			continue
		}
		if user != "" && !strings.EqualFold(f.User, user) {
			continue
		}
		files = append(files, f)
	}
	store.SortByTime(sessions, func(s protocol.WorkSession) time.Time { return s.Start })
	store.SortByTime(files, func(f protocol.FileEvent) time.Time { return f.Time })
	return sessions, files, nil
}

func (c *Core) handleActivityQuery(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.ActivityQueryParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if p.To.IsZero() {
		p.To = time.Now()
	}
	if p.From.IsZero() {
		p.From = p.To.Add(-24 * time.Hour)
	}
	if p.To.Before(p.From) || p.To.Sub(p.From) > 93*24*time.Hour {
		return nil, ipc.InvalidParams("range must be positive and at most 93 days")
	}
	user, err := effectiveUser(ipc.CallerFrom(ctx), p.User)
	if err != nil {
		return nil, err
	}
	s, f, err := c.loadActivity(p.From, p.To, user)
	if err != nil {
		return nil, err
	}
	return protocol.ActivityQueryResult{Sessions: s, FileEvents: f}, nil
}

func (c *Core) handleActivitySummary(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.ActivitySummaryParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	day := time.Now()
	if p.Date != "" {
		d, err := time.ParseInLocation("2006-01-02", p.Date, time.Local)
		if err != nil {
			return nil, ipc.InvalidParams("date must be YYYY-MM-DD")
		}
		day = d
	}
	y, m, d := day.Date()
	from := time.Date(y, m, d, 0, 0, 0, 0, time.Local)
	to := from.Add(24*time.Hour - time.Nanosecond)
	user, err := effectiveUser(ipc.CallerFrom(ctx), p.User)
	if err != nil {
		return nil, err
	}
	sessions, _, err := c.loadActivity(from, to, user)
	if err != nil {
		return nil, err
	}
	return protocol.ActivitySummaryResult{
		Suggestions: tracker.Summarize(sessions, c.cfg.RoundToMinutes, time.Local),
	}, nil
}

func (c *Core) handleTelemetryGet(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.TelemetryGetParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	c.mu.Lock()
	latest, last := c.latest, c.lastRefresh
	c.mu.Unlock()
	if p.Refresh || latest == nil {
		if latest != nil && time.Since(last) < c.cfg.TelemetryRefreshMinGap.D() && !ipc.CallerFrom(ctx).IsAdmin {
			return *latest, nil // rate-limited: serve cached
		}
		snap := c.refreshTelemetry(ctx)
		return snap, nil
	}
	return *latest, nil
}

func (c *Core) handleSoftwareList(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.SoftwareListParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	c.mu.Lock()
	inv := c.software
	c.mu.Unlock()
	if p.Refresh || inv == nil {
		fresh := c.refreshSoftware(ctx)
		inv = &fresh
	}
	out := *inv
	out.Items = telemetry.FilterSoftware(inv.Items, p.Filter)
	out.Count = len(out.Items)
	return out, nil
}

func (c *Core) handleIdentity(ctx context.Context, raw json.RawMessage) (any, error) {
	var p struct {
		Refresh bool `json:"refresh"`
	}
	_ = ipc.DecodeParams(raw, &p)
	c.mu.Lock()
	id, at := c.identity, c.identityAt
	c.mu.Unlock()
	// Identity WMI queries are cheap (<1 s); cache for 10 minutes so a newly
	// set asset tag shows up quickly.
	if id == nil || p.Refresh || time.Since(at) > 10*time.Minute {
		fresh := c.src.Identity(ctx)
		c.mu.Lock()
		c.identity, c.identityAt = &fresh, time.Now()
		c.mu.Unlock()
		id = &fresh
	}
	return *id, nil
}

func (c *Core) handleNotifySend(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.NotifySendParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	if p.Source == "" {
		p.Source = "cli"
	}
	n, err := c.Notify.Send(p)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	c.log.Info("notification queued", "id", n.ID, "title", n.Title, "by", ipc.CallerFrom(ctx).User, "users", n.Users)
	return n, nil
}

func (c *Core) handleNotifyPoll(ctx context.Context, _ json.RawMessage) (any, error) {
	user := ipc.CallerFrom(ctx).User
	if user == "" {
		return protocol.NotifyPollResult{}, nil
	}
	return protocol.NotifyPollResult{Notifications: c.Notify.Pending(user)}, nil
}

func (c *Core) handleNotifyAck(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.NotifyAckParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	user := ipc.CallerFrom(ctx).User
	if user == "" {
		return nil, &protocol.RPCError{Code: protocol.ErrUnauthorized, Message: "caller identity unknown"}
	}
	return map[string]int{"acked": len(p.IDs)}, c.Notify.Ack(user, p.IDs)
}

func (c *Core) handleNotifyList(context.Context, json.RawMessage) (any, error) {
	return protocol.NotifyListResult{Notifications: c.Notify.List()}, nil
}

// ---- helpers ----

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New("empty file")
	}
	return json.Unmarshal(b, v)
}
