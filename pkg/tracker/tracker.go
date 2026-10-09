package tracker

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// WindowInfo describes the current foreground window.
type WindowInfo struct {
	Handle  uintptr
	PID     uint32
	Process string // full image path or exe name
	Title   string
}

// Platform abstracts the OS calls the tracker needs.
type Platform interface {
	// ForegroundWindow returns ok=false when there is no foreground window
	// (locked workstation, secure desktop, UAC prompt).
	ForegroundWindow() (WindowInfo, bool, error)
	// IdleDuration returns the time since the last keyboard/mouse input.
	IdleDuration() (time.Duration, error)
}

// DomainProvider optionally resolves the active tab's domain for a browser
// window. Implementations: a managed browser extension talking to the tray
// over native messaging (recommended), or UI Automation on the address bar.
// Must return only the host — never a path or query.
type DomainProvider interface {
	ActiveDomain(w WindowInfo) (domain string, ok bool)
}

// Options configures a Tracker.
type Options struct {
	PollInterval  time.Duration
	IdleThreshold time.Duration
	Platform      Platform
	Classifier    *Classifier
	Aggregator    *Aggregator
	Domains       DomainProvider // may be nil
	Logger        *slog.Logger
	Now           func() time.Time // for tests
}

// Status is a lightweight snapshot for the tray UI.
type Status struct {
	Paused      bool
	PausedUntil time.Time
	Idle        bool
	App         protocol.AppKind
	ProjectCode string
	FileName    string
	Category    string
	SessionFor  time.Duration
}

// Tracker samples the foreground window on a fixed interval.
type Tracker struct {
	opt Options

	mu          sync.Mutex
	pausedUntil time.Time
	status      Status
}

func New(opt Options) *Tracker {
	if opt.PollInterval <= 0 {
		opt.PollInterval = 2 * time.Second
	}
	if opt.IdleThreshold <= 0 {
		opt.IdleThreshold = 5 * time.Minute
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	return &Tracker{opt: opt}
}

// Pause stops tracking until the given time (closes the open session).
func (t *Tracker) Pause(until time.Time) {
	t.mu.Lock()
	t.pausedUntil = until
	t.mu.Unlock()
	t.opt.Aggregator.Flush(ClosePaused)
	t.opt.Logger.Info("tracking paused", "until", until)
}

// Resume cancels a pause.
func (t *Tracker) Resume() {
	t.mu.Lock()
	t.pausedUntil = time.Time{}
	t.mu.Unlock()
	t.opt.Logger.Info("tracking resumed")
}

// Status returns the latest snapshot.
func (t *Tracker) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

// Run blocks until ctx is cancelled, then flushes the open session.
func (t *Tracker) Run(ctx context.Context) {
	tick := time.NewTicker(t.opt.PollInterval)
	defer tick.Stop()
	defer t.opt.Aggregator.Flush(CloseShutdown)
	t.Sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.Sample()
		}
	}
}

// Sample takes one reading. Exported for tests and for on-demand refresh.
func (t *Tracker) Sample() {
	now := t.opt.Now()

	t.mu.Lock()
	paused := !t.pausedUntil.IsZero() && now.Before(t.pausedUntil)
	pausedUntil := t.pausedUntil
	if !paused {
		t.pausedUntil = time.Time{}
	}
	t.mu.Unlock()
	if paused {
		t.setStatus(Status{Paused: true, PausedUntil: pausedUntil})
		return
	}

	idleFor, err := t.opt.Platform.IdleDuration()
	if err != nil {
		t.opt.Logger.Debug("idle query failed", "err", err)
		idleFor = 0
	}
	if idleFor >= t.opt.IdleThreshold {
		t.opt.Aggregator.Observe(protocol.Heartbeat{
			Time: now, Idle: true, IdleSince: now.Add(-idleFor),
		})
		t.setStatus(Status{Idle: true})
		return
	}

	w, ok, err := t.opt.Platform.ForegroundWindow()
	if err != nil {
		t.opt.Logger.Debug("foreground query failed", "err", err)
	}
	if !ok || err != nil {
		t.opt.Aggregator.Observe(protocol.Heartbeat{Time: now, Trackable: false})
		t.setStatus(Status{})
		return
	}

	var domain string
	if t.opt.Domains != nil && AppForProcess(w.Process) == protocol.AppBrowser {
		domain, _ = t.opt.Domains.ActiveDomain(w)
	}
	hb := t.opt.Classifier.Classify(w.Process, w.Title, domain)
	hb.Time = now
	t.opt.Aggregator.Observe(hb)

	st := Status{App: hb.App, ProjectCode: hb.ProjectCode, FileName: hb.FileName, Category: hb.Category}
	if cur, ok := t.opt.Aggregator.Current(); ok {
		st.SessionFor = cur.Duration
	}
	t.setStatus(st)
}

func (t *Tracker) setStatus(s Status) {
	t.mu.Lock()
	t.status = s
	t.mu.Unlock()
}
