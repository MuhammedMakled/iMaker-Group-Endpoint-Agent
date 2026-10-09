//go:build windows

// Command agent builds ImakerTrayApp.exe — the per-user activity tracker.
//
// It runs in the interactive session with the user's own (standard)
// privileges, samples the foreground window every 2 s, detects idle time,
// watches Dropbox/project folders for CAD saves, builds WorkSessions, stores
// them offline and forwards them to ImakerAgentService over the named pipe.
//
// Build:  GOOS=windows go build -ldflags "-H=windowsgui" -o ImakerTrayApp.exe ./cmd/agent
// Debug:  ImakerTrayApp.exe -console   (no tray icon, logs to the console)
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/logging"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/store"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/tracker"
)

//go:embed assets/icon.ico
var iconICO []byte

// outboxRecord is the envelope queued for delivery to the service.
type outboxRecord struct {
	Kind    string                `json:"kind"` // session | file
	Session *protocol.WorkSession `json:"session,omitempty"`
	File    *protocol.FileEvent   `json:"file,omitempty"`
}

type app struct {
	cfg      *config.Config
	log      *slog.Logger
	tracker  *tracker.Tracker
	agg      *tracker.Aggregator
	watcher  *tracker.FileWatcher
	sessions *store.DailyLog
	files    *store.DailyLog
	outbox   *store.Outbox
	client   *ipc.Client
	dataDir  string

	mu            sync.Mutex
	serviceOnline bool
}

func main() {
	cfgPath := flag.String("config", config.DefaultPath(), "path to agent.json")
	console := flag.Bool("console", false, "run without tray icon and log to stderr")
	flag.Parse()

	// One tracker per user session.
	name, _ := windows.UTF16PtrFromString(`Local\` + config.TrayAppName)
	mutex, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		return
	}
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		cfg = config.Default()
		_ = cfg.Validate()
	}
	dataDir := config.UserDataDir()
	log, closer, err := logging.New(filepath.Join(dataDir, "logs", "tray.log"), cfg.LogLevel, *console)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logging:", err)
		os.Exit(1)
	}
	defer closer.Close()
	slog.SetDefault(log)

	a, err := newApp(cfg, log, dataDir)
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}
	log.Info("tray app starting", "version", config.Version, "user", a.userName(), "config", *cfgPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *console {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		go func() { <-sig; cancel() }()
		a.runWorkers(ctx)
		return
	}

	var wg sync.WaitGroup
	systray.Run(func() {
		a.buildTray(ctx, cancel)
		wg.Add(1)
		go func() { defer wg.Done(); a.runWorkers(ctx) }()
	}, func() {
		cancel()
		wg.Wait() // let the tracker flush the open session and the outbox drain once
	})
}

func newApp(cfg *config.Config, log *slog.Logger, dataDir string) (*app, error) {
	actDir := filepath.Join(dataDir, "activity")
	sessions, err := store.NewDailyLog(actDir, "sessions")
	if err != nil {
		return nil, err
	}
	files, err := store.NewDailyLog(actDir, "file-events")
	if err != nil {
		return nil, err
	}
	outbox, err := store.NewOutbox(filepath.Join(dataDir, "outbox.jsonl"), 50000)
	if err != nil {
		return nil, err
	}
	a := &app{cfg: cfg, log: log, sessions: sessions, files: files, outbox: outbox,
		client: ipc.NewClient(cfg.PipeName), dataDir: dataDir}

	host, _ := os.Hostname()
	a.agg = tracker.NewAggregator(tracker.AggregatorConfig{
		MaxGap:     cfg.MaxHeartbeatGap.D(),
		MinSession: cfg.MinSessionDuration.D(),
		User:       a.userName(),
		Hostname:   host,
	}, a.onSession)

	bf := &tracker.BrowserFilter{
		WorkDomains:           cfg.WorkDomains,
		PersonalDomains:       cfg.PersonalDomains,
		WorkTitleKeywords:     cfg.WorkTitleKeywords,
		PersonalTitleKeywords: cfg.PersonalTitleKeywords,
		RecordUnlistedDomains: cfg.RecordUnlistedDomains,
	}
	if !cfg.TrackBrowsers {
		bf = nil
	}
	classifier := tracker.NewClassifier(cfg.ProjectRegexps(), bf)

	a.tracker = tracker.New(tracker.Options{
		PollInterval:  cfg.PollInterval.D(),
		IdleThreshold: cfg.IdleThreshold.D(),
		Platform:      tracker.NewWin32Platform(),
		Classifier:    classifier,
		Aggregator:    a.agg,
		Logger:        log,
	})

	roots := append([]string{}, cfg.WatchPaths...)
	if cfg.AutoDiscoverDropbox {
		roots = append(roots, tracker.DiscoverDropboxPaths()...)
	}
	if len(roots) > 0 {
		a.watcher = &tracker.FileWatcher{
			Roots:       dedupe(roots),
			Filter:      tracker.NewFileFilter(cfg.WatchedExtensions),
			Debounce:    tracker.NewDebouncer(cfg.FileEventDebounce.D()),
			ProjectCode: func(s string) string { return classifier.ExtractProjectCode(s, "") },
			OnEvent:     a.onFileEvent,
			Logger:      log,
		}
	} else {
		log.Warn("no folders to watch (configure watch_paths or install Dropbox)")
	}

	if n, err := sessions.Prune(cfg.RetentionDays); err == nil && n > 0 {
		log.Info("pruned old activity files", "count", n)
	}
	_, _ = files.Prune(cfg.RetentionDays)
	return a, nil
}

func (a *app) userName() string {
	if u, err := user.Current(); err == nil {
		return u.Username // DOMAIN\user
	}
	return os.Getenv("USERDOMAIN") + `\` + os.Getenv("USERNAME")
}

func (a *app) onSession(s protocol.WorkSession) {
	if err := a.sessions.Append(s.Start, s); err != nil {
		a.log.Error("persist session", "err", err)
	}
	if err := a.outbox.Push(outboxRecord{Kind: "session", Session: &s}); err != nil {
		a.log.Error("queue session", "err", err)
	}
	a.log.Debug("session closed", "app", s.App, "project", s.ProjectCode, "file", s.FileName,
		"sec", s.DurationSec, "reason", s.CloseReason)
}

func (a *app) onFileEvent(ev protocol.FileEvent) {
	ev.User = a.userName()
	ev.Hostname, _ = os.Hostname()
	a.agg.ObserveFileEvent(ev)
	if err := a.files.Append(ev.Time, ev); err != nil {
		a.log.Error("persist file event", "err", err)
	}
	if err := a.outbox.Push(outboxRecord{Kind: "file", File: &ev}); err != nil {
		a.log.Error("queue file event", "err", err)
	}
}

// runWorkers runs tracker, watcher and submitter until ctx is cancelled.
func (a *app) runWorkers(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.tracker.Run(ctx) }()
	go func() { defer wg.Done(); a.submitLoop(ctx) }()
	if a.watcher != nil {
		wg.Add(1)
		go func() { defer wg.Done(); a.watcher.Run(ctx) }()
	}
	wg.Wait()
	// Final best-effort delivery of the session flushed on shutdown.
	fctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a.submitOnce(fctx)
	a.log.Info("tray app stopped")
}

func (a *app) submitLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.SubmitInterval.D())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.submitOnce(ctx)
		}
	}
}

// submitOnce drains the outbox to the service in batches.
func (a *app) submitOnce(ctx context.Context) {
	for {
		raw, err := a.outbox.Peek(500)
		if err != nil || len(raw) == 0 {
			return
		}
		var p protocol.ActivitySubmitParams
		for _, r := range raw {
			var rec outboxRecord
			if json.Unmarshal(r, &rec) != nil {
				continue
			}
			switch {
			case rec.Kind == "session" && rec.Session != nil:
				p.Sessions = append(p.Sessions, *rec.Session)
			case rec.Kind == "file" && rec.File != nil:
				p.FileEvents = append(p.FileEvents, *rec.File)
			}
		}
		err = a.client.Call(ctx, protocol.MethodActivitySubmit, p, nil)
		a.setOnline(err == nil)
		if err != nil {
			a.log.Debug("service unreachable; will retry", "queued", len(raw), "err", err)
			return
		}
		if err := a.outbox.Ack(len(raw)); err != nil {
			a.log.Error("outbox ack", "err", err)
			return
		}
		if len(raw) < 500 {
			return
		}
	}
}

func (a *app) setOnline(v bool) {
	a.mu.Lock()
	a.serviceOnline = v
	a.mu.Unlock()
}

func (a *app) online() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.serviceOnline
}

// ---- Tray UI ----

func (a *app) buildTray(ctx context.Context, cancel context.CancelFunc) {
	systray.SetIcon(iconICO)
	systray.SetTitle("IMAKER Agent")
	systray.SetTooltip("IMAKER Endpoint Agent")

	mStatus := systray.AddMenuItem("Starting…", "Current activity")
	mStatus.Disable()
	mService := systray.AddMenuItem("Service: checking…", "Connection to ImakerAgentService")
	mService.Disable()
	systray.AddSeparator()

	var mPause15, mPause60, mResume *systray.MenuItem
	if a.cfg.AllowUserPause {
		mPause15 = systray.AddMenuItem("Pause tracking for 15 minutes", "Private time — nothing is recorded")
		if a.cfg.MaxPause.D() >= time.Hour {
			mPause60 = systray.AddMenuItem("Pause tracking for 1 hour", "Private time — nothing is recorded")
		}
		mResume = systray.AddMenuItem("Resume tracking", "")
		mResume.Hide()
		systray.AddSeparator()
	}
	mOpen := systray.AddMenuItem("Open my activity folder", "Everything recorded about you is here")
	var mQuit *systray.MenuItem
	if a.cfg.AllowUserQuit {
		systray.AddSeparator()
		mQuit = systray.AddMenuItem("Quit", "")
	}

	clicked := func(m *systray.MenuItem) <-chan struct{} {
		if m == nil {
			return nil
		}
		return m.ClickedCh
	}

	go func() {
		refresh := time.NewTicker(3 * time.Second)
		defer refresh.Stop()
		for {
			select {
			case <-ctx.Done():
				systray.Quit()
				return
			case <-refresh.C:
				st := a.tracker.Status()
				mStatus.SetTitle(statusText(st))
				if a.online() {
					mService.SetTitle(fmt.Sprintf("Service: connected (%d queued)", a.outbox.Len()))
				} else {
					mService.SetTitle(fmt.Sprintf("Service: offline — %d records saved locally", a.outbox.Len()))
				}
				if mResume != nil {
					if st.Paused {
						mResume.Show()
					} else {
						mResume.Hide()
					}
				}
			case <-clicked(mPause15):
				a.tracker.Pause(time.Now().Add(15 * time.Minute))
			case <-clicked(mPause60):
				a.tracker.Pause(time.Now().Add(time.Hour))
			case <-clicked(mResume):
				a.tracker.Resume()
			case <-clicked(mOpen):
				_ = exec.Command("explorer.exe", filepath.Join(a.dataDir, "activity")).Start()
			case <-clicked(mQuit):
				cancel()
			}
		}
	}()
}

func statusText(st tracker.Status) string {
	switch {
	case st.Paused:
		return "Paused until " + st.PausedUntil.Format("15:04")
	case st.Idle:
		return "Idle"
	case st.App == "" || st.App == protocol.AppOther:
		return "Not tracking (no design app in focus)"
	case st.App == protocol.AppBrowser:
		return st.Category
	}
	s := string(st.App)
	if st.ProjectCode != "" {
		s += " · " + st.ProjectCode
	}
	if st.FileName != "" {
		s += " · " + st.FileName
	}
	if st.SessionFor > time.Minute {
		s += fmt.Sprintf(" · %dm", int(st.SessionFor.Minutes()))
	}
	return s
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := filepath.Clean(s)
		if s == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}
