package tracker

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// Close reasons recorded on a WorkSession.
const (
	CloseSwitch    = "switch"
	CloseIdle      = "idle"
	CloseGap       = "gap"
	CloseUntracked = "untracked"
	ClosePaused    = "paused"
	CloseShutdown  = "shutdown"
)

// AggregatorConfig tunes session building.
type AggregatorConfig struct {
	MaxGap     time.Duration // a missing-sample gap longer than this splits a session (sleep, hang)
	MinSession time.Duration // sessions shorter than this are discarded (alt-tab flicker)
	User       string
	Hostname   string
}

// Aggregator folds heartbeats into WorkSessions. It is safe for concurrent use.
type Aggregator struct {
	mu   sync.Mutex
	cfg  AggregatorConfig
	cur  *protocol.WorkSession
	last time.Time // time of the last heartbeat folded into cur
	emit func(protocol.WorkSession)
}

// NewAggregator creates an aggregator that calls emit for every closed session.
func NewAggregator(cfg AggregatorConfig, emit func(protocol.WorkSession)) *Aggregator {
	return &Aggregator{cfg: cfg, emit: emit}
}

func sessionKey(app protocol.AppKind, category, project, file, domain string) string {
	return strings.Join([]string{string(app), category, project, strings.ToLower(file), domain}, "\x1f")
}

func (a *Aggregator) curKey() string {
	c := a.cur
	return sessionKey(c.App, c.Category, c.ProjectCode, c.FileName, c.Domain)
}

// Observe folds one heartbeat.
func (a *Aggregator) Observe(hb protocol.Heartbeat) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Idle: close at the moment input stopped, so idle time is never billed.
	if hb.Idle {
		if a.cur != nil {
			end := hb.IdleSince
			if end.Before(a.cur.Start) {
				end = a.cur.Start
			}
			if end.After(a.last) {
				end = a.last
			}
			a.closeLocked(end, CloseIdle)
		}
		return
	}
	if !hb.Trackable {
		if a.cur != nil {
			a.closeLocked(hb.Time, CloseUntracked)
		}
		return
	}

	key := sessionKey(hb.App, hb.Category, hb.ProjectCode, hb.FileName, hb.Domain)
	if a.cur != nil {
		switch {
		case a.cfg.MaxGap > 0 && hb.Time.Sub(a.last) > a.cfg.MaxGap:
			a.closeLocked(a.last, CloseGap)
		case key != a.curKey():
			a.closeLocked(hb.Time, CloseSwitch)
		}
	}
	if a.cur == nil {
		a.cur = &protocol.WorkSession{
			ID:          NewID(),
			User:        a.cfg.User,
			Hostname:    a.cfg.Hostname,
			App:         hb.App,
			Process:     hb.Process,
			Category:    hb.Category,
			ProjectCode: hb.ProjectCode,
			FileName:    hb.FileName,
			Domain:      hb.Domain,
			Start:       hb.Time,
		}
	}
	a.cur.Heartbeats++
	a.last = hb.Time
}

// ObserveFileEvent credits a save to the open session when it is for the
// same file or project. It returns true if the event was attributed.
func (a *Aggregator) ObserveFileEvent(ev protocol.FileEvent) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur == nil || !a.cur.App.IsDesign() {
		return false
	}
	sameFile := a.cur.FileName != "" && strings.EqualFold(a.cur.FileName, ev.FileName)
	sameProject := a.cur.ProjectCode != "" && a.cur.ProjectCode == ev.ProjectCode
	if sameFile || sameProject {
		a.cur.FileSaves++
		return true
	}
	return false
}

// Flush closes any open session (pause, logoff, shutdown).
func (a *Aggregator) Flush(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur != nil {
		a.closeLocked(a.last, reason)
	}
}

// Current returns a copy of the open session, if any.
func (a *Aggregator) Current() (protocol.WorkSession, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur == nil {
		return protocol.WorkSession{}, false
	}
	s := *a.cur
	s.End = a.last
	s.Duration = s.End.Sub(s.Start)
	s.DurationSec = int64(s.Duration / time.Second)
	return s, true
}

func (a *Aggregator) closeLocked(end time.Time, reason string) {
	s := *a.cur
	a.cur = nil
	if end.Before(s.Start) {
		end = s.Start
	}
	s.End = end
	s.Duration = end.Sub(s.Start)
	s.DurationSec = int64(s.Duration / time.Second)
	s.CloseReason = reason
	if s.Duration < a.cfg.MinSession {
		return
	}
	if a.emit != nil {
		a.emit(s)
	}
}

func NewID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------

// UnassignedProject is used when no project code could be detected.
const UnassignedProject = "UNASSIGNED"

// Summarize rolls sessions up into per-day/per-user/per-project timesheet
// suggestions. Only Design and Browser-Work time is billable; Browser-Other
// is excluded. Minutes are rounded UP to roundTo (e.g. 15) per project-day.
func Summarize(sessions []protocol.WorkSession, roundTo int, loc *time.Location) []protocol.TimesheetSuggestion {
	if loc == nil {
		loc = time.Local
	}
	type agg struct {
		s     protocol.TimesheetSuggestion
		apps  map[string]bool
		files map[string]bool
	}
	groups := map[string]*agg{}
	for _, s := range sessions {
		if s.Category != protocol.CategoryDesign && s.Category != protocol.CategoryBrowserWork {
			continue
		}
		date := s.Start.In(loc).Format("2006-01-02")
		proj := s.ProjectCode
		if proj == "" {
			proj = UnassignedProject
		}
		k := date + "|" + strings.ToLower(s.User) + "|" + proj
		g, ok := groups[k]
		if !ok {
			g = &agg{
				s:     protocol.TimesheetSuggestion{Date: date, User: s.User, ProjectCode: proj},
				apps:  map[string]bool{},
				files: map[string]bool{},
			}
			groups[k] = g
		}
		g.s.Sessions++
		g.s.FileSaves += s.FileSaves
		g.s.TotalMinutes += s.End.Sub(s.Start).Minutes()
		g.apps[string(s.App)] = true
		if s.FileName != "" {
			g.files[s.FileName] = true
		}
	}
	out := make([]protocol.TimesheetSuggestion, 0, len(groups))
	for _, g := range groups {
		g.s.Apps = sortedKeys(g.apps)
		g.s.Files = sortedKeys(g.files)
		g.s.TotalMinutes = math.Round(g.s.TotalMinutes*10) / 10
		g.s.RoundedHours = roundUpHours(g.s.TotalMinutes, roundTo)
		out = append(out, g.s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date < out[j].Date
		}
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].TotalMinutes > out[j].TotalMinutes
	})
	return out
}

func roundUpHours(minutes float64, roundTo int) float64 {
	if roundTo <= 0 {
		roundTo = 15
	}
	blocks := math.Ceil(minutes / float64(roundTo))
	return blocks * float64(roundTo) / 60
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
