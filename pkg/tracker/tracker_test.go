package tracker

import (
	"regexp"
	"testing"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

var projRe = []*regexp.Regexp{regexp.MustCompile(`(?:^|[^A-Za-z0-9])(P-[A-Z0-9]+)(?:[^A-Za-z0-9]|$)`)}

func testFilter() *BrowserFilter {
	return &BrowserFilter{
		WorkDomains:           []string{"imaker-group.co", "dropbox.com"},
		PersonalDomains:       []string{"gmail.com", "mail.google.com", "facebook.com"},
		WorkTitleKeywords:     map[string]string{"Odoo": "odoo"},
		PersonalTitleKeywords: []string{"Gmail", "Bank"},
	}
}

func TestExtractDesignFile(t *testing.T) {
	cases := map[string]string{
		`Autodesk AutoCAD 2025 - [C:\Proj\P-1023_Plan.dwg]`:                "P-1023_Plan.dwg",
		`Autodesk AutoCAD 2024  P-1023_Plan.dwg`:                           "P-1023_Plan.dwg",
		`Autodesk Revit 2024.1 - [P-1023_Model.rvt - Floor Plan: Level 1]`: "P-1023_Model.rvt",
		`P-1023_scene.max - Autodesk 3ds Max 2024`:                         "P-1023_scene.max",
		`P-2001 Villa Facade.skp* - SketchUp Pro 2024`:                     "P-2001 Villa Facade.skp",
		`Autodesk Revit 2024 - Home`:                                       "",
		`Untitled - SketchUp Pro 2024`:                                     "",
	}
	for title, want := range cases {
		if got := ExtractDesignFile(title); got != want {
			t.Errorf("%q: got %q want %q", title, got, want)
		}
	}
}

func TestClassifyDesign(t *testing.T) {
	c := NewClassifier(projRe, testFilter())
	hb := c.Classify(`C:\Program Files\Autodesk\Revit 2024\Revit.exe`,
		`Autodesk Revit 2024.1 - [P-1023_Model.rvt - 3D View: {3D}]`, "")
	if hb.App != protocol.AppRevit || !hb.Trackable || hb.ProjectCode != "P-1023" || hb.FileName != "P-1023_Model.rvt" {
		t.Fatalf("unexpected: %+v", hb)
	}
	// Project code only in the title, not the file name.
	hb = c.Classify("3dsmax.exe", "scene_v3.max - Autodesk 3ds Max 2024 - P-7788", "")
	if hb.ProjectCode != "P-7788" || hb.FileName != "scene_v3.max" {
		t.Fatalf("unexpected: %+v", hb)
	}
	hb = c.Classify("notepad.exe", "P-1 notes.txt - Notepad", "")
	if hb.Trackable || hb.App != protocol.AppOther {
		t.Fatalf("notepad must not be tracked: %+v", hb)
	}
}

func TestBrowserPrivacy(t *testing.T) {
	f := testFilter()
	cases := []struct {
		title, hint, cat, domain string
		private                  bool
	}{
		{"New tab - Personal - Microsoft Edge [InPrivate]", "", "", "", true},
		{"Mozilla Firefox Private Browsing", "", "", "", true},
		{"Inbox (3) - someone@gmail.com - Gmail", "", protocol.CategoryBrowserOther, "", false},
		{"Sales Orders - Odoo", "", protocol.CategoryBrowserWork, "odoo", false},
		{"whatever", "https://www.dropbox.com/home/P-1023?preview=x.dwg", protocol.CategoryBrowserWork, "dropbox.com", false},
		{"whatever", "https://mail.google.com/mail/u/0/#inbox", protocol.CategoryBrowserOther, "", false},
		{"whatever", "https://news.example.org:8443/a/b?q=1", protocol.CategoryBrowserOther, "", false},
		{"My Bank - Online Banking", "", protocol.CategoryBrowserOther, "", false},
	}
	for _, c := range cases {
		v := f.Classify(c.title, c.hint)
		if v.Private != c.private || v.Category != c.cat || v.Domain != c.domain {
			t.Errorf("%q/%q => %+v", c.title, c.hint, v)
		}
	}
	f.RecordUnlistedDomains = true
	if v := f.Classify("x", "https://news.example.org:8443/a"); v.Domain != "news.example.org" {
		t.Errorf("unlisted domain should be kept when enabled: %+v", v)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"https://WWW.Example.com/path?q=1": "example.com",
		"example.com:443":                  "example.com",
		"sub.dropbox.com":                  "sub.dropbox.com",
		"":                                 "",
		"not a domain":                     "",
	} {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

// ---- Aggregator ----

func hb(t0 time.Time, sec int, file string) protocol.Heartbeat {
	return protocol.Heartbeat{
		Time: t0.Add(time.Duration(sec) * time.Second), App: protocol.AppAutoCAD, Process: "acad.exe",
		Category: protocol.CategoryDesign, ProjectCode: "P-1", FileName: file, Trackable: true,
	}
}

func TestAggregatorSwitchAndIdle(t *testing.T) {
	var out []protocol.WorkSession
	a := NewAggregator(AggregatorConfig{MaxGap: 30 * time.Second, MinSession: 10 * time.Second, User: "u"},
		func(s protocol.WorkSession) { out = append(out, s) })
	t0 := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)

	for s := 0; s <= 60; s += 2 {
		a.Observe(hb(t0, s, "a.dwg"))
	}
	for s := 62; s <= 120; s += 2 { // switch file
		a.Observe(hb(t0, s, "b.dwg"))
	}
	// User walked away at 100s; idle detected at 400s (threshold 5m).
	a.Observe(protocol.Heartbeat{Time: t0.Add(400 * time.Second), Idle: true, IdleSince: t0.Add(100 * time.Second)})

	if len(out) != 2 {
		t.Fatalf("want 2 sessions, got %d: %+v", len(out), out)
	}
	if out[0].FileName != "a.dwg" || out[0].Duration != 62*time.Second || out[0].CloseReason != CloseSwitch {
		t.Errorf("session 1: %+v", out[0])
	}
	if out[1].FileName != "b.dwg" || out[1].End != t0.Add(100*time.Second) || out[1].CloseReason != CloseIdle {
		t.Errorf("session 2 should be trimmed to idle start: %+v", out[1])
	}
}

func TestAggregatorGapFlickerAndSaves(t *testing.T) {
	var out []protocol.WorkSession
	a := NewAggregator(AggregatorConfig{MaxGap: 30 * time.Second, MinSession: 10 * time.Second},
		func(s protocol.WorkSession) { out = append(out, s) })
	t0 := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)

	a.Observe(hb(t0, 0, "a.dwg"))
	a.Observe(hb(t0, 4, "a.dwg"))                                // 4s flicker
	a.Observe(protocol.Heartbeat{Time: t0.Add(6 * time.Second)}) // untracked -> discarded (<10s)
	a.Observe(hb(t0, 10, "a.dwg"))
	a.Observe(hb(t0, 30, "a.dwg"))
	if !a.ObserveFileEvent(protocol.FileEvent{FileName: "A.DWG"}) {
		t.Error("save should be attributed")
	}
	a.Observe(hb(t0, 300, "a.dwg")) // laptop slept: gap split
	a.Flush(CloseShutdown)

	if len(out) != 1 {
		t.Fatalf("want 1 session (flicker and 0s tail dropped), got %d: %+v", len(out), out)
	}
	if out[0].Duration != 20*time.Second || out[0].CloseReason != CloseGap || out[0].FileSaves != 1 {
		t.Errorf("unexpected: %+v", out[0])
	}
}

func TestSummarize(t *testing.T) {
	t0 := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	mk := func(proj, cat string, mins int) protocol.WorkSession {
		return protocol.WorkSession{User: "IMAKER\\ali", App: protocol.AppRevit, Category: cat, ProjectCode: proj,
			FileName: proj + ".rvt", Start: t0, End: t0.Add(time.Duration(mins) * time.Minute)}
	}
	got := Summarize([]protocol.WorkSession{
		mk("P-1", protocol.CategoryDesign, 50),
		mk("P-1", protocol.CategoryDesign, 20),
		mk("", protocol.CategoryDesign, 5),
		mk("", protocol.CategoryBrowserOther, 120), // never billable
	}, 15, time.UTC)
	if len(got) != 2 {
		t.Fatalf("want 2 suggestions, got %+v", got)
	}
	if got[0].ProjectCode != "P-1" || got[0].TotalMinutes != 70 || got[0].RoundedHours != 1.25 || got[0].Sessions != 2 {
		t.Errorf("P-1: %+v", got[0])
	}
	if got[1].ProjectCode != UnassignedProject || got[1].RoundedHours != 0.25 {
		t.Errorf("unassigned: %+v", got[1])
	}
}

// ---- Tracker with a fake platform ----

type fakePlatform struct {
	win  WindowInfo
	ok   bool
	idle time.Duration
}

func (f *fakePlatform) ForegroundWindow() (WindowInfo, bool, error) { return f.win, f.ok, nil }
func (f *fakePlatform) IdleDuration() (time.Duration, error)        { return f.idle, nil }

func TestTrackerPauseAndIdle(t *testing.T) {
	var out []protocol.WorkSession
	agg := NewAggregator(AggregatorConfig{MaxGap: time.Minute}, func(s protocol.WorkSession) { out = append(out, s) })
	fp := &fakePlatform{ok: true, win: WindowInfo{Process: "acad.exe", Title: "Autodesk AutoCAD 2025 - [P-9_x.dwg]"}}
	now := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	tr := New(Options{Platform: fp, Classifier: NewClassifier(projRe, testFilter()), Aggregator: agg,
		IdleThreshold: 5 * time.Minute, Now: func() time.Time { return now }})

	for i := 0; i < 10; i++ {
		tr.Sample()
		now = now.Add(2 * time.Second)
	}
	if st := tr.Status(); st.ProjectCode != "P-9" || st.App != protocol.AppAutoCAD {
		t.Fatalf("status: %+v", st)
	}
	tr.Pause(now.Add(10 * time.Minute))
	if len(out) != 1 || out[0].CloseReason != ClosePaused {
		t.Fatalf("pause should close session: %+v", out)
	}
	tr.Sample()
	if !tr.Status().Paused {
		t.Fatal("expected paused status")
	}
	tr.Resume()
	fp.idle = 6 * time.Minute
	tr.Sample()
	if !tr.Status().Idle {
		t.Fatal("expected idle status")
	}
}

// ---- File filter ----

func TestFileFilter(t *testing.T) {
	f := NewFileFilter([]string{".dwg", ".rvt", ".max", ".skp"})
	accept := []string{`C:\Dropbox\P-1\plan.dwg`, `C:\Dropbox\P-1\Model.RVT`, `D:\x\scene.max`}
	reject := []string{
		`C:\Dropbox\P-1\Model.0003.rvt`, `C:\Dropbox\P-1\~$plan.dwg`, `C:\Dropbox\P-1\plan.dwl`,
		`C:\Dropbox\P-1\plan.bak`, `C:\Dropbox\P-1\notes.txt`, `C:\Dropbox\.dropbox.cache\a.dwg`,
		`C:\Dropbox\P-1\Backup\Model.rvt`,
	}
	for _, p := range accept {
		if !f.Accept(p) {
			t.Errorf("should accept %s", p)
		}
	}
	for _, p := range reject {
		if f.Accept(p) {
			t.Errorf("should reject %s", p)
		}
	}
	d := NewDebouncer(3 * time.Second)
	n := time.Now()
	if !d.Allow("a", n) || d.Allow("A", n.Add(time.Second)) || !d.Allow("a", n.Add(4*time.Second)) {
		t.Error("debouncer misbehaves")
	}
}

func TestParseDropboxInfo(t *testing.T) {
	got := ParseDropboxInfo([]byte(`{"personal":{"path":"C:\\Users\\a\\Dropbox"},"business":{"path":"C:\\Users\\a\\Dropbox (IMAKER)"}}`))
	if len(got) != 2 || got[0] != `C:\Users\a\Dropbox (IMAKER)` {
		t.Fatalf("got %v", got)
	}
}
