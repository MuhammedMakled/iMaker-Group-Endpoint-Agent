package tracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// FileFilter decides which file-system notifications are real design-file
// saves. CAD apps write lots of noise (temp files, lock files, backups).
type FileFilter struct {
	Extensions map[string]bool // ".dwg" -> true
}

var (
	// Revit rolling backups: Model.0001.rvt
	revitBackupRe = regexp.MustCompile(`(?i)\.\d{4}\.(rvt|rfa)$`)
	noisePrefixes = []string{"~$", "~", ".~", "._"}
	noiseSuffixes = []string{".tmp", ".bak", ".sv$", ".dwl", ".dwl2", ".skb", ".autosave", ".ac$"}
	noiseDirs     = []string{`\backup\`, `/backup/`, `\revit_temp\`, `\.dropbox.cache\`, `/.dropbox.cache/`}
)

func NewFileFilter(exts []string) *FileFilter {
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[strings.ToLower(e)] = true
	}
	return &FileFilter{Extensions: m}
}

// Accept reports whether full path p is a tracked design file.
func (f *FileFilter) Accept(p string) bool {
	lp := strings.ToLower(p)
	for _, d := range noiseDirs {
		if strings.Contains(lp, d) {
			return false
		}
	}
	name := baseName(lp)
	for _, pre := range noisePrefixes {
		if strings.HasPrefix(name, pre) {
			return false
		}
	}
	for _, suf := range noiseSuffixes {
		if strings.HasSuffix(name, suf) {
			return false
		}
	}
	if revitBackupRe.MatchString(name) {
		return false
	}
	ext := ""
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		ext = name[i:]
	}
	return f.Extensions[ext]
}

// Debouncer suppresses repeated events for the same path within a window
// (a single CAD save typically produces 3–10 notifications).
type Debouncer struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]time.Time
}

func NewDebouncer(window time.Duration) *Debouncer {
	return &Debouncer{window: window, last: map[string]time.Time{}}
}

// Allow returns true if the path has not fired within the window.
func (d *Debouncer) Allow(path string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := strings.ToLower(path)
	if t, ok := d.last[k]; ok && now.Sub(t) < d.window {
		return false
	}
	d.last[k] = now
	if len(d.last) > 4096 { // bound memory
		for p, t := range d.last {
			if now.Sub(t) > d.window {
				delete(d.last, p)
			}
		}
	}
	return true
}

// BuildFileEvent stats the file and fills a protocol.FileEvent.
func BuildFileEvent(path, action string, now time.Time, projectCode func(name string) string) (protocol.FileEvent, bool) {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return protocol.FileEvent{}, false
	}
	name := filepath.Base(path)
	ev := protocol.FileEvent{
		Time:      now,
		Path:      path,
		FileName:  name,
		Extension: strings.ToLower(filepath.Ext(name)),
		Action:    action,
		SizeBytes: st.Size(),
		ModTime:   st.ModTime(),
	}
	if projectCode != nil {
		// Folder names often carry the project code (Dropbox\Projects\P-1023 Villa\...).
		ev.ProjectCode = projectCode(name)
		if ev.ProjectCode == "" {
			ev.ProjectCode = projectCode(filepath.Dir(path))
		}
	}
	return ev, true
}

// DiscoverDropboxPaths reads %LOCALAPPDATA%\Dropbox\info.json (and the
// %APPDATA% fallback) to find personal/business sync roots.
func DiscoverDropboxPaths() []string {
	var candidates []string
	for _, env := range []string{"LOCALAPPDATA", "APPDATA"} {
		if base := os.Getenv(env); base != "" {
			candidates = append(candidates, filepath.Join(base, "Dropbox", "info.json"))
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		for _, p := range ParseDropboxInfo(b) {
			if !seen[strings.ToLower(p)] {
				seen[strings.ToLower(p)] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// ParseDropboxInfo extracts sync roots from Dropbox's info.json, which looks like
// {"personal": {"path": "C:\\Users\\x\\Dropbox", ...}, "business": {...}}.
func ParseDropboxInfo(b []byte) []string {
	var m map[string]struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	var out []string
	for _, k := range []string{"business", "personal"} {
		if v, ok := m[k]; ok && v.Path != "" {
			out = append(out, v.Path)
		}
	}
	for k, v := range m { // any other team/account entries
		if k != "business" && k != "personal" && v.Path != "" {
			out = append(out, v.Path)
		}
	}
	return out
}
