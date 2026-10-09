// Package protocol defines the data contracts shared by the tray app, the
// system service and (later) the Command Center / Odoo backend.
//
// Every type here is plain JSON so the same schema can be shipped over the
// local named pipe today and over REST/WebSocket tomorrow without change.
package protocol

import "time"

// SchemaVersion is bumped whenever a breaking change is made to these types.
const SchemaVersion = 1

// AppKind identifies the tracked application family.
type AppKind string

const (
	AppAutoCAD        AppKind = "autocad"
	AppRevit          AppKind = "revit"
	App3dsMax         AppKind = "3dsmax"
	AppSketchUp       AppKind = "sketchup"
	AppSketchUpLayout AppKind = "sketchup_layout"
	AppBrowser        AppKind = "browser"
	AppOther          AppKind = "other"
)

// IsDesign reports whether the app is one of the tracked CAD/CGI tools.
func (k AppKind) IsDesign() bool {
	switch k {
	case AppAutoCAD, AppRevit, App3dsMax, AppSketchUp, AppSketchUpLayout:
		return true
	}
	return false
}

// Activity categories. Browser titles are NEVER stored; only the category
// and (for allow-listed work sites) the domain.
const (
	CategoryDesign       = "Design"
	CategoryBrowserWork  = "Browser - Work"
	CategoryBrowserOther = "Browser - Other"
)

// Heartbeat is a single 2-second sample of the foreground state. Heartbeats
// are aggregated in memory and are not persisted individually.
type Heartbeat struct {
	Time        time.Time `json:"time"`
	App         AppKind   `json:"app"`
	Process     string    `json:"process"`
	ProjectCode string    `json:"project_code,omitempty"`
	FileName    string    `json:"file_name,omitempty"`
	Category    string    `json:"category,omitempty"`
	Domain      string    `json:"domain,omitempty"`
	Idle        bool      `json:"idle"`
	IdleSince   time.Time `json:"idle_since,omitempty"`
	// Trackable is false for untracked apps, locked screens and private
	// browser windows. A non-trackable heartbeat closes the open session.
	Trackable bool `json:"trackable"`
}

// WorkSession is a contiguous block of activity on one app/project/file.
// This is the unit that becomes a 1-tap timesheet suggestion.
type WorkSession struct {
	ID          string        `json:"id"`
	User        string        `json:"user"` // DOMAIN\user, verified by the service where possible
	UserSID     string        `json:"user_sid,omitempty"`
	Hostname    string        `json:"hostname"`
	App         AppKind       `json:"app"`
	Process     string        `json:"process"`
	Category    string        `json:"category"`
	ProjectCode string        `json:"project_code,omitempty"`
	FileName    string        `json:"file_name,omitempty"`
	Domain      string        `json:"domain,omitempty"`
	Start       time.Time     `json:"start"`
	End         time.Time     `json:"end"`
	Duration    time.Duration `json:"duration_ns"`
	DurationSec int64         `json:"duration_sec"`
	Heartbeats  int           `json:"heartbeats"`
	FileSaves   int           `json:"file_saves"`
	CloseReason string        `json:"close_reason"` // switch | idle | gap | untracked | paused | shutdown
}

// FileEvent is a save/modify of a tracked design file in a watched folder.
type FileEvent struct {
	Time        time.Time `json:"time"`
	User        string    `json:"user,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Path        string    `json:"path"`
	FileName    string    `json:"file_name"`
	Extension   string    `json:"extension"`
	Action      string    `json:"action"` // modified | added | renamed
	SizeBytes   int64     `json:"size_bytes"`
	ModTime     time.Time `json:"mod_time"`
	ProjectCode string    `json:"project_code,omitempty"`
}

// TimesheetSuggestion is a per-day, per-project rollup of work sessions,
// pre-rounded so the dashboard can offer a one-tap "accept" action.
type TimesheetSuggestion struct {
	Date         string   `json:"date"` // YYYY-MM-DD, agent local time
	User         string   `json:"user"`
	ProjectCode  string   `json:"project_code"`
	Apps         []string `json:"apps"`
	Files        []string `json:"files,omitempty"`
	Sessions     int      `json:"sessions"`
	FileSaves    int      `json:"file_saves"`
	TotalMinutes float64  `json:"total_minutes"`
	RoundedHours float64  `json:"rounded_hours"`
}
