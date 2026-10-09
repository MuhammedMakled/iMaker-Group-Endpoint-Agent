// Package eventlog reads recent Windows Security-log events relevant to
// account-escalation monitoring (user created, added to a privileged group).
// The Windows query lives in eventlog_windows.go; the parsing here is pure and
// unit-tested on any OS.
package eventlog

import (
	"encoding/json"
	"strings"
	"time"
)

// Relevant Security event IDs.
const (
	EventUserCreated       = 4720 // A user account was created
	EventAddedGlobalGroup  = 4728 // Member added to a security-enabled global group
	EventAddedLocalGroup   = 4732 // Member added to a security-enabled local group (e.g. Administrators)
	EventAddedUniversalGrp = 4756 // Member added to a security-enabled universal group
)

// SecurityEvent is one parsed account-management event.
type SecurityEvent struct {
	EventID     int       `json:"event_id"`
	Time        time.Time `json:"time"`
	TargetUser  string    `json:"target_user"`  // the account created or added
	GroupName   string    `json:"group_name"`   // for 4728/4732/4756
	SubjectUser string    `json:"subject_user"` // who performed it
	Description string    `json:"description"`
}

// IsPrivilegedGroupEvent reports whether an event adds a member to a group we
// treat as privileged (Administrators and similar).
func (e SecurityEvent) IsPrivilegedGroupEvent() bool {
	if e.EventID != EventAddedLocalGroup && e.EventID != EventAddedGlobalGroup && e.EventID != EventAddedUniversalGrp {
		return false
	}
	g := strings.ToLower(e.GroupName)
	for _, k := range []string{"admin", "remote desktop", "backup operators", "power users"} {
		if strings.Contains(g, k) {
			return true
		}
	}
	return false
}

type rawEvent struct {
	EventID int    `json:"EventID"`
	Time    string `json:"Time"`
	Target  string `json:"Target"`
	Subject string `json:"Subject"`
	Group   string `json:"Group"`
	Message string `json:"Message"`
}

// ParseEvents decodes the PowerShell JSON (object or array) into SecurityEvents.
func ParseEvents(b []byte) ([]SecurityEvent, error) {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "[]" {
		return nil, nil
	}
	var raws []rawEvent
	if strings.HasPrefix(s, "{") { // a single event is emitted as an object
		var one rawEvent
		if err := json.Unmarshal([]byte(s), &one); err != nil {
			return nil, err
		}
		raws = []rawEvent{one}
	} else if err := json.Unmarshal([]byte(s), &raws); err != nil {
		return nil, err
	}
	out := make([]SecurityEvent, 0, len(raws))
	for _, r := range raws {
		t, _ := time.Parse(time.RFC3339, r.Time)
		out = append(out, SecurityEvent{
			EventID:     r.EventID,
			Time:        t,
			TargetUser:  cleanName(r.Target),
			GroupName:   cleanName(r.Group),
			SubjectUser: cleanName(r.Subject),
			Description: r.Message,
		})
	}
	return out, nil
}

func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" || strings.EqualFold(s, "null") {
		return ""
	}
	return s
}
