package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// adminBaseline is the set of local administrators the agent considers known.
type adminBaseline struct {
	Known       map[string]string `json:"known"` // sid -> name
	Established time.Time         `json:"established"`
}

// CheckLocalAdmins compares the snapshot's local admins against the saved
// baseline and raises a critical alert for any NOT-previously-seen admin
// account (a common sign of compromise). The first run just records the
// baseline. Accounts the agent itself created (in the audit log) are expected
// and still reported, but noted as agent-created.
func (c *Core) CheckLocalAdmins(snap protocol.TelemetrySnapshot) {
	if c.Notify == nil || len(snap.LocalAdmins) == 0 {
		return
	}
	path := filepath.Join(c.dataDir, "security", "known_admins.json")
	base := loadBaseline(path)

	current := map[string]string{}
	for _, a := range snap.LocalAdmins {
		key := a.SID
		if key == "" {
			key = strings.ToLower(a.Name)
		}
		current[key] = a.Name
	}

	if base == nil {
		// First run: establish the baseline silently.
		saveBaseline(path, &adminBaseline{Known: current, Established: time.Now().UTC()})
		return
	}

	var added []string
	for key, name := range current {
		if _, ok := base.Known[key]; !ok {
			added = append(added, name)
		}
	}
	if len(added) > 0 {
		sort.Strings(added)
		c.log.Warn("new local administrator detected", "accounts", added)
		if c.Notify != nil {
			_, _ = c.Notify.FireRule("new-admin:"+strings.Join(added, ","), 6*time.Hour, protocol.Notification{
				Title:    "Security alert: new administrator account",
				Message:  "A new account with administrator rights appeared on this PC: " + strings.Join(added, ", ") + ". If this wasn't done by IT, contact IMAKER IT immediately.",
				Severity: protocol.SeverityCritical,
				Category: protocol.CategoryPolicy,
			})
		}
		// Merge the new ones into the baseline so we alert once, not every cycle.
		for k, v := range current {
			base.Known[k] = v
		}
		saveBaseline(path, base)
	} else {
		// Keep the baseline current (handles removed admins) without alerting.
		base.Known = current
		saveBaseline(path, base)
	}
}

func loadBaseline(path string) *adminBaseline {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var base adminBaseline
	if json.Unmarshal(b, &base) != nil || base.Known == nil {
		return nil
	}
	return &base
}

func saveBaseline(path string, base *adminBaseline) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	b, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}
