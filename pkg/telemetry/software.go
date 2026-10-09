package telemetry

import (
	"sort"
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// UninstallEntry is the raw data read from one Uninstall registry key.
type UninstallEntry struct {
	KeyPath         string
	DisplayName     string
	DisplayVersion  string
	Publisher       string
	InstallDate     string
	InstallLocation string
	SystemComponent uint64
	ParentKeyName   string
	ReleaseType     string
	Architecture    string // x64 | x86 | user
	Scope           string // machine | user
	UserSID         string
}

// Keep reports whether an entry represents user-visible software, matching
// what "Apps & features" shows: no hidden system components, no patches.
func (e UninstallEntry) Keep() bool {
	if strings.TrimSpace(e.DisplayName) == "" || e.SystemComponent == 1 || e.ParentKeyName != "" {
		return false
	}
	switch strings.ToLower(e.ReleaseType) {
	case "update", "hotfix", "security update", "service pack":
		return false
	}
	return true
}

// BuildInventory filters, normalises and de-duplicates entries (same name +
// version + scope appear under both registry views for some installers).
func BuildInventory(entries []UninstallEntry) []protocol.SoftwareItem {
	seen := map[string]bool{}
	out := make([]protocol.SoftwareItem, 0, len(entries))
	for _, e := range entries {
		if !e.Keep() {
			continue
		}
		name := strings.TrimSpace(e.DisplayName)
		ver := strings.TrimSpace(e.DisplayVersion)
		key := strings.ToLower(name + "|" + ver + "|" + e.Scope + "|" + e.UserSID)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, protocol.SoftwareItem{
			Name:            name,
			Version:         ver,
			Publisher:       strings.TrimSpace(e.Publisher),
			InstallDate:     ParseInstallDate(e.InstallDate),
			InstallLocation: strings.TrimSpace(e.InstallLocation),
			Architecture:    e.Architecture,
			Scope:           e.Scope,
			UserSID:         e.UserSID,
			RegistryKey:     e.KeyPath,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// FilterSoftware returns items whose name or publisher contains q (case-insensitive).
func FilterSoftware(items []protocol.SoftwareItem, q string) []protocol.SoftwareItem {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return items
	}
	var out []protocol.SoftwareItem
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Name), q) || strings.Contains(strings.ToLower(it.Publisher), q) {
			out = append(out, it)
		}
	}
	return out
}
