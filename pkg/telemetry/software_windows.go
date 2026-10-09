//go:build windows

package telemetry

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

const (
	uninstall64 = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	uninstall32 = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
)

// CollectSoftware scans the machine-wide Uninstall keys (64- and 32-bit
// views) plus the per-user keys of every loaded profile under HKEY_USERS
// (catches per-user installers such as Dropbox, Zoom, VS Code).
func CollectSoftware() protocol.SoftwareInventory {
	inv := protocol.SoftwareInventory{CollectedAt: time.Now().UTC()}
	inv.Hostname, _ = os.Hostname()

	var entries []UninstallEntry
	scan := func(root registry.Key, rootName, path, arch, scope, sid string, view uint32) {
		es, err := readUninstallKey(root, rootName, path, arch, scope, sid, view)
		if err != nil && err != registry.ErrNotExist {
			inv.Errors = append(inv.Errors, fmt.Sprintf("%s\\%s: %v", rootName, path, err))
		}
		entries = append(entries, es...)
	}

	scan(registry.LOCAL_MACHINE, "HKLM", uninstall64, "x64", "machine", "", registry.WOW64_64KEY)
	scan(registry.LOCAL_MACHINE, "HKLM", uninstall32, "x86", "machine", "", registry.WOW64_64KEY)

	for _, sid := range loadedUserSIDs() {
		scan(registry.USERS, "HKU", sid+`\`+uninstall64, "user", "user", sid, 0)
	}

	inv.Items = BuildInventory(entries)
	inv.Count = len(inv.Items)
	return inv
}

func readUninstallKey(root registry.Key, rootName, path, arch, scope, sid string, view uint32) ([]UninstallEntry, error) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|view)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	out := make([]UninstallEntry, 0, len(subs))
	for _, sub := range subs {
		sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE|view)
		if err != nil {
			continue
		}
		e := UninstallEntry{
			KeyPath:      rootName + `\` + path + `\` + sub,
			Architecture: arch,
			Scope:        scope,
			UserSID:      sid,
		}
		e.DisplayName = str(sk, "DisplayName")
		e.DisplayVersion = str(sk, "DisplayVersion")
		e.Publisher = str(sk, "Publisher")
		e.InstallDate = str(sk, "InstallDate")
		e.InstallLocation = str(sk, "InstallLocation")
		e.ParentKeyName = str(sk, "ParentKeyName")
		e.ReleaseType = str(sk, "ReleaseType")
		if v, _, err := sk.GetIntegerValue("SystemComponent"); err == nil {
			e.SystemComponent = v
		}
		sk.Close()
		out = append(out, e)
	}
	return out, nil
}

func str(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

// loadedUserSIDs lists real user hives loaded under HKEY_USERS (S-1-5-21-…),
// skipping *_Classes hives and service accounts.
func loadedUserSIDs() []string {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "S-1-5-21-") && !strings.HasSuffix(n, "_Classes") {
			out = append(out, n)
		}
	}
	return out
}
