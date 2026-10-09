//go:build windows

package sysctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

const (
	runKeyPath      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	runKey32Path    = `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
	approvedRunHKLM = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
	approvedRunHKCU = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
)

// ListStartup enumerates startup entries from the Run keys (machine + user)
// and the common Startup folder, reporting enabled/disabled per the
// StartupApproved data that Task Manager uses.
func ListStartup() ([]protocol.StartupItem, error) {
	var items []protocol.StartupItem

	items = append(items, runKeyItems(registry.LOCAL_MACHINE, runKeyPath, LocHKLMRun, "machine", approvedRunHKLM)...)
	items = append(items, runKeyItems(registry.LOCAL_MACHINE, runKey32Path, LocHKLMRun32, "machine", approvedRunHKLM)...)
	items = append(items, runKeyItems(registry.CURRENT_USER, runKeyPath, LocHKCURun, "user", approvedRunHKCU)...)
	items = append(items, startupFolderItems()...)
	return items, nil
}

func runKeyItems(root registry.Key, path, location, scope, approvedPath string) []protocol.StartupItem {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	var out []protocol.StartupItem
	for _, n := range names {
		cmd, _, err := k.GetStringValue(n)
		if err != nil {
			continue
		}
		out = append(out, protocol.StartupItem{
			Name:     n,
			Command:  cmd,
			Location: location,
			Scope:    scope,
			Enabled:  approvedEnabled(root, approvedPath, n),
			ID:       EncodeStartupID(location, n),
		})
	}
	return out
}

// approvedEnabled reads StartupApproved: the first byte of the binary value is
// even (0x02/0x06) when enabled, odd (0x03) when disabled by the user.
func approvedEnabled(root registry.Key, approvedPath, name string) bool {
	k, err := registry.OpenKey(root, approvedPath, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return true // no record means enabled
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue(name)
	if err != nil || len(b) == 0 {
		return true
	}
	return b[0]&0x01 == 0
}

func startupFolderItems() []protocol.StartupItem {
	dirs := []struct {
		path, scope string
	}{
		{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`), "machine"},
		{filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`), "user"},
	}
	var out []protocol.StartupItem
	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.EqualFold(filepath.Ext(name), ".ini") {
				continue
			}
			disabled := strings.EqualFold(filepath.Ext(name), ".disabled")
			out = append(out, protocol.StartupItem{
				Name:     strings.TrimSuffix(name, ".disabled"),
				Command:  filepath.Join(d.path, name),
				Location: LocStartupMenu,
				Scope:    d.scope,
				Enabled:  !disabled,
				ID:       EncodeStartupID(LocStartupMenu, filepath.Join(d.path, name)),
			})
		}
	}
	return out
}

// ToggleStartup enables or disables a startup entry.
func ToggleStartup(id string, enable bool) error {
	location, name, err := DecodeStartupID(id)
	if err != nil {
		return err
	}
	switch location {
	case LocHKLMRun, LocHKLMRun32:
		return setApproved(registry.LOCAL_MACHINE, approvedRunHKLM, name, enable)
	case LocHKCURun:
		return setApproved(registry.CURRENT_USER, approvedRunHKCU, name, enable)
	case LocStartupMenu:
		return toggleStartupFile(name, enable)
	}
	return fmt.Errorf("unknown startup location %q", location)
}

// setApproved writes the StartupApproved binary record to enable/disable.
func setApproved(root registry.Key, approvedPath, name string, enable bool) error {
	k, _, err := registry.CreateKey(root, approvedPath, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	// 12-byte record: first byte 0x02 = enabled, 0x03 = disabled; rest zero.
	val := make([]byte, 12)
	if enable {
		val[0] = 0x02
	} else {
		val[0] = 0x03
	}
	return k.SetBinaryValue(name, val)
}

// toggleStartupFile renames a Startup-folder shortcut to <name>.disabled.
func toggleStartupFile(path string, enable bool) error {
	if enable {
		if strings.HasSuffix(path, ".disabled") {
			return os.Rename(path, strings.TrimSuffix(path, ".disabled"))
		}
		disabled := path + ".disabled"
		if _, err := os.Stat(disabled); err == nil {
			return os.Rename(disabled, path)
		}
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return os.Rename(path, path+".disabled")
	}
	return nil
}
