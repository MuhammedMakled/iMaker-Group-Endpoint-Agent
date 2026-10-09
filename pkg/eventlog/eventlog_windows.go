//go:build windows

package eventlog

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// psScript returns the Security-log events (4720/4728/4732/4756) since a
// placeholder time as compact JSON. __START__ is substituted at call time so
// the Go string contains no backticks (which would close the raw literal).
const psScript = `
$ErrorActionPreference='Stop'
$start=[datetime]::Parse('__START__').ToUniversalTime()
try {
 $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4728,4732,4756; StartTime=$start} -ErrorAction Stop
} catch { '[]'; exit }
$out = foreach ($e in $ev) {
  $p = $e.Properties | ForEach-Object { $_.Value }
  [pscustomobject]@{
    EventID = $e.Id
    Time = $e.TimeCreated.ToUniversalTime().ToString('o')
    Target = [string]$p[0]
    Subject = [string]$p[5]
    Group = [string]$p[2]
    Message = (($e.Message -split '\r?\n') | Select-Object -First 1)
  }
}
$out | ConvertTo-Json -Compress -Depth 3
`

func psQuery(since time.Time) string {
	return strings.ReplaceAll(psScript, "__START__", since.UTC().Format("2006-01-02T15:04:05Z"))
}

// Query returns account-management events since the given time.
func Query(since time.Time) ([]SecurityEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", psQuery(since))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Get-WinEvent: %w", err)
	}
	return ParseEvents(out)
}

// EnableAuditPolicy turns on the audit subcategories that generate 4720/4728/
// 4732/4756. Requires admin. Best-effort.
func EnableAuditPolicy() error {
	for _, sub := range []string{"User Account Management", "Security Group Management"} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, "auditpol.exe", "/set",
			"/subcategory:"+sub, "/success:enable", "/failure:enable")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		err := cmd.Run()
		cancel()
		if err != nil {
			return fmt.Errorf("auditpol %q: %w", sub, err)
		}
	}
	return nil
}
