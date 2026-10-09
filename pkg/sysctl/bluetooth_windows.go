//go:build windows

package sysctl

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// Bluetooth is toggled through the WinRT Radio Management API, driven from a
// hidden PowerShell host (keeps the agent CGO-free). The same API backs the
// Settings → Bluetooth toggle, so behaviour matches the OS.

const psGetBluetooth = `
$ErrorActionPreference='Stop'
Function Await($t,$ty){ $as=[WindowsRuntimeSystemExtensions].GetMethods()|?{$_.Name -eq 'GetAwaiter' -and $_.GetParameters().Count -eq 1}|select -First 1
 $g=$as.MakeGenericMethod($ty).Invoke($null,@($t)); $g.GetResult() }
[void][Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime]
[void][Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime]
$radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
$bt = $radios | ? { $_.Kind -eq 'Bluetooth' } | select -First 1
if ($bt -eq $null) { 'NOTPRESENT' } else { $bt.State.ToString() }
`

const psSetBluetoothFmt = `
$ErrorActionPreference='Stop'
Function Await($t,$ty){ $as=[WindowsRuntimeSystemExtensions].GetMethods()|?{$_.Name -eq 'GetAwaiter' -and $_.GetParameters().Count -eq 1}|select -First 1
 $g=$as.MakeGenericMethod($ty).Invoke($null,@($t)); $g.GetResult() }
[void][Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime]
[void][Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime]
$null = Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus])
$radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
$bt = $radios | ? { $_.Kind -eq 'Bluetooth' } | select -First 1
if ($bt -eq $null) { 'NOTPRESENT'; exit }
$state = [Windows.Devices.Radios.RadioState]::%s
$null = Await ($bt.SetStateAsync($state)) ([Windows.Devices.Radios.RadioAccessStatus])
$bt.State.ToString()
`

// GetBluetooth returns the Bluetooth radio state.
func GetBluetooth() (protocol.BluetoothStatus, error) {
	out, err := runPowerShell(psGetBluetooth, 20*time.Second)
	if err != nil {
		return protocol.BluetoothStatus{State: "Unknown"}, err
	}
	return parseBluetoothState(out), nil
}

// SetBluetooth turns Bluetooth on or off.
func SetBluetooth(on bool) (protocol.BluetoothStatus, error) {
	state := "Off"
	if on {
		state = "On"
	}
	script := strings.Replace(psSetBluetoothFmt, "%s", state, 1)
	out, err := runPowerShell(script, 25*time.Second)
	if err != nil {
		return protocol.BluetoothStatus{State: "Unknown"}, err
	}
	return parseBluetoothState(out), nil
}

func parseBluetoothState(raw string) protocol.BluetoothStatus {
	s := strings.TrimSpace(raw)
	// take the last non-empty line
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			s = t
			break
		}
	}
	switch strings.ToLower(s) {
	case "on":
		return protocol.BluetoothStatus{Present: true, On: true, State: "On"}
	case "off":
		return protocol.BluetoothStatus{Present: true, On: false, State: "Off"}
	case "notpresent":
		return protocol.BluetoothStatus{Present: false, State: "NotPresent"}
	}
	return protocol.BluetoothStatus{Present: true, State: "Unknown"}
}

func runPowerShell(script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
