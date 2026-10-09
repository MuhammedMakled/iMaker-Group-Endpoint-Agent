package protocol

import "time"

// ---- Services ("servers" the user sees) ----

const (
	MethodServiceList    = "service.list"    // admin
	MethodServiceControl = "service.control" // privileged
)

type ServiceInfo struct {
	Name        string `json:"name"`         // service key, e.g. "Spooler"
	DisplayName string `json:"display_name"` // "Print Spooler"
	Status      string `json:"status"`       // Running | Stopped | Paused | StartPending | ...
	StartType   string `json:"start_type"`   // Automatic | Automatic (Delayed) | Manual | Disabled
	PID         uint32 `json:"pid,omitempty"`
	Description string `json:"description,omitempty"`
	CanStop     bool   `json:"can_stop"`
	Account     string `json:"account,omitempty"` // LogOnAs
}

type ServiceListParams struct {
	Filter string `json:"filter,omitempty"` // case-insensitive substring on name/display
	// OnlyRunning, when true, returns just running services.
	OnlyRunning bool `json:"only_running,omitempty"`
}

type ServiceListResult struct {
	Services []ServiceInfo `json:"services"`
	Count    int           `json:"count"`
}

// ServiceAction values.
const (
	SvcStart   = "start"
	SvcStop    = "stop"
	SvcRestart = "restart"
)

type ServiceControlParams struct {
	Name   string `json:"name"`
	Action string `json:"action"` // start | stop | restart
	Reason string `json:"reason,omitempty"`
}

type ServiceControlResult struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Status string `json:"status"` // resulting status
}

// ---- Startup apps ----

const (
	MethodStartupList   = "startup.list"   // admin
	MethodStartupToggle = "startup.toggle" // privileged
)

type StartupItem struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"` // HKLM Run | HKCU Run | Startup folder | Scheduled task
	Scope    string `json:"scope"`    // machine | user
	Enabled  bool   `json:"enabled"`
	// ID uniquely identifies the item for toggling (location-specific).
	ID string `json:"id"`
}

type StartupListResult struct {
	Items []StartupItem `json:"items"`
}

type StartupToggleParams struct {
	ID     string `json:"id"`
	Enable bool   `json:"enable"`
	Reason string `json:"reason,omitempty"`
}

type StartupToggleResult struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// ---- Processes (Task Manager) ----

const (
	MethodProcessList = "process.list" // admin
	MethodProcessKill = "process.kill" // privileged
)

type ProcessInfo struct {
	PID          uint32    `json:"pid"`
	Name         string    `json:"name"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	MemoryBytes  uint64    `json:"memory_bytes"`
	MemoryMB     float64   `json:"memory_mb"`
	CPUPercent   float64   `json:"cpu_percent"`
	User         string    `json:"user,omitempty"`
	StartTime    time.Time `json:"start_time,omitempty"`
}

type ProcessListResult struct {
	Processes []ProcessInfo `json:"processes"`
	Count     int           `json:"count"`
}

type ProcessKillParams struct {
	PID    uint32 `json:"pid"`
	Name   string `json:"name,omitempty"` // optional safety cross-check
	Reason string `json:"reason,omitempty"`
}

type ProcessKillResult struct {
	PID    uint32 `json:"pid"`
	Killed bool   `json:"killed"`
}

// ---- Bluetooth ----

const (
	MethodBluetoothStatus = "bluetooth.status" // admin
	MethodBluetoothSet    = "bluetooth.set"    // privileged
)

type BluetoothStatus struct {
	Present bool   `json:"present"`
	On      bool   `json:"on"`
	State   string `json:"state"` // On | Off | Unknown | NotPresent
}

type BluetoothSetParams struct {
	On     bool   `json:"on"`
	Reason string `json:"reason,omitempty"`
}
