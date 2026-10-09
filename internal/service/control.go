package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// ControlProvider abstracts the system-control operations (Windows-backed),
// so handlers are testable without touching the machine.
type ControlProvider interface {
	ListServices(filter string, onlyRunning bool) ([]protocol.ServiceInfo, error)
	ControlService(name, action string) (status string, err error)
	ListStartup() ([]protocol.StartupItem, error)
	ToggleStartup(id string, enable bool) error
	ListProcesses() ([]protocol.ProcessInfo, error)
	KillProcess(pid uint32, name string) error
	BluetoothStatus() (protocol.BluetoothStatus, error)
	SetBluetooth(on bool) (protocol.BluetoothStatus, error)
	// v1.4 endpoint controls
	LockSession(sessionID uint32) (protocol.SessionActionResult, error)
	SignoutSession(sessionID uint32) (protocol.SessionActionResult, error)
	ListSessions() ([]protocol.UserSession, error)
	USBStatus() (protocol.USBStatus, error)
	USBSet(mode string) (protocol.USBStatus, error)
	QuerySecurityEvents(since time.Time) ([]EscalationEvent, error)
}

// EscalationEvent is a minimal view of a Windows account-management event,
// decoupled from the Windows-only eventlog package so this file stays portable.
type EscalationEvent struct {
	EventID     int
	Time        time.Time
	TargetUser  string
	GroupName   string
	SubjectUser string
	Privileged  bool // adds to Administrators or similar
	Description string
}

// SetControl installs the system-control backend.
func (c *Core) SetControl(cp ControlProvider) { c.control = cp }

func (c *Core) registerControl(m *ipc.Mux) {
	if c.control == nil {
		return
	}
	// Listing is admin-tier (read-only).
	m.HandleAdmin(protocol.MethodServiceList, c.handleServiceList)
	m.HandleAdmin(protocol.MethodStartupList, c.handleStartupList)
	m.HandleAdmin(protocol.MethodProcessList, c.handleProcessList)
	m.HandleAdmin(protocol.MethodBluetoothStatus, c.handleBluetoothStatus)
	// State changes require the global-admin session (privileged).
	m.HandlePrivileged(protocol.MethodServiceControl, c.handleServiceControl)
	m.HandlePrivileged(protocol.MethodStartupToggle, c.handleStartupToggle)
	m.HandlePrivileged(protocol.MethodProcessKill, c.handleProcessKill)
	m.HandlePrivileged(protocol.MethodBluetoothSet, c.handleBluetoothSet)
	// Remote lock / sign-out
	m.HandleAdmin(protocol.MethodSessionList, c.handleSessionList)
	m.HandlePrivileged(protocol.MethodSessionLock, c.handleSessionLock)
	m.HandlePrivileged(protocol.MethodSessionSignout, c.handleSessionSignout)
	// USB storage control
	m.HandleAdmin(protocol.MethodUSBStatus, c.handleUSBStatus)
	m.HandlePrivileged(protocol.MethodUSBSet, c.handleUSBSet)
	// IP allowlist (read-only view + checker)
	m.HandleAdmin(protocol.MethodIPAllowStatus, c.handleIPAllowStatus)
	m.HandleAdmin(protocol.MethodIPAllowCheck, c.handleIPAllowCheck)
}

func (c *Core) handleSessionList(ctx context.Context, _ json.RawMessage) (any, error) {
	sess, err := c.control.ListSessions()
	if err != nil {
		return nil, err
	}
	return protocol.SessionListResult{Sessions: sess}, nil
}

func (c *Core) handleSessionLock(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.SessionActionParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	res, err := c.control.LockSession(p.SessionID)
	res.Action = "lock"
	c.audit(caller, "session_lock", res.User, "reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return res, nil
}

func (c *Core) handleSessionSignout(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.SessionActionParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	res, err := c.control.SignoutSession(p.SessionID)
	res.Action = "signout"
	c.audit(caller, "session_signout", res.User, "reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return res, nil
}

func (c *Core) handleUSBStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	return c.control.USBStatus()
}

func (c *Core) handleUSBSet(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.USBSetParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	st, err := c.control.USBSet(p.Mode)
	c.audit(caller, "usb_"+p.Mode, "", "reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return st, nil
}

func (c *Core) handleIPAllowStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	return protocol.IPAllowStatus{
		Enabled:         !c.ipAllow.Empty(),
		Rules:           c.ipAllow.Rules(),
		ActiveForRemote: false, // local-pipe only until the Phase-3 uplink
	}, nil
}

func (c *Core) handleIPAllowCheck(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.IPAllowCheckParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	ok, matched := c.ipAllow.Allowed(p.IP)
	return protocol.IPAllowCheckResult{IP: p.IP, Allowed: ok, Matched: matched}, nil
}

func (c *Core) handleServiceList(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.ServiceListParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	svcs, err := c.control.ListServices(p.Filter, p.OnlyRunning)
	if err != nil {
		return nil, err
	}
	return protocol.ServiceListResult{Services: svcs, Count: len(svcs)}, nil
}

func (c *Core) handleServiceControl(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.ServiceControlParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	status, err := c.control.ControlService(p.Name, p.Action)
	c.audit(caller, "service_"+p.Action, p.Name, "reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return protocol.ServiceControlResult{Name: p.Name, Action: p.Action, Status: status}, nil
}

func (c *Core) handleStartupList(ctx context.Context, _ json.RawMessage) (any, error) {
	items, err := c.control.ListStartup()
	if err != nil {
		return nil, err
	}
	return protocol.StartupListResult{Items: items}, nil
}

func (c *Core) handleStartupToggle(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.StartupToggleParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	err := c.control.ToggleStartup(p.ID, p.Enable)
	verb := "disable"
	if p.Enable {
		verb = "enable"
	}
	c.audit(caller, "startup_"+verb, p.ID, "reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return protocol.StartupToggleResult{ID: p.ID, Enabled: p.Enable}, nil
}

func (c *Core) handleProcessList(ctx context.Context, _ json.RawMessage) (any, error) {
	procs, err := c.control.ListProcesses()
	if err != nil {
		return nil, err
	}
	return protocol.ProcessListResult{Processes: procs, Count: len(procs)}, nil
}

func (c *Core) handleProcessKill(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.ProcessKillParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	err := c.control.KillProcess(p.PID, p.Name)
	c.audit(caller, "process_kill", fmt.Sprintf("pid=%d name=%s", p.PID, p.Name), "reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return protocol.ProcessKillResult{PID: p.PID, Killed: true}, nil
}

func (c *Core) handleBluetoothStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	return c.control.BluetoothStatus()
}

func (c *Core) handleBluetoothSet(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.BluetoothSetParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	st, err := c.control.SetBluetooth(p.On)
	onoff := "off"
	if p.On {
		onoff = "on"
	}
	c.audit(caller, "bluetooth_"+onoff, "", "reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return st, nil
}
