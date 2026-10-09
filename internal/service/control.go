package service

import (
	"context"
	"encoding/json"
	"fmt"

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
