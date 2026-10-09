package service

import (
	"strings"
	"testing"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type fakeControl struct {
	stopped   string
	killedPID uint32
	btOn      bool
}

func (f *fakeControl) ListServices(filter string, onlyRunning bool) ([]protocol.ServiceInfo, error) {
	return []protocol.ServiceInfo{{Name: "Spooler", DisplayName: "Print Spooler", Status: "Running", CanStop: true}}, nil
}
func (f *fakeControl) ControlService(name, action string) (string, error) {
	if action == "stop" {
		f.stopped = name
		return "Stopped", nil
	}
	return "Running", nil
}
func (f *fakeControl) ListStartup() ([]protocol.StartupItem, error) {
	return []protocol.StartupItem{{Name: "Dropbox", Enabled: true, ID: "abc"}}, nil
}
func (f *fakeControl) ToggleStartup(id string, enable bool) error { return nil }
func (f *fakeControl) ListProcesses() ([]protocol.ProcessInfo, error) {
	return []protocol.ProcessInfo{{PID: 1234, Name: "chrome.exe", MemoryMB: 500}}, nil
}
func (f *fakeControl) KillProcess(pid uint32, name string) error { f.killedPID = pid; return nil }
func (f *fakeControl) BluetoothStatus() (protocol.BluetoothStatus, error) {
	return protocol.BluetoothStatus{Present: true, On: f.btOn, State: boolState(f.btOn)}, nil
}
func (f *fakeControl) SetBluetooth(on bool) (protocol.BluetoothStatus, error) {
	f.btOn = on
	return protocol.BluetoothStatus{Present: true, On: on, State: boolState(on)}, nil
}
func boolState(b bool) string {
	if b {
		return "On"
	}
	return "Off"
}

func TestControlHandlers(t *testing.T) {
	c, _ := newCore(t)
	fc := &fakeControl{}
	c.SetControl(fc)
	admin := ipc.Caller{User: `IMAKER\it`, IsAdmin: true}

	res, err := call(t, c.handleServiceList, admin, protocol.ServiceListParams{})
	if err != nil || res.(protocol.ServiceListResult).Count != 1 {
		t.Fatalf("service list: %v %+v", err, res)
	}
	if _, err := call(t, c.handleServiceControl, admin, protocol.ServiceControlParams{Name: "Spooler", Action: "stop", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if fc.stopped != "Spooler" {
		t.Fatal("service not stopped")
	}
	if _, err := call(t, c.handleProcessKill, admin, protocol.ProcessKillParams{PID: 1234, Reason: "hung"}); err != nil {
		t.Fatal(err)
	}
	if fc.killedPID != 1234 {
		t.Fatal("process not killed")
	}
	if _, err := call(t, c.handleBluetoothSet, admin, protocol.BluetoothSetParams{On: true}); err != nil {
		t.Fatal(err)
	}
	if !fc.btOn {
		t.Fatal("bluetooth not turned on")
	}

	// All state changes must be in the audit log.
	entries := c.auditLog.recent(timeDaysAgo(1), timeNow())
	var svc, kill, bt bool
	for _, e := range entries {
		switch {
		case e.Action == "service_stop" && e.Target == "Spooler":
			svc = true
		case e.Action == "process_kill" && strings.Contains(e.Target, "1234"):
			kill = true
		case e.Action == "bluetooth_on":
			bt = true
		}
	}
	if !svc || !kill || !bt {
		t.Fatalf("missing audit entries: svc=%v kill=%v bt=%v", svc, kill, bt)
	}
}

func TestNewAdminAlert(t *testing.T) {
	c, _ := newCore(t)
	snap := protocol.TelemetrySnapshot{LocalAdmins: []protocol.LocalAccount{
		{Name: `PC\Administrator`, SID: "S-1-5-21-1-500"},
		{Name: `IMAKER\it`, SID: "S-1-5-21-1-1001"},
	}}
	// First run establishes the baseline — no alert.
	c.CheckLocalAdmins(snap)
	if n := c.Notify.Pending(`IMAKER\ali`); len(n) != 0 {
		t.Fatalf("baseline run should not alert: %+v", n)
	}
	// A new admin appears -> critical alert.
	snap.LocalAdmins = append(snap.LocalAdmins, protocol.LocalAccount{Name: `PC\sneaky`, SID: "S-1-5-21-1-1337"})
	c.CheckLocalAdmins(snap)
	pending := c.Notify.Pending(`IMAKER\ali`)
	if len(pending) != 1 || pending[0].Severity != protocol.SeverityCritical || !strings.Contains(pending[0].Message, "sneaky") {
		t.Fatalf("expected critical new-admin alert: %+v", pending)
	}
	// Running again should not re-alert (baseline updated).
	c.Notify.Ack(`IMAKER\ali`, []string{pending[0].ID})
	c.CheckLocalAdmins(snap)
	if n := c.Notify.Pending(`IMAKER\ali`); len(n) != 0 {
		t.Fatalf("should not re-alert for the same admin: %+v", n)
	}
}
