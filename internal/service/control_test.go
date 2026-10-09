package service

import (
	"strings"
	"testing"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type fakeControl struct {
	stopped   string
	killedPID uint32
	btOn      bool
	usbSet    string
	events    []EscalationEvent
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

func (f *fakeControl) LockSession(id uint32) (protocol.SessionActionResult, error) {
	return protocol.SessionActionResult{SessionID: 1, User: `IMAKER\ali`, Done: true}, nil
}
func (f *fakeControl) SignoutSession(id uint32) (protocol.SessionActionResult, error) {
	return protocol.SessionActionResult{SessionID: 1, User: `IMAKER\ali`, Done: true}, nil
}
func (f *fakeControl) ListSessions() ([]protocol.UserSession, error) {
	return []protocol.UserSession{{SessionID: 1, User: `IMAKER\ali`, State: "Active"}}, nil
}
func (f *fakeControl) USBStatus() (protocol.USBStatus, error) {
	return protocol.USBStatus{Mode: protocol.USBAllow, StorageEnabled: true}, nil
}
func (f *fakeControl) usbMode() string { return f.usbSet }
func (f *fakeControl) USBSet(mode string) (protocol.USBStatus, error) {
	f.usbSet = mode
	return protocol.USBStatus{Mode: mode}, nil
}
func (f *fakeControl) QuerySecurityEvents(since time.Time) ([]EscalationEvent, error) {
	return f.events, nil
}

func TestEscalationAlerting(t *testing.T) {
	c, _ := newCoreWithExec(t)
	fc := &fakeControl{}
	c.SetControl(fc)
	admin := ipc.Caller{User: `IMAKER\it`, IsAdmin: true}

	// The agent legitimately creates "ali" (audited).
	if _, err := call(t, c.handleCreateUser, admin, protocol.CreateLocalUserParams{
		Username: "ali", Password: "Str0ng-Pass!", Administrator: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fc.events = []EscalationEvent{
		// Authorized: matches the audited create_local_user for "ali".
		{EventID: 4720, Time: now, TargetUser: `IMAKER\ali`, SubjectUser: `IMAKER\it`},
		// Unauthorized: a user created with no matching audit entry.
		{EventID: 4720, Time: now, TargetUser: `PC\sneaky`, SubjectUser: `PC\attacker`},
		// Unauthorized admin escalation.
		{EventID: 4732, Time: now, TargetUser: `PC\bob`, GroupName: "Administrators", SubjectUser: `PC\attacker`, Privileged: true},
	}
	c.checkEscalation(now.Add(-time.Hour))

	pending := c.Notify.Pending(`IMAKER\ali`)
	// Two alerts: sneaky (created) + bob (escalated). "ali" was authorized.
	if len(pending) != 2 {
		t.Fatalf("expected 2 escalation alerts, got %d: %+v", len(pending), pending)
	}
	for _, p := range pending {
		if p.Severity != protocol.SeverityCritical {
			t.Errorf("escalation alerts must be critical: %+v", p)
		}
		if strings.Contains(p.Message, "ali") {
			t.Error("authorized account should not alert")
		}
	}
}
