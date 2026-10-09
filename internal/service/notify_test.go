package service

import (
	"testing"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

func TestNotificationRPCFlow(t *testing.T) {
	c, _ := newCore(t)
	admin := ipc.Caller{User: `IMAKER\it`, IsAdmin: true}
	ali := ipc.Caller{User: `IMAKER\ali`}
	sara := ipc.Caller{User: `IMAKER\sara`}

	// Broadcast + one targeted at "sara" (short form, no domain).
	if _, err := call(t, c.handleNotifySend, admin, protocol.NotifySendParams{Notification: protocol.Notification{
		Title: "Revit 2025 update tonight", Message: "Please save and close Revit by 8 PM.", Category: protocol.CategoryUpdate,
		URL: "https://imaker-group.co/it"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, c.handleNotifySend, admin, protocol.NotifySendParams{Notification: protocol.Notification{
		Title: "Your laptop is ready", Message: "Collect it from IT.", Users: []string{"sara"}}, TTL: "1h"}); err != nil {
		t.Fatal(err)
	}
	// Validation.
	if _, err := call(t, c.handleNotifySend, admin, protocol.NotifySendParams{Notification: protocol.Notification{
		Title: "x", Message: "y", URL: "javascript:alert(1)"}}); err == nil {
		t.Fatal("non-http url must be rejected")
	}

	poll := func(caller ipc.Caller) []protocol.Notification {
		res, err := call(t, c.handleNotifyPoll, caller, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.(protocol.NotifyPollResult).Notifications
	}
	if got := poll(ali); len(got) != 1 || got[0].Severity != protocol.SeverityInfo {
		t.Fatalf("ali should get only the broadcast: %+v", got)
	}
	if got := poll(sara); len(got) != 2 {
		t.Fatalf("sara should get both: %+v", got)
	}
	ids := []string{poll(ali)[0].ID}
	if _, err := call(t, c.handleNotifyAck, ali, protocol.NotifyAckParams{IDs: ids}); err != nil {
		t.Fatal(err)
	}
	if got := poll(ali); len(got) != 0 {
		t.Fatalf("acked notification must not repeat: %+v", got)
	}
	if got := poll(sara); len(got) != 2 {
		t.Fatal("ack is per user")
	}

	// Admins can list with delivery status (the admin-only check itself is
	// enforced by ipc.Mux.HandleAdmin, covered in pkg/ipc tests).
	res, _ := call(t, c.handleNotifyList, admin, nil)
	list := res.(protocol.NotifyListResult).Notifications
	if len(list) != 2 {
		t.Fatalf("list: %+v", list)
	}

	// Expiry.
	c.Notify.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if got := poll(sara); len(got) != 1 {
		t.Fatalf("1h notification should have expired: %+v", got)
	}

	// Persistence across restart.
	nc2, err := NewNotificationCenter(c.dataDir + "/notifications")
	if err != nil || len(nc2.List()) != 2 {
		t.Fatalf("not persisted: %v", err)
	}
}

func TestHealthAlerts(t *testing.T) {
	c, _ := newCore(t)
	fail := true
	snap := protocol.TelemetrySnapshot{
		Volumes:       []protocol.LogicalVolume{{DriveLetter: "C:", LowSpace: true, FreeGB: 8.2, SizeGB: 476}},
		OS:            protocol.OSInfo{UptimeHours: 100},
		Updates:       protocol.UpdateStatus{RebootPending: true},
		PhysicalDisks: []protocol.PhysicalDisk{{Model: "WD Blue", SerialNumber: "WD1", Health: "Unhealthy", SmartPredictFailure: &fail}},
	}
	cfg := HealthAlertConfig{Enabled: true, RestartAfterHours: 72, SupportURL: "https://imaker-group.co/it"}
	fired := EvaluateHealth(c.Notify, cfg, snap)
	if len(fired) != 3 {
		t.Fatalf("want 3 alerts, got %v", fired)
	}
	if again := EvaluateHealth(c.Notify, cfg, snap); len(again) != 0 {
		t.Fatalf("cooldown should suppress repeats: %v", again)
	}
	pending := c.Notify.Pending(`IMAKER\ali`)
	if len(pending) != 3 || pending[0].URL == "" || pending[0].Category != protocol.CategoryHealth {
		t.Fatalf("pending: %+v", pending)
	}
	if EvaluateHealth(c.Notify, HealthAlertConfig{}, snap) != nil {
		t.Fatal("disabled config must not fire")
	}
}

func TestIdentityRPC(t *testing.T) {
	c, _ := newCore(t)
	res, err := call(t, c.handleIdentity, ipc.Caller{User: `IMAKER\ali`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id := res.(protocol.AssetIdentity); id.SerialNumber != "MB123456" || !id.IsCustomBuild {
		t.Fatalf("%+v", id)
	}
}
