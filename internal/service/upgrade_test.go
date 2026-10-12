package service

import (
	"context"
	"strings"
	"testing"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type fakeUpdater struct {
	spawned []string
	sigErr  error
}

func (f *fakeUpdater) InstallDir() string                      { return "" }
func (f *fakeUpdater) VerifySignature(path, subj string) error { return f.sigErr }
func (f *fakeUpdater) SpawnUpdater(exe string) error {
	f.spawned = append(f.spawned, exe)
	return nil
}

func upgradeCore(t *testing.T) (*Core, *fakeUpdater) {
	t.Helper()
	c, _ := newCore(t)
	c.cfg.UpdateAllowedHosts = []string{"updates.imaker-group.co"}
	fu := &fakeUpdater{}
	c.SetUpdater(fu)
	return c, fu
}

var admin = ipc.Caller{User: `IMAKER\it`, IsAdmin: true}

func TestUpgradeRefusesWithoutUpdater(t *testing.T) {
	c, _ := newCore(t)
	c.cfg.UpdateAllowedHosts = []string{"updates.imaker-group.co"}
	_, err := call(t, c.handleUpgradeAgent, admin, protocol.UpgradeAgentParams{
		DownloadURL: "https://updates.imaker-group.co/a.zip", TargetVersion: "99.0.0", SHA256: strings.Repeat("a", 64)})
	if err == nil || !strings.Contains(err.Error(), "only supported on Windows") {
		t.Fatalf("expected Windows-only refusal, got %v", err)
	}
}

func TestUpgradeRejectsBadRequests(t *testing.T) {
	cases := map[string]protocol.UpgradeAgentParams{
		"plain http":   {DownloadURL: "http://updates.imaker-group.co/a.zip", TargetVersion: "99.0.0", SHA256: strings.Repeat("a", 64)},
		"foreign host": {DownloadURL: "https://evil.example.com/a.zip", TargetVersion: "99.0.0", SHA256: strings.Repeat("a", 64)},
		"not newer":    {DownloadURL: "https://updates.imaker-group.co/a.zip", TargetVersion: config.Version, SHA256: strings.Repeat("a", 64)},
		"no hash":      {DownloadURL: "https://updates.imaker-group.co/a.zip", TargetVersion: "99.0.0", SHA256: ""},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			c, fu := upgradeCore(t)
			if _, err := call(t, c.handleUpgradeAgent, admin, p); err == nil {
				t.Fatal("bad request accepted")
			}
			if len(fu.spawned) != 0 {
				t.Fatal("updater spawned for a rejected request")
			}
		})
	}
}

func TestUpgradeDisabledWithoutAllowedHosts(t *testing.T) {
	c, _ := upgradeCore(t)
	c.cfg.UpdateAllowedHosts = nil
	_, err := call(t, c.handleUpgradeAgent, admin, protocol.UpgradeAgentParams{
		DownloadURL: "https://updates.imaker-group.co/a.zip", TargetVersion: "99.0.0", SHA256: strings.Repeat("a", 64)})
	if err == nil {
		t.Fatal("upgrade allowed with no update_allowed_hosts")
	}
}

func TestReportWaitsForReportURL(t *testing.T) {
	c, _ := upgradeCore(t)
	c.ReportUpgradeResult(context.Background()) // no URL configured: must be a no-op, not a panic
}
