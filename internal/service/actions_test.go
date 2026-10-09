package service

import (
	"strings"
	"testing"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type fakeExec struct {
	host       string
	renamed    string
	created    string
	createdPw  string
	grantAdmin bool
	resetRan   string
}

func (f *fakeExec) Hostname() string        { return f.host }
func (f *fakeExec) RenamePC(n string) error { f.renamed = n; return nil }
func (f *fakeExec) CreateLocalUser(u, pw, fn, c string, admin, ne bool) (string, bool, error) {
	f.created, f.createdPw, f.grantAdmin = u, pw, admin
	return "S-1-5-21-xx-1001", admin, nil
}
func (f *fakeExec) ResetCommand(scope string) []string {
	return []string{"systemreset.exe", "-factoryreset"}
}
func (f *fakeExec) RunReset(scope string) (string, error) {
	f.resetRan = scope
	return "systemreset.exe -factoryreset", nil
}

func newCoreWithExec(t *testing.T) (*Core, *fakeExec) {
	c, _ := newCore(t)
	fe := &fakeExec{host: "DXB-ARCH-07"}
	c.SetExecutor(fe)
	return c, fe
}

func TestRenameAndCreateUserAudited(t *testing.T) {
	c, fe := newCoreWithExec(t)
	admin := ipc.Caller{User: `IMAKER\it`, SID: "S-1-5-21-admin", IsAdmin: true}

	if _, err := call(t, c.handleRename, admin, protocol.RenamePCParams{NewName: "DXB-ARCH-99", Reason: "re-issue"}); err != nil {
		t.Fatal(err)
	}
	if fe.renamed != "DXB-ARCH-99" {
		t.Fatalf("rename not applied: %q", fe.renamed)
	}
	if _, err := call(t, c.handleRename, admin, protocol.RenamePCParams{NewName: "bad name!"}); err == nil {
		t.Fatal("invalid name should be rejected")
	}

	res, err := call(t, c.handleCreateUser, admin, protocol.CreateLocalUserParams{
		Username: "ali.hassan", Password: "Str0ngPass!", FullName: "Ali Hassan", Administrator: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := res.(protocol.CreateLocalUserResult); !r.AddedToAdmins || r.SID == "" {
		t.Fatalf("create user: %+v", r)
	}

	// Audit log: records actions, never the password.
	entries := c.auditLog.recent(timeDaysAgo(1), timeNow())
	if len(entries) < 3 {
		t.Fatalf("expected audit entries, got %d", len(entries))
	}
	for _, e := range entries {
		if strings.Contains(e.Detail, "Str0ngPass") || strings.Contains(e.Error, "Str0ngPass") {
			t.Fatal("password leaked into audit log")
		}
	}
	// The admin grant must be called out explicitly.
	foundGrant := false
	for _, e := range entries {
		if e.Action == "create_local_user" && strings.Contains(e.Detail, "GRANTED LOCAL ADMIN") {
			foundGrant = true
		}
	}
	if !foundGrant {
		t.Fatal("admin grant not flagged in audit log")
	}
}

func TestResetGuards(t *testing.T) {
	c, fe := newCoreWithExec(t)
	admin := ipc.Caller{User: `IMAKER\it`, IsAdmin: true}

	// No reason → refused.
	if _, err := call(t, c.handleReset, admin, protocol.ResetParams{Confirm: "RESET DXB-ARCH-07", Execute: true}); err == nil {
		t.Fatal("reset without reason must be refused")
	}
	// Wrong confirmation → refused.
	if _, err := call(t, c.handleReset, admin, protocol.ResetParams{Reason: "lost laptop", Confirm: "RESET WRONG-PC", Execute: true}); err == nil {
		t.Fatal("reset with wrong confirmation must be refused")
	}
	if fe.resetRan != "" {
		t.Fatal("no reset should have run yet")
	}
	// Correct confirmation but Execute omitted → safe dry run, no wipe.
	res, err := call(t, c.handleReset, admin, protocol.ResetParams{Reason: "lost laptop", Confirm: "reset dxb-arch-07"})
	if err != nil {
		t.Fatal(err)
	}
	if r := res.(protocol.ResetResult); !r.DryRun || !r.Accepted {
		t.Fatalf("omitted execute must be a dry run: %+v", r)
	}
	if fe.resetRan != "" {
		t.Fatal("dry run must not wipe")
	}

	// Everything correct + Execute=true → accepted (runs after delay in a goroutine).
	res, err = call(t, c.handleReset, admin, protocol.ResetParams{
		Scope: protocol.ResetKeepNothing, Reason: "employee offboarding", Confirm: "RESET DXB-ARCH-07",
		Execute: true, DelaySeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if r := res.(protocol.ResetResult); r.DryRun || !r.Accepted {
		t.Fatalf("execute reset: %+v", r)
	}
	// The attempt (and the refusals) must all be in the audit log.
	entries := c.auditLog.recent(timeDaysAgo(1), timeNow())
	var refused, executed int
	for _, e := range entries {
		if e.Action != "reset_pc" {
			continue
		}
		if strings.Contains(e.Detail, "REFUSED") {
			refused++
		}
		if strings.HasPrefix(e.Detail, "EXECUTE") {
			executed++
		}
	}
	if refused != 2 || executed != 1 {
		t.Fatalf("audit should show 2 refusals + 1 execute, got refused=%d executed=%d", refused, executed)
	}
}

// time helpers kept local so the test file is self-contained.
func timeNow() time.Time          { return time.Now() }
func timeDaysAgo(n int) time.Time { return time.Now().AddDate(0, 0, -n) }
