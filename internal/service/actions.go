package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/store"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/winadmin"
)

// ActionExecutor abstracts the privileged Windows operations so the handlers
// can be unit-tested without touching the real machine.
type ActionExecutor interface {
	Hostname() string
	RenamePC(newName string) error
	CreateLocalUser(username, password, fullName, comment string, admin, neverExpires bool) (sid string, addedAdmin bool, err error)
	ResetCommand(scope string) []string // the exact command a reset would run
	RunReset(scope string) (cmd string, err error)
}

// auditLog is an append-only, admin-readable record of every privileged
// action attempt. It lives alongside telemetry and is retained like it.
type auditLog struct {
	mu  sync.Mutex
	log *store.DailyLog
}

func newAuditLog(dir string) (*auditLog, error) {
	dl, err := store.NewDailyLog(dir, "audit")
	if err != nil {
		return nil, err
	}
	return &auditLog{log: dl}, nil
}

func (a *auditLog) record(e protocol.AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.log.Append(e.Time, e)
}

func (a *auditLog) recent(from, to time.Time) []protocol.AuditEntry {
	raw, _ := a.log.ReadRange(from, to)
	out := store.DecodeAll[protocol.AuditEntry](raw)
	store.SortByTime(out, func(e protocol.AuditEntry) time.Time { return e.Time })
	return out
}

// registerActions wires the admin-only action handlers.
func (c *Core) registerActions(m *ipc.Mux) {
	if c.exec == nil {
		return // non-Windows build / tests without an executor
	}
	m.HandleAdmin(protocol.MethodActionRename, c.handleRename)
	m.HandleAdmin(protocol.MethodActionCreateUser, c.handleCreateUser)
	m.HandleAdmin(protocol.MethodActionReset, c.handleReset)
	m.HandleAdmin(protocol.MethodActionListAudit, c.handleAuditLog)
}

func (c *Core) audit(caller ipc.Caller, action, target, detail string, err error) {
	e := protocol.AuditEntry{
		Time: time.Now().UTC(), Action: action, Caller: caller.User, CallerSID: caller.SID,
		Target: target, Detail: detail, Success: err == nil,
	}
	if err != nil {
		e.Error = err.Error()
	}
	if c.auditLog != nil {
		c.auditLog.record(e)
	}
	c.log.Info("admin action", "action", action, "caller", caller.User, "target", target,
		"detail", detail, "ok", err == nil, "err", err)
}

func (c *Core) handleRename(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.RenamePCParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	if err := winadmin.ValidateComputerName(p.NewName); err != nil {
		c.audit(caller, "rename_pc", p.NewName, "REFUSED: invalid name", err)
		return nil, ipc.InvalidParams("%v", err)
	}
	old := c.exec.Hostname()
	err := c.exec.RenamePC(p.NewName)
	c.audit(caller, "rename_pc", p.NewName, "from="+old+"; reason="+p.Reason, err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return protocol.RenamePCResult{OldName: old, NewName: p.NewName, RebootPending: true}, nil
}

func (c *Core) handleCreateUser(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.CreateLocalUserParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	if err := winadmin.ValidateUsername(p.Username); err != nil {
		c.audit(caller, "create_local_user", p.Username, "REFUSED: invalid username", err)
		return nil, ipc.InvalidParams("%v", err)
	}
	if err := winadmin.ValidatePassword(p.Password); err != nil {
		c.audit(caller, "create_local_user", p.Username, "REFUSED: weak password", err)
		return nil, ipc.InvalidParams("%v", err)
	}
	sid, addedAdmin, err := c.exec.CreateLocalUser(p.Username, p.Password, p.FullName, p.Comment, p.Administrator, p.PasswordNeverExpires)
	detail := "admin=" + fmt.Sprint(p.Administrator)
	if addedAdmin {
		detail = "GRANTED LOCAL ADMIN"
	}
	c.audit(caller, "create_local_user", p.Username, detail, err) // password is never recorded
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return protocol.CreateLocalUserResult{Username: p.Username, SID: sid, AddedToAdmins: addedAdmin}, nil
}

func (c *Core) handleReset(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.ResetParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	host := c.exec.Hostname()
	scope := string(p.Scope)
	if scope == "" {
		scope = string(protocol.ResetKeepNothing)
	}
	cmdPreview := fmt.Sprint(c.exec.ResetCommand(scope))

	// Guard 1: reason is mandatory.
	if len(p.Reason) < 3 {
		err := fmt.Errorf("a reason is required to reset a PC")
		c.audit(caller, "reset_pc", host, "REFUSED: no reason; scope="+scope, err)
		return nil, ipc.InvalidParams("%v", err)
	}
	// Guard 2: confirmation token must match this exact host.
	if err := winadmin.CheckResetConfirm(p.Confirm, host); err != nil {
		c.audit(caller, "reset_pc", host, "REFUSED: bad confirmation; scope="+scope+"; reason="+p.Reason, err)
		return nil, ipc.InvalidParams("%v", err)
	}

	// Dry run (the safe default): validate + log, do not wipe.
	if !p.Execute {
		c.audit(caller, "reset_pc", host, "DRY-RUN ok; scope="+scope+"; would run: "+cmdPreview+"; reason="+p.Reason, nil)
		return protocol.ResetResult{
			Accepted: true, DryRun: true, Scope: scope, Hostname: host,
			Message: "Dry run only — nothing was wiped. Would run: " + cmdPreview +
				". Re-send with execute=true (CLI: --i-understand) to actually reset this PC.",
		}, nil
	}

	// Real reset. Record BEFORE launching, because the machine is about to go.
	delay := p.DelaySeconds
	if delay <= 0 {
		delay = 60
	}
	c.audit(caller, "reset_pc", host, fmt.Sprintf("EXECUTE scope=%s delay=%ds cmd=%s reason=%s", scope, delay, cmdPreview, p.Reason), nil)

	go func() {
		c.log.Warn("REMOTE RESET scheduled", "host", host, "scope", scope, "delay_s", delay, "by", caller.User)
		time.Sleep(time.Duration(delay) * time.Second)
		cmd, err := c.exec.RunReset(scope)
		c.audit(caller, "reset_pc", host, "LAUNCHED: "+cmd, err)
		if err != nil {
			c.log.Error("remote reset failed to launch", "err", err)
		}
	}()

	return protocol.ResetResult{
		Accepted: true, DryRun: false, Scope: scope, Hostname: host,
		ScheduledAt: time.Now().Add(time.Duration(delay) * time.Second),
		Message:     fmt.Sprintf("Reset accepted. This PC will begin wiping in %d seconds using: %s", delay, cmdPreview),
	}, nil
}

func (c *Core) handleAuditLog(ctx context.Context, raw json.RawMessage) (any, error) {
	var p struct {
		Days int `json:"days"`
	}
	_ = ipc.DecodeParams(raw, &p)
	if p.Days <= 0 || p.Days > 90 {
		p.Days = 30
	}
	to := time.Now()
	from := to.AddDate(0, 0, -p.Days)
	if c.auditLog == nil {
		return protocol.AuditLogResult{}, nil
	}
	return protocol.AuditLogResult{Entries: c.auditLog.recent(from, to)}, nil
}

// osHostname is a tiny helper for the executor on all platforms.
func osHostname() string {
	h, _ := os.Hostname()
	return h
}
