package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

func ipcSystemCaller() ipc.Caller { return ipc.Caller{User: "SYSTEM (agent)", IsAdmin: true} }

// runEscalationWatcher polls the Windows Security log for account-creation and
// privilege-escalation events (4720/4728/4732/4756) and raises a critical
// alert for anything not performed by the agent's own audited commands. This
// complements the Administrators-group baseline check (which catches the state)
// by catching the *event* with who/when, even if the account is later removed.
func (c *Core) runEscalationWatcher(stop <-chan struct{}) {
	if c.control == nil || c.Notify == nil {
		return
	}
	interval := c.cfg.EventLogPollInterval.D()
	if interval < time.Minute {
		interval = 10 * time.Minute
	}
	since := time.Now().Add(-interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			since = c.checkEscalation(since)
		}
	}
}

func (c *Core) checkEscalation(since time.Time) time.Time {
	next := time.Now()
	events, err := c.control.QuerySecurityEvents(since)
	if err != nil {
		c.log.Debug("security event query failed", "err", err)
		return since // retry the same window next time
	}
	for _, e := range events {
		if e.EventID != 4720 && !e.Privileged {
			continue
		}
		if c.wasAuthorized(e) {
			c.log.Info("account change (IT-authorized)", "event", e.EventID, "target", e.TargetUser, "group", e.GroupName)
			continue
		}
		c.raiseEscalationAlert(e)
	}
	return next
}

// wasAuthorized reports whether a recent audited agent action explains this
// event (the agent created the user / granted admin itself).
func (c *Core) wasAuthorized(e EscalationEvent) bool {
	if c.auditLog == nil || e.TargetUser == "" {
		return false
	}
	entries := c.auditLog.recent(e.Time.Add(-30*time.Minute), e.Time.Add(5*time.Minute))
	target := strings.ToLower(bareUser(e.TargetUser))
	for _, a := range entries {
		if a.Action != "create_local_user" || !a.Success {
			continue
		}
		if strings.ToLower(bareUser(a.Target)) == target {
			return true
		}
	}
	return false
}

func bareUser(s string) string {
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func (c *Core) raiseEscalationAlert(e EscalationEvent) {
	var title, msg string
	switch {
	case e.EventID == 4720:
		title = "Security alert: account created outside IT"
		msg = fmt.Sprintf("A Windows account %q was created on this PC by %q, which was not done through IMAKER IT tools. If this wasn't expected, contact IT immediately.",
			e.TargetUser, firstNonEmptyStr(e.SubjectUser, "an unknown user"))
	default:
		title = "Security alert: admin rights granted outside IT"
		msg = fmt.Sprintf("Account %q was added to %q by %q, outside IMAKER IT tools. This grants elevated access — contact IT immediately if unexpected.",
			e.TargetUser, firstNonEmptyStr(e.GroupName, "a privileged group"), firstNonEmptyStr(e.SubjectUser, "an unknown user"))
	}
	c.log.Warn("ESCALATION ALERT", "event", e.EventID, "target", e.TargetUser, "group", e.GroupName, "by", e.SubjectUser)
	c.audit(ipcSystemCaller(), "escalation_detected", e.TargetUser,
		fmt.Sprintf("event=%d group=%s by=%s", e.EventID, e.GroupName, e.SubjectUser), nil)
	rule := fmt.Sprintf("escalation:%d:%s:%s", e.EventID, e.TargetUser, e.GroupName)
	_, _ = c.Notify.FireRule(rule, 6*time.Hour, protocol.Notification{
		Title: title, Message: msg, Severity: protocol.SeverityCritical, Category: protocol.CategoryPolicy,
	})
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
