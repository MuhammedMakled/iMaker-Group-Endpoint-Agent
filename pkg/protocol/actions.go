package protocol

import "time"

// Administrative action RPC methods. ALL of these are admin-only: the IPC
// server authorises them from the caller's verified Windows token
// (elevated Administrators member or LocalSystem). The destructive ones
// additionally require an explicit typed confirmation (see below).
const (
	MethodActionRename     = "action.rename_pc"
	MethodActionCreateUser = "action.create_local_user"
	MethodActionReset      = "action.reset_pc" // remote wipe — guarded, see ResetParams
	MethodActionListAudit  = "action.audit_log"
)

// RenamePCParams renames the computer. The new name takes effect after the
// reboot the caller schedules separately (Windows requires a restart).
type RenamePCParams struct {
	NewName string `json:"new_name"`
	Reason  string `json:"reason,omitempty"`
}

type RenamePCResult struct {
	OldName       string `json:"old_name"`
	NewName       string `json:"new_name"`
	RebootPending bool   `json:"reboot_pending"`
}

// CreateLocalUserParams creates a standard (non-admin by default) local user.
type CreateLocalUserParams struct {
	Username string `json:"username"`
	FullName string `json:"full_name,omitempty"`
	// Password must satisfy the machine's policy. It is never logged or stored.
	Password string `json:"password"`
	Comment  string `json:"comment,omitempty"`
	// Administrator adds the account to the local Administrators group.
	// Defaults to false; granting admin is called out explicitly in the audit log.
	Administrator        bool `json:"administrator,omitempty"`
	PasswordNeverExpires bool `json:"password_never_expires,omitempty"`
}

type CreateLocalUserResult struct {
	Username      string `json:"username"`
	SID           string `json:"sid,omitempty"`
	AddedToAdmins bool   `json:"added_to_admins"`
}

// ResetScope selects how much is removed on a reset.
type ResetScope string

const (
	// ResetKeepNothing performs a full wipe: remove apps, settings and all
	// user files, then reinstall Windows (equivalent to "Reset this PC →
	// Remove everything"). Intended for decommissioning or re-issuing a device.
	ResetKeepNothing ResetScope = "remove_everything"
	// ResetCleanData additionally runs the data-cleaning pass (slower; makes
	// recovery of removed files harder — for a device leaving the company).
	ResetCleanData ResetScope = "remove_everything_clean"
)

// ResetParams requests a remote reset/wipe. This is deliberately hard to
// trigger by accident:
//
//   - Admin-only, like every action method.
//   - Confirm MUST equal exactly "RESET <hostname>" (the agent's own
//     hostname), so a broadcast or wrong-target command cannot wipe a PC.
//   - Execute MUST be explicitly true to wipe. The zero value is a safe
//     dry-run, so an omitted/forgotten field never wipes. The CLI sets it
//     only when the operator passes --i-understand.
//   - Every attempt (including refused/dry-run) is written to the audit log
//     with the caller's identity before anything happens.
type ResetParams struct {
	Scope        ResetScope `json:"scope"`
	Confirm      string     `json:"confirm"`       // must be "RESET <hostname>"
	Reason       string     `json:"reason"`        // required, recorded in the audit log
	DelaySeconds int        `json:"delay_seconds"` // grace period before it starts (default 60)
	// Execute must be true to actually wipe. Anything else (including the
	// zero value) is a validate-and-log dry run.
	Execute bool `json:"execute"`
}

type ResetResult struct {
	Accepted    bool      `json:"accepted"`
	DryRun      bool      `json:"dry_run"`
	Scope       string    `json:"scope"`
	Hostname    string    `json:"hostname"`
	ScheduledAt time.Time `json:"scheduled_at,omitempty"`
	Message     string    `json:"message"`
}

// AuditEntry is one recorded administrative action.
type AuditEntry struct {
	Time      time.Time `json:"time"`
	Action    string    `json:"action"`
	Caller    string    `json:"caller"`
	CallerSID string    `json:"caller_sid,omitempty"`
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

type AuditLogResult struct {
	Entries []AuditEntry `json:"entries"`
}
