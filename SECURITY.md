# Security model

The IMAKER Endpoint Agent is a **managed-IT agent for the company's own
devices**, in the same category as Intune or an RMM tool. It is meant to be
deployed by IT on company-owned PCs, with the knowledge of the organisation.
This document describes the controls that keep its powerful features from being
misused.

## Trust boundaries

| Component | Runs as | Can do |
|---|---|---|
| `ImakerTrayApp.exe` | The logged-in user (standard rights) | Track that user's own activity, show them notifications, read this PC's identity. **Cannot** perform any admin action. |
| `ImakerAgentService.exe` | `LocalSystem` service | Telemetry, inventory, and — only via admin-authorised RPC — rename/create-user/reset. |

The two talk over a local named pipe (`\\.\pipe\imaker_agent_ipc`). The pipe
ACL grants SYSTEM/Administrators full access and authenticated users
read/write, because ordinary users legitimately submit their own activity and
read their own notifications.

## Authorization

The service never trusts anything in a request for identity or privilege.
For **every** call it resolves the caller from the client process token:

- `GetNamedPipeClientProcessId` → `OpenProcessToken` → the caller's user, SID,
  and whether they are an **elevated** Administrators member (the UAC-filtered
  token is checked, so a non-elevated admin does not pass) or LocalSystem.
- Ordinary methods (submit/read activity, poll notifications, read telemetry)
  are available to any authenticated local user, but a non-admin can only ever
  see **their own** activity.
- Privileged methods — `action.rename_pc`, `action.create_local_user`,
  `action.reset_pc`, `notify.send`, `notify.list`, `action.audit_log` — go
  through `Mux.HandleAdmin` and are refused unless the caller is an elevated
  admin or SYSTEM.

## Destructive actions

The remote **reset/wipe** is the most dangerous capability, so it has layered
guards (full list in [`docs/ADMIN_ACTIONS.md`](docs/ADMIN_ACTIONS.md)):
admin-only, mandatory reason, a confirmation token tied to the **exact
hostname**, a safe-by-default dry run (the `execute` flag's zero value does not
wipe), an interactive name-retype in the CLI, a grace delay, and an audit entry
written *before* the wipe starts. It invokes **Windows' own `systemreset.exe`**
rather than deleting files directly.

Creating a user and renaming the PC are likewise admin-only and validated
server-side before they run.

## Auditing

Every administrative attempt — success, refusal, or dry run — is appended to
`C:\ProgramData\Imaker\data\audit\` with timestamp, action, caller name, caller
SID, target, outcome and reason. **Passwords are never written** to the audit
log, the service log, or anywhere on disk; the create-user path zeroes the
password in memory once the account exists.

## Data protection

`C:\ProgramData\Imaker` is ACL-hardened on install (SYSTEM/Administrators full,
Users read-only), so standard users cannot read other users' activity, alter
the audit log, or tamper with configuration.

## Deployment expectations

- Code-sign both binaries before fleet rollout.
- Deploy only to company-owned devices, consistent with your acceptable-use and
  privacy policies. The tray app is intentionally transparent to users: it
  shows what is being tracked, lets them pause tracking, and lets them open
  their own activity folder. Browser URLs and page titles are never recorded.

## Reporting

For anything security-sensitive about this agent, contact IMAKER IT rather than
filing a public issue.
