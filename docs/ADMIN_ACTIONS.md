# Admin actions, performance & extended inventory (v1.2)

This release adds live performance monitoring, more inventory, and the
**privileged administrative actions**: rename PC, create a local user, and
remote reset/wipe. All commands below are run from an elevated PowerShell in
`C:\Program Files\Imaker`, and all of them talk to the running service over
the named pipe.

> **Security model.** Every action method is **admin-only**. The service
> identifies the caller from their Windows process token (an elevated
> Administrators member, or LocalSystem) — never from anything in the request.
> A standard user cannot invoke any of these, even by crafting their own pipe
> client. Every attempt — success, refusal or dry run — is written to a
> tamper-evident **audit log** with the caller's name and SID. See
> [`SECURITY.md`](../SECURITY.md).

## Live performance — what's running and what's heavy

```powershell
.\ImakerAgentService.exe performance
```
Returns overall CPU %, per-core load, RAM used, per-disk busy %, and the **top
applications by CPU and by memory**. Processes that share an executable (e.g.
many `chrome.exe`) are grouped into one line with an instance count, so you see
"Google Chrome — 12 instances — 31% CPU, 4.2 GB" rather than 12 rows.

## Extended inventory (in the normal `collect` / telemetry)

- **Battery health** (laptops): charge %, design vs full-charge capacity, a
  **health %** (how worn the battery is), cycle count and chemistry.
- **Windows & Office licensing**: activation status, edition, channel
  (Retail/Volume/OEM) and the **last 5 characters** of the product key only
  (never the full key).
- **Local administrators audit**: everyone in the local Administrators group,
  with SID, whether the account is local or domain, and whether it's disabled —
  so you can spot users who shouldn't have admin rights.

## Rename the PC

```powershell
.\ImakerAgentService.exe rename-pc -name "DXB-ARCH-07" -reason "standardising names"
```
Uses `SetComputerNameExW`. The new name applies after the next reboot (schedule
that separately). Names are validated against Windows' rules before anything
changes.

## Create a local user

```powershell
# standard user; password is prompted without showing on screen
.\ImakerAgentService.exe create-user -username ali.hassan -fullname "Ali Hassan"

# make them a local administrator, password never expires
.\ImakerAgentService.exe create-user -username site.admin -admin -never-expires
```
Uses `NetUserAdd` (+ `NetLocalGroupAddMembers` for `-admin`). The password is
read with the console echo off, sent straight to Windows, zeroed in memory, and
**never logged**. Granting admin is flagged explicitly in the audit log.

## Remote reset / wipe — "Reset this PC, remove everything"

This erases all data and reinstalls Windows, for a lost/stolen device or an
employee leaving. It is deliberately hard to trigger by accident.

**It runs Windows' own reset engine (`systemreset.exe`).** The agent never
deletes files itself — it hands off to the same mechanism as Settings →
Recovery → Reset this PC.

```powershell
# 1) DRY RUN (default): validates, logs, and prints the exact command — wipes NOTHING
.\ImakerAgentService.exe reset-pc -reason "employee offboarding - John Doe"

# 2) REAL wipe: requires -i-understand AND retyping the computer name
.\ImakerAgentService.exe reset-pc -reason "lost laptop, ticket #4821" -i-understand
```

Guards, in order:
1. **Admin-only** (token-verified).
2. **Reason required** — recorded in the audit log.
3. **Confirmation tied to this exact PC** — the request must carry
   `RESET <HOSTNAME>`; the CLI fills this in for the local host, so a broadcast
   or wrong-target command cannot wipe a machine.
4. **Safe by default** — without `-i-understand` the request is a dry run
   (the `execute` field defaults to the safe value, so even a hand-crafted
   request that forgets it will not wipe).
5. **Retype to confirm** — with `-i-understand`, the CLI makes you type the
   computer name before sending.
6. **Grace delay** — `-delay` seconds (default 60) before it starts.
7. **Audited before launch** — the execute entry is written *before* the engine
   is invoked, so the record survives the wipe.

`-scope remove_everything_clean` additionally runs the drive-clean pass (slower;
makes file recovery harder — use when a device leaves the company).

> On Windows editions without `systemreset.exe`, or for fully-unattended wipes
> at fleet scale, the supported path is the **MDM RemoteWipe CSP**. The action
> contract here is the same one the Phase 3 Command Center/Odoo backend will
> call, so moving to MDM-triggered wipes needs no agent change.

## Audit log

```powershell
.\ImakerAgentService.exe audit -days 30
```
Every rename, user creation and reset attempt, with timestamp, caller, SID,
target, outcome and reason. Stored under
`C:\ProgramData\Imaker\data\audit\audit-YYYY-MM-DD.jsonl` (the folder is
ACL-locked to SYSTEM/Administrators). Passwords never appear here.

## From the dashboard (Phase 3)

All of the above are RPC methods (`action.rename_pc`, `action.create_local_user`,
`action.reset_pc`, `performance.get`, `action.audit_log`). When the Command
Center/Odoo backend is connected it will call these same methods, so the
dashboard gets remote reset, user provisioning and live performance with the
identical authorization and auditing described here.
