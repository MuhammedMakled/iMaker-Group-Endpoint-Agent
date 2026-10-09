# v1.4 — remote lock/sign-out, USB control, escalation alerting, IP allowlist

All commands run from an elevated PowerShell in `C:\Program Files\Imaker`. The
state-changing ones require the global admin login (`login`) set up in v1.3.

## Remote lock & sign-out

```powershell
.\ImakerAgentService.exe sessions                 # list logged-on users + session ids
.\ImakerAgentService.exe lock                      # lock the active user's screen
.\ImakerAgentService.exe lock -session 2           # lock a specific session
.\ImakerAgentService.exe signout -reason "offboarding"   # sign the user out
```
- **Lock** runs `rundll32 user32,LockWorkStation` inside the user's own session
  (the service is in session 0, so it launches it in the interactive session via
  `CreateProcessAsUser`). `LockWorkStation()` is the native Win32 call behind it.
- **Sign-out** uses `WTSLogoffSession` to gracefully log the session off.

## USB / removable storage control

```powershell
.\ImakerAgentService.exe usb-status
.\ImakerAgentService.exe usb -mode read_only -reason "prevent data leakage"
.\ImakerAgentService.exe usb -mode block
.\ImakerAgentService.exe usb -mode allow
```
| Mode | Effect | Registry |
|---|---|---|
| `allow` | USB drives read/write | `USBSTOR\Start=3`, `WriteProtect=0` |
| `read_only` | USB drives mount but can't be written | `USBSTOR\Start=3`, `WriteProtect=1` |
| `block` | USB mass-storage disabled entirely | `USBSTOR\Start=4` |

`read_only` sets `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect`.
Changes apply to newly-connected drives immediately; a drive already mounted may
need a re-plug (or reboot for `block`) to pick up the new policy.

## New-admin / escalation alerting (Event Log)

The service watches the Windows **Security log** every `event_log_poll_interval`
(default 10 min) for:

| Event ID | Meaning |
|---|---|
| 4720 | A user account was created |
| 4728 | Member added to a security-enabled **global** group |
| 4732 | Member added to a security-enabled **local** group (e.g. Administrators) |
| 4756 | Member added to a security-enabled **universal** group |

For each account creation or privileged-group addition, the agent checks its own
**audit log**: if the change matches an IT-authorized `create-user` command, it's
logged as authorized and ignored. **Anything else raises a critical alert** to
every user on the PC and is written to the audit log with who/when. This runs
alongside the v1.3 Administrators-group baseline check — the baseline catches the
resulting *state*, the event watcher catches the *action* (and who did it), even
if the account is quickly deleted to cover tracks.

> These events only exist if the audit policy is on. `install` enables it
> automatically (`auditpol /set /subcategory:"User Account Management"` and
> `"Security Group Management"`). Disable the whole watcher with
> `"event_log_monitor": false`.

## Global admin, sessions, tamper protection (from v1.3, still in force)

Every state-changing command above requires the **global admin password**
(Argon2id, idle-timeout sessions, lockout). Uninstall is password-gated; the
service auto-restarts; new-admin accounts alert. See
[docs/SECURITY_AND_CONTROL.md](SECURITY_AND_CONTROL.md) and [SECURITY.md](../SECURITY.md).

## Device & network controls (from v1.3)

Process/service management (`services`, `service`, `ps`, `kill`), Bluetooth
(`bluetooth`), startup apps (`startup`, `startup-toggle`), and the full network
view (in `collect`) are unchanged — see SECURITY_AND_CONTROL.md.

## IP allowlist rules

```powershell
.\ImakerAgentService.exe ipallow                      # show configured rules
.\ImakerAgentService.exe ipallow-check -ip 203.0.113.5
```
Configure in `agent.json`:
```json
"allowed_command_ips": ["203.0.113.5", "10.8.0.0/24"]
```
Accepts single IPs and CIDR ranges (IPv4 and IPv6). **Today everything runs over
the local named pipe**, so the list is inert (`active_for_remote: false`) and is
there so the policy is defined and testable now. When the Phase-3 dashboard
uplink is added, the agent will accept remote commands **only** from these
addresses (fail-closed) and dial only your fixed dashboard address.
