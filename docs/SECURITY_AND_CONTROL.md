# Global admin login, network, and system control (v1.3)

This release adds the **application-level global admin login** that guards every
powerful action, a full **network view**, and **system control**: services,
startup apps, processes, and Bluetooth. It also adds **tamper protection**.

All commands run from an elevated PowerShell in `C:\Program Files\Imaker`.

## 1. The global admin login (set this up first)

A single **global admin password**, which you set and hold, is required — on
top of Windows admin — for every powerful action (reset, rename, create user,
stop services, disable startup, kill processes, Bluetooth) and to uninstall the
agent. It is stored only as an **Argon2id hash** (never recoverable), in an
ACL-locked file, and brute-force attempts trigger a lockout.

```powershell
.\ImakerAgentService.exe set-admin-password     # set it the first time (prompted twice)
.\ImakerAgentService.exe login                  # start a session
.\ImakerAgentService.exe auth-status            # check status / idle timeout
.\ImakerAgentService.exe logout
```

- **Idle timeout:** after you log in, the session stays valid until you're idle
  for `admin_idle_timeout` (default **15 minutes**), then you're asked again.
  The powerful commands auto-prompt for login if your session has expired.
- **Change it:** `set-admin-password` asks for the current password first.
- **Only you manage it:** there is no recovery backdoor. Keep the password safe.
  (When the Phase-3 dashboard is added, you'll be able to rotate it fleet-wide
  from there.)

> Powerful actions now fail with "global admin login required" until a password
> is set and you've logged in — this is the intended security posture.

## 2. Network

`collect` now reports, per adapter: **IPv4 and IPv6** addresses, **private IP**,
gateway, DNS servers, DHCP on/off and DHCP server, link speed, connection
status, adapter **type (Ethernet / Wireless / Virtual)**, and the **MAC address**
— so you can see the LAN and Wi-Fi MACs separately. The snapshot also includes
the **public IP** (fetched from `public_ip_endpoint`, default api.ipify.org;
turn off with `"detect_public_ip": false`).

## 3. Services (your "servers" list)

```powershell
.\ImakerAgentService.exe services -running            # list running services
.\ImakerAgentService.exe services -filter sql         # find services by name
.\ImakerAgentService.exe service -service Spooler -action stop -reason "maintenance"
.\ImakerAgentService.exe service -service Spooler -action start
.\ImakerAgentService.exe service -service W3SVC -action restart
```
Critical system services (RPC, DCOM, WMI, LSASS, Task Scheduler, the agent
itself, …) are **refused for stop/restart** so a remote command can't make a PC
unmanageable or unbootable.

## 4. Startup apps

```powershell
.\ImakerAgentService.exe startup                      # list; note the "id" of each
.\ImakerAgentService.exe startup-toggle -id <ID>              # disable it
.\ImakerAgentService.exe startup-toggle -id <ID> -enable     # re-enable it
```
Covers the machine and user **Run** keys and the **Startup folders**, using the
same enabled/disabled record Task Manager uses.

## 5. Processes (Task Manager)

```powershell
.\ImakerAgentService.exe ps                           # processes with CPU% and RAM
.\ImakerAgentService.exe kill -pid 1234 -reason "hung Revit"
.\ImakerAgentService.exe kill -pid 1234 -name revit.exe   # -name is a safety cross-check
```
`performance` (from v1.2) still gives the grouped "top apps by CPU/RAM" view.

## 6. Bluetooth

```powershell
.\ImakerAgentService.exe bluetooth-status
.\ImakerAgentService.exe bluetooth -on                # turn on
.\ImakerAgentService.exe bluetooth                    # turn off
```
Uses the same Windows radio control as Settings → Bluetooth.

## 7. Tamper protection

- **Uninstall requires the global admin password** (once set): a local admin
  can't quietly remove the agent through our tooling.
- **Auto-restart:** the service is registered to restart automatically if it
  crashes.
- **New-admin alerts:** the agent keeps a baseline of local administrators. If
  a new admin account appears that wasn't there before, every user gets a
  **critical alert** and it's written to the audit log — a strong signal of a
  scammer or compromise.

> Honest limit: a determined person with local admin rights can still remove a
> Windows service at the SCM level (e.g. `sc delete`). That's a Windows reality
> no user-space agent fully prevents. The mitigations are auto-restart, the
> password-gated uninstall, and the tamper **alerting** so you find out. A
> kernel-level protected service would be needed to block it outright, which is
> out of scope for this agent.

## 8. IP allowlisting & "only you install it" (how this maps to your asks)

- **"Require the global admin password to install/manage, only you control it"**
  — done via the global admin login above. Uninstall is gated now; when the
  Phase-3 installer/MSI is built, it will require the same global password to
  deploy, and the password is yours alone.
- **"Assign a specific IP for safety"** — everything today runs over the local
  named pipe (nothing is accepted over the network). The IP allowlist belongs to
  the Phase-3 dashboard uplink: the agent will accept remote commands **only**
  from your office/VPN IP(s) and will dial **only** your fixed dashboard
  address, with signed commands. The config hooks for this land with that uplink.

## Audit

Every powerful action and every login (success/failure), password change, and
tamper alert is in the audit log:
```powershell
.\ImakerAgentService.exe audit -days 30
```
Passwords are never written anywhere.
