# IMAKER Endpoint Agent — Phase 1 & 2

Windows endpoint agent for the **IMAKER IT Command Center & Time Tracking System**.
Pure Go, CGO-free, two small static binaries (~3.5 MB each).

| Binary | Runs as | Does |
|---|---|---|
| `ImakerTrayApp.exe` (`cmd/agent`) | Logged-in user (standard rights) | Foreground-window tracking for AutoCAD / Revit / 3ds Max / SketchUp, idle detection, Dropbox/project file watcher, privacy-filtered browser categorisation, work-session building, offline outbox |
| `ImakerAgentService.exe` (`cmd/service`) | `LocalSystem` Windows service | Hardware specs, disk health (SMART / NVMe reliability counters), BitLocker, AV/Defender, Windows Update state, installed-software inventory, machine-wide activity store, named-pipe JSON-RPC API |

```
 ┌──────────── user session ────────────┐        ┌──────────── session 0 (SYSTEM) ─────────────┐
 │ ImakerTrayApp.exe                    │        │ ImakerAgentService.exe                      │
 │  tracker ─► aggregator ─► sessions   │ JSON-  │  ipc.Server (\\.\pipe\imaker_agent_ipc)     │
 │  filewatch (ReadDirectoryChangesW) ─┘│  RPC   │   ├ activity.submit/query/summary           │
 │  outbox.jsonl ──────── submit ───────┼───────►│   ├ telemetry.get   ├ software.list         │
 │  %LOCALAPPDATA%\Imaker               │  pipe  │  telemetry (WMI) + registry scanners        │
 └──────────────────────────────────────┘        │  %ProgramData%\Imaker\data  (ACL-hardened)  │
                                                 └──── Phase 3: actions/deploy, backend uplink ┘
```

## Project layout

```
cmd/agent/            ImakerTrayApp.exe (tray UI, wiring)       + assets/icon.ico
cmd/service/          ImakerAgentService.exe (SCM + CLI)
internal/config/      agent.json loader, defaults, paths, version
internal/logging/     slog JSON logger + size-rotating file
internal/service/     service core: RPC handlers, schedulers, install/uninstall, SCM handler
pkg/protocol/         shared JSON contracts (sessions, telemetry, JSON-RPC) — reuse for Odoo/API
pkg/tracker/          classifier, browser privacy filter, session aggregator, timesheet summary,
                      Win32 foreground/idle (win32_windows.go), file watcher (filewatch_windows.go)
pkg/telemetry/        WMI collectors (hardware, disks, BitLocker, security, updates), registry inventory
pkg/store/            day-partitioned JSONL store + durable outbox (no CGO, no SQLite needed)
pkg/ipc/              JSON-RPC mux/client + named-pipe server with caller identity from token
```

All decision logic (classification, privacy rules, session math, RPC auth, decoding) is
OS-independent and unit-tested; only thin syscall/WMI adapters live in `*_windows.go`.

## Build

Requires Go 1.22+. From the repo root:

```powershell
go mod tidy
go test ./...
.\build.ps1 -Version 1.0.0          # outputs to .\dist
```
or manually / from Linux / macOS:
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H=windowsgui -X github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config.Version=1.0.0" -o dist/ImakerTrayApp.exe ./cmd/agent
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config.Version=1.0.0" -o dist/ImakerAgentService.exe ./cmd/service
```
Code-sign both binaries before fleet rollout (Defender/SmartScreen treat unsigned agents harshly).

## Install & test on one PC (elevated PowerShell)

```powershell
mkdir "C:\Program Files\Imaker"; copy dist\*.exe "C:\Program Files\Imaker\"
cd "C:\Program Files\Imaker"
.\ImakerAgentService.exe collect            # 1. sanity check: full telemetry JSON, no service needed
.\ImakerAgentService.exe software | more
.\ImakerAgentService.exe install            # registers service + HKLM\...\Run for the tray app
.\ImakerAgentService.exe start
.\ImakerAgentService.exe status             # ping over the named pipe
```
Then, as the normal user: start `ImakerTrayApp.exe` (or sign out/in). Open a `P-1023_Model.rvt`
in Revit for a few minutes, save it, switch to AutoCAD, then:
```powershell
.\ImakerAgentService.exe summary            # today's timesheet suggestions for you
```
Debug the tray without the icon: `ImakerTrayApp.exe -console`.

Uninstall: `ImakerAgentService.exe uninstall` (data in `%ProgramData%\Imaker` is kept).

## Where data lives

| Path | Content |
|---|---|
| `%ProgramData%\Imaker\agent.json` | Config (written with defaults on install; push via GPO/Intune) |
| `%ProgramData%\Imaker\data\activity\sessions-YYYY-MM-DD.jsonl` | Machine-wide work sessions (all users) |
| `%ProgramData%\Imaker\data\telemetry\latest.json` + daily history | Telemetry snapshots |
| `%ProgramData%\Imaker\data\software\latest.json` | Software inventory |
| `%ProgramData%\Imaker\logs\service.log` | Service log (rotating 10 MB × 3) |
| `%LOCALAPPDATA%\Imaker\activity\` | The user's own copy (tray menu → "Open my activity folder") |
| `%LOCALAPPDATA%\Imaker\outbox.jsonl` | Records not yet acknowledged by the service |

`%ProgramData%\Imaker` is ACL-hardened on install: SYSTEM/Admins full control, Users read-only.

## Key behaviour

**Session building** — 2 s samples are folded into `WorkSession`s keyed by app + project + file
(or browser category/domain). A session closes on switch, on idle (≥ 5 min via `GetLastInputInfo`,
and the end time is trimmed back to the *last input*, so idle time is never billed), on a sampling
gap > 30 s (sleep/hibernate), on lock screen / untracked app, on user pause, and on shutdown.
Sessions < 15 s (alt-tab flicker) are dropped. File saves from the watcher are credited to the open
session (`file_saves`).

**Project codes** — default pattern `(?:^|[^A-Za-z0-9])(P-[A-Z0-9]+)(?:[^A-Za-z0-9]|$)` (capture group
1 is the code; `_` counts as a separator so `P-1023_Model.rvt` → `P-1023`). Checked in the file name,
then the window title, then the folder path for file events. Add more patterns in `agent.json`.

**Timesheet suggestions** — `activity.summary` groups a day's Design + Browser-Work sessions by
user and project and rounds each project-day **up** to 15 min (`round_to_minutes`). Untagged work
is reported as `UNASSIGNED` so the user can allocate it with one tap.

**Privacy** — browser titles and URLs are never stored. InPrivate/Private/Incognito windows are
ignored. Personal domains/keywords (banking, Gmail, social) → `Browser - Other` with no domain.
Only allow-listed work domains are recorded. Users can pause tracking from the tray
(`allow_user_pause`, default on) and can see everything recorded about them locally.

**Security** — the pipe ACL allows SYSTEM/Admins full and authenticated users read/write. The
server resolves every caller's identity from the client process token
(`GetNamedPipeClientProcessId` → `OpenProcessToken`): submitted sessions are stamped with the
*verified* user (payload user is ignored), non-admins can only query their own activity, and
`Mux.HandleAdmin` requires an elevated admin or SYSTEM — this is the hook for Phase 3 actions.
Re-sent batches are de-duplicated by session ID, so the tray's at-least-once delivery is safe.

## Known limitations / Phase 3 notes

1. **Browser domains.** Chrome/Edge/Firefox don't put the URL in the window title, so out of the
   box the tray classifies browser time via configurable title keywords (privacy-safe but coarse).
   Exact domains need a `tracker.DomainProvider`; the recommended implementation is a small
   force-installed browser extension (Chrome/Edge `ExtensionInstallForcelist` policy) that sends
   only the active tab's host to the tray via native messaging. UI Automation on the address bar is
   the no-extension alternative but is fragile across browser versions.
2. **Elevated CAD apps.** If a user runs Revit "as administrator", the standard-user tray can't
   read its process name (`OpenProcess` access denied) and that time won't be tracked.
3. **GPU VRAM** — `Win32_VideoController.AdapterRAM` caps at 4 GB, so the agent also reads
   `HardwareInformation.qwMemorySize` from the display-adapter registry key for the true size.
4. **SMART** — NVMe health comes from `MSFT_StorageReliabilityCounter` (temperature, wear %, power-on
   hours, error counts); the legacy `MSStorageDriver_FailurePredictStatus` only covers ATA/SATA.
   Some USB/RAID controllers expose neither — fields are then omitted, not zero.
5. **Unclean logoff** — if the tray is killed without a shutdown message, the currently open
   session (≤ a few minutes) is lost; everything already closed is on disk.
6. **Phase 3 hooks ready:** `Mux.HandleAdmin` for `action.restart` / `action.rename` /
   `deploy.install`; `pkg/protocol` is the wire schema for the backend uplink; the service's daily
   JSONL files are the upload source.
