# iMaker-Group-Endpoint-Agent
Lightweight Windows Endpoint Agent for iMaker Group (Activity Tracking, Telemetry &amp; Software Deployment)


# 🏢 iMaker Group — Windows Endpoint Agent Architecture & Roadmap

> **Enterprise IT Telemetry, Automated Design Activity Tracking & Targeted Deployment Engine**
> Built for **iMaker Furniture and Decor Trading** (UAE, KSA, Egypt, London, Miami branches).

---

## 📌 Executive Overview

The **iMaker Endpoint Agent** is a lightweight, high-performance background service engineered for Windows endpoints. It bridges the operational gap between creative designers/engineers and IT management by collecting passive productivity heartbeats and real-time hardware telemetry—without relying on manual timesheet entries, screen capture, or invasive surveillance.

### Key Capabilities
1. **Passive Time Tracking:** Captures active window titles from key design applications (**AutoCAD, Revit, 3ds Max, SketchUp**) and local **Dropbox** sync events to propose automated 1-tap timesheet suggestions.
2. **PC Telemetry & Health Monitoring:** Collects real-time CPU, RAM, NVMe SMART health, BitLocker status, Windows updates, and installed software registry inventory.
3. **Targeted Deployment & Remote Admin:** Supports secure, password-gated, and SHA-256 hash-verified software deployments, remote PC renames, and reboot commands targeted by office location or individual machine.

---

## 🏗️ System Architecture & Stack

### Technology Stack
- **Language:** **Go (Golang 1.22+)** — Single static binary compilation, zero runtime dependencies, low memory footprint (< 30 MB RAM).
- **Target OS:** Windows 10 / 11 Pro & Enterprise (64-bit).
- **Communication Protocol:** Named Pipes (`\\.\pipe\imaker_agent_ipc`) for internal IPC; HTTPS REST/JSON API for backend dashboard telemetry sync.

### Dual-Process Execution Model

┌────────────────────────────────────────────────────────────────────────┐
│                    iMaker Windows Endpoint (PC)                         │
│                                                                        │
│  ┌─────────────────────────────────┐   ┌────────────────────────────┐  │
│  │   ImakerTrayApp.exe             │   │  ImakerAgentService.exe    │  │
│  │   (User-Space Context)          │   │  (SYSTEM Service Context)  │  │
│  ├─────────────────────────────────┤   ├────────────────────────────┤  │
│  │ • Active Window Listener        │   │ • WMI Hardware Telemetry   │  │
│  │ • Idle Time Detector            │   │ • NVMe SMART Health        │  │
│  │ • Dropbox Save Monitor          │   │ • BitLocker & OS Status    │  │
│  │ • Privacy Browser Domain Filter │   │ • Software Registry Scan   │  │
│  │ • Local User Notifications      │   │ • Deployment & Exec Engine │  │
│  └────────────────┬────────────────┘   └─────────────┬──────────────┘  │
│                   │                                  │                 │
│                   └─────────► Local IPC Pipe ◄───────┘                 │
└──────────────────────────────────────┬─────────────────────────────────┘
│ (Encrypted HTTPS Payload)
▼
┌────────────────────────────────────────┐
│  iMaker IT Command Center & Odoo API   │
└────────────────────────────────────────┘


---

## 🚀 Core Modules & Features

### 1. Design Activity & Heartbeat Collector (`User-Space TrayApp`)
- **Process & Window Title Monitor:** Polls `GetForegroundWindow` every 2 seconds to capture active document titles from:
  - `acad.exe` (AutoCAD `.dwg`)
  - `revit.exe` (Revit `.rvt`)
  - `3dsmax.exe` (3ds Max `.max`)
  - `sketchup.exe` / `layout.exe` (SketchUp `.skp`)
- **Dropbox Event Watcher:** Listens for local file system modification events (`ReadDirectoryChangesW`) inside synchronized project directories matching project codes (e.g., `P-AZR_...`).
- **Idle Time Detector:** Checks system input idle time (`GetLastInputInfo`); automatically pauses activity recording after 5 minutes of inactivity.
- **Privacy Browser Domain Filter:** Records active domain names only (e.g., `github.com`, `pinterest.com`). Suppresses full URLs, query parameters, private windows, and personal domains (banking, personal webmail).

### 2. Hardware Telemetry & Health Collector (`SYSTEM Service`)
- **Hardware Inventory:** Queries WMI/Win32 APIs for CPU model, physical RAM configuration, GPU adapters, and disk serial numbers.
- **Disk & Storage SMART Health:** Monitors NVMe/SSD wear levels, temperature, and SMART failure indicators.
- **Security Audit:** Verifies BitLocker drive encryption status, Windows Defender engine status, and pending system updates.
- **Installed Software Registry Scanner:** Scans 64-bit and 32-bit uninstall registry keys (`HKLM\SOFTWARE\...`) to keep an up-to-date software inventory.

### 3. Remote Command & Deployment Engine (`SYSTEM Service`)
- **System Commands:**
  - **Restart Machine:** Triggers controlled system reboots (`InitiateSystemShutdownEx`).
  - **Rename Computer:** Renames hostname in Active Directory / Workgroup (`SetComputerNameExW`).
- **Software Deployment Handler:**
  - Accepts package payload: `URL`, `SHA-256 Hash`, `Silent Install Flags` (e.g., `/qn /norestart`), and `Admin Security Token`.
  - **Security Rule 1:** Enforces strict SHA-256 hash match against the downloaded installer before execution.
  - **Security Rule 2:** Rejects non-whitelisted executable installers.
  - Executes installation quietly in `SYSTEM` context and returns installer exit codes.

---

## 📂 Project Repository Structure

```
iMaker-Group-Endpoint-Agent/
├── .github/workflows/build.yml   # CI: test + build on Windows; publishes release .exe files on v* tags
├── cmd/
│   ├── agent/                    # ImakerTrayApp.exe — user-space tray app (+ assets/icon.ico)
│   └── service/                  # ImakerAgentService.exe — SYSTEM service + admin CLI
├── internal/
│   ├── config/                   # agent.json loader, defaults, paths, build version
│   ├── logging/                  # structured JSON logs with file rotation
│   └── service/                  # service core: RPC handlers, schedulers, install/uninstall
├── pkg/
│   ├── protocol/                 # shared JSON contracts (sessions, telemetry, JSON-RPC) for IPC & Odoo API
│   ├── tracker/                  # window polling, idle detection, Dropbox watcher, browser privacy filter, sessions
│   ├── telemetry/                # WMI: CPU/RAM/GPU, disk SMART/NVMe, BitLocker, Defender/AV, updates, software registry
│   ├── store/                    # offline JSONL storage + durable outbox
│   └── ipc/                      # named-pipe JSON-RPC server/client with token-verified callers
├── configs/agent.example.json    # default configuration
├── docs/DEVELOPER_GUIDE.md       # build, install, test, data locations, design notes
├── build.ps1                     # local Windows build script
├── go.mod / go.sum
└── README.md
```

> 🛠️ **Build, install & test instructions:** see [`docs/DEVELOPER_GUIDE.md`](docs/DEVELOPER_GUIDE.md).

---

## 📅 Development Phases & Roadmap

### Phase 1: Core Activity Tracking (`TrayApp`) — ✅ Completed
- [x] Create Go module & project folder layout.
- [x] Implement Active Window Title Listener (`GetForegroundWindow`).
- [x] Implement Idle Time Detector (`GetLastInputInfo`).
- [x] Implement Dropbox file watcher for `.rvt`, `.dwg`, `.max`, `.skp`.
- [x] Build local JSON (JSONL) buffer for offline activity queuing.

### Phase 2: Hardware Telemetry & System Service (`SystemService`) — ✅ Completed
- [x] Implement Windows Service wrapper (`golang.org/x/sys/windows/svc`).
- [x] Build WMI / Win32 collectors for CPU, RAM, NVMe SMART status, and BitLocker.
- [x] Build Registry scanner for installed software.
- [x] Establish Named Pipes IPC connection between Service and TrayApp.

### Phase 3: Targeted Deployment & Command Execution Engine
- [ ] Implement safe `Restart` and `Rename PC` handlers.
- [ ] Implement SHA-256 installer download and hash validation module.
- [ ] Implement silent installer execution runner (`/qn`, `/silent`).
- [ ] Add Local Mock Endpoint / CLI tester for dashboard API simulations.

---

## 🔐 Security & Privacy Commitments

1. **No Screen Captures:** The agent does **not** record screens, take screenshots, or log keystrokes.
2. **Whitelisted Deployments:** Remote installation requires pre-hashed installer approval and password authorization.
3. **Data Protection:** Telemetry and activity events are transmitted exclusively via encrypted HTTPS endpoints.
