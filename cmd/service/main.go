//go:build windows

// Command service builds ImakerAgentService.exe — the SYSTEM-level service.
//
// Usage (elevated prompt):
//
//	ImakerAgentService.exe install [-tray "C:\Program Files\Imaker\ImakerTrayApp.exe"]
//	ImakerAgentService.exe start | stop | uninstall
//	ImakerAgentService.exe run          # foreground/debug mode, logs to console
//	ImakerAgentService.exe collect      # print one telemetry snapshot as JSON
//	ImakerAgentService.exe software     # print the software inventory as JSON
//	ImakerAgentService.exe status       # ping the running service over the pipe
//	ImakerAgentService.exe summary [-date 2026-10-09] [-user DOMAIN\user]
//	ImakerAgentService.exe asset [-json]          # serial number / asset identity
//	ImakerAgentService.exe set-asset-tag IMK-UAE-0042
//	ImakerAgentService.exe notify -title "..." -message "..." [-severity warning] [-url https://...] [-users "DOMAIN\a,DOMAIN\b"] [-ttl 24h]
//	ImakerAgentService.exe notifications          # list sent notifications and who saw them
//
// When launched by the Service Control Manager it runs as the service.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/logging"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/service"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/telemetry"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/winadmin"
)

func main() {
	if service.IsWindowsService() {
		cfg, log := setup(config.DefaultPath(), false)
		if err := service.RunAsService(cfg, log); err != nil {
			log.Error("service failed", "err", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "path to agent.json")
	tray := fs.String("tray", "", "path to ImakerTrayApp.exe to auto-start at logon (install)")
	date := fs.String("date", "", "YYYY-MM-DD (summary)")
	user := fs.String("user", "", `DOMAIN\user (summary; admins only for other users)`)
	asJSON := fs.Bool("json", false, "print JSON (asset)")
	title := fs.String("title", "", "notification title (notify)")
	message := fs.String("message", "", "notification text (notify)")
	severity := fs.String("severity", "info", "info | warning | critical (notify)")
	category := fs.String("category", "it", "update | it | health | policy (notify)")
	link := fs.String("url", "", "https link opened on click (notify)")
	button := fs.String("button", "", "button label for the link (notify)")
	users := fs.String("users", "", `comma-separated DOMAIN\user list; empty = everyone (notify)`)
	ttl := fs.String("ttl", "72h", "how long the notification stays deliverable (notify)")
	name := fs.String("name", "", "computer name (rename-pc) / process name (kill-process)")
	newUser := fs.String("username", "", "new local account name (create-user)")
	pw := fs.String("password", "", "password for the new account (create-user)")
	fullName := fs.String("fullname", "", "full name for the new account (create-user)")
	mkAdmin := fs.Bool("admin", false, "add the new account to local Administrators (create-user)")
	neverExp := fs.Bool("never-expires", false, "password never expires (create-user)")
	reason := fs.String("reason", "", "reason, recorded in the audit log (rename-pc / reset-pc)")
	confirm := fs.String("confirm", "", `reset confirmation: must be "RESET <HOSTNAME>" (reset-pc)`)
	scope := fs.String("scope", "remove_everything", "remove_everything | remove_everything_clean (reset-pc)")
	iUnderstand := fs.Bool("i-understand", false, "REQUIRED to actually wipe; without it, reset-pc is a dry run")
	delaySec := fs.Int("delay", 60, "seconds before the reset starts (reset-pc)")
	days := fs.Int("days", 30, "how many days of audit log to show (audit)")
	svcName := fs.String("service", "", "service name (services)")
	svcAction := fs.String("action", "", "start | stop | restart (services)")
	onlyRunning := fs.Bool("running", false, "only running services (services)")
	filter := fs.String("filter", "", "name filter (services/software)")
	startupID := fs.String("id", "", "startup item id (startup)")
	enable := fs.Bool("enable", false, "enable the startup item (startup); omit to disable")
	pid := fs.Int("pid", 0, "process id (kill-process)")
	btOn := fs.Bool("on", false, "turn Bluetooth on (bluetooth); omit for off")
	sessID := fs.Int("session", 0, "target session id (lock/signout; 0 = active console)")
	usbMode := fs.String("mode", "", "allow | read_only | block (usb)")
	checkIP := fs.String("ip", "", "IP to test against the allowlist (ipallow-check)")
	_ = fs.Parse(args)

	var err error
	switch cmd {
	case "install":
		exe, _ := os.Executable()
		trayPath := *tray
		if trayPath == "" {
			cand := filepath.Join(filepath.Dir(exe), "ImakerTrayApp.exe")
			if _, statErr := os.Stat(cand); statErr == nil {
				trayPath = cand
			}
		}
		if err = service.Install(exe, trayPath); err == nil {
			fmt.Println("Installed", config.ServiceName, "— start it with: ImakerAgentService.exe start")
		}
	case "uninstall":
		cfg, _ := config.Load(*cfgPath)
		if err = requireAdminForUninstall(cfg); err != nil {
			break
		}
		if err = service.Uninstall(); err == nil {
			fmt.Println("Uninstalled", config.ServiceName)
		}
	case "start":
		err = service.Start()
	case "stop":
		err = service.Control(svc.Stop, svc.Stopped)
	case "run":
		cfg, log := setup(*cfgPath, true)
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		err = service.Run(ctx, cfg, log)
	case "collect":
		cfg, log := setup(*cfgPath, true)
		ep := ""
		if cfg.DetectPublicIP {
			ep = cfg.PublicIPEndpoint
		}
		c := &telemetry.Collector{Logger: log, IncludeUpdateHistory: cfg.CollectWindowsUpdateHistory, PublicIPEndpoint: ep}
		err = printJSON(c.Collect(context.Background()))
	case "software":
		err = printJSON(telemetry.CollectSoftware())
	case "status":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.PingResult
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodPing, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "summary":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.ActivitySummaryResult
		p := protocol.ActivitySummaryParams{Date: *date, User: *user}
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodActivitySummary, p, &res); err == nil {
			err = printJSON(res)
		}
	case "asset":
		id := telemetry.CollectIdentity()
		if *asJSON {
			err = printJSON(id)
		} else {
			printIdentity(id)
		}
	case "set-asset-tag":
		tag := fs.Arg(0)
		if err = telemetry.SetAssetTag(tag); err == nil {
			if tag == "" {
				fmt.Println("Asset tag cleared.")
			} else {
				fmt.Println("Asset tag set to", tag)
			}
		}
	case "notify":
		cfg, _ := config.Load(*cfgPath)
		p := protocol.NotifySendParams{TTL: *ttl, Notification: protocol.Notification{
			Title: *title, Message: *message, Severity: *severity, Category: *category,
			URL: *link, ButtonLabel: *button, Users: splitList(*users), Source: "cli",
		}}
		var n protocol.Notification
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodNotifySend, p, &n); err == nil {
			target := "all users of this PC"
			if len(n.Users) > 0 {
				target = strings.Join(n.Users, ", ")
			}
			fmt.Printf("Queued %s for %s — it appears within ~30 s (or at next sign-in), until %s.\n",
				n.ID, target, n.ExpiresAt.Local().Format("02 Jan 15:04"))
		}
	case "notifications":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.NotifyListResult
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodNotifyList, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "performance", "perf":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.PerformanceSnapshot
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodPerformanceGet, protocol.PerformanceGetParams{}, &res); err == nil {
			err = printJSON(res)
		}
	case "rename-pc":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.RenamePCResult
		pp := protocol.RenamePCParams{NewName: *name, Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodActionRename, pp, &res)
		})
		if err == nil {
			fmt.Printf("Renamed %s -> %s. A restart is required to apply it.\n", res.OldName, res.NewName)
		}
	case "create-user":
		cfg, _ := config.Load(*cfgPath)
		pass := *pw
		if pass == "" {
			pass, err = readHiddenPassword("New account password: ")
			if err != nil {
				break
			}
		}
		var res protocol.CreateLocalUserResult
		pp := protocol.CreateLocalUserParams{Username: *newUser, Password: pass, FullName: *fullName,
			Administrator: *mkAdmin, PasswordNeverExpires: *neverExp}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodActionCreateUser, pp, &res)
		})
		if err == nil {
			msg := "Created local user " + res.Username
			if res.AddedToAdmins {
				msg += " (ADDED TO ADMINISTRATORS)"
			}
			fmt.Println(msg)
		}
	case "reset-pc":
		cfg, _ := config.Load(*cfgPath)
		host, _ := os.Hostname()
		if *confirm == "" {
			*confirm = winadmin.ResetConfirmToken(host)
			fmt.Printf("Using confirmation %q for this PC.\n", *confirm)
		}
		if *iUnderstand {
			fmt.Printf("\n*** This will ERASE ALL DATA on %s and reinstall Windows. ***\n", host)
			if !confirmInteractive(host) {
				fmt.Println("Aborted.")
				return
			}
		}
		var res protocol.ResetResult
		pp := protocol.ResetParams{Scope: protocol.ResetScope(*scope), Confirm: *confirm,
			Reason: *reason, DelaySeconds: *delaySec, Execute: *iUnderstand}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodActionReset, pp, &res)
		})
		if err == nil {
			fmt.Println(res.Message)
		}
	case "services":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.ServiceListResult
		pp := protocol.ServiceListParams{Filter: *filter, OnlyRunning: *onlyRunning}
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodServiceList, pp, &res); err == nil {
			err = printJSON(res)
		}
	case "service":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.ServiceControlResult
		pp := protocol.ServiceControlParams{Name: *svcName, Action: *svcAction, Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodServiceControl, pp, &res)
		})
		if err == nil {
			fmt.Printf("%s %s -> %s\n", res.Action, res.Name, res.Status)
		}
	case "startup":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.StartupListResult
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodStartupList, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "startup-toggle":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.StartupToggleResult
		pp := protocol.StartupToggleParams{ID: *startupID, Enable: *enable, Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodStartupToggle, pp, &res)
		})
		if err == nil {
			state := "disabled"
			if res.Enabled {
				state = "enabled"
			}
			fmt.Println("Startup item", state)
		}
	case "processes", "ps":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.ProcessListResult
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodProcessList, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "kill-process", "kill":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.ProcessKillResult
		pp := protocol.ProcessKillParams{PID: uint32(*pid), Name: *name, Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodProcessKill, pp, &res)
		})
		if err == nil {
			fmt.Printf("Killed PID %d\n", res.PID)
		}
	case "bluetooth":
		cfg, _ := config.Load(*cfgPath)
		// "bluetooth" with -on/off toggles; "bluetooth-status" just reads.
		var res protocol.BluetoothStatus
		pp := protocol.BluetoothSetParams{On: *btOn, Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodBluetoothSet, pp, &res)
		})
		if err == nil {
			fmt.Println("Bluetooth is now", res.State)
		}
	case "bluetooth-status":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.BluetoothStatus
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodBluetoothStatus, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "lock", "lock-workstation":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.SessionActionResult
		pp := protocol.SessionActionParams{SessionID: uint32(*sessID), Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodSessionLock, pp, &res)
		})
		if err == nil {
			fmt.Printf("Locked session %d (%s)\n", res.SessionID, res.User)
		}
	case "signout", "signout-user", "logoff":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.SessionActionResult
		pp := protocol.SessionActionParams{SessionID: uint32(*sessID), Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodSessionSignout, pp, &res)
		})
		if err == nil {
			fmt.Printf("Signed out session %d (%s)\n", res.SessionID, res.User)
		}
	case "sessions":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.SessionListResult
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodSessionList, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "usb-status":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.USBStatus
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodUSBStatus, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "usb":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.USBStatus
		pp := protocol.USBSetParams{Mode: *usbMode, Reason: *reason}
		err = ensurePrivileged(cfg, func(cl *ipc.Client) error {
			return cl.Call(context.Background(), protocol.MethodUSBSet, pp, &res)
		})
		if err == nil {
			fmt.Println("USB storage mode:", res.Mode, "-", res.Detail)
		}
	case "ipallow":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.IPAllowStatus
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodIPAllowStatus, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "ipallow-check":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.IPAllowCheckResult
		pp := protocol.IPAllowCheckParams{IP: *checkIP}
		if err = authedClient(cfg).Call(context.Background(), protocol.MethodIPAllowCheck, pp, &res); err == nil {
			err = printJSON(res)
		}
	case "set-admin-password", "set-password":
		cfg, _ := config.Load(*cfgPath)
		err = setAdminPasswordFlow(cfg)
	case "login":
		cfg, _ := config.Load(*cfgPath)
		err = loginFlow(cfg)
	case "logout":
		cfg, _ := config.Load(*cfgPath)
		tok := loadToken()
		if tok != "" {
			_ = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodAuthLogout, protocol.AuthLogoutParams{Token: tok}, nil)
		}
		clearToken()
		fmt.Println("Logged out.")
	case "auth-status":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.AuthStatusResult
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodAuthStatus, nil, &res); err == nil {
			err = printJSON(res)
		}
	case "audit":
		cfg, _ := config.Load(*cfgPath)
		var res protocol.AuditLogResult
		req := map[string]int{"days": *days}
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodActionListAudit, req, &res); err == nil {
			err = printJSON(res)
		}
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func setup(cfgPath string, console bool) (*config.Config, *slog.Logger) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error, using defaults:", err)
		cfg = config.Default()
		_ = cfg.Validate()
	}
	logPath := filepath.Join(config.ProgramDataDir(), "logs", "service.log")
	log, _, err := logging.New(logPath, cfg.LogLevel, console)
	if err != nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	slog.SetDefault(log)
	return cfg, log
}

func pipeName(cfg *config.Config) string {
	if cfg != nil && cfg.PipeName != "" {
		return cfg.PipeName
	}
	return config.DefaultPipeName
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func usage() {
	fmt.Fprintf(os.Stderr, `IMAKER Endpoint Agent Service %s

Usage: ImakerAgentService.exe <command> [flags]

Commands:
  install    Register the Windows service (run as administrator) [-tray path]
  uninstall  Stop and remove the service
  start      Start the service
  stop       Stop the service
  run        Run in the foreground (debug), Ctrl+C to stop
  collect    Print one telemetry snapshot as JSON
  software   Print the installed-software inventory as JSON
  status     Ping the running service over the named pipe
  summary    Print timesheet suggestions [-date YYYY-MM-DD] [-user DOMAIN\user]
  asset      Show the PC's serial number / asset identity [-json]
  set-asset-tag <TAG>   Store IT's asset tag on this PC (empty TAG clears it)
  notify     Send a notification to users of this PC (admin):
               -title "..." -message "..." [-severity info|warning|critical]
               [-url https://...] [-button "Open"] [-users "DOMAIN\a,DOMAIN\b"] [-ttl 24h]
  notifications  List notifications and who has seen them (admin)
  performance    Live CPU/RAM/disk load and the top apps by CPU and memory
  rename-pc      Rename this PC (admin): -name NEW-NAME -reason "..."  (needs reboot)
  create-user    Create a local account (admin):
                   -username ali.hassan [-fullname "Ali Hassan"] [-admin] [-never-expires]
                   (password is prompted hidden, or pass -password)
  reset-pc       Remotely reset/WIPE this PC (admin). Dry run by default:
                   -reason "..."  [-scope remove_everything|remove_everything_clean]
                   add -i-understand to actually wipe (also retypes the name to confirm)
  audit          Show the administrative action audit log (admin) [-days N]

 Global admin login (the security layer):
  set-admin-password    Set or change the global admin password (prompted)
  login                 Log in with the global admin password; caches a session
  logout                End the cached session
  auth-status           Show whether a password is set and the idle timeout

 Network / performance / inventory (admin, read-only):
  (network, battery, licensing and local-admins now appear in the collect command)

 System control:
  services              List services [-filter X] [-running]
  service               Start/stop/restart a service (login): -service NAME -action start|stop|restart
  startup               List startup apps
  startup-toggle        Enable/disable a startup app (login): -id ID [-enable]
  processes             List processes with CPU/RAM (alias: ps)
  kill-process          End a process (login): -pid N [-name safety-check]  (alias: kill)
  bluetooth             Turn Bluetooth on/off (login): -on to enable, omit for off
  bluetooth-status      Show Bluetooth state
  lock                  Lock the user's screen (login): [-session N]
  signout               Sign the user out (login): [-session N]
  sessions              List interactive user sessions
  usb-status            Show USB storage access (allow/read_only/block)
  usb                   Set USB storage access (login): -mode allow|read_only|block
  ipallow               Show the IP allowlist (for the Phase-3 remote uplink)
  ipallow-check         Test an IP against the allowlist: -ip 203.0.113.5
`, config.Version)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printIdentity(id protocol.AssetIdentity) {
	host, _ := os.Hostname()
	kind := "Branded PC (BIOS serial)"
	if id.IsCustomBuild {
		kind = "Custom-built PC (no BIOS serial — using fallback)"
	}
	row := func(k, v string) {
		if v != "" {
			fmt.Printf("  %-22s %s\n", k, v)
		}
	}
	fmt.Println()
	row("Computer name:", host)
	row("Type:", kind)
	row("Chassis:", id.ChassisType)
	fmt.Println()
	row("SERIAL NUMBER:", id.SerialNumber)
	row("  source:", id.SerialSource)
	row("ASSET TAG:", id.AssetTag)
	row("  source:", id.AssetTagSource)
	row("Hardware ID:", id.HardwareFingerprint)
	fmt.Println()
	fmt.Println("  Raw identifiers:")
	row("BIOS serial:", id.BIOSSerial)
	row("Chassis serial:", id.EnclosureSerial)
	row("Motherboard:", strings.TrimSpace(id.BaseboardManufacturer+" "+id.BaseboardProduct))
	row("Motherboard serial:", id.BaseboardSerial)
	row("SMBIOS UUID:", id.SMBIOSUUID)
	row("Boot disk serial:", id.BootDiskSerial)
	row("Onboard MAC:", id.PrimaryMAC)
	row("Windows MachineGuid:", id.MachineGUID)
	fmt.Println()
}
