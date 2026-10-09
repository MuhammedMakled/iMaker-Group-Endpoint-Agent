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
	name := fs.String("name", "", "new computer name (rename-pc)")
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
		c := &telemetry.Collector{Logger: log, IncludeUpdateHistory: cfg.CollectWindowsUpdateHistory}
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
		p := protocol.RenamePCParams{NewName: *name, Reason: *reason}
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodActionRename, p, &res); err == nil {
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
		p := protocol.CreateLocalUserParams{Username: *newUser, Password: pass, FullName: *fullName,
			Administrator: *mkAdmin, PasswordNeverExpires: *neverExp}
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodActionCreateUser, p, &res); err == nil {
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
		p := protocol.ResetParams{Scope: protocol.ResetScope(*scope), Confirm: *confirm,
			Reason: *reason, DelaySeconds: *delaySec, Execute: *iUnderstand}
		if err = ipc.NewClient(pipeName(cfg)).Call(context.Background(), protocol.MethodActionReset, p, &res); err == nil {
			fmt.Println(res.Message)
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
