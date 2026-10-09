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

	"golang.org/x/sys/windows/svc"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/logging"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/service"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/telemetry"
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
`, config.Version)
}
