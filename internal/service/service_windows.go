//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/sysctl"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/telemetry"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/winadmin"
)

// WindowsSource adapts the telemetry package to TelemetrySource.
type WindowsSource struct {
	Collector *telemetry.Collector
}

func (w WindowsSource) Collect(ctx context.Context) protocol.TelemetrySnapshot {
	return w.Collector.Collect(ctx)
}

func (w WindowsSource) Software(context.Context) protocol.SoftwareInventory {
	return telemetry.CollectSoftware()
}

func (w WindowsSource) Identity(context.Context) protocol.AssetIdentity {
	return telemetry.CollectIdentity()
}

func (w WindowsSource) Performance(ctx context.Context, p protocol.PerformanceGetParams) protocol.PerformanceSnapshot {
	return telemetry.CollectPerformance(ctx, p)
}

// winExecutor implements ActionExecutor using the winadmin package.
type winExecutor struct{}

func (winExecutor) Hostname() string              { return osHostname() }
func (winExecutor) RenamePC(newName string) error { return winadmin.RenamePC(newName) }
func (winExecutor) CreateLocalUser(username, password, fullName, comment string, admin, neverExpires bool) (string, bool, error) {
	return winadmin.CreateLocalUser(username, password, fullName, comment, admin, neverExpires)
}
func (winExecutor) ResetCommand(scope string) []string    { return winadmin.ResetArgs(scope) }
func (winExecutor) RunReset(scope string) (string, error) { return winadmin.RunReset(scope) }

// winControl implements ControlProvider using the sysctl package.
type winControl struct{}

func (winControl) ListServices(filter string, onlyRunning bool) ([]protocol.ServiceInfo, error) {
	return sysctl.ListServices(filter, onlyRunning)
}
func (winControl) ControlService(name, action string) (string, error) {
	return sysctl.ControlService(name, action)
}
func (winControl) ListStartup() ([]protocol.StartupItem, error) { return sysctl.ListStartup() }
func (winControl) ToggleStartup(id string, enable bool) error {
	return sysctl.ToggleStartup(id, enable)
}
func (winControl) ListProcesses() ([]protocol.ProcessInfo, error) {
	return sysctl.ListProcesses(runtime.NumCPU())
}
func (winControl) KillProcess(pid uint32, name string) error          { return sysctl.KillProcess(pid, name) }
func (winControl) BluetoothStatus() (protocol.BluetoothStatus, error) { return sysctl.GetBluetooth() }
func (winControl) SetBluetooth(on bool) (protocol.BluetoothStatus, error) {
	return sysctl.SetBluetooth(on)
}

// Run starts the core (IPC server + schedulers) and blocks until ctx ends.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	endpoint := ""
	if cfg.DetectPublicIP {
		endpoint = cfg.PublicIPEndpoint
	}
	src := WindowsSource{Collector: &telemetry.Collector{Logger: log, IncludeUpdateHistory: cfg.CollectWindowsUpdateHistory, PublicIPEndpoint: endpoint}}
	core, err := NewCore(cfg, log, src, filepath.Join(config.ProgramDataDir(), "data"))
	if err != nil {
		return err
	}
	core.SetExecutor(winExecutor{})
	core.SetControl(winControl{})
	mux := ipc.NewMux(log)
	core.Register(mux)
	srv := &ipc.Server{PipeName: cfg.PipeName, Mux: mux, Logger: log}

	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	wg.Add(2)
	go func() { defer wg.Done(); errCh <- srv.Serve(ctx) }()
	go func() { defer wg.Done(); core.RunSchedulers(ctx) }()

	select {
	case <-ctx.Done():
	case err = <-errCh:
		if err != nil {
			log.Error("ipc server failed", "err", err)
		}
	}
	wg.Wait()
	return err
}

// handler implements svc.Handler for the SCM.
type handler struct {
	cfg *config.Config
	log *slog.Logger
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, h.cfg, h.log) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	h.log.Info("service running", "version", config.Version)

	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				h.log.Error("service stopped with error", "err", err)
				return false, 1 // non-zero exit triggers SCM recovery (restart)
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				h.log.Info("service stopping", "cmd", c.Cmd)
				status <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				cancel()
				select {
				case <-done:
				case <-time.After(12 * time.Second):
					h.log.Warn("shutdown timed out")
				}
				return false, 0
			}
		}
	}
}

// RunAsService hands control to the SCM.
func RunAsService(cfg *config.Config, log *slog.Logger) error {
	return svc.Run(config.ServiceName, &handler{cfg: cfg, log: log})
}

// IsWindowsService reports whether we were launched by the SCM.
func IsWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// ---- Install / uninstall ----

// dataDirSDDL: SYSTEM + Administrators full control, Users read/execute only,
// so standard users cannot tamper with stored activity or config.
const dataDirSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// Install registers the service (LocalSystem, delayed auto-start, restart on
// failure), hardens %ProgramData%\Imaker, writes a default config and
// registers the tray app to start at every user logon.
func Install(exePath, trayPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM (run as administrator): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(config.ServiceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", config.ServiceName)
	}
	s, err := m.CreateService(config.ServiceName, exePath, mgr.Config{
		DisplayName:      config.ServiceDisplay,
		Description:      "IMAKER IT Command Center endpoint agent: hardware telemetry, disk health, BitLocker and software inventory.",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	recovery := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}
	if err := s.SetRecoveryActions(recovery, uint32((24 * time.Hour).Seconds())); err != nil {
		fmt.Fprintln(os.Stderr, "warning: set recovery actions:", err)
	}

	dir := config.ProgramDataDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		return err
	}
	if err := hardenDir(dir); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not harden data directory ACL:", err)
	}
	if err := config.WriteExample(config.DefaultPath()); err != nil {
		fmt.Fprintln(os.Stderr, "warning: write default config:", err)
	}
	if trayPath != "" {
		if err := setTrayAutostart(trayPath); err != nil {
			fmt.Fprintln(os.Stderr, "warning: register tray autostart:", err)
		}
	}
	return nil
}

// Uninstall stops and removes the service and the tray autostart entry.
// Collected data in %ProgramData%\Imaker is left in place.
func Uninstall() error {
	_ = Control(svc.Stop, svc.Stopped)
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(config.ServiceName)
	if err != nil {
		return fmt.Errorf("service not installed: %w", err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE|registry.WOW64_64KEY); err == nil {
		_ = k.DeleteValue(config.TrayAppName)
		k.Close()
	}
	return nil
}

// Start starts the installed service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(config.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

// Control sends cmd and waits up to 20 s for the target state.
func Control(cmd svc.Cmd, want svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(config.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Control(cmd)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for st.State != want {
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for service state change")
		}
		time.Sleep(300 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

const runKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

func setTrayAutostart(trayPath string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(config.TrayAppName, `"`+trayPath+`"`)
}

func hardenDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
