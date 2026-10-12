//go:build windows

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/update"
)

// runApplyUpdate is the updater process: it applies the pending upgrade or
// rolls it back. Returns the process exit code.
func runApplyUpdate() int {
	logDir := filepath.Join(config.ProgramDataDir(), "logs")
	_ = os.MkdirAll(logDir, 0o755)
	f, err := os.OpenFile(filepath.Join(logDir, "updater.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return 1
	}
	defer f.Close()
	log := slog.New(slog.NewTextHandler(f, nil))

	d := update.Dirs{Root: filepath.Join(config.ProgramDataDir(), "updates")}
	ops := update.WinOps{ServiceName: config.ServiceName, TrayName: config.TrayAppName + ".exe"}
	st, err := update.RunUpdater(d, ops, update.HealthTimeout)
	if err != nil {
		log.Error("apply-update failed", "err", err)
		return 1
	}
	log.Info("apply-update finished", "status", st.Status, "target", st.TargetVersion,
		"error", st.Error, "finished", st.FinishedAt.Format(time.RFC3339))
	if st.Phase != update.PhaseSuccess {
		return 1
	}
	return 0
}
