package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/ipc"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/update"
)

// Updater is the Windows side of self-update. It is nil outside Windows, where
// upgrade-agent refuses to run.
type Updater interface {
	InstallDir() string
	VerifySignature(path, subject string) error
	SpawnUpdater(exe string) error
}

// SetUpdater installs the OS updater implementation.
func (c *Core) SetUpdater(u Updater) { c.upd = u }

// updateDirs is %ProgramData%\Imaker\updates. dataDir is ...\Imaker\data, so
// the parent is the Imaker root in production and a temp dir in tests.
func (c *Core) updateDirs() update.Dirs {
	return update.Dirs{Root: filepath.Join(filepath.Dir(c.dataDir), "updates")}
}

func (c *Core) registerUpgrade(m *ipc.Mux) {
	m.HandlePrivileged(protocol.MethodAgentUpgrade, c.handleUpgradeAgent)
}

func (c *Core) handleUpgradeAgent(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.UpgradeAgentParams
	if err := ipc.DecodeParams(raw, &p); err != nil {
		return nil, err
	}
	caller := ipc.CallerFrom(ctx)
	res, err := c.startUpgrade(ctx, p, caller)
	// Audit the host only: a download URL can carry sensitive query strings.
	host := ""
	if u, perr := url.Parse(p.DownloadURL); perr == nil {
		host = u.Hostname()
	}
	c.audit(caller, "agent_upgrade", p.TargetVersion, fmt.Sprintf("from=%s; host=%s", config.Version, host), err)
	if err != nil {
		return nil, ipc.InvalidParams("%v", err)
	}
	return res, nil
}

// startUpgrade validates, downloads, verifies and stages the bundle, backs up
// the current binaries, then hands off to the updater. The service keeps
// running until the updater stops it. Nothing installed is replaced here.
func (c *Core) startUpgrade(ctx context.Context, p protocol.UpgradeAgentParams, caller ipc.Caller) (protocol.UpgradeAgentResult, error) {
	res := protocol.UpgradeAgentResult{Status: update.StatusAccepted, FromVersion: config.Version, TargetVersion: p.TargetVersion}
	if c.upd == nil {
		return res, errors.New("self-update is only supported on Windows")
	}

	req := update.Request{DownloadURL: p.DownloadURL, TargetVersion: p.TargetVersion, SHA256: p.SHA256}
	if err := req.Validate(update.Policy{AllowedHosts: c.cfg.UpdateAllowedHosts, Current: config.Version}); err != nil {
		return res, err
	}

	d := c.updateDirs()
	if prev, err := update.ReadState(d); err == nil {
		switch {
		case prev.Phase == update.PhaseApplying:
			return res, errors.New("an upgrade is already in progress")
		case !prev.Reported && (prev.Phase == update.PhaseSuccess || prev.Phase == update.PhaseFailed):
			return res, errors.New("the previous upgrade result has not been reported yet; configure update_report_url or retry later")
		}
	}

	if err := os.MkdirAll(d.Incoming(), 0o755); err != nil {
		return res, err
	}
	zipPath := filepath.Join(d.Incoming(), p.TargetVersion+".zip")
	defer os.Remove(zipPath)
	if err := update.Download(ctx, c.httpClient, p.DownloadURL, zipPath, update.MaxBundleBytes, c.cfg.UpdateAllowedHosts); err != nil {
		return res, err
	}
	// The hash is checked before the bundle is opened as a zip.
	if err := update.VerifySHA256(zipPath, p.SHA256); err != nil {
		return res, err
	}
	files, err := update.ExtractBundle(zipPath, d.Staged(p.TargetVersion))
	if err != nil {
		return res, err
	}
	if c.cfg.UpdateRequireSignature {
		for _, name := range update.BundleFiles {
			if err := c.upd.VerifySignature(files[name], c.cfg.UpdateSignerSubject); err != nil {
				return res, err
			}
		}
	}

	// Back up the installed binaries and copy the running service as the updater.
	install := c.upd.InstallDir()
	if err := os.MkdirAll(d.Backup(), 0o755); err != nil {
		return res, err
	}
	for _, name := range update.BundleFiles {
		if err := copyFileTo(filepath.Join(install, name), filepath.Join(d.Backup(), name)); err != nil {
			return res, fmt.Errorf("back up %s: %w", name, err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		return res, err
	}
	if err := copyFileTo(self, d.Updater()); err != nil {
		return res, fmt.Errorf("prepare updater: %w", err)
	}

	st := update.State{
		Phase: update.PhaseApplying, FromVersion: config.Version, TargetVersion: p.TargetVersion,
		InstallDir: install, Caller: caller.User, RequestedAt: time.Now().UTC(),
	}
	if err := update.WriteState(d, st); err != nil {
		return res, err
	}
	if err := c.upd.SpawnUpdater(d.Updater()); err != nil {
		st.Phase, st.Status = update.PhaseFailed, update.StatusFailed
		st.Error = "could not start updater: " + err.Error()
		st.FinishedAt = time.Now().UTC()
		_ = update.WriteState(d, st)
		return res, err
	}
	c.log.Info("agent upgrade accepted", "from", config.Version, "to", p.TargetVersion, "caller", caller.User)
	return res, nil
}

// MarkHealthy records that this process started successfully. The updater
// waits for this record (for the target version) before it finishes.
func (c *Core) MarkHealthy() {
	if err := update.WriteHealth(c.updateDirs(), config.Version, time.Now().UTC()); err != nil {
		c.log.Warn("write health record", "err", err)
	}
}

// ReportUpgradeResult posts a finished upgrade once. It does nothing until
// update_report_url is configured, so the result stays in state.json.
func (c *Core) ReportUpgradeResult(ctx context.Context) {
	if c.cfg.UpdateReportURL == "" {
		return
	}
	d := c.updateDirs()
	st, err := update.ReadState(d)
	if err != nil || st.Reported || (st.Phase != update.PhaseSuccess && st.Phase != update.PhaseFailed) {
		return
	}
	rep := update.Report{
		Status: st.Status, FromVersion: st.FromVersion, TargetVersion: st.TargetVersion,
		Error: st.Error, FinishedAt: st.FinishedAt, Hostname: c.hostname,
	}
	if err := update.PostReport(ctx, c.httpClient, c.cfg.UpdateReportURL, rep); err != nil {
		c.log.Warn("upgrade result not delivered; will retry", "err", err)
		return
	}
	st.Reported = true
	if err := update.WriteState(d, st); err != nil {
		c.log.Warn("mark upgrade reported", "err", err)
	}
	c.log.Info("upgrade result reported", "status", st.Status, "target", st.TargetVersion)
}

func copyFileTo(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
