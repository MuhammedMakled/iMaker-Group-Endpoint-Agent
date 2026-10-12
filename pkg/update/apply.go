package update

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// Ops is the set of Windows operations the updater needs. The production
// implementation is WinOps (ops_windows.go); tests use a fake.
type Ops interface {
	StopTray() error                         // best effort: the tray may not be running
	StopService(timeout time.Duration) error // stop and wait until fully stopped
	StartService() error                     // start and return once running is requested
	CopyFile(src, dst string) error          // replace dst with src
}

// RunUpdater applies the pending update recorded in state.json. It is the
// logic behind the hidden `apply-update` command, which runs from
// updates\updater.exe after the service has accepted the request.
//
// Sequence:
//  1. Stop the tray, then stop the service.
//  2. Copy the staged binaries over the installed ones.
//  3. Start the service and wait up to healthTimeout for the new version to
//     write its health record.
//  4. On any failure after step 2, restore the backups, start the old service
//     and record UPGRADE_FAILED. Otherwise record UPGRADE_SUCCESS.
//
// The returned State is the final state that was written to disk.
func RunUpdater(d Dirs, ops Ops, healthTimeout time.Duration) (State, error) {
	st, err := ReadState(d)
	if err != nil {
		return st, err
	}
	if st.Phase != PhaseApplying {
		return st, fmt.Errorf("no update is pending (phase %q)", st.Phase)
	}
	if st.InstallDir == "" || st.TargetVersion == "" {
		return failNow(d, st, errors.New("state is missing install_dir or target_version"))
	}

	_ = ops.StopTray()
	if err := ops.StopService(60 * time.Second); err != nil {
		// Nothing has been replaced yet, so just bring the service back.
		_ = ops.StartService()
		return failNow(d, st, fmt.Errorf("stop service: %w", err))
	}

	staged := d.Staged(st.TargetVersion)
	for _, f := range BundleFiles {
		if err := ops.CopyFile(filepath.Join(staged, f), filepath.Join(st.InstallDir, f)); err != nil {
			return rollback(d, ops, st, fmt.Errorf("copy %s: %w", f, err))
		}
	}

	since := time.Now()
	if err := ops.StartService(); err != nil {
		return rollback(d, ops, st, fmt.Errorf("start service: %w", err))
	}
	if err := WaitForHealth(d, st.TargetVersion, since, healthTimeout); err != nil {
		return rollback(d, ops, st, err)
	}

	st.Phase = PhaseSuccess
	st.Status = StatusSuccess
	st.Error = ""
	st.FinishedAt = time.Now().UTC()
	return st, WriteState(d, st)
}

// rollback restores the backed-up binaries and restarts the previous service.
// The failure is written to state before the old service starts, so the
// reporting loop sees the final result as soon as the old service is back.
func rollback(d Dirs, ops Ops, st State, cause error) (State, error) {
	_ = ops.StopService(60 * time.Second) // may already be stopped

	var restoreErr error
	for _, f := range BundleFiles {
		if err := ops.CopyFile(filepath.Join(d.Backup(), f), filepath.Join(st.InstallDir, f)); err != nil && restoreErr == nil {
			restoreErr = fmt.Errorf("restore %s: %w", f, err)
		}
	}

	st.Phase = PhaseFailed
	st.Status = StatusFailed
	st.Error = cause.Error()
	if restoreErr != nil {
		st.Error += "; ROLLBACK INCOMPLETE: " + restoreErr.Error()
	}
	st.FinishedAt = time.Now().UTC()
	if err := WriteState(d, st); err != nil {
		return st, err
	}
	if err := ops.StartService(); err != nil {
		st.Error += "; restart after rollback failed: " + err.Error()
		_ = WriteState(d, st)
		return st, err
	}
	return st, nil
}

// failNow records a failure that happened before any file was replaced.
func failNow(d Dirs, st State, cause error) (State, error) {
	st.Phase = PhaseFailed
	st.Status = StatusFailed
	st.Error = cause.Error()
	st.FinishedAt = time.Now().UTC()
	return st, WriteState(d, st)
}
