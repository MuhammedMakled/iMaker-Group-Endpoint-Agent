//go:build windows

package service

import (
	"os"
	"path/filepath"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/update"
)

// winUpdater adapts the update package's Windows operations to the Updater interface.
type winUpdater struct{}

// InstallDir is the folder holding the running service binary (C:\Program Files\Imaker).
func (winUpdater) InstallDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

func (winUpdater) VerifySignature(path, subject string) error {
	return update.VerifySignature(path, subject)
}

func (winUpdater) SpawnUpdater(exe string) error {
	return update.SpawnDetached(exe, "apply-update")
}
