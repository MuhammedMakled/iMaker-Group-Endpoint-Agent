//go:build windows

package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/yusufpapurcu/wmi"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/internal/config"
	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// WMI namespaces used by the collectors.
const (
	nsCIMV2     = `root\CIMV2`
	nsStorage   = `root\Microsoft\Windows\Storage`
	nsWMI       = `root\WMI`
	nsBitLocker = `root\CIMV2\Security\MicrosoftVolumeEncryption`
	nsSecCenter = `root\SecurityCenter2`
	nsDefender  = `root\Microsoft\Windows\Defender`
)

// wmiClient tolerates class/field differences across Windows 10/11 builds:
// missing properties are skipped and NULLs become zero values / nil pointers.
var wmiClient = &wmi.Client{AllowMissingFields: true, PtrNil: true, NonePtrZero: true}

func query(namespace, q string, dst any) error {
	return wmiClient.Query(q, dst, nil, namespace)
}

// Collector gathers a full TelemetrySnapshot. Most sections require SYSTEM
// or elevated admin rights (BitLocker, reliability counters, Defender).
type Collector struct {
	Logger *slog.Logger
	// IncludeUpdateHistory queries the Windows Update Agent COM API for the
	// last successful install (adds ~1–3 s).
	IncludeUpdateHistory bool
}

type section struct {
	name string
	fn   func(*protocol.TelemetrySnapshot) error
}

// Collect runs every section, recording (not propagating) per-section errors.
func (c *Collector) Collect(ctx context.Context) protocol.TelemetrySnapshot {
	log := c.Logger
	if log == nil {
		log = slog.Default()
	}
	start := time.Now()
	snap := protocol.TelemetrySnapshot{
		SchemaVersion: protocol.SchemaVersion,
		AgentVersion:  config.Version,
		CollectedAt:   start.UTC(),
	}
	snap.System.Hostname, _ = os.Hostname()

	sections := []section{
		{"system", collectSystem},
		{"cpu", collectCPU},
		{"gpu", collectGPU},
		{"disks", collectPhysicalDisks},
		{"volumes", collectVolumes},
		{"bitlocker", collectBitLocker},
		{"antivirus", collectAntivirus},
		{"defender", collectDefender},
		{"updates", func(s *protocol.TelemetrySnapshot) error { return collectUpdates(s, c.IncludeUpdateHistory) }},
	}
	for _, sec := range sections {
		if ctx.Err() != nil {
			snap.Errors = append(snap.Errors, "collection cancelled")
			break
		}
		t0 := time.Now()
		err := safeRun(sec.fn, &snap)
		if err != nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("%s: %v", sec.name, err))
			log.Warn("telemetry section failed", "section", sec.name, "err", err)
		}
		log.Debug("telemetry section", "section", sec.name, "ms", time.Since(t0).Milliseconds())
	}
	snap.DurationMs = time.Since(start).Milliseconds()
	return snap
}

// safeRun converts panics inside COM/WMI code into errors.
func safeRun(fn func(*protocol.TelemetrySnapshot) error, s *protocol.TelemetrySnapshot) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return fn(s)
}
