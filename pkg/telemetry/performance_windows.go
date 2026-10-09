//go:build windows

package telemetry

import (
	"context"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// CollectPerformance returns a live utilization snapshot. CPU% uses WMI's
// pre-computed formatted counters (one query, no manual sampling), so SampleMs
// reflects WMI's refresh window rather than a busy loop.
func CollectPerformance(ctx context.Context, p protocol.PerformanceGetParams) protocol.PerformanceSnapshot {
	topN := p.TopN
	if topN <= 0 || topN > 50 {
		topN = 10
	}
	snap := protocol.PerformanceSnapshot{
		SchemaVersion: protocol.SchemaVersion,
		CollectedAt:   time.Now().UTC(),
	}
	start := time.Now()
	snap.CPU.LogicalCount = int(logicalProcessors())
	snap.Memory = memoryLoad()

	collectCPULoad(&snap)
	collectDiskLoad(&snap)

	// Per-process CPU and working set from the perf-formatted WMI class.
	var procs []win32PerfProcProcess
	if err := query(nsCIMV2, "SELECT IDProcess, Name, PercentProcessorTime, WorkingSetPrivate FROM Win32_PerfFormattedData_PerfProc_Process", &procs); err != nil {
		snap.Errors = append(snap.Errors, "processes: "+err.Error())
	} else {
		raw := make([]RawProcess, 0, len(procs))
		for _, pr := range procs {
			raw = append(raw, RawProcess{
				PID:         pr.IDProcess,
				Name:        pr.Name,
				CPUPercent:  float64(pr.PercentProcessorTime),
				MemoryBytes: pr.WorkingSetPrivate,
			})
		}
		cpuN := snap.CPU.LogicalCount
		if cpuN < 1 {
			cpuN = 1
		}
		snap.TopByCPU, snap.TopByMemory, snap.ProcessCount = BuildPerformance(raw, cpuN, topN)
	}

	snap.SampleMs = time.Since(start).Milliseconds()
	return snap
}

type win32PerfProcProcess struct {
	IDProcess            uint32
	Name                 string
	PercentProcessorTime uint64
	WorkingSetPrivate    uint64
}

type win32PerfOSProcessor struct {
	Name                 string
	PercentProcessorTime uint64
	ProcessorQueueLength uint32
}

type win32PerfOSSystem struct {
	ProcessorQueueLength uint32
}

func collectCPULoad(snap *protocol.PerformanceSnapshot) {
	var cpus []win32PerfOSProcessor
	if err := query(nsCIMV2, "SELECT Name, PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor", &cpus); err != nil {
		snap.Errors = append(snap.Errors, "cpu: "+err.Error())
		return
	}
	for _, c := range cpus {
		if c.Name == "_Total" {
			snap.CPU.UsedPercent = round2(float64(c.PercentProcessorTime))
		} else {
			snap.CPU.PerCore = append(snap.CPU.PerCore, round2(float64(c.PercentProcessorTime)))
		}
	}
	var sys []win32PerfOSSystem
	if query(nsCIMV2, "SELECT ProcessorQueueLength FROM Win32_PerfFormattedData_PerfOS_System", &sys) == nil && len(sys) > 0 {
		snap.CPU.QueueLength = float64(sys[0].ProcessorQueueLength)
	}
}

type win32PerfDiskPhysical struct {
	Name                   string
	PercentDiskTime        uint64
	DiskReadBytesPerSec    uint64
	DiskWriteBytesPerSec   uint64
	CurrentDiskQueueLength uint32
}

func collectDiskLoad(snap *protocol.PerformanceSnapshot) {
	var disks []win32PerfDiskPhysical
	if err := query(nsCIMV2, "SELECT * FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk", &disks); err != nil {
		snap.Errors = append(snap.Errors, "disk load: "+err.Error())
		return
	}
	for _, d := range disks {
		if d.Name == "_Total" {
			continue
		}
		busy := float64(d.PercentDiskTime)
		if busy > 100 {
			busy = 100
		}
		snap.Disks = append(snap.Disks, protocol.DiskLoad{
			Drive:         d.Name,
			BusyPercent:   round2(busy),
			ReadBytesSec:  float64(d.DiskReadBytesPerSec),
			WriteBytesSec: float64(d.DiskWriteBytesPerSec),
			QueueLength:   float64(d.CurrentDiskQueueLength),
		})
	}
}

// ---- memory via GlobalMemoryStatusEx (exact, no WMI) ----

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx    = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetActiveProcessorCount = kernel32.NewProc("GetActiveProcessorCount")
)

const allProcessorGroups = 0xffff

func memoryLoad() protocol.MemoryLoad {
	m := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	var out protocol.MemoryLoad
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return out
	}
	out.TotalBytes = m.TotalPhys
	out.AvailableBytes = m.AvailPhys
	out.UsedBytes = m.TotalPhys - m.AvailPhys
	out.UsedPercent = float64(m.MemoryLoad)
	out.CommitLimitBytes = m.TotalPageFile
	out.CommitUsedBytes = m.TotalPageFile - m.AvailPageFile
	return out
}

func logicalProcessors() uint32 {
	if r, _, _ := procGetActiveProcessorCount.Call(uintptr(allProcessorGroups)); r > 0 {
		return uint32(r)
	}
	return uint32(runtime.NumCPU())
}
