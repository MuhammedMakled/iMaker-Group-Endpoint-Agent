//go:build windows

package sysctl

import (
	"fmt"
	"math"
	"sort"
	"time"

	"golang.org/x/sys/windows"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

type win32Process struct {
	ProcessId      uint32
	Name           string
	WorkingSetSize uint64
	CreationDate   time.Time
}

type perfProc struct {
	IDProcess            uint32
	PercentProcessorTime uint64
}

// protectedPIDs are never killable.
var protectedPIDs = map[uint32]bool{0: true, 4: true}

// ListProcesses returns running processes with memory and CPU%.
func ListProcesses(logicalCPUs int) ([]protocol.ProcessInfo, error) {
	if logicalCPUs < 1 {
		logicalCPUs = 1
	}
	var procs []win32Process
	if err := wmiClient.Query("SELECT ProcessId, Name, WorkingSetSize, CreationDate FROM Win32_Process", &procs); err != nil {
		return nil, err
	}
	cpu := map[uint32]float64{}
	var perf []perfProc
	if err := wmiClient.Query("SELECT IDProcess, PercentProcessorTime FROM Win32_PerfFormattedData_PerfProc_Process", &perf); err == nil {
		for _, p := range perf {
			cpu[p.IDProcess] = float64(p.PercentProcessorTime) / float64(logicalCPUs)
		}
	}
	out := make([]protocol.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		c := cpu[p.ProcessId]
		if c > 100 {
			c = 100
		}
		out = append(out, protocol.ProcessInfo{
			PID:         p.ProcessId,
			Name:        p.Name,
			MemoryBytes: p.WorkingSetSize,
			MemoryMB:    math.Round(float64(p.WorkingSetSize)/(1<<20)*100) / 100,
			CPUPercent:  math.Round(c*100) / 100,
			StartTime:   p.CreationDate,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MemoryBytes > out[j].MemoryBytes })
	return out, nil
}

// KillProcess terminates a process by PID. If name is non-empty it must match
// the running process (a guard against killing a recycled PID).
func KillProcess(pid uint32, name string) error {
	if protectedPIDs[pid] {
		return fmt.Errorf("process %d is a protected system process", pid)
	}
	if name != "" {
		if actual, err := processName(pid); err == nil && !equalFoldExe(actual, name) {
			return fmt.Errorf("PID %d is %q, not %q — refusing (PID may have been reused)", pid, actual, name)
		}
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("cannot open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate %d: %w", pid, err)
	}
	return nil
}

func processName(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	full := windows.UTF16ToString(buf[:size])
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == '\\' || full[i] == '/' {
			return full[i+1:], nil
		}
	}
	return full, nil
}

func equalFoldExe(a, b string) bool {
	norm := func(s string) string {
		s = trimExe(s)
		return s
	}
	return equalFold(norm(a), norm(b))
}

func trimExe(s string) string {
	if len(s) > 4 && equalFold(s[len(s)-4:], ".exe") {
		return s[:len(s)-4]
	}
	return s
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
