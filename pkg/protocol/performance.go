package protocol

import "time"

// PerformanceSnapshot is a live view of how hard the machine is working right
// now: overall utilization plus the processes (grouped into applications)
// consuming the most CPU and memory. This is the "Task Manager" view the
// Command Center shows for a PC on demand.
type PerformanceSnapshot struct {
	SchemaVersion int           `json:"schema_version"`
	CollectedAt   time.Time     `json:"collected_at"`
	SampleMs      int64         `json:"sample_ms"` // window over which CPU% was measured
	CPU           CPULoad       `json:"cpu"`
	Memory        MemoryLoad    `json:"memory"`
	Disks         []DiskLoad    `json:"disks"`
	GPUs          []GPULoad     `json:"gpus"`
	TopByCPU      []ProcessLoad `json:"top_by_cpu"`
	TopByMemory   []ProcessLoad `json:"top_by_memory"`
	ProcessCount  int           `json:"process_count"`
	Errors        []string      `json:"errors,omitempty"`
}

type CPULoad struct {
	UsedPercent  float64   `json:"used_percent"`
	PerCore      []float64 `json:"per_core,omitempty"`
	QueueLength  float64   `json:"queue_length"`
	LogicalCount int       `json:"logical_count"`
}

type MemoryLoad struct {
	TotalBytes       uint64  `json:"total_bytes"`
	UsedBytes        uint64  `json:"used_bytes"`
	AvailableBytes   uint64  `json:"available_bytes"`
	UsedPercent      float64 `json:"used_percent"`
	CommitUsedBytes  uint64  `json:"commit_used_bytes"`
	CommitLimitBytes uint64  `json:"commit_limit_bytes"`
}

type DiskLoad struct {
	Drive         string  `json:"drive"`        // physical disk or volume label
	BusyPercent   float64 `json:"busy_percent"` // % active time
	ReadBytesSec  float64 `json:"read_bytes_sec"`
	WriteBytesSec float64 `json:"write_bytes_sec"`
	QueueLength   float64 `json:"queue_length"`
}

type GPULoad struct {
	Name            string  `json:"name"`
	UsedPercent     float64 `json:"used_percent"`
	MemoryUsedBytes uint64  `json:"memory_used_bytes"`
}

// ProcessLoad is one application's resource usage. Processes sharing an
// executable (e.g. several chrome.exe) are summed into one entry.
type ProcessLoad struct {
	Name         string   `json:"name"`          // acad.exe
	FriendlyName string   `json:"friendly_name"` // AutoCAD
	PIDs         []uint32 `json:"pids,omitempty"`
	Instances    int      `json:"instances"`
	CPUPercent   float64  `json:"cpu_percent"`
	MemoryBytes  uint64   `json:"memory_bytes"` // working set (private + shared resident)
	MemoryMB     float64  `json:"memory_mb"`
}

type PerformanceGetParams struct {
	// SampleMs is the CPU measurement window (default 1000, max 5000).
	SampleMs int `json:"sample_ms,omitempty"`
	// TopN limits each top-list (default 10, max 50).
	TopN int `json:"top_n,omitempty"`
}

const MethodPerformanceGet = "performance.get"
