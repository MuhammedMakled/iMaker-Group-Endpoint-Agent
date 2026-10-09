package protocol

import "time"

// TelemetrySnapshot is the full PC health report produced by the service.
// Sub-collectors are best-effort: a failure in one section is recorded in
// Errors and never prevents the rest of the snapshot from being returned.
type TelemetrySnapshot struct {
	SchemaVersion int              `json:"schema_version"`
	AgentVersion  string           `json:"agent_version"`
	CollectedAt   time.Time        `json:"collected_at"`
	DurationMs    int64            `json:"duration_ms"`
	System        SystemInfo       `json:"system"`
	OS            OSInfo           `json:"os"`
	CPU           []CPUInfo        `json:"cpu"`
	Memory        MemoryInfo       `json:"memory"`
	GPUs          []GPUInfo        `json:"gpus"`
	PhysicalDisks []PhysicalDisk   `json:"physical_disks"`
	Volumes       []LogicalVolume  `json:"volumes"`
	BitLocker     []BitLockerState `json:"bitlocker"`
	Security      SecurityStatus   `json:"security"`
	Updates       UpdateStatus     `json:"updates"`
	Errors        []string         `json:"errors,omitempty"`
}

type SystemInfo struct {
	Hostname     string `json:"hostname"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	BIOSVersion  string `json:"bios_version"`
	Domain       string `json:"domain"`
	PartOfDomain bool   `json:"part_of_domain"`
	LoggedOnUser string `json:"logged_on_user,omitempty"`
}

type OSInfo struct {
	Caption        string    `json:"caption"`
	Version        string    `json:"version"`
	BuildNumber    string    `json:"build_number"`
	Architecture   string    `json:"architecture"`
	InstallDate    time.Time `json:"install_date"`
	LastBootUpTime time.Time `json:"last_boot_up_time"`
	UptimeHours    float64   `json:"uptime_hours"`
}

type CPUInfo struct {
	Name              string `json:"name"`
	Manufacturer      string `json:"manufacturer"`
	PhysicalCores     uint32 `json:"physical_cores"`
	LogicalProcessors uint32 `json:"logical_processors"`
	MaxClockMHz       uint32 `json:"max_clock_mhz"`
}

type MemoryInfo struct {
	TotalBytes     uint64  `json:"total_bytes"`
	TotalGB        float64 `json:"total_gb"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type GPUInfo struct {
	Name          string `json:"name"`
	DriverVersion string `json:"driver_version"`
	// AdapterRAMBytes comes from Win32_VideoController, which is a uint32
	// and therefore caps at 4 GB. Treat values >= 4 GB as "4 GB or more".
	AdapterRAMBytes uint64 `json:"adapter_ram_bytes"`
	VideoProcessor  string `json:"video_processor"`
	Status          string `json:"status"`
}

// PhysicalDisk merges Win32_DiskDrive, MSFT_PhysicalDisk,
// MSFT_StorageReliabilityCounter and MSStorageDriver_FailurePredictStatus.
type PhysicalDisk struct {
	Index         uint32  `json:"index"`
	Model         string  `json:"model"`
	SerialNumber  string  `json:"serial_number"`
	SizeBytes     uint64  `json:"size_bytes"`
	SizeGB        float64 `json:"size_gb"`
	InterfaceType string  `json:"interface_type"`
	BusType       string  `json:"bus_type"`   // NVMe, SATA, USB, ...
	MediaType     string  `json:"media_type"` // SSD, HDD, SCM, Unspecified
	WMIStatus     string  `json:"wmi_status"`
	// Health is the Windows Storage health verdict: Healthy | Warning | Unhealthy | Unknown.
	Health            string   `json:"health"`
	OperationalStatus []string `json:"operational_status,omitempty"`
	// Reliability counters (SMART-derived). Nil when the driver does not expose them.
	TemperatureC        *uint32 `json:"temperature_c,omitempty"`
	WearPercentUsed     *uint32 `json:"wear_percent_used,omitempty"`
	PowerOnHours        *uint32 `json:"power_on_hours,omitempty"`
	ReadErrorsTotal     *uint64 `json:"read_errors_total,omitempty"`
	WriteErrorsTotal    *uint64 `json:"write_errors_total,omitempty"`
	SmartPredictFailure *bool   `json:"smart_predict_failure,omitempty"`
}

type LogicalVolume struct {
	DriveLetter string  `json:"drive_letter"`
	Label       string  `json:"label"`
	FileSystem  string  `json:"file_system"`
	SizeBytes   uint64  `json:"size_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	SizeGB      float64 `json:"size_gb"`
	FreeGB      float64 `json:"free_gb"`
	UsedPercent float64 `json:"used_percent"`
	LowSpace    bool    `json:"low_space"` // < 10% free or < 20 GB free
}

type BitLockerState struct {
	DriveLetter      string `json:"drive_letter"`
	DeviceID         string `json:"device_id"`
	VolumeType       string `json:"volume_type"`       // OperatingSystem | FixedData | Removable
	ProtectionStatus string `json:"protection_status"` // On | Off | Unknown
	ConversionStatus string `json:"conversion_status,omitempty"`
	EncryptionMethod string `json:"encryption_method,omitempty"`
	Compliant        bool   `json:"compliant"`
}

type SecurityStatus struct {
	AntivirusProducts []AntivirusProduct `json:"antivirus_products"`
	Defender          *DefenderStatus    `json:"defender,omitempty"`
	// AnyAntivirusActive is true if at least one registered AV is enabled.
	AnyAntivirusActive bool `json:"any_antivirus_active"`
}

type AntivirusProduct struct {
	Name         string `json:"name"`
	ProductState uint32 `json:"product_state"`
	Enabled      bool   `json:"enabled"`
	UpToDate     bool   `json:"up_to_date"`
	Path         string `json:"path,omitempty"`
}

type DefenderStatus struct {
	ServiceEnabled            bool      `json:"service_enabled"`
	AntivirusEnabled          bool      `json:"antivirus_enabled"`
	RealTimeProtectionEnabled bool      `json:"real_time_protection_enabled"`
	SignatureVersion          string    `json:"signature_version"`
	SignatureLastUpdated      time.Time `json:"signature_last_updated"`
	SignatureAgeDays          float64   `json:"signature_age_days"`
	TamperProtected           *bool     `json:"tamper_protected,omitempty"`
}

type UpdateStatus struct {
	LastHotfixID         string    `json:"last_hotfix_id,omitempty"`
	LastHotfixInstalled  time.Time `json:"last_hotfix_installed,omitempty"`
	LastSuccessfulUpdate time.Time `json:"last_successful_update,omitempty"`
	LastUpdateTitle      string    `json:"last_update_title,omitempty"`
	DaysSinceLastUpdate  float64   `json:"days_since_last_update"`
	RebootPending        bool      `json:"reboot_pending"`
}

// SoftwareInventory is collected on its own (slower) schedule.
type SoftwareInventory struct {
	CollectedAt time.Time      `json:"collected_at"`
	Hostname    string         `json:"hostname"`
	Count       int            `json:"count"`
	Items       []SoftwareItem `json:"items"`
	Errors      []string       `json:"errors,omitempty"`
}

type SoftwareItem struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	InstallDate     string `json:"install_date,omitempty"` // normalised to YYYY-MM-DD when parseable
	InstallLocation string `json:"install_location,omitempty"`
	Architecture    string `json:"architecture"` // x64 | x86 | user
	Scope           string `json:"scope"`        // machine | user
	UserSID         string `json:"user_sid,omitempty"`
	RegistryKey     string `json:"registry_key"`
}
