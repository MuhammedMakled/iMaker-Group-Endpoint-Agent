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
	Asset         AssetIdentity    `json:"asset"`
	Monitors      []MonitorInfo    `json:"monitors"`
	Network       []NetworkAdapter `json:"network"`
	PublicIP      string           `json:"public_ip,omitempty"`
	PublicIPError string           `json:"public_ip_error,omitempty"`
	Battery       *BatteryInfo     `json:"battery,omitempty"`
	Licensing     LicensingInfo    `json:"licensing"`
	LocalAdmins   []LocalAccount   `json:"local_admins"`
	Errors        []string         `json:"errors,omitempty"`
}

type SystemInfo struct {
	Hostname     string `json:"hostname"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"` // raw BIOS serial; see Asset for the inventory-safe value
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

// AssetIdentity is the inventory identity of the machine. Branded PCs
// (Dell, HP, Lenovo…) have a real BIOS serial; custom-built PCs usually
// report placeholders such as "To be filled by O.E.M." or "Default string",
// so the agent falls back through other hardware identifiers.
type AssetIdentity struct {
	// SerialNumber is the best hardware serial found; SerialSource says where
	// it came from: bios | enclosure | baseboard | smbios_uuid | fingerprint.
	SerialNumber string `json:"serial_number"`
	SerialSource string `json:"serial_source"`
	// IsCustomBuild is true when the BIOS has no real system serial.
	IsCustomBuild bool `json:"is_custom_build"`
	// AssetTag is IT's own label (set with `ImakerAgentService set-asset-tag`
	// or in the BIOS SMBIOS asset-tag field). Prefer this in the inventory.
	AssetTag       string `json:"asset_tag,omitempty"`
	AssetTagSource string `json:"asset_tag_source,omitempty"` // registry | smbios
	// HardwareFingerprint is a stable hash of motherboard serial, SMBIOS
	// UUID, boot-disk serial and onboard MAC. It survives Windows reinstalls.
	HardwareFingerprint string `json:"hardware_fingerprint"`
	ChassisType         string `json:"chassis_type"` // Desktop | Laptop | Mini PC | All-in-One | ...

	// Raw candidates, for audit and manual matching.
	BIOSSerial            string `json:"bios_serial,omitempty"`
	EnclosureSerial       string `json:"enclosure_serial,omitempty"`
	BaseboardSerial       string `json:"baseboard_serial,omitempty"`
	BaseboardManufacturer string `json:"baseboard_manufacturer,omitempty"`
	BaseboardProduct      string `json:"baseboard_product,omitempty"`
	SMBIOSUUID            string `json:"smbios_uuid,omitempty"`
	BootDiskSerial        string `json:"boot_disk_serial,omitempty"`
	PrimaryMAC            string `json:"primary_mac,omitempty"`
	MachineGUID           string `json:"machine_guid,omitempty"` // changes on Windows reinstall
}

// MonitorInfo comes from the monitor's EDID (WmiMonitorID).
type MonitorInfo struct {
	Manufacturer      string `json:"manufacturer"`
	Model             string `json:"model"`
	SerialNumber      string `json:"serial_number"`
	ProductCode       string `json:"product_code,omitempty"`
	YearOfManufacture int    `json:"year_of_manufacture,omitempty"`
	Active            bool   `json:"active"`
}

// NetworkAdapter is one network interface with its full addressing.
type NetworkAdapter struct {
	Name          string   `json:"name"`        // connection name, e.g. "Ethernet 3", "Wi-Fi"
	Description   string   `json:"description"` // driver/device description
	Type          string   `json:"type"`        // Ethernet | Wireless | Virtual | Other
	MACAddress    string   `json:"mac_address"`
	Status        string   `json:"status"` // Connected | Disconnected | ...
	LinkSpeedMbps uint64   `json:"link_speed_mbps,omitempty"`
	DHCPEnabled   bool     `json:"dhcp_enabled"`
	DHCPServer    string   `json:"dhcp_server,omitempty"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
	Gateways      []string `json:"gateways,omitempty"`
	DNSServers    []string `json:"dns_servers,omitempty"`
	DNSDomain     string   `json:"dns_domain,omitempty"`
	IsPhysical    bool     `json:"is_physical"`
}

// BatteryInfo is laptop battery health (nil on desktops).
type BatteryInfo struct {
	Present           bool   `json:"present"`
	ChargePercent     uint32 `json:"charge_percent"`
	Status            string `json:"status"` // Charging | Discharging | Fully Charged | ...
	ACConnected       bool   `json:"ac_connected"`
	DesignCapacitymWh uint32 `json:"design_capacity_mwh"`
	FullChargemWh     uint32 `json:"full_charge_capacity_mwh"`
	// HealthPercent is FullCharge/Design: 100 = like new, lower = worn.
	HealthPercent       float64 `json:"health_percent"`
	CycleCount          uint32  `json:"cycle_count,omitempty"`
	EstimatedRuntimeMin int32   `json:"estimated_runtime_min,omitempty"`
	Chemistry           string  `json:"chemistry,omitempty"`
}

// LicensingInfo covers Windows and Office activation.
type LicensingInfo struct {
	WindowsActivated  bool            `json:"windows_activated"`
	WindowsStatus     string          `json:"windows_status"` // Licensed | Notification | Unlicensed | ...
	WindowsEdition    string          `json:"windows_edition,omitempty"`
	WindowsPartialKey string          `json:"windows_partial_key,omitempty"` // last 5 chars only
	WindowsChannel    string          `json:"windows_channel,omitempty"`     // Retail | Volume | OEM
	Office            []OfficeLicense `json:"office,omitempty"`
}

type OfficeLicense struct {
	Product    string `json:"product"`
	Status     string `json:"status"`
	PartialKey string `json:"partial_key,omitempty"`
}

// LocalAccount is a member of the local Administrators group.
type LocalAccount struct {
	Name     string `json:"name"` // DOMAIN\user or PC\user
	SID      string `json:"sid"`
	Type     string `json:"type"` // User | Group | Domain
	Disabled bool   `json:"disabled"`
	Local    bool   `json:"local"` // true = local account, false = domain
}
