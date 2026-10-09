//go:build windows

package telemetry

import (
	"fmt"
	"runtime"
	"sort"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows/registry"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// ---- BitLocker ----

type win32EncryptableVolume struct {
	DeviceID         string
	DriveLetter      string
	ProtectionStatus uint32
	VolumeType       *uint32 // Windows 8+
	ConversionStatus *uint32 // Windows 8+
	EncryptionMethod *uint32
}

func collectBitLocker(s *protocol.TelemetrySnapshot) error {
	var vols []win32EncryptableVolume
	if err := query(nsBitLocker, "SELECT * FROM Win32_EncryptableVolume", &vols); err != nil {
		return fmt.Errorf("%w (requires SYSTEM/admin; BitLocker feature may be absent on Home editions)", err)
	}
	for _, v := range vols {
		b := protocol.BitLockerState{
			DriveLetter:      v.DriveLetter,
			DeviceID:         v.DeviceID,
			ProtectionStatus: ProtectionStatusName(v.ProtectionStatus),
			VolumeType:       "Unknown",
		}
		if v.VolumeType != nil {
			b.VolumeType = VolumeTypeName(*v.VolumeType)
		}
		if v.ConversionStatus != nil {
			b.ConversionStatus = ConversionStatusName(*v.ConversionStatus)
		}
		if v.EncryptionMethod != nil {
			b.EncryptionMethod = EncryptionMethodName(*v.EncryptionMethod)
		}
		// Policy: OS and fixed data volumes must be protected; removable media is informational.
		b.Compliant = b.ProtectionStatus == "On" || b.VolumeType == "Removable"
		s.BitLocker = append(s.BitLocker, b)
	}
	sort.Slice(s.BitLocker, func(i, j int) bool { return s.BitLocker[i].DriveLetter < s.BitLocker[j].DriveLetter })
	return nil
}

// ---- Antivirus / Defender ----

// The wmi package maps properties by Go field name; IDispatch name lookup is
// case-insensitive, so these match displayName / productState / ...
type antiVirusProductRaw struct {
	DisplayName            string
	ProductState           uint32
	PathToSignedProductExe string
}

func collectAntivirus(s *protocol.TelemetrySnapshot) error {
	var avs []antiVirusProductRaw
	if err := query(nsSecCenter, "SELECT * FROM AntiVirusProduct", &avs); err != nil {
		return fmt.Errorf("%w (SecurityCenter2 is unavailable on Windows Server)", err)
	}
	for _, a := range avs {
		on, current := DecodeAVProductState(a.ProductState)
		s.Security.AntivirusProducts = append(s.Security.AntivirusProducts, protocol.AntivirusProduct{
			Name: a.DisplayName, ProductState: a.ProductState, Enabled: on, UpToDate: current,
			Path: a.PathToSignedProductExe,
		})
		if on {
			s.Security.AnyAntivirusActive = true
		}
	}
	return nil
}

type msftMpComputerStatus struct {
	AMServiceEnabled              bool
	AntivirusEnabled              bool
	RealTimeProtectionEnabled     bool
	AntivirusSignatureVersion     string
	AntivirusSignatureLastUpdated time.Time
	IsTamperProtected             *bool
}

func collectDefender(s *protocol.TelemetrySnapshot) error {
	var st []msftMpComputerStatus
	if err := query(nsDefender, "SELECT * FROM MSFT_MpComputerStatus", &st); err != nil {
		return fmt.Errorf("%w (Defender may be replaced by a third-party AV)", err)
	}
	if len(st) == 0 {
		return nil
	}
	d := st[0]
	ds := &protocol.DefenderStatus{
		ServiceEnabled:            d.AMServiceEnabled,
		AntivirusEnabled:          d.AntivirusEnabled,
		RealTimeProtectionEnabled: d.RealTimeProtectionEnabled,
		SignatureVersion:          d.AntivirusSignatureVersion,
		SignatureLastUpdated:      d.AntivirusSignatureLastUpdated,
		TamperProtected:           d.IsTamperProtected,
	}
	if !d.AntivirusSignatureLastUpdated.IsZero() {
		ds.SignatureAgeDays = round2(time.Since(d.AntivirusSignatureLastUpdated).Hours() / 24)
	}
	s.Security.Defender = ds
	if d.AntivirusEnabled && d.RealTimeProtectionEnabled {
		s.Security.AnyAntivirusActive = true
	}
	return nil
}

// ---- Windows Update ----

type win32QuickFixEngineering struct {
	HotFixID    string
	InstalledOn string
}

func collectUpdates(s *protocol.TelemetrySnapshot, history bool) error {
	var qfes []win32QuickFixEngineering
	if err := query(nsCIMV2, "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering", &qfes); err == nil {
		for _, q := range qfes {
			if t, ok := ParseHotfixDate(q.InstalledOn); ok && t.After(s.Updates.LastHotfixInstalled) {
				s.Updates.LastHotfixInstalled = t
				s.Updates.LastHotfixID = q.HotFixID
			}
		}
	} else {
		s.Errors = append(s.Errors, "updates: QFE: "+err.Error())
	}

	s.Updates.RebootPending = rebootPending()

	if history {
		if t, title, err := lastSuccessfulUpdate(); err == nil {
			s.Updates.LastSuccessfulUpdate = t
			s.Updates.LastUpdateTitle = title
		} else {
			s.Errors = append(s.Errors, "updates: history: "+err.Error())
		}
	}

	latest := s.Updates.LastHotfixInstalled
	if s.Updates.LastSuccessfulUpdate.After(latest) {
		latest = s.Updates.LastSuccessfulUpdate
	}
	if !latest.IsZero() {
		s.Updates.DaysSinceLastUpdate = round2(time.Since(latest).Hours() / 24)
	}
	return nil
}

// rebootPending checks the well-known servicing flags.
func rebootPending() bool {
	keys := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
	}
	for _, p := range keys {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
			k.Close()
			return true
		}
	}
	return false
}

// lastSuccessfulUpdate uses the Windows Update Agent COM API
// (Microsoft.Update.Session -> IUpdateSearcher.QueryHistory). It does not
// contact Windows Update servers.
func lastSuccessfulUpdate() (when time.Time, title string, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		if oe, ok := err.(*ole.OleError); !ok || oe.Code() != 1 { // S_FALSE = already initialised
			return when, "", err
		}
	}
	defer ole.CoUninitialize()

	unk, err := oleutil.CreateObject("Microsoft.Update.Session")
	if err != nil {
		return when, "", err
	}
	defer unk.Release()
	session, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return when, "", err
	}
	defer session.Release()

	searcherV, err := oleutil.CallMethod(session, "CreateUpdateSearcher")
	if err != nil {
		return when, "", err
	}
	searcher := searcherV.ToIDispatch()
	defer searcher.Release()

	countV, err := oleutil.CallMethod(searcher, "GetTotalHistoryCount")
	if err != nil {
		return when, "", err
	}
	count := int(countV.Val)
	if count == 0 {
		return when, "", nil
	}
	if count > 100 {
		count = 100 // newest first
	}
	histV, err := oleutil.CallMethod(searcher, "QueryHistory", 0, count)
	if err != nil {
		return when, "", err
	}
	hist := histV.ToIDispatch()
	defer hist.Release()

	for i := 0; i < count; i++ {
		itemV, err := oleutil.GetProperty(hist, "Item", i)
		if err != nil {
			continue
		}
		item := itemV.ToIDispatch()
		op, _ := oleutil.GetProperty(item, "Operation")  // 1 = installation
		rc, _ := oleutil.GetProperty(item, "ResultCode") // 2 = succeeded
		dt, _ := oleutil.GetProperty(item, "Date")
		tt, _ := oleutil.GetProperty(item, "Title")
		if op != nil && rc != nil && op.Val == 1 && rc.Val == 2 && dt != nil {
			if t, ok := dt.Value().(time.Time); ok && t.After(when) {
				when = t
				if tt != nil {
					title, _ = tt.Value().(string)
				}
			}
		}
		item.Release()
	}
	return when, title, nil
}
