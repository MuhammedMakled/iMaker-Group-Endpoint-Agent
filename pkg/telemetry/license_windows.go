//go:build windows

package telemetry

import (
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// Application IDs for SoftwareLicensingProduct.
const (
	appIDWindows = "55c92734-d682-4d71-983e-d6ec3f16059f"
	appIDOffice  = "0ff1ce15-a989-479d-af46-f275c6370663"
)

type softwareLicensingProduct struct {
	Name              string
	Description       string
	ApplicationID     string
	LicenseStatus     uint32
	PartialProductKey string
	ProductKeyChannel string
}

var licenseStatusNames = map[uint32]string{
	0: "Unlicensed", 1: "Licensed", 2: "Out-of-box Grace", 3: "Out-of-tolerance Grace",
	4: "Non-genuine Grace", 5: "Notification", 6: "Extended Grace",
}

func collectLicensing(s *protocol.TelemetrySnapshot) error {
	// Only products with a PartialProductKey are actually installed licenses.
	var prods []softwareLicensingProduct
	if err := query(nsCIMV2, "SELECT Name, Description, ApplicationID, LicenseStatus, PartialProductKey, ProductKeyChannel FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL", &prods); err != nil {
		return err
	}
	for _, p := range prods {
		switch strings.ToLower(p.ApplicationID) {
		case appIDWindows:
			s.Licensing.WindowsActivated = p.LicenseStatus == 1
			s.Licensing.WindowsStatus = licenseStatusNames[p.LicenseStatus]
			s.Licensing.WindowsEdition = p.Name
			s.Licensing.WindowsPartialKey = p.PartialProductKey
			s.Licensing.WindowsChannel = channelFromDescription(p.Description, p.ProductKeyChannel)
		case appIDOffice:
			s.Licensing.Office = append(s.Licensing.Office, protocol.OfficeLicense{
				Product:    p.Name,
				Status:     licenseStatusNames[p.LicenseStatus],
				PartialKey: p.PartialProductKey,
			})
		}
	}
	return nil
}

// channelFromDescription extracts Retail/Volume/OEM from the license
// description (e.g. "Windows(R) Operating System, VOLUME_KMSCLIENT channel").
func channelFromDescription(desc, channel string) string {
	if channel != "" {
		return channel
	}
	u := strings.ToUpper(desc)
	switch {
	case strings.Contains(u, "OEM"):
		return "OEM"
	case strings.Contains(u, "VOLUME") || strings.Contains(u, "KMS") || strings.Contains(u, "MAK"):
		return "Volume"
	case strings.Contains(u, "RETAIL"):
		return "Retail"
	}
	return ""
}
