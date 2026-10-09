//go:build windows

package telemetry

import "github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"

type win32Battery struct {
	BatteryStatus            uint16
	EstimatedChargeRemaining uint16
	EstimatedRunTime         uint32
	Chemistry                uint16
	DesignCapacity           uint32
	FullChargeCapacity       uint32
}

// root\WMI classes carry the accurate capacity/cycle data Win32_Battery lacks.
type batteryStaticData struct {
	DesignedCapacity uint32
}
type batteryFullCharged struct {
	FullChargedCapacity uint32
}
type batteryCycleCount struct {
	CycleCount uint32
}

var batteryStatusNames = map[uint16]string{
	1: "Discharging", 2: "On AC", 3: "Fully Charged", 4: "Low", 5: "Critical",
	6: "Charging", 7: "Charging (High)", 8: "Charging (Low)", 9: "Charging (Critical)",
	10: "Undefined", 11: "Partially Charged",
}

var batteryChemistry = map[uint16]string{
	1: "Other", 2: "Unknown", 3: "Lead Acid", 4: "Nickel Cadmium",
	5: "Nickel Metal Hydride", 6: "Lithium-ion", 7: "Zinc Air", 8: "Lithium Polymer",
}

func collectBattery(s *protocol.TelemetrySnapshot) error {
	var bats []win32Battery
	if err := query(nsCIMV2, "SELECT * FROM Win32_Battery", &bats); err != nil {
		return err
	}
	if len(bats) == 0 {
		return nil // desktop: no battery
	}
	b := bats[0]
	info := &protocol.BatteryInfo{
		Present:           true,
		ChargePercent:     uint32(b.EstimatedChargeRemaining),
		Status:            batteryStatusNames[b.BatteryStatus],
		ACConnected:       b.BatteryStatus == 2 || (b.BatteryStatus >= 6 && b.BatteryStatus <= 9) || b.BatteryStatus == 3,
		Chemistry:         batteryChemistry[b.Chemistry],
		DesignCapacitymWh: b.DesignCapacity,
		FullChargemWh:     b.FullChargeCapacity,
	}
	if b.EstimatedRunTime > 0 && b.EstimatedRunTime < 0x0FFFFFFF {
		info.EstimatedRuntimeMin = int32(b.EstimatedRunTime)
	}

	// Prefer the accurate root\WMI capacity data when present.
	var sd []batteryStaticData
	if query(nsWMI, "SELECT DesignedCapacity FROM BatteryStaticData", &sd) == nil && len(sd) > 0 && sd[0].DesignedCapacity > 0 {
		info.DesignCapacitymWh = sd[0].DesignedCapacity
	}
	var fc []batteryFullCharged
	if query(nsWMI, "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity", &fc) == nil && len(fc) > 0 && fc[0].FullChargedCapacity > 0 {
		info.FullChargemWh = fc[0].FullChargedCapacity
	}
	var cc []batteryCycleCount
	if query(nsWMI, "SELECT CycleCount FROM BatteryCycleCount", &cc) == nil && len(cc) > 0 {
		info.CycleCount = cc[0].CycleCount
	}

	if info.DesignCapacitymWh > 0 && info.FullChargemWh > 0 {
		info.HealthPercent = round2(float64(info.FullChargemWh) / float64(info.DesignCapacitymWh) * 100)
		if info.HealthPercent > 100 {
			info.HealthPercent = 100
		}
	}
	s.Battery = info
	return nil
}
