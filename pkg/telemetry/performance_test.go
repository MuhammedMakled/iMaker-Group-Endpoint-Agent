package telemetry

import "testing"

func TestBuildPerformanceGroupingAndNormalise(t *testing.T) {
	raw := []RawProcess{
		{PID: 1, Name: "chrome.exe", CPUPercent: 180, MemoryBytes: 500 << 20}, // 8 cores -> 22.5%
		{PID: 2, Name: "chrome.exe", CPUPercent: 60, MemoryBytes: 300 << 20},
		{PID: 3, Name: "revit", CPUPercent: 400, MemoryBytes: 4096 << 20}, // no .exe suffix
		{PID: 4, Name: "Idle", CPUPercent: 700, MemoryBytes: 0},           // excluded
		{PID: 5, Name: "System", CPUPercent: 10, MemoryBytes: 1 << 20},    // excluded
	}
	byCPU, byMem, total := BuildPerformance(raw, 8, 10)
	if total != 3 {
		t.Fatalf("process count should exclude Idle/System: %d", total)
	}
	if byCPU[0].Name != "revit.exe" || byCPU[0].FriendlyName != "Revit" || byCPU[0].CPUPercent != 50 {
		t.Fatalf("top CPU: %+v", byCPU[0])
	}
	// chrome grouped: (180+60)/8 = 30%, 2 instances, 800 MB
	var chrome *struct{}
	for _, p := range byCPU {
		if p.Name == "chrome.exe" {
			if p.Instances != 2 || p.CPUPercent != 30 || p.MemoryMB != 800 {
				t.Fatalf("chrome group: %+v", p)
			}
			chrome = &struct{}{}
		}
	}
	if chrome == nil {
		t.Fatal("chrome missing")
	}
	if byMem[0].Name != "revit.exe" {
		t.Fatalf("top mem: %+v", byMem[0])
	}
}

func TestCPUClamp(t *testing.T) {
	// A single process pegged on all cores must clamp to 100%.
	byCPU, _, _ := BuildPerformance([]RawProcess{{PID: 1, Name: "x.exe", CPUPercent: 1600}}, 8, 5)
	if byCPU[0].CPUPercent != 100 {
		t.Fatalf("clamp: %+v", byCPU[0])
	}
}
