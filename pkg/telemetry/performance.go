package telemetry

import (
	"sort"
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// RawProcess is one process sample before grouping.
type RawProcess struct {
	PID         uint32
	Name        string // image name, e.g. "chrome.exe" (no "#1" suffix)
	CPUPercent  float64
	MemoryBytes uint64
}

// friendlyApps maps common executables to human names for the dashboard.
var friendlyApps = map[string]string{
	"acad.exe": "AutoCAD", "acadlt.exe": "AutoCAD LT", "revit.exe": "Revit",
	"3dsmax.exe": "3ds Max", "sketchup.exe": "SketchUp", "layout.exe": "SketchUp LayOut",
	"v_ray.exe": "V-Ray", "vray.exe": "V-Ray", "corona.exe": "Corona Renderer",
	"photoshop.exe": "Adobe Photoshop", "illustrator.exe": "Adobe Illustrator",
	"indesign.exe": "Adobe InDesign", "acrobat.exe": "Adobe Acrobat", "acrord32.exe": "Adobe Reader",
	"chrome.exe": "Google Chrome", "msedge.exe": "Microsoft Edge", "firefox.exe": "Firefox",
	"excel.exe": "Microsoft Excel", "winword.exe": "Microsoft Word", "powerpnt.exe": "Microsoft PowerPoint",
	"outlook.exe": "Microsoft Outlook", "onedrive.exe": "OneDrive", "dropbox.exe": "Dropbox",
	"teams.exe": "Microsoft Teams", "ms-teams.exe": "Microsoft Teams", "zoom.exe": "Zoom",
	"code.exe": "VS Code", "explorer.exe": "Windows Explorer", "dwm.exe": "Desktop Window Manager",
	"msmpeng.exe": "Microsoft Defender", "searchindexer.exe": "Windows Search",
	"imakertrayapp.exe": "IMAKER Agent (tray)", "imakeragentservice.exe": "IMAKER Agent (service)",
}

// FriendlyAppName returns a human label for an executable name.
func FriendlyAppName(exe string) string {
	if n, ok := friendlyApps[strings.ToLower(exe)]; ok {
		return n
	}
	return strings.TrimSuffix(exe, ".exe")
}

// systemIdle are pseudo-processes excluded from "top app" lists.
var systemIdle = map[string]bool{
	"idle": true, "_total": true, "system": true, "memory compression": true,
}

// BuildPerformance groups raw per-process samples into applications and
// returns the top consumers. logicalCPUs normalises CPU% to a 0–100 scale
// (WMI reports per-process CPU as a sum across all cores).
func BuildPerformance(raw []RawProcess, logicalCPUs, topN int) (byCPU, byMem []protocol.ProcessLoad, total int) {
	if logicalCPUs < 1 {
		logicalCPUs = 1
	}
	if topN <= 0 {
		topN = 10
	}
	type agg struct {
		pids []uint32
		cpu  float64
		mem  uint64
	}
	groups := map[string]*agg{}
	for _, p := range raw {
		name := strings.ToLower(strings.TrimSpace(p.Name))
		if name == "" || systemIdle[name] {
			continue
		}
		if !strings.HasSuffix(name, ".exe") {
			name += ".exe"
		}
		g := groups[name]
		if g == nil {
			g = &agg{}
			groups[name] = g
		}
		g.pids = append(g.pids, p.PID)
		g.cpu += p.CPUPercent
		g.mem += p.MemoryBytes
	}
	total = 0
	loads := make([]protocol.ProcessLoad, 0, len(groups))
	for name, g := range groups {
		total += len(g.pids)
		cpu := g.cpu / float64(logicalCPUs)
		if cpu > 100 {
			cpu = 100
		}
		pids := g.pids
		if len(pids) > 20 {
			pids = pids[:20]
		}
		loads = append(loads, protocol.ProcessLoad{
			Name:         name,
			FriendlyName: FriendlyAppName(name),
			PIDs:         pids,
			Instances:    len(g.pids),
			CPUPercent:   round2(cpu),
			MemoryBytes:  g.mem,
			MemoryMB:     round2(float64(g.mem) / (1 << 20)),
		})
	}

	byCPU = append([]protocol.ProcessLoad{}, loads...)
	sort.Slice(byCPU, func(i, j int) bool {
		if byCPU[i].CPUPercent != byCPU[j].CPUPercent {
			return byCPU[i].CPUPercent > byCPU[j].CPUPercent
		}
		return byCPU[i].MemoryBytes > byCPU[j].MemoryBytes
	})
	if len(byCPU) > topN {
		byCPU = byCPU[:topN]
	}

	byMem = append([]protocol.ProcessLoad{}, loads...)
	sort.Slice(byMem, func(i, j int) bool { return byMem[i].MemoryBytes > byMem[j].MemoryBytes })
	if len(byMem) > topN {
		byMem = byMem[:topN]
	}
	return byCPU, byMem, total
}
