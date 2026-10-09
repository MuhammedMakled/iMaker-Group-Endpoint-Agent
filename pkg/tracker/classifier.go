// Package tracker implements the user-space activity tracker: foreground
// window sampling, CAD/CGI process classification, project-code extraction,
// privacy-filtered browser categorisation, idle detection, design-file
// watching and aggregation of samples into WorkSessions.
//
// Platform calls live in *_windows.go files behind small interfaces so all of
// the decision logic in this package is unit-testable on any OS.
package tracker

import (
	"path"
	"regexp"
	"strings"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

// designProcesses maps lower-case executable names to the tracked app.
var designProcesses = map[string]protocol.AppKind{
	"acad.exe":     protocol.AppAutoCAD,
	"acadlt.exe":   protocol.AppAutoCAD,
	"revit.exe":    protocol.AppRevit,
	"3dsmax.exe":   protocol.App3dsMax,
	"sketchup.exe": protocol.AppSketchUp,
	"layout.exe":   protocol.AppSketchUpLayout,
}

var browserProcesses = map[string]bool{
	"chrome.exe":  true,
	"msedge.exe":  true,
	"firefox.exe": true,
	"brave.exe":   true,
	"opera.exe":   true,
}

// designExtRe matches a title segment that ends with a design file name.
var designExtRe = regexp.MustCompile(`(?i)\.(dwg|dxf|dwt|rvt|rfa|rte|max|skp|layout)$`)

// titleSplitRe splits window titles on the separators CAD apps use:
// " - ", " — ", " | ", "[", "]", and runs of 2+ spaces (AutoCAD).
var titleSplitRe = regexp.MustCompile(`\s+[-–—|]\s+|\[|\]|\s{2,}`)

// Classifier turns a raw (process, title) pair into a Heartbeat skeleton.
type Classifier struct {
	projectRe []*regexp.Regexp
	browser   *BrowserFilter
}

func NewClassifier(projectPatterns []*regexp.Regexp, browser *BrowserFilter) *Classifier {
	return &Classifier{projectRe: projectPatterns, browser: browser}
}

// AppForProcess returns the app family for an executable name or path.
func AppForProcess(exe string) protocol.AppKind {
	exe = strings.ToLower(baseName(exe))
	if k, ok := designProcesses[exe]; ok {
		return k
	}
	if browserProcesses[exe] {
		return protocol.AppBrowser
	}
	return protocol.AppOther
}

// Classify fills App/Category/ProjectCode/FileName/Domain/Trackable.
// domainHint is optional (from a DomainProvider); title is used only in
// memory and never persisted for browsers.
func (c *Classifier) Classify(exe, title, domainHint string) protocol.Heartbeat {
	hb := protocol.Heartbeat{Process: strings.ToLower(baseName(exe))}
	hb.App = AppForProcess(exe)

	switch {
	case hb.App.IsDesign():
		hb.Category = protocol.CategoryDesign
		hb.FileName = ExtractDesignFile(title)
		hb.ProjectCode = c.ExtractProjectCode(title, hb.FileName)
		hb.Trackable = true

	case hb.App == protocol.AppBrowser && c.browser != nil:
		v := c.browser.Classify(title, domainHint)
		if v.Private {
			hb.Trackable = false // incognito / InPrivate: record nothing
			return hb
		}
		hb.Category = v.Category
		hb.Domain = v.Domain
		hb.Trackable = true

	default:
		hb.Trackable = false
	}
	return hb
}

// ExtractProjectCode returns the first project-code match, checking the file
// name first (most specific) and then the full title. If a pattern contains a
// capture group, group 1 is the code.
func (c *Classifier) ExtractProjectCode(title, fileName string) string {
	for _, src := range []string{fileName, title} {
		if src == "" {
			continue
		}
		for _, re := range c.projectRe {
			m := re.FindStringSubmatch(src)
			if m == nil {
				continue
			}
			// Use the first capture group when the pattern defines one, so
			// patterns can express boundaries RE2 can't (no look-around).
			code := m[0]
			if len(m) > 1 && m[1] != "" {
				code = m[1]
			}
			return strings.ToUpper(strings.TrimSpace(code))
		}
	}
	return ""
}

// ExtractDesignFile pulls the open document's base name out of a CAD/CGI
// window title. Examples handled:
//
//	Autodesk AutoCAD 2025 - [C:\Proj\P-1023_Plan.dwg]
//	Autodesk AutoCAD 2024  P-1023_Plan.dwg
//	Autodesk Revit 2024.1 - [P-1023_Model.rvt - Floor Plan: Level 1]
//	P-1023_scene.max - Autodesk 3ds Max 2024
//	P-1023 Villa.skp* - SketchUp Pro 2024
func ExtractDesignFile(title string) string {
	for _, seg := range titleSplitRe.Split(title, -1) {
		seg = strings.TrimSpace(seg)
		seg = strings.TrimRight(seg, "* ")
		seg = strings.TrimSpace(seg)
		if seg == "" || !designExtRe.MatchString(seg) {
			continue
		}
		return baseName(seg)
	}
	return ""
}

// baseName strips both Windows and POSIX directory prefixes.
func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	return path.Base(p)
}
