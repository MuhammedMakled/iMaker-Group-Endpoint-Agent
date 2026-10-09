package telemetry

import "testing"

func TestBuildInventory(t *testing.T) {
	items := BuildInventory([]UninstallEntry{
		{DisplayName: "Autodesk Revit 2024", DisplayVersion: "24.2.0", Publisher: "Autodesk", InstallDate: "20240301", Scope: "machine", Architecture: "x64"},
		{DisplayName: "Autodesk Revit 2024", DisplayVersion: "24.2.0", Publisher: "Autodesk", Scope: "machine", Architecture: "x86"}, // dup view
		{DisplayName: "Security Update for X", ParentKeyName: "X"},
		{DisplayName: "Hidden runtime", SystemComponent: 1},
		{DisplayName: "KB123", ReleaseType: "Hotfix"},
		{DisplayName: ""},
		{DisplayName: "Dropbox", DisplayVersion: "210.4", Publisher: "Dropbox, Inc.", Scope: "user", UserSID: "S-1-5-21-1"},
	})
	if len(items) != 2 {
		t.Fatalf("want 2 items, got %d: %+v", len(items), items)
	}
	if items[0].Name != "Autodesk Revit 2024" || items[0].InstallDate != "2024-03-01" {
		t.Errorf("unexpected first item %+v", items[0])
	}
	if got := FilterSoftware(items, "dropbox"); len(got) != 1 || got[0].Scope != "user" {
		t.Errorf("filter: %+v", got)
	}
}
