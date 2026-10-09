package toast

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

func TestBuildXML(t *testing.T) {
	n := protocol.Notification{
		Title:    `Revit <2025> & "Dropbox"`,
		Message:  "Save your work & close Revit.",
		Severity: protocol.SeverityCritical,
		URL:      "https://imaker-group.co/it?a=1&b=2",
	}
	x := BuildXML(n, "IMAKER IT")
	// Must be well-formed XML despite special characters.
	if err := xml.Unmarshal([]byte(x), new(struct{})); err != nil {
		t.Fatalf("invalid xml: %v\n%s", err, x)
	}
	for _, want := range []string{`scenario="reminder"`, `activationType="protocol"`, `&amp;b=2`, `Dismiss`, `IMAKER IT`, `&lt;2025&gt;`} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q in %s", want, x)
		}
	}
	plain := BuildXML(protocol.Notification{Title: "Hi", Message: "There", Severity: protocol.SeverityInfo}, "")
	if strings.Contains(plain, "<actions>") || strings.Contains(plain, "scenario") {
		t.Errorf("info toast without URL should be minimal: %s", plain)
	}
}

func TestValidAppID(t *testing.T) {
	if !ValidAppID("IMAKER.EndpointAgent") || ValidAppID("x'; Remove-Item C:\\") || ValidAppID("") {
		t.Error("app id validation")
	}
}
