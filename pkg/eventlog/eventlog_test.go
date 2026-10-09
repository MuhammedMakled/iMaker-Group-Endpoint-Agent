package eventlog

import "testing"

func TestParseEvents(t *testing.T) {
	// array form
	arr := `[{"EventID":4720,"Time":"2026-10-09T18:00:00Z","Target":"sneaky","Subject":"IMAKER\\it","Group":"-","Message":"A user account was created"},
{"EventID":4732,"Time":"2026-10-09T18:01:00Z","Target":"sneaky","Subject":"IMAKER\\it","Group":"Administrators","Message":"Member added"}]`
	evs, err := ParseEvents([]byte(arr))
	if err != nil || len(evs) != 2 {
		t.Fatalf("parse: %v %d", err, len(evs))
	}
	if evs[0].TargetUser != "sneaky" || evs[0].EventID != 4720 {
		t.Fatalf("ev0: %+v", evs[0])
	}
	if !evs[1].IsPrivilegedGroupEvent() {
		t.Error("Administrators add should be privileged")
	}
	// single object form
	one, err := ParseEvents([]byte(`{"EventID":4728,"Time":"2026-10-09T18:02:00Z","Target":"x","Subject":"-","Group":"Power Users","Message":"m"}`))
	if err != nil || len(one) != 1 || !one[0].IsPrivilegedGroupEvent() {
		t.Fatalf("single: %v %+v", err, one)
	}
	// empty
	if evs, _ := ParseEvents([]byte("[]")); evs != nil {
		t.Error("empty should be nil")
	}
	// non-privileged group
	ng, _ := ParseEvents([]byte(`{"EventID":4732,"Time":"2026-10-09T18:02:00Z","Target":"x","Group":"Users","Message":"m"}`))
	if ng[0].IsPrivilegedGroupEvent() {
		t.Error("Users group is not privileged")
	}
}
