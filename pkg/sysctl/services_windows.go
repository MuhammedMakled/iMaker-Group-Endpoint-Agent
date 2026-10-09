//go:build windows

package sysctl

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/MuhammedMakled/iMaker-Group-Endpoint-Agent/pkg/protocol"
)

var wmiClient = &wmi.Client{AllowMissingFields: true, PtrNil: true, NonePtrZero: true}

type win32Service struct {
	Name             string
	DisplayName      string
	State            string
	StartMode        string
	ProcessId        uint32
	Description      string
	AcceptStop       bool
	StartName        string
	DelayedAutoStart bool
}

// ListServices returns all services, optionally filtered.
func ListServices(filter string, onlyRunning bool) ([]protocol.ServiceInfo, error) {
	var svcs []win32Service
	if err := wmiClient.Query("SELECT Name, DisplayName, State, StartMode, ProcessId, Description, AcceptStop, StartName, DelayedAutoStart FROM Win32_Service", &svcs); err != nil {
		return nil, err
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	out := make([]protocol.ServiceInfo, 0, len(svcs))
	for _, s := range svcs {
		if onlyRunning && !strings.EqualFold(s.State, "Running") {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(s.Name), filter) &&
			!strings.Contains(strings.ToLower(s.DisplayName), filter) {
			continue
		}
		out = append(out, protocol.ServiceInfo{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Status:      s.State,
			StartType:   NormalizeStartMode(s.StartMode, s.DelayedAutoStart),
			PID:         s.ProcessId,
			Description: s.Description,
			CanStop:     s.AcceptStop && !IsCriticalService(s.Name),
			Account:     s.StartName,
		})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].DisplayName) < strings.ToLower(out[j].DisplayName) })
	return out, nil
}

// ControlService starts, stops or restarts a service. Critical services are
// refused for stop/restart.
func ControlService(name, action string) (string, error) {
	if err := ValidateServiceAction(action); err != nil {
		return "", err
	}
	if (action == "stop" || action == "restart") && IsCriticalService(name) {
		return "", fmt.Errorf("%q is a critical system service and cannot be stopped through the agent", name)
	}
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return "", fmt.Errorf("service %q not found: %w", name, err)
	}
	defer s.Close()

	switch action {
	case "start":
		if err := s.Start(); err != nil {
			return "", err
		}
		return waitState(s, svc.Running)
	case "stop":
		if _, err := s.Control(svc.Stop); err != nil {
			return "", err
		}
		return waitState(s, svc.Stopped)
	case "restart":
		if _, err := s.Control(svc.Stop); err == nil {
			_, _ = waitState(s, svc.Stopped)
		}
		if err := s.Start(); err != nil {
			return "", err
		}
		return waitState(s, svc.Running)
	}
	return "", nil
}

func waitState(s *mgr.Service, want svc.State) (string, error) {
	deadline := time.Now().Add(25 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			return "", err
		}
		if st.State == want {
			return stateName(st.State), nil
		}
		if time.Now().After(deadline) {
			return stateName(st.State), fmt.Errorf("timed out waiting for service to reach %s", stateName(want))
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "Stopped"
	case svc.StartPending:
		return "StartPending"
	case svc.StopPending:
		return "StopPending"
	case svc.Running:
		return "Running"
	case svc.PausePending:
		return "PausePending"
	case svc.Paused:
		return "Paused"
	case svc.ContinuePending:
		return "ContinuePending"
	}
	return "Unknown"
}
