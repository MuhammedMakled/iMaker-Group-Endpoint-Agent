// Package ipallow implements an IP allowlist for the agent's remote command
// channel. Everything today runs over the local named pipe, so the list is
// inert until the Phase-3 dashboard uplink is enabled; it is built and tested
// now so the policy is ready and auditable.
package ipallow

import (
	"fmt"
	"net"
	"strings"
)

// List is a compiled set of allowed IPs / CIDR ranges.
type List struct {
	nets    []*net.IPNet
	singles []net.IP
	rules   []string
}

// Parse compiles rule strings. Each rule is an IP ("203.0.113.5"), a CIDR
// ("10.0.0.0/8"), or an IPv6 equivalent. Empty input yields an empty list.
func Parse(rules []string) (*List, error) {
	l := &List{}
	for _, raw := range rules {
		r := strings.TrimSpace(raw)
		if r == "" {
			continue
		}
		l.rules = append(l.rules, r)
		if strings.Contains(r, "/") {
			_, n, err := net.ParseCIDR(r)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", r, err)
			}
			l.nets = append(l.nets, n)
			continue
		}
		ip := net.ParseIP(r)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", r)
		}
		l.singles = append(l.singles, ip)
	}
	return l, nil
}

// Empty reports whether no rules are configured.
func (l *List) Empty() bool { return len(l.nets)+len(l.singles) == 0 }

// Rules returns the configured rule strings.
func (l *List) Rules() []string { return append([]string{}, l.rules...) }

// Allowed reports whether ip matches any rule. An empty list allows nothing
// (fail-closed) — callers decide whether an empty list means "no restriction".
func (l *List) Allowed(ip string) (bool, string) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false, ""
	}
	for _, s := range l.singles {
		if s.Equal(parsed) {
			return true, s.String()
		}
	}
	for _, n := range l.nets {
		if n.Contains(parsed) {
			return true, n.String()
		}
	}
	return false, ""
}
