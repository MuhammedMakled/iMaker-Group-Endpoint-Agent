package ipallow

import "testing"

func TestParseAndMatch(t *testing.T) {
	l, err := Parse([]string{"203.0.113.5", "10.0.0.0/8", " 192.168.1.0/24 ", "2001:db8::/32", ""})
	if err != nil {
		t.Fatal(err)
	}
	if l.Empty() {
		t.Fatal("list should not be empty")
	}
	cases := map[string]bool{
		"203.0.113.5":  true,
		"203.0.113.6":  false,
		"10.42.1.9":    true,
		"192.168.1.50": true,
		"192.168.2.50": false,
		"8.8.8.8":      false,
		"2001:db8::1":  true,
		"2001:dbff::1": false,
		"garbage":      false,
	}
	for ip, want := range cases {
		got, matched := l.Allowed(ip)
		if got != want {
			t.Errorf("%s: got %v (matched %q), want %v", ip, got, matched, want)
		}
		if got && matched == "" {
			t.Errorf("%s matched but no rule reported", ip)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]string{"10.0.0.0/33"}); err == nil {
		t.Error("bad CIDR should error")
	}
	if _, err := Parse([]string{"notanip"}); err == nil {
		t.Error("bad IP should error")
	}
}

func TestEmpty(t *testing.T) {
	l, _ := Parse(nil)
	if !l.Empty() {
		t.Fatal("nil rules should be empty")
	}
	if ok, _ := l.Allowed("1.2.3.4"); ok {
		t.Fatal("empty list must not allow anything (fail-closed)")
	}
}
