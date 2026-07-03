package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantSNI  string
	}{
		{"example.com", "example.com", 443, "example.com"},
		{"example.com:8443", "example.com", 8443, "example.com"},
		{"10.0.0.5", "10.0.0.5", 443, ""},                                        // bare IP => no SNI
		{"10.0.0.5:9443", "10.0.0.5", 9443, ""},                                  // bare IP with port
		{"10.0.0.5:9443#internal.example", "10.0.0.5", 9443, "internal.example"}, // explicit SNI
		{"host.example#sni.example", "host.example", 443, "sni.example"},
	}
	for _, c := range cases {
		got, err := parseEndpoint(c.in, DefaultPort)
		if err != nil {
			t.Fatalf("parseEndpoint(%q): %v", c.in, err)
		}
		if got.Host != c.wantHost || got.Port != c.wantPort || got.ServerName != c.wantSNI {
			t.Errorf("parseEndpoint(%q) = %+v, want host=%q port=%d sni=%q",
				c.in, got, c.wantHost, c.wantPort, c.wantSNI)
		}
	}
}

func TestParseEndpointErrors(t *testing.T) {
	for _, in := range []string{"", "host:notaport", "host:0", "host:70000"} {
		if _, err := parseEndpoint(in, DefaultPort); err == nil {
			t.Errorf("parseEndpoint(%q) expected error", in)
		}
	}
}

func TestParseTargetsDedup(t *testing.T) {
	spec := TargetSpec{Endpoints: []string{"a.example:443", "a.example", "b.example"}}
	targets, err := ParseTargets(spec)
	if err != nil {
		t.Fatal(err)
	}
	// "a.example:443" and "a.example" resolve to the same host:port#sni.
	if len(targets) != 2 {
		t.Errorf("expected 2 de-duplicated targets, got %d: %+v", len(targets), targets)
	}
}

func TestParseTargetsHostsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	content := "# a comment\n\nfirst.example\nsecond.example:8443  # trailing comment\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := ParseTargets(TargetSpec{HostsFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets from hosts file, got %d: %+v", len(targets), targets)
	}
	if targets[1].Port != 8443 {
		t.Errorf("second entry port = %d, want 8443", targets[1].Port)
	}
}

func TestExpandCIDR(t *testing.T) {
	// A /30 has 4 addresses; network and broadcast are excluded => 2 usable.
	targets, err := expandCIDR("192.168.5.0/30", 443, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("/30 expanded to %d targets, want 2: %+v", len(targets), targets)
	}
	if targets[0].Host != "192.168.5.1" || targets[1].Host != "192.168.5.2" {
		t.Errorf("unexpected hosts: %+v", targets)
	}
}

func TestExpandCIDRTooLarge(t *testing.T) {
	if _, err := expandCIDR("10.0.0.0/8", 443, 4096); err == nil {
		t.Errorf("expected an error for an over-broad CIDR")
	}
}

func TestExpandCIDRPointToPoint(t *testing.T) {
	// A /31 has no network/broadcast reservation: both addresses are usable.
	targets, err := expandCIDR("192.168.5.0/31", 443, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Errorf("/31 expanded to %d targets, want 2", len(targets))
	}
}
