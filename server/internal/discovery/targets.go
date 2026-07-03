package discovery

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// TargetSpec collects every way a caller can name endpoints to scan. The scanner
// expands it into a de-duplicated, ordered list of Targets.
type TargetSpec struct {
	// Endpoints are literal "host[:port][#sni]" entries.
	Endpoints []string
	// HostsFile, when set, is a file of one endpoint per line ('#' begins a
	// comment; blank lines ignored).
	HostsFile string
	// CIDRs are network ranges (e.g. "10.0.0.0/28"); every host address in each
	// range becomes a target with the default port and no SNI.
	CIDRs []string
	// DefaultPort is applied to entries without an explicit port (0 => DefaultPort).
	DefaultPort int
	// MaxCIDRHosts caps how many addresses a single CIDR may expand to, so an
	// over-broad range cannot blow up the scan (0 => 4096).
	MaxCIDRHosts int
}

// ParseTargets expands a TargetSpec into an ordered, de-duplicated target list.
func ParseTargets(spec TargetSpec) ([]Target, error) {
	port := spec.DefaultPort
	if port == 0 {
		port = DefaultPort
	}
	maxHosts := spec.MaxCIDRHosts
	if maxHosts == 0 {
		maxHosts = 4096
	}

	var out []Target
	seen := make(map[string]bool)
	add := func(t Target) {
		key := t.Address() + "|" + t.ServerName
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, t)
	}

	for _, e := range spec.Endpoints {
		t, err := parseEndpoint(e, port)
		if err != nil {
			return nil, err
		}
		add(t)
	}

	if spec.HostsFile != "" {
		entries, err := readHostsFile(spec.HostsFile)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			t, err := parseEndpoint(e, port)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", spec.HostsFile, err)
			}
			add(t)
		}
	}

	for _, c := range spec.CIDRs {
		targets, err := expandCIDR(c, port, maxHosts)
		if err != nil {
			return nil, err
		}
		for _, t := range targets {
			add(t)
		}
	}

	return out, nil
}

// parseEndpoint parses a "host[:port][#sni]" entry. When no port is given the
// default is used; when no explicit SNI is given, a DNS host is used as its own
// SNI and a bare IP presents no SNI.
func parseEndpoint(entry string, defaultPort int) (Target, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return Target{}, fmt.Errorf("empty endpoint")
	}

	sni := ""
	if i := strings.Index(entry, "#"); i >= 0 {
		sni = strings.TrimSpace(entry[i+1:])
		entry = strings.TrimSpace(entry[:i])
	}

	host := entry
	port := defaultPort
	if h, p, err := net.SplitHostPort(entry); err == nil {
		host = h
		parsed, perr := strconv.Atoi(p)
		if perr != nil || parsed <= 0 || parsed > 65535 {
			return Target{}, fmt.Errorf("invalid port in %q", entry)
		}
		port = parsed
	} else if strings.Count(entry, ":") >= 2 && !strings.Contains(entry, "]") {
		// A bare IPv6 literal without brackets (e.g. "::1") has no port; keep it.
		host = entry
	}

	host = strings.TrimSpace(host)
	if host == "" {
		return Target{}, fmt.Errorf("missing host in %q", entry)
	}

	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	return Target{Host: host, Port: port, ServerName: sni}, nil
}

// readHostsFile reads endpoints from a file, one per line, skipping blank lines
// and '#'-prefixed comments (trailing comments are also stripped).
func readHostsFile(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening hosts file: %w", err)
	}
	defer func() { _ = fh.Close() }()

	var entries []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			entries = append(entries, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading hosts file: %w", err)
	}
	return entries, nil
}

// expandCIDR turns a network range into one target per host address (excluding
// the network and broadcast addresses for IPv4 ranges larger than a /31). It
// errors if the range would exceed maxHosts.
func expandCIDR(cidr string, port, maxHosts int) ([]Target, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	// Guard against enormous ranges before materializing anything.
	if hostBits > 20 || (1<<uint(hostBits)) > maxHosts+2 {
		return nil, fmt.Errorf("CIDR %q expands to too many hosts (limit %d); narrow the range", cidr, maxHosts)
	}

	var targets []Target
	isV4 := ipnet.IP.To4() != nil
	for ip := cloneIP(ipnet.IP); ipnet.Contains(ip); incIP(ip) {
		// Skip network/broadcast for IPv4 ranges bigger than a point-to-point /31.
		if isV4 && hostBits >= 2 {
			if isNetworkAddr(ip, ipnet) || isBroadcastAddr(ip, ipnet) {
				continue
			}
		}
		targets = append(targets, Target{Host: ip.String(), Port: port})
		if len(targets) > maxHosts {
			return nil, fmt.Errorf("CIDR %q expands to too many hosts (limit %d); narrow the range", cidr, maxHosts)
		}
	}
	return targets, nil
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func isNetworkAddr(ip net.IP, ipnet *net.IPNet) bool {
	return ip.Equal(ipnet.IP)
}

func isBroadcastAddr(ip net.IP, ipnet *net.IPNet) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	bcast := make(net.IP, len(v4))
	base := ipnet.IP.To4()
	if base == nil {
		return false
	}
	for i := range v4 {
		bcast[i] = base[i] | ^ipnet.Mask[i]
	}
	return v4.Equal(bcast)
}
