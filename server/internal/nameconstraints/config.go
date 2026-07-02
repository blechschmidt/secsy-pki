package nameconstraints

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// SubtreeConfig is the string-oriented configuration of one polarity's subtrees,
// as supplied by the API, CLI, or a config file. IPs are CIDR strings and
// DirNames are RFC 4514-style distinguished names ("O=Acme,C=US").
type SubtreeConfig struct {
	DNS      []string `json:"dns,omitempty"`
	IP       []string `json:"ip,omitempty"`
	Email    []string `json:"email,omitempty"`
	URI      []string `json:"uri,omitempty"`
	DirNames []string `json:"dir_names,omitempty"`
}

func (s SubtreeConfig) isEmpty() bool {
	return len(s.DNS) == 0 && len(s.IP) == 0 && len(s.Email) == 0 &&
		len(s.URI) == 0 && len(s.DirNames) == 0
}

// Config is the operator-facing Name Constraints configuration for a CA.
type Config struct {
	Permitted SubtreeConfig `json:"permitted,omitempty"`
	Excluded  SubtreeConfig `json:"excluded,omitempty"`
	// Critical overrides the default (critical) extension marking. Nil defaults to
	// true, as RFC 5280 requires.
	Critical *bool `json:"critical,omitempty"`
}

// IsZero reports whether the configuration requests no name constraints.
func (c Config) IsZero() bool {
	return c.Permitted.isEmpty() && c.Excluded.isEmpty()
}

// Build validates the configuration and produces Constraints ready to encode.
func (c Config) Build() (Constraints, error) {
	if c.IsZero() {
		return Constraints{}, nil
	}
	permitted, err := c.Permitted.build()
	if err != nil {
		return Constraints{}, fmt.Errorf("permitted subtrees: %w", err)
	}
	excluded, err := c.Excluded.build()
	if err != nil {
		return Constraints{}, fmt.Errorf("excluded subtrees: %w", err)
	}
	critical := true
	if c.Critical != nil {
		critical = *c.Critical
	}
	return Constraints{Permitted: permitted, Excluded: excluded, Critical: critical}, nil
}

func (s SubtreeConfig) build() (Subtrees, error) {
	out := Subtrees{DNS: s.DNS, Email: s.Email, URI: s.URI}
	for _, cidr := range s.IP {
		ipnet, err := parseCIDR(cidr)
		if err != nil {
			return Subtrees{}, err
		}
		out.IP = append(out.IP, ipnet)
	}
	for _, dn := range s.DirNames {
		name, err := ParseDN(dn)
		if err != nil {
			return Subtrees{}, err
		}
		out.DirNames = append(out.DirNames, name)
	}
	return out, nil
}

// parseCIDR accepts a CIDR ("10.0.0.0/8") or a bare address (treated as a host
// route: /32 for IPv4, /128 for IPv6).
func parseCIDR(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid IP subtree %q: %w", s, err)
		}
		return ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP subtree %q", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// dnAttributeOIDs maps the RFC 4514 short attribute names accepted in a
// directoryName subtree to their object identifiers.
var dnAttributeOIDs = map[string]asn1.ObjectIdentifier{
	"CN": {2, 5, 4, 3},
	"C":  {2, 5, 4, 6},
	"L":  {2, 5, 4, 7},
	"ST": {2, 5, 4, 8},
	"S":  {2, 5, 4, 8},
	"O":  {2, 5, 4, 10},
	"OU": {2, 5, 4, 11},
	"DC": {0, 9, 2342, 19200300, 100, 1, 25},
}

// ParseDN parses a comma-separated RFC 4514-style distinguished name into a
// pkix.Name, supporting the common short attribute types. It is intentionally
// minimal — enough for name-constraint directoryName subtrees.
func ParseDN(s string) (pkix.Name, error) {
	var rdns pkix.RDNSequence
	for _, part := range splitDN(s) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.Index(part, "=")
		if eq < 0 {
			return pkix.Name{}, fmt.Errorf("invalid DN component %q (want TYPE=VALUE)", part)
		}
		typ := strings.ToUpper(strings.TrimSpace(part[:eq]))
		value := strings.TrimSpace(part[eq+1:])
		oid, ok := dnAttributeOIDs[typ]
		if !ok {
			return pkix.Name{}, fmt.Errorf("unsupported DN attribute %q in %q", typ, s)
		}
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{Type: oid, Value: value}})
	}
	if len(rdns) == 0 {
		return pkix.Name{}, fmt.Errorf("empty distinguished name %q", s)
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	return name, nil
}

// splitDN splits a DN on unescaped commas.
func splitDN(s string) []string {
	var parts []string
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())
	return parts
}
