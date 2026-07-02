package nameconstraints

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
)

// FromExtensions locates the Name Constraints extension among a certificate's
// extensions and parses it. It returns a zero Constraints and false when no such
// extension is present.
func FromExtensions(exts []pkix.Extension) (Constraints, bool, error) {
	for _, e := range exts {
		if e.Id.Equal(oidNameConstraints) {
			c, err := ParseExtension(e.Value, e.Critical)
			if err != nil {
				return Constraints{}, false, err
			}
			return c, true, nil
		}
	}
	return Constraints{}, false, nil
}

// ParseExtension parses the DER value of a Name Constraints extension.
func ParseExtension(der []byte, critical bool) (Constraints, error) {
	var top struct {
		Permitted asn1.RawValue `asn1:"optional,tag:0"`
		Excluded  asn1.RawValue `asn1:"optional,tag:1"`
	}
	if _, err := asn1.Unmarshal(der, &top); err != nil {
		return Constraints{}, fmt.Errorf("parsing name constraints: %w", err)
	}
	c := Constraints{Critical: critical}
	var err error
	if len(top.Permitted.Bytes) > 0 || top.Permitted.FullBytes != nil {
		if c.Permitted, err = parseSubtrees(top.Permitted.Bytes); err != nil {
			return Constraints{}, fmt.Errorf("parsing permitted subtrees: %w", err)
		}
	}
	if len(top.Excluded.Bytes) > 0 || top.Excluded.FullBytes != nil {
		if c.Excluded, err = parseSubtrees(top.Excluded.Bytes); err != nil {
			return Constraints{}, fmt.Errorf("parsing excluded subtrees: %w", err)
		}
	}
	return c, nil
}

// parseSubtrees decodes the concatenated GeneralSubtree elements of one polarity.
func parseSubtrees(content []byte) (Subtrees, error) {
	var out Subtrees
	rest := content
	for len(rest) > 0 {
		var st generalSubtree
		var err error
		rest, err = asn1.Unmarshal(rest, &st)
		if err != nil {
			return Subtrees{}, fmt.Errorf("parsing subtree: %w", err)
		}
		gn := st.Base
		switch gn.Tag {
		case tagDNSName:
			out.DNS = append(out.DNS, string(gn.Bytes))
		case tagRFC822Name:
			out.Email = append(out.Email, string(gn.Bytes))
		case tagURI:
			out.URI = append(out.URI, string(gn.Bytes))
		case tagIPAddress:
			ipnet, err := parseIPSubtree(gn.Bytes)
			if err != nil {
				return Subtrees{}, err
			}
			out.IP = append(out.IP, ipnet)
		case tagDirName:
			var rdn pkix.RDNSequence
			if _, err := asn1.Unmarshal(gn.Bytes, &rdn); err != nil {
				return Subtrees{}, fmt.Errorf("parsing directoryName subtree: %w", err)
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			out.DirNames = append(out.DirNames, name)
		default:
			// An unrecognized general-name form in the CA's own constraints is a
			// hard error: the enforcement gate must never silently ignore a subtree
			// it cannot evaluate (that would be fail-open).
			return Subtrees{}, fmt.Errorf("unsupported general-name tag %d in name-constraint subtree", gn.Tag)
		}
	}
	return out, nil
}

// parseIPSubtree decodes a name-constraint iPAddress octet string (address ||
// mask) into a network.
func parseIPSubtree(b []byte) (*net.IPNet, error) {
	switch len(b) {
	case 2 * net.IPv4len:
		return &net.IPNet{IP: net.IP(b[:net.IPv4len]), Mask: net.IPMask(b[net.IPv4len:])}, nil
	case 2 * net.IPv6len:
		return &net.IPNet{IP: net.IP(b[:net.IPv6len]), Mask: net.IPMask(b[net.IPv6len:])}, nil
	default:
		return nil, fmt.Errorf("invalid IP name-constraint length %d (want 8 or 32)", len(b))
	}
}
