package certpolicy

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// PolicyConfig is the string-oriented certificate-policy configuration supplied
// by the API, CLI, or a config file.
type PolicyConfig struct {
	// OIDs are dotted policy identifiers ("1.3.6.1.4.1.99999.1.1"), or the literal
	// "anyPolicy" for 2.5.29.32.0.
	OIDs []string `json:"oids,omitempty"`
	// CPS, when set, is applied as the CPS-URI qualifier of every listed policy.
	CPS string `json:"cps,omitempty"`
	// Critical marks the certificatePolicies extension critical (rarely needed).
	Critical bool `json:"critical,omitempty"`
	// Mappings are "issuerOID:subjectOID" policy-mapping pairs (CA certificates).
	Mappings []string `json:"mappings,omitempty"`
	// RequireExplicitPolicy / InhibitPolicyMapping emit a policyConstraints
	// extension when non-nil (CA certificates).
	RequireExplicitPolicy *int `json:"require_explicit_policy,omitempty"`
	InhibitPolicyMapping  *int `json:"inhibit_policy_mapping,omitempty"`
}

// IsZero reports whether the configuration emits nothing.
func (c PolicyConfig) IsZero() bool {
	return len(c.OIDs) == 0 && len(c.Mappings) == 0 &&
		c.RequireExplicitPolicy == nil && c.InhibitPolicyMapping == nil
}

// Build validates the configuration and produces a Policies value.
func (c PolicyConfig) Build() (Policies, error) {
	if c.IsZero() {
		return Policies{}, nil
	}
	p := Policies{
		CertificatePoliciesCritical: c.Critical,
		RequireExplicitPolicy:       c.RequireExplicitPolicy,
		InhibitPolicyMapping:        c.InhibitPolicyMapping,
	}
	for _, s := range c.OIDs {
		oid, err := ParseOID(s)
		if err != nil {
			return Policies{}, err
		}
		p.Info = append(p.Info, PolicyInfo{OID: oid, CPS: c.CPS})
	}
	for _, m := range c.Mappings {
		issuer, subject, ok := strings.Cut(m, ":")
		if !ok {
			return Policies{}, fmt.Errorf("invalid policy mapping %q (want issuerOID:subjectOID)", m)
		}
		iOID, err := ParseOID(strings.TrimSpace(issuer))
		if err != nil {
			return Policies{}, fmt.Errorf("policy mapping %q: %w", m, err)
		}
		sOID, err := ParseOID(strings.TrimSpace(subject))
		if err != nil {
			return Policies{}, fmt.Errorf("policy mapping %q: %w", m, err)
		}
		p.Mappings = append(p.Mappings, PolicyMapping{IssuerDomainPolicy: iOID, SubjectDomainPolicy: sOID})
	}
	return p, nil
}

// ParseOID parses a dotted object identifier, accepting the alias "anyPolicy".
func ParseOID(s string) (asn1.ObjectIdentifier, error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "anyPolicy") {
		return oidAnyPolicy, nil
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q: bad arc %q", s, p)
		}
		oid = append(oid, n)
	}
	return oid, nil
}
