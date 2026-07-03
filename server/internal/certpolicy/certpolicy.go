// Package certpolicy builds the RFC 5280 certificate-policy family of X.509
// extensions: Certificate Policies (2.5.29.32 §4.2.1.4), Policy Mappings
// (2.5.29.33 §4.2.1.5), and Policy Constraints (2.5.29.36 §4.2.1.11).
//
// Certificate Policies assign one or more policy OIDs (optionally with a CPS URI
// qualifier) to a leaf or CA certificate. Policy Mappings and Policy Constraints
// are CA-only extensions that relate an issuer's policy OIDs to a subordinate's
// and bound how policy processing proceeds down the chain. Go's crypto/x509 can
// emit certificate policies but not policy mappings or policy constraints, so
// this package hand-rolls the ASN.1 for all three and returns them as
// pkix.Extensions to append to a certificate template.
package certpolicy

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var (
	oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidPolicyMappings      = asn1.ObjectIdentifier{2, 5, 29, 33}
	oidPolicyConstraints   = asn1.ObjectIdentifier{2, 5, 29, 36}

	// oidAnyPolicy is the special anyPolicy identifier (2.5.29.32.0).
	oidAnyPolicy = asn1.ObjectIdentifier{2, 5, 29, 32, 0}
	// oidCPS is id-qt-cps, the CPS pointer qualifier (RFC 5280 §4.2.1.4).
	oidCPS = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
)

// AnyPolicyOID returns the anyPolicy object identifier (2.5.29.32.0).
func AnyPolicyOID() asn1.ObjectIdentifier { return oidAnyPolicy }

// PolicyInfo is a single certificate policy: its OID and an optional CPS-URI
// qualifier.
type PolicyInfo struct {
	OID asn1.ObjectIdentifier
	// CPS, when non-empty, is embedded as an id-qt-cps qualifier (a URI pointing
	// at the Certification Practice Statement).
	CPS string
}

// PolicyMapping relates an issuer-domain policy OID to the subject-domain policy
// OID it maps to on a subordinate CA.
type PolicyMapping struct {
	IssuerDomainPolicy  asn1.ObjectIdentifier
	SubjectDomainPolicy asn1.ObjectIdentifier
}

// Policies is the certificate-policy configuration for one certificate.
type Policies struct {
	// Info lists the certificate policies to assert. Empty emits no
	// certificatePolicies extension.
	Info []PolicyInfo
	// CertificatePoliciesCritical marks the certificatePolicies extension critical
	// (usually false).
	CertificatePoliciesCritical bool

	// Mappings, when non-empty, emits a policyMappings extension (CA certificates
	// only).
	Mappings []PolicyMapping

	// RequireExplicitPolicy / InhibitPolicyMapping, when non-nil, emit a
	// policyConstraints extension with the given skipCerts values. Per RFC 5280
	// policyConstraints is always critical.
	RequireExplicitPolicy *int
	InhibitPolicyMapping  *int
}

// IsZero reports whether the configuration emits no extensions.
func (p Policies) IsZero() bool {
	return len(p.Info) == 0 && len(p.Mappings) == 0 &&
		p.RequireExplicitPolicy == nil && p.InhibitPolicyMapping == nil
}

// Extensions builds the DER-encoded certificate-policy extensions the
// configuration requests, in canonical order (policies, mappings, constraints).
func (p Policies) Extensions() ([]pkix.Extension, error) {
	var out []pkix.Extension

	if len(p.Info) > 0 {
		ext, err := p.certificatePoliciesExtension()
		if err != nil {
			return nil, err
		}
		out = append(out, ext)
	}
	if len(p.Mappings) > 0 {
		ext, err := p.policyMappingsExtension()
		if err != nil {
			return nil, err
		}
		out = append(out, ext)
	}
	if p.RequireExplicitPolicy != nil || p.InhibitPolicyMapping != nil {
		ext, err := p.policyConstraintsExtension()
		if err != nil {
			return nil, err
		}
		out = append(out, ext)
	}
	return out, nil
}

// policyQualifierInfo mirrors the PolicyQualifierInfo SEQUENCE. The qualifier is
// a raw value so a CPS pointer (IA5String URI) is carried verbatim.
type policyQualifierInfo struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         asn1.RawValue
}

// policyInformation mirrors the PolicyInformation SEQUENCE.
type policyInformation struct {
	Policy     asn1.ObjectIdentifier
	Qualifiers []policyQualifierInfo `asn1:"omitempty"`
}

func (p Policies) certificatePoliciesExtension() (pkix.Extension, error) {
	infos := make([]policyInformation, 0, len(p.Info))
	for _, pi := range p.Info {
		if len(pi.OID) == 0 {
			return pkix.Extension{}, fmt.Errorf("certificate policy has an empty OID")
		}
		info := policyInformation{Policy: pi.OID}
		if pi.CPS != "" {
			qualifier, err := asn1.MarshalWithParams(pi.CPS, "ia5")
			if err != nil {
				return pkix.Extension{}, fmt.Errorf("encoding CPS qualifier: %w", err)
			}
			info.Qualifiers = []policyQualifierInfo{{
				PolicyQualifierID: oidCPS,
				Qualifier:         asn1.RawValue{FullBytes: qualifier},
			}}
		}
		infos = append(infos, info)
	}
	value, err := asn1.Marshal(infos)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding certificate policies: %w", err)
	}
	return pkix.Extension{Id: oidCertificatePolicies, Critical: p.CertificatePoliciesCritical, Value: value}, nil
}

// policyMapping mirrors one PolicyMappings entry.
type policyMapping struct {
	IssuerDomainPolicy  asn1.ObjectIdentifier
	SubjectDomainPolicy asn1.ObjectIdentifier
}

func (p Policies) policyMappingsExtension() (pkix.Extension, error) {
	maps := make([]policyMapping, 0, len(p.Mappings))
	for _, m := range p.Mappings {
		if len(m.IssuerDomainPolicy) == 0 || len(m.SubjectDomainPolicy) == 0 {
			return pkix.Extension{}, fmt.Errorf("policy mapping requires both issuer and subject domain policy OIDs")
		}
		maps = append(maps, policyMapping(m))
	}
	value, err := asn1.Marshal(maps)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding policy mappings: %w", err)
	}
	// RFC 5280 §4.2.1.5: policyMappings SHOULD be marked critical.
	return pkix.Extension{Id: oidPolicyMappings, Critical: true, Value: value}, nil
}

func (p Policies) policyConstraintsExtension() (pkix.Extension, error) {
	// PolicyConstraints ::= SEQUENCE {
	//   requireExplicitPolicy [0] SkipCerts OPTIONAL,
	//   inhibitPolicyMapping  [1] SkipCerts OPTIONAL }
	// The SkipCerts INTEGERs are IMPLICIT context-tagged.
	var content []byte
	if p.RequireExplicitPolicy != nil {
		b, err := marshalImplicitInt(0, *p.RequireExplicitPolicy)
		if err != nil {
			return pkix.Extension{}, err
		}
		content = append(content, b...)
	}
	if p.InhibitPolicyMapping != nil {
		b, err := marshalImplicitInt(1, *p.InhibitPolicyMapping)
		if err != nil {
			return pkix.Extension{}, err
		}
		content = append(content, b...)
	}
	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding policy constraints: %w", err)
	}
	// RFC 5280 §4.2.1.11: policyConstraints MUST be critical.
	return pkix.Extension{Id: oidPolicyConstraints, Critical: true, Value: value}, nil
}

// marshalImplicitInt encodes an INTEGER with an IMPLICIT context tag by rewriting
// the universal INTEGER tag byte to the context-specific primitive tag.
func marshalImplicitInt(tag, v int) ([]byte, error) {
	der, err := asn1.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encoding skipCerts: %w", err)
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("empty INTEGER encoding")
	}
	// 0x80 = context-specific, primitive; low 5 bits carry the tag number.
	der[0] = 0x80 | byte(tag)
	return der, nil
}
