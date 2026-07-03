package certlint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
	"time"
)

// baseSMIMECert builds a structurally valid dual-use mailbox-validated S/MIME
// leaf that passes the full rule set under the default (multipurpose, dual)
// policy. Tests mutate a copy per case.
func baseSMIMECert(t *testing.T) *x509.Certificate {
	t.Helper()
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "Alice Example"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		EmailAddresses:        []string{"alice@example.com"},
		BasicConstraintsValid: true,
	}
}

func smimePolicy(class SMIMEClass, variant SMIMEVariant) Policy {
	return Policy{SMIME: &SMIMEPolicy{Class: class, Variant: variant}}
}

func TestSMIMELintChecks(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		policy   Policy
		mutate   func(c *x509.Certificate)
		wantCode string // "" means expect a clean pass
	}{
		{
			name:   "valid dual-use cert passes",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {},
		},
		{
			name:   "smime checks off without policy",
			policy: Policy{},
			mutate: func(c *x509.Certificate) { c.EmailAddresses = nil; c.DNSNames = []string{"x.example.com"} },
		},
		{
			name:     "SAN-less request rejected",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.EmailAddresses = nil },
			wantCode: CheckSMIMESANPresent,
		},
		{
			name:     "dNSName SAN mixed in rejected",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.DNSNames = []string{"mail.example.com"} },
			wantCode: CheckSMIMESANTypes,
		},
		{
			name:     "iPAddress SAN mixed in rejected",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} },
			wantCode: CheckSMIMESANTypes,
		},
		{
			name:     "unnormalized rfc822Name rejected",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.EmailAddresses = []string{"alice@EXAMPLE.com"} },
			wantCode: CheckSMIMEEmailSyntax,
		},
		{
			name:     "malformed rfc822Name rejected",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.EmailAddresses = []string{"Alice <alice@example.com>"} },
			wantCode: CheckSMIMEEmailSyntax,
		},
		{
			name:   "serverAuth mixing rejected",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			},
			wantCode: CheckSMIMEEKU,
		},
		{
			name:   "anyExtendedKeyUsage rejected",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageAny)
			},
			wantCode: CheckSMIMEEKU,
		},
		{
			name:   "missing emailProtection rejected",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			wantCode: CheckSMIMEEKU,
		},
		{
			name:   "multipurpose tolerates clientAuth",
			policy: smimePolicy(SMIMEClassMultipurpose, ""),
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
			},
		},
		{
			name:   "strict rejects clientAuth",
			policy: smimePolicy(SMIMEClassStrict, ""),
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
			},
			wantCode: CheckSMIMEEKU,
		},
		{
			name:     "multipurpose validity cap enforced",
			policy:   smimePolicy(SMIMEClassMultipurpose, ""),
			mutate:   func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(900 * 24 * time.Hour) },
			wantCode: CheckSMIMEValidity,
		},
		{
			name:   "legacy permits 900 days",
			policy: smimePolicy(SMIMEClassLegacy, ""),
			mutate: func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(900 * 24 * time.Hour) },
		},
		{
			name:     "legacy validity cap enforced",
			policy:   smimePolicy(SMIMEClassLegacy, ""),
			mutate:   func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(1200 * 24 * time.Hour) },
			wantCode: CheckSMIMEValidity,
		},
		{
			name:     "missing key usage rejected",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.KeyUsage = 0 },
			wantCode: CheckSMIMEKeyUsage,
		},
		{
			name:     "certSign bit rejected by smime set",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign },
			wantCode: CheckSMIMEKeyUsage,
		},
		{
			name:   "signing variant clean",
			policy: smimePolicy("", SMIMEVariantSign),
			mutate: func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
			},
		},
		{
			name:     "signing variant with keyEncipherment rejected",
			policy:   smimePolicy("", SMIMEVariantSign),
			mutate:   func(c *x509.Certificate) {},
			wantCode: CheckSMIMEKeyUsage,
		},
		{
			name:   "encryption variant clean",
			policy: smimePolicy("", SMIMEVariantEncrypt),
			mutate: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment },
		},
		{
			name:     "encryption variant with digitalSignature rejected",
			policy:   smimePolicy("", SMIMEVariantEncrypt),
			mutate:   func(c *x509.Certificate) {},
			wantCode: CheckSMIMEKeyUsage,
		},
		{
			name:     "dual variant without key management rejected",
			policy:   smimePolicy("", SMIMEVariantDual),
			mutate:   func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
			wantCode: CheckSMIMEKeyUsage,
		},
		{
			name:   "RSA key with keyAgreement rejected",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.PublicKey = &rsaKey.PublicKey
				c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
			},
			wantCode: CheckSMIMEKeyUsage,
		},
		{
			name:   "EC key with keyEncipherment rejected",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.PublicKey = &ecKey.PublicKey
			},
			wantCode: CheckSMIMEKeyUsage,
		},
		{
			name:   "EC key with keyAgreement clean",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.PublicKey = &ecKey.PublicKey
				c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
			},
		},
		{
			name:   "subject emailAddress matching SAN passes",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{
					Type:  oidEmailAddress,
					Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("alice@example.com")},
				}}
			},
		},
		{
			name:   "subject emailAddress not in SAN rejected",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) {
				c.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{
					Type:  oidEmailAddress,
					Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("mallory@example.com")},
				}}
			},
			wantCode: CheckSMIMESubjectEmail,
		},
		{
			name:   "mailbox-shaped CN in SAN passes",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) { c.Subject.CommonName = "Alice@example.com" },
		},
		{
			name:     "mailbox-shaped CN not in SAN rejected",
			policy:   smimePolicy("", ""),
			mutate:   func(c *x509.Certificate) { c.Subject.CommonName = "mallory@example.com" },
			wantCode: CheckSMIMESubjectEmail,
		},
		{
			name:   "personal-name CN passes",
			policy: smimePolicy("", ""),
			mutate: func(c *x509.Certificate) { c.Subject.CommonName = "Alice Q. Example" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := baseSMIMECert(t)
			tc.mutate(cert)
			res := Lint(cert, tc.policy)

			if tc.wantCode == "" {
				if !res.OK() {
					t.Fatalf("expected clean pass, got findings: %v", res.Summary())
				}
				return
			}
			if !hasCode(res, tc.wantCode) {
				t.Fatalf("expected finding %q, got: %v", tc.wantCode, res.Summary())
			}
		})
	}
}

// TestSMIMEWarnOverride verifies the per-check enforce/warn gating applies to
// the S/MIME rule set exactly as it does to the baseline checks.
func TestSMIMEWarnOverride(t *testing.T) {
	cert := baseSMIMECert(t)
	cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	pol := smimePolicy("", "")
	if res := Lint(cert, pol); !res.HasErrors() {
		t.Fatalf("serverAuth mixing should block under enforce: %v", res.Summary())
	}

	pol.Overrides = map[string]Mode{CheckSMIMEEKU: ModeWarn}
	res := Lint(cert, pol)
	if res.HasErrors() {
		t.Fatalf("warn override should not block: %v", res.Summary())
	}
	if len(res.Warnings()) == 0 {
		t.Fatal("warn override should still report the finding")
	}
}
