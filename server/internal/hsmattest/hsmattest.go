// Package hsmattest obtains and verifies YubiHSM key attestations (Task 168).
//
// A YubiHSM can sign an X.509 certificate over the public key of an asymmetric
// object it holds, using a factory-provisioned attestation key whose own
// certificate chains to Yubico's attestation PKI. The Yubico extensions in that
// certificate carry the device's assertions about the object: its on-device
// handle and label, the domains it lives in, how it came to exist, and the
// exact set of capabilities it holds.
//
// The point of the exercise is that these assertions come from the hardware,
// not from the CA operator. "This CA key was generated inside the HSM and has
// no capability that would let it be exported" is a claim a relying party can
// check for itself, given the attestation and Yubico's root — which is the
// difference between a policy statement and a proof.
//
// This complements the audit-log work in internal/hsmaudit. That subsystem
// bounds what the HSM *did*: no signature exists beyond the published ones.
// This one bounds what the key *is*: the private material never left the
// device, so those published signatures are the only ones that can ever exist.
// Neither implies the other, and an operator wanting to say "our CA key cannot
// be misused" needs both.
package hsmattest

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// Attestation is a self-contained YubiHSM key attestation.
//
// It carries certificates rather than parsed conclusions so that a third party
// can re-derive every claim themselves. Claims is included for readability and
// is recomputed, not trusted, by Verify.
type Attestation struct {
	// KeyLabel is the label the attestation was requested for.
	KeyLabel string `json:"key_label,omitempty"`
	// CertificatePEM is the per-key attestation certificate the device signed.
	CertificatePEM string `json:"certificate_pem"`
	// DeviceCertificatePEM is the device's own attestation certificate, read
	// from opaque object 0x0000. It is the issuer of CertificatePEM and the
	// link between this key and Yubico's attestation PKI, so it travels with
	// the attestation — an auditor cannot read it off a device they do not have.
	DeviceCertificatePEM string `json:"device_certificate_pem,omitempty"`
	// Claims are the decoded device assertions. Informational: Verify re-parses
	// the certificate and ignores this field.
	Claims *Claims `json:"claims,omitempty"`
	// ProducedAt is when the attestation was obtained.
	ProducedAt time.Time `json:"produced_at"`
}

// Certificate parses the per-key attestation certificate.
func (a *Attestation) Certificate() (*x509.Certificate, error) {
	if a == nil || strings.TrimSpace(a.CertificatePEM) == "" {
		return nil, fmt.Errorf("hsmattest: attestation carries no certificate")
	}
	return parseCertPEM(a.CertificatePEM, "attestation certificate")
}

// DeviceCertificate parses the device attestation certificate, returning nil
// when the attestation does not carry one.
func (a *Attestation) DeviceCertificate() (*x509.Certificate, error) {
	if a == nil || strings.TrimSpace(a.DeviceCertificatePEM) == "" {
		return nil, nil
	}
	return parseCertPEM(a.DeviceCertificatePEM, "device attestation certificate")
}

func parseCertPEM(s, what string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("hsmattest: %s is not valid PEM", what)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("hsmattest: %s has PEM type %q, want CERTIFICATE", what, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hsmattest: parsing %s: %w", what, err)
	}
	return cert, nil
}

// Attester produces key attestations. It is an interface so that the REST,
// CLI and test paths share one implementation of the surrounding logic while
// the hardware-dependent half can be replaced by a fixture.
type Attester interface {
	// AttestKey attests the asymmetric key with the given label.
	AttestKey(ctx context.Context, label string) (*Attestation, error)
}

// ShellAttester is the production Attester, driven through yubihsm-shell.
//
// It uses the shell rather than PKCS#11 because attestation is a YubiHSM
// vendor command with no PKCS#11 equivalent — the installed yubihsm_pkcs11
// module exposes no attestation mechanism — and because internal/hsmaudit
// already reaches the device this way.
type ShellAttester struct {
	Cfg hsm.Config
	// AttestKeyID selects the attesting key; 0 (the default) selects the
	// factory-provisioned one.
	AttestKeyID uint16
}

// NewShellAttester returns an Attester backed by the yubihsm-shell binary.
func NewShellAttester(cfg hsm.Config) *ShellAttester { return &ShellAttester{Cfg: cfg} }

// AttestKey resolves label to an on-device object and attests it.
func (s *ShellAttester) AttestKey(ctx context.Context, label string) (*Attestation, error) {
	if strings.TrimSpace(label) == "" {
		return nil, fmt.Errorf("hsmattest: key label is required")
	}
	objectID, err := hsm.FindAsymmetricKey(s.Cfg, label)
	if err != nil {
		return nil, err
	}
	return s.attest(ctx, label, objectID)
}

// AttestObject attests the asymmetric key with the given on-device object ID,
// for callers that hold the handle rather than a label — on a YubiHSM the
// PKCS#11 CKA_ID is that handle.
func (s *ShellAttester) AttestObject(ctx context.Context, objectID uint16) (*Attestation, error) {
	return s.attest(ctx, "", objectID)
}

func (s *ShellAttester) attest(ctx context.Context, label string, objectID uint16) (*Attestation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	certPEM, err := hsm.AttestAsymmetricKey(s.Cfg, objectID, s.AttestKeyID)
	if err != nil {
		return nil, err
	}

	att := &Attestation{
		KeyLabel:       label,
		CertificatePEM: certPEM,
		ProducedAt:     time.Now().UTC(),
	}

	// The device attestation certificate is what lets the attestation be
	// checked away from the device, so a failure to read it degrades the
	// attestation rather than invalidating it: the per-key certificate is still
	// the device's signed statement, and Verify reports precisely which of the
	// two links it could establish.
	if der, err := hsm.GetDeviceAttestation(s.Cfg); err == nil && len(der) > 0 {
		att.DeviceCertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	cert, err := att.Certificate()
	if err != nil {
		return nil, err
	}
	claims, err := ParseClaims(cert)
	if err != nil {
		return nil, err
	}
	att.Claims = claims
	if att.KeyLabel == "" {
		att.KeyLabel = claims.Label
	}
	return att, nil
}
