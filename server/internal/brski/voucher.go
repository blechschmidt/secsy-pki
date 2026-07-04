// Package brski implements the registrar (Join Registrar/Coordinator, JRC) side
// of BRSKI — Bootstrapping Remote Secure Key Infrastructure, RFC 8995 — layered
// on top of the existing EST enrollment (Task 22) and hardware-attestation trust
// anchors (Task 49) to give IoT / network devices zero-touch onboarding.
//
// The three actors of BRSKI are:
//
//   - Pledge: the new device. It ships with a manufacturer-installed IDevID (an
//     IEEE 802.1AR birth certificate) and a pre-installed MASA trust anchor.
//   - Registrar (this package): the domain's onboarding server. It validates the
//     pledge's IDevID against the trusted manufacturer roots, relays a voucher
//     request to the MASA, returns the signed voucher, and then hands the pledge
//     off to EST simpleenroll for the actual (HSM-backed) LDevID issuance.
//   - MASA (Manufacturer Authorized Signing Authority): issues the RFC 8366
//     voucher that tells the pledge which domain now owns it. A pluggable client
//     (external HTTPS or the minimal built-in Service in masa.go) fronts it.
//
// Vouchers and voucher-requests are RFC 8366 YANG-modeled JSON documents wrapped
// in a CMS SignedData (media type application/voucher-cms+json), built and
// verified through the shared internal/cms layer so every signature — pledge,
// registrar, and MASA — flows through a crypto.Signer and no private key is
// exported. The domain CA that ultimately signs the pledge's LDevID stays on its
// HSM via the EST handoff.
package brski

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// Media types (RFC 8995 §5). Voucher and voucher-request artifacts are CMS-signed
// JSON; the status-telemetry endpoints exchange plain JSON.
const (
	MediaTypeVoucherCMS = "application/voucher-cms+json"
	MediaTypeJSON       = "application/json"
)

// JSON top-level wrapper keys (RFC 8366 §5.3 / RFC 8995 §3.3). A voucher and a
// voucher-request share almost all fields but are distinguished on the wire by
// their YANG module namespace, encoded as the single top-level object key.
const (
	voucherWrapperKey        = "ietf-voucher:voucher"
	voucherRequestWrapperKey = "ietf-voucher-request:voucher"
)

// Assertion values (RFC 8366 §5.3 "assertion"). The pledge asserts "proximity"
// (it pinned the registrar cert of the TLS connection it is on); the MASA sets
// "verified" or "logged" according to how it established ownership.
const (
	AssertionVerified  = "verified"
	AssertionLogged    = "logged"
	AssertionProximity = "proximity"
)

// Voucher is the union of the RFC 8366 voucher and the RFC 8995 voucher-request
// content. Which fields are populated depends on the artifact: a pledge/registrar
// voucher-request carries proximity-registrar-cert / prior-signed-voucher-request,
// while a MASA-issued voucher carries pinned-domain-cert. Binary fields are Go
// []byte, which encoding/json renders as standard (padded) base64 exactly as
// RFC 8366 requires; omitempty drops the fields that do not apply to an artifact.
type Voucher struct {
	// CreatedOn is when the artifact was assembled (RFC 3339). Always present.
	CreatedOn time.Time `json:"created-on"`
	// ExpiresOn bounds a nonceless voucher's validity (mutually exclusive with
	// Nonce). Nil for a nonceful voucher or a voucher-request.
	ExpiresOn *time.Time `json:"expires-on,omitempty"`
	// Assertion is the ownership-assertion level (see the Assertion* constants).
	Assertion string `json:"assertion,omitempty"`
	// SerialNumber is the pledge's serial (from its IDevID). Required throughout.
	SerialNumber string `json:"serial-number"`
	// IDevIDIssuer is the Authority Key Identifier of the pledge's IDevID, letting
	// the MASA disambiguate the signing CA (RFC 8995 §5.5). Registrar-request and
	// voucher only.
	IDevIDIssuer []byte `json:"idevid-issuer,omitempty"`
	// PinnedDomainCert is the domain certificate the pledge must pin as its new
	// trust anchor — the registrar cert of the connection it bootstrapped over.
	// Voucher only.
	PinnedDomainCert []byte `json:"pinned-domain-cert,omitempty"`
	// DomainCertRevocationChecks asks the pledge to CRL/OCSP-check the domain
	// chain. Optional; nil means the RFC 8366 default (false).
	DomainCertRevocationChecks *bool `json:"domain-cert-revocation-checks,omitempty"`
	// Nonce ties a voucher to a specific live voucher-request, preventing replay.
	// Present on a nonceful voucher-request and echoed on the voucher.
	Nonce []byte `json:"nonce,omitempty"`
	// LastRenewalDate is the latest a nonceless voucher may be relied upon.
	LastRenewalDate *time.Time `json:"last-renewal-date,omitempty"`

	// --- voucher-request-only fields (RFC 8995 §3) ---

	// ProximityRegistrarCert is the registrar TLS certificate the pledge pinned
	// from its provisional connection, asserting proximity. Pledge-request only.
	ProximityRegistrarCert []byte `json:"proximity-registrar-cert,omitempty"`
	// PriorSignedVoucherRequest is the pledge's entire signed voucher-request
	// (CMS), embedded verbatim by the registrar so the MASA can validate the
	// pledge's own assertion. Registrar-request only.
	PriorSignedVoucherRequest []byte `json:"prior-signed-voucher-request,omitempty"`
}

// MarshalVoucher serializes v as a MASA voucher (ietf-voucher:voucher wrapper).
func MarshalVoucher(v *Voucher) ([]byte, error) { return marshalWrapped(voucherWrapperKey, v) }

// MarshalVoucherRequest serializes v as a voucher-request
// (ietf-voucher-request:voucher wrapper), used for both the pledge and registrar
// requests.
func MarshalVoucherRequest(v *Voucher) ([]byte, error) {
	return marshalWrapped(voucherRequestWrapperKey, v)
}

// ParseVoucher decodes a MASA voucher JSON document.
func ParseVoucher(data []byte) (*Voucher, error) { return unmarshalWrapped(voucherWrapperKey, data) }

// ParseVoucherRequest decodes a voucher-request JSON document.
func ParseVoucherRequest(data []byte) (*Voucher, error) {
	return unmarshalWrapped(voucherRequestWrapperKey, data)
}

func marshalWrapped(key string, v *Voucher) ([]byte, error) {
	if v == nil {
		return nil, errors.New("brski: nil voucher")
	}
	inner, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("brski: marshaling voucher content: %w", err)
	}
	return json.Marshal(map[string]json.RawMessage{key: inner})
}

func unmarshalWrapped(key string, data []byte) (*Voucher, error) {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("brski: parsing voucher wrapper: %w", err)
	}
	raw, ok := wrapper[key]
	if !ok {
		return nil, fmt.Errorf("brski: voucher document missing %q top-level key", key)
	}
	var v Voucher
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("brski: parsing voucher content: %w", err)
	}
	return &v, nil
}

// signVoucherCMS wraps a voucher/voucher-request JSON document in a CMS SignedData
// signed by signer (holding the key for cert). The signer certificate and any
// chain are embedded so the verifier can recover the signer. The eContentType is
// left at the CMS default (id-data): RFC 8995 does not register a JSON-voucher
// content type, and both endpoints of every hop are under our control.
func signVoucherCMS(content []byte, signer crypto.Signer, cert *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	certs := []*x509.Certificate{cert}
	certs = append(certs, chain...)
	return cms.BuildSignedData(cms.SignedDataOpts{
		Content:      content,
		SignerCert:   cert,
		Signer:       signer,
		Certificates: certs,
	})
}

// parseSignedVoucherCMS parses a CMS-signed voucher artifact, verifies the CMS
// signature against its embedded signer certificate, and returns the parsed
// message plus the encapsulated JSON content. It establishes that the artifact
// was signed by the key of the embedded certificate; the caller decides whether
// to trust that certificate (chain to a manufacturer root, match the registrar
// identity, etc.).
func parseSignedVoucherCMS(der []byte) (*cms.ParsedSignedData, []byte, error) {
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, nil, err
	}
	if err := sd.Verify(); err != nil {
		return nil, nil, fmt.Errorf("brski: voucher CMS signature invalid: %w", err)
	}
	if len(sd.Content) == 0 {
		return nil, nil, errors.New("brski: voucher CMS carries no encapsulated content")
	}
	return sd, sd.Content, nil
}
