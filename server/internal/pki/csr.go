package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

// CACSRRequest describes a PKCS#10 certificate signing request for a
// certificate-authority key, to be signed by an external parent (an offline
// corporate root or a third-party bridge CA).
type CACSRRequest struct {
	// Subject is the distinguished name requested for the CA.
	Subject pkix.Name
	// RawSubject, when non-nil, embeds this exact DER-encoded distinguished name
	// instead of Subject — used to re-emit a CSR for a key whose certificate
	// already exists (external renewal) without re-encoding the DN.
	RawSubject []byte
	// MaxPathLen requests a basic-constraints path-length constraint. A nil
	// value leaves the path length unconstrained; 0 requests a CA that may only
	// issue end-entity certificates. The external parent may override this in
	// the certificate it actually issues.
	MaxPathLen *int
}

var (
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// basicConstraints mirrors the RFC 5280 BasicConstraints ASN.1 structure as
// crypto/x509 encodes it (cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER
// OPTIONAL).
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// CreateCACSR builds and signs a PKCS#10 certificate signing request for a CA
// key. The request carries the CA's intended extensions in its extensionRequest
// attribute — basicConstraints cA=TRUE (with the optional path-length
// constraint) and keyUsage keyCertSign|cRLSign|digitalSignature, both critical,
// matching the extensions CreateCACertificate emits — so an external parent
// signing the CSR verbatim produces a certificate our issuance stack accepts.
//
// signer must be the CA's own key (for an HSM-backed provider the private key
// never leaves the device). The returned bytes are the DER encoding of the CSR.
func CreateCACSR(signer crypto.Signer, req CACSRRequest) ([]byte, error) {
	if err := fips.CheckPublicKey(signer.Public()); err != nil {
		return nil, err
	}

	bcExt, err := marshalBasicConstraints(req.MaxPathLen)
	if err != nil {
		return nil, err
	}
	kuExt, err := marshalKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature)
	if err != nil {
		return nil, err
	}

	template := &x509.CertificateRequest{
		Subject: req.Subject,
		// crypto/x509 places ExtraExtensions inside the CSR's extensionRequest
		// attribute (1.2.840.113549.1.9.14), which is where RFC 2986 puts
		// requested certificate extensions.
		ExtraExtensions: []pkix.Extension{bcExt, kuExt},
	}
	if len(req.RawSubject) > 0 {
		template.RawSubject = req.RawSubject
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("creating CA CSR: %w", err)
	}
	return der, nil
}

// EncodeCSRPEM wraps a DER certificate signing request in a PEM block.
func EncodeCSRPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// ParseCSRPEM decodes a PEM-encoded PKCS#10 certificate signing request and
// verifies its self-signature (proof of possession of the private key).
func ParseCSRPEM(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM: expected CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	return csr, nil
}

// marshalBasicConstraints encodes a critical cA=TRUE basic-constraints
// extension with the optional path-length constraint.
func marshalBasicConstraints(maxPathLen *int) (pkix.Extension, error) {
	bc := basicConstraints{IsCA: true, MaxPathLen: -1}
	if maxPathLen != nil {
		if *maxPathLen < 0 {
			return pkix.Extension{}, fmt.Errorf("path-length constraint must be >= 0, got %d", *maxPathLen)
		}
		bc.MaxPathLen = *maxPathLen
	}
	val, err := asn1.Marshal(bc)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding basic constraints: %w", err)
	}
	return pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true, Value: val}, nil
}

// KeyUsageBitString encodes an x509.KeyUsage bitmask as the DER BIT STRING that
// forms the value of the keyUsage extension (2.5.29.15). X.509 key-usage bits
// are numbered from the most significant bit of the BIT STRING, so the
// x509.KeyUsage bitmask (bit 0 = digitalSignature) is bit-reversed per byte, and
// trailing zero bits are trimmed from the BIT STRING length as DER requires. It
// is exported so protocol layers (e.g. the EST /csrattrs advertisement) can
// encode the exact keyUsage value a profile mandates without duplicating this
// bit-ordering logic.
func KeyUsageBitString(ku x509.KeyUsage) ([]byte, error) {
	buf := [2]byte{reverseBits(byte(ku)), reverseBits(byte(ku >> 8))}
	octets := 1
	if buf[1] != 0 {
		octets = 2
	}
	bits := octets * 8
	for bits > 0 && buf[(bits-1)/8]&(1<<(7-(bits-1)%8)) == 0 {
		bits--
	}
	return asn1.Marshal(asn1.BitString{Bytes: buf[:octets], BitLength: bits})
}

// marshalKeyUsage encodes a critical keyUsage extension.
func marshalKeyUsage(ku x509.KeyUsage) (pkix.Extension, error) {
	val, err := KeyUsageBitString(ku)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding key usage: %w", err)
	}
	return pkix.Extension{Id: oidExtensionKeyUsage, Critical: true, Value: val}, nil
}

// reverseBits mirrors the bit order within a byte (bit 0 <-> bit 7).
func reverseBits(b byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		if b&(1<<i) != 0 {
			out |= 1 << (7 - i)
		}
	}
	return out
}
