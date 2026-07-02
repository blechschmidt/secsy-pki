package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CACertRequest describes the certificate to build for a certificate authority.
// The same struct is used for self-signed roots and for intermediates signed by
// a parent CA; which one is produced depends on the parent argument to
// CreateCACertificate.
type CACertRequest struct {
	// Subject is the distinguished name of the CA being created.
	Subject pkix.Name
	// PublicKey is the public key of the CA being created (the subject key).
	PublicKey crypto.PublicKey
	// Serial is the certificate serial number. It must be positive and unique
	// within the issuing CA.
	Serial *big.Int
	// NotBefore / NotAfter bound the certificate validity.
	NotBefore time.Time
	NotAfter  time.Time
	// MaxPathLen constrains the number of intermediate CAs that may appear below
	// this one. A nil value leaves the path length unconstrained. A value of 0
	// means this CA may only issue end-entity certificates.
	MaxPathLen *int
}

// CreateCACertificate builds and signs an X.509 CA certificate.
//
// When parent is nil the certificate is self-signed (a root CA): signer must be
// the CA's own key, corresponding to req.PublicKey. When parent is non-nil the
// certificate is an intermediate: parent is the issuing CA's certificate and
// signer is the issuing CA's key. In both cases the signing operation is
// performed by signer, which for an HSM-backed provider means the private key
// never leaves the device.
//
// The returned bytes are the DER encoding of the certificate.
func CreateCACertificate(signer crypto.Signer, parent *x509.Certificate, req CACertRequest) ([]byte, error) {
	if req.Serial == nil || req.Serial.Sign() <= 0 {
		return nil, fmt.Errorf("CA certificate serial must be a positive integer")
	}
	if req.PublicKey == nil {
		return nil, fmt.Errorf("CA certificate requires a subject public key")
	}
	if !req.NotAfter.After(req.NotBefore) {
		return nil, fmt.Errorf("CA certificate not_after (%s) must be after not_before (%s)", req.NotAfter, req.NotBefore)
	}

	template := &x509.Certificate{
		SerialNumber: req.Serial,
		Subject:      req.Subject,
		NotBefore:    req.NotBefore,
		NotAfter:     req.NotAfter,
		// A CA key signs subordinate certificates and CRLs. DigitalSignature is
		// included so the same key can also sign OCSP responses.
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if req.MaxPathLen != nil {
		template.MaxPathLen = *req.MaxPathLen
		// MaxPathLenZero disambiguates "path length 0" from "unset" in Go's
		// x509 encoder; it must be set explicitly when the constraint is 0.
		template.MaxPathLenZero = *req.MaxPathLen == 0
	}

	// For a self-signed root the issuer template is the certificate itself.
	issuer := parent
	if issuer == nil {
		issuer = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, req.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}
	return der, nil
}

// EncodeCertificatePEM wraps a DER certificate in a PEM block.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ParseCertificatePEM decodes a PEM-encoded X.509 certificate.
func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM: expected CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

// ParseCertificateChainPEM decodes every CERTIFICATE block in a PEM bundle, in
// order. Non-CERTIFICATE blocks are ignored so a bundle with interleaved
// comments or keys still parses. It errors only when a CERTIFICATE block fails
// to decode as DER (a malformed chain), returning an empty slice for input with
// no certificates.
func ParseCertificateChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate in chain: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}
