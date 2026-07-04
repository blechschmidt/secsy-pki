package brski

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// Body-size ceilings for the voucher exchange. Voucher requests and vouchers are
// small JSON+CMS documents; these guard the handlers against oversized bodies.
const (
	maxVoucherRequestBytes = 128 * 1024
	maxVoucherBytes        = 128 * 1024
	maxStatusBytes         = 64 * 1024
)

// deviceSerial derives the pledge serial-number from its IDevID (RFC 8995 §2.3.1).
// The X.520 serialNumber attribute of the subject DN is the primary source; when
// absent it falls back to the certificate serial number in hex, so a pledge whose
// birth certificate omits the RDN still gets a stable identifier.
func deviceSerial(idevid *x509.Certificate) string {
	if idevid == nil {
		return ""
	}
	if s := strings.TrimSpace(idevid.Subject.SerialNumber); s != "" {
		return s
	}
	return fmt.Sprintf("%X", idevid.SerialNumber)
}

// requireSameSerial fails when two serial-number values that must agree do not.
// An empty value on either side is tolerated (some artifacts omit a serial the
// caller has already validated elsewhere); only a present-and-different pair is
// an error, closing the substitution corner where a registrar requests a voucher
// for a device other than the one that signed the pledge request.
func requireSameSerial(aLabel, a, bLabel, b string) error {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return nil
	}
	if a != b {
		return fmt.Errorf("serial-number mismatch: %s=%q but %s=%q", aLabel, a, bLabel, b)
	}
	return nil
}

// verifyCertChain establishes that leaf chains to one of roots, using
// intermediates for path building. It mirrors the attestation gate's trust model
// (ExtKeyUsageAny — an IDevID carries no predictable EKU, so trust is established
// purely by chaining to a configured manufacturer root, the operator's explicit
// trust decision).
func verifyCertChain(roots *x509.CertPool, intermediates []*x509.Certificate, leaf *x509.Certificate, now time.Time) error {
	if roots == nil || len(roots.Subjects()) == 0 { //nolint:staticcheck // Subjects() is fine for the emptiness check.
		return errors.New("no trusted manufacturer roots configured")
	}
	if leaf == nil {
		return errors.New("no certificate to verify")
	}
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		if c != nil && !bytes.Equal(c.Raw, leaf.Raw) {
			inter.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("chain does not reach a trusted manufacturer root: %w", err)
	}
	return nil
}

// publicKeyMatchesCert reports whether pub is the public key certified by cert,
// by comparing PKIX (SubjectPublicKeyInfo) encodings across key types.
func publicKeyMatchesCert(pub crypto.PublicKey, cert *x509.Certificate) bool {
	if pub == nil || cert == nil {
		return false
	}
	a, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return false
	}
	b, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(a, b)
}

// certEqual reports whether two DER certificate encodings are byte-identical.
func certEqual(a, b []byte) bool { return bytes.Equal(a, b) }

// bytesEqual reports whether two byte slices are equal (nonce comparison).
func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }

// parseVoucherContent parses a CMS-signed voucher and returns its encapsulated
// JSON content WITHOUT verifying the signature. It is used by the registrar to
// inspect a MASA voucher it relays but whose signature it is not required (and
// may lack the anchor) to verify — the pledge performs the authoritative
// verification with its pre-installed MASA trust anchor.
func parseVoucherContent(der []byte) ([]byte, error) {
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, err
	}
	if len(sd.Content) == 0 {
		return nil, errors.New("brski: voucher carries no encapsulated content")
	}
	return sd.Content, nil
}

// normalizeBasePath cleans a configured base path to a leading-slash, no-trailing-
// slash form, defaulting to /.well-known/brski (RFC 8995 §5).
func normalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/.well-known/brski"
	}
	return "/" + strings.Trim(p, "/")
}
