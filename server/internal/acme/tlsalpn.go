package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// acmeTLS1ALPN is the ALPN protocol identifier a tls-alpn-01 validation TLS
// handshake must negotiate (RFC 8737 §3).
const acmeTLS1ALPN = "acme-tls/1"

// idPEACMEIdentifier is the id-pe-acmeIdentifier extension OID (RFC 8737 §3,
// { id-pe 31 }). A tls-alpn-01 validation certificate MUST carry this extension,
// marked critical, whose value is an OCTET STRING holding SHA-256(keyAuth).
var idPEACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ValidateTLSALPN01 performs a tls-alpn-01 challenge check (RFC 8737). It opens a
// TLS connection to the identifier on the ACME TLS ALPN port (443), offering only
// the "acme-tls/1" ALPN protocol, and requires the peer to:
//
//   - negotiate the "acme-tls/1" protocol,
//   - present exactly one self-signed certificate whose single subjectAltName is
//     the identifier under validation, and
//   - carry a critical id-pe-acmeIdentifier extension whose OCTET STRING value
//     equals SHA-256(keyAuthorization).
//
// The check performs no HSM operation. It returns nil on success or an ACME
// Problem describing the failure.
func (v *Validator) ValidateTLSALPN01(ctx context.Context, identifier, keyAuth string) *Problem {
	port := v.TLSALPNPort
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort(identifier, strconv.Itoa(port))

	dial := v.TLSDialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	rawConn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return newProblem(probConnection, http.StatusBadRequest,
			fmt.Sprintf("dialing tls-alpn-01 challenge at %s: %v", addr, err))
	}
	defer rawConn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	tlsCfg := &tls.Config{
		// The validation certificate is self-signed and validated by hand against
		// RFC 8737 below, so the usual PKI chain verification does not apply.
		InsecureSkipVerify: true, //nolint:gosec // RFC 8737 self-signed cert; verified manually
		NextProtos:         []string{acmeTLS1ALPN},
		MinVersion:         tls.VersionTLS12,
	}
	// SNI carries the DNS identifier so a multi-tenant responder can select the
	// right validation certificate. IP identifiers (RFC 8738) omit SNI because it
	// cannot carry an IP literal (RFC 6066 §3).
	if net.ParseIP(identifier) == nil {
		tlsCfg.ServerName = identifier
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return newProblem(probTLS, http.StatusBadRequest,
			fmt.Sprintf("tls-alpn-01 handshake with %s failed: %v", addr, err))
	}
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != acmeTLS1ALPN {
		return newProblem(probTLS, http.StatusForbidden,
			fmt.Sprintf("tls-alpn-01 server did not negotiate the %q ALPN protocol (got %q)",
				acmeTLS1ALPN, state.NegotiatedProtocol))
	}
	if len(state.PeerCertificates) != 1 {
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			fmt.Sprintf("tls-alpn-01 server presented %d certificates, want exactly one self-signed certificate",
				len(state.PeerCertificates)))
	}
	return verifyTLSALPN01Cert(state.PeerCertificates[0], identifier, keyAuth)
}

// verifyTLSALPN01Cert applies the RFC 8737 §3 acceptance rules to the certificate
// presented over an "acme-tls/1" handshake: it must be self-signed, name exactly
// the identifier in its subjectAltName, and carry the critical id-pe-acmeIdentifier
// extension committing to SHA-256(keyAuthorization).
func verifyTLSALPN01Cert(cert *x509.Certificate, identifier, keyAuth string) *Problem {
	// Self-signed: subject == issuer and the certificate verifies under its own
	// public key. CheckSignature avoids the CA basic-constraints requirement that
	// CheckSignatureFrom imposes, since a challenge certificate is not a CA.
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			"tls-alpn-01 validation certificate is not self-signed (subject != issuer)")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			"tls-alpn-01 validation certificate self-signature is invalid: "+err.Error())
	}

	if prob := checkTLSALPN01SAN(cert, identifier); prob != nil {
		return prob
	}

	// Locate the critical id-pe-acmeIdentifier extension.
	var ext *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(idPEACMEIdentifier) {
			ext = &cert.Extensions[i]
			break
		}
	}
	if ext == nil {
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			"tls-alpn-01 validation certificate is missing the id-pe-acmeIdentifier extension")
	}
	if !ext.Critical {
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			"tls-alpn-01 id-pe-acmeIdentifier extension must be marked critical")
	}

	// The extension value is an OCTET STRING wrapping the 32-byte digest.
	var got []byte
	rest, err := asn1.Unmarshal(ext.Value, &got)
	if err != nil || len(rest) != 0 {
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			"tls-alpn-01 id-pe-acmeIdentifier extension is not a valid OCTET STRING")
	}
	want := sha256.Sum256([]byte(keyAuth))
	if len(got) != len(want) || subtle.ConstantTimeCompare(got, want[:]) != 1 {
		return newProblem(probUnauthorized, http.StatusForbidden,
			"tls-alpn-01 id-pe-acmeIdentifier extension does not match the expected key authorization digest")
	}
	return nil
}

// checkTLSALPN01SAN enforces the RFC 8737 §3 requirement that the validation
// certificate's subjectAltName contains exactly one entry, matching the
// identifier under validation (a dNSName for DNS identifiers, an iPAddress for IP
// identifiers per RFC 8738 §5).
func checkTLSALPN01SAN(cert *x509.Certificate, identifier string) *Problem {
	total := len(cert.DNSNames) + len(cert.IPAddresses) + len(cert.EmailAddresses) + len(cert.URIs)
	if ip := net.ParseIP(identifier); ip != nil {
		if len(cert.IPAddresses) == 1 && total == 1 && cert.IPAddresses[0].Equal(ip) {
			return nil
		}
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			"tls-alpn-01 validation certificate subjectAltName must be exactly the IP address "+identifier)
	}
	if len(cert.DNSNames) == 1 && total == 1 && strings.EqualFold(cert.DNSNames[0], identifier) {
		return nil
	}
	return newProblem(probIncorrectResponse, http.StatusForbidden,
		"tls-alpn-01 validation certificate subjectAltName must be exactly the DNS name "+identifier)
}
