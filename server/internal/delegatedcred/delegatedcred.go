// Package delegatedcred implements RFC 9345 Delegated Credentials for TLS.
//
// A delegated credential (DC) is a short-lived, CA-independent credential that a
// TLS 1.3 end-entity certificate can authorize its key to sign. It lets an
// operator hand a front end (load balancer, edge node) a credential valid for at
// most seven days without ever giving that front end the long-lived certificate
// private key: the DC binds a fresh public key and an expiry, signed by the
// end-entity key, and the peer accepts it because the end-entity certificate is
// marked eligible with the RFC 9345 DelegationUsage extension (see
// internal/pki.DelegationUsageExtension).
//
// # The operator holds the leaf key
//
// Minting a DC requires the end-entity certificate's PRIVATE key, because the DC
// is signed by it. This CA never holds subscriber leaf keys for ordinary CSR-
// based issuance — only the subscriber does. The system can supply the leaf key
// for a DC only when it generated that key server-side: the PKCS#12 export path
// (Task 80), optionally with the key escrowed under the M-of-N recovery policy
// (Task 33), from which it can be recovered by a quorum. In every case a human or
// a recovery quorum must present the leaf key; the HSM-held CA key plays no part
// in signing a DC. Mint therefore takes a crypto.Signer for the leaf key and does
// no HSM or database work.
package delegatedcred

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"golang.org/x/crypto/cryptobyte"
)

// MaxValidTime is the RFC 9345 §4.1.3 upper bound on a delegated credential's
// validity: seven days, measured from the associated certificate's notBefore.
const MaxValidTime = 7 * 24 * time.Hour

// context strings signed into a delegated credential, distinguishing the two
// endpoint roles so a server DC cannot be replayed as a client DC or vice versa
// (RFC 9345 §4.1.3).
const (
	serverContext = "TLS, server delegated credentials"
	clientContext = "TLS, client delegated credentials"
)

// Endpoint selects whether a delegated credential authenticates a server or a
// client, which changes the signed context string. The zero value is a server DC
// (the overwhelmingly common case).
type Endpoint int

const (
	// ServerEndpoint is a server-side delegated credential (the default).
	ServerEndpoint Endpoint = iota
	// ClientEndpoint is a client-side delegated credential (RFC 9345 §5).
	ClientEndpoint
)

func (e Endpoint) contextString() string {
	if e == ClientEndpoint {
		return clientContext
	}
	return serverContext
}

// Credential is the RFC 9345 Credential structure: the delegated public key, the
// scheme it will use in the handshake, and its validity relative to the
// certificate notBefore.
//
//	struct {
//	  uint32 valid_time;
//	  SignatureScheme expected_cert_verify_algorithm;
//	  opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
//	} Credential;
type Credential struct {
	// ValidTime is the credential lifetime in seconds, measured from the
	// associated certificate's notBefore. RFC 9345 caps it at MaxValidTime.
	ValidTime uint32
	// ExpectedCertVerifyAlgorithm is the TLS scheme the delegated key uses in the
	// handshake CertificateVerify.
	ExpectedCertVerifyAlgorithm SignatureScheme
	// SubjectPublicKeyInfo is the DER SubjectPublicKeyInfo of the delegated key.
	SubjectPublicKeyInfo []byte
}

// DelegatedCredential is the RFC 9345 DelegatedCredential structure: a Credential
// plus the end-entity signature over it.
//
//	struct {
//	  Credential cred;
//	  SignatureScheme algorithm;
//	  opaque signature<0..2^16-1>;
//	} DelegatedCredential;
type DelegatedCredential struct {
	Cred Credential
	// Algorithm is the scheme used to sign the credential with the end-entity key.
	Algorithm SignatureScheme
	Signature []byte
}

// marshal serializes a Credential to its RFC 9345 wire encoding.
func (c Credential) marshal() ([]byte, error) {
	if n := len(c.SubjectPublicKeyInfo); n == 0 || n > (1<<24)-1 {
		return nil, fmt.Errorf("delegatedcred: SubjectPublicKeyInfo length %d out of range [1, 2^24-1]", n)
	}
	var b cryptobyte.Builder
	b.AddUint32(c.ValidTime)
	b.AddUint16(uint16(c.ExpectedCertVerifyAlgorithm))
	b.AddUint24LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(c.SubjectPublicKeyInfo)
	})
	return b.Bytes()
}

// Marshal serializes a DelegatedCredential to its RFC 9345 wire encoding — the
// form deployed into a TLS terminator alongside the delegated private key.
func (dc *DelegatedCredential) Marshal() ([]byte, error) {
	credBytes, err := dc.Cred.marshal()
	if err != nil {
		return nil, err
	}
	if len(dc.Signature) > (1<<16)-1 {
		return nil, fmt.Errorf("delegatedcred: signature length %d exceeds 2^16-1", len(dc.Signature))
	}
	var b cryptobyte.Builder
	b.AddBytes(credBytes)
	b.AddUint16(uint16(dc.Algorithm))
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(dc.Signature)
	})
	return b.Bytes()
}

// Parse decodes a DelegatedCredential from its RFC 9345 wire encoding.
func Parse(data []byte) (*DelegatedCredential, error) {
	s := cryptobyte.String(data)
	var (
		validTime uint32
		scheme    uint16
		spki      cryptobyte.String
	)
	if !s.ReadUint32(&validTime) || !s.ReadUint16(&scheme) || !s.ReadUint24LengthPrefixed(&spki) {
		return nil, errors.New("delegatedcred: malformed credential")
	}
	if len(spki) == 0 {
		return nil, errors.New("delegatedcred: empty SubjectPublicKeyInfo")
	}
	var (
		algorithm uint16
		sig       cryptobyte.String
	)
	if !s.ReadUint16(&algorithm) || !s.ReadUint16LengthPrefixed(&sig) {
		return nil, errors.New("delegatedcred: malformed delegated credential")
	}
	if !s.Empty() {
		return nil, errors.New("delegatedcred: trailing data after delegated credential")
	}
	return &DelegatedCredential{
		Cred: Credential{
			ValidTime:                   validTime,
			ExpectedCertVerifyAlgorithm: SignatureScheme(scheme),
			SubjectPublicKeyInfo:        append([]byte(nil), spki...),
		},
		Algorithm: SignatureScheme(algorithm),
		Signature: append([]byte(nil), sig...),
	}, nil
}

// sigMessage builds the RFC 9345 §4.1.3 message signed by the end-entity key:
//
//	0x20 * 64 || context || 0x00 || DER(certificate) || cred || algorithm
func (dc *DelegatedCredential) sigMessage(leafCert *x509.Certificate, endpoint Endpoint) ([]byte, error) {
	credBytes, err := dc.Cred.marshal()
	if err != nil {
		return nil, err
	}
	return buildSigMessage(leafCert.Raw, credBytes, dc.Algorithm, endpoint), nil
}

func buildSigMessage(certDER, credBytes []byte, algorithm SignatureScheme, endpoint Endpoint) []byte {
	ctx := endpoint.contextString()
	msg := make([]byte, 0, 64+len(ctx)+1+len(certDER)+len(credBytes)+2)
	for i := 0; i < 64; i++ {
		msg = append(msg, 0x20)
	}
	msg = append(msg, ctx...)
	msg = append(msg, 0x00)
	msg = append(msg, certDER...)
	msg = append(msg, credBytes...)
	msg = append(msg, byte(algorithm>>8), byte(algorithm))
	return msg
}

// MintRequest describes a delegated credential to construct and sign.
type MintRequest struct {
	// LeafCert is the end-entity certificate whose key authorizes the credential.
	// It must carry the RFC 9345 DelegationUsage extension and the digitalSignature
	// key usage, or minting is refused (the resulting DC would be unusable).
	LeafCert *x509.Certificate
	// LeafKey is the end-entity private key. The operator holds it; this package
	// does no HSM work. Its public half must match LeafCert.
	LeafKey crypto.Signer
	// DCPublicKey is the delegated credential's public key. Its DER
	// SubjectPublicKeyInfo is bound into the credential.
	DCPublicKey crypto.PublicKey
	// ValidFor is how long the credential should remain usable, measured from Now.
	// Because the wire valid_time is anchored to the certificate notBefore, the
	// effective cap is MaxValidTime minus the certificate's current age: mint from
	// a freshly issued certificate.
	ValidFor time.Duration
	// Endpoint selects the server (default) or client context string.
	Endpoint Endpoint
	// ExpectedCertVerifyAlgorithm is the scheme the delegated key uses in the
	// handshake. Zero derives it from DCPublicKey.
	ExpectedCertVerifyAlgorithm SignatureScheme
	// Algorithm is the scheme used to sign the credential with the leaf key. Zero
	// derives it from LeafKey (RSA uses RSASSA-PSS per RFC 9345 §4.1.3).
	Algorithm SignatureScheme
	// Now overrides the current time (tests). Zero uses time.Now().
	Now time.Time
	// Rand overrides the entropy source (tests). Nil uses crypto/rand.Reader.
	Rand io.Reader
}

// MintResult is the outcome of minting a delegated credential.
type MintResult struct {
	// DelegatedCredential is the signed structure.
	DelegatedCredential *DelegatedCredential
	// Wire is the serialized RFC 9345 encoding, ready to deploy into a TLS
	// terminator alongside the delegated private key.
	Wire []byte
	// ValidTime is the credential's valid_time field (seconds from notBefore).
	ValidTime uint32
	// NotAfter is the credential's absolute expiry (notBefore + valid_time).
	NotAfter time.Time
	// Algorithm and ExpectedCertVerifyAlgorithm are the resolved schemes.
	Algorithm                   SignatureScheme
	ExpectedCertVerifyAlgorithm SignatureScheme
}

// Mint constructs and signs a delegated credential. The signature is produced by
// the end-entity certificate's private key (req.LeafKey), which the operator must
// hold; no HSM or CA key is involved.
func Mint(req MintRequest) (*MintResult, error) {
	if req.LeafCert == nil {
		return nil, errors.New("delegatedcred: nil end-entity certificate")
	}
	if req.LeafKey == nil {
		return nil, errors.New("delegatedcred: nil end-entity private key")
	}
	if req.DCPublicKey == nil {
		return nil, errors.New("delegatedcred: nil delegated public key")
	}
	if err := CheckEligible(req.LeafCert); err != nil {
		return nil, err
	}
	// The signing key must actually be the certificate's key, or the DC would not
	// verify against the presented certificate.
	if err := publicKeyMatches(req.LeafCert.PublicKey, req.LeafKey.Public()); err != nil {
		return nil, fmt.Errorf("delegatedcred: end-entity private key does not match the certificate: %w", err)
	}

	rnd := req.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Resolve the two signature schemes and refuse RSA PKCS#1 v1.5 implicitly (only
	// the PSS schemes are enumerated) per RFC 9345 §4.1.3.
	algorithm, err := SchemeForKey(req.LeafKey.Public(), req.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("delegatedcred: resolving signing algorithm: %w", err)
	}
	expected, err := SchemeForKey(req.DCPublicKey, req.ExpectedCertVerifyAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("delegatedcred: resolving delegated-key algorithm: %w", err)
	}

	// Marshal the delegated public key to DER SubjectPublicKeyInfo.
	spki, err := x509.MarshalPKIXPublicKey(req.DCPublicKey)
	if err != nil {
		return nil, fmt.Errorf("delegatedcred: encoding delegated public key: %w", err)
	}

	// Compute valid_time relative to the certificate notBefore and enforce the
	// 7-day maximum. A credential minted from a stale certificate would exceed the
	// cap; the error names the cause so the operator re-issues a fresh leaf.
	if req.ValidFor <= 0 {
		return nil, errors.New("delegatedcred: valid_for must be positive")
	}
	expiry := now.Add(req.ValidFor)
	validSpan := expiry.Sub(req.LeafCert.NotBefore)
	if validSpan <= 0 {
		return nil, errors.New("delegatedcred: credential would already be expired")
	}
	if validSpan > MaxValidTime {
		return nil, fmt.Errorf("delegatedcred: valid_time %s exceeds the RFC 9345 maximum of %s (certificate notBefore %s is too far in the past — mint from a fresher certificate)",
			validSpan.Round(time.Second), MaxValidTime, req.LeafCert.NotBefore.UTC().Format(time.RFC3339))
	}
	validTime := uint32(validSpan / time.Second)
	if validTime == 0 {
		return nil, errors.New("delegatedcred: valid_time rounds down to zero seconds")
	}

	dc := &DelegatedCredential{
		Cred: Credential{
			ValidTime:                   validTime,
			ExpectedCertVerifyAlgorithm: expected,
			SubjectPublicKeyInfo:        spki,
		},
		Algorithm: algorithm,
	}

	msg, err := dc.sigMessage(req.LeafCert, req.Endpoint)
	if err != nil {
		return nil, err
	}
	sig, err := signMessage(rnd, req.LeafKey, algorithm, msg)
	if err != nil {
		return nil, fmt.Errorf("delegatedcred: signing credential: %w", err)
	}
	dc.Signature = sig

	wire, err := dc.Marshal()
	if err != nil {
		return nil, err
	}
	return &MintResult{
		DelegatedCredential:         dc,
		Wire:                        wire,
		ValidTime:                   validTime,
		NotAfter:                    req.LeafCert.NotBefore.Add(time.Duration(validTime) * time.Second),
		Algorithm:                   algorithm,
		ExpectedCertVerifyAlgorithm: expected,
	}, nil
}

// Verify checks that a delegated credential is authorized by the given end-entity
// certificate: the certificate is eligible (DelegationUsage + digitalSignature),
// the credential's valid_time does not exceed the RFC 9345 maximum, and the
// end-entity key's signature over the credential is valid for the given endpoint
// role. It does not check the current wall-clock time against the window; use
// ValidAt for that.
func (dc *DelegatedCredential) Verify(leafCert *x509.Certificate, endpoint Endpoint) error {
	if leafCert == nil {
		return errors.New("delegatedcred: nil end-entity certificate")
	}
	if err := CheckEligible(leafCert); err != nil {
		return err
	}
	if time.Duration(dc.Cred.ValidTime)*time.Second > MaxValidTime {
		return fmt.Errorf("delegatedcred: valid_time %ds exceeds the RFC 9345 maximum of %s", dc.Cred.ValidTime, MaxValidTime)
	}
	if len(dc.SubjectPublicKeyInfo()) == 0 {
		return errors.New("delegatedcred: empty delegated public key")
	}
	msg, err := dc.sigMessage(leafCert, endpoint)
	if err != nil {
		return err
	}
	if err := verifyMessage(leafCert.PublicKey, dc.Algorithm, msg, dc.Signature); err != nil {
		return fmt.Errorf("delegatedcred: %w", err)
	}
	return nil
}

// ValidAt reports whether the credential is within its validity window at time t:
// t is at or after the certificate notBefore and at or before notBefore +
// valid_time (RFC 9345 §4.1.3).
func (dc *DelegatedCredential) ValidAt(leafCert *x509.Certificate, t time.Time) bool {
	if leafCert == nil {
		return false
	}
	notAfter := leafCert.NotBefore.Add(time.Duration(dc.Cred.ValidTime) * time.Second)
	return !t.Before(leafCert.NotBefore) && !t.After(notAfter)
}

// SubjectPublicKeyInfo returns the DER SubjectPublicKeyInfo of the delegated key.
func (dc *DelegatedCredential) SubjectPublicKeyInfo() []byte {
	return dc.Cred.SubjectPublicKeyInfo
}

// DelegatedPublicKey parses and returns the delegated public key.
func (dc *DelegatedCredential) DelegatedPublicKey() (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(dc.Cred.SubjectPublicKeyInfo)
}

// CheckEligible verifies a certificate may authorize delegated credentials per
// RFC 9345 §4.2: it must carry the DelegationUsage extension and the
// digitalSignature key usage.
func CheckEligible(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("delegatedcred: nil certificate")
	}
	if !pki.HasDelegationUsage(cert) {
		return errors.New("delegatedcred: certificate is not eligible to authorize delegated credentials (missing the RFC 9345 DelegationUsage extension; issue it under a delegation_usage profile)")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("delegatedcred: certificate lacks the digitalSignature key usage required by RFC 9345 §4.2")
	}
	return nil
}
