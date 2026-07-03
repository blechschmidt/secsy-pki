package signing

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// VerifyRequest describes one signature-verification operation. Exactly one of
// Content or Digest must be provided.
type VerifyRequest struct {
	// Signature is the DER-encoded CMS detached SignedData.
	Signature []byte
	// Content is the artifact the signature claims to cover.
	Content []byte
	// Digest is the precomputed artifact digest (computed with the signature's
	// digest algorithm; see cms.SignerDigestAlgorithm) for digest-input
	// verification of large artifacts.
	Digest []byte
	// Roots are the trust anchors the signer (and any TSA) chain must build to.
	Roots []*x509.Certificate
	// Intermediates are additional untrusted issuer certificates to consider
	// when building the path, on top of those embedded in the signature.
	Intermediates []*x509.Certificate
	// RequireTimestamp fails verification when no (valid) RFC 3161
	// countersignature is embedded.
	RequireTimestamp bool
	// Now overrides the wall clock (tests). Zero means time.Now().
	Now time.Time
}

// VerifyResult reports the details of a successful verification.
type VerifyResult struct {
	// SignerCertificate is the code-signing certificate that produced the
	// signature; Chain is the verified path from it to a supplied root.
	SignerCertificate *x509.Certificate
	Chain             []*x509.Certificate
	// DigestAlgorithm / ArtifactDigest identify what the signature covers.
	DigestAlgorithm crypto.Hash
	ArtifactDigest  []byte
	// Timestamped reports whether a valid RFC 3161 countersignature was
	// embedded. When true, GenTime/serial/TSA describe it, TimestampToken is
	// the raw token (for external audit, e.g. openssl ts), and VerifiedAt is
	// the token's genTime; otherwise VerifiedAt is the wall clock.
	Timestamped      bool
	TimestampGenTime time.Time
	TimestampSerial  *big.Int
	TimestampToken   []byte
	TSACertificate   *x509.Certificate
	VerifiedAt       time.Time
}

// Verify checks a CMS detached signature end to end, fail-closed:
//
//  1. the signature cryptographically covers the supplied content (or digest);
//  2. the signer certificate carries the code-signing shape (EKU + KU);
//  3. an embedded RFC 3161 countersignature, when present, itself verifies
//     (token signature, imprint over the signature value, TSA EKU, TSA chain
//     to the same trust anchors) — only then does it set the validation time;
//  4. the signer chain builds to the supplied roots for the codeSigning EKU at
//     the validation time (the token's genTime when timestamped, else now) —
//     so a properly countersigned artifact keeps verifying after its signing
//     certificate expires, while an unstamped one does not.
//
// Revocation is not consulted here; pair verification with the PKI's CRL/OCSP
// data when policy requires it.
func Verify(req VerifyRequest) (*VerifyResult, error) {
	if len(req.Roots) == 0 {
		return nil, errors.New("signing: verification requires at least one trust anchor")
	}
	if req.Content == nil && req.Digest == nil {
		return nil, errors.New("signing: either the artifact content or its digest is required")
	}
	if req.Content != nil && req.Digest != nil {
		return nil, errors.New("signing: provide the artifact content or its digest, not both")
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}

	p, err := cms.ParseSignedData(req.Signature)
	if err != nil {
		return nil, err
	}
	hash, err := p.SignerDigestAlgorithm()
	if err != nil {
		return nil, err
	}

	// 1. Cryptographic verification against the artifact.
	var artifactDigest []byte
	if req.Digest != nil {
		if err := p.VerifyDetachedDigest(req.Digest); err != nil {
			return nil, err
		}
		artifactDigest = req.Digest
	} else {
		if err := p.VerifyDetached(req.Content); err != nil {
			return nil, err
		}
		h := hash.New()
		h.Write(req.Content)
		artifactDigest = h.Sum(nil)
	}

	signerCert := p.SignerCertificate()
	if signerCert == nil {
		return nil, errors.New("signing: signature does not embed its signer certificate")
	}

	// 2. The signer must look like a code-signing identity, and when the ESS
	// signing-certificate-v2 attribute is present it must bind this certificate
	// (guarding against certificate substitution within the message).
	if err := CheckCodeSigningCert(signerCert); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if err := checkSigningCertificateV2(p, signerCert); err != nil {
		return nil, err
	}

	result := &VerifyResult{
		SignerCertificate: signerCert,
		DigestAlgorithm:   hash,
		ArtifactDigest:    artifactDigest,
		VerifiedAt:        now,
	}

	// 3. Timestamp countersignature (optional unless required).
	if raw, ok := p.UnauthenticatedAttribute(OIDTimeStampToken); ok {
		info, tsaCert, err := verifyTimestampToken(raw.FullBytes, p.Signature(), req.Roots, req.Intermediates, now)
		if err != nil {
			return nil, err
		}
		result.Timestamped = true
		result.TimestampGenTime = info.GenTime
		result.TimestampSerial = info.SerialNumber
		result.TimestampToken = append([]byte(nil), raw.FullBytes...)
		result.TSACertificate = tsaCert
		result.VerifiedAt = info.GenTime
	} else if req.RequireTimestamp {
		return nil, errors.New("signing: signature carries no RFC 3161 timestamp countersignature (required)")
	}

	// 4. Chain the signer to the trust anchors at the validation time.
	chain, err := verifyChain(signerCert, p.Certificates, req.Roots, req.Intermediates,
		result.VerifiedAt, x509.ExtKeyUsageCodeSigning)
	if err != nil {
		return nil, fmt.Errorf("signing: signer certificate chain: %w", err)
	}
	result.Chain = chain
	return result, nil
}

// verifyTimestampToken validates an embedded TimeStampToken end to end: the
// token's own CMS signature (with the TSA certificate embedded in the token),
// the message imprint over the artifact signature value, the TSA certificate's
// time-stamping EKU and chain to the trust anchors at genTime, and a
// plausibility bound that genTime is not in the future.
func verifyTimestampToken(tokenDER, signature []byte, roots, intermediates []*x509.Certificate, now time.Time) (*tsa.TokenInfo, *x509.Certificate, error) {
	tok, err := cms.ParseSignedData(tokenDER)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: parsing timestamp token: %w", err)
	}
	if err := tok.Verify(); err != nil {
		return nil, nil, fmt.Errorf("signing: timestamp token signature: %w", err)
	}
	tsaCert := tok.SignerCertificate()
	if tsaCert == nil {
		return nil, nil, errors.New("signing: timestamp token does not embed the TSA certificate")
	}

	info, err := tsa.ParseTokenInfo(tokenDER)
	if err != nil {
		return nil, nil, err
	}
	h := info.Hash.New()
	h.Write(signature)
	if !bytes.Equal(h.Sum(nil), info.HashedMessage) {
		return nil, nil, errors.New("signing: timestamp token does not cover this signature value")
	}
	if info.GenTime.After(now.Add(clockSkew)) {
		return nil, nil, fmt.Errorf("signing: timestamp genTime %s is in the future", info.GenTime.UTC().Format(time.RFC3339))
	}

	hasTS := false
	for _, eku := range tsaCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTS = true
		}
	}
	if !hasTS {
		return nil, nil, errors.New("signing: timestamp token signer lacks the id-kp-timeStamping extended key usage")
	}
	if _, err := verifyChain(tsaCert, tok.Certificates, roots, intermediates, info.GenTime, x509.ExtKeyUsageTimeStamping); err != nil {
		return nil, nil, fmt.Errorf("signing: TSA certificate chain: %w", err)
	}
	return info, tsaCert, nil
}

// verifyChain builds a verified path from cert to one of the roots, offering
// the message-embedded certificates plus any caller-supplied intermediates as
// untrusted issuers, evaluated at the given time for the given EKU.
func verifyChain(cert *x509.Certificate, embedded, roots, extra []*x509.Certificate, at time.Time, eku x509.ExtKeyUsage) ([]*x509.Certificate, error) {
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	interPool := x509.NewCertPool()
	for _, c := range embedded {
		if !bytes.Equal(c.Raw, cert.Raw) {
			interPool.AddCert(c)
		}
	}
	for _, c := range extra {
		interPool.AddCert(c)
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{eku},
	})
	if err != nil {
		return nil, err
	}
	return chains[0], nil
}

// checkSigningCertificateV2 validates the ESS signing-certificate-v2 attribute
// when present: its first ESSCertIDv2 hash must match the resolved signer
// certificate (RFC 5035 §4; default id-sha256 hash).
func checkSigningCertificateV2(p *cms.ParsedSignedData, signerCert *x509.Certificate) error {
	raw, ok := p.AuthenticatedAttribute(cms.OIDSigningCertificateV2)
	if !ok {
		return nil
	}
	var scv2 struct {
		Certs []struct {
			CertHash []byte
		}
	}
	if _, err := asn1.Unmarshal(raw.FullBytes, &scv2); err != nil {
		return fmt.Errorf("signing: parsing signing-certificate-v2 attribute: %w", err)
	}
	if len(scv2.Certs) == 0 {
		return errors.New("signing: signing-certificate-v2 attribute is empty")
	}
	sum := sha256.Sum256(signerCert.Raw)
	if !bytes.Equal(scv2.Certs[0].CertHash, sum[:]) {
		return errors.New("signing: signing-certificate-v2 attribute does not match the signer certificate")
	}
	return nil
}
