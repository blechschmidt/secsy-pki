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

	"golang.org/x/crypto/ocsp"

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
	// RequireLevel fails verification when the achieved CAdES level is below this
	// minimum (b < t < lt). Empty imposes no floor. Requiring lt implies a
	// timestamp and embedded revocation material.
	RequireLevel Level
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
	// Level is the highest CAdES baseline level the signature is shown to achieve
	// (b|t|lt), or empty when the CAdES-B signed attributes are absent.
	Level Level
	// RevocationCRLs / RevocationOCSPs count the distinct long-term-validation
	// revocation objects embedded in the signature (SignedData.crls +
	// id-aa-ets-revocationValues).
	RevocationCRLs  int
	RevocationOCSPs int
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

	// 5. Long-term-validation material (CAdES-LT). Parse any embedded CRLs/OCSP
	// responses; fail closed if they show the signer revoked. Their presence and
	// coverage of the signer, together with a valid timestamp, is what raises the
	// reported level to LT.
	ltv, err := evaluateEmbeddedRevocation(p, signerCert, chain)
	if err != nil {
		return nil, err
	}
	result.RevocationCRLs = ltv.crls
	result.RevocationOCSPs = ltv.ocsps

	// 6. Report the achieved CAdES level and enforce any required floor.
	result.Level = achievedLevel(p, result.Timestamped, ltv)
	if req.RequireLevel != "" {
		if !req.RequireLevel.valid() {
			return nil, fmt.Errorf("signing: unknown required CAdES level %q (want b, t, or lt)", req.RequireLevel)
		}
		if result.Level.rank() < req.RequireLevel.rank() {
			achieved := result.Level
			if achieved == "" {
				return nil, fmt.Errorf("signing: signature does not reach %s (the CAdES-B signed attributes are absent)", req.RequireLevel)
			}
			return nil, fmt.Errorf("signing: signature achieves %s, below the required %s", achieved, req.RequireLevel)
		}
	}
	return result, nil
}

// oidSigningTime is the id-signingTime signed attribute (RFC 5652 §11.3), one of
// the two attributes CAdES-B requires alongside signing-certificate-v2.
var oidSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

// achievedLevel reports the highest CAdES baseline level the signature is shown
// to reach: B requires both CAdES-B signed attributes; T additionally a valid
// timestamp; LT additionally embedded revocation material covering the signer.
func achievedLevel(p *cms.ParsedSignedData, timestamped bool, ltv *ltvInfo) Level {
	_, hasSCv2 := p.AuthenticatedAttribute(cms.OIDSigningCertificateV2)
	_, hasSigningTime := p.AuthenticatedAttribute(oidSigningTime)
	if !hasSCv2 || !hasSigningTime {
		return "" // not a CAdES-B signature
	}
	if !timestamped {
		return LevelB
	}
	if ltv.covered {
		return LevelLT
	}
	return LevelT
}

// ltvInfo summarizes the long-term-validation material embedded in a signature.
type ltvInfo struct {
	crls    int  // distinct embedded CRLs
	ocsps   int  // distinct embedded OCSP responses
	covered bool // at least one valid CRL/OCSP specifically covers the signer
}

// evaluateEmbeddedRevocation parses the revocation material embedded in the
// signature (the SignedData `crls` field and the id-aa-ets-revocationValues
// unsigned attribute), fails closed if it shows the signer certificate revoked,
// and reports whether it authenticly covers the signer (a valid CRL from the
// signer's issuer, or a valid OCSP response for the signer's serial).
func evaluateEmbeddedRevocation(p *cms.ParsedSignedData, signerCert *x509.Certificate, chain []*x509.Certificate) (*ltvInfo, error) {
	// Gather CRLs (crls field + revocation-values) and OCSP BasicOCSPResponses
	// (revocation-values), de-duplicating by DER since we embed CRLs in both
	// containers.
	crlSet := map[string][]byte{}
	for _, der := range p.EmbeddedCRLs() {
		crlSet[string(der)] = der
	}
	var basicOCSPs [][]byte
	if raw, ok := p.UnauthenticatedAttribute(cms.OIDRevocationValues); ok {
		rv, err := cms.ParseRevocationValues(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("signing: parsing revocation-values attribute: %w", err)
		}
		for _, der := range rv.CRLs {
			crlSet[string(der)] = der
		}
		ocspSet := map[string]bool{}
		for _, der := range rv.BasicOCSPResponses {
			if ocspSet[string(der)] {
				continue
			}
			ocspSet[string(der)] = true
			basicOCSPs = append(basicOCSPs, der)
		}
	}

	info := &ltvInfo{crls: len(crlSet), ocsps: len(basicOCSPs)}

	// The signer's issuer is the CA whose subject matches the signer's issuer DN.
	var signerIssuer *x509.Certificate
	for _, c := range chain {
		if bytes.Equal(c.RawSubject, signerCert.RawIssuer) {
			signerIssuer = c
			break
		}
	}

	// CRLs: a valid CRL from the signer's issuer that lists the signer serial is
	// a hard revocation. Any valid CRL from the signer's issuer counts as cover.
	for _, der := range crlSet {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			continue // unparsable material is ignored, not trusted
		}
		var crlIssuer *x509.Certificate
		for _, c := range chain {
			if bytes.Equal(c.RawSubject, crl.RawIssuer) {
				crlIssuer = c
				break
			}
		}
		if crlIssuer == nil || crl.CheckSignatureFrom(crlIssuer) != nil {
			continue // can't authenticate this CRL
		}
		if !bytes.Equal(crlIssuer.RawSubject, signerCert.RawIssuer) {
			continue // covers a different CA in the chain, not the signer
		}
		info.covered = true
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(signerCert.SerialNumber) == 0 {
				return nil, errors.New("signing: signer certificate is revoked (embedded CRL)")
			}
		}
	}

	// OCSP: a valid response for the signer serial that says revoked is a hard
	// revocation; good counts as cover.
	if signerIssuer != nil {
		for _, basic := range basicOCSPs {
			wrapped, err := cms.WrapBasicOCSPResponse(basic)
			if err != nil {
				continue
			}
			resp, err := ocsp.ParseResponse(wrapped, signerIssuer)
			if err != nil {
				continue // signature/parse failure: not trusted
			}
			if resp.SerialNumber == nil || resp.SerialNumber.Cmp(signerCert.SerialNumber) != 0 {
				continue
			}
			if resp.Status == ocsp.Revoked {
				return nil, errors.New("signing: signer certificate is revoked (embedded OCSP response)")
			}
			info.covered = true
		}
	}

	return info, nil
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
