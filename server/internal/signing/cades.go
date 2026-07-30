package signing

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
)

// Level is an ETSI EN 319 122 CAdES baseline signature level. The signing
// service produces, and the verifier reports, three of the baseline levels:
//
//   - LevelB  (CAdES-B, baseline): the signing-certificate-v2 (ESSCertIDv2) and
//     signing-time signed attributes are present. Every signature this service
//     produces is at least B.
//   - LevelT  (CAdES-T): B plus an RFC 3161 signature-timestamp (a TimeStampToken
//     over the SignerInfo signature value, id-aa-timeStampToken) from the
//     in-process TSA, anchoring the signing time so the signature survives
//     signer-certificate expiry.
//   - LevelLT (CAdES-LT): T plus long-term-validation material — the signer/CA
//     certificate chain together with current OCSP responses and/or CRLs
//     (SignedData.crls and the id-aa-ets-revocationValues unsigned attribute) —
//     so the chain can be validated offline after the certificates expire.
//
// The archival LevelLTA (periodic archive-timestamps) is out of scope.
type Level string

const (
	// LevelB is CAdES-B (baseline): signed signing-certificate-v2 + signing-time.
	LevelB Level = "b"
	// LevelT is CAdES-T: B + RFC 3161 signature-timestamp.
	LevelT Level = "t"
	// LevelLT is CAdES-LT: T + embedded long-term-validation revocation material.
	LevelLT Level = "lt"
)

// ParseLevel normalizes a level string (case-insensitive, tolerating the
// "cades-"/"b-" prefixes some tooling uses) to one of the known levels. An empty
// string maps to the zero Level, which callers treat as "unspecified".
func ParseLevel(s string) (Level, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, "cades-")
	t = strings.TrimPrefix(t, "baseline-")
	switch Level(t) {
	case "":
		return "", nil
	case LevelB:
		return LevelB, nil
	case LevelT:
		return LevelT, nil
	case LevelLT:
		return LevelLT, nil
	default:
		return "", fmt.Errorf("signing: unknown CAdES level %q (want b, t, or lt)", s)
	}
}

// valid reports whether l is one of the three supported baseline levels.
func (l Level) valid() bool {
	switch l {
	case LevelB, LevelT, LevelLT:
		return true
	default:
		return false
	}
}

// rank orders the levels so a verifier can check an achieved level meets a
// required minimum (B < T < LT). An unknown level ranks 0.
func (l Level) rank() int {
	switch l {
	case LevelB:
		return 1
	case LevelT:
		return 2
	case LevelLT:
		return 3
	default:
		return 0
	}
}

// String renders the level as its uppercase CAdES name (e.g. "CAdES-LT").
func (l Level) String() string {
	if !l.valid() {
		return string(l)
	}
	return "CAdES-" + strings.ToUpper(string(l))
}

// needsTimestamp reports whether producing this level embeds an RFC 3161
// signature-timestamp (true for T and LT).
func (l Level) needsTimestamp() bool { return l == LevelT || l == LevelLT }

// needsLTV reports whether producing this level embeds long-term-validation
// revocation material (true for LT only).
func (l Level) needsLTV() bool { return l == LevelLT }

// RevocationSource supplies the long-term-validation revocation evidence that
// raises a signature to CAdES-LT: given the signer certificate chain, it returns
// OCSP responses and CRLs proving the non-root certificates are not revoked, so
// the signature stays verifiable after those certificates expire.
//
// The ca.Manager satisfies this interface. Implementations are best-effort:
// certificates whose issuer is not a CA known to the deployment are skipped —
// what matters is that the signer leaf and its issuers are covered.
type RevocationSource interface {
	// CollectRevocation returns DER OCSP responses (complete OCSPResponse) and DER
	// CRLs (CertificateList) covering the certificates in chain.
	CollectRevocation(ctx context.Context, chain []*x509.Certificate) (ocspResponses [][]byte, crls [][]byte, err error)
}
