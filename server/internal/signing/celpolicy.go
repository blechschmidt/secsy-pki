package signing

// The CEL signing-restriction facts for an artifact signature (Task 224).
//
// A code-signing key is the most consequential key an enterprise operates: a
// signature made with it is trusted by machines that will never see the request
// that produced it. The configuration already fixes the signer's certificate,
// its digest and its default CAdES level — but it cannot express the rules that
// actually matter around a release pipeline: which identity may use the release
// key, whether a signature made by a human is acceptable at all, whether a
// signature must carry a trusted timestamp, whether this service may attest to
// a digest it never saw.
//
// Those are relationships between the request, the caller's token and the key,
// which is what the restriction engine is for.

import (
	"encoding/hex"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
)

// policyFacts assembles the signing facts of one artifact-signature request.
// The level is the resolved one (not the requested one) and the digest is the
// one the signature will actually cover, so a rule is true of the signature
// rather than of the JSON that asked for it.
func (s *Service) policyFacts(req SignRequest, sc *SignerConfig, level Level, artifactDigest []byte) celpolicy.SigningRequest {
	facts := celpolicy.SigningRequest{
		Operation:   celpolicy.OpSignArtifact,
		Tenant:      sc.TenantID,
		RequestedBy: req.RequestedBy,
		Purpose:     req.Purpose,
		Artifact: celpolicy.ArtifactInfo{
			Present:     true,
			Signer:      sc.Name,
			Level:       string(level),
			Timestamped: level.needsTimestamp(),
			Name:        req.Name,
			Certificate: celpolicy.SignerCertFactsFrom(sc.Certificate),
		},
		Payload: celpolicy.PayloadInfo{
			Present:         true,
			Size:            len(req.Content),
			Digest:          hex.EncodeToString(artifactDigest),
			DigestAlgorithm: celpolicy.HashName(sc.Digest),
			// A digest-input request means the service is attesting to bytes it
			// never saw. That is the whole point of digest input for a
			// multi-gigabyte image, and it is also exactly what a policy may
			// want to forbid for a key whose signatures imply review.
			Prehashed: req.Digest != nil,
		},
	}
	facts.Key = celpolicy.SigningKeyInfo{
		Name:     sc.Name,
		Label:    sc.KeyLabel,
		Ref:      sc.KeyLabel,
		Provider: s.provider.Name(),
		Tenant:   sc.TenantID,
	}
	if sc.Certificate != nil {
		pub := celpolicy.KeyFactsFromPublic(sc.Certificate.PublicKey)
		facts.Key.Algorithm = pub.Algorithm
		facts.Key.Size = pub.Size
		facts.Key.Curve = pub.Curve
		facts.Key.Fingerprint = pub.Fingerprint
	}
	return facts
}
