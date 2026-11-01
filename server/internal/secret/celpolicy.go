package secret

// The CEL signing-restriction gate for raw signatures (Task 224).
//
// A named signing key (Task 153) is the most *generic* signing surface this
// deployment has: it signs whatever bytes a caller hands it, with an
// HSM-resident key, and returns the signature. Nothing about the payload tells
// the service what it just attested to — which is precisely why the decision of
// whether to sign at all has to be expressible as policy. The key's algorithm
// is fixed at creation and the caller's RBAC capability is checked by the
// transport; what neither can say is "this key is reserved for the release
// workflow's token", "this key never signs a digest nobody looked at", "no
// signature outside business hours without a change ticket".
//
// The gate is reached through an option rather than a field on a service,
// because Sign is a package function shared by the REST/gRPC handlers and the
// secsy-secret CLI, and both of them hold the rule store the gate reads.

import (
	"context"
	"crypto"
	"encoding/hex"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// SignPolicy is the restriction gate plus the attribution a rule reads. A zero
// value — or an absent WithPolicy option — permits every signature, which is
// what a caller with no rule store (a unit test, a tool) means; it is not the
// same as a rule set that could not be loaded, which the gate itself refuses.
type SignPolicy struct {
	// Gate evaluates the stored signing rules. Nil permits.
	Gate celpolicy.SigningChecker
	// RequestedBy is the identity the signature is attributed to, reaching a
	// rule as signing.requested_by. The HTTP paths can leave it empty (the
	// request context carries the authenticated principal); a CLI invocation
	// cannot, so it passes the operator explicitly.
	RequestedBy string
	// Purpose is the free-text reason the caller gave, as signing.purpose.
	Purpose string
	// Source names the surface, for signing.source, when it is known more
	// precisely than the context reveals (the CLI).
	Source string
}

// SignOption adjusts a Sign call. It is variadic so the existing callers — and
// the signature every test in this package already uses — stay valid.
type SignOption func(*signOptions)

type signOptions struct {
	policy SignPolicy
}

// WithPolicy supplies the signing-restriction gate and the attribution it
// reports. A call without it is unrestricted.
func WithPolicy(p SignPolicy) SignOption {
	return func(o *signOptions) { o.policy = p }
}

func resolveSignOptions(opts []SignOption) signOptions {
	var o signOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// checkPolicy consults the gate, if one was supplied, with the facts of this
// signature. It returns a *celpolicy.DenyError when an enforcing rule refused.
func (o signOptions) checkPolicy(ctx context.Context, provider keyprovider.Provider, row *models.SigningKey,
	alg SigningAlgorithm, hash crypto.Hash, digest []byte, dataLen int, preHashed bool) error {
	if o.policy.Gate == nil {
		return nil
	}
	return o.policy.Gate.CheckSigning(ctx,
		o.signingFacts(provider, row, alg, hash, digest, dataLen, preHashed))
}

// signingFacts assembles the facts of one raw-signature request.
func (o signOptions) signingFacts(provider keyprovider.Provider, row *models.SigningKey,
	alg SigningAlgorithm, hash crypto.Hash, digest []byte, dataLen int, preHashed bool) celpolicy.SigningRequest {
	facts := celpolicy.SigningRequest{
		Operation:   celpolicy.OpSignData,
		Source:      o.policy.Source,
		Tenant:      row.TenantID,
		RequestedBy: o.policy.RequestedBy,
		Purpose:     o.policy.Purpose,
		Key: celpolicy.SigningKeyInfo{
			Name:      row.Name,
			Label:     row.KeyRef,
			Ref:       row.KeyRef,
			Algorithm: string(alg),
			Type:      row.KeyType,
			Provider:  row.Provider,
			Tenant:    row.TenantID,
		},
		Data: celpolicy.DataInfo{
			Present:   true,
			Key:       row.Name,
			Algorithm: string(alg),
			Hash:      celpolicy.HashName(hash),
		},
		Payload: celpolicy.PayloadInfo{
			Present:         true,
			Digest:          hex.EncodeToString(digest),
			DigestAlgorithm: celpolicy.HashName(hash),
			Prehashed:       preHashed,
		},
	}
	// The payload size is the length of what the caller actually supplied. A
	// pre-hashed request has no message length to report, and reporting the
	// digest's 32 bytes as the payload size would let `signing.payload.size`
	// read as a tiny message rather than as an unknown one.
	if !preHashed {
		facts.Payload.Size = dataLen
	}
	if pub, err := PublicKey(row); err == nil {
		k := celpolicy.KeyFactsFromPublic(pub)
		facts.Key.Size = k.Size
		facts.Key.Curve = k.Curve
		facts.Key.Fingerprint = k.Fingerprint
	}
	if facts.Key.Provider == "" && provider != nil {
		facts.Key.Provider = provider.Name()
	}
	return facts
}
