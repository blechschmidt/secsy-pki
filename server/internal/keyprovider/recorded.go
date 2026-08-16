package keyprovider

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"sync"
)

// The signature ledger exists because a YubiHSM audit log entry says that key
// 0x1939 performed an ECDSA signature, but not what it signed. A device log
// alone therefore cannot distinguish 412 legitimate certificate signatures from
// 411 legitimate ones plus one forged certificate: the counts are identical.
//
// Recording every signature request here — at the one point every signing
// operation in the system passes through — supplies the missing half. The
// device log bounds how many signatures exist; the ledger says which ones they
// were. An auditor who has both, plus the artifacts the CA published, can close
// the loop: device count == ledger count == published artifacts.
//
// Putting the hook at the Provider level rather than in each caller is what
// makes the bound trustworthy. CA issuance, CRL and OCSP signing, the TSA, the
// SSH CA, SPIFFE SVIDs, artifact signing, the canary probe and every background
// job reach the HSM through this interface, so none of them can sign without
// leaving a ledger row — including code added later that never heard of the
// audit subsystem.

// SignatureRecord describes one signing operation for the ledger.
type SignatureRecord struct {
	// KeyLabel is the provider key label.
	KeyLabel string
	// KeyID is the backend key identifier — for PKCS#11 the hex CKA_ID, which
	// on a YubiHSM is the two-byte on-device object ID that the device audit
	// log reports as target_key. It is the field reconciliation joins on.
	KeyID string
	// Digest is the exact digest handed to the signer. For an X.509
	// certificate signed with ecdsa-with-SHA256 it is SHA-256 over the
	// TBSCertificate; an auditor recomputes it from the published certificate.
	Digest []byte
	// Algorithm names the digest algorithm, so an auditor knows which hash to
	// recompute over a published artifact.
	Algorithm string
	// Provider is the backend name, retained so a ledger spanning a key
	// migration stays interpretable.
	Provider string
}

// SignatureRecorder durably records signing operations. It is deliberately a
// narrow interface declared here rather than in the audit package, so that the
// dependency runs audit -> keyprovider and no import cycle arises.
type SignatureRecorder interface {
	// RecordSignature persists rec. Returning an error causes the signature to
	// be discarded rather than returned to the caller.
	RecordSignature(ctx context.Context, rec SignatureRecord) error
}

// Record wraps a Provider so that every signature it produces is recorded via
// rec before being returned to the caller.
//
// Ordering — sign first, then record — is chosen so that the common failure
// modes stay self-consistent rather than generating false alarms:
//
//   - The signature fails: the device logs a rejected attempt, which
//     reconciliation counts separately from signatures, and no ledger row is
//     written. Balanced.
//   - The signature and the recording both succeed: one device entry, one
//     ledger row. Balanced.
//   - The signature succeeds but the recording fails: the HSM really did
//     produce a signature the CA cannot account for, so the imbalance an
//     auditor sees is not spurious — it is accurate. Record fails closed by
//     discarding the signature and returning an error, so the artifact is never
//     published, and the surplus is left visible for an auditor to ask about
//     rather than hidden.
//
// Recording before signing would invert the last case into a permanent phantom
// deficit for every transient HSM error, which is worse: an auditor learns to
// ignore imbalances.
func Record(p Provider, rec SignatureRecorder) Provider {
	if p == nil || rec == nil {
		return p
	}
	rp := &recordingProvider{Provider: p, rec: rec, ids: map[string]string{}}
	if _, ok := p.(DecrypterProvider); ok {
		return &recordingDecrypterProvider{recordingProvider: rp}
	}
	if _, ok := p.(KeyWrapper); ok {
		return &recordingKeyWrapperProvider{recordingProvider: rp}
	}
	return rp
}

type recordingProvider struct {
	Provider
	rec SignatureRecorder

	// ids caches label -> backend key ID. Resolving the ID costs a FindKey
	// round-trip to the HSM, and it cannot change for a given label without the
	// key being deleted and recreated — both of which are force-audited
	// operations that appear in the device log.
	mu  sync.RWMutex
	ids map[string]string
}

// Ping, ListKeys and Random forward the optional capabilities the embedded
// Provider interface does not surface, so wrapping does not silently remove the
// readiness probe, key inventory, or hardware RNG.
func (p *recordingProvider) Ping(ctx context.Context) error {
	pr, ok := p.Provider.(Prober)
	if !ok {
		return ErrProbeUnsupported
	}
	return pr.Ping(ctx)
}

func (p *recordingProvider) ListKeys(ctx context.Context) ([]KeyDescriptor, error) {
	kl, ok := p.Provider.(KeyLister)
	if !ok {
		return nil, fmt.Errorf("keyprovider: provider does not support key listing")
	}
	return kl.ListKeys(ctx)
}

func (p *recordingProvider) Random(ctx context.Context, n int) ([]byte, error) {
	rp, ok := p.Provider.(RandomProvider)
	if !ok {
		return nil, ErrRandomUnsupported
	}
	return rp.Random(ctx, n)
}

func (p *recordingProvider) Signer(ctx context.Context, ref KeyRef) (Signer, error) {
	s, err := p.Provider.Signer(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &recordingSigner{
		Signer:   s,
		p:        p,
		ctx:      ctx,
		label:    ref.Label,
		keyID:    p.resolveKeyID(ctx, ref),
		provider: p.Name(),
	}, nil
}

// resolveKeyID returns the backend key identifier for ref, preferring the one
// the caller already supplied and otherwise asking the provider once.
//
// A failure to resolve is not fatal: the ledger row is still written, with an
// empty key ID. Refusing to sign because an identifier lookup failed would
// trade a complete audit trail for an outage, and reconciliation reports an
// unattributable row loudly enough that the gap cannot pass unnoticed.
func (p *recordingProvider) resolveKeyID(ctx context.Context, ref KeyRef) string {
	if ref.ID != "" {
		return ref.ID
	}
	if ref.Label == "" {
		return ""
	}
	p.mu.RLock()
	id, ok := p.ids[ref.Label]
	p.mu.RUnlock()
	if ok {
		return id
	}
	info, err := p.Provider.FindKey(ctx, ref)
	if err != nil || info == nil {
		return ""
	}
	p.mu.Lock()
	p.ids[ref.Label] = info.ID
	p.mu.Unlock()
	return info.ID
}

type recordingSigner struct {
	Signer
	p        *recordingProvider
	ctx      context.Context
	label    string
	keyID    string
	provider string
}

func (s *recordingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.Signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	alg := ""
	if opts != nil {
		alg = opts.HashFunc().String()
	}
	if err := s.p.rec.RecordSignature(ctx, SignatureRecord{
		KeyLabel:  s.label,
		KeyID:     s.keyID,
		Digest:    digest,
		Algorithm: alg,
		Provider:  s.provider,
	}); err != nil {
		return nil, fmt.Errorf("keyprovider: signature produced by key %q was not recorded in the audit ledger, "+
			"discarding it rather than releasing an unaccountable signature: %w", s.label, err)
	}
	return sig, nil
}

// recordingDecrypterProvider and recordingKeyWrapperProvider re-expose the
// capabilities the wrapper would otherwise mask. Neither decryption nor key
// wrapping produces a signature, so neither is recorded — the device log still
// covers them, and inventing ledger rows for them would break the one-row-per-
// signature invariant reconciliation depends on.
type recordingDecrypterProvider struct {
	*recordingProvider
}

func (p *recordingDecrypterProvider) Decrypter(ctx context.Context, ref KeyRef) (Decrypter, error) {
	return p.Provider.(DecrypterProvider).Decrypter(ctx, ref)
}

type recordingKeyWrapperProvider struct {
	*recordingProvider
}

func (p *recordingKeyWrapperProvider) WrapKey(ctx context.Context, ref KeyRef, plaintext []byte) ([]byte, error) {
	return p.Provider.(KeyWrapper).WrapKey(ctx, ref, plaintext)
}

func (p *recordingKeyWrapperProvider) UnwrapKey(ctx context.Context, ref KeyRef, ciphertext []byte) ([]byte, error) {
	return p.Provider.(KeyWrapper).UnwrapKey(ctx, ref, ciphertext)
}
