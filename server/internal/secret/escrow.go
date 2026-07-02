package secret

// Key escrow and recovery for the envelope-encryption layer.
//
// Escrow gives an enterprise a break-glass path to a secret's plaintext when the
// original requester loses access, without weakening the day-to-day security of
// the primary KEK. At encryption time the per-message data-encryption key (DEK)
// is additionally split with Shamir's Secret Sharing (see shamir.go) into N
// shares under a reconstruction threshold M; each share is then wrapped
// (RSA-OAEP) to one recovery agent's public key. The wrapped shares travel with
// the envelope in an EscrowBlock.
//
// Recovery is a dual-control ceremony: a quorum of M distinct recovery agents
// each unwrap their share — on their HSM, so the agent's private key never
// leaves the token — and the M cleartext shares reconstruct the DEK, which
// decrypts the ciphertext. Any M-1 agents learn nothing about the DEK (Shamir's
// information-theoretic guarantee), so no sub-quorum can recover the plaintext.
//
// Security notes:
//   - The EscrowBlock is bound into the AES-GCM additional-authenticated-data of
//     the envelope (see Envelope.aad), so an attacker cannot substitute their own
//     recovery agents or shares without invalidating the ciphertext tag.
//   - Cleartext Shamir shares exist only transiently in memory during a recovery
//     ceremony and are zeroized immediately after the DEK is reconstructed.
//   - Wrapping uses each agent's exported public key and needs no HSM; only
//     recovery touches the agents' private keys.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// EscrowFormatVersion1 is the current escrow-block format version.
const EscrowFormatVersion1 = 1

// AlgShamirRSAOAEP identifies the escrow scheme: a Shamir split over GF(2^8)
// whose shares are individually RSA-OAEP wrapped to recovery-agent keys.
const AlgShamirRSAOAEP = "shamir-gf256+rsa-oaep"

// Escrow-related errors. Shamir errors are deliberately distinct so callers and
// tests can tell a malformed share from a sub-quorum from a bad configuration.
var (
	errThresholdTooLow     = errors.New("secret: escrow threshold must be at least 2 (dual control)")
	errPartsBelowThreshold = errors.New("secret: number of recovery agents is below the threshold")
	errTooManyParts        = errors.New("secret: at most 255 recovery agents are supported")
	errEmptySecret         = errors.New("secret: cannot split an empty secret")
	errTooFewShares        = errors.New("secret: at least two shares are required to combine")
	errShareMalformed      = errors.New("secret: malformed Shamir share")
	errShareZeroX          = errors.New("secret: Shamir share has an invalid zero x-coordinate")
	errShareLengthMismatch = errors.New("secret: Shamir shares have inconsistent lengths")
	errShareDuplicateX     = errors.New("secret: duplicate Shamir share x-coordinate")
)

// RecoveryAgent is a configured escrow recipient: a named principal whose RSA
// public key wraps one Shamir share at encryption time, and whose private key
// (held in the key provider / HSM) unwraps it during a recovery ceremony.
type RecoveryAgent struct {
	// ID is the stable, human-meaningful agent identifier (e.g. "alice",
	// "security-officer-1"). It labels the agent's share in the envelope and in
	// the audit log.
	ID string
	// KeyLabel is the agent's key label within the key provider. It is required
	// to unwrap the share during recovery; it may be empty for an agent whose
	// public key was supplied externally and whose private key lives outside this
	// provider (such an agent can be wrapped-to but not recovered here).
	KeyLabel string
	// Pub is the agent's RSA public key, used to wrap the share offline.
	Pub *rsa.PublicKey
	// wrapAlg is the RSA-OAEP variant negotiated for this agent (SHA-256, or
	// SHA-1 for tokens like SoftHSM that support only SHA-1 OAEP).
	wrapAlg string
}

// EscrowPolicy is a validated M-of-N escrow configuration ready to seal shares.
type EscrowPolicy struct {
	threshold int
	agents    []RecoveryAgent
}

// Threshold returns the quorum size M.
func (p *EscrowPolicy) Threshold() int { return p.threshold }

// Agents returns the configured recovery agents (N of them).
func (p *EscrowPolicy) Agents() []RecoveryAgent { return p.agents }

// AgentSpec describes one recovery agent before its public key is resolved. Give
// either an inline PEM-encoded public key (PublicKeyPEM) or a KeyLabel to fetch
// the public key from the key provider; a KeyLabel is required if the agent must
// participate in recovery through this provider.
type AgentSpec struct {
	ID           string
	KeyLabel     string
	PublicKeyPEM string
}

// NewEscrowPolicy builds and validates an M-of-N escrow policy against a key
// provider. For each agent it resolves the RSA public key (from an inline PEM if
// given, otherwise from the provider by KeyLabel) and negotiates the RSA-OAEP
// hash the agent's token can actually unwrap with, so recovery on SoftHSM (SHA-1
// only) works transparently.
func NewEscrowPolicy(ctx context.Context, provider keyprovider.Provider, threshold int, specs []AgentSpec) (*EscrowPolicy, error) {
	if threshold < 2 {
		return nil, errThresholdTooLow
	}
	if len(specs) < threshold {
		return nil, errPartsBelowThreshold
	}
	if len(specs) > 255 {
		return nil, errTooManyParts
	}

	seenID := make(map[string]bool, len(specs))
	seenLabel := make(map[string]bool, len(specs))
	agents := make([]RecoveryAgent, 0, len(specs))
	for i, spec := range specs {
		if spec.ID == "" {
			return nil, fmt.Errorf("secret: recovery agent %d has no id", i)
		}
		if seenID[spec.ID] {
			return nil, fmt.Errorf("secret: duplicate recovery agent id %q", spec.ID)
		}
		seenID[spec.ID] = true
		if spec.KeyLabel != "" {
			if seenLabel[spec.KeyLabel] {
				return nil, fmt.Errorf("secret: recovery agents %q reuse key label %q", spec.ID, spec.KeyLabel)
			}
			seenLabel[spec.KeyLabel] = true
		}

		pub, err := resolveAgentPublicKey(ctx, provider, spec)
		if err != nil {
			return nil, fmt.Errorf("secret: recovery agent %q: %w", spec.ID, err)
		}
		if pub.N.BitLen() < 2048 {
			return nil, fmt.Errorf("secret: recovery agent %q key is too small (%d bits); minimum is 2048", spec.ID, pub.N.BitLen())
		}

		// Negotiate the wrap algorithm against the agent's token when its private
		// key is available in this provider; otherwise default to SHA-256, which
		// every production HSM supports.
		wrapAlg := AlgRSAOAEPSHA256
		if spec.KeyLabel != "" {
			if _, ok := provider.(keyprovider.DecrypterProvider); ok {
				alg, err := negotiateWrapAlg(ctx, provider, keyprovider.KeyRef{Label: spec.KeyLabel}, pub)
				if err != nil {
					return nil, fmt.Errorf("secret: recovery agent %q: %w", spec.ID, err)
				}
				wrapAlg = alg
			}
		}

		agents = append(agents, RecoveryAgent{
			ID:       spec.ID,
			KeyLabel: spec.KeyLabel,
			Pub:      pub,
			wrapAlg:  wrapAlg,
		})
	}
	return &EscrowPolicy{threshold: threshold, agents: agents}, nil
}

// resolveAgentPublicKey obtains an agent's RSA public key from an inline PEM or,
// failing that, from the provider by key label.
func resolveAgentPublicKey(ctx context.Context, provider keyprovider.Provider, spec AgentSpec) (*rsa.PublicKey, error) {
	if spec.PublicKeyPEM != "" {
		pub, err := parseRSAPublicKeyPEM([]byte(spec.PublicKeyPEM))
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
	if spec.KeyLabel == "" {
		return nil, fmt.Errorf("no public key: set a key_label or an inline public_key")
	}
	info, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: spec.KeyLabel})
	if err != nil {
		return nil, fmt.Errorf("locating agent key: %w", err)
	}
	pub, ok := info.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("agent key %q is not RSA (type %T)", spec.KeyLabel, info.PublicKey)
	}
	return pub, nil
}

// EscrowShare is one recovery agent's wrapped Shamir share, stored in the
// envelope's EscrowBlock. It carries no cleartext key material.
type EscrowShare struct {
	// AgentID identifies the recovery agent this share belongs to.
	AgentID string `json:"agent_id"`
	// KeyLabel is the agent's key label needed to unwrap the share (may be empty
	// for externally-held keys).
	KeyLabel string `json:"key_label,omitempty"`
	// X is the Shamir x-coordinate of this share (1..255).
	X int `json:"x"`
	// WrapAlg is the RSA-OAEP variant used to wrap the share.
	WrapAlg string `json:"wrap_alg"`
	// WrappedShare is the RSA-OAEP-wrapped serialized Shamir share.
	WrappedShare []byte `json:"wrapped_share"`
}

// EscrowBlock is the self-describing record of an M-of-N escrow, embedded in an
// Envelope. It reveals only metadata and wrapped shares — never the DEK, the
// cleartext shares, or the plaintext.
type EscrowBlock struct {
	// Version is the escrow-block format version.
	Version int `json:"version"`
	// Alg is the escrow scheme identifier (AlgShamirRSAOAEP).
	Alg string `json:"alg"`
	// Threshold is the quorum M required to reconstruct the DEK.
	Threshold int `json:"threshold"`
	// Shares are the N wrapped shares, one per recovery agent.
	Shares []EscrowShare `json:"shares"`
}

// sealEscrow splits dek into an EscrowBlock under this policy: a Shamir split
// followed by an RSA-OAEP wrap of each share to its agent. The cleartext shares
// are zeroized before returning.
func (p *EscrowPolicy) sealEscrow(dek []byte) (*EscrowBlock, error) {
	shares, err := shamirSplit(dek, len(p.agents), p.threshold, func(b []byte) error {
		_, err := rand.Read(b)
		return err
	})
	if err != nil {
		return nil, err
	}
	block := &EscrowBlock{
		Version:   EscrowFormatVersion1,
		Alg:       AlgShamirRSAOAEP,
		Threshold: p.threshold,
		Shares:    make([]EscrowShare, len(p.agents)),
	}
	for i, agent := range p.agents {
		raw := shares[i].bytes()
		h, err := algHash(agent.wrapAlg)
		if err != nil {
			zero(raw)
			return nil, err
		}
		wrapped, err := rsa.EncryptOAEP(h.New(), rand.Reader, agent.Pub, raw, nil)
		zero(raw)
		if err != nil {
			return nil, fmt.Errorf("secret: wrapping share for agent %q: %w", agent.ID, err)
		}
		block.Shares[i] = EscrowShare{
			AgentID:      agent.ID,
			KeyLabel:     agent.KeyLabel,
			X:            int(shares[i].X),
			WrapAlg:      agent.wrapAlg,
			WrappedShare: wrapped,
		}
	}
	return block, nil
}

// validate checks structural integrity of an escrow block before use.
func (b *EscrowBlock) validate() error {
	if b == nil {
		return nil
	}
	if b.Version != EscrowFormatVersion1 {
		return fmt.Errorf("secret: unsupported escrow version %d", b.Version)
	}
	if b.Alg != AlgShamirRSAOAEP {
		return fmt.Errorf("secret: unsupported escrow algorithm %q", b.Alg)
	}
	if b.Threshold < 2 {
		return errThresholdTooLow
	}
	if len(b.Shares) < b.Threshold {
		return errPartsBelowThreshold
	}
	seenX := make(map[int]bool, len(b.Shares))
	seenID := make(map[string]bool, len(b.Shares))
	for i, s := range b.Shares {
		if s.X < 1 || s.X > 255 {
			return fmt.Errorf("secret: escrow share %d has invalid x-coordinate %d", i, s.X)
		}
		if seenX[s.X] {
			return fmt.Errorf("secret: escrow shares reuse x-coordinate %d", s.X)
		}
		seenX[s.X] = true
		if s.AgentID == "" {
			return fmt.Errorf("secret: escrow share %d has no agent id", i)
		}
		if seenID[s.AgentID] {
			return fmt.Errorf("secret: duplicate escrow agent id %q", s.AgentID)
		}
		seenID[s.AgentID] = true
		if !supportedWrapAlgs[s.WrapAlg] {
			return fmt.Errorf("secret: escrow share %q uses unsupported wrap algorithm %q", s.AgentID, s.WrapAlg)
		}
		if len(s.WrappedShare) == 0 {
			return fmt.Errorf("secret: escrow share %q is missing wrapped material", s.AgentID)
		}
	}
	return nil
}

// digest returns a stable SHA-256 commitment to the escrow block's parameters
// and wrapped shares, bound into the envelope AAD so the escrow cannot be
// tampered with or substituted. The encoding is length-prefixed and shares are
// sorted by x-coordinate so the digest is independent of share ordering.
func (b *EscrowBlock) digest() []byte {
	h := sha256.New()
	writeLP := func(p []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var hdr [12]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(b.Version))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(b.Threshold))
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(b.Shares)))
	h.Write(hdr[:])
	writeLP([]byte(b.Alg))

	shares := make([]EscrowShare, len(b.Shares))
	copy(shares, b.Shares)
	sort.Slice(shares, func(i, j int) bool { return shares[i].X < shares[j].X })
	for _, s := range shares {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], uint32(s.X))
		h.Write(x[:])
		writeLP([]byte(s.AgentID))
		writeLP([]byte(s.KeyLabel))
		writeLP([]byte(s.WrapAlg))
		writeLP(s.WrappedShare)
	}
	return h.Sum(nil)
}

// recoveredShare is one recovery agent's contribution to a ceremony: the
// cleartext Shamir share obtained by unwrapping the agent's EscrowShare on its
// token. It is consumed by reconstructDEK and never persisted.
type recoveredShare struct {
	agentID string
	share   shamirShare
}

// reconstructDEK combines a quorum of recovered shares back into the DEK,
// enforcing that at least the block's threshold distinct agents contributed.
func reconstructDEK(block *EscrowBlock, recovered []recoveredShare) ([]byte, error) {
	if len(recovered) < block.Threshold {
		return nil, fmt.Errorf("secret: recovery quorum not met: %d of %d required share(s) provided", len(recovered), block.Threshold)
	}
	shares := make([]shamirShare, len(recovered))
	for i, r := range recovered {
		shares[i] = r.share
	}
	dek, err := shamirCombine(shares)
	if err != nil {
		return nil, err
	}
	if len(dek) != dekSize {
		zero(dek)
		return nil, fmt.Errorf("secret: reconstructed key has wrong length %d", len(dek))
	}
	return dek, nil
}

// RecoveryService performs escrow-recovery ceremonies against a key provider
// (HSM). It is independent of the primary KEK: recovery works even when the
// original KEK is unavailable, which is the point of escrow.
type RecoveryService struct {
	provider keyprovider.Provider
}

// NewRecoveryService binds a recovery service to a key provider that can unwrap
// recovery-agent shares.
func NewRecoveryService(provider keyprovider.Provider) (*RecoveryService, error) {
	if provider == nil {
		return nil, fmt.Errorf("secret: nil key provider")
	}
	if _, ok := provider.(keyprovider.DecrypterProvider); !ok {
		return nil, fmt.Errorf("secret: key provider %q cannot decrypt (recovery unsupported)", provider.Name())
	}
	return &RecoveryService{provider: provider}, nil
}

// unwrapAgentShare unwraps a single agent's EscrowShare on its token, returning
// the cleartext Shamir share. The agent's private key never leaves the provider.
func (rs *RecoveryService) unwrapAgentShare(ctx context.Context, share EscrowShare) (shamirShare, error) {
	if share.KeyLabel == "" {
		return shamirShare{}, fmt.Errorf("secret: recovery agent %q has no key label in this provider", share.AgentID)
	}
	h, err := algHash(share.WrapAlg)
	if err != nil {
		return shamirShare{}, err
	}
	dp := rs.provider.(keyprovider.DecrypterProvider)
	dec, err := dp.Decrypter(ctx, keyprovider.KeyRef{Label: share.KeyLabel})
	if err != nil {
		return shamirShare{}, fmt.Errorf("secret: opening agent %q key: %w", share.AgentID, err)
	}
	defer dec.Close()
	raw, err := dec.Decrypt(rand.Reader, share.WrappedShare, &rsa.OAEPOptions{Hash: h})
	if err != nil {
		return shamirShare{}, fmt.Errorf("secret: agent %q failed to unwrap its share", share.AgentID)
	}
	defer zero(raw)
	ss, err := parseShamirShare(raw)
	if err != nil {
		return shamirShare{}, err
	}
	if int(ss.X) != share.X {
		return shamirShare{}, fmt.Errorf("secret: agent %q share x-coordinate mismatch", share.AgentID)
	}
	return ss, nil
}

// RecoverDEK runs the unwrap step of a recovery ceremony for the named agents
// and reconstructs the DEK. It enforces the quorum and that every named agent is
// actually an escrow recipient of this envelope. The returned DEK must be
// zeroized by the caller.
func (rs *RecoveryService) RecoverDEK(ctx context.Context, block *EscrowBlock, agentIDs []string) ([]byte, error) {
	if err := block.validate(); err != nil {
		return nil, err
	}
	byID := make(map[string]EscrowShare, len(block.Shares))
	for _, s := range block.Shares {
		byID[s.AgentID] = s
	}
	seen := make(map[string]bool, len(agentIDs))
	var recovered []recoveredShare
	for _, id := range agentIDs {
		if seen[id] {
			return nil, fmt.Errorf("secret: recovery agent %q named more than once", id)
		}
		seen[id] = true
		share, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("secret: %q is not a recovery agent of this envelope", id)
		}
		ss, err := rs.unwrapAgentShare(ctx, share)
		if err != nil {
			return nil, err
		}
		recovered = append(recovered, recoveredShare{agentID: id, share: ss})
	}
	return reconstructDEK(block, recovered)
}

// Recover runs a full recovery ceremony: it unwraps the named agents' shares,
// reconstructs the DEK, and decrypts the envelope. context must match what was
// supplied at encryption time. It fails closed if the envelope carries no escrow
// block or the quorum is not met.
func (rs *RecoveryService) Recover(ctx context.Context, env *Envelope, agentIDs []string, context []byte) ([]byte, error) {
	if err := env.validate(); err != nil {
		return nil, err
	}
	if env.Escrow == nil {
		return nil, fmt.Errorf("secret: this envelope has no key escrow; recovery is not possible")
	}
	dek, err := rs.RecoverDEK(ctx, env.Escrow, agentIDs)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	return openWithDEK(env, dek, context)
}

// AgentIDs returns the set of recovery agent identifiers an envelope is escrowed
// to, for display in a recovery ceremony.
func (b *EscrowBlock) AgentIDs() []string {
	ids := make([]string, len(b.Shares))
	for i, s := range b.Shares {
		ids[i] = s.AgentID
	}
	return ids
}

// parseRSAPublicKeyPEM parses a PEM-encoded RSA public key (PKIX/SPKI or the
// legacy PKCS#1 "RSA PUBLIC KEY" form).
func parseRSAPublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA (type %T)", pub)
		}
		return rp, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
}
