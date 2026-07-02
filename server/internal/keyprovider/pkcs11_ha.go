package keyprovider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// This file implements high availability for the PKCS#11 backend: a set of
// tokens/slots, each holding a replica of the signing key(s) under the same
// CKA_LABEL, behind health-tracked failover.
//
// Design:
//
//   - Each token is a distinct single-token PKCS11Provider (its own bounded
//     session pool over the shared, reference-counted module context). The HA
//     provider owns a slice of these "members" plus a health record per member.
//   - Every operation is routed to a healthy member chosen by the selection
//     policy (primary/backup or round-robin). If it errors on that member, the
//     operation is retried on the next candidate — so signing survives a token
//     dropping out mid-flight. A signer bound by Signer() re-selects on every
//     Sign, so a long-lived signer keeps working across a failover.
//   - A member is marked unhealthy after FailureThreshold consecutive
//     health-affecting failures (a logical key-not-found does not count), taking
//     it out of rotation. A background prober re-checks members on ProbeInterval
//     and returns a member to rotation once its probe passes again.
//   - Per-token health (secsy_hsm_token_up) and failover activity
//     (secsy_hsm_token_failovers_total / secsy_hsm_token_errors_total) are
//     exported for alerting.
//
// The unique-CKA_LABEL invariant (see the pkcs11-duplicate-label note: two
// key pairs sharing a label on one token resolve ambiguously and produce
// unverifiable signatures) is preserved across the set: GenerateKey refuses a
// label that already exists on ANY member, and generates on the primary token
// only — replicating the (non-extractable) key onto backup tokens is an
// operator key-ceremony step, not something the provider can do by regenerating.

// SelectionPolicy determines which healthy token an operation is routed to.
type SelectionPolicy string

const (
	// PolicyPrimaryBackup always prefers the first healthy token in configured
	// order; backup tokens are used only while higher-priority tokens are
	// unhealthy. It is the default.
	PolicyPrimaryBackup SelectionPolicy = "primary-backup"
	// PolicyRoundRobin spreads operations across all currently-healthy tokens.
	PolicyRoundRobin SelectionPolicy = "round-robin"
)

const (
	// DefaultFailureThreshold is the number of consecutive health-affecting
	// failures on a token before it is marked unhealthy and taken out of rotation.
	DefaultFailureThreshold = 3
	// DefaultProbeInterval is how often the background health prober re-checks
	// tokens so a recovered token is returned to rotation.
	DefaultProbeInterval = 15 * time.Second
	// haProbeTimeout bounds a single background/readiness probe so a hung token
	// cannot wedge the prober loop.
	haProbeTimeout = 5 * time.Second
)

// errTokenUnreachable is the synthetic error a member yields when it has been
// marked unreachable by a test seam (see haMember.unreachable). It is treated as
// a health-affecting failure, exactly like a real PKCS#11 transport error.
var errTokenUnreachable = errors.New("keyprovider: pkcs11 token unreachable")

// haMember is one token in the HA set: its single-token provider plus a health
// record. The health fields are guarded by mu; recordSuccess/recordFailure are
// the only mutators.
type haMember struct {
	name     string
	provider *PKCS11Provider

	mu      sync.Mutex
	healthy bool
	fails   int // consecutive health-affecting failures

	// unreachable is a test-only seam: when set, the member behaves as if its
	// token had vanished — operations and probes fail with errTokenUnreachable —
	// without disturbing the real session pool. It is always false in production
	// and exists so the SoftHSM failover test can pull a token out mid-load
	// deterministically and concurrency-safely.
	unreachable atomic.Bool
}

func (m *haMember) isHealthy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthy
}

// recordSuccess resets the member's failure count and, if it was unhealthy,
// returns it to rotation and refreshes its health gauge.
func (m *haMember) recordSuccess() {
	m.mu.Lock()
	recovered := !m.healthy
	m.healthy = true
	m.fails = 0
	m.mu.Unlock()
	if recovered {
		metrics.SetHSMTokenUp(m.name, true)
		log.Printf("keyprovider: PKCS#11 token %q recovered and returned to rotation", m.name)
	}
}

// recordFailure charges one health-affecting failure to the member and, once the
// threshold is reached, marks it unhealthy (out of rotation) and drops its health
// gauge to zero.
func (m *haMember) recordFailure(threshold int) {
	m.mu.Lock()
	m.fails++
	fails := m.fails
	downed := false
	if m.healthy && m.fails >= threshold {
		m.healthy = false
		downed = true
	}
	m.mu.Unlock()
	if downed {
		metrics.SetHSMTokenUp(m.name, false)
		log.Printf("keyprovider: PKCS#11 token %q marked unhealthy after %d consecutive failures; failing over", m.name, fails)
	}
}

// ping probes the member's token, honoring the unreachable test seam.
func (m *haMember) ping(ctx context.Context) error {
	if m.unreachable.Load() {
		return errTokenUnreachable
	}
	return m.provider.Ping(ctx)
}

// PKCS11HAProvider is a Provider that spans multiple PKCS#11 tokens with
// health-tracked failover. It satisfies Provider, Prober, DecrypterProvider, and
// KeyLister, so it is a drop-in replacement for the single-token PKCS11Provider
// (and works through the instrumented wrapper unchanged).
type PKCS11HAProvider struct {
	members   []*haMember
	policy    SelectionPolicy
	threshold int

	rr atomic.Uint64 // round-robin cursor

	probeInterval time.Duration
	stopCh        chan struct{}
	stopOnce      sync.Once
	wg            sync.WaitGroup
}

// NewPKCS11HAProvider builds a high-availability provider over the tokens in s.
// Each token becomes a single-token member provider sharing the module path and
// session-pool size; per-token PIN/label/serial come from s.Tokens. A background
// health prober is started and must be stopped via Close.
func NewPKCS11HAProvider(s PKCS11Settings) (*PKCS11HAProvider, error) {
	if len(s.Tokens) == 0 {
		return nil, fmt.Errorf("keyprovider: pkcs11 HA provider requires at least one token")
	}
	if s.ModulePath == "" {
		return nil, fmt.Errorf("keyprovider: pkcs11 module_path is required")
	}

	policy := SelectionPolicy(s.SelectionPolicy)
	switch policy {
	case "", PolicyPrimaryBackup:
		policy = PolicyPrimaryBackup
	case PolicyRoundRobin:
		// ok
	default:
		return nil, fmt.Errorf("keyprovider: unknown pkcs11 selection_policy %q (want %q or %q)",
			s.SelectionPolicy, PolicyPrimaryBackup, PolicyRoundRobin)
	}

	threshold := s.FailureThreshold
	if threshold <= 0 {
		threshold = DefaultFailureThreshold
	}
	interval := s.ProbeInterval
	if interval <= 0 {
		interval = DefaultProbeInterval
	}

	seen := make(map[string]bool, len(s.Tokens))
	members := make([]*haMember, 0, len(s.Tokens))
	for i, tok := range s.Tokens {
		name := tok.Name
		if name == "" {
			name = tok.TokenLabel
		}
		if name == "" {
			name = fmt.Sprintf("token-%d", i)
		}
		if seen[name] {
			return nil, fmt.Errorf("keyprovider: duplicate token name %q in pkcs11 HA set", name)
		}
		seen[name] = true

		pin := tok.Pin
		if pin == "" {
			pin = s.Pin
		}
		member, err := NewPKCS11Provider(PKCS11Settings{
			ModulePath:        s.ModulePath,
			Pin:               pin,
			TokenLabel:        tok.TokenLabel,
			TokenSerial:       tok.TokenSerial,
			TokenManufacturer: tok.TokenManufacturer,
			SessionPoolSize:   s.SessionPoolSize,
		})
		if err != nil {
			return nil, fmt.Errorf("keyprovider: configuring token %q: %w", name, err)
		}
		members = append(members, &haMember{name: name, provider: member, healthy: true})
		// Start optimistic: pools are built lazily, so a token is assumed healthy
		// until an operation or probe proves otherwise.
		metrics.SetHSMTokenUp(name, true)
	}

	p := &PKCS11HAProvider{
		members:       members,
		policy:        policy,
		threshold:     threshold,
		probeInterval: interval,
		stopCh:        make(chan struct{}),
	}
	p.wg.Add(1)
	go p.probeLoop()
	return p, nil
}

func (p *PKCS11HAProvider) Name() string { return string(ProviderPKCS11) }

// route returns members in the order operations should try them: healthy members
// first (ordered by the selection policy), then any unhealthy members as a last
// resort. Trying an unhealthy member last means a fully-degraded set still
// attempts the operation rather than failing outright — the operation itself is
// the freshest health signal and can recover the member.
func (p *PKCS11HAProvider) route() []*haMember {
	healthy := make([]*haMember, 0, len(p.members))
	unhealthy := make([]*haMember, 0)
	for _, m := range p.members {
		if m.isHealthy() {
			healthy = append(healthy, m)
		} else {
			unhealthy = append(unhealthy, m)
		}
	}
	if p.policy == PolicyRoundRobin && len(healthy) > 1 {
		off := int(p.rr.Add(1) % uint64(len(healthy)))
		rotated := make([]*haMember, 0, len(healthy))
		rotated = append(rotated, healthy[off:]...)
		rotated = append(rotated, healthy[:off]...)
		healthy = rotated
	}
	return append(healthy, unhealthy...)
}

// withFailover runs fn against routed members in order, returning on the first
// success. A health-affecting failure (anything other than a logical
// key-not-found) charges the member's health and, if another candidate remains,
// counts a failover. It returns the last error when every candidate fails.
func (p *PKCS11HAProvider) withFailover(fn func(m *haMember) error) error {
	members := p.route()
	if len(members) == 0 {
		return fmt.Errorf("keyprovider: no PKCS#11 tokens configured")
	}
	var lastErr error
	for i, m := range members {
		var err error
		if m.unreachable.Load() {
			err = errTokenUnreachable
		} else {
			err = fn(m)
		}
		if err == nil {
			m.recordSuccess()
			return nil
		}
		lastErr = err
		if healthAffecting(err) {
			metrics.RecordHSMTokenError(m.name)
			m.recordFailure(p.threshold)
			if i+1 < len(members) {
				metrics.RecordHSMTokenFailover(m.name)
			}
		}
	}
	return lastErr
}

// healthAffecting reports whether an error should count against a token's health.
// A logical key-not-found is a property of the request, not the token, so it is
// excluded; everything else (PKCS#11 transport/session errors, unreachable
// tokens) counts.
func healthAffecting(err error) bool {
	if err == nil {
		return false
	}
	return !errors.Is(err, ErrKeyNotFound)
}

// GenerateKey creates a key on the primary token, first enforcing the unique
// label invariant across every token in the set: if the label already exists on
// any member the request is refused, and if any member cannot be checked (e.g. it
// is unreachable) generation fails closed rather than risk a duplicate-labeled,
// differently-keyed pair on a replica. Replicating the generated key onto backup
// tokens is a separate operator key-ceremony step.
func (p *PKCS11HAProvider) GenerateKey(ctx context.Context, spec KeySpec) (*KeyInfo, error) {
	if spec.Label == "" {
		return nil, fmt.Errorf("keyprovider: key label is required")
	}
	for _, m := range p.members {
		existing, err := m.provider.FindKey(ctx, KeyRef{Label: spec.Label})
		if err == nil {
			_ = existing
			return nil, fmt.Errorf("keyprovider: a key labeled %q already exists on token %q", spec.Label, m.name)
		} else if !errors.Is(err, ErrKeyNotFound) {
			return nil, fmt.Errorf("keyprovider: checking token %q for existing key %q: %w", m.name, spec.Label, err)
		}
	}
	// Generate on the first healthy token (the primary under primary-backup).
	primary := p.route()[0]
	info, err := primary.provider.GenerateKey(ctx, spec)
	if err != nil {
		primary.recordFailure(p.threshold)
		return nil, err
	}
	primary.recordSuccess()
	return info, nil
}

// FindKey locates the key on any healthy token holding a replica.
func (p *PKCS11HAProvider) FindKey(ctx context.Context, ref KeyRef) (*KeyInfo, error) {
	var info *KeyInfo
	err := p.withFailover(func(m *haMember) error {
		got, e := m.provider.FindKey(ctx, ref)
		if e != nil {
			return e
		}
		info = got
		return nil
	})
	return info, err
}

// PublicKey exports the referenced key's public half from any healthy replica.
func (p *PKCS11HAProvider) PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error) {
	info, err := p.FindKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	return info.PublicKey, nil
}

// Signer returns a failover-aware signer for the referenced key. The public key
// and type are resolved from a healthy replica up front; each Sign re-selects a
// healthy token, so the signer keeps working across a token failing mid-use.
func (p *PKCS11HAProvider) Signer(ctx context.Context, ref KeyRef) (Signer, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	info, err := p.FindKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &haSigner{p: p, ctx: ctx, label: label, pub: info.PublicKey, keyType: info.KeyType}, nil
}

// signWithFailover signs digest for label, retrying across tokens on failure.
func (p *PKCS11HAProvider) signWithFailover(ctx context.Context, label string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var sig []byte
	err := p.withFailover(func(m *haMember) error {
		var e error
		sig, e = m.provider.signOp(ctx, label, digest, opts)
		return e
	})
	return sig, err
}

// decryptWithFailover unwraps ciphertext for the labeled KEK, retrying across
// tokens on failure.
func (p *PKCS11HAProvider) decryptWithFailover(ctx context.Context, label string, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	var pt []byte
	err := p.withFailover(func(m *haMember) error {
		var e error
		pt, e = m.provider.decryptOp(ctx, label, ciphertext, opts)
		return e
	})
	return pt, err
}

// Decrypter returns a failover-aware decrypter for the referenced RSA KEK.
func (p *PKCS11HAProvider) Decrypter(ctx context.Context, ref KeyRef) (Decrypter, error) {
	label, err := ref.resolve()
	if err != nil {
		return nil, err
	}
	info, err := p.FindKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	if _, ok := info.PublicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("keyprovider: key %q is not an RSA key and cannot be used for decryption", label)
	}
	return &haDecrypter{p: p, ctx: ctx, label: label, pub: info.PublicKey}, nil
}

// ListKeys enumerates keys from any healthy token (the tokens are replicas).
func (p *PKCS11HAProvider) ListKeys(ctx context.Context) ([]KeyDescriptor, error) {
	var keys []KeyDescriptor
	err := p.withFailover(func(m *haMember) error {
		got, e := m.provider.ListKeys(ctx)
		if e != nil {
			return e
		}
		keys = got
		return nil
	})
	return keys, err
}

// Ping reports the HA set healthy if at least one token is reachable, probing
// every member and updating each one's health along the way. It satisfies the
// Prober interface for readiness checks.
func (p *PKCS11HAProvider) Ping(ctx context.Context) error {
	var lastErr error
	anyUp := false
	for _, m := range p.members {
		if err := m.ping(ctx); err != nil {
			lastErr = err
			m.recordFailure(p.threshold)
		} else {
			m.recordSuccess()
			anyUp = true
		}
	}
	if anyUp {
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no tokens configured")
	}
	return fmt.Errorf("keyprovider: all PKCS#11 tokens unhealthy: %w", lastErr)
}

// probeLoop periodically re-checks every member so a recovered token returns to
// rotation and a silently-dead one is taken out even without live traffic.
func (p *PKCS11HAProvider) probeLoop() {
	defer p.wg.Done()
	t := time.NewTicker(p.probeInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			for _, m := range p.members {
				ctx, cancel := context.WithTimeout(context.Background(), haProbeTimeout)
				err := m.ping(ctx)
				cancel()
				if err != nil {
					m.recordFailure(p.threshold)
				} else {
					m.recordSuccess()
				}
			}
		}
	}
}

// Close stops the background prober and closes every member's session pool. It is
// idempotent.
func (p *PKCS11HAProvider) Close() error {
	p.stopOnce.Do(func() { close(p.stopCh) })
	p.wg.Wait()
	var firstErr error
	for _, m := range p.members {
		if err := m.provider.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// haSigner is a failover-aware Signer. It holds no token affinity: each Sign asks
// the HA provider to route to a healthy token, so a signer obtained before a
// failover keeps working after it. Close is an idempotent bookkeeping no-op.
type haSigner struct {
	p       *PKCS11HAProvider
	ctx     context.Context
	label   string
	pub     crypto.PublicKey
	keyType string

	mu     sync.Mutex
	closed bool
}

func (s *haSigner) Public() crypto.PublicKey { return s.pub }
func (s *haSigner) KeyType() string          { return s.keyType }

func (s *haSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("keyprovider: signer is closed")
	}
	return s.p.signWithFailover(s.ctx, s.label, digest, opts)
}

func (s *haSigner) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

// haDecrypter is a failover-aware Decrypter, mirroring haSigner for RSA-OAEP /
// PKCS#1v1.5 unwrap on a replicated KEK.
type haDecrypter struct {
	p     *PKCS11HAProvider
	ctx   context.Context
	label string
	pub   crypto.PublicKey

	mu     sync.Mutex
	closed bool
}

func (d *haDecrypter) Public() crypto.PublicKey { return d.pub }

func (d *haDecrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("keyprovider: decrypter is closed")
	}
	return d.p.decryptWithFailover(d.ctx, d.label, ciphertext, opts)
}

func (d *haDecrypter) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}

var (
	_ Provider          = (*PKCS11HAProvider)(nil)
	_ Prober            = (*PKCS11HAProvider)(nil)
	_ DecrypterProvider = (*PKCS11HAProvider)(nil)
	_ KeyLister         = (*PKCS11HAProvider)(nil)
	_ Signer            = (*haSigner)(nil)
	_ Decrypter         = (*haDecrypter)(nil)
)
