package pki

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"github.com/miekg/pkcs11"
	"go.opentelemetry.io/otel/attribute"
)

// This file introduces a bounded PKCS#11 session pool. It is the performance
// and concurrency foundation for the HSM-backed key provider.
//
// The original design opened a fresh Cryptoki context per operation
// (pkcs11.New + C_Initialize + OpenSession + Login) and tore it all down on
// Close (Logout + CloseSession + C_Finalize + C_Destroy). That is not only slow
// — it is unsafe under concurrency on tokens whose Cryptoki state is
// per-application rather than per-session (SoftHSM among them): one operation's
// C_Finalize or C_Logout during teardown disrupts another operation's in-flight
// session in the same process.
//
// The pool fixes both problems:
//
//   - The module is loaded and C_Initialize is called exactly once per module
//     path (reference-counted across pools/providers in the process). It is
//     finalized only when the last user releases it.
//   - A bounded set of long-lived, already-logged-in R/W sessions is kept open.
//     An operation borrows a session, uses it, and returns it. There is no
//     per-operation login round-trip and no per-operation finalize.
//   - Because miekg/pkcs11 initializes Cryptoki with CKF_OS_LOCKING_OK, distinct
//     sessions may be used concurrently by distinct goroutines, so N pooled
//     sessions yield up to N concurrent on-device operations.
//
// Borrowing blocks when every session is in use, which bounds the number of
// concurrent requests hitting the token — the tuning knob is the pool size.

// sharedModule is a reference-counted wrapper around a single loaded PKCS#11
// module context. Cryptoki C_Initialize / C_Finalize are process-global for a
// given module, so all pools and providers using the same module path in one
// process must share one context and finalize it only once, when the last user
// releases it.
type sharedModule struct {
	ctx      *pkcs11.Ctx
	refCount int
}

var (
	moduleMu sync.Mutex
	modules  = map[string]*sharedModule{}
)

// acquireModule returns a shared, initialized context for the given module path,
// loading and initializing it on first use and bumping its reference count.
func acquireModule(path string) (*pkcs11.Ctx, error) {
	moduleMu.Lock()
	defer moduleMu.Unlock()

	if m, ok := modules[path]; ok {
		m.refCount++
		return m.ctx, nil
	}

	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", path)
	}
	if err := ctx.Initialize(); err != nil {
		// Another loaded handle in this process may already have initialized the
		// underlying library; that is fine and expected.
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, fmt.Errorf("initializing PKCS#11: %w", err)
		}
	}
	modules[path] = &sharedModule{ctx: ctx, refCount: 1}
	return ctx, nil
}

// releaseModule drops one reference to the module at path, finalizing and
// destroying the context when the last reference is released.
func releaseModule(path string) {
	moduleMu.Lock()
	defer moduleMu.Unlock()

	m, ok := modules[path]
	if !ok {
		return
	}
	m.refCount--
	if m.refCount > 0 {
		return
	}
	m.ctx.Finalize()
	m.ctx.Destroy()
	delete(modules, path)
}

// pooledSession is one long-lived, logged-in session plus a per-session cache of
// resolved key objects. PKCS#11 object handles are only valid within the session
// that produced them, so the cache is keyed per session. A pooledSession is only
// ever handled by one goroutine at a time (it is checked out of the pool's
// channel), so the cache needs no locking.
type pooledSession struct {
	handle pkcs11.SessionHandle
	keys   map[string]keyObjects
}

// keyObjectsFor returns the cached key objects for the locator on this session,
// resolving and caching them on first use. The cache is keyed by the locator so a
// label lookup and an id lookup (or a combined one) are distinct cache entries.
func (s *pooledSession) keyObjectsFor(ctx *pkcs11.Ctx, loc KeyLocator) (keyObjects, error) {
	key := loc.cacheKey()
	if ko, ok := s.keys[key]; ok {
		return ko, nil
	}
	ko, err := findKeyObjects(ctx, s.handle, loc)
	if err != nil {
		return keyObjects{}, err
	}
	s.keys[key] = ko
	return ko, nil
}

// SessionPool is a bounded pool of authenticated PKCS#11 sessions over a single
// shared module context. It is safe for concurrent use by multiple goroutines.
type SessionPool struct {
	cfg  PKCS11Config
	ctx  *pkcs11.Ctx
	free chan *pooledSession
	size int

	// identity is the resolved token's actual identity (label/serial/model/
	// manufacturer/slot-id), captured once at construction. It lets the HA layer
	// pin an operation to a specific token by serial or slot-id (RFC 7512
	// addressing) even when the token was configured only by label.
	identity TokenIdentity

	mu     sync.Mutex
	closed bool
}

// TokenIdentity is the actual identity of a resolved PKCS#11 token, as reported
// by the token itself (not merely what was configured). It backs RFC 7512
// serial/slot-id/model token addressing.
type TokenIdentity struct {
	SlotID       uint
	Label        string
	Serial       string
	Model        string
	Manufacturer string
}

// NewSessionPool loads (or reuses) the configured module, opens `size`
// authenticated R/W sessions, and returns a ready pool. size must be >= 1; it is
// the maximum number of concurrent on-device operations the pool permits.
//
// On any failure it releases everything it acquired so a failed construction
// (e.g. a wrong PIN) leaks no module reference or session.
func NewSessionPool(cfg PKCS11Config, size int) (_ *SessionPool, err error) {
	if size < 1 {
		return nil, fmt.Errorf("pkcs11 session pool: size must be >= 1, got %d", size)
	}

	ctx, err := acquireModule(cfg.ModulePath)
	if err != nil {
		return nil, err
	}
	// Release the module reference if we do not return a live pool.
	defer func() {
		if err != nil {
			releaseModule(cfg.ModulePath)
		}
	}()

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("getting slots: %w", err)
	}
	slotID, err := findToken(ctx, slots, cfg)
	if err != nil {
		return nil, err
	}

	// Capture the resolved token's actual identity so callers (the HA layer) can
	// pin operations to it by serial/slot-id/model. Best-effort: a token that
	// refuses GetTokenInfo still yields a usable pool (identity carries only the
	// slot id).
	identity := TokenIdentity{SlotID: slotID}
	if info, terr := ctx.GetTokenInfo(slotID); terr == nil {
		identity.Label = strings.TrimRight(info.Label, " ")
		identity.Serial = strings.TrimRight(info.SerialNumber, " ")
		identity.Model = strings.TrimRight(info.Model, " ")
		identity.Manufacturer = strings.TrimRight(info.ManufacturerID, " ")
	}

	p := &SessionPool{
		cfg:      cfg,
		ctx:      ctx,
		free:     make(chan *pooledSession, size),
		size:     size,
		identity: identity,
	}

	// Open and log in every session up front. Cleanup on partial failure so we
	// do not leak sessions or leave the application logged in.
	opened := make([]*pooledSession, 0, size)
	cleanup := func() {
		for _, s := range opened {
			ctx.CloseSession(s.handle)
		}
	}
	for i := 0; i < size; i++ {
		sh, oerr := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if oerr != nil {
			cleanup()
			err = fmt.Errorf("opening session %d/%d: %w", i+1, size, oerr)
			return nil, err
		}
		// Login state is per-application on many tokens (SoftHSM included), so a
		// second login returns CKR_USER_ALREADY_LOGGED_IN; treat that as success.
		// On tokens with per-session login this logs each session in explicitly.
		if lerr := ctx.Login(sh, pkcs11.CKU_USER, cfg.Pin); lerr != nil {
			if e, ok := lerr.(pkcs11.Error); !ok || e != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
				ctx.CloseSession(sh)
				cleanup()
				err = fmt.Errorf("logging in session %d/%d: %w", i+1, size, lerr)
				return nil, err
			}
		}
		opened = append(opened, &pooledSession{handle: sh, keys: map[string]keyObjects{}})
	}

	for _, s := range opened {
		p.free <- s
	}
	return p, nil
}

// Size returns the configured maximum concurrency (number of sessions).
func (p *SessionPool) Size() int { return p.size }

// borrow checks a session out of the pool, blocking until one is available or
// the context is cancelled. The returned release function must be called to
// return the session.
func (p *SessionPool) borrow(ctx context.Context) (*pooledSession, func(), error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, nil, fmt.Errorf("pkcs11 session pool: closed")
	}
	// Record the time spent waiting for a free session as an event on the current
	// span. Under HSM concurrency pressure (Task 20) this wait is a primary
	// latency source, so surfacing it in the trace tells operators when the pool —
	// not the on-device crypto — is the bottleneck. The event is a no-op when
	// tracing is disabled.
	waitStart := time.Now()
	select {
	case s := <-p.free:
		var once sync.Once
		release := func() {
			once.Do(func() { p.free <- s })
		}
		tracing.AddEvent(ctx, "hsm.session.acquired",
			attribute.Float64("hsm.session.wait_ms", float64(time.Since(waitStart).Microseconds())/1000.0),
			attribute.Int("hsm.pool.size", p.size))
		return s, release, nil
	case <-ctx.Done():
		tracing.AddEvent(ctx, "hsm.session.acquire_failed",
			attribute.Float64("hsm.session.wait_ms", float64(time.Since(waitStart).Microseconds())/1000.0),
			attribute.String("error", ctx.Err().Error()))
		return nil, nil, ctx.Err()
	}
}

// Identity returns the resolved token's actual identity (label/serial/model/
// manufacturer/slot-id). It is populated at construction from the live token.
func (p *SessionPool) Identity() TokenIdentity { return p.identity }

// ResolvedKey is the public half plus the resolved object's actual identifiers,
// returned by Resolve so an id-addressed lookup can still report the key's label.
type ResolvedKey struct {
	Public  crypto.PublicKey
	KeyType string
	IsEdDSA bool
	Label   string
	ID      []byte
}

// Resolve resolves the key matching loc and returns its public half and actual
// identifiers, borrowing a session for the lookup.
func (p *SessionPool) Resolve(ctx context.Context, loc KeyLocator) (ResolvedKey, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return ResolvedKey{}, err
	}
	defer release()
	ko, err := s.keyObjectsFor(p.ctx, loc)
	if err != nil {
		return ResolvedKey{}, err
	}
	return ResolvedKey{Public: ko.pubKey, KeyType: ko.keyType, IsEdDSA: ko.isEdDSA, Label: ko.label, ID: ko.id}, nil
}

// PublicKey resolves and returns the public key, canonical SSH key-type name,
// and whether the key is Ed25519, for the key matching loc.
func (p *SessionPool) PublicKey(ctx context.Context, loc KeyLocator) (crypto.PublicKey, string, bool, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, "", false, err
	}
	defer release()
	ko, err := s.keyObjectsFor(p.ctx, loc)
	if err != nil {
		return nil, "", false, err
	}
	return ko.pubKey, ko.keyType, ko.isEdDSA, nil
}

// Sign performs an on-device signing operation for the key matching loc,
// borrowing a session for the duration of the call.
func (p *SessionPool) Sign(ctx context.Context, loc KeyLocator, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ko, err := s.keyObjectsFor(p.ctx, loc)
	if err != nil {
		return nil, err
	}
	return signOnSession(p.ctx, s.handle, ko.priv, ko.pubKey, ko.isEdDSA, digest, opts)
}

// Decrypt performs an on-device RSA-OAEP unwrap for the KEK matching loc,
// borrowing a session for the duration of the call.
func (p *SessionPool) Decrypt(ctx context.Context, loc KeyLocator, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ko, err := s.keyObjectsFor(p.ctx, loc)
	if err != nil {
		return nil, err
	}
	if _, ok := ko.pubKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("pkcs11 decrypt: key %s is not RSA (type %T)", loc.Describe(), ko.pubKey)
	}
	if _, ok := opts.(*rsa.PKCS1v15DecryptOptions); ok {
		return decryptPKCS1v15OnSession(p.ctx, s.handle, ko.priv, ciphertext)
	}
	return decryptOAEPOnSession(p.ctx, s.handle, ko.priv, ciphertext, opts)
}

// GenerateSignKey creates a signing key pair on the token via a pooled session.
func (p *SessionPool) GenerateSignKey(ctx context.Context, label, keyType string) (*GeneratedHSMKey, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return generateKeyPairOnSession(p.ctx, s.handle, p.cfg, label, keyType)
}

// GenerateRSAKEK creates an RSA key-encryption key pair on the token via a
// pooled session.
func (p *SessionPool) GenerateRSAKEK(ctx context.Context, label string, bits int) (*GeneratedHSMKey, error) {
	if bits != 2048 && bits != 4096 {
		return nil, fmt.Errorf("unsupported KEK size %d (must be 2048 or 4096)", bits)
	}
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return generateRSAKEKOnSession(p.ctx, s.handle, p.cfg, label, bits)
}

// ListKeys enumerates the token's private-key objects via a pooled session.
func (p *SessionPool) ListKeys(ctx context.Context) ([]HSMKeyInfo, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return listKeysOnSession(p.ctx, s.handle)
}

// Ping confirms a pooled session is live and usable, satisfying readiness
// probes without a per-probe login round-trip. Because the pool's sessions are
// already authenticated, a healthy borrow-and-check means the token can service
// signing requests right now.
func (p *SessionPool) Ping(ctx context.Context) error {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err := p.ctx.GetSessionInfo(s.handle); err != nil {
		return fmt.Errorf("pkcs11 session unusable: %w", err)
	}
	return nil
}

// Close drains and closes every session, logs the application out once, and
// releases the shared module reference (finalizing the module if this was the
// last user). It is idempotent.
func (p *SessionPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	// Drain all sessions and close them. Callers must stop issuing operations
	// before Close (shut the listener down first); the drain collects exactly
	// p.size sessions. The channel is deliberately NOT closed: a late release
	// racing shutdown then lands harmlessly in the (now-empty, size-capacity)
	// buffer instead of panicking on a send to a closed channel.
	var loggedOut bool
	for i := 0; i < p.size; i++ {
		s := <-p.free
		if !loggedOut {
			// One logout suffices for per-application login state; harmless
			// otherwise. Do it before closing the last session.
			p.ctx.Logout(s.handle)
			loggedOut = true
		}
		p.ctx.CloseSession(s.handle)
	}
	releaseModule(p.cfg.ModulePath)
	return nil
}
