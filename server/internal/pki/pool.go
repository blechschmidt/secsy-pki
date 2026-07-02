package pki

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
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

// keyObjectsFor returns the cached key objects for label on this session,
// resolving and caching them on first use.
func (s *pooledSession) keyObjectsFor(ctx *pkcs11.Ctx, label string) (keyObjects, error) {
	if ko, ok := s.keys[label]; ok {
		return ko, nil
	}
	ko, err := findKeyObjects(ctx, s.handle, label)
	if err != nil {
		return keyObjects{}, err
	}
	s.keys[label] = ko
	return ko, nil
}

// SessionPool is a bounded pool of authenticated PKCS#11 sessions over a single
// shared module context. It is safe for concurrent use by multiple goroutines.
type SessionPool struct {
	cfg  PKCS11Config
	ctx  *pkcs11.Ctx
	free chan *pooledSession
	size int

	mu     sync.Mutex
	closed bool
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

	p := &SessionPool{
		cfg:  cfg,
		ctx:  ctx,
		free: make(chan *pooledSession, size),
		size: size,
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
	select {
	case s := <-p.free:
		var once sync.Once
		release := func() {
			once.Do(func() { p.free <- s })
		}
		return s, release, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// PublicKey resolves and returns the public key, canonical SSH key-type name,
// and whether the key is Ed25519, for the labeled key.
func (p *SessionPool) PublicKey(ctx context.Context, label string) (crypto.PublicKey, string, bool, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, "", false, err
	}
	defer release()
	ko, err := s.keyObjectsFor(p.ctx, label)
	if err != nil {
		return nil, "", false, err
	}
	return ko.pubKey, ko.keyType, ko.isEdDSA, nil
}

// Sign performs an on-device signing operation for the labeled key, borrowing a
// session for the duration of the call.
func (p *SessionPool) Sign(ctx context.Context, label string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ko, err := s.keyObjectsFor(p.ctx, label)
	if err != nil {
		return nil, err
	}
	return signOnSession(p.ctx, s.handle, ko.priv, ko.pubKey, ko.isEdDSA, digest, opts)
}

// Decrypt performs an on-device RSA-OAEP unwrap for the labeled KEK, borrowing a
// session for the duration of the call.
func (p *SessionPool) Decrypt(ctx context.Context, label string, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	ko, err := s.keyObjectsFor(p.ctx, label)
	if err != nil {
		return nil, err
	}
	if _, ok := ko.pubKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("pkcs11 decrypt: key %q is not RSA (type %T)", label, ko.pubKey)
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
