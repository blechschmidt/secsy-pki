package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// The recording wrapper is the one point every HSM operation in the system
// passes through, which is why both the signature ledger (Task 167) and the
// device-log drain signal (Task 181) hang off it. These tests hold it to that:
// an operation that reaches the backend without firing the hook is an operation
// whose device log entry nothing will collect.

// hookedProvider is the base Provider: signing plus the hardware RNG. The
// optional capabilities live on the two wrappers below, one each, because
// Record selects a branch per capability and a test that conflated them would
// leave one branch unexercised.
type hookedProvider struct {
	key *ecdsa.PrivateKey

	mu       sync.Mutex
	signErr  error
	backend  []string // operations that actually reached the backend
	randomN  int
	unwrapIn []byte
}

func newHookedProvider(t *testing.T) *hookedProvider {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	return &hookedProvider{key: k}
}

func (p *hookedProvider) note(op string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backend = append(p.backend, op)
}

func (p *hookedProvider) reached() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.backend...)
}

func (p *hookedProvider) Name() string { return "hooked" }
func (p *hookedProvider) Close() error { return nil }

func (p *hookedProvider) GenerateKey(context.Context, KeySpec) (*KeyInfo, error) {
	return nil, fmt.Errorf("not needed")
}

func (p *hookedProvider) FindKey(_ context.Context, ref KeyRef) (*KeyInfo, error) {
	return &KeyInfo{Label: ref.Label, ID: "1939"}, nil
}

func (p *hookedProvider) PublicKey(context.Context, KeyRef) (crypto.PublicKey, error) {
	return p.key.Public(), nil
}

func (p *hookedProvider) Signer(_ context.Context, ref KeyRef) (Signer, error) {
	return &hookedSigner{p: p}, nil
}

func (p *hookedProvider) Random(_ context.Context, n int) ([]byte, error) {
	p.note("random")
	p.mu.Lock()
	p.randomN = n
	p.mu.Unlock()
	return make([]byte, n), nil
}

// wrappingProvider adds the symmetric key-wrap capability (the cloud-KMS
// shape); decryptingProvider adds the asymmetric KEK one (the PKCS#11 shape).
type wrappingProvider struct{ *hookedProvider }

func (p *wrappingProvider) WrapKey(_ context.Context, _ KeyRef, plaintext []byte) ([]byte, error) {
	p.note("wrap")
	return append([]byte("wrapped:"), plaintext...), nil
}

func (p *wrappingProvider) UnwrapKey(_ context.Context, _ KeyRef, ciphertext []byte) ([]byte, error) {
	p.note("unwrap")
	p.mu.Lock()
	p.unwrapIn = ciphertext
	p.mu.Unlock()
	return []byte("plain"), nil
}

type decryptingProvider struct{ *hookedProvider }

func (p *decryptingProvider) Decrypter(context.Context, KeyRef) (Decrypter, error) {
	return &hookedDecrypter{p: p.hookedProvider}, nil
}

type hookedSigner struct{ p *hookedProvider }

func (s *hookedSigner) Public() crypto.PublicKey { return s.p.key.Public() }
func (s *hookedSigner) KeyType() string          { return "ecdsa-p256" }
func (s *hookedSigner) Close() error             { return nil }

func (s *hookedSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.p.note("sign")
	s.p.mu.Lock()
	err := s.p.signErr
	s.p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, s.p.key, digest)
}

type hookedDecrypter struct{ p *hookedProvider }

func (d *hookedDecrypter) Public() crypto.PublicKey { return d.p.key.Public() }
func (d *hookedDecrypter) Close() error             { return nil }

func (d *hookedDecrypter) Decrypt(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) {
	d.p.note("decrypt")
	return []byte("plain"), nil
}

// countingRecorder is a SignatureRecorder that counts and can fail.
type countingRecorder struct {
	n    atomic.Int64
	fail error
}

func (r *countingRecorder) RecordSignature(context.Context, SignatureRecord) error {
	r.n.Add(1)
	return r.fail
}

func TestOnOperationFiresForEveryBackendOperation(t *testing.T) {
	ctx := context.Background()
	base := newHookedProvider(t)
	var hooks atomic.Int64

	p := Record(&wrappingProvider{base}, &countingRecorder{}, OnOperation(func() { hooks.Add(1) }))

	signer, err := p.Signer(ctx, KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	defer func() { _ = signer.Close() }()
	digest := make([]byte, 32)
	if _, err := signer.Sign(rand.Reader, digest, crypto.SHA256); err != nil {
		t.Fatalf("sign: %v", err)
	}

	kw, ok := p.(KeyWrapper)
	if !ok {
		t.Fatal("the recording wrapper masked the KeyWrapper capability")
	}
	if _, err := kw.WrapKey(ctx, KeyRef{Label: "kek"}, []byte("dek")); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := kw.UnwrapKey(ctx, KeyRef{Label: "kek"}, []byte("wrapped:dek")); err != nil {
		t.Fatalf("unwrap: %v", err)
	}

	rp, ok := p.(RandomProvider)
	if !ok {
		t.Fatal("the recording wrapper masked the RandomProvider capability")
	}
	if _, err := rp.Random(ctx, 16); err != nil {
		t.Fatalf("random: %v", err)
	}

	// Four operations reached the device, so four entries need collecting.
	if got := hooks.Load(); got != 4 {
		t.Fatalf("the drain hook fired %d time(s) for 4 backend operations (%v): "+
			"an operation whose entry nothing collects is one that sits in a volatile ring",
			got, base.reached())
	}
}

// A provider exposing DecrypterProvider takes a different wrapper branch than
// one exposing KeyWrapper, so the decryption path is asserted on its own — with
// the hook on Decrypt rather than on obtaining the Decrypter, since the former
// is what the device logs.
func TestOnOperationFiresForDecryption(t *testing.T) {
	ctx := context.Background()
	base := newHookedProvider(t)
	var hooks atomic.Int64

	p := Record(&decryptingProvider{base}, &countingRecorder{}, OnOperation(func() { hooks.Add(1) }))
	dp, ok := p.(DecrypterProvider)
	if !ok {
		t.Fatal("the recording wrapper masked the DecrypterProvider capability")
	}
	d, err := dp.Decrypter(ctx, KeyRef{Label: "kek"})
	if err != nil {
		t.Fatalf("decrypter: %v", err)
	}
	defer func() { _ = d.Close() }()

	if got := hooks.Load(); got != 0 {
		t.Fatalf("obtaining a Decrypter fired the drain hook %d time(s): it is a handle lookup, not a device operation", got)
	}
	if _, err := d.Decrypt(rand.Reader, []byte("ct"), nil); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got := hooks.Load(); got != 1 {
		t.Fatalf("the drain hook fired %d time(s) for one decryption, want 1", got)
	}
}

// A rejected signature still leaves a device log entry, so it still needs a
// drain. Firing only on success would leave exactly the entries an
// investigation cares about — failed attempts — uncollected until the backstop.
func TestOnOperationFiresForARejectedSignature(t *testing.T) {
	base := newHookedProvider(t)
	base.signErr = fmt.Errorf("device refused")
	var hooks atomic.Int64

	p := Record(base, &countingRecorder{}, OnOperation(func() { hooks.Add(1) }))
	signer, err := p.Signer(context.Background(), KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	defer func() { _ = signer.Close() }()

	if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("expected the signature to fail")
	}
	if got := hooks.Load(); got != 1 {
		t.Fatalf("the drain hook fired %d time(s) for a rejected signature, want 1", got)
	}
}

// A signature the ledger refuses is discarded (Task 167's fail-closed rule) —
// but the device produced it, so its log entry must still be collected.
func TestARejectedLedgerWriteStillDrainsTheDeviceLog(t *testing.T) {
	base := newHookedProvider(t)
	var hooks atomic.Int64

	p := Record(base, &countingRecorder{fail: fmt.Errorf("database down")},
		OnOperation(func() { hooks.Add(1) }))
	signer, err := p.Signer(context.Background(), KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	defer func() { _ = signer.Close() }()

	if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("a signature that could not be recorded must not be released")
	}
	if got := hooks.Load(); got != 1 {
		t.Fatalf("the drain hook fired %d time(s), want 1: the HSM signed, so the entry exists either way", got)
	}
}

// Record without the option must behave exactly as it did before Task 181, so a
// deployment with no device-log collector pays nothing for the mechanism.
func TestRecordWithoutTheHookIsUnchanged(t *testing.T) {
	base := newHookedProvider(t)
	rec := &countingRecorder{}
	p := Record(base, rec)

	signer, err := p.Signer(context.Background(), KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	defer func() { _ = signer.Close() }()
	if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := rec.n.Load(); got != 1 {
		t.Fatalf("ledger recorded %d signature(s), want 1", got)
	}
}
