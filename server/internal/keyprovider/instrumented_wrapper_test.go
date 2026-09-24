package keyprovider

// Tests for the instrumentation wrapper every key operation in the running
// system passes through (main.go wires it as recordHSMSignatures(Instrument(p))).
// Its whole job is to be transparent: add a metric and a span, change nothing
// else. A value it alters or an error it swallows turns a hardware failure into a
// silently wrong answer on the signing path, so these tests assert the wrapper's
// results are the wrapped provider's results, that errors come back matchable
// with errors.Is, that arguments arrive unmutated, and that the capability
// probing does not claim capabilities the wrapped provider lacks (the decrypt
// path type-asserts the inner provider without checking).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// errStub is the sentinel every failure case injects. The wrapper must hand it
// back such that errors.Is finds it: callers distinguish ErrKeyNotFound from a
// device failure that way, and a wrapped-beyond-recognition error makes a
// missing key look like a broken HSM (or the reverse).
var errStub = errors.New("stub: device refused")

// stubProvider is a Provider with every optional capability (Prober, KeyLister,
// RandomProvider) and canned, identifiable results. Setting fail makes every
// operation return errStub; setting nilResults makes them return (nil, nil), the
// shape a misbehaving backend produces and the wrapper must survive.
type stubProvider struct {
	mu sync.Mutex

	key *ecdsa.PrivateKey

	info      *KeyInfo
	list      []KeyDescriptor
	randomOut []byte
	sigOut    []byte
	plainOut  []byte

	fail       error
	nilResults bool

	calls     []string
	gotSpec   KeySpec
	gotRefs   []KeyRef
	gotDigest []byte
	gotOpts   crypto.SignerOpts
	gotRand   io.Reader
	gotN      int
	gotMsg    []byte
	closed    bool
}

func newStubProvider(t *testing.T) *stubProvider {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating stub key: %v", err)
	}
	return &stubProvider{
		key:       k,
		info:      &KeyInfo{Label: "ca", ID: "07", KeyType: KeyTypeECDSAP256, URI: "stub:ca"},
		list:      []KeyDescriptor{{Label: "ca", ID: "07", KeyType: KeyTypeECDSAP256, URI: "stub:ca"}},
		randomOut: []byte{0xde, 0xad, 0xbe, 0xef},
		sigOut:    []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
		plainOut:  []byte("the plaintext dek"),
	}
}

func (p *stubProvider) note(op string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, op)
}

func (p *stubProvider) called() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func (p *stubProvider) Name() string { return "stub" }

func (p *stubProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.calls = append(p.calls, "close")
	return p.fail
}

func (p *stubProvider) GenerateKey(_ context.Context, spec KeySpec) (*KeyInfo, error) {
	p.note("generate")
	p.mu.Lock()
	p.gotSpec = spec
	p.mu.Unlock()
	if p.fail != nil {
		return nil, p.fail
	}
	if p.nilResults {
		return nil, nil
	}
	return p.info, nil
}

func (p *stubProvider) FindKey(_ context.Context, ref KeyRef) (*KeyInfo, error) {
	p.note("find")
	p.recordRef(ref)
	if p.fail != nil {
		return nil, p.fail
	}
	if p.nilResults {
		return nil, nil
	}
	return p.info, nil
}

func (p *stubProvider) PublicKey(_ context.Context, ref KeyRef) (crypto.PublicKey, error) {
	p.note("public_key")
	p.recordRef(ref)
	if p.fail != nil {
		return nil, p.fail
	}
	if p.nilResults {
		return nil, nil
	}
	return p.key.Public(), nil
}

func (p *stubProvider) Signer(_ context.Context, ref KeyRef) (Signer, error) {
	p.note("signer")
	p.recordRef(ref)
	if p.fail != nil {
		return nil, p.fail
	}
	if p.nilResults {
		return nil, nil
	}
	return &stubSigner{p: p}, nil
}

func (p *stubProvider) ListKeys(context.Context) ([]KeyDescriptor, error) {
	p.note("list")
	if p.fail != nil {
		return nil, p.fail
	}
	if p.nilResults {
		return nil, nil
	}
	return p.list, nil
}

func (p *stubProvider) Random(_ context.Context, n int) ([]byte, error) {
	p.note("random")
	p.mu.Lock()
	p.gotN = n
	p.mu.Unlock()
	if p.fail != nil {
		return nil, p.fail
	}
	if p.nilResults {
		return nil, nil
	}
	return p.randomOut, nil
}

func (p *stubProvider) Ping(context.Context) error {
	p.note("ping")
	return p.fail
}

func (p *stubProvider) recordRef(ref KeyRef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gotRefs = append(p.gotRefs, ref)
}

type stubSigner struct{ p *stubProvider }

func (s *stubSigner) Public() crypto.PublicKey { return s.p.key.Public() }
func (s *stubSigner) KeyType() string          { return KeyTypeECDSAP256 }
func (s *stubSigner) Close() error             { return nil }

func (s *stubSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.p.note("sign")
	s.p.mu.Lock()
	s.p.gotDigest = digest
	s.p.gotOpts = opts
	s.p.gotRand = r
	s.p.mu.Unlock()
	if s.p.fail != nil {
		return nil, s.p.fail
	}
	if s.p.nilResults {
		return nil, nil
	}
	return s.p.sigOut, nil
}

// stubDecrypterProvider adds the asymmetric-KEK capability, the branch Instrument
// selects for the software and PKCS#11 backends.
type stubDecrypterProvider struct{ *stubProvider }

func (p *stubDecrypterProvider) Decrypter(context.Context, KeyRef) (Decrypter, error) {
	p.note("decrypter")
	if p.fail != nil {
		return nil, p.fail
	}
	if p.nilResults {
		return nil, nil
	}
	return &stubDecrypter{p: p.stubProvider}, nil
}

type stubDecrypter struct{ p *stubProvider }

func (d *stubDecrypter) Public() crypto.PublicKey { return d.p.key.Public() }
func (d *stubDecrypter) Close() error             { return nil }

func (d *stubDecrypter) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	d.p.note("decrypt")
	d.p.mu.Lock()
	d.p.gotMsg = msg
	d.p.gotRand = r
	d.p.mu.Unlock()
	if d.p.fail != nil {
		return nil, d.p.fail
	}
	if d.p.nilResults {
		return nil, nil
	}
	return d.p.plainOut, nil
}

// bareProvider implements Provider and nothing else: no Ping, no ListKeys, no
// Random, no Decrypter. It is the shape that proves the wrapper's capability
// probes are real probes.
type bareProvider struct{ pub crypto.PublicKey }

func (p *bareProvider) Name() string { return "bare" }
func (p *bareProvider) Close() error { return nil }
func (p *bareProvider) GenerateKey(context.Context, KeySpec) (*KeyInfo, error) {
	return &KeyInfo{Label: "k"}, nil
}
func (p *bareProvider) FindKey(context.Context, KeyRef) (*KeyInfo, error) {
	return &KeyInfo{Label: "k"}, nil
}
func (p *bareProvider) PublicKey(context.Context, KeyRef) (crypto.PublicKey, error) {
	return p.pub, nil
}
func (p *bareProvider) Signer(context.Context, KeyRef) (Signer, error) {
	return nil, errors.New("bare: no signer")
}

// ---------------------------------------------------------------------------
// transparency on the success path
// ---------------------------------------------------------------------------

// TestInstrumentedProviderReturnsTheWrappedResults asserts the wrapper hands back
// exactly what the provider produced — same *KeyInfo, same public key, same
// descriptor slice, same signature and plaintext bytes — for every operation.
func TestInstrumentedProviderReturnsTheWrappedResults(t *testing.T) {
	ctx := context.Background()
	base := newStubProvider(t)
	wrapped := Instrument(&stubDecrypterProvider{base})

	if got := wrapped.Name(); got != base.Name() {
		t.Errorf("Name() = %q, want %q", got, base.Name())
	}

	info, err := wrapped.GenerateKey(ctx, KeySpec{Label: "ca", KeyType: KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if info != base.info {
		t.Errorf("GenerateKey returned %+v, want the provider's own *KeyInfo %+v", info, base.info)
	}

	if info, err = wrapped.FindKey(ctx, KeyRef{Label: "ca"}); err != nil || info != base.info {
		t.Errorf("FindKey = (%+v, %v), want the provider's own *KeyInfo", info, err)
	}

	pub, err := wrapped.PublicKey(ctx, KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !pub.(*ecdsa.PublicKey).Equal(base.key.Public()) {
		t.Error("PublicKey returned a different key than the provider did")
	}

	kl, ok := wrapped.(KeyLister)
	if !ok {
		t.Fatal("wrapped provider does not expose KeyLister")
	}
	keys, err := kl.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0] != base.list[0] {
		t.Errorf("ListKeys = %+v, want %+v", keys, base.list)
	}

	rp, ok := wrapped.(RandomProvider)
	if !ok {
		t.Fatal("wrapped provider does not expose RandomProvider")
	}
	b, err := rp.Random(ctx, 4)
	if err != nil {
		t.Fatalf("Random: %v", err)
	}
	if string(b) != string(base.randomOut) {
		t.Errorf("Random = %x, want %x", b, base.randomOut)
	}
	if base.gotN != 4 {
		t.Errorf("provider saw n = %d, want 4", base.gotN)
	}

	signer, err := wrapped.Signer(ctx, KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer func() { _ = signer.Close() }()
	// The wrapper wraps the signer, so the embedded methods must still reach the
	// real one: a Public() that answered nil would break every certificate.
	if !signer.Public().(*ecdsa.PublicKey).Equal(base.key.Public()) {
		t.Error("wrapped Signer.Public() is not the provider's public key")
	}
	if got := signer.KeyType(); got != KeyTypeECDSAP256 {
		t.Errorf("wrapped Signer.KeyType() = %q, want %q", got, KeyTypeECDSAP256)
	}
	digest := make([]byte, 32)
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(sig) != string(base.sigOut) {
		t.Errorf("Sign = %x, want the provider's bytes %x", sig, base.sigOut)
	}

	dp, ok := wrapped.(DecrypterProvider)
	if !ok {
		t.Fatal("wrapped provider does not expose DecrypterProvider")
	}
	d, err := dp.Decrypter(ctx, KeyRef{Label: "kek"})
	if err != nil {
		t.Fatalf("Decrypter: %v", err)
	}
	defer func() { _ = d.Close() }()
	if !d.Public().(*ecdsa.PublicKey).Equal(base.key.Public()) {
		t.Error("wrapped Decrypter.Public() is not the provider's public key")
	}
	pt, err := d.Decrypt(rand.Reader, []byte("ciphertext"), nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(base.plainOut) {
		t.Errorf("Decrypt = %q, want the provider's plaintext %q", pt, base.plainOut)
	}

	// Close must reach the backend; a swallowed Close leaks PKCS#11 sessions.
	if err := wrapped.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if !base.closed {
		t.Error("Close did not reach the wrapped provider")
	}
}

// TestInstrumentedProviderPropagatesErrors injects one sentinel and requires
// every operation to return it unchanged and matchable with errors.Is, with a nil
// result alongside. A wrapper that returned a value *and* an error, or an error
// callers cannot match, is the failure mode that turns an HSM outage into a
// wrong answer.
func TestInstrumentedProviderPropagatesErrors(t *testing.T) {
	ctx := context.Background()
	base := newStubProvider(t)
	base.fail = fmt.Errorf("pkcs11: %w", errStub) // wrapped once, as a real backend would
	wrapped := Instrument(&stubDecrypterProvider{base})

	if info, err := wrapped.GenerateKey(ctx, KeySpec{Label: "ca"}); !errors.Is(err, errStub) || info != nil {
		t.Errorf("GenerateKey = (%v, %v), want (nil, errStub)", info, err)
	}
	if info, err := wrapped.FindKey(ctx, KeyRef{Label: "ca"}); !errors.Is(err, errStub) || info != nil {
		t.Errorf("FindKey = (%v, %v), want (nil, errStub)", info, err)
	}
	if pub, err := wrapped.PublicKey(ctx, KeyRef{Label: "ca"}); !errors.Is(err, errStub) || pub != nil {
		t.Errorf("PublicKey = (%v, %v), want (nil, errStub)", pub, err)
	}
	if s, err := wrapped.Signer(ctx, KeyRef{Label: "ca"}); !errors.Is(err, errStub) || s != nil {
		t.Errorf("Signer = (%v, %v), want (nil, errStub)", s, err)
	}
	if keys, err := wrapped.(KeyLister).ListKeys(ctx); !errors.Is(err, errStub) || keys != nil {
		t.Errorf("ListKeys = (%v, %v), want (nil, errStub)", keys, err)
	}
	if b, err := wrapped.(RandomProvider).Random(ctx, 8); !errors.Is(err, errStub) || b != nil {
		t.Errorf("Random = (%x, %v), want (nil, errStub)", b, err)
	}
	if err := wrapped.(Prober).Ping(ctx); !errors.Is(err, errStub) {
		t.Errorf("Ping = %v, want errStub", err)
	}
	if d, err := wrapped.(DecrypterProvider).Decrypter(ctx, KeyRef{Label: "kek"}); !errors.Is(err, errStub) || d != nil {
		t.Errorf("Decrypter = (%v, %v), want (nil, errStub)", d, err)
	}
	if err := wrapped.Close(); !errors.Is(err, errStub) {
		t.Errorf("Close = %v, want errStub", err)
	}

	// A signer obtained before the device broke must still surface the failure.
	base.fail = nil
	signer, err := wrapped.Signer(ctx, KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	dp, err := wrapped.(DecrypterProvider).Decrypter(ctx, KeyRef{Label: "kek"})
	if err != nil {
		t.Fatalf("Decrypter: %v", err)
	}
	base.fail = fmt.Errorf("pkcs11: %w", errStub)
	if sig, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, errStub) || sig != nil {
		t.Errorf("Sign = (%x, %v), want (nil, errStub)", sig, err)
	}
	if pt, err := dp.Decrypt(rand.Reader, []byte("ct"), nil); !errors.Is(err, errStub) || pt != nil {
		t.Errorf("Decrypt = (%x, %v), want (nil, errStub)", pt, err)
	}
}

// TestInstrumentedProviderDoesNotMutateArguments: the wrapper reads the label out
// of the spec/ref for its span attributes, and must not alter what the backend
// then receives — nor the caller's digest buffer, which the caller may reuse.
func TestInstrumentedProviderDoesNotMutateArguments(t *testing.T) {
	ctx := context.Background()
	base := newStubProvider(t)
	wrapped := Instrument(&stubDecrypterProvider{base})

	slot := uint(3)
	spec := KeySpec{Label: "ca-root", ID: "0a0b", KeyType: KeyTypeRSA3072, Usage: KeyUsageDecrypt}
	specCopy := spec
	if _, err := wrapped.GenerateKey(ctx, spec); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if spec != specCopy {
		t.Errorf("GenerateKey mutated the caller's KeySpec: %+v != %+v", spec, specCopy)
	}
	if base.gotSpec != specCopy {
		t.Errorf("provider received %+v, want %+v", base.gotSpec, specCopy)
	}

	ref := KeyRef{Label: "ca-root", ID: "0a0b", Token: TokenSelector{Serial: "X1", SlotID: &slot}}
	refCopy := ref
	for _, call := range []struct {
		name string
		fn   func(KeyRef) error
	}{
		{"FindKey", func(r KeyRef) error { _, err := wrapped.FindKey(ctx, r); return err }},
		{"PublicKey", func(r KeyRef) error { _, err := wrapped.PublicKey(ctx, r); return err }},
		{"Signer", func(r KeyRef) error { _, err := wrapped.Signer(ctx, r); return err }},
	} {
		if err := call.fn(ref); err != nil {
			t.Fatalf("%s: %v", call.name, err)
		}
		if ref != refCopy {
			t.Errorf("%s mutated the caller's KeyRef: %+v != %+v", call.name, ref, refCopy)
		}
	}
	for i, got := range base.gotRefs {
		if got != refCopy {
			t.Errorf("call %d received KeyRef %+v, want %+v", i, got, refCopy)
		}
	}
	if *ref.Token.SlotID != 3 {
		t.Errorf("the token selector's slot id changed to %d", *ref.Token.SlotID)
	}

	signer, err := wrapped.Signer(ctx, ref)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	digest := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	want := string(digest)
	if _, err := signer.Sign(rand.Reader, digest, crypto.SHA384); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(digest) != want {
		t.Errorf("Sign mutated the caller's digest: %x, want %x", digest, want)
	}
	if string(base.gotDigest) != want {
		t.Errorf("provider received digest %x, want %x", base.gotDigest, want)
	}
	if base.gotOpts != crypto.SignerOpts(crypto.SHA384) {
		t.Errorf("provider received opts %v, want SHA-384: a rewritten hash signs with the wrong algorithm", base.gotOpts)
	}
	if base.gotRand != rand.Reader {
		t.Error("provider received a different entropy source than the caller passed")
	}

	d, err := wrapped.(DecrypterProvider).Decrypter(ctx, ref)
	if err != nil {
		t.Fatalf("Decrypter: %v", err)
	}
	ct := []byte("wrapped-dek")
	if _, err := d.Decrypt(rand.Reader, ct, nil); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(ct) != "wrapped-dek" || string(base.gotMsg) != "wrapped-dek" {
		t.Errorf("Decrypt altered the ciphertext: caller has %q, provider saw %q", ct, base.gotMsg)
	}
}

// TestInstrumentedProviderSurvivesNilResults: a backend that answers (nil, nil)
// is broken, but the wrapper must pass that through rather than panic on it
// while recording a metric. A panic here takes the server down.
func TestInstrumentedProviderSurvivesNilResults(t *testing.T) {
	ctx := context.Background()
	base := newStubProvider(t)
	base.nilResults = true
	wrapped := Instrument(&stubDecrypterProvider{base})

	if info, err := wrapped.GenerateKey(ctx, KeySpec{Label: "ca"}); info != nil || err != nil {
		t.Errorf("GenerateKey = (%v, %v), want (nil, nil)", info, err)
	}
	if info, err := wrapped.FindKey(ctx, KeyRef{Label: "ca"}); info != nil || err != nil {
		t.Errorf("FindKey = (%v, %v), want (nil, nil)", info, err)
	}
	if pub, err := wrapped.PublicKey(ctx, KeyRef{Label: "ca"}); pub != nil || err != nil {
		t.Errorf("PublicKey = (%v, %v), want (nil, nil)", pub, err)
	}
	if keys, err := wrapped.(KeyLister).ListKeys(ctx); keys != nil || err != nil {
		t.Errorf("ListKeys = (%v, %v), want (nil, nil)", keys, err)
	}
	if b, err := wrapped.(RandomProvider).Random(ctx, 4); b != nil || err != nil {
		t.Errorf("Random = (%x, %v), want (nil, nil)", b, err)
	}
	// Signer/Decrypter return a wrapper around the nil handle; obtaining one must
	// not panic (using it is the broken backend's fault, not the wrapper's).
	if s, err := wrapped.Signer(ctx, KeyRef{Label: "ca"}); err != nil {
		t.Errorf("Signer = (%v, %v), want no error", s, err)
	}
	if d, err := wrapped.(DecrypterProvider).Decrypter(ctx, KeyRef{Label: "kek"}); err != nil {
		t.Errorf("Decrypter = (%v, %v), want no error", d, err)
	}
}

// TestInstrumentedSignerWithoutAContextDoesNotPanic covers the nil-context guard
// in the signer and decrypter. Both start a span from a context captured earlier,
// and starting a span from a nil context panics — so the guard is the difference
// between a degraded trace and a crashed signing request.
func TestInstrumentedSignerWithoutAContextDoesNotPanic(t *testing.T) {
	base := newStubProvider(t)
	signer := &instrumentedSigner{Signer: &stubSigner{p: base}, label: "ca", provider: base.Name()}
	sig, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign with a nil context: %v", err)
	}
	if string(sig) != string(base.sigOut) {
		t.Errorf("Sign = %x, want %x", sig, base.sigOut)
	}

	dec := &instrumentedDecrypter{Decrypter: &stubDecrypter{p: base}, label: "kek", provider: base.Name()}
	pt, err := dec.Decrypt(rand.Reader, []byte("ct"), nil)
	if err != nil {
		t.Fatalf("Decrypt with a nil context: %v", err)
	}
	if string(pt) != string(base.plainOut) {
		t.Errorf("Decrypt = %q, want %q", pt, base.plainOut)
	}
}

// ---------------------------------------------------------------------------
// capability probing
// ---------------------------------------------------------------------------

// TestInstrumentedProviderReportsMissingCapabilities: ListKeys, Random and Ping
// exist on the wrapper unconditionally, so they must report the wrapped
// provider's missing capability as an error. Returning an empty list and no error
// would make "this backend cannot enumerate keys" look like "this backend holds
// no keys" — a disaster-recovery check that silently passes.
func TestInstrumentedProviderReportsMissingCapabilities(t *testing.T) {
	ctx := context.Background()
	wrapped := Instrument(&bareProvider{})

	keys, err := wrapped.(KeyLister).ListKeys(ctx)
	if err == nil {
		t.Errorf("ListKeys on a provider without KeyLister = %+v, want an error", keys)
	}
	if keys != nil {
		t.Errorf("ListKeys returned %+v alongside the error", keys)
	}
	b, err := wrapped.(RandomProvider).Random(ctx, 16)
	if !errors.Is(err, ErrRandomUnsupported) {
		t.Errorf("Random = (%x, %v), want ErrRandomUnsupported", b, err)
	}
	if b != nil {
		t.Errorf("Random returned %x alongside the error: the caller must fall back to crypto/rand, not use this", b)
	}
	if err := wrapped.(Prober).Ping(ctx); !errors.Is(err, ErrProbeUnsupported) {
		t.Errorf("Ping = %v, want ErrProbeUnsupported", err)
	}
}

// TestInstrumentDoesNotInventCapabilities: the decrypt and wrap branches
// type-assert the wrapped provider without checking (instrumented.go:189, :231),
// so claiming a capability the provider lacks would panic on the envelope
// decryption path instead of returning "unsupported".
func TestInstrumentDoesNotInventCapabilities(t *testing.T) {
	bare := Instrument(&bareProvider{})
	if _, ok := bare.(DecrypterProvider); ok {
		t.Error("wrapping a provider with no Decrypter advertised DecrypterProvider: the unchecked assertion would panic")
	}
	if _, ok := bare.(KeyWrapper); ok {
		t.Error("wrapping a provider with no WrapKey advertised KeyWrapper")
	}

	dec := Instrument(&stubDecrypterProvider{newStubProvider(t)})
	if _, ok := dec.(DecrypterProvider); !ok {
		t.Error("wrapping a DecrypterProvider dropped the capability")
	}
	if _, ok := dec.(KeyWrapper); ok {
		t.Error("wrapping a DecrypterProvider invented KeyWrapper")
	}
}

// TestInstrumentCapabilitiesAreMutuallyExclusiveInPractice holds the premise
// Instrument documents and relies on: it installs at most one capability
// extension, so a provider implementing both DecrypterProvider and KeyWrapper
// would silently lose its wrapping. Check the providers that can be constructed
// without hardware or credentials.
func TestInstrumentCapabilitiesAreMutuallyExclusiveInPractice(t *testing.T) {
	sw, err := NewSoftwareProvider(SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	defer func() { _ = sw.Close() }()
	kms, err := NewKMSProvider(KMSSettings{Backend: KMSBackendFake})
	if err != nil {
		t.Fatalf("NewKMSProvider: %v", err)
	}
	defer func() { _ = kms.Close() }()

	for _, p := range []Provider{sw, kms} {
		_, dec := p.(DecrypterProvider)
		_, wrap := p.(KeyWrapper)
		if dec && wrap {
			t.Errorf("provider %q implements both DecrypterProvider and KeyWrapper; Instrument keeps only the former",
				p.Name())
		}
		// Whichever one it has must survive wrapping.
		wrapped := Instrument(p)
		if _, ok := wrapped.(DecrypterProvider); dec != ok {
			t.Errorf("provider %q: DecrypterProvider present=%v, after Instrument=%v", p.Name(), dec, ok)
		}
		if _, ok := wrapped.(KeyWrapper); wrap != ok {
			t.Errorf("provider %q: KeyWrapper present=%v, after Instrument=%v", p.Name(), wrap, ok)
		}
	}
}

// ---------------------------------------------------------------------------
// metrics and spans
// ---------------------------------------------------------------------------

// hsmOpCount reads one secsy_hsm_operations_total series out of the rendered
// exposition text. A series with no observations yet reads 0.
func hsmOpCount(t *testing.T, text, operation, result string) float64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^secsy_hsm_operations_total\{operation="` + regexp.QuoteMeta(operation) +
		`",result="` + regexp.QuoteMeta(result) + `"\} ([0-9.eE+-]+)$`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("parsing counter value %q: %v", m[1], err)
	}
	return v
}

// TestInstrumentedProviderCountsEveryOperation is the point of the wrapper: each
// operation must land on its own metric series with the right outcome. An
// operation charged to the wrong label (or to no label) is an operation whose
// failure rate no alert can see.
func TestInstrumentedProviderCountsEveryOperation(t *testing.T) {
	ctx := context.Background()
	base := newStubProvider(t)
	wrapped := Instrument(&stubDecrypterProvider{base})

	type op struct {
		name string
		run  func() error
		// failing builds the closure for the error case. It runs while the device
		// is still healthy, so operations that need a handle (Sign needs a Signer,
		// Decrypt needs a Decrypter) can acquire it before the failure is injected —
		// otherwise the acquisition fails first and the operation under test never
		// happens.
		failing func(t *testing.T) func() error
	}
	ops := []op{
		{name: "generate", run: func() error { _, err := wrapped.GenerateKey(ctx, KeySpec{Label: "ca"}); return err }},
		{name: "find", run: func() error { _, err := wrapped.FindKey(ctx, KeyRef{Label: "ca"}); return err }},
		{name: "public_key", run: func() error { _, err := wrapped.PublicKey(ctx, KeyRef{Label: "ca"}); return err }},
		{name: "signer", run: func() error { _, err := wrapped.Signer(ctx, KeyRef{Label: "ca"}); return err }},
		{name: "list", run: func() error { _, err := wrapped.(KeyLister).ListKeys(ctx); return err }},
		{name: "random", run: func() error { _, err := wrapped.(RandomProvider).Random(ctx, 4); return err }},
		{name: "ping", run: func() error { return wrapped.(Prober).Ping(ctx) }},
		{name: "sign", run: func() error {
			s, err := wrapped.Signer(ctx, KeyRef{Label: "ca"})
			if err != nil {
				return err
			}
			_, err = s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
			return err
		}, failing: func(t *testing.T) func() error {
			s, err := wrapped.Signer(ctx, KeyRef{Label: "ca"})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			return func() error {
				_, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
				return err
			}
		}},
		{name: "decrypt", run: func() error {
			d, err := wrapped.(DecrypterProvider).Decrypter(ctx, KeyRef{Label: "kek"})
			if err != nil {
				return err
			}
			_, err = d.Decrypt(rand.Reader, []byte("ct"), nil)
			return err
		}, failing: func(t *testing.T) func() error {
			d, err := wrapped.(DecrypterProvider).Decrypter(ctx, KeyRef{Label: "kek"})
			if err != nil {
				t.Fatalf("Decrypter: %v", err)
			}
			return func() error {
				_, err := d.Decrypt(rand.Reader, []byte("ct"), nil)
				return err
			}
		}},
	}

	for _, o := range ops {
		t.Run(o.name+"/success", func(t *testing.T) {
			base.fail = nil
			before := hsmOpCount(t, renderMetrics(t), o.name, "success")
			if err := o.run(); err != nil {
				t.Fatalf("%s: %v", o.name, err)
			}
			after := hsmOpCount(t, renderMetrics(t), o.name, "success")
			if after < before+1 {
				t.Errorf("secsy_hsm_operations_total{operation=%q,result=\"success\"} went %v -> %v, want at least +1",
					o.name, before, after)
			}
		})
	}
	for _, o := range ops {
		t.Run(o.name+"/error", func(t *testing.T) {
			run := o.run
			if o.failing != nil {
				run = o.failing(t) // acquire the handle while the device still works
			}
			base.fail = errStub
			defer func() { base.fail = nil }() // never leak the failure into the next subtest
			before := hsmOpCount(t, renderMetrics(t), o.name, "error")
			if err := run(); !errors.Is(err, errStub) {
				t.Fatalf("%s returned %v, want errStub", o.name, err)
			}
			after := hsmOpCount(t, renderMetrics(t), o.name, "error")
			if after < before+1 {
				t.Errorf("secsy_hsm_operations_total{operation=%q,result=\"error\"} went %v -> %v, want at least +1",
					o.name, before, after)
			}
		})
	}

	// Failing to obtain the Decrypter is charged to the decrypt path too
	// (instrumented.go:192): otherwise a KEK that cannot even be opened produces
	// no decrypt error at all, and the envelope-decryption failure rate reads zero
	// while nothing can be decrypted.
	t.Run("decrypter acquisition failure counts as a decrypt error", func(t *testing.T) {
		base.fail = errStub
		defer func() { base.fail = nil }()
		before := hsmOpCount(t, renderMetrics(t), "decrypt", "error")
		if _, err := wrapped.(DecrypterProvider).Decrypter(ctx, KeyRef{Label: "kek"}); !errors.Is(err, errStub) {
			t.Fatalf("Decrypter = %v, want errStub", err)
		}
		if after := hsmOpCount(t, renderMetrics(t), "decrypt", "error"); after < before+1 {
			t.Errorf("secsy_hsm_operations_total{operation=\"decrypt\",result=\"error\"} went %v -> %v, want at least +1",
				before, after)
		}
	})
}

// TestInstrumentedSignAttachesToTheCallersTrace pins the deliberate choice at
// instrumented.go:148: the signer carries the *caller's* context, not the
// (already ended) signer-acquisition span's context, so every Sign lands on the
// live request trace. Attaching to the ended span instead produces orphaned or
// invisible sign spans — the exact latency operators come looking for.
func TestInstrumentedSignAttachesToTheCallersTrace(t *testing.T) {
	exp := installRecordingTracer(t)
	base := newStubProvider(t)
	wrapped := Instrument(base)

	ctx, root := otel.Tracer("test").Start(context.Background(), "request")
	signer, err := wrapped.Signer(ctx, KeyRef{Label: "ca"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Fail the next signature so the span's error status can be checked too.
	base.fail = errStub
	if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); !errors.Is(err, errStub) {
		t.Fatalf("Sign after failure injection = %v, want errStub", err)
	}
	root.End()

	spans := exp.GetSpans()
	byName := map[string][]tracetest.SpanStub{}
	for _, s := range spans {
		byName[s.Name] = append(byName[s.Name], s)
	}
	signerSpans := byName["hsm.signer"]
	signSpans := byName["hsm.sign"]
	if len(signerSpans) != 1 {
		t.Fatalf("recorded %d hsm.signer spans, want 1 (spans: %v)", len(signerSpans), spans.Snapshots())
	}
	if len(signSpans) != 2 {
		t.Fatalf("recorded %d hsm.sign spans, want 2", len(signSpans))
	}
	rootID := root.SpanContext().SpanID()
	for i, s := range signSpans {
		if s.Parent.SpanID() != rootID {
			t.Errorf("hsm.sign[%d] parent = %v, want the caller's span %v (the signer-acquisition span was %v)",
				i, s.Parent.SpanID(), rootID, signerSpans[0].SpanContext.SpanID())
		}
		if s.SpanContext.TraceID() != root.SpanContext().TraceID() {
			t.Errorf("hsm.sign[%d] is on trace %v, not the request's trace %v",
				i, s.SpanContext.TraceID(), root.SpanContext().TraceID())
		}
	}
	if got := signSpans[0].Status.Code; got == codes.Error {
		t.Errorf("the successful signature's span is marked %v", got)
	}
	if got := signSpans[1].Status.Code; got != codes.Error {
		t.Errorf("the failed signature's span status = %v, want Error: a failure the trace does not show", got)
	}
}

// TestInstrumentedProviderSpansCarryTheKeyLabel checks the attributes the
// operation spans are searched by. A missing provider/label attribute makes a
// trace useless for answering "which key was slow".
func TestInstrumentedProviderSpansCarryTheKeyLabel(t *testing.T) {
	exp := installRecordingTracer(t)
	ctx := context.Background()
	base := newStubProvider(t)
	wrapped := Instrument(&stubDecrypterProvider{base})

	if _, err := wrapped.GenerateKey(ctx, KeySpec{Label: "ca-root", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := wrapped.FindKey(ctx, KeyRef{Label: "ca-root"}); err != nil {
		t.Fatalf("FindKey: %v", err)
	}
	if _, err := wrapped.PublicKey(ctx, KeyRef{Label: "ca-root"}); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	want := map[string]string{
		"hsm.generate_key": "generate",
		"hsm.find_key":     "find",
		"hsm.public_key":   "public_key",
	}
	seen := map[string]bool{}
	for _, s := range exp.GetSpans() {
		wantOp, ok := want[s.Name]
		if !ok {
			continue
		}
		seen[s.Name] = true
		attrs := map[string]string{}
		for _, a := range s.Attributes {
			attrs[string(a.Key)] = a.Value.AsString()
		}
		if attrs["hsm.operation"] != wantOp {
			t.Errorf("%s hsm.operation = %q, want %q", s.Name, attrs["hsm.operation"], wantOp)
		}
		if attrs["hsm.key.label"] != "ca-root" {
			t.Errorf("%s hsm.key.label = %q, want %q", s.Name, attrs["hsm.key.label"], "ca-root")
		}
		if attrs["hsm.provider"] != base.Name() {
			t.Errorf("%s hsm.provider = %q, want %q", s.Name, attrs["hsm.provider"], base.Name())
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("no %s span was recorded", name)
		}
	}
}

// TestInstrumentedProviderConcurrentOperations runs every instrumented path from
// many goroutines at once. The wrapper's metric and span bookkeeping sits on the
// hot path of a CA that signs concurrently, so a data race here is a production
// crash; this is the case -race exists to catch.
func TestInstrumentedProviderConcurrentOperations(t *testing.T) {
	ctx := context.Background()
	base := newStubProvider(t)
	wrapped := Instrument(&stubDecrypterProvider{base})

	const goroutines, iterations = 12, 20
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*iterations*4)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			label := fmt.Sprintf("key-%d", g)
			for i := 0; i < iterations; i++ {
				if _, err := wrapped.GenerateKey(ctx, KeySpec{Label: label, KeyType: KeyTypeECDSAP256}); err != nil {
					errCh <- err
				}
				if _, err := wrapped.FindKey(ctx, KeyRef{Label: label}); err != nil {
					errCh <- err
				}
				if _, err := wrapped.PublicKey(ctx, KeyRef{Label: label}); err != nil {
					errCh <- err
				}
				if _, err := wrapped.(KeyLister).ListKeys(ctx); err != nil {
					errCh <- err
				}
				if _, err := wrapped.(RandomProvider).Random(ctx, 8); err != nil {
					errCh <- err
				}
				if err := wrapped.(Prober).Ping(ctx); err != nil {
					errCh <- err
				}
				s, err := wrapped.Signer(ctx, KeyRef{Label: label})
				if err != nil {
					errCh <- err
					continue
				}
				if _, err := s.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err != nil {
					errCh <- err
				}
				if err := s.Close(); err != nil {
					errCh <- err
				}
				d, err := wrapped.(DecrypterProvider).Decrypter(ctx, KeyRef{Label: label})
				if err != nil {
					errCh <- err
					continue
				}
				if _, err := d.Decrypt(rand.Reader, []byte("ct"), nil); err != nil {
					errCh <- err
				}
				if err := d.Close(); err != nil {
					errCh <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent operation failed: %v", err)
	}
	// Ten backend calls per iteration: generate, find, public_key, list, random,
	// ping, signer, sign, decrypter, decrypt. A lost call means the wrapper
	// short-circuited something under concurrency.
	if got, want := len(base.called()), goroutines*iterations*10; got != want {
		t.Errorf("backend saw %d operations, want %d", got, want)
	}
}
