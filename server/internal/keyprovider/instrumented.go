package keyprovider

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// Instrument wraps a Provider so every key operation records latency and
// success/error metrics via the metrics package. The wrapper is transparent: it
// preserves the Provider contract and, when the underlying provider supports
// decryption (DecrypterProvider), the wrapper does too — so envelope decryption
// continues to work through the same type assertion callers already use.
//
// Metric operation labels: generate, find, signer, public_key, sign, decrypt,
// wrap, unwrap. "signer"/"sign" are distinct because obtaining a Signer (which
// may open a PKCS#11 session and locate the key) and performing the actual
// C_Sign are separately interesting latencies on an HSM.
//
// DecrypterProvider (software/pkcs11, RSA-OAEP KEK) and KeyWrapper (Vault
// Transit, symmetric KEK) are mutually exclusive in practice — no provider
// implements both — so the wrapper selects at most one capability extension.
func Instrument(p Provider) Provider {
	if p == nil {
		return nil
	}
	ip := &instrumentedProvider{Provider: p}
	if _, ok := p.(DecrypterProvider); ok {
		return &instrumentedDecrypterProvider{instrumentedProvider: ip}
	}
	if _, ok := p.(KeyWrapper); ok {
		return &instrumentedKeyWrapperProvider{instrumentedProvider: ip}
	}
	return ip
}

type instrumentedProvider struct {
	Provider
}

// Ping delegates to the wrapped provider's Prober implementation so the
// readiness probe still reaches the HSM through the instrumented wrapper. The
// embedded Provider interface does not surface Ping, hence this explicit
// forward. Probe latency/outcome is recorded under the "ping" operation.
func (p *instrumentedProvider) Ping(ctx context.Context) error {
	pr, ok := p.Provider.(Prober)
	if !ok {
		return ErrProbeUnsupported
	}
	start := time.Now()
	err := pr.Ping(ctx)
	metrics.ObserveHSM("ping", start, err)
	return err
}

// ListKeys forwards to the wrapped provider's KeyLister implementation so the
// inventory capability survives the instrumented wrapper (the embedded Provider
// interface does not surface ListKeys). Returns ErrProbeUnsupported's sibling
// behavior — a nil list and no error would hide a missing capability, so we
// surface an explicit error instead.
func (p *instrumentedProvider) ListKeys(ctx context.Context) ([]KeyDescriptor, error) {
	kl, ok := p.Provider.(KeyLister)
	if !ok {
		return nil, fmt.Errorf("keyprovider: provider does not support key listing")
	}
	start := time.Now()
	keys, err := kl.ListKeys(ctx)
	metrics.ObserveHSM("list", start, err)
	return keys, err
}

func (p *instrumentedProvider) GenerateKey(ctx context.Context, spec KeySpec) (*KeyInfo, error) {
	ctx, span := tracing.Start(ctx, "hsm.generate_key",
		attribute.String("hsm.operation", "generate"),
		attribute.String("hsm.key.label", spec.Label),
		attribute.String("hsm.provider", p.Name()))
	defer span.End()
	start := time.Now()
	info, err := p.Provider.GenerateKey(ctx, spec)
	metrics.ObserveHSM("generate", start, err)
	tracing.RecordError(ctx, err)
	return info, err
}

func (p *instrumentedProvider) FindKey(ctx context.Context, ref KeyRef) (*KeyInfo, error) {
	ctx, span := tracing.Start(ctx, "hsm.find_key",
		attribute.String("hsm.operation", "find"),
		attribute.String("hsm.key.label", ref.Label),
		attribute.String("hsm.provider", p.Name()))
	defer span.End()
	start := time.Now()
	info, err := p.Provider.FindKey(ctx, ref)
	metrics.ObserveHSM("find", start, err)
	tracing.RecordError(ctx, err)
	return info, err
}

func (p *instrumentedProvider) PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error) {
	ctx, span := tracing.Start(ctx, "hsm.public_key",
		attribute.String("hsm.operation", "public_key"),
		attribute.String("hsm.key.label", ref.Label),
		attribute.String("hsm.provider", p.Name()))
	defer span.End()
	start := time.Now()
	pub, err := p.Provider.PublicKey(ctx, ref)
	metrics.ObserveHSM("public_key", start, err)
	tracing.RecordError(ctx, err)
	return pub, err
}

func (p *instrumentedProvider) Signer(ctx context.Context, ref KeyRef) (Signer, error) {
	spanCtx, span := tracing.Start(ctx, "hsm.signer",
		attribute.String("hsm.operation", "signer"),
		attribute.String("hsm.key.label", ref.Label),
		attribute.String("hsm.provider", p.Name()))
	defer span.End()
	start := time.Now()
	s, err := p.Provider.Signer(spanCtx, ref)
	metrics.ObserveHSM("signer", start, err)
	tracing.RecordError(spanCtx, err)
	if err != nil {
		return nil, err
	}
	// Capture the caller's context (not the ended signer-acquisition span's
	// context) so each Sign attaches its span to the live request trace. The
	// crypto.Signer interface carries no context, so this is the only channel.
	return &instrumentedSigner{Signer: s, ctx: ctx, label: ref.Label, provider: p.Name()}, nil
}

// instrumentedSigner times the actual signing operation (the on-device C_Sign
// for a PKCS#11 key), which is the latency that matters most for an HSM. It
// carries the context captured when the signer was obtained so each Sign can
// open a child span on the originating request's trace.
type instrumentedSigner struct {
	Signer
	ctx      context.Context
	label    string
	provider string
}

func (s *instrumentedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, span := tracing.Start(ctx, "hsm.sign",
		attribute.String("hsm.operation", "sign"),
		attribute.String("hsm.key.label", s.label),
		attribute.String("hsm.provider", s.provider))
	defer span.End()
	start := time.Now()
	sig, err := s.Signer.Sign(rand, digest, opts)
	metrics.ObserveHSM("sign", start, err)
	tracing.RecordError(ctx, err)
	return sig, err
}

// instrumentedDecrypterProvider adds the DecrypterProvider capability to the
// instrumented wrapper, timing the unwrap operation.
type instrumentedDecrypterProvider struct {
	*instrumentedProvider
}

func (p *instrumentedDecrypterProvider) Decrypter(ctx context.Context, ref KeyRef) (Decrypter, error) {
	dp := p.Provider.(DecrypterProvider)
	d, err := dp.Decrypter(ctx, ref)
	if err != nil {
		// A failure to obtain the decrypter is itself a decrypt-path error.
		metrics.HSMOperations.Inc("decrypt", metrics.ResultError)
		return nil, err
	}
	return &instrumentedDecrypter{Decrypter: d, ctx: ctx, label: ref.Label, provider: p.Name()}, nil
}

type instrumentedDecrypter struct {
	Decrypter
	ctx      context.Context
	label    string
	provider string
}

func (d *instrumentedDecrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	ctx := d.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, span := tracing.Start(ctx, "hsm.decrypt",
		attribute.String("hsm.operation", "decrypt"),
		attribute.String("hsm.key.label", d.label),
		attribute.String("hsm.provider", d.provider))
	defer span.End()
	start := time.Now()
	pt, err := d.Decrypter.Decrypt(rand, msg, opts)
	metrics.ObserveHSM("decrypt", start, err)
	tracing.RecordError(ctx, err)
	return pt, err
}

// instrumentedKeyWrapperProvider adds the KeyWrapper capability to the
// instrumented wrapper, timing the wrap/unwrap operations (the Vault Transit
// encrypt/decrypt round-trips) under the "wrap"/"unwrap" operation labels.
type instrumentedKeyWrapperProvider struct {
	*instrumentedProvider
}

func (p *instrumentedKeyWrapperProvider) WrapKey(ctx context.Context, ref KeyRef, plaintext []byte) ([]byte, error) {
	kw := p.Provider.(KeyWrapper)
	ctx, span := tracing.Start(ctx, "hsm.wrap",
		attribute.String("hsm.operation", "wrap"),
		attribute.String("hsm.key.label", ref.Label),
		attribute.String("hsm.provider", p.Name()))
	defer span.End()
	start := time.Now()
	ct, err := kw.WrapKey(ctx, ref, plaintext)
	metrics.ObserveHSM("wrap", start, err)
	tracing.RecordError(ctx, err)
	return ct, err
}

func (p *instrumentedKeyWrapperProvider) UnwrapKey(ctx context.Context, ref KeyRef, ciphertext []byte) ([]byte, error) {
	kw := p.Provider.(KeyWrapper)
	ctx, span := tracing.Start(ctx, "hsm.unwrap",
		attribute.String("hsm.operation", "unwrap"),
		attribute.String("hsm.key.label", ref.Label),
		attribute.String("hsm.provider", p.Name()))
	defer span.End()
	start := time.Now()
	pt, err := kw.UnwrapKey(ctx, ref, ciphertext)
	metrics.ObserveHSM("unwrap", start, err)
	tracing.RecordError(ctx, err)
	return pt, err
}
