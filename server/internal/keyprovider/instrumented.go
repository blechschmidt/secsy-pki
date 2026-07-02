package keyprovider

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// Instrument wraps a Provider so every key operation records latency and
// success/error metrics via the metrics package. The wrapper is transparent: it
// preserves the Provider contract and, when the underlying provider supports
// decryption (DecrypterProvider), the wrapper does too — so envelope decryption
// continues to work through the same type assertion callers already use.
//
// Metric operation labels: generate, find, signer, public_key, sign, decrypt.
// "signer"/"sign" are distinct because obtaining a Signer (which may open a
// PKCS#11 session and locate the key) and performing the actual C_Sign are
// separately interesting latencies on an HSM.
func Instrument(p Provider) Provider {
	if p == nil {
		return nil
	}
	ip := &instrumentedProvider{Provider: p}
	if _, ok := p.(DecrypterProvider); ok {
		return &instrumentedDecrypterProvider{instrumentedProvider: ip}
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
	start := time.Now()
	info, err := p.Provider.GenerateKey(ctx, spec)
	metrics.ObserveHSM("generate", start, err)
	return info, err
}

func (p *instrumentedProvider) FindKey(ctx context.Context, ref KeyRef) (*KeyInfo, error) {
	start := time.Now()
	info, err := p.Provider.FindKey(ctx, ref)
	metrics.ObserveHSM("find", start, err)
	return info, err
}

func (p *instrumentedProvider) PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error) {
	start := time.Now()
	pub, err := p.Provider.PublicKey(ctx, ref)
	metrics.ObserveHSM("public_key", start, err)
	return pub, err
}

func (p *instrumentedProvider) Signer(ctx context.Context, ref KeyRef) (Signer, error) {
	start := time.Now()
	s, err := p.Provider.Signer(ctx, ref)
	metrics.ObserveHSM("signer", start, err)
	if err != nil {
		return nil, err
	}
	return &instrumentedSigner{Signer: s}, nil
}

// instrumentedSigner times the actual signing operation (the on-device C_Sign
// for a PKCS#11 key), which is the latency that matters most for an HSM.
type instrumentedSigner struct {
	Signer
}

func (s *instrumentedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	start := time.Now()
	sig, err := s.Signer.Sign(rand, digest, opts)
	metrics.ObserveHSM("sign", start, err)
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
	return &instrumentedDecrypter{Decrypter: d}, nil
}

type instrumentedDecrypter struct {
	Decrypter
}

func (d *instrumentedDecrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	start := time.Now()
	pt, err := d.Decrypter.Decrypt(rand, msg, opts)
	metrics.ObserveHSM("decrypt", start, err)
	return pt, err
}
