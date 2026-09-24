package acme

// Coverage for DKIMSigner.Validate, the startup check that keeps a
// half-configured signer from being accepted. RFC 8823 §5 expects the
// email-reply-00 challenge message to be DKIM-signed, and the challenge email
// carries token-part-1 — so an unsigned or unsignable challenge is both a
// spoofing opening and a silently-broken validation path. Validate exists so the
// misconfiguration surfaces at startup rather than at the first send, which makes
// "it returns an error for every incomplete signer" the property to pin.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"strings"
	"testing"
)

// nilSigner is a crypto.Signer that is non-nil but useless, so a test can tell
// "no signer configured" apart from "a signer that happens to fail".
type nilSigner struct{}

func (nilSigner) Public() crypto.PublicKey { return nil }
func (nilSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestDKIMSignerValidate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	cases := []struct {
		name    string
		signer  *DKIMSigner
		wantErr string // "" means Validate must accept
	}{
		{
			name:   "nil-signer-is-not-a-misconfiguration",
			signer: nil,
		},
		{
			name:   "complete",
			signer: &DKIMSigner{Domain: "pki.example.test", Selector: "acme", Signer: key},
		},
		{
			name:    "missing-domain",
			signer:  &DKIMSigner{Selector: "acme", Signer: key},
			wantErr: "domain",
		},
		{
			name:    "blank-domain",
			signer:  &DKIMSigner{Domain: "   \t ", Selector: "acme", Signer: key},
			wantErr: "domain",
		},
		{
			name:    "missing-selector",
			signer:  &DKIMSigner{Domain: "pki.example.test", Signer: key},
			wantErr: "selector",
		},
		{
			name:    "blank-selector",
			signer:  &DKIMSigner{Domain: "pki.example.test", Selector: "\n ", Signer: key},
			wantErr: "selector",
		},
		{
			name:    "missing-key",
			signer:  &DKIMSigner{Domain: "pki.example.test", Selector: "acme"},
			wantErr: "key",
		},
		{
			// The domain check must fire before the others so the operator is told
			// about the first missing field, not an arbitrary one.
			name:    "everything-missing",
			signer:  &DKIMSigner{},
			wantErr: "domain",
		},
		{
			name:    "only-a-key",
			signer:  &DKIMSigner{Signer: key},
			wantErr: "domain",
		},
		{
			name:   "non-nil-but-broken-signer-is-accepted-structurally",
			signer: &DKIMSigner{Domain: "pki.example.test", Selector: "acme", Signer: nilSigner{}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.signer.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tc.wantErr)
			}
			// Every configuration error must be attributable to DKIM.
			if !strings.Contains(err.Error(), "dkim") {
				t.Errorf("Validate() = %q, want the error to name the dkim subsystem", err)
			}
		})
	}
}

// TestDKIMSignerValidateMatchesSignability is the consistency property: whenever
// Validate accepts a signer that holds a usable key, signing actually works — so
// a passing startup check really does mean challenge emails can be signed.
func TestDKIMSignerValidateMatchesSignability(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	d := &DKIMSigner{Domain: "pki.example.test", Selector: "acme", Signer: key}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	sig, err := d.sign([]header{{"Subject", "ACME: token-part-1"}}, []byte("body\r\n"))
	if err != nil {
		t.Fatalf("sign after a passing Validate: %v", err)
	}
	for _, want := range []string{"v=1", "a=rsa-sha256", "d=pki.example.test", "s=acme", "b="} {
		if !strings.Contains(sig, want) {
			t.Errorf("DKIM-Signature %q is missing %q", sig, want)
		}
	}

	// A signer with no key is rejected by Validate and also cannot sign, so the
	// two never disagree.
	noKey := &DKIMSigner{Domain: "pki.example.test", Selector: "acme"}
	if err := noKey.Validate(); err == nil {
		t.Fatal("Validate accepted a signer with no key")
	}
	if _, err := noKey.sign([]header{{"Subject", "x"}}, nil); err == nil {
		t.Error("sign succeeded without a signing key")
	}
}
