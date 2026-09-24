package secret

// Tests for the parts of escrow.go that consume operator-supplied configuration
// rather than key material produced by this package: the recovery-agent public
// key parser, the M-of-N policy invariants, and the ordering contract of an
// escrow block's agent list. All of it runs against the software key provider (or
// no provider at all), so none of it needs a PKCS#11 token.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// One 2048-bit RSA key is generated at most once per test binary and reused by
// every case below; RSA key generation dwarfs everything else these tests do.
var (
	sharedRSA2048 = sync.OnceValue(func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("escrow_parse_test: generating the shared RSA key: " + err.Error())
		}
		return k
	})
	sharedRSA1024 = sync.OnceValue(func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			panic("escrow_parse_test: generating the undersized RSA key: " + err.Error())
		}
		return k
	})
	sharedECDSA = sync.OnceValue(func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic("escrow_parse_test: generating the EC key: " + err.Error())
		}
		return k
	})
)

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func mustPKIXDER(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(%T): %v", pub, err)
	}
	return der
}

// rsaPubPEM is the ordinary PKIX/SPKI form an operator pastes into an agent spec.
func rsaPubPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pemBlock("PUBLIC KEY", mustPKIXDER(t, &key.PublicKey))
}

// TestParseRSAPublicKeyPEM drives the recovery-agent key parser with the
// malformed, mismatched and outright hostile inputs an operator (or a tampered
// config file) can supply. Two classes of failure matter most: accepting a
// PRIVATE key where a public key is expected, and accepting a non-RSA key that a
// later RSA-OAEP wrap would then have to interpret — both must be refused here.
func TestParseRSAPublicKeyPEM(t *testing.T) {
	rsaKey := sharedRSA2048()
	ecKey := sharedECDSA()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	pkixRSA := mustPKIXDER(t, &rsaKey.PublicKey)
	pkcs1Pub := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	pkcs1Priv := x509.MarshalPKCS1PrivateKey(rsaKey)
	pkcs8Priv, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	ecPriv, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	_ = edPriv

	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"pkix rsa public key", pemBlock("PUBLIC KEY", pkixRSA), true},
		{"pkcs1 rsa public key", pemBlock("RSA PUBLIC KEY", pkcs1Pub), true},

		{"empty input", nil, false},
		{"empty string", []byte(""), false},
		{"whitespace only", []byte("\n\n  \t\n"), false},
		{"not pem at all", []byte("this is not a PEM file"), false},
		{"json instead of pem", []byte(`{"kty":"RSA","n":"AQAB"}`), false},
		{"pem header only", []byte("-----BEGIN PUBLIC KEY-----\n"), false},
		{"invalid base64 body", []byte("-----BEGIN PUBLIC KEY-----\n!!!not base64!!!\n-----END PUBLIC KEY-----\n"), false},
		{"empty pem body", []byte("-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n"), false},
		{"wrong block type certificate", pemBlock("CERTIFICATE", pkixRSA), false},
		{"wrong block type openssh", pemBlock("OPENSSH PUBLIC KEY", pkixRSA), false},

		// Encoding mismatches: the right key in the wrong envelope must not be
		// coerced into the other format.
		{"pkcs1 body in pkix block", pemBlock("PUBLIC KEY", pkcs1Pub), false},
		{"pkix body in pkcs1 block", pemBlock("RSA PUBLIC KEY", pkixRSA), false},

		// A private key offered where a public key is expected. Accepting any of
		// these would mean the escrow shares were "wrapped" using material the
		// operator believed to be public — a serious confusion bug.
		{"pkcs1 private key block", pemBlock("RSA PRIVATE KEY", pkcs1Priv), false},
		{"pkcs8 private key block", pemBlock("PRIVATE KEY", pkcs8Priv), false},
		{"ec private key block", pemBlock("EC PRIVATE KEY", ecPriv), false},
		{"pkcs1 private key mislabeled as pkcs1 public", pemBlock("RSA PUBLIC KEY", pkcs1Priv), false},
		{"pkcs1 private key mislabeled as pkix public", pemBlock("PUBLIC KEY", pkcs1Priv), false},
		{"pkcs8 private key mislabeled as pkix public", pemBlock("PUBLIC KEY", pkcs8Priv), false},

		// Non-RSA keys where RSA is required.
		{"ec public key", pemBlock("PUBLIC KEY", mustPKIXDER(t, &ecKey.PublicKey)), false},
		{"ed25519 public key", pemBlock("PUBLIC KEY", mustPKIXDER(t, edPub)), false},

		// Structurally broken DER.
		{"truncated pkix der", pemBlock("PUBLIC KEY", pkixRSA[:len(pkixRSA)/2]), false},
		{"truncated pkcs1 der", pemBlock("RSA PUBLIC KEY", pkcs1Pub[:len(pkcs1Pub)/2]), false},
		{"pkix der with trailing garbage", pemBlock("PUBLIC KEY", append(append([]byte(nil), pkixRSA...), 0x00, 0x01)), false},
		{"pkcs1 der with trailing garbage", pemBlock("RSA PUBLIC KEY", append(append([]byte(nil), pkcs1Pub...), 0x00, 0x01)), false},

		// A short key parses here; the 2048-bit floor is policy, enforced by
		// NewEscrowPolicy (see TestEscrowPolicyRejectsUndersizedInlineKey).
		{"undersized key parses", pemBlock("PUBLIC KEY", mustPKIXDER(t, &sharedRSA1024().PublicKey)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRSAPublicKeyPEM(tc.in)
			if !tc.ok {
				if err == nil {
					t.Fatalf("parseRSAPublicKeyPEM accepted %s (got a %d-bit key)", tc.name, got.N.BitLen())
				}
				if got != nil {
					t.Errorf("rejected input returned a non-nil key: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRSAPublicKeyPEM(%s): %v", tc.name, err)
			}
			if got == nil {
				t.Fatal("parseRSAPublicKeyPEM returned a nil key with a nil error")
			}
		})
	}

	// A successful parse must yield the key that was actually encoded — "no
	// error" alone would also be satisfied by returning some other key.
	for _, in := range [][]byte{pemBlock("PUBLIC KEY", pkixRSA), pemBlock("RSA PUBLIC KEY", pkcs1Pub)} {
		got, err := parseRSAPublicKeyPEM(in)
		if err != nil {
			t.Fatalf("parseRSAPublicKeyPEM: %v", err)
		}
		if got.N.Cmp(rsaKey.N) != 0 || got.E != rsaKey.E {
			t.Errorf("parsed key differs from the encoded one: N equal=%v, E=%d want %d", got.N.Cmp(rsaKey.N) == 0, got.E, rsaKey.E)
		}
	}
}

// TestParseRSAPublicKeyPEMUsesFirstBlock: pem.Decode takes the first block, so
// an attacker who can only APPEND to an agent's key file cannot substitute their
// own key. Leading non-PEM text (mail headers, comments) is skipped as usual.
func TestParseRSAPublicKeyPEMUsesFirstBlock(t *testing.T) {
	operator := sharedRSA2048()
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	concat := append(rsaPubPEM(t, operator), rsaPubPEM(t, attacker)...)
	got, err := parseRSAPublicKeyPEM(concat)
	if err != nil {
		t.Fatalf("parseRSAPublicKeyPEM: %v", err)
	}
	if got.N.Cmp(operator.N) != 0 {
		t.Error("an appended second PEM block displaced the operator's key")
	}

	withPreamble := append([]byte("Comment: agent alice\nsome preamble\n"), rsaPubPEM(t, operator)...)
	got, err = parseRSAPublicKeyPEM(withPreamble)
	if err != nil {
		t.Fatalf("parseRSAPublicKeyPEM with a preamble: %v", err)
	}
	if got.N.Cmp(operator.N) != 0 {
		t.Error("the key behind a text preamble did not parse to the operator's key")
	}
}

// inlineSpecs builds n agent specs that carry an inline public key and no key
// label, so NewEscrowPolicy never has to touch the provider (no HSM, no keygen).
func inlineSpecs(t *testing.T, n int) []AgentSpec {
	t.Helper()
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("agent-%02d", i)
	}
	return inlineSpecsWithIDs(t, ids...)
}

// inlineSpecsWithIDs is inlineSpecs for a caller that needs specific (in
// particular deliberately unsorted) agent identifiers.
func inlineSpecsWithIDs(t *testing.T, ids ...string) []AgentSpec {
	t.Helper()
	keyPEM := string(rsaPubPEM(t, sharedRSA2048()))
	specs := make([]AgentSpec, len(ids))
	for i, id := range ids {
		specs[i] = AgentSpec{ID: id, PublicKeyPEM: keyPEM}
	}
	return specs
}

// TestEscrowPolicyMofNInvariants pins the M-of-N configuration rules. A policy
// that accepted M below 2 would drop dual control; one that accepted M above N
// would produce an escrow block that can never reach quorum — an envelope
// advertising recoverability that is in fact unrecoverable.
func TestEscrowPolicyMofNInvariants(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	specs3 := inlineSpecs(t, 3)

	t.Run("threshold below dual control", func(t *testing.T) {
		for _, m := range []int{-1000, -1, 0, 1} {
			_, err := NewEscrowPolicy(ctx, prov, m, specs3)
			if err == nil {
				t.Errorf("threshold %d was accepted", m)
				continue
			}
			if !errors.Is(err, errThresholdTooLow) {
				t.Errorf("threshold %d: error = %v, want errThresholdTooLow", m, err)
			}
		}
	})

	t.Run("threshold above agent count", func(t *testing.T) {
		for _, m := range []int{4, 5, 1000} {
			_, err := NewEscrowPolicy(ctx, prov, m, specs3)
			if err == nil {
				t.Errorf("threshold %d of 3 agents was accepted", m)
				continue
			}
			if !errors.Is(err, errPartsBelowThreshold) {
				t.Errorf("threshold %d: error = %v, want errPartsBelowThreshold", m, err)
			}
		}
		if _, err := NewEscrowPolicy(ctx, prov, 2, nil); !errors.Is(err, errPartsBelowThreshold) {
			t.Errorf("no agents at all: error = %v, want errPartsBelowThreshold", err)
		}
	})

	t.Run("more agents than shamir x-coordinates", func(t *testing.T) {
		// The Shamir split has 255 usable x-coordinates; 256 agents must be
		// refused at configuration time, not at seal time.
		_, err := NewEscrowPolicy(ctx, prov, 2, inlineSpecs(t, 256))
		if !errors.Is(err, errTooManyParts) {
			t.Errorf("256 agents: error = %v, want errTooManyParts", err)
		}
		if _, err := NewEscrowPolicy(ctx, prov, 2, inlineSpecs(t, 255)); err != nil {
			t.Errorf("255 agents should be allowed: %v", err)
		}
	})

	t.Run("threshold equal to agent count", func(t *testing.T) {
		p, err := NewEscrowPolicy(ctx, prov, 3, specs3)
		if err != nil {
			t.Fatalf("3-of-3: %v", err)
		}
		if p.Threshold() != 3 || len(p.Agents()) != 3 {
			t.Errorf("3-of-3 policy reports %d-of-%d", p.Threshold(), len(p.Agents()))
		}
	})

	t.Run("accessors mirror the validated configuration", func(t *testing.T) {
		p, err := NewEscrowPolicy(ctx, prov, 2, specs3)
		if err != nil {
			t.Fatalf("NewEscrowPolicy: %v", err)
		}
		if p.Threshold() != 2 {
			t.Errorf("Threshold() = %d, want 2", p.Threshold())
		}
		agents := p.Agents()
		if len(agents) != len(specs3) {
			t.Fatalf("Agents() returned %d agents, want %d", len(agents), len(specs3))
		}
		// Order must follow the spec order: the agent at index i is the one
		// whose share gets x-coordinate i's share in sealEscrow.
		for i, a := range agents {
			if a.ID != specs3[i].ID {
				t.Errorf("Agents()[%d].ID = %q, want %q", i, a.ID, specs3[i].ID)
			}
			if a.Pub == nil || a.Pub.N.Cmp(sharedRSA2048().N) != 0 {
				t.Errorf("Agents()[%d] carries the wrong public key", i)
			}
			if a.wrapAlg != AlgRSAOAEPSHA256 {
				t.Errorf("Agents()[%d].wrapAlg = %q, want %q for an externally supplied key", i, a.wrapAlg, AlgRSAOAEPSHA256)
			}
		}
	})

	t.Run("malformed agent specs", func(t *testing.T) {
		keyPEM := string(rsaPubPEM(t, sharedRSA2048()))
		bad := map[string][]AgentSpec{
			"empty id": {
				{ID: "", PublicKeyPEM: keyPEM},
				{ID: "b", PublicKeyPEM: keyPEM},
			},
			"duplicate id": {
				{ID: "same", PublicKeyPEM: keyPEM},
				{ID: "same", PublicKeyPEM: keyPEM},
			},
			"duplicate key label": {
				{ID: "a", KeyLabel: "shared-label", PublicKeyPEM: keyPEM},
				{ID: "b", KeyLabel: "shared-label", PublicKeyPEM: keyPEM},
			},
			"no key material": {
				{ID: "a"},
				{ID: "b", PublicKeyPEM: keyPEM},
			},
			"unparseable inline key": {
				{ID: "a", PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n"},
				{ID: "b", PublicKeyPEM: keyPEM},
			},
		}
		for name, specs := range bad {
			if p, err := NewEscrowPolicy(ctx, prov, 2, specs); err == nil {
				t.Errorf("%s was accepted (policy=%+v)", name, p)
			}
		}
	})
}

// TestEscrowPolicyRejectsUndersizedInlineKey: an operator pasting a legacy
// 1024-bit agent key must be refused at configuration time. Wrapping a share to
// it would give that recovery agent's contribution far less protection than the
// DEK it helps reconstruct.
func TestEscrowPolicyRejectsUndersizedInlineKey(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	small := string(rsaPubPEM(t, sharedRSA1024()))
	good := string(rsaPubPEM(t, sharedRSA2048()))

	_, err := NewEscrowPolicy(ctx, prov, 2, []AgentSpec{
		{ID: "weak", PublicKeyPEM: small},
		{ID: "strong", PublicKeyPEM: good},
	})
	if err == nil {
		t.Fatal("a 1024-bit recovery-agent key was accepted")
	}
	if !strings.Contains(err.Error(), "too small") || !strings.Contains(err.Error(), "weak") {
		t.Errorf("error should name the weak agent and the size problem, got: %v", err)
	}
}

// TestEscrowPolicySealOrderAndAgentIDs covers the ordering contract of an escrow
// block. AgentIDs() must be a stable, deterministic list in the policy's agent
// order (it is what a recovery ceremony shows the operator and what audit records
// name), while digest() — the value bound into the envelope AAD — must be
// independent of share order so a re-serialized block still authenticates.
func TestEscrowPolicySealOrderAndAgentIDs(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	// Deliberately NOT in sorted order: the contract is "policy order", so a
	// sorted (or map-ranged) agent list must not be able to pass this test.
	specs := inlineSpecsWithIDs(t, "zeta", "alpha", "mike", "bravo", "kilo")
	policy, err := NewEscrowPolicy(ctx, prov, 3, specs)
	if err != nil {
		t.Fatalf("NewEscrowPolicy: %v", err)
	}

	dek := bytes.Repeat([]byte{0x5a}, dekSize)
	block, err := policy.sealEscrow(dek)
	if err != nil {
		t.Fatalf("sealEscrow: %v", err)
	}
	if err := block.validate(); err != nil {
		t.Fatalf("a freshly sealed block does not validate: %v", err)
	}

	want := make([]string, len(specs))
	for i, s := range specs {
		want[i] = s.ID
	}
	// Deterministic, in policy order, and stable across calls: a map-iteration
	// order slip here would scramble a stored escrow blob's agent list.
	for i := 0; i < 5; i++ {
		got := block.AgentIDs()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("AgentIDs() call %d = %q, want %q", i, got, want)
		}
	}
	if len(block.Shares) != len(specs) {
		t.Fatalf("sealed %d shares for %d agents", len(block.Shares), len(specs))
	}
	// No agent may appear twice, and every share must carry a distinct
	// x-coordinate (a repeated x would silently shrink the quorum).
	seenID, seenX := map[string]bool{}, map[int]bool{}
	for _, s := range block.Shares {
		if seenID[s.AgentID] {
			t.Errorf("agent %q appears in two shares", s.AgentID)
		}
		seenID[s.AgentID] = true
		if seenX[s.X] {
			t.Errorf("x-coordinate %d reused", s.X)
		}
		seenX[s.X] = true
		if len(s.WrappedShare) == 0 {
			t.Errorf("agent %q has no wrapped share", s.AgentID)
		}
		if bytes.Contains(s.WrappedShare, dek) {
			t.Errorf("agent %q's wrapped share contains the DEK in the clear", s.AgentID)
		}
	}

	// Serializing and reloading the block preserves both the order and the AAD
	// digest, so a stored envelope still opens.
	blob, err := json.Marshal(block)
	if err != nil {
		t.Fatalf("marshal escrow block: %v", err)
	}
	var reloaded EscrowBlock
	if err := json.Unmarshal(blob, &reloaded); err != nil {
		t.Fatalf("unmarshal escrow block: %v", err)
	}
	if strings.Join(reloaded.AgentIDs(), ",") != strings.Join(want, ",") {
		t.Errorf("AgentIDs() after a JSON round trip = %q, want %q", reloaded.AgentIDs(), want)
	}
	if !bytes.Equal(reloaded.digest(), block.digest()) {
		t.Error("the escrow digest changed across a JSON round trip; stored envelopes would stop authenticating")
	}

	// Reordering the shares changes the displayed agent order but must NOT
	// change the digest (it sorts by x-coordinate).
	shuffled := cloneEscrow(block)
	shuffled.Shares[0], shuffled.Shares[4] = shuffled.Shares[4], shuffled.Shares[0]
	if !bytes.Equal(shuffled.digest(), block.digest()) {
		t.Error("digest() depends on share order; a re-serialized envelope would fail to authenticate")
	}
	if strings.Join(shuffled.AgentIDs(), ",") == strings.Join(want, ",") {
		t.Error("AgentIDs() ignores share order, so it cannot be reporting the stored order")
	}

	// An empty block yields an empty list rather than panicking.
	if ids := (&EscrowBlock{}).AgentIDs(); len(ids) != 0 {
		t.Errorf("AgentIDs() on an empty block = %q, want empty", ids)
	}
}

// TestRecoveryRejectsAgentWithoutKeyLabel: an agent configured from an inline
// public key has no private key in this provider. Such an envelope can be
// wrapped to that agent but not recovered here, and the attempt must fail with a
// clear error instead of reaching into the provider with an empty label.
func TestRecoveryRejectsAgentWithoutKeyLabel(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	policy, err := NewEscrowPolicy(ctx, prov, 2, inlineSpecs(t, 3))
	if err != nil {
		t.Fatalf("NewEscrowPolicy: %v", err)
	}
	block, err := policy.sealEscrow(bytes.Repeat([]byte{0x11}, dekSize))
	if err != nil {
		t.Fatalf("sealEscrow: %v", err)
	}
	rs, err := NewRecoveryService(prov)
	if err != nil {
		t.Fatalf("NewRecoveryService: %v", err)
	}
	ids := block.AgentIDs()
	dek, err := rs.RecoverDEK(ctx, block, []string{ids[0], ids[1]})
	if err == nil {
		t.Fatalf("recovery succeeded for agents whose private keys are not in this provider (dek=%x)", dek)
	}
	if dek != nil {
		t.Errorf("failed RecoverDEK returned %d bytes of key material", len(dek))
	}
	if !strings.Contains(err.Error(), "key label") {
		t.Errorf("error should explain the missing key label, got: %v", err)
	}
}

// TestEncryptWithEscrowToJSONRoundTrip covers the serialize-and-store form of
// escrowed encryption on both the single-KEK Service and the rotation Ring: the
// escrow block must survive JSON storage with its threshold, agent order and AAD
// binding intact, and the stored blob must not contain the plaintext.
func TestEncryptWithEscrowToJSONRoundTrip(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	if _, err := ProvisionKEK(ctx, prov, "escrow-json-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: "escrow-json-kek"})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ring, err := LoadRing(ctx, prov, "escrow-json-kek", nil)
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}
	specs := inlineSpecsWithIDs(t, "officer-z", "officer-a", "officer-m", "officer-b")
	policy, err := NewEscrowPolicy(ctx, prov, 3, specs)
	if err != nil {
		t.Fatalf("NewEscrowPolicy: %v", err)
	}
	wantIDs := make([]string, len(specs))
	for i, s := range specs {
		wantIDs[i] = s.ID
	}

	plaintext := []byte("the break-glass database password")
	encCtx := []byte("tenant=acme")

	check := func(t *testing.T, blob []byte, decrypt func([]byte) ([]byte, error)) {
		t.Helper()
		if bytes.Contains(blob, plaintext) {
			t.Fatal("the serialized envelope contains the plaintext")
		}
		env := decodeEnv(t, blob)
		if env.Escrow == nil {
			t.Fatal("the serialized envelope lost its escrow block")
		}
		if env.Escrow.Threshold != 3 || len(env.Escrow.Shares) != 4 {
			t.Errorf("escrow block is %d-of-%d, want 3-of-4", env.Escrow.Threshold, len(env.Escrow.Shares))
		}
		if env.Escrow.Alg != AlgShamirRSAOAEP || env.Escrow.Version != EscrowFormatVersion1 {
			t.Errorf("escrow block header = {v%d %q}, want {v%d %q}", env.Escrow.Version, env.Escrow.Alg, EscrowFormatVersion1, AlgShamirRSAOAEP)
		}
		if got := strings.Join(env.Escrow.AgentIDs(), ","); got != strings.Join(wantIDs, ",") {
			t.Errorf("stored agent order = %q, want %q", got, wantIDs)
		}
		// The primary KEK path still opens it, which only works if the escrow
		// digest bound into the AAD survived serialization byte-for-byte.
		got, err := decrypt(blob)
		if err != nil {
			t.Fatalf("decrypting the stored envelope: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("round-tripped plaintext = %q, want %q", got, plaintext)
		}
	}

	t.Run("service", func(t *testing.T) {
		blob, err := svc.EncryptWithEscrowToJSON(plaintext, encCtx, policy)
		if err != nil {
			t.Fatalf("EncryptWithEscrowToJSON: %v", err)
		}
		check(t, blob, func(b []byte) ([]byte, error) { return svc.DecryptJSON(b, encCtx) })
		// A nil policy is documented to behave like plain EncryptToJSON.
		plain, err := svc.EncryptWithEscrowToJSON(plaintext, nil, nil)
		if err != nil {
			t.Fatalf("EncryptWithEscrowToJSON(nil policy): %v", err)
		}
		if decodeEnv(t, plain).Escrow != nil {
			t.Error("a nil escrow policy still produced an escrow block")
		}
	})

	t.Run("ring", func(t *testing.T) {
		blob, err := ring.EncryptWithEscrowToJSON(plaintext, encCtx, policy)
		if err != nil {
			t.Fatalf("Ring.EncryptWithEscrowToJSON: %v", err)
		}
		check(t, blob, func(b []byte) ([]byte, error) { return ring.DecryptJSON(ctx, b, encCtx) })

		env, err := ring.EncryptWithEscrow(plaintext, encCtx, policy)
		if err != nil {
			t.Fatalf("Ring.EncryptWithEscrow: %v", err)
		}
		if env.Escrow == nil || env.KEKVersion != ring.ActiveVersion() {
			t.Errorf("ring-sealed envelope: escrow=%v kek version=%d want version %d", env.Escrow != nil, env.KEKVersion, ring.ActiveVersion())
		}
		if ring.Active() == nil {
			t.Error("Ring.Active() returned nil for a loaded ring")
		}
	})
}

// TestEscrowPolicyRefusesUnusableExponent: parseRSAPublicKeyPEM does not police
// the RSA exponent, so a nonsense one reaches the wrap step. The invariant that
// matters is that it fails closed there — a share must never come out
// unencrypted.
func TestEscrowPolicyRefusesUnusableExponent(t *testing.T) {
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	weird := &rsa.PublicKey{N: new(big.Int).Set(sharedRSA2048().N), E: 1}
	der, err := x509.MarshalPKIXPublicKey(weird)
	if err != nil {
		t.Skipf("this Go version refuses to marshal an E=1 RSA key: %v", err)
	}
	specs := []AgentSpec{
		{ID: "bad-exponent", PublicKeyPEM: string(pemBlock("PUBLIC KEY", der))},
		{ID: "good", PublicKeyPEM: string(rsaPubPEM(t, sharedRSA2048()))},
	}
	policy, err := NewEscrowPolicy(ctx, prov, 2, specs)
	if err != nil {
		// Rejecting it at configuration time is the better outcome; either way
		// no share may be sealed to it.
		return
	}
	dek := bytes.Repeat([]byte{0x33}, dekSize)
	block, err := policy.sealEscrow(dek)
	if err == nil {
		for _, s := range block.Shares {
			if bytes.Contains(s.WrappedShare, dek) {
				t.Fatalf("agent %q's share was not encrypted", s.AgentID)
			}
		}
		t.Fatalf("sealEscrow accepted an E=1 recovery-agent key")
	}
}
