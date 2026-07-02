package secret

import (
	"bytes"
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// escrowFixture provisions a KEK plus n recovery-agent RSA keys in a software
// provider and returns a Service, the provider, and an m-of-n escrow policy.
func escrowFixture(t *testing.T, m, n int) (*Service, keyprovider.Provider, *EscrowPolicy) {
	t.Helper()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	svc, err := ProvisionKEK(context.Background(), prov, "escrow-kek", keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	specs := make([]AgentSpec, n)
	for i := 0; i < n; i++ {
		label := agentLabel(i)
		if _, err := prov.GenerateKey(context.Background(), keyprovider.KeySpec{
			Label:   label,
			KeyType: keyprovider.KeyTypeRSA2048,
			Usage:   keyprovider.KeyUsageDecrypt,
		}); err != nil {
			t.Fatalf("generate agent key %d: %v", i, err)
		}
		specs[i] = AgentSpec{ID: agentID(i), KeyLabel: label}
	}
	policy, err := NewEscrowPolicy(context.Background(), prov, m, specs)
	if err != nil {
		t.Fatalf("NewEscrowPolicy: %v", err)
	}
	return svc, prov, policy
}

func agentID(i int) string    { return "agent-" + string(rune('A'+i)) }
func agentLabel(i int) string { return "agent-key-" + string(rune('A'+i)) }

// TestEscrowQuorumRecovers proves that a quorum of recovery agents reconstructs
// the plaintext via the escrow path, while a full and partial decrypt behave as
// expected.
func TestEscrowQuorumRecovers(t *testing.T) {
	svc, prov, policy := escrowFixture(t, 3, 5)
	plaintext := []byte("the database master password")

	env, err := svc.EncryptWithEscrow(plaintext, nil, policy)
	if err != nil {
		t.Fatalf("EncryptWithEscrow: %v", err)
	}
	if env.Escrow == nil || env.Escrow.Threshold != 3 || len(env.Escrow.Shares) != 5 {
		t.Fatalf("unexpected escrow block: %+v", env.Escrow)
	}
	// The primary KEK path must still decrypt an escrowed envelope.
	if got, err := svc.Decrypt(env, nil); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("primary decrypt of escrowed envelope failed: %v", err)
	}

	rs, err := NewRecoveryService(prov)
	if err != nil {
		t.Fatalf("NewRecoveryService: %v", err)
	}
	// Exactly the threshold recovers.
	got, err := rs.Recover(context.Background(), env, []string{agentID(0), agentID(2), agentID(4)}, nil)
	if err != nil {
		t.Fatalf("Recover with quorum: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovered plaintext mismatch: got %q", got)
	}
	// More than the threshold also recovers.
	got, err = rs.Recover(context.Background(), env, []string{agentID(0), agentID(1), agentID(2), agentID(3)}, nil)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Recover with super-quorum: %v", err)
	}
}

// TestEscrowSubQuorumCannotRecover proves that fewer than the threshold agents
// cannot recover the plaintext — the core dual-control guarantee.
func TestEscrowSubQuorumCannotRecover(t *testing.T) {
	svc, prov, policy := escrowFixture(t, 3, 5)
	plaintext := []byte("top secret")
	env, err := svc.EncryptWithEscrow(plaintext, nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := NewRecoveryService(prov)
	if err != nil {
		t.Fatal(err)
	}
	// Two of three required agents: must be rejected before any reconstruction.
	if _, err := rs.Recover(context.Background(), env, []string{agentID(0), agentID(1)}, nil); err == nil {
		t.Fatal("a sub-quorum (2 of 3) must not recover the plaintext")
	}
	// A single agent likewise cannot.
	if _, err := rs.Recover(context.Background(), env, []string{agentID(0)}, nil); err == nil {
		t.Fatal("a single agent must not recover the plaintext")
	}
}

// TestEscrowRejectsUnknownAgent ensures only configured recovery agents can
// contribute to a ceremony.
func TestEscrowRejectsUnknownAgent(t *testing.T) {
	svc, prov, policy := escrowFixture(t, 2, 3)
	env, err := svc.EncryptWithEscrow([]byte("x"), nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := NewRecoveryService(prov)
	if _, err := rs.Recover(context.Background(), env, []string{agentID(0), "intruder"}, nil); err == nil {
		t.Fatal("an agent not party to the escrow must be rejected")
	}
	// Naming the same agent twice must not be counted as two toward the quorum.
	if _, err := rs.Recover(context.Background(), env, []string{agentID(0), agentID(0)}, nil); err == nil {
		t.Fatal("duplicate agent must be rejected")
	}
}

// TestEscrowBoundIntoAAD verifies the escrow block is authenticated: tampering
// with a wrapped share invalidates the ciphertext, and stripping the escrow
// block does too.
func TestEscrowBoundIntoAAD(t *testing.T) {
	svc, _, policy := escrowFixture(t, 2, 3)
	env, err := svc.EncryptWithEscrow([]byte("integrity"), nil, policy)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("tamper wrapped share", func(t *testing.T) {
		bad := *env
		bad.Escrow = cloneEscrow(env.Escrow)
		bad.Escrow.Shares[0].WrappedShare[0] ^= 0x01
		if _, err := svc.Decrypt(&bad, nil); err == nil {
			t.Fatal("expected GCM failure after tampering with an escrow share")
		}
	})

	t.Run("strip escrow", func(t *testing.T) {
		bad := *env
		bad.Escrow = nil
		if _, err := svc.Decrypt(&bad, nil); err == nil {
			t.Fatal("expected GCM failure after stripping the escrow block")
		}
	})

	t.Run("swap threshold", func(t *testing.T) {
		bad := *env
		bad.Escrow = cloneEscrow(env.Escrow)
		bad.Escrow.Threshold = 3
		if _, err := svc.Decrypt(&bad, nil); err == nil {
			t.Fatal("expected GCM failure after altering the escrow threshold")
		}
	})
}

// TestEscrowContextBinding verifies recovery honors the encryption context.
func TestEscrowContextBinding(t *testing.T) {
	svc, prov, policy := escrowFixture(t, 2, 3)
	encCtx := []byte("tenant=acme")
	env, err := svc.EncryptWithEscrow([]byte("ctx-bound"), encCtx, policy)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := NewRecoveryService(prov)
	if _, err := rs.Recover(context.Background(), env, []string{agentID(0), agentID(1)}, encCtx); err != nil {
		t.Fatalf("recover with correct context: %v", err)
	}
	if _, err := rs.Recover(context.Background(), env, []string{agentID(0), agentID(1)}, []byte("tenant=evil")); err == nil {
		t.Fatal("recover with wrong context must fail")
	}
}

// TestEscrowPolicyValidation checks that NewEscrowPolicy enforces dual control
// and consistency.
func TestEscrowPolicyValidation(t *testing.T) {
	prov, _ := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	for i := 0; i < 3; i++ {
		prov.GenerateKey(context.Background(), keyprovider.KeySpec{Label: agentLabel(i), KeyType: keyprovider.KeyTypeRSA2048, Usage: keyprovider.KeyUsageDecrypt})
	}
	specs := []AgentSpec{{ID: agentID(0), KeyLabel: agentLabel(0)}, {ID: agentID(1), KeyLabel: agentLabel(1)}, {ID: agentID(2), KeyLabel: agentLabel(2)}}

	if _, err := NewEscrowPolicy(context.Background(), prov, 1, specs); err == nil {
		t.Error("threshold 1 must be rejected")
	}
	if _, err := NewEscrowPolicy(context.Background(), prov, 4, specs); err == nil {
		t.Error("threshold > agents must be rejected")
	}
	dup := []AgentSpec{{ID: "same", KeyLabel: agentLabel(0)}, {ID: "same", KeyLabel: agentLabel(1)}}
	if _, err := NewEscrowPolicy(context.Background(), prov, 2, dup); err == nil {
		t.Error("duplicate agent id must be rejected")
	}
}

// cloneEscrow makes a deep-enough copy of an escrow block for tamper tests so
// mutating the copy does not affect the original.
func cloneEscrow(b *EscrowBlock) *EscrowBlock {
	cp := *b
	cp.Shares = make([]EscrowShare, len(b.Shares))
	for i, s := range b.Shares {
		cp.Shares[i] = s
		cp.Shares[i].WrappedShare = append([]byte(nil), s.WrappedShare...)
	}
	return &cp
}
