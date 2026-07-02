package secret

import (
	"bytes"
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// TestHSMEscrowQuorumRecovers proves the full M-of-N escrow/recovery flow works
// against a real HSM: the DEK is Shamir-split, each share is wrapped to an
// agent's HSM key, and a quorum reconstructs the plaintext with every agent
// unwrap running on the token (the agent private keys never leave the device).
// A sub-quorum must fail. This is the SoftHSM-backed proof required by the task.
func TestHSMEscrowQuorumRecovers(t *testing.T) {
	ctx := context.Background()
	p := pkcs11Provider(t)

	kekLabel := uniqueKEKLabel(t)
	svc, err := ProvisionKEK(ctx, p, kekLabel, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}

	// Provision 5 recovery-agent keys on the token, unique labels per run.
	const n, m = 5, 3
	specs := make([]AgentSpec, n)
	for i := 0; i < n; i++ {
		label := uniqueKEKLabel(t) + "-agent"
		if _, err := p.GenerateKey(ctx, keyprovider.KeySpec{
			Label:   label,
			KeyType: keyprovider.KeyTypeRSA2048,
			Usage:   keyprovider.KeyUsageDecrypt,
		}); err != nil {
			t.Fatalf("generate agent key %d: %v", i, err)
		}
		specs[i] = AgentSpec{ID: agentID(i), KeyLabel: label}
	}
	policy, err := NewEscrowPolicy(ctx, p, m, specs)
	if err != nil {
		t.Fatalf("NewEscrowPolicy: %v", err)
	}

	plaintext := []byte("hsm-escrowed database master key")
	env, err := svc.EncryptWithEscrow(plaintext, nil, policy)
	if err != nil {
		t.Fatalf("EncryptWithEscrow: %v", err)
	}
	if bytes.Contains(mustMarshal(t, env), plaintext) {
		t.Fatal("plaintext leaked into escrowed envelope")
	}

	rs, err := NewRecoveryService(p)
	if err != nil {
		t.Fatalf("NewRecoveryService: %v", err)
	}

	// A quorum of 3 distinct agents recovers on the HSM.
	got, err := rs.Recover(ctx, env, []string{agentID(0), agentID(2), agentID(4)}, nil)
	if err != nil {
		t.Fatalf("HSM recover with quorum: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovered plaintext mismatch: got %q", got)
	}

	// A sub-quorum of 2 must not recover.
	if _, err := rs.Recover(ctx, env, []string{agentID(0), agentID(1)}, nil); err == nil {
		t.Fatal("a sub-quorum (2 of 3) must not recover on the HSM")
	}
}

func mustMarshal(t *testing.T, env *Envelope) []byte {
	t.Helper()
	b, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}
