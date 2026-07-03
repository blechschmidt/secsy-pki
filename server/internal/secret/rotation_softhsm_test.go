package secret

// SoftHSM acceptance test for Task 63: KEK rotation with the wrapping keys on
// a real PKCS#11 token. It walks the full operational flow —
//
//	provision v1 → encrypt (incl. context-bound and escrowed secrets)
//	→ rotate → old secrets still decrypt (dual-KEK window), new encrypts land
//	  on the versioned v2 label
//	→ rewrap → data blobs untouched, escrow still recoverable, old envelope
//	  copies still decrypt (v1 is retiring, not gone)
//	→ retire v1 → decryption fails ONLY for envelopes still on v1; re-wrapped
//	  and freshly sealed secrets are unaffected
//
// and checks the unique-CKA_LABEL invariant for the versioned keys. Mirrors
// the other *_softhsm_test.go files: skipped unless setup-softhsm.sh's
// environment is present.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func TestHSMKEKRotationLifecycle(t *testing.T) {
	ctx := context.Background()
	p := pkcs11Provider(t)
	family := uniqueKEKLabel(t) // unique per run; the persistent SoftHSM store is shared

	// --- provision v1 and seal the "fleet" -------------------------------
	if _, err := ProvisionKEK(ctx, p, family, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK on HSM: %v", err)
	}
	store := newFakeKEKStore()
	ring1, err := loadRingFromStore(ctx, p, store, family)
	if err != nil {
		t.Fatalf("LoadRing(v1): %v", err)
	}
	if ring1.ActiveVersion() != 1 || ring1.ActiveLabel() != family {
		t.Fatalf("pre-rotation ring active = v%d %q", ring1.ActiveVersion(), ring1.ActiveLabel())
	}

	// A recovery agent pair for the escrowed secret (2-of-2 quorum).
	agentA, agentB := family+"-agent-a", family+"-agent-b"
	for _, l := range []string{agentA, agentB} {
		if _, err := p.GenerateKey(ctx, keyprovider.KeySpec{
			Label: l, KeyType: keyprovider.KeyTypeRSA2048, Usage: keyprovider.KeyUsageDecrypt,
		}); err != nil {
			t.Fatalf("generating agent key %q: %v", l, err)
		}
	}
	policy, err := NewEscrowPolicy(ctx, p, 2, []AgentSpec{
		{ID: "a", KeyLabel: agentA}, {ID: "b", KeyLabel: agentB},
	})
	if err != nil {
		t.Fatalf("NewEscrowPolicy: %v", err)
	}

	addStored := func(id string, blob []byte) {
		t.Helper()
		env, err := Unmarshal(blob)
		if err != nil {
			t.Fatal(err)
		}
		store.secrets[id] = &models.StoredSecret{
			ID: id, TenantID: "default", Name: id, Envelope: string(blob),
			KEKFamily: family, KEKLabel: env.KEKLabel, KEKVersion: 1,
			ContextBound: env.ContextBound, Escrowed: env.Escrow != nil,
		}
	}
	plainBlob, err := ring1.EncryptToJSON([]byte("plain secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctxBlob, err := ring1.EncryptToJSON([]byte("context secret"), []byte("tenant=acme"))
	if err != nil {
		t.Fatal(err)
	}
	escrowBlob, err := ring1.EncryptWithEscrowToJSON([]byte("escrowed secret"), nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	addStored("plain", plainBlob)
	addStored("ctx", ctxBlob)
	addStored("escrowed", escrowBlob)

	// --- rotate -----------------------------------------------------------
	res, err := RotateKEK(ctx, p, store, family, keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("RotateKEK on HSM: %v", err)
	}
	if res.NewLabel != family+"-v2" || res.NewVersion != 2 {
		t.Fatalf("rotation result = %+v", res)
	}
	// Unique-CKA_LABEL invariant: v1 and v2 are distinct token objects, both
	// resolvable by their own label.
	if _, err := p.FindKey(ctx, keyprovider.KeyRef{Label: family}); err != nil {
		t.Fatalf("v1 key lookup after rotation: %v", err)
	}
	if _, err := p.FindKey(ctx, keyprovider.KeyRef{Label: family + "-v2"}); err != nil {
		t.Fatalf("v2 key lookup after rotation: %v", err)
	}

	ring2, err := loadRingFromStore(ctx, p, store, family)
	if err != nil {
		t.Fatalf("LoadRing(v2): %v", err)
	}

	// Old secrets still decrypt through the dual-KEK window, unwrapping on the
	// token under the retiring v1 key.
	if got, err := ring2.DecryptJSON(ctx, plainBlob, nil); err != nil || string(got) != "plain secret" {
		t.Fatalf("post-rotation decrypt(plain) = %q, %v", got, err)
	}
	if got, err := ring2.DecryptJSON(ctx, ctxBlob, []byte("tenant=acme")); err != nil || string(got) != "context secret" {
		t.Fatalf("post-rotation decrypt(ctx) = %q, %v", got, err)
	}

	// New encrypts land on the v2 label and round-trip.
	freshBlob, err := ring2.EncryptToJSON([]byte("fresh secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := Unmarshal(freshBlob)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.KEKLabel != family+"-v2" || fresh.KEKVersion != 2 {
		t.Fatalf("fresh envelope header = %q v%d", fresh.KEKLabel, fresh.KEKVersion)
	}
	if got, err := ring2.DecryptJSON(ctx, freshBlob, nil); err != nil || string(got) != "fresh secret" {
		t.Fatalf("fresh decrypt = %q, %v", got, err)
	}

	// --- rewrap ------------------------------------------------------------
	// Keep pre-rewrap copies: the retiring v1 KEK must keep opening them until
	// retirement.
	preRewrapPlain := append([]byte(nil), plainBlob...)

	report, err := RewrapStoredSecrets(ctx, ring2, store, nil)
	if err != nil {
		t.Fatalf("RewrapStoredSecrets: %v", err)
	}
	if report.Rewrapped != 3 || report.Failed != 0 || report.Conflicts != 0 {
		t.Fatalf("rewrap report = %+v", report)
	}
	for _, id := range []string{"plain", "ctx", "escrowed"} {
		s, _ := store.GetStoredSecret(id)
		if s.KEKLabel != family+"-v2" || s.KEKVersion != 2 {
			t.Fatalf("stored secret %q not migrated: %+v", id, s)
		}
		env, err := Unmarshal([]byte(s.Envelope))
		if err != nil {
			t.Fatalf("re-wrapped envelope %q invalid: %v", id, err)
		}
		// Data blob untouched: nonce and ciphertext identical to the original.
		orig, _ := Unmarshal(map[string][]byte{"plain": plainBlob, "ctx": ctxBlob, "escrowed": escrowBlob}[id])
		if !bytes.Equal(env.Nonce, orig.Nonce) || !bytes.Equal(env.Ciphertext, orig.Ciphertext) {
			t.Fatalf("re-wrap of %q touched the data blob", id)
		}
	}

	// Re-wrapped secrets decrypt (context-bound one still needs its context)...
	rewrapped := func(id string) []byte {
		s, _ := store.GetStoredSecret(id)
		return []byte(s.Envelope)
	}
	if got, err := ring2.DecryptJSON(ctx, rewrapped("plain"), nil); err != nil || string(got) != "plain secret" {
		t.Fatalf("decrypt rewrapped(plain) = %q, %v", got, err)
	}
	if got, err := ring2.DecryptJSON(ctx, rewrapped("ctx"), []byte("tenant=acme")); err != nil || string(got) != "context secret" {
		t.Fatalf("decrypt rewrapped(ctx) = %q, %v", got, err)
	}
	// ...the escrowed one is still recoverable by the agent quorum, on-token,
	// without either KEK version.
	escEnv, err := Unmarshal(rewrapped("escrowed"))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := NewRecoveryService(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rs.Recover(ctx, escEnv, []string{"a", "b"}, nil); err != nil || string(got) != "escrowed secret" {
		t.Fatalf("escrow recovery after rewrap = %q, %v", got, err)
	}
	if _, err := rs.Recover(ctx, escEnv, []string{"a"}, nil); err == nil {
		t.Fatal("sub-quorum escrow recovery must fail after rewrap")
	}
	// The pre-rewrap copy still decrypts: v1 is retiring, not retired.
	if got, err := ring2.DecryptJSON(ctx, preRewrapPlain, nil); err != nil || string(got) != "plain secret" {
		t.Fatalf("pre-rewrap copy decrypt = %q, %v", got, err)
	}

	// --- retire v1 ----------------------------------------------------------
	// The guard holds while a secret still sits on v1 (simulate a straggler).
	store.secrets["straggler"] = &models.StoredSecret{
		ID: "straggler", TenantID: "default", Name: "straggler", Envelope: string(preRewrapPlain),
		KEKFamily: family, KEKLabel: family, KEKVersion: 1,
	}
	if _, err := RetireKEK(store, family, 1, false); err == nil {
		t.Fatal("retire must be refused while a secret sits on v1")
	}
	if _, err := RewrapStoredSecrets(ctx, ring2, store, []string{"straggler"}); err != nil {
		t.Fatal(err)
	}
	if _, err := RetireKEK(store, family, 1, false); err != nil {
		t.Fatalf("retire after draining v1: %v", err)
	}

	ring3, err := loadRingFromStore(ctx, p, store, family)
	if err != nil {
		t.Fatal(err)
	}
	// Decryption fails ONLY after retirement, and only for v1 envelopes...
	if _, err := ring3.DecryptJSON(ctx, preRewrapPlain, nil); err == nil {
		t.Fatal("decrypt under the retired v1 KEK must fail")
	} else if !strings.Contains(err.Error(), "retired") {
		t.Fatalf("retired-KEK error should say so: %v", err)
	}
	if _, err := ring3.Rewrap(ctx, mustUnmarshal(t, preRewrapPlain)); err == nil {
		t.Fatal("re-wrap from the retired v1 KEK must fail")
	}
	// ...while re-wrapped and fresh secrets are unaffected.
	if got, err := ring3.DecryptJSON(ctx, rewrapped("plain"), nil); err != nil || string(got) != "plain secret" {
		t.Fatalf("rewrapped secret after retirement = %q, %v", got, err)
	}
	if got, err := ring3.DecryptJSON(ctx, freshBlob, nil); err != nil || string(got) != "fresh secret" {
		t.Fatalf("fresh secret after retirement = %q, %v", got, err)
	}
	if _, err := ring3.EncryptToJSON([]byte("post-retirement"), nil); err != nil {
		t.Fatalf("encrypt after retirement: %v", err)
	}
	// Escrow remains the break-glass path for stranded v1 ciphertext.
	if got, err := rs.Recover(ctx, mustUnmarshal(t, escrowBlob), []string{"a", "b"}, nil); err != nil || string(got) != "escrowed secret" {
		t.Fatalf("escrow recovery of a v1 envelope after retirement = %q, %v", got, err)
	}
}

func mustUnmarshal(t *testing.T, blob []byte) *Envelope {
	t.Helper()
	env, err := Unmarshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	return env
}
