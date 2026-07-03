package secret

// Unit tests for KEK rotation, the dual-KEK decrypt Ring, and DEK re-wrap,
// against the software key provider and an in-memory KEK/vault store. The
// SoftHSM acceptance flow lives in rotation_softhsm_test.go.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeKEKStore is an in-memory KEKStore + Vault, standing in for *database.DB.
type fakeKEKStore struct {
	versions map[string][]models.KEKVersion
	secrets  map[string]*models.StoredSecret
	// failUpdates makes every optimistic envelope update report a conflict.
	failUpdates bool
}

func newFakeKEKStore() *fakeKEKStore {
	return &fakeKEKStore{
		versions: make(map[string][]models.KEKVersion),
		secrets:  make(map[string]*models.StoredSecret),
	}
}

func (f *fakeKEKStore) ListKEKVersions(family string) ([]models.KEKVersion, error) {
	return append([]models.KEKVersion(nil), f.versions[family]...), nil
}

func (f *fakeKEKStore) ListKEKFamilies() ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for fam := range f.versions {
		if !seen[fam] {
			seen[fam] = true
			out = append(out, fam)
		}
	}
	for _, s := range f.secrets {
		if !seen[s.KEKFamily] {
			seen[s.KEKFamily] = true
			out = append(out, s.KEKFamily)
		}
	}
	return out, nil
}

func (f *fakeKEKStore) RotateKEKVersion(v *models.KEKVersion) error {
	now := time.Now().UTC()
	vs := f.versions[v.Family]
	if len(vs) == 0 && v.Version > 1 {
		vs = append(vs, models.KEKVersion{Family: v.Family, Version: 1, Label: v.Family, Status: models.KEKStatusActive, CreatedAt: now})
	}
	for i := range vs {
		if vs[i].Status == models.KEKStatusActive {
			vs[i].Status = models.KEKStatusRetiring
			t := now
			vs[i].RotatedAt = &t
		}
		if vs[i].Version == v.Version {
			return fmt.Errorf("duplicate version %d", v.Version)
		}
	}
	f.versions[v.Family] = append(vs, models.KEKVersion{
		Family: v.Family, Version: v.Version, Label: v.Label,
		Status: models.KEKStatusActive, CreatedAt: now,
	})
	return nil
}

func (f *fakeKEKStore) SetKEKVersionStatus(family string, version int, status string) (bool, error) {
	vs := f.versions[family]
	for i := range vs {
		if vs[i].Version == version {
			vs[i].Status = status
			if status == models.KEKStatusRetired {
				t := time.Now().UTC()
				vs[i].RetiredAt = &t
			}
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeKEKStore) CountStoredSecretsOnKEK(label string) (int64, error) {
	var n int64
	for _, s := range f.secrets {
		if s.KEKLabel == label {
			n++
		}
	}
	return n, nil
}

func (f *fakeKEKStore) CountStoredSecretsByKEKLabel(family string) (map[string]int64, error) {
	out := make(map[string]int64)
	for _, s := range f.secrets {
		if s.KEKFamily == family {
			out[s.KEKLabel]++
		}
	}
	return out, nil
}

func (f *fakeKEKStore) GetStoredSecret(id string) (*models.StoredSecret, error) {
	s, ok := f.secrets[id]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}

func (f *fakeKEKStore) ListStoredSecretIDsForRewrap(family, activeLabel string) ([]string, error) {
	var out []string
	for id, s := range f.secrets {
		if s.KEKFamily == family && s.KEKLabel != activeLabel {
			out = append(out, id)
		}
	}
	return out, nil
}

func (f *fakeKEKStore) UpdateStoredSecretEnvelope(id, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error) {
	if f.failUpdates {
		return false, nil
	}
	s, ok := f.secrets[id]
	if !ok || s.KEKLabel != expectKEKLabel {
		return false, nil
	}
	s.Envelope, s.KEKLabel, s.KEKVersion = envelope, kekLabel, kekVersion
	s.UpdatedAt = time.Now().UTC()
	return true, nil
}

// rotationFixture provisions a software-backed family KEK and rotates it once,
// returning the provider, store, and a Ring for the post-rotation lineage.
func rotationFixture(t *testing.T) (keyprovider.Provider, *fakeKEKStore, *Ring, *RotationResult) {
	t.Helper()
	ctx := context.Background()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	if _, err := ProvisionKEK(ctx, prov, "fam-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	store := newFakeKEKStore()
	res, err := RotateKEK(ctx, prov, store, "fam-kek", keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	ring, err := loadRingFromStore(ctx, prov, store, "fam-kek")
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}
	return prov, store, ring, res
}

func loadRingFromStore(ctx context.Context, prov keyprovider.Provider, store KEKStore, family string) (*Ring, error) {
	vs, err := store.ListKEKVersions(family)
	if err != nil {
		return nil, err
	}
	return LoadRing(ctx, prov, family, vs)
}

// sealV1 manufactures a legacy version-1 envelope under a Service's KEK — the
// shape every envelope had before this feature — so upgrade-on-rewrap and v1
// AAD binding stay covered even though seal() now emits version 2.
func sealV1(t *testing.T, svc *Service, plaintext, context []byte) *Envelope {
	t.Helper()
	return sealV1Escrow(t, svc, plaintext, context, nil)
}

func sealV1Escrow(t *testing.T, svc *Service, plaintext, context []byte, escrow *EscrowPolicy) *Envelope {
	t.Helper()
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		t.Fatal(err)
	}
	wrapped, alg, err := svc.wrapper.Wrap(dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	env := &Envelope{
		Version:      FormatVersion1,
		Provider:     svc.wrapper.ProviderName(),
		KEKLabel:     svc.wrapper.Label(),
		KEKURI:       svc.wrapper.URI(),
		WrapAlg:      alg,
		DataAlg:      AlgAES256GCM,
		WrappedDEK:   wrapped,
		Nonce:        nonce,
		ContextBound: len(context) > 0,
	}
	if escrow != nil {
		block, err := escrow.sealEscrow(dek)
		if err != nil {
			t.Fatalf("sealEscrow: %v", err)
		}
		env.Escrow = block
	}
	blockCipher, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		t.Fatal(err)
	}
	env.Ciphertext = gcm.Seal(nil, nonce, plaintext, env.aad(context))
	return env
}

func TestVersionLabel(t *testing.T) {
	if got := VersionLabel("kek", 1); got != "kek" {
		t.Errorf("v1 label = %q, want %q", got, "kek")
	}
	if got := VersionLabel("kek", 3); got != "kek-v3" {
		t.Errorf("v3 label = %q, want %q", got, "kek-v3")
	}
}

// TestRotateKEKLineage covers the rotation bookkeeping: versioned unique
// labels, the implicit-v1 backfill, active/retiring statuses, and the refusal
// to bootstrap a family that has no key.
func TestRotateKEKLineage(t *testing.T) {
	ctx := context.Background()
	_, store, ring, res := rotationFixture(t)

	if res.OldVersion != 1 || res.OldLabel != "fam-kek" || res.NewVersion != 2 || res.NewLabel != "fam-kek-v2" {
		t.Fatalf("unexpected rotation result: %+v", res)
	}
	vs, _ := store.ListKEKVersions("fam-kek")
	if len(vs) != 2 {
		t.Fatalf("lineage has %d versions, want 2 (implicit v1 backfilled)", len(vs))
	}
	if vs[0].Status != models.KEKStatusRetiring || vs[1].Status != models.KEKStatusActive {
		t.Fatalf("statuses = %q,%q; want retiring,active", vs[0].Status, vs[1].Status)
	}
	if ring.ActiveVersion() != 2 || ring.ActiveLabel() != "fam-kek-v2" {
		t.Fatalf("ring active = v%d %q", ring.ActiveVersion(), ring.ActiveLabel())
	}

	// A rotation of a family with no key at all must be refused.
	prov2, _ := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if _, err := RotateKEK(ctx, prov2, newFakeKEKStore(), "ghost", ""); err == nil {
		t.Fatal("rotating a family with no existing KEK must fail")
	}
}

// TestDualKEKDecryptWindow is the rotate → old secrets still decrypt → new
// encrypts land on the new KEK flow, plus fail-closed handling of unknown
// labels.
func TestDualKEKDecryptWindow(t *testing.T) {
	ctx := context.Background()
	prov, store, _, _ := rotationFixture(t)

	// Seal one envelope under v1 BEFORE rotation semantics: build a v1-bound
	// service the way pre-rotation deployments did.
	v1svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: "fam-kek"})
	if err != nil {
		t.Fatal(err)
	}
	oldBlob, err := v1svc.EncryptToJSON([]byte("sealed before rotation"), nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := sealV1(t, v1svc, []byte("legacy v1 envelope"), nil)

	ring, err := loadRingFromStore(ctx, prov, store, "fam-kek")
	if err != nil {
		t.Fatal(err)
	}

	// Old envelopes (v2-on-old-KEK and legacy v1) still decrypt through the ring.
	if got, err := ring.DecryptJSON(ctx, oldBlob, nil); err != nil || string(got) != "sealed before rotation" {
		t.Fatalf("old envelope decrypt = %q, %v", got, err)
	}
	if got, err := ring.Decrypt(ctx, legacy, nil); err != nil || string(got) != "legacy v1 envelope" {
		t.Fatalf("legacy envelope decrypt = %q, %v", got, err)
	}

	// New encrypts land on the new versioned label.
	env, err := ring.Encrypt([]byte("sealed after rotation"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if env.KEKLabel != "fam-kek-v2" || env.KEKVersion != 2 {
		t.Fatalf("new envelope wrap header = %q v%d, want fam-kek-v2 v2", env.KEKLabel, env.KEKVersion)
	}
	if got, err := ring.Decrypt(ctx, env, nil); err != nil || string(got) != "sealed after rotation" {
		t.Fatalf("new envelope decrypt = %q, %v", got, err)
	}

	// A label outside the lineage is refused.
	stray := *env
	stray.KEKLabel = "not-in-family"
	if _, err := ring.Decrypt(ctx, &stray, nil); err == nil {
		t.Fatal("decrypt under a label outside the family must fail")
	}
}

// TestRewrapMigratesOnlyTheHeader is the core re-wrap property: the DEK moves
// to the new KEK while nonce, ciphertext, context binding, and escrow bytes
// stay identical, for both native-v2 and legacy-v1 (upgraded) envelopes.
func TestRewrapMigratesOnlyTheHeader(t *testing.T) {
	ctx := context.Background()
	prov, store, _, _ := rotationFixture(t)
	v1svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: "fam-kek"})
	if err != nil {
		t.Fatal(err)
	}
	ring, err := loadRingFromStore(ctx, prov, store, "fam-kek")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("native v2 envelope", func(t *testing.T) {
		env, err := v1svc.Encrypt([]byte("v2 payload"), nil)
		if err != nil {
			t.Fatal(err)
		}
		nonce := append([]byte(nil), env.Nonce...)
		ct := append([]byte(nil), env.Ciphertext...)
		commit := append([]byte(nil), env.DEKCommit...)

		changed, err := ring.Rewrap(ctx, env)
		if err != nil || !changed {
			t.Fatalf("Rewrap = %v, %v; want changed", changed, err)
		}
		if env.KEKLabel != "fam-kek-v2" || env.KEKVersion != 2 {
			t.Fatalf("rewrapped header = %q v%d", env.KEKLabel, env.KEKVersion)
		}
		if !bytes.Equal(env.Nonce, nonce) || !bytes.Equal(env.Ciphertext, ct) || !bytes.Equal(env.DEKCommit, commit) {
			t.Fatal("re-wrap touched the data blob (nonce/ciphertext/commitment must be byte-identical)")
		}
		if env.Origin != nil {
			t.Fatal("native v2 envelope gained an origin block")
		}
		if got, err := ring.Decrypt(ctx, env, nil); err != nil || string(got) != "v2 payload" {
			t.Fatalf("decrypt after rewrap = %q, %v", got, err)
		}
		// Idempotence: already on the active KEK.
		if changed, err := ring.Rewrap(ctx, env); err != nil || changed {
			t.Fatalf("second Rewrap = %v, %v; want no-op", changed, err)
		}
	})

	t.Run("legacy v1 envelope upgrades with origin", func(t *testing.T) {
		env := sealV1(t, v1svc, []byte("v1 payload"), []byte("ctx"))
		nonce := append([]byte(nil), env.Nonce...)
		ct := append([]byte(nil), env.Ciphertext...)

		// Note: no encryption context is needed to re-wrap a context-bound
		// envelope — the plaintext is never touched.
		changed, err := ring.Rewrap(ctx, env)
		if err != nil || !changed {
			t.Fatalf("Rewrap = %v, %v; want changed", changed, err)
		}
		if env.Version != FormatVersion2 {
			t.Fatalf("upgraded version = %d, want 2", env.Version)
		}
		if env.Origin == nil || env.Origin.KEKLabel != "fam-kek" {
			t.Fatalf("origin = %+v, want frozen v1 label fam-kek", env.Origin)
		}
		if env.KEKLabel != "fam-kek-v2" || env.KEKVersion != 2 {
			t.Fatalf("rewrapped header = %q v%d", env.KEKLabel, env.KEKVersion)
		}
		if len(env.DEKCommit) != 32 {
			t.Fatalf("upgraded envelope has no DEK commitment")
		}
		if !bytes.Equal(env.Nonce, nonce) || !bytes.Equal(env.Ciphertext, ct) {
			t.Fatal("re-wrap touched the data blob")
		}
		// Round-trip through JSON (validate() must accept the upgraded shape)
		// and decrypt with the original context.
		blob, err := env.Marshal()
		if err != nil {
			t.Fatalf("Marshal upgraded: %v", err)
		}
		if got, err := ring.DecryptJSON(ctx, blob, []byte("ctx")); err != nil || string(got) != "v1 payload" {
			t.Fatalf("decrypt upgraded = %q, %v", got, err)
		}
		// Wrong context still fails (context binding survived the upgrade).
		if _, err := ring.DecryptJSON(ctx, blob, []byte("wrong")); err == nil {
			t.Fatal("upgraded envelope decrypted under the wrong context")
		}
		// Tampering with the frozen origin label breaks the reconstructed AAD.
		bad := *env
		bad.Origin = &OriginBinding{KEKLabel: "attacker", WrapAlg: env.Origin.WrapAlg}
		if _, err := ring.Decrypt(ctx, &bad, []byte("ctx")); err == nil {
			t.Fatal("tampered origin label must fail decryption")
		}
	})
}

// TestRewrapPreservesEscrow proves escrow (Task 33) compatibility: after a
// re-wrap the same recovery-agent quorum still reconstructs the DEK and
// decrypts, for native-v2 and upgraded-v1 envelopes alike, and a sub-quorum
// still cannot.
func TestRewrapPreservesEscrow(t *testing.T) {
	ctx := context.Background()
	prov, store, _, _ := rotationFixture(t)
	v1svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: "fam-kek"})
	if err != nil {
		t.Fatal(err)
	}
	ring, err := loadRingFromStore(ctx, prov, store, "fam-kek")
	if err != nil {
		t.Fatal(err)
	}

	// Two recovery agents, 2-of-2.
	specs := make([]AgentSpec, 2)
	for i := range specs {
		id := fmt.Sprintf("agent-%d", i+1)
		if _, err := prov.GenerateKey(ctx, keyprovider.KeySpec{
			Label: id, KeyType: keyprovider.KeyTypeRSA2048, Usage: keyprovider.KeyUsageDecrypt,
		}); err != nil {
			t.Fatal(err)
		}
		specs[i] = AgentSpec{ID: id, KeyLabel: id}
	}
	policy, err := NewEscrowPolicy(ctx, prov, 2, specs)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := NewRecoveryService(prov)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		env  *Envelope
	}{
		{"native v2", mustEncryptEscrow(t, v1svc, []byte("escrowed v2"), policy)},
		{"legacy v1", sealV1Escrow(t, v1svc, []byte("escrowed v1"), nil, policy)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			escrowBytes := env.Escrow.digest()
			want := "escrowed v2"
			if tc.name == "legacy v1" {
				want = "escrowed v1"
			}

			changed, err := ring.Rewrap(ctx, env)
			if err != nil || !changed {
				t.Fatalf("Rewrap = %v, %v", changed, err)
			}
			if !bytes.Equal(env.Escrow.digest(), escrowBytes) {
				t.Fatal("re-wrap altered the escrow block")
			}
			// The full quorum still recovers WITHOUT the (new or old) KEK.
			got, err := rs.Recover(ctx, env, []string{"agent-1", "agent-2"}, nil)
			if err != nil {
				t.Fatalf("escrow recovery after rewrap: %v", err)
			}
			if string(got) != want {
				t.Fatalf("recovered %q, want %q", got, want)
			}
			// A sub-quorum still cannot.
			if _, err := rs.Recover(ctx, env, []string{"agent-1"}, nil); err == nil {
				t.Fatal("sub-quorum recovery must fail")
			}
			// And the ordinary KEK path decrypts under the new KEK.
			if got, err := ring.Decrypt(ctx, env, nil); err != nil || string(got) != want {
				t.Fatalf("KEK decrypt after rewrap = %q, %v", got, err)
			}
		})
	}
}

func mustEncryptEscrow(t *testing.T, svc *Service, plaintext []byte, policy *EscrowPolicy) *Envelope {
	t.Helper()
	env, err := svc.EncryptWithEscrow(plaintext, nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestRetireKEK covers the retire-guard and the fail-closed post-retirement
// behavior: decrypt and re-wrap under a retired version are refused, and
// retirement is refused while secrets still sit on the version (unless forced).
func TestRetireKEK(t *testing.T) {
	ctx := context.Background()
	prov, store, ring, _ := rotationFixture(t)
	v1svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: "fam-kek"})
	if err != nil {
		t.Fatal(err)
	}
	env, err := v1svc.Encrypt([]byte("still on v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := env.Marshal()
	store.secrets["s1"] = &models.StoredSecret{
		ID: "s1", TenantID: "default", Name: "s1", Envelope: string(blob),
		KEKFamily: "fam-kek", KEKLabel: "fam-kek", KEKVersion: 1,
	}

	// The active version cannot be retired; an unknown version errors.
	if _, err := RetireKEK(store, "fam-kek", 2, false); err == nil {
		t.Fatal("retiring the active version must fail")
	}
	if _, err := RetireKEK(store, "fam-kek", 9, false); err == nil {
		t.Fatal("retiring an unknown version must fail")
	}
	// The guard refuses while a secret still sits on v1.
	if _, err := RetireKEK(store, "fam-kek", 1, false); err == nil || !strings.Contains(err.Error(), "re-wrap") {
		t.Fatalf("retire with secrets on the version must fail with guidance, got %v", err)
	}

	// Re-wrap the fleet, then retirement succeeds.
	report, err := RewrapStoredSecrets(ctx, ring, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Rewrapped != 1 || report.Failed != 0 {
		t.Fatalf("rewrap report = %+v", report)
	}
	if _, err := RetireKEK(store, "fam-kek", 1, false); err != nil {
		t.Fatalf("retire after rewrap: %v", err)
	}
	if _, err := RetireKEK(store, "fam-kek", 1, false); err == nil {
		t.Fatal("double retirement must fail")
	}

	// A ring loaded after retirement refuses v1 envelopes — and only them.
	ring2, err := loadRingFromStore(ctx, prov, store, "fam-kek")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring2.Decrypt(ctx, env, nil); err == nil {
		t.Fatal("decrypt under a retired KEK must fail")
	} else if !strings.Contains(err.Error(), "retired") {
		t.Fatalf("retired-KEK decrypt error should say so, got: %v", err)
	}
	if _, err := ring2.Rewrap(ctx, env); err == nil {
		t.Fatal("re-wrap from a retired KEK must fail")
	}
	rewrapped, _ := store.GetStoredSecret("s1")
	if got, err := ring2.DecryptJSON(ctx, []byte(rewrapped.Envelope), nil); err != nil || string(got) != "still on v1" {
		t.Fatalf("re-wrapped secret must survive retirement: %q, %v", got, err)
	}
}

// TestRewrapStoredSecretsBatch covers the fleet migration: work-list
// enumeration, per-item failure isolation, family scoping, and optimistic
// conflict accounting.
func TestRewrapStoredSecretsBatch(t *testing.T) {
	ctx := context.Background()
	prov, store, ring, _ := rotationFixture(t)
	v1svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: "fam-kek"})
	if err != nil {
		t.Fatal(err)
	}

	addSecret := func(id, payload string) {
		t.Helper()
		blob, err := v1svc.EncryptToJSON([]byte(payload), nil)
		if err != nil {
			t.Fatal(err)
		}
		store.secrets[id] = &models.StoredSecret{
			ID: id, TenantID: "default", Name: id, Envelope: string(blob),
			KEKFamily: "fam-kek", KEKLabel: "fam-kek", KEKVersion: 1,
		}
	}
	addSecret("a", "alpha")
	addSecret("b", "beta")
	store.secrets["corrupt"] = &models.StoredSecret{
		ID: "corrupt", TenantID: "default", Name: "corrupt", Envelope: "{not json",
		KEKFamily: "fam-kek", KEKLabel: "fam-kek", KEKVersion: 1,
	}
	store.secrets["other"] = &models.StoredSecret{
		ID: "other", TenantID: "default", Name: "other", Envelope: "{}",
		KEKFamily: "other-family", KEKLabel: "other-family", KEKVersion: 1,
	}

	report, err := RewrapStoredSecrets(ctx, ring, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 3 || report.Rewrapped != 2 || report.Failed != 1 {
		t.Fatalf("fleet report = %+v; want total 3, rewrapped 2, failed 1 (corrupt)", report)
	}
	for _, id := range []string{"a", "b"} {
		s, _ := store.GetStoredSecret(id)
		if s.KEKLabel != "fam-kek-v2" || s.KEKVersion != 2 {
			t.Fatalf("secret %s not migrated: %+v", id, s)
		}
		if got, err := ring.DecryptJSON(ctx, []byte(s.Envelope), nil); err != nil {
			t.Fatalf("decrypt migrated %s: %v (%q)", id, err, got)
		}
	}
	if s, _ := store.GetStoredSecret("other"); s.KEKLabel != "other-family" {
		t.Fatal("fleet rewrap crossed into another family")
	}

	// Explicit IDs: a foreign-family secret is refused, a missing one fails.
	report, err = RewrapStoredSecrets(ctx, ring, store, []string{"other", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 2 || report.Rewrapped != 0 {
		t.Fatalf("explicit-id report = %+v; want 2 failures", report)
	}

	// Optimistic conflicts are counted, not treated as success.
	addSecret("c", "gamma")
	store.failUpdates = true
	report, err = RewrapStoredSecrets(ctx, ring, store, []string{"c"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Conflicts != 1 || report.Rewrapped != 0 {
		t.Fatalf("conflict report = %+v; want 1 conflict", report)
	}
}

// TestBuildKEKStatusAndMetricsRefresh covers the status report and the
// monitor-facing gauge refresh warnings.
func TestBuildKEKStatusAndMetricsRefresh(t *testing.T) {
	ctx := context.Background()
	prov, store, ring, _ := rotationFixture(t)
	v1svc, err := NewService(ctx, prov, keyprovider.KeyRef{Label: "fam-kek"})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := v1svc.EncryptToJSON([]byte("x"), nil)
	store.secrets["s1"] = &models.StoredSecret{
		ID: "s1", TenantID: "default", Name: "s1", Envelope: string(blob),
		KEKFamily: "fam-kek", KEKLabel: "fam-kek", KEKVersion: 1,
	}

	st, err := BuildKEKStatus(store, "fam-kek")
	if err != nil {
		t.Fatal(err)
	}
	if st.ActiveVersion != 2 || st.SecretsOnOldKEK != 1 || st.StoredSecrets != 1 {
		t.Fatalf("status = %+v", st)
	}
	warns, err := RefreshKEKMetrics(store, "fam-kek")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "rewrap") {
		t.Fatalf("warnings = %v; want one rewrap hint", warns)
	}

	// After migration the family is clean and a never-rotated default family
	// reports version 1 with no warnings.
	if _, err := RewrapStoredSecrets(ctx, ring, store, nil); err != nil {
		t.Fatal(err)
	}
	warns, err = RefreshKEKMetrics(store, "fresh-family")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("clean refresh produced warnings: %v", warns)
	}
	st, err = BuildKEKStatus(store, "fresh-family")
	if err != nil {
		t.Fatal(err)
	}
	if !st.NeverRotated || st.ActiveVersion != 1 {
		t.Fatalf("fresh family status = %+v", st)
	}
}

// TestRotateKEKAdoptsOrphanKey covers the crash-retry path: a key generated by
// a rotation that died before recording it is adopted (not regenerated) on the
// next attempt, keeping HSM labels unique.
func TestRotateKEKAdoptsOrphanKey(t *testing.T) {
	ctx := context.Background()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProvisionKEK(ctx, prov, "fam-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatal(err)
	}
	// Simulate the orphan: the v2 key exists, but the store never heard of it.
	if _, err := prov.GenerateKey(ctx, keyprovider.KeySpec{
		Label: "fam-kek-v2", KeyType: keyprovider.KeyTypeRSA2048, Usage: keyprovider.KeyUsageDecrypt,
	}); err != nil {
		t.Fatal(err)
	}
	store := newFakeKEKStore()
	res, err := RotateKEK(ctx, prov, store, "fam-kek", keyprovider.KeyTypeRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Adopted || res.NewLabel != "fam-kek-v2" {
		t.Fatalf("expected orphan adoption, got %+v", res)
	}
}
