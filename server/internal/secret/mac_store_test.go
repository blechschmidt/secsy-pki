package secret

// Tests for the stateful half of the keyed-HMAC service (mac.go): lazily
// provisioning a family's MAC key, unwrapping a stored row's sealed seed, and
// the tag/verify entry points that hang off a row. mac_test.go already covers
// the pure derivation; what matters here is the *lifecycle*, because a MAC key
// that silently changes invalidates every token ever issued under it.
//
// Everything runs against the software key provider, so no HSM is required.

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeMACStore is an in-memory MACStore standing in for *database.DB, with hooks
// for the failure and race paths EnsureActiveMACKey has to survive.
type fakeMACStore struct {
	rows    map[string][]*models.MACKey // by family, in insertion order
	inserts int

	getErr    error
	maxErr    error
	insertErr error
	// beforeInsert runs before an insert is applied; a test uses it to plant a
	// concurrent writer's row (and then return a conflict error).
	beforeInsert func(k *models.MACKey) error
}

func newFakeMACStore() *fakeMACStore {
	return &fakeMACStore{rows: map[string][]*models.MACKey{}}
}

func (f *fakeMACStore) GetActiveMACKey(family string) (*models.MACKey, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	var best *models.MACKey
	for _, r := range f.rows[family] {
		if r.Status == models.MACKeyStatusActive && (best == nil || r.Version > best.Version) {
			best = r
		}
	}
	if best == nil {
		return nil, nil
	}
	cp := *best
	return &cp, nil
}

func (f *fakeMACStore) GetMACKeyVersion(family string, version int) (*models.MACKey, error) {
	for _, r := range f.rows[family] {
		if r.Version == version {
			cp := *r
			return &cp, nil
		}
	}
	return nil, nil
}

func (f *fakeMACStore) MaxMACKeyVersion(family string) (int, error) {
	if f.maxErr != nil {
		return 0, f.maxErr
	}
	max := 0
	for _, r := range f.rows[family] {
		if r.Version > max {
			max = r.Version
		}
	}
	return max, nil
}

func (f *fakeMACStore) InsertMACKey(k *models.MACKey) error {
	if f.beforeInsert != nil {
		if err := f.beforeInsert(k); err != nil {
			return err
		}
	}
	if f.insertErr != nil {
		return f.insertErr
	}
	for _, r := range f.rows[k.Family] {
		if r.Version == k.Version {
			return fmt.Errorf("fakeMACStore: duplicate primary key (%s, %d)", k.Family, k.Version)
		}
	}
	cp := *k
	f.rows[k.Family] = append(f.rows[k.Family], &cp)
	f.inserts++
	return nil
}

// macRing provisions a software KEK and returns a Ring for it, the cheapest
// HSM-free stand-in for the family's key ring.
func macRing(t *testing.T, family string) *Ring {
	t.Helper()
	ctx := context.Background()
	prov := newSoftwareProvider(t)
	if _, err := ProvisionKEK(ctx, prov, family, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK(%s): %v", family, err)
	}
	ring, err := LoadRing(ctx, prov, family, nil)
	if err != nil {
		t.Fatalf("LoadRing(%s): %v", family, err)
	}
	return ring
}

// countingSeedRand hands out a DIFFERENT seed on every call, so any code path
// that re-mints a seed when it should have reused the stored one produces a
// different MAC key and is caught by a tag that no longer verifies.
func countingSeedRand(calls *int) func(int) ([]byte, error) {
	return func(n int) ([]byte, error) {
		*calls++
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(*calls)*31 ^ byte(i)
		}
		return b, nil
	}
}

// TestEnsureActiveMACKeyIsIdempotent is the central lifecycle invariant: the
// first call provisions version 1 and every later call returns that same row.
// Minting a fresh key per call would silently invalidate every previously issued
// HMAC token, so the test proves it by verifying a tag computed BEFORE the second
// call against the row returned AFTER it.
func TestEnsureActiveMACKeyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	ring := macRing(t, "mac-fam")
	store := newFakeMACStore()
	calls := 0
	seedRand := countingSeedRand(&calls)

	first, err := EnsureActiveMACKey(ctx, store, ring, "mac-fam", seedRand)
	if err != nil {
		t.Fatalf("EnsureActiveMACKey: %v", err)
	}
	if first.Version != 1 {
		t.Errorf("first provisioned version = %d, want 1", first.Version)
	}
	if first.Status != models.MACKeyStatusActive {
		t.Errorf("provisioned status = %q, want %q", first.Status, models.MACKeyStatusActive)
	}
	if first.Family != "mac-fam" {
		t.Errorf("provisioned family = %q, want mac-fam", first.Family)
	}
	if first.Envelope == "" {
		t.Fatal("provisioned row carries no sealed envelope")
	}

	data := []byte("POST /api/v1/orders\n{\"id\":1}")
	tag, err := TagHMAC(ctx, ring, first, data)
	if err != nil {
		t.Fatalf("TagHMAC: %v", err)
	}
	if len(tag) != 32 {
		t.Errorf("HMAC-SHA256 tag length = %d, want 32", len(tag))
	}

	for i := 0; i < 3; i++ {
		again, err := EnsureActiveMACKey(ctx, store, ring, "mac-fam", seedRand)
		if err != nil {
			t.Fatalf("EnsureActiveMACKey call %d: %v", i+2, err)
		}
		if again.Version != first.Version {
			t.Fatalf("call %d returned version %d, want the existing %d", i+2, again.Version, first.Version)
		}
		if again.Envelope != first.Envelope {
			t.Fatalf("call %d re-sealed the MAC key seed (envelope changed); every issued token would break", i+2)
		}
		ok, err := CheckHMAC(ctx, ring, again, data, tag)
		if err != nil {
			t.Fatalf("CheckHMAC after call %d: %v", i+2, err)
		}
		if !ok {
			t.Fatalf("a tag issued before call %d no longer verifies: the active MAC key changed", i+2)
		}
	}
	if store.inserts != 1 {
		t.Errorf("store saw %d inserts, want exactly 1", store.inserts)
	}
	if calls != 1 {
		t.Errorf("seed generator was called %d times, want exactly 1", calls)
	}
}

// TestEnsureActiveMACKeySealsSeedAndZeroizes checks the two handling rules for
// the freshly minted seed: it is only persisted sealed (never in the clear), and
// the caller's buffer is wiped before the function returns.
func TestEnsureActiveMACKeySealsSeedAndZeroizes(t *testing.T) {
	ctx := context.Background()
	ring := macRing(t, "mac-seal")
	store := newFakeMACStore()

	// handed is the exact slice EnsureActiveMACKey receives; kept is our own copy
	// of the bytes, since the seed buffer is expected to be zeroized in place.
	var handed, kept []byte
	seedRand := func(n int) ([]byte, error) {
		handed = make([]byte, n)
		for i := range handed {
			handed[i] = byte(0xA5 ^ i)
		}
		kept = append([]byte(nil), handed...)
		return handed, nil
	}

	row, err := EnsureActiveMACKey(ctx, store, ring, "mac-seal", seedRand)
	if err != nil {
		t.Fatalf("EnsureActiveMACKey: %v", err)
	}
	if len(kept) != MACSeedBytes {
		t.Fatalf("seed generator asked for %d bytes, want %d", len(kept), MACSeedBytes)
	}
	if bytes.Contains([]byte(row.Envelope), kept) {
		t.Error("the sealed envelope contains the raw seed")
	}
	if strings.Contains(row.Envelope, base64.StdEncoding.EncodeToString(kept)) {
		t.Error("the sealed envelope contains the base64-encoded seed")
	}
	if !bytes.Equal(handed, make([]byte, len(handed))) {
		t.Errorf("the seed buffer was not zeroized after use: %x", handed)
	}

	// The seed is recoverable only through the KEK, and it must be the same bytes
	// that were minted — otherwise the derived MAC key would not be reproducible.
	unsealed, err := ring.DecryptJSON(ctx, []byte(row.Envelope), nil)
	if err != nil {
		t.Fatalf("unsealing the stored seed: %v", err)
	}
	if !bytes.Equal(unsealed, kept) {
		t.Error("the unsealed seed differs from the minted one")
	}
}

// TestEnsureActiveMACKeyAdvancesPastRetiredVersions: with no active row but a
// retired version 1 on file, the next key must be version 2. Reusing version 1
// would mean two different keys share one version number, so tokens issued under
// the old key would fail to verify with no way to tell why — while the retired
// row itself must keep verifying its own tags.
func TestEnsureActiveMACKeyAdvancesPastRetiredVersions(t *testing.T) {
	ctx := context.Background()
	ring := macRing(t, "mac-rotate")
	store := newFakeMACStore()
	calls := 0
	seedRand := countingSeedRand(&calls)

	v1, err := EnsureActiveMACKey(ctx, store, ring, "mac-rotate", seedRand)
	if err != nil {
		t.Fatalf("provisioning v1: %v", err)
	}
	data := []byte("token payload")
	oldTag, err := TagHMAC(ctx, ring, v1, data)
	if err != nil {
		t.Fatalf("TagHMAC under v1: %v", err)
	}

	// Retire v1, as `rotate` would.
	store.rows["mac-rotate"][0].Status = models.MACKeyStatusRetired

	v2, err := EnsureActiveMACKey(ctx, store, ring, "mac-rotate", seedRand)
	if err != nil {
		t.Fatalf("provisioning v2: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("new version = %d, want 2 (a retired version number must not be reused)", v2.Version)
	}
	if v2.Envelope == v1.Envelope {
		t.Error("the new version reused the retired version's sealed seed")
	}

	// The retired row still verifies the token it issued...
	ok, err := CheckHMAC(ctx, ring, store.rows["mac-rotate"][0], data, oldTag)
	if err != nil {
		t.Fatalf("CheckHMAC under retired v1: %v", err)
	}
	if !ok {
		t.Error("a token issued under v1 no longer verifies under the retired v1 row")
	}
	// ...and the new version must not verify it (version-bound derivation).
	ok, err = CheckHMAC(ctx, ring, v2, data, oldTag)
	if err != nil {
		t.Fatalf("CheckHMAC under v2: %v", err)
	}
	if ok {
		t.Error("a v1 token verified under the v2 key; the versions are not domain-separated")
	}
}

// TestEnsureActiveMACKeyAdoptsRaceWinner: when two requests provision the same
// family at once the loser's insert hits the (family, version) primary key. It
// must re-read and adopt the winner's row rather than failing the request or —
// far worse — returning its own unsaved key, which would tag with a key nobody
// can later verify against.
func TestEnsureActiveMACKeyAdoptsRaceWinner(t *testing.T) {
	ctx := context.Background()
	ring := macRing(t, "mac-race")
	store := newFakeMACStore()

	winnerSeed := bytes.Repeat([]byte{0x7e}, MACSeedBytes)
	winnerEnv, err := ring.EncryptToJSON(winnerSeed, nil)
	if err != nil {
		t.Fatalf("sealing the winner's seed: %v", err)
	}
	store.beforeInsert = func(k *models.MACKey) error {
		// The winner lands first, then our insert conflicts.
		store.beforeInsert = nil
		store.rows[k.Family] = append(store.rows[k.Family], &models.MACKey{
			Family: k.Family, Version: k.Version, Envelope: string(winnerEnv), Status: models.MACKeyStatusActive,
		})
		return fmt.Errorf("UNIQUE constraint failed: mac_keys.family, mac_keys.version")
	}

	calls := 0
	row, err := EnsureActiveMACKey(ctx, store, ring, "mac-race", countingSeedRand(&calls))
	if err != nil {
		t.Fatalf("EnsureActiveMACKey lost the race and gave up: %v", err)
	}
	if row.Envelope != string(winnerEnv) {
		t.Fatal("the loser returned its own unsaved key instead of the winner's stored row")
	}
	// The adopted row must be usable: a tag under it verifies against the row a
	// later reader would load from the store.
	tag, err := TagHMAC(ctx, ring, row, []byte("payload"))
	if err != nil {
		t.Fatalf("TagHMAC with the adopted row: %v", err)
	}
	stored, err := store.GetActiveMACKey("mac-race")
	if err != nil || stored == nil {
		t.Fatalf("GetActiveMACKey: %v (row=%v)", err, stored)
	}
	ok, err := CheckHMAC(ctx, ring, stored, []byte("payload"), tag)
	if err != nil || !ok {
		t.Fatalf("the adopted row does not agree with the stored row: ok=%v err=%v", ok, err)
	}
}

// TestEnsureActiveMACKeyErrorPaths: every failure must surface as an error with
// no row handed back. Returning a zero-valued row here would make TagHMAC derive
// from an empty envelope.
func TestEnsureActiveMACKeyErrorPaths(t *testing.T) {
	ctx := context.Background()
	ring := macRing(t, "mac-err")
	boom := fmt.Errorf("database is locked")

	cases := map[string]func(*fakeMACStore) func(int) ([]byte, error){
		"read of the active row fails": func(s *fakeMACStore) func(int) ([]byte, error) {
			s.getErr = boom
			return func(n int) ([]byte, error) { return make([]byte, n), nil }
		},
		"seed generation fails": func(s *fakeMACStore) func(int) ([]byte, error) {
			return func(int) ([]byte, error) { return nil, fmt.Errorf("HSM RNG unavailable") }
		},
		"version lookup fails": func(s *fakeMACStore) func(int) ([]byte, error) {
			s.maxErr = boom
			return func(n int) ([]byte, error) { return make([]byte, n), nil }
		},
		"insert fails with no winner to adopt": func(s *fakeMACStore) func(int) ([]byte, error) {
			s.insertErr = boom
			return func(n int) ([]byte, error) { return make([]byte, n), nil }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			store := newFakeMACStore()
			seedRand := setup(store)
			row, err := EnsureActiveMACKey(ctx, store, ring, "mac-err", seedRand)
			if err == nil {
				t.Fatalf("EnsureActiveMACKey succeeded, returning %+v", row)
			}
			if row != nil {
				t.Errorf("failed EnsureActiveMACKey returned a row: %+v", row)
			}
		})
	}

	// A seed of the wrong size must never turn into a MAC key. Both production
	// seed sources (handlers.API.randomBytes and cliRandomBytes) already refuse a
	// short read from the HSM RNG and fall back to the OS CSPRNG, so the guard
	// that matters here is the length check inside the derivation.
	t.Run("short seed never yields a derived key", func(t *testing.T) {
		store := newFakeMACStore()
		row, err := EnsureActiveMACKey(ctx, store, ring, "mac-err", func(int) ([]byte, error) {
			return bytes.Repeat([]byte{0x01}, MACSeedBytes/2), nil
		})
		if err != nil {
			// Refusing up front is the ideal behavior.
			if store.inserts != 0 {
				t.Errorf("a short seed was stored anyway (%d inserts)", store.inserts)
			}
			return
		}
		// Otherwise the row exists, and the failure must at least be loud at use
		// time rather than producing a key from a truncated seed.
		if _, err := macKeyFromRow(ctx, ring, row); err == nil {
			t.Fatal("a MAC key was derived from a short seed")
		}
	})
}

// TestMACKeyFromRowRejectsCorruptRows: an unreadable row must produce an error,
// never a key. A zero or partially derived key would still compute and "verify"
// tags, so callers could not tell a corrupt row from a working one.
func TestMACKeyFromRowRejectsCorruptRows(t *testing.T) {
	ctx := context.Background()
	ring := macRing(t, "mac-corrupt")
	other := macRing(t, "mac-other")

	goodSeed := bytes.Repeat([]byte{0x42}, MACSeedBytes)
	good, err := ring.EncryptToJSON(goodSeed, nil)
	if err != nil {
		t.Fatalf("sealing a good seed: %v", err)
	}
	shortSeed, err := ring.EncryptToJSON(bytes.Repeat([]byte{0x42}, 16), nil)
	if err != nil {
		t.Fatalf("sealing a short seed: %v", err)
	}
	foreign, err := other.EncryptToJSON(goodSeed, nil)
	if err != nil {
		t.Fatalf("sealing under the other KEK: %v", err)
	}
	tampered := append([]byte(nil), good...)
	env := decodeEnv(t, tampered)
	env.Ciphertext[0] ^= 0x01
	retampered, err := env.Marshal()
	if err != nil {
		t.Fatalf("re-marshalling the tampered envelope: %v", err)
	}

	// A control: the good row does derive a key, so the failures below are about
	// the corruption and not about the fixture.
	if key, err := macKeyFromRow(ctx, ring, &models.MACKey{Family: "mac-corrupt", Version: 1, Envelope: string(good)}); err != nil || len(key) != macKeyBytes {
		t.Fatalf("control row failed: err=%v len=%d", err, len(key))
	}

	cases := map[string]*models.MACKey{
		"empty envelope":           {Family: "mac-corrupt", Version: 1, Envelope: ""},
		"not json":                 {Family: "mac-corrupt", Version: 1, Envelope: "not an envelope"},
		"empty json object":        {Family: "mac-corrupt", Version: 1, Envelope: "{}"},
		"truncated json":           {Family: "mac-corrupt", Version: 1, Envelope: string(good[:len(good)/2])},
		"seed of the wrong size":   {Family: "mac-corrupt", Version: 1, Envelope: string(shortSeed)},
		"tampered ciphertext":      {Family: "mac-corrupt", Version: 1, Envelope: string(retampered)},
		"sealed under another kek": {Family: "mac-corrupt", Version: 1, Envelope: string(foreign)},
		"non positive version":     {Family: "mac-corrupt", Version: 0, Envelope: string(good)},
		"negative version":         {Family: "mac-corrupt", Version: -1, Envelope: string(good)},
	}
	for name, row := range cases {
		t.Run(name, func(t *testing.T) {
			key, err := macKeyFromRow(ctx, ring, row)
			if err == nil {
				t.Fatalf("macKeyFromRow accepted a %s row and returned %d bytes", name, len(key))
			}
			if key != nil {
				t.Errorf("failed macKeyFromRow returned %d bytes of key material (%x)", len(key), key)
			}
			// The tag/verify wrappers must propagate the failure, not fall back
			// to a default key or report a successful verification.
			if tag, err := TagHMAC(ctx, ring, row, []byte("data")); err == nil {
				t.Errorf("TagHMAC produced a tag (%x) from a %s row", tag, name)
			}
			if ok, err := CheckHMAC(ctx, ring, row, []byte("data"), make([]byte, 32)); err == nil || ok {
				t.Errorf("CheckHMAC returned ok=%v err=%v for a %s row", ok, err, name)
			}
		})
	}
}

// TestMACKeysAreFamilySeparated feeds the SAME seed bytes to two families, so the
// only thing standing between them is the family binding inside the HKDF info
// string. A token tagged for one family must not verify for the other, or a
// tenant could replay another tenant's tokens.
func TestMACKeysAreFamilySeparated(t *testing.T) {
	ctx := context.Background()
	ring := macRing(t, "mac-shared-kek")
	store := newFakeMACStore()
	// A constant seed, freshly copied per call because the seed buffer is
	// zeroized in place by the callee.
	seedRand := func(n int) ([]byte, error) { return bytes.Repeat([]byte{0x9c}, n), nil }

	rowA, err := EnsureActiveMACKey(ctx, store, ring, "tenant-a", seedRand)
	if err != nil {
		t.Fatalf("EnsureActiveMACKey(tenant-a): %v", err)
	}
	rowB, err := EnsureActiveMACKey(ctx, store, ring, "tenant-b", seedRand)
	if err != nil {
		t.Fatalf("EnsureActiveMACKey(tenant-b): %v", err)
	}
	if rowA.Family == rowB.Family {
		t.Fatal("the two rows share a family; the test premise is broken")
	}

	keyA, err := macKeyFromRow(ctx, ring, rowA)
	if err != nil {
		t.Fatalf("macKeyFromRow(a): %v", err)
	}
	keyB, err := macKeyFromRow(ctx, ring, rowB)
	if err != nil {
		t.Fatalf("macKeyFromRow(b): %v", err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("two families derived the same MAC key from the same seed")
	}

	data := []byte("GET /api/v1/secret/tenant-a")
	tagA, err := TagHMAC(ctx, ring, rowA, data)
	if err != nil {
		t.Fatalf("TagHMAC(a): %v", err)
	}
	if ok, err := CheckHMAC(ctx, ring, rowA, data, tagA); err != nil || !ok {
		t.Fatalf("tenant-a's own tag did not verify: ok=%v err=%v", ok, err)
	}
	if ok, err := CheckHMAC(ctx, ring, rowB, data, tagA); err != nil || ok {
		t.Errorf("tenant-a's tag verified under tenant-b's key: ok=%v err=%v", ok, err)
	}
	// And the usual tamper checks through the row-based entry points.
	if ok, _ := CheckHMAC(ctx, ring, rowA, []byte("GET /api/v1/secret/tenant-b"), tagA); ok {
		t.Error("a tag verified over altered data")
	}
	badTag := append([]byte(nil), tagA...)
	badTag[len(badTag)-1] ^= 0x01
	if ok, _ := CheckHMAC(ctx, ring, rowA, data, badTag); ok {
		t.Error("an altered tag verified")
	}
	if ok, _ := CheckHMAC(ctx, ring, rowA, data, tagA[:16]); ok {
		t.Error("a truncated tag verified")
	}
}
