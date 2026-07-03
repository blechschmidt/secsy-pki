package secret

// KEK rotation and DEK re-wrap for the envelope-encryption layer (Task 63),
// mirroring what Task 24's dual-chain overlap did for CA signing keys.
//
// A KEK "family" is the lineage of versioned HSM keys behind one logical
// wrapping key: the family name is the base label from configuration (the
// deployment-wide secret.kek_label or a tenant's kek_label), version 1 is the
// key under that base label, and every later version N lives under the label
// "<family>-vN" — each version its own CKA_LABEL, per the invariant that a
// duplicate label makes PKCS#11 key lookup ambiguous.
//
// Rotation never re-encrypts data and never exposes a DEK outside the
// process: RotateKEK generates the next versioned key in the HSM and marks the
// superseded version "retiring", opening a dual-KEK decrypt window in which a
// Ring — the family's working set of KEK Services — seals new envelopes under
// the active version while still opening envelopes wrapped under retiring
// ones. Rewrap then walks the existing envelopes, unwraps each DEK on the HSM
// under its old KEK and immediately re-wraps it under the active one; the data
// ciphertext, nonce, and escrow block are untouched (the DEK is unchanged, so
// existing M-of-N escrow shares remain valid), and the DEK exists only
// transiently in locked process memory, zeroized before returning — exactly
// as it does on any ordinary decrypt. Once nothing remains wrapped under the
// old version, RetireKEK withdraws it: decryption under a retired version is
// refused fail-closed from then on.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ErrKEKRetired reports that an envelope references a KEK version that has
// been withdrawn from service. Decryption under a retired KEK is refused
// fail-closed; the version must be deliberately reinstated (status set back to
// retiring) before its envelopes can be opened or re-wrapped again.
var ErrKEKRetired = errors.New("secret: KEK version is retired")

// ErrUnknownKEK reports that an envelope references a KEK label outside the
// family's recorded lineage.
var ErrUnknownKEK = errors.New("secret: envelope references a KEK outside this family")

// VersionLabel returns the HSM label of a family's KEK version: the family
// name itself for version 1, "<family>-vN" for later versions. Every version
// gets a unique CKA_LABEL.
func VersionLabel(family string, version int) string {
	if version <= 1 {
		return family
	}
	return fmt.Sprintf("%s-v%d", family, version)
}

// KEKStore is the persistence the rotation layer needs: the versioned lineage
// per family and the retire-guard count. *database.DB satisfies it.
type KEKStore interface {
	ListKEKVersions(family string) ([]models.KEKVersion, error)
	RotateKEKVersion(v *models.KEKVersion) error
	SetKEKVersionStatus(family string, version int, status string) (bool, error)
	CountStoredSecretsOnKEK(label string) (int64, error)
}

// Vault is the stored-secret access a fleet re-wrap needs: the current
// registry envelopes plus the value-history entries (Task 73), which must
// migrate too so old versions stay decryptable (and retirable KEKs actually
// drain). *database.DB satisfies it.
type Vault interface {
	GetStoredSecret(id string) (*models.StoredSecret, error)
	ListStoredSecretIDsForRewrap(family, activeLabel string) ([]string, error)
	UpdateStoredSecretEnvelope(id, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error)
	ListStoredSecretVersionRefsForRewrap(family, activeLabel string) ([]models.SecretVersionRef, error)
	GetStoredSecretVersion(secretID string, version int) (*models.StoredSecretVersion, error)
	UpdateStoredSecretVersionEnvelope(secretID string, version int, envelope, kekLabel string, kekVersion int, expectKEKLabel string) (bool, error)
}

// Ring is a KEK family's working set during (and outside) a rotation window:
// it seals new envelopes under the family's active KEK version and opens
// envelopes wrapped under the active or any retiring version, refusing retired
// ones. It is safe for concurrent use.
type Ring struct {
	provider keyprovider.Provider
	family   string
	active   *Service
	entries  map[string]models.KEKVersion // by label, every recorded version
	ordered  []models.KEKVersion          // ascending by version

	mu       sync.Mutex
	services map[string]*Service // lazily built decrypt-only handles, by label
}

// LoadRing assembles a family's Ring from its recorded lineage (as returned by
// KEKStore.ListKEKVersions). An empty lineage means the family has never been
// rotated: its base key is implicitly version 1, active. Only the active
// version's Service is constructed eagerly (it self-tests the wrap algorithm
// against the token); handles for older versions are built lazily when an
// envelope referencing them is opened.
func LoadRing(ctx context.Context, provider keyprovider.Provider, family string, versions []models.KEKVersion) (*Ring, error) {
	if family == "" {
		return nil, fmt.Errorf("secret: KEK family is required")
	}
	if len(versions) == 0 {
		versions = []models.KEKVersion{{
			Family:  family,
			Version: 1,
			Label:   family,
			Status:  models.KEKStatusActive,
		}}
	}
	entries := make(map[string]models.KEKVersion, len(versions))
	var active *models.KEKVersion
	for i := range versions {
		v := versions[i]
		if v.Family != family {
			return nil, fmt.Errorf("secret: KEK version %q belongs to family %q, not %q", v.Label, v.Family, family)
		}
		if _, dup := entries[v.Label]; dup {
			return nil, fmt.Errorf("secret: duplicate KEK label %q in family %q", v.Label, family)
		}
		entries[v.Label] = v
		if v.Status == models.KEKStatusActive {
			if active != nil {
				return nil, fmt.Errorf("secret: family %q has more than one active KEK version (%d and %d)",
					family, active.Version, v.Version)
			}
			active = &versions[i]
		}
	}
	if active == nil {
		return nil, fmt.Errorf("secret: family %q has no active KEK version", family)
	}
	svc, err := NewVersionedService(ctx, provider, keyprovider.KeyRef{Label: active.Label}, active.Version)
	if err != nil {
		return nil, err
	}
	ordered := append([]models.KEKVersion(nil), versions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Version < ordered[j].Version })
	return &Ring{
		provider: provider,
		family:   family,
		active:   svc,
		entries:  entries,
		ordered:  ordered,
		services: map[string]*Service{active.Label: svc},
	}, nil
}

// Family returns the ring's KEK family name.
func (r *Ring) Family() string { return r.family }

// Active returns the Service bound to the family's active KEK version.
func (r *Ring) Active() *Service { return r.active }

// ActiveVersion returns the active KEK's rotation version.
func (r *Ring) ActiveVersion() int { return r.active.wrapper.version }

// ActiveLabel returns the active KEK's HSM label.
func (r *Ring) ActiveLabel() string { return r.active.wrapper.label }

// Versions returns the family lineage the ring was loaded with, ascending by
// version (a single implicit version 1 for a never-rotated family).
func (r *Ring) Versions() []models.KEKVersion {
	return append([]models.KEKVersion(nil), r.ordered...)
}

// Encrypt, EncryptWithEscrow and their *ToJSON variants seal under the active
// KEK version, exactly like the corresponding Service methods.
func (r *Ring) Encrypt(plaintext, context []byte) (*Envelope, error) {
	return r.active.Encrypt(plaintext, context)
}

func (r *Ring) EncryptToJSON(plaintext, context []byte) ([]byte, error) {
	return r.active.EncryptToJSON(plaintext, context)
}

func (r *Ring) EncryptWithEscrow(plaintext, context []byte, escrow *EscrowPolicy) (*Envelope, error) {
	return r.active.EncryptWithEscrow(plaintext, context, escrow)
}

func (r *Ring) EncryptWithEscrowToJSON(plaintext, context []byte, escrow *EscrowPolicy) ([]byte, error) {
	return r.active.EncryptWithEscrowToJSON(plaintext, context, escrow)
}

// serviceFor resolves the Service able to unwrap an envelope sealed under
// kekLabel, enforcing the retirement policy: unknown labels and retired
// versions are refused. Decrypt-only handles are built on first use and
// cached for the ring's lifetime.
func (r *Ring) serviceFor(ctx context.Context, kekLabel string) (*Service, error) {
	entry, ok := r.entries[kekLabel]
	if !ok {
		return nil, fmt.Errorf("%w: KEK %q is not in family %q", ErrUnknownKEK, kekLabel, r.family)
	}
	if entry.Status == models.KEKStatusRetired {
		return nil, fmt.Errorf("%w: KEK %q (version %d of family %q) was retired; the secret must be recovered from escrow or the version deliberately reinstated",
			ErrKEKRetired, kekLabel, entry.Version, r.family)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if svc, ok := r.services[kekLabel]; ok {
		return svc, nil
	}
	svc, err := newDecryptOnlyService(ctx, r.provider, keyprovider.KeyRef{Label: kekLabel}, entry.Version)
	if err != nil {
		return nil, err
	}
	r.services[kekLabel] = svc
	return svc, nil
}

// Decrypt opens an envelope sealed under any non-retired version of the
// family — the dual-KEK decrypt window that keeps reads working while secrets
// are re-wrapped after a rotation.
func (r *Ring) Decrypt(ctx context.Context, env *Envelope, context []byte) ([]byte, error) {
	if err := env.validate(); err != nil {
		return nil, err
	}
	svc, err := r.serviceFor(ctx, env.KEKLabel)
	if err != nil {
		return nil, err
	}
	return svc.Decrypt(env, context)
}

// DecryptJSON parses a serialized envelope and decrypts it via Decrypt.
func (r *Ring) DecryptJSON(ctx context.Context, data, context []byte) ([]byte, error) {
	env, err := Unmarshal(data)
	if err != nil {
		return nil, err
	}
	return r.Decrypt(ctx, env, context)
}

// Rewrap migrates an envelope onto the family's active KEK version in place:
// the DEK is unwrapped on the HSM under the envelope's current (old) KEK,
// checked against the envelope's key-commitment, immediately re-wrapped under
// the active KEK, and zeroized. Only the wrap header changes — the nonce, data
// ciphertext, context binding, and escrow block are byte-for-byte untouched
// (the DEK is unchanged, so existing escrow shares stay valid). No plaintext
// is ever decrypted, and no encryption context is needed.
//
// A version-1 envelope is upgraded to version 2 in the process: its original
// KEK label and wrap algorithm move into the immutable Origin block (they are
// bound into the v1 AAD and must keep reconstructing it), and a DEK commitment
// is recorded for subsequent unwrap verification.
//
// It returns false with no error when the envelope is already wrapped under
// the active KEK. Re-wrapping FROM a retired version is refused just like
// decryption is.
func (r *Ring) Rewrap(ctx context.Context, env *Envelope) (bool, error) {
	if err := env.validate(); err != nil {
		return false, err
	}
	if env.KEKLabel == r.ActiveLabel() {
		return false, nil
	}
	src, err := r.serviceFor(ctx, env.KEKLabel)
	if err != nil {
		return false, err
	}

	dek, err := src.wrapper.Unwrap(env.WrappedDEK, env.WrapAlg)
	if err != nil {
		// Deliberately generic, like open(): unwrap failures must not leak
		// padding details.
		return false, fmt.Errorf("secret: unwrapping data key failed")
	}
	defer zero(dek)
	if len(dek) != dekSize {
		return false, fmt.Errorf("secret: unwrapped data key has wrong length")
	}
	if len(env.DEKCommit) > 0 && !subtleEqual(dekCommitment(dek), env.DEKCommit) {
		return false, fmt.Errorf("secret: unwrapped data key failed its commitment check")
	}

	wrapped, wrapAlg, err := r.active.wrapper.Wrap(dek)
	if err != nil {
		return false, fmt.Errorf("secret: re-wrapping data key: %w", err)
	}
	if !supportedWrapAlgs[wrapAlg] {
		return false, fmt.Errorf("secret: wrapper produced unsupported algorithm %q", wrapAlg)
	}

	if env.Version == FormatVersion1 {
		// Freeze the original AAD inputs before the header is rewritten; the
		// unchanged GCM tag keeps verifying against them. These fields never
		// change again, even across further re-wraps.
		env.Origin = &OriginBinding{KEKLabel: env.KEKLabel, WrapAlg: env.WrapAlg}
		env.Version = FormatVersion2
		env.DEKCommit = dekCommitment(dek)
	}
	env.Provider = r.active.wrapper.ProviderName()
	env.KEKLabel = r.active.wrapper.label
	env.KEKURI = r.active.wrapper.uri
	env.KEKVersion = r.active.wrapper.version
	env.WrapAlg = wrapAlg
	env.WrappedDEK = wrapped
	return true, nil
}

// RewrapJSON is Rewrap over a serialized envelope, returning the (possibly
// rewritten) serialization.
func (r *Ring) RewrapJSON(ctx context.Context, data []byte) ([]byte, bool, error) {
	env, err := Unmarshal(data)
	if err != nil {
		return nil, false, err
	}
	changed, err := r.Rewrap(ctx, env)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return data, false, nil
	}
	out, err := env.Marshal()
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// RotationResult describes a completed KEK rotation.
type RotationResult struct {
	Family     string `json:"family"`
	OldVersion int    `json:"old_version"`
	OldLabel   string `json:"old_label"`
	NewVersion int    `json:"new_version"`
	NewLabel   string `json:"new_label"`
	// Adopted is true when the new version's key already existed in the HSM
	// (an earlier rotation generated it but crashed before recording it) and
	// was registered rather than regenerated — the crash-retry path that keeps
	// the unique-label invariant intact.
	Adopted bool `json:"adopted,omitempty"`
}

// RotateKEK generates the family's next versioned wrapping key in the HSM and
// records it as the new active version, moving the superseded version to
// retiring (the dual-KEK decrypt window). keyType must be an RSA type (empty
// defaults to rsa-4096). The new key is self-tested (a wrap/unwrap probe)
// before the lineage is advanced, so a key the token cannot actually unwrap
// with never becomes active. Existing envelopes are untouched — they keep
// decrypting under the retiring version until re-wrapped.
func RotateKEK(ctx context.Context, provider keyprovider.Provider, store KEKStore, family, keyType string) (*RotationResult, error) {
	if family == "" {
		return nil, fmt.Errorf("secret: KEK family is required")
	}
	if keyType == "" {
		keyType = keyprovider.KeyTypeRSA4096
	}
	versions, err := store.ListKEKVersions(family)
	if err != nil {
		return nil, fmt.Errorf("secret: reading KEK lineage: %w", err)
	}

	oldVersion, oldLabel, next := 1, family, 2
	if len(versions) == 0 {
		// Never rotated: the base key must exist — rotation supersedes a key, it
		// does not bootstrap one.
		if _, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: family}); err != nil {
			return nil, fmt.Errorf("secret: family %q has no existing KEK to rotate (create it with init-kek first): %w", family, err)
		}
	} else {
		foundActive := false
		for _, v := range versions {
			if v.Version >= next {
				next = v.Version + 1
			}
			if v.Status == models.KEKStatusActive {
				oldVersion, oldLabel = v.Version, v.Label
				foundActive = true
			}
		}
		if !foundActive {
			return nil, fmt.Errorf("secret: family %q has no active KEK version to rotate", family)
		}
	}

	newLabel := VersionLabel(family, next)
	adopted := false
	if _, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: newLabel}); err == nil {
		// The key exists but the lineage does not know it: a previous rotation
		// generated it and crashed before the store recorded it. Adopt it instead
		// of generating a second key under the same label.
		adopted = true
	} else {
		if _, err := provider.GenerateKey(ctx, keyprovider.KeySpec{
			Label:   newLabel,
			KeyType: keyType,
			Usage:   keyprovider.KeyUsageDecrypt,
		}); err != nil {
			return nil, fmt.Errorf("secret: generating KEK version %d: %w", next, err)
		}
	}

	// Self-test before the lineage advances: locate the key, check its shape,
	// and negotiate a wrap algorithm (which round-trips a probe value through
	// the token).
	if _, err := NewVersionedService(ctx, provider, keyprovider.KeyRef{Label: newLabel}, next); err != nil {
		return nil, fmt.Errorf("secret: new KEK version failed its self-test (lineage not advanced): %w", err)
	}

	if err := store.RotateKEKVersion(&models.KEKVersion{
		Family:  family,
		Version: next,
		Label:   newLabel,
		Status:  models.KEKStatusActive,
	}); err != nil {
		return nil, fmt.Errorf("secret: recording KEK rotation: %w", err)
	}
	return &RotationResult{
		Family:     family,
		OldVersion: oldVersion,
		OldLabel:   oldLabel,
		NewVersion: next,
		NewLabel:   newLabel,
		Adopted:    adopted,
	}, nil
}

// RetireKEK withdraws a superseded KEK version from service: envelopes wrapped
// under it can no longer be decrypted or re-wrapped. The active version cannot
// be retired. Unless force is set, retirement is refused while any stored
// secret is still wrapped under the version — the fail-closed guard against
// stranding ciphertext.
func RetireKEK(store KEKStore, family string, version int, force bool) (*models.KEKVersion, error) {
	versions, err := store.ListKEKVersions(family)
	if err != nil {
		return nil, fmt.Errorf("secret: reading KEK lineage: %w", err)
	}
	var target *models.KEKVersion
	for i := range versions {
		if versions[i].Version == version {
			target = &versions[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("secret: family %q has no recorded KEK version %d (a never-rotated family has no versions to retire)", family, version)
	}
	if target.Status == models.KEKStatusActive {
		return nil, fmt.Errorf("secret: refusing to retire the ACTIVE KEK version %d of family %q; rotate first", version, family)
	}
	if target.Status == models.KEKStatusRetired {
		return nil, fmt.Errorf("secret: KEK version %d of family %q is already retired", version, family)
	}
	if !force {
		n, err := store.CountStoredSecretsOnKEK(target.Label)
		if err != nil {
			return nil, fmt.Errorf("secret: counting secrets on KEK %q: %w", target.Label, err)
		}
		if n > 0 {
			return nil, fmt.Errorf("secret: %d stored secret(s) are still wrapped under KEK version %d of family %q and would become undecryptable; re-wrap them first (or pass force to retire anyway)",
				n, version, family)
		}
	}
	ok, err := store.SetKEKVersionStatus(family, version, models.KEKStatusRetired)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("secret: KEK version %d of family %q disappeared during retirement", version, family)
	}
	target.Status = models.KEKStatusRetired
	return target, nil
}

// RewrapReport summarizes a stored-secret re-wrap batch. Counts are in
// ENVELOPES: each current registry envelope and each historical value-history
// entry is one work item, matching how the KEK status report counts what must
// drain before a version can retire.
type RewrapReport struct {
	Family        string `json:"family"`
	ActiveVersion int    `json:"active_version"`
	ActiveLabel   string `json:"active_label"`
	// Total is the number of envelopes in the work list.
	Total int `json:"total"`
	// HistoryEnvelopes is how many of Total were historical version entries
	// (the remainder are current registry envelopes).
	HistoryEnvelopes int `json:"history_envelopes,omitempty"`
	// Rewrapped were migrated onto the active KEK and persisted.
	Rewrapped int `json:"rewrapped"`
	// Skipped were already on the active KEK (nothing to do).
	Skipped int `json:"skipped"`
	// Conflicts lost an optimistic update to a concurrent writer; re-running
	// the batch picks them up if they still need migration.
	Conflicts int `json:"conflicts"`
	// Failed could not be re-wrapped (per-secret reasons in Errors).
	Failed int `json:"failed"`
	// Errors carries up to maxRewrapErrors "id: reason" strings.
	Errors []string `json:"errors,omitempty"`
}

// maxRewrapErrors bounds the error detail carried in a RewrapReport (and thus
// in API responses and audit events); the counts remain exact.
const maxRewrapErrors = 20

// RewrapStoredSecrets re-wraps stored secrets onto the ring's active KEK
// version. With ids nil, it processes every envelope of the family not
// already on the active KEK — current registry envelopes AND historical
// value-history entries (a fleet migration); with explicit ids it processes
// exactly those secrets (again including their history), refusing secrets
// that belong to a different family. Individual failures don't abort the
// batch — the report carries the counts — and each persisted update is
// optimistic, so a batch racing another writer records a conflict rather than
// clobbering newer ciphertext.
func RewrapStoredSecrets(ctx context.Context, ring *Ring, vault Vault, ids []string) (*RewrapReport, error) {
	report := &RewrapReport{
		Family:        ring.Family(),
		ActiveVersion: ring.ActiveVersion(),
		ActiveLabel:   ring.ActiveLabel(),
	}
	explicit := ids != nil
	if !explicit {
		var err error
		ids, err = vault.ListStoredSecretIDsForRewrap(ring.Family(), ring.ActiveLabel())
		if err != nil {
			return nil, fmt.Errorf("secret: listing secrets for re-wrap: %w", err)
		}
	}
	// Historical version entries on old KEKs. In explicit mode the family-wide
	// list is filtered down to the selected secrets.
	refs, err := vault.ListStoredSecretVersionRefsForRewrap(ring.Family(), ring.ActiveLabel())
	if err != nil {
		return nil, fmt.Errorf("secret: listing history entries for re-wrap: %w", err)
	}
	if explicit {
		selected := make(map[string]bool, len(ids))
		for _, id := range ids {
			selected[id] = true
		}
		kept := refs[:0]
		for _, ref := range refs {
			if selected[ref.SecretID] {
				kept = append(kept, ref)
			}
		}
		refs = kept
	}

	report.Total = len(ids) + len(refs)
	report.HistoryEnvelopes = len(refs)
	remaining := report.Total
	metrics.SecretRewrapPending.Set(float64(remaining), ring.Family())
	defer metrics.SecretRewrapPending.Set(0, ring.Family())
	done := func() {
		remaining--
		metrics.SecretRewrapPending.Set(float64(remaining), ring.Family())
	}

	fail := func(what, reason string) {
		report.Failed++
		metrics.SecretRewrap.Inc("error")
		if len(report.Errors) < maxRewrapErrors {
			report.Errors = append(report.Errors, what+": "+reason)
		}
	}
	for i, id := range ids {
		if err := ctx.Err(); err != nil {
			return report, fmt.Errorf("secret: re-wrap batch interrupted after %d of %d envelopes: %w", i, report.Total, err)
		}
		s, err := vault.GetStoredSecret(id)
		if err != nil {
			fail(id, err.Error())
			done()
			continue
		}
		if s == nil {
			fail(id, "no such stored secret")
			done()
			continue
		}
		if s.KEKFamily != ring.Family() {
			fail(id, fmt.Sprintf("belongs to KEK family %q, not %q", s.KEKFamily, ring.Family()))
			done()
			continue
		}
		oldLabel := s.KEKLabel
		blob, changed, err := ring.RewrapJSON(ctx, []byte(s.Envelope))
		if err != nil {
			fail(id, err.Error())
			done()
			continue
		}
		if !changed {
			report.Skipped++
			done()
			continue
		}
		ok, err := vault.UpdateStoredSecretEnvelope(id, string(blob), ring.ActiveLabel(), ring.ActiveVersion(), oldLabel)
		if err != nil {
			fail(id, err.Error())
			done()
			continue
		}
		if !ok {
			report.Conflicts++
			metrics.SecretRewrap.Inc("conflict")
		} else {
			report.Rewrapped++
			metrics.SecretRewrap.Inc("ok")
		}
		done()
	}

	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			return report, fmt.Errorf("secret: re-wrap batch interrupted after %d of %d envelopes: %w", len(ids)+i, report.Total, err)
		}
		what := fmt.Sprintf("%s@v%d", ref.SecretID, ref.Version)
		v, err := vault.GetStoredSecretVersion(ref.SecretID, ref.Version)
		if err != nil {
			fail(what, err.Error())
			done()
			continue
		}
		if v == nil {
			fail(what, "no such stored-secret version")
			done()
			continue
		}
		if v.KEKFamily != ring.Family() {
			fail(what, fmt.Sprintf("belongs to KEK family %q, not %q", v.KEKFamily, ring.Family()))
			done()
			continue
		}
		oldLabel := v.KEKLabel
		blob, changed, err := ring.RewrapJSON(ctx, []byte(v.Envelope))
		if err != nil {
			fail(what, err.Error())
			done()
			continue
		}
		if !changed {
			report.Skipped++
			done()
			continue
		}
		ok, err := vault.UpdateStoredSecretVersionEnvelope(ref.SecretID, ref.Version, string(blob), ring.ActiveLabel(), ring.ActiveVersion(), oldLabel)
		if err != nil {
			fail(what, err.Error())
			done()
			continue
		}
		if !ok {
			report.Conflicts++
			metrics.SecretRewrap.Inc("conflict")
		} else {
			report.Rewrapped++
			metrics.SecretRewrap.Inc("ok")
		}
		done()
	}
	return report, nil
}
