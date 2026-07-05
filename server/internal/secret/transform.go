package secret

// Format-preserving encryption (FF1) and searchable tokenization for the secret
// layer (Task 144).
//
// This complements envelope encryption: instead of turning a value into an
// opaque blob, a "transform" enciphers structured data (a card PAN, an SSN, an
// account number) into another value of the SAME length over the SAME alphabet,
// so legacy systems that validate format keep working. The FF1 key is never held
// in the clear at rest: a random seed is sealed as an ordinary envelope under the
// family's HSM-held KEK (exactly like the MAC seed in mac.go) and a per-template
// FF1 key is HKDF-derived from it per use. Deriving — rather than using the seed
// directly — domain-separates each template's key from every other and from any
// other use of the same seed.
//
// A deterministic (convergent) template uses a fixed empty tweak, so equal
// plaintext always yields equal ciphertext: that stable mapping is what lets a
// protected column still be searched for equality and de-duplicated. A
// non-deterministic template takes a per-request tweak (e.g. a record id), so the
// same value tokenizes differently in different contexts; the caller must present
// the same tweak to decode.
//
// The seed does not rotate — a format-preserving token carries no version to
// select an old key, so changing the seed would strand every issued token — but
// its KEK wrapping is re-sealed when the classical KEK rotates (ResealFPESeed),
// keeping the derived keys stable while the HSM protection follows the rotation.

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/fpe"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const (
	// FPESeedBytes is the size of the random seed sealed under the KEK. 256 bits
	// matches the AES-256 FF1 key derived from it.
	FPESeedBytes = 32
	// fpeKeyBytes is the size of the HKDF-derived FF1 key (AES-256).
	fpeKeyBytes = 32
	// fpeKDFInfoTag domain-separates FF1-key derivation from every other use of
	// HKDF in this package (see macKDFInfoTag, pqcKDFInfoTag).
	fpeKDFInfoTag = "secsy-pki/secret/fpe-key-v1\x00"

	// TweakSourceNone marks a deterministic (convergent) template: the FF1 tweak
	// is always empty, so equal plaintext yields equal ciphertext for equality
	// search and de-duplication.
	TweakSourceNone = "none"
	// TweakSourceRequest marks a context template: the FF1 tweak is supplied per
	// request, so the same value tokenizes differently under different tweaks. The
	// caller must present the same tweak to decode.
	TweakSourceRequest = "request"
)

// DeriveFPEKey derives the per-template FF1 key from an unwrapped seed via
// HKDF-SHA256, domain-separated by the KEK family and the template name so a key
// derived for one (family, template) is independent of every other. The seed must
// be FPESeedBytes long. The caller zeroizes both the seed and the returned key.
func DeriveFPEKey(seed []byte, family, template string) ([]byte, error) {
	if len(seed) != FPESeedBytes {
		return nil, fmt.Errorf("secret: FPE seed must be %d bytes, got %d", FPESeedBytes, len(seed))
	}
	if template == "" {
		return nil, fmt.Errorf("secret: FPE template name is required for key derivation")
	}
	info := fpeKDFInfoTag + family + "\x00" + template
	key, err := hkdf.Key(sha256.New, seed, nil, info, fpeKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("secret: deriving FPE key: %w", err)
	}
	return key, nil
}

// TransformSpec is the configuration-facing description of a transform template,
// resolved and validated into a TransformTemplate by ResolveTransformTemplate.
// It mirrors the config.TransformConfig fields but keeps the secret package free
// of a dependency on the config package.
type TransformSpec struct {
	Name          string
	Alphabet      string
	MinLength     int
	MaxLength     int
	Deterministic bool
	TweakSource   string
	PreserveOther bool
	// Roles optionally restricts which operator roles may use the template
	// (per-template RBAC). Empty means any holder of the secret:transform
	// capability in the tenant may use it. Role names are validated by the caller.
	Roles []string
}

// TransformTemplate is a resolved, validated transform: an alphabet (and thus an
// FF1 radix), the accepted length window, and the tweak/determinism policy. It is
// immutable and safe to share.
type TransformTemplate struct {
	Name          string
	Alphabet      *fpe.Alphabet
	MinLength     int // effective minimum, at least the FF1 domain minimum for the radix
	MaxLength     int // 0 = unbounded (up to the FF1 maximum)
	Deterministic bool
	TweakSource   string
	PreserveOther bool
	// Roles is the optional per-template role allowlist (empty = any holder of
	// secret:transform in the tenant). The handler layer enforces it.
	Roles []string
}

// Radix returns the template's FF1 radix (its alphabet size).
func (t *TransformTemplate) Radix() int { return t.Alphabet.Radix() }

// ResolveTransformTemplate validates a spec and resolves it to a TransformTemplate,
// failing closed on any inconsistency (unknown alphabet, a minimum below the FF1
// domain requirement, a min/max window that excludes all inputs, or a
// tweak-source that contradicts the determinism flag).
func ResolveTransformTemplate(spec TransformSpec) (*TransformTemplate, error) {
	if spec.Name == "" {
		return nil, fmt.Errorf("secret: transform template name is required")
	}
	alphabet, err := fpe.ResolveAlphabet(spec.Alphabet)
	if err != nil {
		return nil, fmt.Errorf("secret: transform %q: %w", spec.Name, err)
	}
	radix := alphabet.Radix()
	domainMin := fpe.MinLen(radix)

	minLen := spec.MinLength
	if minLen == 0 {
		minLen = domainMin
	}
	if minLen < domainMin {
		return nil, fmt.Errorf("secret: transform %q min_length %d is below the FF1 domain minimum %d for radix %d (radix^len must be >= 1000000)", spec.Name, minLen, domainMin, radix)
	}
	if spec.MaxLength != 0 && spec.MaxLength < minLen {
		return nil, fmt.Errorf("secret: transform %q max_length %d is below its effective min_length %d", spec.Name, spec.MaxLength, minLen)
	}

	tweakSource := spec.TweakSource
	if tweakSource == "" {
		if spec.Deterministic {
			tweakSource = TweakSourceNone
		} else {
			tweakSource = TweakSourceRequest
		}
	}
	switch tweakSource {
	case TweakSourceNone:
		if !spec.Deterministic {
			return nil, fmt.Errorf("secret: transform %q sets tweak_source=none but deterministic=false; an empty tweak is inherently convergent — set deterministic=true", spec.Name)
		}
	case TweakSourceRequest:
		if spec.Deterministic {
			return nil, fmt.Errorf("secret: transform %q sets tweak_source=request but deterministic=true; a per-request tweak is not convergent — set deterministic=false or tweak_source=none", spec.Name)
		}
	default:
		return nil, fmt.Errorf("secret: transform %q has unknown tweak_source %q (want %q or %q)", spec.Name, tweakSource, TweakSourceNone, TweakSourceRequest)
	}

	return &TransformTemplate{
		Name:          spec.Name,
		Alphabet:      alphabet,
		MinLength:     minLen,
		MaxLength:     spec.MaxLength,
		Deterministic: spec.Deterministic,
		TweakSource:   tweakSource,
		PreserveOther: spec.PreserveOther,
		Roles:         append([]string(nil), spec.Roles...),
	}, nil
}

// FPESeedStore is the minimal persistence the FPE-seed lifecycle needs.
// *database.DB satisfies it structurally; keeping it an interface lets both the
// REST/gRPC handlers and the secsy-secret CLI share one implementation without
// the secret package depending on the database package.
type FPESeedStore interface {
	GetFPESeed(family string) (*models.FPESeed, error)
	InsertFPESeed(s *models.FPESeed) error
	UpdateFPESeedEnvelope(family, envelope string, sealedUnderVersion int) (bool, error)
}

// EnsureFPESeed returns the family's FPE seed, lazily provisioning one on first
// use: it mints a random seed via seedRand (the HSM RNG when available), seals it
// as an ordinary envelope under the ring's active KEK, and persists it. The
// family primary key resolves a concurrent first-use race — the loser re-reads
// the winner's row.
func EnsureFPESeed(ctx context.Context, store FPESeedStore, ring *Ring, family string, seedRand func(n int) ([]byte, error)) (*models.FPESeed, error) {
	existing, err := store.GetFPESeed(family)
	if err != nil {
		return nil, fmt.Errorf("secret: reading FPE seed state: %w", err)
	}
	if existing != nil {
		return existing, nil
	}
	seed, err := seedRand(FPESeedBytes)
	if err != nil {
		return nil, fmt.Errorf("secret: generating FPE seed: %w", err)
	}
	defer zero(seed)
	env, err := ring.EncryptToJSON(seed, nil)
	if err != nil {
		return nil, fmt.Errorf("secret: sealing FPE seed: %w", err)
	}
	row := &models.FPESeed{Family: family, Envelope: string(env), SealedUnderVersion: ring.ActiveVersion()}
	if err := store.InsertFPESeed(row); err != nil {
		// A concurrent request may have provisioned the seed first; the family
		// primary-key conflict is expected — re-read and use the winner.
		if a, rerr := store.GetFPESeed(family); rerr == nil && a != nil {
			return a, nil
		}
		return nil, fmt.Errorf("secret: provisioning FPE seed: %w", err)
	}
	return row, nil
}

// ResealFPESeed re-seals a family's FPE seed under the ring's active KEK version
// if it is currently sealed under an older one, keeping the seed bytes (and thus
// every derived FF1 key and every issued token) unchanged. It is idempotent and
// returns whether a re-seal occurred plus the version now sealing the seed. A
// family with no FPE seed is a no-op.
func ResealFPESeed(ctx context.Context, ring *Ring, store FPESeedStore, family string) (resealed bool, sealedUnderVersion int, err error) {
	row, err := store.GetFPESeed(family)
	if err != nil {
		return false, 0, fmt.Errorf("secret: reading FPE seed state: %w", err)
	}
	if row == nil {
		return false, 0, nil
	}
	active := ring.ActiveVersion()
	if row.SealedUnderVersion == active {
		return false, active, nil
	}
	seed, err := ring.DecryptJSON(ctx, []byte(row.Envelope), nil)
	if err != nil {
		return false, 0, fmt.Errorf("secret: unwrapping FPE seed for re-seal: %w", err)
	}
	defer zero(seed)
	env, err := ring.EncryptToJSON(seed, nil)
	if err != nil {
		return false, 0, fmt.Errorf("secret: re-sealing FPE seed: %w", err)
	}
	ok, err := store.UpdateFPESeedEnvelope(family, string(env), active)
	if err != nil {
		return false, 0, fmt.Errorf("secret: persisting re-sealed FPE seed: %w", err)
	}
	return ok, active, nil
}

// Transformer applies one template's FF1 cipher, with its per-template key
// already derived and loaded. It is created per operation (the derived key lives
// only for the Transformer's lifetime) and is not retained.
type Transformer struct {
	tmpl *TransformTemplate
	ff1  *fpe.FF1
}

// NewTransformer unwraps the family's FPE seed on the HSM (via the ring's KEK),
// derives the template's FF1 key, and returns a ready Transformer. The derived
// key is zeroized before returning — the AES key schedule inside the FF1 cipher
// is the only copy that outlives the call.
func NewTransformer(ctx context.Context, ring *Ring, seedRow *models.FPESeed, tmpl *TransformTemplate) (*Transformer, error) {
	seed, err := ring.DecryptJSON(ctx, []byte(seedRow.Envelope), nil)
	if err != nil {
		return nil, fmt.Errorf("secret: unwrapping FPE seed: %w", err)
	}
	defer zero(seed)
	key, err := DeriveFPEKey(seed, seedRow.Family, tmpl.Name)
	if err != nil {
		return nil, err
	}
	defer zero(key)
	ff1, err := fpe.NewFF1(key, tmpl.Alphabet.Radix())
	if err != nil {
		return nil, err
	}
	return &Transformer{tmpl: tmpl, ff1: ff1}, nil
}

// Encode format-preserving-enciphers plaintext under the template. reqTweak is
// the per-request tweak for a TweakSourceRequest template (required, and
// re-supplied verbatim to Decode); it must be nil/empty for a deterministic
// (TweakSourceNone) template.
func (t *Transformer) Encode(plaintext string, reqTweak []byte) (string, error) {
	tweak, err := t.effectiveTweak(reqTweak)
	if err != nil {
		return "", err
	}
	return t.apply(plaintext, tweak, true)
}

// Decode inverts Encode for the same template and tweak.
func (t *Transformer) Decode(ciphertext string, reqTweak []byte) (string, error) {
	tweak, err := t.effectiveTweak(reqTweak)
	if err != nil {
		return "", err
	}
	return t.apply(ciphertext, tweak, false)
}

// effectiveTweak resolves the FF1 tweak from the template policy and the caller's
// request tweak, failing closed when the two disagree.
func (t *Transformer) effectiveTweak(reqTweak []byte) ([]byte, error) {
	switch t.tmpl.TweakSource {
	case TweakSourceNone:
		if len(reqTweak) != 0 {
			return nil, fmt.Errorf("secret: transform %q is deterministic and takes no tweak", t.tmpl.Name)
		}
		return nil, nil
	case TweakSourceRequest:
		if len(reqTweak) == 0 {
			return nil, fmt.Errorf("secret: transform %q requires a per-request tweak", t.tmpl.Name)
		}
		return reqTweak, nil
	default:
		return nil, fmt.Errorf("secret: transform %q has invalid tweak source %q", t.tmpl.Name, t.tmpl.TweakSource)
	}
}

// apply extracts the alphabet symbols from s, runs FF1 over them, and reassembles
// the result. With PreserveOther, characters outside the alphabet (separators,
// spaces) are copied verbatim to the same positions and only the alphabet symbols
// are enciphered — so the format (dashes in a card number, say) is preserved and
// the operation stays perfectly invertible. Without it, any non-alphabet
// character is rejected.
func (t *Transformer) apply(s string, tweak []byte, encrypt bool) (string, error) {
	runes := []rune(s)
	nums := make([]uint16, 0, len(runes))
	positions := make([]int, 0, len(runes))
	for i, r := range runes {
		if v, ok := t.tmpl.Alphabet.IndexOf(r); ok {
			nums = append(nums, v)
			positions = append(positions, i)
			continue
		}
		if !t.tmpl.PreserveOther {
			return "", fmt.Errorf("secret: character %q is not in transform %q alphabet %q (set preserve_other to pass separators through)", string(r), t.tmpl.Name, t.tmpl.Alphabet.Name())
		}
	}
	if err := t.checkLen(len(nums)); err != nil {
		return "", err
	}

	var out []uint16
	var err error
	if encrypt {
		out, err = t.ff1.Encrypt(tweak, nums)
	} else {
		out, err = t.ff1.Decrypt(tweak, nums)
	}
	if err != nil {
		return "", fmt.Errorf("secret: transform %q: %w", t.tmpl.Name, err)
	}

	res := make([]rune, len(runes))
	copy(res, runes)
	for j, pos := range positions {
		res[pos] = t.tmpl.Alphabet.SymbolAt(out[j])
	}
	return string(res), nil
}

// checkLen enforces the template's accepted length window (in alphabet symbols).
func (t *Transformer) checkLen(n int) error {
	if n < t.tmpl.MinLength {
		return fmt.Errorf("secret: transform %q needs at least %d alphabet symbols, got %d", t.tmpl.Name, t.tmpl.MinLength, n)
	}
	if t.tmpl.MaxLength != 0 && n > t.tmpl.MaxLength {
		return fmt.Errorf("secret: transform %q accepts at most %d alphabet symbols, got %d", t.tmpl.Name, t.tmpl.MaxLength, n)
	}
	return nil
}
