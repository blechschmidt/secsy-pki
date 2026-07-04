package doctor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// --- 1. configuration --------------------------------------------------------

// checkConfig parses and validates the config file (config.parse) and lints it
// for unknown keys (config.unknown_keys). It returns the loaded config, or nil
// when it could not be loaded.
func checkConfig(r *Report, path string) *config.Config {
	var cfg *config.Config
	r.run("config.parse", func() (Status, string) {
		c, err := config.Load(path)
		if err != nil {
			return StatusFail, fmt.Sprintf("%s: %v", path, err)
		}
		cfg = c
		return StatusPass, fmt.Sprintf("%s parsed and validated", path)
	})

	r.run("config.unknown_keys", func() (Status, string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return StatusSkip, fmt.Sprintf("config not readable: %v", err)
		}
		unknown, err := config.UnknownKeys(data)
		if err != nil {
			// Malformed YAML is already reported by config.parse.
			return StatusSkip, fmt.Sprintf("strict decode impossible: %v", err)
		}
		if len(unknown) > 0 {
			return StatusWarn, fmt.Sprintf("%d unrecognized key%s (typo?): %s",
				len(unknown), plural(len(unknown)), strings.Join(unknown, "; "))
		}
		return StatusPass, "every key maps to a known config field"
	})
	return cfg
}

// --- 2. key providers ---------------------------------------------------------

// haTokenSet is the health surface of the multi-token PKCS#11 HA provider.
// *keyprovider.PKCS11HAProvider satisfies it; asserting on the interface keeps
// the check tolerant of wrappers that forward these methods. ProbeToken (an
// active per-token probe) is used rather than the threshold-based rotation
// state, which starts optimistic and would hide a dead backup token from a
// single diagnostic pass.
type haTokenSet interface {
	NumTokens() int
	TokenName(i int) string
	ProbeToken(ctx context.Context, i int) error
}

// checkProviders constructs the key-provider backend for every signing role in
// use and probes each for reachability: PKCS#11 module/slot/PIN login for HSM
// backends (via keyprovider.Prober, the same probe /readyz uses), credential /
// endpoint checks for cloud KMS, keystore access for the software backend.
// When the PKCS#11 backend is a multi-token HA set it additionally reports
// per-token health (hsm.ha_tokens): the HA provider's own Ping actively probes
// every member and updates its rotation state.
func checkProviders(ctx context.Context, r *Report, cfg *config.Config, opts Options) *roleProviders {
	providers := &roleProviders{byRole: map[string]keyprovider.Provider{}}
	byType := map[string]keyprovider.Provider{}

	for _, role := range rolesInUse(cfg) {
		role := role
		ptype := cfg.KeyProviderTypeForRole(role)
		r.run("keyprovider."+role, func() (Status, string) {
			backend := describeBackend(cfg, ptype)
			if existing, ok := byType[ptype]; ok {
				providers.byRole[role] = existing
				return StatusPass, fmt.Sprintf("shares the already-verified %s backend", backend)
			}
			if opts.BuildProvider == nil {
				return StatusSkip, "no provider factory supplied"
			}
			p, err := opts.BuildProvider(cfg, role)
			if err != nil {
				return StatusFail, fmt.Sprintf("%s: constructing provider: %v", backend, err)
			}
			byType[ptype] = p
			providers.owned = append(providers.owned, p)
			providers.byRole[role] = p

			prober, ok := p.(keyprovider.Prober)
			if !ok {
				return StatusWarn, fmt.Sprintf("%s constructed, but the backend supports no connectivity probe", backend)
			}
			if err := prober.Ping(ctx); err != nil {
				return StatusFail, fmt.Sprintf("%s unreachable: %v", backend, err)
			}
			return StatusPass, fmt.Sprintf("%s reachable (login/credentials OK)", backend)
		})
	}

	// Per-token HA health, when any constructed backend is a multi-token set.
	// Every member is actively probed here — a dead backup token must surface
	// even while the primary carries all traffic.
	for _, p := range providers.owned {
		ha, ok := p.(haTokenSet)
		if !ok {
			continue
		}
		r.run("hsm.ha_tokens", func() (Status, string) {
			total := ha.NumTokens()
			var down []string
			for i := 0; i < total; i++ {
				if err := ha.ProbeToken(ctx, i); err != nil {
					down = append(down, fmt.Sprintf("%s: %v", ha.TokenName(i), err))
				}
			}
			switch {
			case len(down) == 0:
				return StatusPass, fmt.Sprintf("all %d HA token%s reachable and in rotation", total, plural(total))
			case len(down) < total:
				return StatusWarn, fmt.Sprintf("%d/%d token%s unreachable (%s); operations continue on the healthy set",
					len(down), total, plural(total), strings.Join(down, "; "))
			default:
				return StatusFail, fmt.Sprintf("all %d HA tokens unreachable (%s)", total, strings.Join(down, "; "))
			}
		})
	}
	return providers
}

// checkPinSources probes the external credential source(s) backing the PKCS#11
// user PIN (pkcs11.pin_source) for reachability, so a plaintext-free PIN
// configuration is verified before HSM login actually needs the PIN. It resolves
// each source and confirms a non-empty PIN comes back; the value is discarded and
// never logged (only the source Describe() and token name appear in the report).
// An inline (plaintext) PIN has nothing to probe and is reported as a skip that
// nudges toward externalizing it.
func checkPinSources(ctx context.Context, r *Report, cfg *config.Config, opts Options) {
	// Only the PKCS#11 backend has a user PIN.
	usesPKCS11 := false
	for _, role := range rolesInUse(cfg) {
		if cfg.KeyProviderTypeForRole(role) == string(keyprovider.ProviderPKCS11) {
			usesPKCS11 = true
			break
		}
	}
	if !usesPKCS11 {
		r.skip("pin.source", "no signing role uses the PKCS#11 backend")
		return
	}
	if opts.BuildPinSources == nil {
		r.skip("pin.source", "no pin-source factory supplied")
		return
	}
	sources, err := opts.BuildPinSources(cfg)
	if err != nil {
		r.run("pin.source", func() (Status, string) {
			return StatusFail, fmt.Sprintf("configuring pin source: %v", err)
		})
		return
	}
	var external []keyprovider.NamedPinSource
	for _, s := range sources {
		if s.External {
			external = append(external, s)
		}
	}
	if len(external) == 0 {
		r.skip("pin.source", "PIN read inline (pkcs11.pin / SECSY_USER_PIN); set pkcs11.pin_source to source it from a credential store")
		return
	}
	r.run("pin.source", func() (Status, string) {
		var failures, okDescs []string
		for _, s := range external {
			pin, err := s.Source.Resolve(ctx)
			switch {
			case err != nil:
				failures = append(failures, fmt.Sprintf("%s (%s): %v", s.Name, s.Source.Describe(), err))
			case pin == "":
				failures = append(failures, fmt.Sprintf("%s (%s): returned an empty PIN", s.Name, s.Source.Describe()))
			default:
				okDescs = append(okDescs, fmt.Sprintf("%s→%s", s.Name, s.Source.Describe()))
			}
		}
		if len(failures) > 0 {
			return StatusFail, fmt.Sprintf("%d/%d PIN source(s) unreachable: %s", len(failures), len(external), strings.Join(failures, "; "))
		}
		return StatusPass, fmt.Sprintf("all %d PIN source(s) reachable, PIN retrieved (%s)", len(external), strings.Join(okDescs, ", "))
	})
}

// describeBackend renders a short human description of a provider backend.
func describeBackend(cfg *config.Config, ptype string) string {
	switch ptype {
	case string(keyprovider.ProviderPKCS11):
		if n := len(cfg.PKCS11.Tokens); n > 0 {
			return fmt.Sprintf("pkcs11 HA set (%d tokens, module %s)", n, cfg.PKCS11.ModulePath)
		}
		return fmt.Sprintf("pkcs11 token %q (module %s)", cfg.PKCS11.TokenLabel, cfg.PKCS11.ModulePath)
	case string(keyprovider.ProviderKMS):
		if cfg.KeyProvider.KMS.Backend == keyprovider.KMSBackendVault {
			addr := cfg.KeyProvider.KMS.Vault.Address
			mount := cfg.KeyProvider.KMS.Vault.Mount
			if mount == "" {
				mount = "transit"
			}
			return fmt.Sprintf("HashiCorp Vault Transit (%s, mount %s)", addr, mount)
		}
		return fmt.Sprintf("cloud KMS (%s)", cfg.KeyProvider.KMS.Backend)
	case string(keyprovider.ProviderSoftware):
		return "software keystore"
	default:
		return fmt.Sprintf("%q backend", ptype)
	}
}

// --- 3. database --------------------------------------------------------------

// checkDatabase opens the configured store WITHOUT running migrations
// (database.OpenExisting — the read-only invariant), pings it, and reports
// pending migrations as the set of schema tables that would be created on the
// next normal open. Returns the handle plus whether the schema is complete
// enough for the store-dependent checks to run.
func checkDatabase(r *Report, cfg *config.Config) (dbHandle, bool) {
	var db dbHandle
	r.run("db.connectivity", func() (Status, string) {
		d, err := database.OpenExisting(cfg.Database.Driver, cfg.Database.DSN)
		if err != nil {
			return StatusFail, fmt.Sprintf("%s: %v", cfg.Database.Driver, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.Ping(ctx); err != nil {
			_ = d.Close()
			return StatusFail, fmt.Sprintf("%s: %v", cfg.Database.Driver, err)
		}
		db = d
		return StatusPass, fmt.Sprintf("%s store reachable (opened without migrating)", cfg.Database.Driver)
	})
	if db == nil {
		r.skip("db.schema", "store unreachable")
		return nil, false
	}

	schemaOK := false
	r.run("db.schema", func() (Status, string) {
		missing, err := db.MissingTables()
		if err != nil {
			return StatusFail, fmt.Sprintf("inspecting schema: %v", err)
		}
		if len(missing) == 0 {
			schemaOK = true
			return StatusPass, "schema complete; no pending migrations"
		}
		return StatusWarn, fmt.Sprintf("%d table%s pending migration (%s); they are created automatically on the next server/secsy-ca start",
			len(missing), plural(len(missing)), strings.Join(missing, ", "))
	})
	return db, schemaOK
}

// --- 4. role keys -------------------------------------------------------------

// checkRoleKeys runs a sign/verify self-test for every configured signing key:
// each CA key recorded in the store, the TSA key, each artifact-signing key,
// and (presence only — it is a decrypt-usage KEK) the secret-envelope keys.
// The signature is produced inside the provider and verified here against the
// public half — private material never leaves the backend, and where the
// backend can attest it (PKCS#11 CKA_EXTRACTABLE), a key that is unexpectedly
// extractable is flagged.
func checkRoleKeys(ctx context.Context, r *Report, cfg *config.Config, db dbHandle, schemaOK bool, providers *roleProviders) {
	caProv := providers.get("ca")

	// CA signing keys (X.509 and SSH CAs alike), addressed exactly as the
	// issuance path would (ca.KeyRefForCA).
	r.run("keys.ca", func() (Status, string) {
		if caProv == nil {
			return StatusSkip, "ca key provider unavailable"
		}
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		cas, err := db.ListCAs()
		if err != nil {
			return StatusFail, fmt.Sprintf("listing CAs: %v", err)
		}
		if len(cas) == 0 {
			return StatusSkip, "no CAs provisioned yet"
		}
		extractable := extractabilityIndex(ctx, caProv)
		verified := 0
		var problems, warns []string
		for i := range cas {
			c := &cas[i]
			if c.Status == models.CAStatusRetired {
				continue // key may legitimately be destroyed after retirement
			}
			ref := ca.KeyRefForCA(c)
			var wantPub crypto.PublicKey
			if c.Certificate != "" {
				if cert, err := pki.ParseCertificatePEM([]byte(c.Certificate)); err == nil {
					wantPub = cert.PublicKey
				}
			}
			if err := selfTestSign(ctx, caProv, ref, wantPub); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", c.Label, err))
				continue
			}
			if flagged, known := extractable[ref.Label]; known && flagged {
				warns = append(warns, fmt.Sprintf("%s: private key is EXTRACTABLE on the token (violates the non-extractability invariant)", c.Label))
			}
			verified++
		}
		if len(problems) > 0 {
			return StatusFail, fmt.Sprintf("%d/%d CA key%s failed: %s",
				len(problems), verified+len(problems), plural(len(problems)), strings.Join(problems, "; "))
		}
		if len(warns) > 0 {
			return StatusWarn, strings.Join(warns, "; ")
		}
		return StatusPass, fmt.Sprintf("%d CA key%s signed and verified on %s", verified, plural(verified), caProv.Name())
	})

	// TSA signing key.
	if cfg.TSA.Enabled || cfg.TSA.KeyLabel != "" {
		r.run("keys.tsa", func() (Status, string) {
			p := providers.get("tsa")
			if p == nil {
				return StatusSkip, "tsa key provider unavailable"
			}
			if cfg.TSA.KeyLabel == "" {
				return StatusFail, "tsa.enabled is set but tsa.key_label is empty"
			}
			if err := selfTestSign(ctx, p, keyprovider.KeyRef{Label: cfg.TSA.KeyLabel}, nil); err != nil {
				return StatusFail, fmt.Sprintf("%s: %v", cfg.TSA.KeyLabel, err)
			}
			return StatusPass, fmt.Sprintf("%s signed and verified on %s", cfg.TSA.KeyLabel, p.Name())
		})
	} else {
		r.skip("keys.tsa", "tsa not configured")
	}

	// Artifact code-signing keys.
	if len(cfg.Signing.Signers) > 0 {
		r.run("keys.signing", func() (Status, string) {
			p := providers.get("signing")
			if p == nil {
				return StatusSkip, "signing key provider unavailable"
			}
			var problems []string
			for _, s := range cfg.Signing.Signers {
				if err := selfTestSign(ctx, p, keyprovider.KeyRef{Label: s.KeyLabel}, nil); err != nil {
					problems = append(problems, fmt.Sprintf("%s (%s): %v", s.Name, s.KeyLabel, err))
				}
			}
			if len(problems) > 0 {
				return StatusFail, strings.Join(problems, "; ")
			}
			n := len(cfg.Signing.Signers)
			return StatusPass, fmt.Sprintf("%d signing key%s signed and verified on %s", n, plural(n), p.Name())
		})
	} else {
		r.skip("keys.signing", "no artifact signers configured")
	}

	// Secret-envelope KEKs (deployment-wide plus per-tenant overrides). These
	// are RSA decrypt-usage keys: a signing self-test does not apply, so the
	// check asserts presence and type. A missing KEK is a warning, not a
	// failure — it is provisioned on first use — but existing envelopes sealed
	// under a lost KEK would be unrecoverable, hence the loud detail.
	kekLabels := map[string]string{}
	if cfg.Secret.KEKLabel != "" {
		kekLabels[cfg.Secret.KEKLabel] = "secret.kek_label"
	}
	for _, t := range cfg.Tenants {
		if t.KEKLabel != "" {
			kekLabels[t.KEKLabel] = "tenant " + t.ID
		}
	}
	if len(kekLabels) > 0 {
		r.run("keys.secret_kek", func() (Status, string) {
			if caProv == nil {
				return StatusSkip, "ca key provider unavailable"
			}
			var present, absent, wrong []string
			for _, label := range sortedKeys(kekLabels) {
				info, err := caProv.FindKey(ctx, keyprovider.KeyRef{Label: label})
				switch {
				case errors.Is(err, keyprovider.ErrKeyNotFound):
					absent = append(absent, fmt.Sprintf("%s (%s)", label, kekLabels[label]))
				case err != nil:
					wrong = append(wrong, fmt.Sprintf("%s: %v", label, err))
				case !strings.HasPrefix(info.KeyType, "rsa-"):
					wrong = append(wrong, fmt.Sprintf("%s: key type %s (envelope KEKs must be RSA)", label, info.KeyType))
				default:
					present = append(present, label)
				}
			}
			if len(wrong) > 0 {
				return StatusFail, strings.Join(wrong, "; ")
			}
			if len(absent) > 0 {
				return StatusWarn, fmt.Sprintf("KEK%s not yet provisioned: %s (created on first encrypt; envelopes sealed under a lost KEK are unrecoverable)",
					plural(len(absent)), strings.Join(absent, ", "))
			}
			return StatusPass, fmt.Sprintf("%d KEK%s present (RSA, decrypt usage)", len(present), plural(len(present)))
		})
	} else {
		r.skip("keys.secret_kek", "no envelope KEK configured")
	}

	// Delegated OCSP responder keys. The responder certificate itself is
	// short-lived and re-issued in memory as it nears expiry, so its headroom
	// is by construction; what can rot is the responder key. Missing keys are
	// fine (provisioned on first response), but a present key must work.
	if cfg.Server.OCSP.Delegated {
		r.run("keys.ocsp_delegate", func() (Status, string) {
			if caProv == nil {
				return StatusSkip, "ca key provider unavailable"
			}
			if db == nil || !schemaOK {
				return StatusSkip, "store unavailable or schema incomplete"
			}
			cas, err := db.ListCAs()
			if err != nil {
				return StatusFail, fmt.Sprintf("listing CAs: %v", err)
			}
			verified, pending := 0, 0
			var problems []string
			for i := range cas {
				c := &cas[i]
				if c.Status != models.CAStatusActive || c.Certificate == "" {
					continue
				}
				ref := keyprovider.KeyRef{Label: ca.DelegatedOCSPKeyLabel(c.ID)}
				if _, err := caProv.FindKey(ctx, ref); errors.Is(err, keyprovider.ErrKeyNotFound) {
					pending++
					continue
				}
				if err := selfTestSign(ctx, caProv, ref, nil); err != nil {
					problems = append(problems, fmt.Sprintf("%s: %v", c.Label, err))
					continue
				}
				verified++
			}
			if len(problems) > 0 {
				return StatusFail, strings.Join(problems, "; ")
			}
			detail := fmt.Sprintf("%d responder key%s signed and verified", verified, plural(verified))
			if pending > 0 {
				detail += fmt.Sprintf("; %d auto-provisioned on first OCSP response", pending)
			}
			if verified == 0 && pending == 0 {
				return StatusSkip, "no active X.509 CAs"
			}
			return StatusPass, detail + " (responder certificates are short-lived and re-issued automatically)"
		})
	} else {
		r.skip("keys.ocsp_delegate", "delegated OCSP signing not enabled")
	}
}

// extractabilityIndex returns label -> CKA_EXTRACTABLE for hardware-backed
// providers that can enumerate their keys. Software keystores intentionally
// report every key extractable (they are on-disk files), which is not a
// finding, so they are excluded here.
func extractabilityIndex(ctx context.Context, p keyprovider.Provider) map[string]bool {
	if p.Name() != string(keyprovider.ProviderPKCS11) {
		return nil
	}
	lister, ok := p.(keyprovider.KeyLister)
	if !ok {
		return nil
	}
	keys, err := lister.ListKeys(ctx)
	if err != nil {
		return nil // inventory failure is not itself a key failure
	}
	idx := make(map[string]bool, len(keys))
	for _, k := range keys {
		// A label can appear once per key pair; any extractable private half
		// flags the label.
		if k.Extractable {
			idx[k.Label] = true
		} else if _, seen := idx[k.Label]; !seen {
			idx[k.Label] = false
		}
	}
	return idx
}

// selfTestSign proves the referenced key is present and usable: it signs a
// fresh digest/message inside the provider and verifies the signature against
// the public key locally. When wantPub is non-nil (the public key from the
// key's certificate on record), it additionally asserts the provider key and
// the certificate agree — the classic silent failure after a restore from the
// wrong HSM backup. No private key material is read, exported, or created.
func selfTestSign(ctx context.Context, p keyprovider.Provider, ref keyprovider.KeyRef, wantPub crypto.PublicKey) error {
	signer, err := p.Signer(ctx, ref)
	if err != nil {
		return fmt.Errorf("opening signer: %w", err)
	}
	defer signer.Close()

	pub := signer.Public()
	if pub == nil {
		return fmt.Errorf("signer exposes no public key")
	}
	if wantPub != nil && !publicKeysEqual(wantPub, pub) {
		return fmt.Errorf("provider key does not match the certificate on record (restored from a different key set?)")
	}

	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		return fmt.Errorf("generating challenge: %w", err)
	}

	keyType := signer.KeyType()
	switch {
	case keyType == keyprovider.KeyTypeEd25519:
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not ed25519")
		}
		if !ed25519.Verify(edPub, msg, sig) {
			return fmt.Errorf("ed25519 signature failed verification")
		}
	case pqc.IsPQC(keyType):
		sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		if !pqc.VerifyMessage(keyType, pub, msg, sig) {
			return fmt.Errorf("ML-DSA signature failed verification")
		}
	default:
		digest := sha256.Sum256(msg)
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(k, digest[:], sig) {
				return fmt.Errorf("ECDSA signature failed verification")
			}
		case *rsa.PublicKey:
			if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig); err != nil {
				return fmt.Errorf("RSA signature failed verification: %w", err)
			}
		default:
			return fmt.Errorf("unsupported public key type %T for self-test", pub)
		}
	}
	return nil
}

// publicKeysEqual compares two public keys via their Equal method where
// available. Unknown key types conservatively report equal (no false alarm).
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(x crypto.PublicKey) bool }
	if ae, ok := a.(equaler); ok {
		return ae.Equal(b)
	}
	return true
}

// --- 5. audit chain -----------------------------------------------------------

// checkAuditChain re-verifies the newest AuditSample entries of the
// hash-chained event log (audit.chain_head) — contiguous sequence numbers,
// intact back-links, and content hashes, via the same audit.VerifyChain the
// exporters trust. With Deep set it additionally runs the full
// database.VerifyStoreIntegrity gate (db.integrity), which walks the entire
// chain from the genesis entry and asserts the serial/CRL/revocation
// invariants — the same check as `secsy-ca db verify`.
func checkAuditChain(r *Report, db dbHandle, schemaOK bool, opts Options) {
	r.run("audit.chain_head", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		maxSeq, err := db.MaxEventSeq()
		if err != nil {
			return StatusFail, fmt.Sprintf("reading audit head: %v", err)
		}
		if maxSeq == 0 {
			return StatusPass, "audit log is empty (nothing to verify)"
		}
		after := maxSeq - int64(opts.AuditSample)
		if after < 0 {
			after = 0
		}
		events, err := db.ListEventsSince(after, opts.AuditSample)
		if err != nil {
			return StatusFail, fmt.Sprintf("loading audit tail: %v", err)
		}
		res := audit.VerifyChain(events)
		if !res.Valid {
			return StatusFail, fmt.Sprintf("chain broken at seq %d: %s (sampled newest %d of %d)",
				res.BrokenAtSeq, res.Reason, len(events), maxSeq)
		}
		head := events[len(events)-1]
		return StatusPass, fmt.Sprintf("newest %d of %d event%s verified; head seq=%d hash=%.12s…",
			len(events), maxSeq, plural(int(maxSeq)), head.Seq, head.Hash)
	})

	if !opts.Deep {
		r.skip("db.integrity", "run with -deep for the full store-integrity gate (secsy-ca db verify)")
		return
	}
	r.run("db.integrity", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		res, err := db.VerifyStoreIntegrity()
		if err != nil {
			return StatusFail, fmt.Sprintf("verifying store: %v", err)
		}
		if !res.OK {
			var bad []string
			for _, c := range res.Checks {
				if !c.OK {
					bad = append(bad, fmt.Sprintf("%s: %s", c.Name, c.Detail))
				}
			}
			return StatusFail, strings.Join(bad, "; ")
		}
		return StatusPass, fmt.Sprintf("full chain (%d events) and serial/CRL/revocation invariants verified",
			res.Fingerprint.AuditEventCount)
	})
}

// --- 6. certificate expiry -----------------------------------------------------

// expiryStatus classifies remaining certificate lifetime against the
// configured thresholds.
func expiryStatus(notAfter time.Time, now time.Time, opts Options) (Status, string) {
	left := notAfter.Sub(now)
	switch {
	case left <= 0:
		return StatusFail, fmt.Sprintf("EXPIRED %s ago", humanDuration(left))
	case left < opts.ExpiryFail:
		return StatusFail, fmt.Sprintf("expires in %s", humanDuration(left))
	case left < opts.ExpiryWarn:
		return StatusWarn, fmt.Sprintf("expires in %s", humanDuration(left))
	default:
		return StatusPass, fmt.Sprintf("%s of headroom", humanDuration(left))
	}
}

// worse returns the more severe of two statuses (fail > warn > pass > skip).
func worse(a, b Status) Status {
	rank := map[Status]int{StatusSkip: 0, StatusPass: 1, StatusWarn: 2, StatusFail: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// checkCertExpiry reports expiry headroom for the CA certificates on record
// (certs.ca_expiry) and for the TSA / artifact-signing certificates configured
// from PEM files (certs.tsa_expiry, certs.signing_expiry). Superseded CAs cap
// at warn — expiring is their expected fate mid-rotation; retired CAs are
// skipped.
func checkCertExpiry(r *Report, cfg *config.Config, db dbHandle, schemaOK bool, opts Options) {
	now := time.Now()

	r.run("certs.ca_expiry", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		cas, err := db.ListCAs()
		if err != nil {
			return StatusFail, fmt.Sprintf("listing CAs: %v", err)
		}
		overall := StatusPass
		checked := 0
		var findings []string
		minLeft := time.Duration(1<<62 - 1)
		var minLabel string
		for i := range cas {
			c := &cas[i]
			if c.Certificate == "" || c.Status == models.CAStatusRetired {
				continue
			}
			cert, err := pki.ParseCertificatePEM([]byte(c.Certificate))
			if err != nil {
				overall = worse(overall, StatusFail)
				findings = append(findings, fmt.Sprintf("%s: unparseable certificate: %v", c.Label, err))
				continue
			}
			checked++
			st, msg := expiryStatus(cert.NotAfter, now, opts)
			if c.Status == models.CAStatusSuperseded && st == StatusFail {
				st = StatusWarn // rotation already in progress; expiry is expected
				msg += " (superseded; rotation in progress)"
			}
			if st != StatusPass {
				findings = append(findings, fmt.Sprintf("%s: %s", c.Label, msg))
			}
			overall = worse(overall, st)
			if left := cert.NotAfter.Sub(now); left < minLeft {
				minLeft, minLabel = left, c.Label
			}
		}
		if checked == 0 {
			return StatusSkip, "no X.509 CA certificates on record"
		}
		if len(findings) > 0 {
			return overall, strings.Join(findings, "; ")
		}
		return StatusPass, fmt.Sprintf("%d CA certificate%s healthy; tightest headroom %s (%s)",
			checked, plural(checked), humanDuration(minLeft), minLabel)
	})

	checkCertFile := func(name, path, what string, enabled bool) {
		if !enabled {
			r.skip(name, what+" not configured")
			return
		}
		r.run(name, func() (Status, string) {
			if path == "" {
				return StatusFail, what + " is enabled but no certificate_file is configured"
			}
			pemBytes, err := os.ReadFile(path)
			if err != nil {
				return StatusFail, fmt.Sprintf("%s: %v", what, err)
			}
			cert, err := pki.ParseCertificatePEM(pemBytes)
			if err != nil {
				return StatusFail, fmt.Sprintf("%s %s: %v", what, path, err)
			}
			st, msg := expiryStatus(cert.NotAfter, now, opts)
			return st, fmt.Sprintf("%s (%q): %s", path, cert.Subject.CommonName, msg)
		})
	}

	checkCertFile("certs.tsa_expiry", cfg.TSA.CertificateFile, "TSA certificate",
		cfg.TSA.Enabled || cfg.TSA.CertificateFile != "")

	if len(cfg.Signing.Signers) > 0 {
		r.run("certs.signing_expiry", func() (Status, string) {
			overall := StatusPass
			var findings []string
			for _, s := range cfg.Signing.Signers {
				pemBytes, err := os.ReadFile(s.CertificateFile)
				if err != nil {
					overall = StatusFail
					findings = append(findings, fmt.Sprintf("%s: %v", s.Name, err))
					continue
				}
				cert, err := pki.ParseCertificatePEM(pemBytes)
				if err != nil {
					overall = StatusFail
					findings = append(findings, fmt.Sprintf("%s: %v", s.Name, err))
					continue
				}
				st, msg := expiryStatus(cert.NotAfter, now, opts)
				if st != StatusPass {
					findings = append(findings, fmt.Sprintf("%s: %s", s.Name, msg))
				}
				overall = worse(overall, st)
			}
			if len(findings) > 0 {
				return overall, strings.Join(findings, "; ")
			}
			n := len(cfg.Signing.Signers)
			return StatusPass, fmt.Sprintf("%d signing certificate%s healthy", n, plural(n))
		})
	} else {
		r.skip("certs.signing_expiry", "no artifact signers configured")
	}
}

// --- 7. CRL freshness -----------------------------------------------------------

// checkCRLFreshness compares every persisted base/delta CRL's nextUpdate
// against now. A CRL past nextUpdate is normally regenerated on the next API
// fetch, so it warns — unless static publishing is enabled, where consumers
// read the persisted artifact directly and staleness fails the check. A CRL
// inside the final quarter of its window warns.
func checkCRLFreshness(r *Report, cfg *config.Config, db dbHandle, schemaOK bool) {
	r.run("crl.freshness", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		crls, err := db.ListPublishedCRLs()
		if err != nil {
			return StatusFail, fmt.Sprintf("listing persisted CRLs: %v", err)
		}
		if len(crls) == 0 {
			return StatusSkip, "no persisted CRLs (generated on first fetch/publish)"
		}

		labels := caLabelIndex(db)
		now := time.Now()
		staleIsFatal := cfg.Publish.Enabled
		fresh, nearing, stale := 0, 0, 0
		var findings []string
		for _, c := range crls {
			name := fmt.Sprintf("%s %s/%s #%d", labels[c.CAID], c.Scope, c.Kind, c.Number)
			remaining := c.NextUpdate.Sub(now)
			window := c.NextUpdate.Sub(c.ThisUpdate)
			switch {
			case remaining <= 0:
				stale++
				findings = append(findings, fmt.Sprintf("%s expired %s ago", name, humanDuration(remaining)))
			case window > 0 && remaining < window/4:
				nearing++
				findings = append(findings, fmt.Sprintf("%s has %s of %s window left", name, humanDuration(remaining), humanDuration(window)))
			default:
				fresh++
			}
		}
		summary := fmt.Sprintf("%d fresh, %d nearing nextUpdate, %d stale of %d persisted CRL%s",
			fresh, nearing, stale, len(crls), plural(len(crls)))
		if len(findings) > 0 {
			summary += ": " + strings.Join(findings, "; ")
		}
		switch {
		case stale > 0 && staleIsFatal:
			return StatusFail, summary + " (publish.enabled serves these statically — republish now)"
		case stale > 0:
			return StatusWarn, summary + " (regenerated on next fetch; republish if served statically)"
		case nearing > 0:
			return StatusWarn, summary
		default:
			return StatusPass, summary
		}
	})
}

// caLabelIndex maps CA ids to labels for readable findings; on any error the
// ids simply appear raw.
func caLabelIndex(db dbHandle) map[string]string {
	labels := map[string]string{}
	if cas, err := db.ListCAs(); err == nil {
		for _, c := range cas {
			labels[c.ID] = c.Label
		}
	}
	return labels
}

// --- 7b. issuance canary -----------------------------------------------------

// canaryEventWindow bounds how many recent canary.probe audit events the check
// reads to find each probed CA's newest result. Far above any realistic number
// of canary-probed CAs per cycle.
const canaryEventWindow = 100

// checkCanary surfaces the synthetic issuance canary's last outcome per probed
// CA (Task 71) from the canary.probe audit trail: a fail when any CA's newest
// probe errored, a warn when the canary looks stalled (enabled but silent for
// over three intervals), and the last-success ages otherwise. The audit log is
// the offline source of truth here — doctor runs out-of-process, so it cannot
// read the prober's in-memory state or metrics.
func checkCanary(r *Report, cfg *config.Config, db dbHandle, schemaOK bool) {
	r.run("canary.last_probe", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		events, _, err := db.ListEvents(audit.ActionCanaryProbe, "", "", canaryEventWindow, 0)
		if err != nil {
			return StatusFail, fmt.Sprintf("listing canary.probe audit events: %v", err)
		}
		if len(events) == 0 {
			if cfg.Canary.Enabled {
				return StatusWarn, "canary.enabled is set but no probe has been recorded yet (server not started, or this replica never led?)"
			}
			return StatusSkip, "issuance canary disabled (canary.enabled) and no probes on record"
		}

		// Newest event per probed CA (events arrive newest-first).
		type lastProbe struct{ e audit.Event }
		latest := map[string]lastProbe{}
		order := []string{}
		for _, e := range events {
			if _, seen := latest[e.Target]; seen {
				continue
			}
			latest[e.Target] = lastProbe{e: e}
			order = append(order, e.Target)
		}

		now := time.Now()
		stalledAfter := 3 * cfg.Canary.Interval()
		overall := StatusPass
		var parts []string
		for _, target := range order {
			e := latest[target].e
			name := e.TargetName
			if name == "" {
				name = target
			}
			age := humanDuration(now.Sub(e.Timestamp))
			switch {
			case e.Result != audit.ResultSuccess:
				overall = worse(overall, StatusFail)
				parts = append(parts, fmt.Sprintf("%s: FAILED %s ago (%s)", name, age, e.Detail))
			case cfg.Canary.Enabled && now.Sub(e.Timestamp) > stalledAfter:
				overall = worse(overall, StatusWarn)
				parts = append(parts, fmt.Sprintf("%s: ok but stalled — last probe %s ago exceeds 3x the %s interval", name, age, cfg.Canary.Interval()))
			default:
				parts = append(parts, fmt.Sprintf("%s: ok %s ago", name, age))
			}
		}
		return overall, strings.Join(parts, "; ")
	})
}

// checkBackup surfaces the scheduled encrypted-backup job's freshness (Task 89)
// from the backup.run audit trail: a fail when the newest run errored or the
// last successful backup is older than the retention max age (a real data-loss
// window), a warn when the job looks stalled (enabled but silent beyond three
// intervals), and the last-success age otherwise. The audit log is the offline
// source of truth here — doctor runs out-of-process and cannot read the runner's
// in-memory state or metrics.
func checkBackup(r *Report, cfg *config.Config, db dbHandle, schemaOK bool) {
	r.run("backup.freshness", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		events, _, err := db.ListEvents(audit.ActionBackupRun, "", "", 20, 0)
		if err != nil {
			return StatusFail, fmt.Sprintf("listing backup.run audit events: %v", err)
		}
		if len(events) == 0 {
			if cfg.Backup.Enabled {
				return StatusWarn, "backup.enabled is set but no backup has been recorded yet (server not started, or this replica never led?)"
			}
			return StatusSkip, "scheduled backup disabled (backup.enabled) and no backups on record"
		}

		newest := events[0] // newest first
		now := time.Now()
		age := humanDuration(now.Sub(newest.Timestamp))
		if newest.Result != audit.ResultSuccess {
			return StatusFail, fmt.Sprintf("last backup FAILED %s ago (%s)", age, newest.Detail)
		}
		if !cfg.Backup.Enabled {
			return StatusPass, fmt.Sprintf("last backup ok %s ago (scheduled backup currently disabled)", age)
		}
		elapsed := now.Sub(newest.Timestamp)
		if maxAge := cfg.Backup.MaxAge(); maxAge > 0 && elapsed > maxAge {
			return StatusFail, fmt.Sprintf("last successful backup was %s ago, exceeding the %s retention max age — backups are stale and may already have been pruned",
				age, humanDuration(maxAge))
		}
		if elapsed > 3*cfg.Backup.Interval() {
			return StatusWarn, fmt.Sprintf("last backup ok but stalled — %s ago exceeds 3x the %s interval", age, cfg.Backup.Interval())
		}
		return StatusPass, fmt.Sprintf("last backup ok %s ago", age)
	})
}

// checkBackupRestoreVerified surfaces the automated restore-verification drill's
// freshness (Task 94) from the backup.verify audit trail: a fail when the newest
// drill failed (a published backup that could not be proven restorable — an
// untested backup is not a backup) or when the last successful verification is
// older than the retention max age (the verified backup may already have been
// pruned, so nothing current is proven restorable), a warn when the drill looks
// stalled (enabled but silent beyond three verify intervals), and the
// last-verified age otherwise. Like checkBackup, the audit log is the offline
// source of truth — doctor cannot read the verifier's in-memory state.
func checkBackupRestoreVerified(r *Report, cfg *config.Config, db dbHandle, schemaOK bool) {
	r.run("backup.restore-verified", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		enabled := cfg.Backup.Enabled && cfg.Backup.VerifyEnabled()
		events, _, err := db.ListEvents(audit.ActionBackupVerify, "", "", 20, 0)
		if err != nil {
			return StatusFail, fmt.Sprintf("listing backup.verify audit events: %v", err)
		}
		if len(events) == 0 {
			if enabled {
				return StatusWarn, "backup.verify.enabled is set but no restore-verification has been recorded yet (server not started, or this replica never led?)"
			}
			return StatusSkip, "automated restore-verification disabled (backup.verify.enabled) and no drills on record"
		}

		newest := events[0] // newest first
		now := time.Now()
		age := humanDuration(now.Sub(newest.Timestamp))
		if newest.Result != audit.ResultSuccess {
			return StatusFail, fmt.Sprintf("last restore-verification FAILED %s ago (%s) — recovery is unproven", age, newest.Detail)
		}
		if !enabled {
			return StatusPass, fmt.Sprintf("last restore-verification ok %s ago (automated verification currently disabled)", age)
		}
		elapsed := now.Sub(newest.Timestamp)
		if maxAge := cfg.Backup.MaxAge(); maxAge > 0 && elapsed > maxAge {
			return StatusFail, fmt.Sprintf("last successful restore-verification was %s ago, exceeding the %s retention max age — the verified backup may already be pruned, so no current backup is proven restorable",
				age, humanDuration(maxAge))
		}
		if elapsed > 3*cfg.Backup.VerifyInterval() {
			return StatusWarn, fmt.Sprintf("last restore-verification ok but stalled — %s ago exceeds 3x the %s verify interval", age, cfg.Backup.VerifyInterval())
		}
		return StatusPass, fmt.Sprintf("last restore-verification ok %s ago (backup proven restorable)", age)
	})
}

// --- 7d. CT inclusion monitoring ---------------------------------------------

// checkCTInclusion surfaces the Certificate Transparency SCT inclusion monitor's
// state (Task 93): it FAILS when any embedded SCT is in the 'failed' state — a
// log that did not honor an SCT it issued (mis-issuance / log-misbehavior) — read
// directly from the sct_inclusion table, and warns when the monitor is enabled
// but silent (no scan recorded) or stalled (last scan older than three
// intervals). The audit log supplies scan freshness; the table supplies the
// standing pass/fail counts. Both are offline reads, so doctor works without a
// running server or a metrics scrape.
func checkCTInclusion(r *Report, cfg *config.Config, db dbHandle, schemaOK bool) {
	r.run("ct.inclusion", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		enabled := cfg.CertificateTransparency.InclusionMonitor.Enabled
		counts, err := db.CountSCTInclusionByStatus()
		if err != nil {
			return StatusFail, fmt.Sprintf("reading SCT inclusion state: %v", err)
		}
		total := 0
		for _, n := range counts {
			total += n
		}
		if total == 0 {
			if enabled {
				return StatusWarn, "CT inclusion monitor is enabled but no SCT has been verified yet (server not started, or this replica never led?)"
			}
			return StatusSkip, "CT inclusion monitor disabled and no SCT inclusion state on record"
		}

		included := counts[models.SCTInclusionIncluded]
		pending := counts[models.SCTInclusionPending]
		failed := counts[models.SCTInclusionFailed]
		unknown := counts[models.SCTInclusionUnknownLog]
		summary := fmt.Sprintf("%d SCT(s): %d included, %d pending, %d failed, %d unknown-log",
			total, included, pending, failed, unknown)

		// A failed SCT is the primary signal: a log did not include a certificate
		// it issued an SCT for.
		if failed > 0 {
			return StatusFail, summary + " — a CT log FAILED to honor an embedded SCT (mis-issuance / log-misbehavior); inspect `secsy-ca ct verify-inclusion`"
		}

		// Freshness of the newest scan (only meaningful while enabled).
		events, _, err := db.ListEvents(audit.ActionCTInclusion, "", "", 1, 0)
		if err != nil {
			return StatusWarn, summary + fmt.Sprintf("; could not read scan freshness: %v", err)
		}
		if enabled {
			if len(events) == 0 {
				return StatusWarn, summary + "; monitor enabled but no scan recorded yet"
			}
			newest := events[0]
			age := humanDuration(time.Since(newest.Timestamp))
			if newest.Result != audit.ResultSuccess {
				return StatusWarn, summary + fmt.Sprintf("; last scan reported an issue %s ago (%s)", age, newest.Detail)
			}
			if time.Since(newest.Timestamp) > 3*cfg.CertificateTransparency.InclusionMonitor.Interval() {
				return StatusWarn, summary + fmt.Sprintf("; monitor stalled — last scan %s ago exceeds 3x the %s interval",
					age, cfg.CertificateTransparency.InclusionMonitor.Interval())
			}
		}
		if unknown > 0 {
			return StatusWarn, summary + " — some SCTs reference logs not in the registry (configure their public keys to verify inclusion)"
		}
		return StatusPass, summary
	})
}

// --- 7e. outbound webhook dead-letters ------------------------------------------

// checkWebhookDeadLetters reports on the durable outbound webhook queue (Task
// 116). Dead-lettered deliveries — those that exhausted their retry budget — are
// the operator's signal that an endpoint is misconfigured (wrong URL/secret) or
// down: the CA kept issuing but downstream automation stopped hearing about it. A
// stale dead-letter (older than the configured threshold) escalates to a failure;
// a fresh one is a warning. It also flags the misconfiguration where deliveries
// are queued but the delivery worker is disabled, so they will never be sent.
func checkWebhookDeadLetters(r *Report, cfg *config.Config, db dbHandle, schemaOK bool) {
	r.run("webhook.dead_letters", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		counts, err := db.CountWebhookDeliveriesByStatus()
		if err != nil {
			return StatusFail, fmt.Sprintf("reading webhook delivery state: %v", err)
		}
		subs, err := db.ListEnabledWebhookSubscriptions()
		if err != nil {
			return StatusFail, fmt.Sprintf("reading webhook subscriptions: %v", err)
		}
		total := 0
		for _, n := range counts {
			total += n
		}
		if total == 0 && len(subs) == 0 {
			return StatusSkip, "no webhook subscriptions or deliveries on record"
		}

		dead := counts[models.WebhookDeliveryDead]
		pending := counts[models.WebhookDeliveryPending]
		delivered := counts[models.WebhookDeliveryDelivered]
		summary := fmt.Sprintf("%d subscription(s); deliveries: %d delivered, %d pending, %d dead-lettered",
			len(subs), delivered, pending, dead)

		// Queued work with no worker to send it is a standing misconfiguration.
		if pending > 0 && !cfg.Webhook.Enabled {
			return StatusWarn, summary + " — webhook.enabled is false, so the pending deliveries will not be sent until the delivery worker is enabled"
		}

		if dead == 0 {
			return StatusPass, summary
		}

		// A dead-letter is a genuine delivery failure; escalate on staleness.
		oldest, err := db.OldestDeadWebhookDelivery()
		if err != nil || oldest == nil {
			return StatusWarn, summary + " — dead-lettered deliveries need triage (inspect `secsy-ca webhook deliveries`)"
		}
		age := time.Since(oldest.CreatedAt)
		threshold := cfg.Webhook.DeadLetterStale()
		if age > threshold {
			return StatusFail, fmt.Sprintf("%s — oldest dead-letter is %s old, exceeding the %s threshold; an endpoint is misconfigured or down (inspect `secsy-ca webhook deliveries -status dead`)",
				summary, humanDuration(age), humanDuration(threshold))
		}
		return StatusWarn, fmt.Sprintf("%s — oldest dead-letter is %s old (inspect `secsy-ca webhook deliveries -status dead`)",
			summary, humanDuration(age))
	})
}

// --- 7f. pre-issuance key-quality gate (Task 120) --------------------------------

// checkKeyChecks reports on the fail-closed pre-issuance key-quality gate
// (CA/Browser Forum BR §6.1.1.3). keychecks.blocklist proves the optional Debian
// weak-key blocklist file(s) load (a configured-but-unloadable path is fatal —
// the server would refuse to start) and reports the operator compromised-key
// blocklist size. keychecks.profiles flags any custom profile that has weakened
// the gate (disabled or set to warn mode), which reopens the weak/compromised-key
// hole for that profile.
func checkKeyChecks(r *Report, cfg *config.Config, db dbHandle, schemaOK bool) {
	r.run("keychecks.blocklist", func() (Status, string) {
		var loaded int
		if paths := cfg.KeyChecks.WeakKeyBlocklistPaths; len(paths) > 0 {
			bl, err := keycheck.LoadBlocklist(paths...)
			if err != nil {
				// The server treats this as fatal at startup; surface it as a failure.
				return StatusFail, fmt.Sprintf("weak-key blocklist (keychecks.weak_key_blocklist_paths) failed to load: %v — the server would refuse to start", err)
			}
			loaded = bl.Len()
		}
		opCount := -1
		if db != nil && schemaOK {
			n, err := db.CountBlockedKeys()
			if err != nil {
				return StatusFail, fmt.Sprintf("reading the compromised-key blocklist: %v", err)
			}
			opCount = n
		}
		opDetail := "unknown (store unavailable)"
		if opCount >= 0 {
			opDetail = fmt.Sprintf("%d key%s", opCount, plural(opCount))
		}
		detail := fmt.Sprintf("weak-key file blocklist: %d fingerprint(s); operator compromised-key blocklist: %s", loaded, opDetail)
		if loaded == 0 && len(cfg.KeyChecks.WeakKeyBlocklistPaths) == 0 {
			// The structural checks (ROCA / exponent / modulus) and the operator
			// blocklist still run; the Debian file blocklist is simply not configured.
			return StatusPass, detail + " (no Debian weak-key blocklist configured; structural checks still enforce)"
		}
		return StatusPass, detail
	})

	r.run("keychecks.profiles", func() (Status, string) {
		var weakened []string
		for _, p := range cfg.Profiles {
			switch {
			case p.KeyChecks.Disabled:
				weakened = append(weakened, p.Name+"=disabled")
			case strings.EqualFold(strings.TrimSpace(p.KeyChecks.Mode), "warn"):
				weakened = append(weakened, p.Name+"=warn")
			}
		}
		if len(weakened) == 0 {
			return StatusPass, fmt.Sprintf("key-quality gate is enforced on all %d custom profile(s) (and every built-in)", len(cfg.Profiles))
		}
		return StatusWarn, fmt.Sprintf("%d profile(s) have weakened the key-quality gate: %s — weak/compromised subject keys will not be blocked there",
			len(weakened), strings.Join(weakened, ", "))
	})
}

// --- 8. clock skew ---------------------------------------------------------------

// checkClockSkew sanity-checks this host's clock. Against PostgreSQL it
// measures the offset to the database server's NOW() (bounded by the query
// round-trip); skewed replica clocks distort validity windows, CRL freshness,
// and audit ordering. On any backend it also asserts the newest audit event
// is not from the future, which catches a rewound local clock.
func checkClockSkew(ctx context.Context, r *Report, db dbHandle, schemaOK bool, opts Options) {
	r.run("clock.skew", func() (Status, string) {
		if db == nil {
			return StatusSkip, "store unavailable"
		}
		var parts []string

		before := time.Now()
		dbTime, comparable, err := db.ServerTime(ctx)
		rtt := time.Since(before)
		if err != nil {
			return StatusFail, fmt.Sprintf("reading database time: %v", err)
		}
		status := StatusPass
		if comparable {
			// Compare against the query midpoint; the round-trip bounds the
			// measurement error, so only offsets beyond rtt are meaningful.
			skew := dbTime.Sub(before.Add(rtt / 2))
			if skew < 0 {
				skew = -skew
			}
			effective := skew - rtt
			if effective < 0 {
				effective = 0
			}
			switch {
			case effective > opts.SkewFail:
				status = StatusFail
			case effective > opts.SkewWarn:
				status = StatusWarn
			}
			parts = append(parts, fmt.Sprintf("host↔database offset ≈%s (rtt %s)", humanDuration(skew), humanDuration(rtt)))
		} else {
			parts = append(parts, "embedded store shares the host clock")
		}

		// Future-dated audit head: the newest sealed event must not be ahead of
		// this host's clock by more than a small tolerance.
		if schemaOK {
			if maxSeq, err := db.MaxEventSeq(); err == nil && maxSeq > 0 {
				if events, err := db.ListEventsSince(maxSeq-1, 1); err == nil && len(events) == 1 {
					if ahead := time.Until(events[0].Timestamp); ahead > 2*time.Minute {
						status = worse(status, StatusWarn)
						parts = append(parts, fmt.Sprintf("newest audit event is %s in the future (clock rewound, or a replica clock is ahead)", humanDuration(ahead)))
					}
				}
			}
		}
		return status, strings.Join(parts, "; ")
	})
}

// --- 8f. self-issued serving certificate ------------------------------------

// checkServingCert surfaces the freshness of the self-managed serving-TLS
// certificate (Task 118) when server.tls.self_issue is enabled. The server
// dogfoods its own HTTPS listener certificate from an internal CA and a
// background loop rotates it before expiry. doctor runs out-of-process and
// cannot read the loop's in-memory state, so it consults the offline source of
// truth: the newest serving-tls-marked record in the store. A certificate
// already inside its renew_before window (or expired) means rotation is not
// keeping up — the process is not running, never issued one, or issuance is
// failing.
func checkServingCert(r *Report, cfg *config.Config, db dbHandle, schemaOK bool, opts Options) {
	sc := cfg.Server.TLS.SelfIssue
	if !sc.Enabled {
		r.skip("serving.self_issued", "server.tls.self_issue disabled")
		return
	}
	r.run("serving.self_issued", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		cas, err := db.ListCAs()
		if err != nil {
			return StatusFail, fmt.Sprintf("listing CAs: %v", err)
		}
		var newest *models.IssuedCertificate
		for i := range cas {
			issued, err := db.ListIssuedCertificates(cas[i].ID)
			if err != nil {
				return StatusFail, fmt.Sprintf("listing issued certificates for CA %s: %v", cas[i].Label, err)
			}
			for j := range issued {
				c := &issued[j]
				if c.Marker != models.CertMarkerServingTLS {
					continue
				}
				if newest == nil || c.NotAfter.After(newest.NotAfter) {
					newest = c
				}
			}
		}
		if newest == nil {
			return StatusWarn, "self_issue enabled but no serving-tls certificate on record yet (server not started, or it has not issued one?)"
		}
		now := time.Now()
		st, msg := expiryStatus(newest.NotAfter, now, opts)
		// A certificate already inside its renew_before window should have been
		// rotated already; flag it even when it still has generic expiry headroom.
		if renewBefore, derr := sc.RenewBeforeDuration(); derr == nil && renewBefore > 0 {
			if remaining := newest.NotAfter.Sub(now); remaining > 0 && remaining <= renewBefore && st == StatusPass {
				st = StatusWarn
				msg = fmt.Sprintf("%s, inside the renew_before=%s window — is the rotation loop running?", msg, humanDuration(renewBefore))
			}
		}
		return st, fmt.Sprintf("newest serving-tls cert (serial %s, CN=%q): %s", newest.Serial, newest.CommonName, msg)
	})
}

// --- 9. listener TLS ---------------------------------------------------------------

// checkListenerTLS validates the listener's TLS material statically
// (certificate/key parse and match, leaf expiry headroom) and, when the
// listener is reachable, performs a live handshake and confirms the running
// server presents the configured certificate. An unreachable listener is not a
// finding — doctor typically runs before the server starts.
func checkListenerTLS(r *Report, cfg *config.Config, opts Options) {
	r.run("listener.tls", func() (Status, string) {
		if cfg.Server.TLSCert == "" || cfg.Server.TLSKey == "" {
			// Self-issued serving certificate (Task 118): the server mints and
			// rotates its own listener certificate, so there is no static cert/key
			// pair on disk. serving.self_issued covers its store-side freshness;
			// here we only attempt a live handshake to confirm TLS is served.
			if cfg.Server.TLS.SelfIssue.Enabled {
				return checkSelfIssuedListener(cfg, opts)
			}
			// Mirror the server's own opt-in switch (cmd/server insecureHTTPAllowed).
			switch strings.ToLower(strings.TrimSpace(os.Getenv("SECSY_ALLOW_INSECURE_HTTP"))) {
			case "1", "true", "yes":
				return StatusWarn, "no TLS configured; SECSY_ALLOW_INSECURE_HTTP opts into cleartext (only safe behind a trusted TLS-terminating proxy)"
			}
			return StatusFail, "no TLS configured (server.tls_cert/tls_key); the server fails closed and will refuse to start"
		}

		pair, err := tls.LoadX509KeyPair(cfg.Server.TLSCert, cfg.Server.TLSKey)
		if err != nil {
			return StatusFail, fmt.Sprintf("loading key pair: %v", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return StatusFail, fmt.Sprintf("parsing certificate: %v", err)
		}
		status, msg := expiryStatus(leaf.NotAfter, time.Now(), opts)
		detail := fmt.Sprintf("certificate/key match; %s", msg)

		if opts.SkipListener {
			return status, detail + "; live probe skipped"
		}

		host := cfg.Server.Host
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", cfg.Server.Port))
		conn, err := net.DialTimeout("tcp", addr, opts.DialTimeout)
		if err != nil {
			return status, detail + fmt.Sprintf("; listener %s not reachable (server not running?)", addr)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(opts.DialTimeout))

		// The handshake itself is the check; the served chain is then compared
		// to the configured certificate, so verification is pinned rather than
		// PKI-dependent.
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- identity is pinned below
		if err := tlsConn.Handshake(); err != nil {
			return worse(status, StatusWarn), detail + fmt.Sprintf("; %s reachable but TLS handshake failed: %v", addr, err)
		}
		served := tlsConn.ConnectionState().PeerCertificates
		if len(served) > 0 && served[0].Equal(leaf) {
			return status, detail + fmt.Sprintf("; live handshake OK on %s (%s, serving the configured certificate)",
				addr, tls.VersionName(tlsConn.ConnectionState().Version))
		}
		return worse(status, StatusWarn), detail + fmt.Sprintf("; live handshake OK on %s but the server presents a DIFFERENT certificate (restart pending after cert rotation?)", addr)
	})
}

// checkSelfIssuedListener probes the listener when the self-issued serving
// certificate is in use (no static cert/key pair to compare against). It reports
// the served leaf's expiry from a live handshake; an unreachable listener is not
// a finding, since doctor commonly runs before the server is up.
func checkSelfIssuedListener(cfg *config.Config, opts Options) (Status, string) {
	if opts.SkipListener {
		return StatusPass, "self-issued serving certificate (no static key pair on disk); live probe skipped"
	}
	host := cfg.Server.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", cfg.Server.Port))
	conn, err := net.DialTimeout("tcp", addr, opts.DialTimeout)
	if err != nil {
		return StatusPass, fmt.Sprintf("self-issued serving certificate; listener %s not reachable (server not running?)", addr)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(opts.DialTimeout))

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- reads served-cert freshness, does not authenticate
	if err := tlsConn.Handshake(); err != nil {
		return StatusWarn, fmt.Sprintf("self-issued serving certificate; %s reachable but TLS handshake failed: %v", addr, err)
	}
	served := tlsConn.ConnectionState().PeerCertificates
	if len(served) == 0 {
		return StatusWarn, fmt.Sprintf("self-issued serving certificate; %s served no certificate", addr)
	}
	leaf := served[0]
	status, msg := expiryStatus(leaf.NotAfter, time.Now(), opts)
	return status, fmt.Sprintf("self-issued serving certificate (CN=%q): live handshake OK on %s (%s); %s",
		leaf.Subject.CommonName, addr, tls.VersionName(tlsConn.ConnectionState().Version), msg)
}

// --- 10. FIPS 140-3 posture ---------------------------------------------------

// checkFIPS diagnoses the FIPS 140-3 posture when the fail-closed security.fips
// policy is enabled (config with non-approved algorithms never reaches here —
// config.Load rejects it, which config.parse reports verbatim). It verifies the
// process actually runs on the Go Cryptographic Module, that key material
// already in the store satisfies the policy (a CA keyed before the policy was
// enabled would fail at its next issuance), and that the secret-envelope KEKs
// negotiate SHA-256 OAEP — the policy refuses the SHA-1 fallback SoftHSM would
// otherwise get (see the secret package).
func checkFIPS(ctx context.Context, r *Report, cfg *config.Config, db dbHandle, schemaOK bool, providers *roleProviders) {
	if !cfg.Security.FIPS {
		r.skip("fips.mode", "security.fips not enabled")
		r.skip("fips.store_keys", "security.fips not enabled")
		r.skip("fips.secret_oaep", "security.fips not enabled")
		return
	}

	r.run("fips.mode", func() (Status, string) {
		if !fips.ModuleEnabled() {
			return StatusWarn, "security.fips policy is enforced but the process is NOT running on the Go FIPS 140-3 module — build with `make build-fips` (GOFIPS140) or set GODEBUG=fips140=on (" + fips.Summary() + ")"
		}
		return StatusPass, fips.Summary()
	})

	// Key material created before the policy was enabled may be non-approved;
	// issuance under such a CA fails at runtime, so surface it up front.
	r.run("fips.store_keys", func() (Status, string) {
		if db == nil || !schemaOK {
			return StatusSkip, "store unavailable or schema incomplete"
		}
		cas, err := db.ListCAs()
		if err != nil {
			return StatusFail, fmt.Sprintf("listing CAs: %v", err)
		}
		overall := StatusPass
		checked := 0
		var findings []string
		for i := range cas {
			c := &cas[i]
			if c.Certificate == "" || c.Status == models.CAStatusRetired {
				continue
			}
			cert, err := pki.ParseCertificatePEM([]byte(c.Certificate))
			if err != nil {
				// certs.ca_expiry already fails unparseable certificates.
				continue
			}
			checked++
			if err := fips.ApprovedPublicKey(cert.PublicKey); err != nil {
				overall = worse(overall, StatusFail)
				findings = append(findings, fmt.Sprintf("CA %s: %v", c.Label, err))
				continue
			}
			if err := fips.ApprovedSignatureAlgorithm(cert.SignatureAlgorithm); err != nil {
				overall = worse(overall, StatusFail)
				findings = append(findings, fmt.Sprintf("CA %s: certificate signature: %v", c.Label, err))
			}
		}
		if overall != StatusPass {
			return overall, fmt.Sprintf("%d non-approved key%s in the store (issuance under them will be refused): %s",
				len(findings), plural(len(findings)), strings.Join(findings, "; "))
		}
		return StatusPass, fmt.Sprintf("%d CA key%s satisfy the FIPS policy", checked, plural(checked))
	})

	// The secret layer refuses the SoftHSM SHA-1 OAEP fallback under the policy;
	// run the same wrap/unwrap negotiation the server would, per configured KEK.
	r.run("fips.secret_oaep", func() (Status, string) {
		kekLabels := map[string]string{}
		if cfg.Secret.KEKLabel != "" {
			kekLabels[cfg.Secret.KEKLabel] = "secret.kek_label"
		}
		for _, t := range cfg.Tenants {
			if t.KEKLabel != "" {
				kekLabels[t.KEKLabel] = fmt.Sprintf("tenants[%s].kek_label", t.ID)
			}
		}
		if len(kekLabels) == 0 {
			return StatusSkip, "secret layer not configured (no kek_label)"
		}
		prov := providers.get("ca")
		if prov == nil {
			return StatusSkip, "ca key provider unavailable"
		}
		overall := StatusPass
		var notes []string
		for _, label := range sortedKeys(kekLabels) {
			svc, err := secret.NewService(ctx, prov, keyprovider.KeyRef{Label: label})
			switch {
			case errors.Is(err, keyprovider.ErrKeyNotFound):
				// Not a FIPS violation — the keys check already reports missing
				// KEKs loudly; there is just nothing to negotiate against.
				overall = worse(overall, StatusWarn)
				notes = append(notes, fmt.Sprintf("%s (%s): KEK not provisioned, negotiation not probed", label, kekLabels[label]))
			case err != nil:
				overall = worse(overall, StatusFail)
				notes = append(notes, fmt.Sprintf("%s (%s): %v", label, kekLabels[label], err))
			default:
				notes = append(notes, fmt.Sprintf("%s negotiates %s", label, svc.KEKInfo().WrapAlg))
			}
		}
		return overall, strings.Join(notes, "; ")
	})
}
