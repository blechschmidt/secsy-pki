package ca

import (
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Pre-issuance weak-key and compromised-key blocklist gate (Task 120).
//
// This is the fail-closed key-quality gate required by CA/Browser Forum Baseline
// Requirements §6.1.1.3. It runs on the classical issuance path (buildLeaf) and,
// through the same pure evaluator, on the Task 113 dry-run preview, so a weak or
// known-compromised subject public key is rejected identically on every surface
// (REST/ACME/EST/SCEP/CMP/SPIFFE). It combines:
//
//   - the stateless structural checks in internal/keycheck (ROCA/CVE-2017-15361,
//     RSA exponent policy, modulus sanity, and the optional Debian weak-key
//     blocklist); with
//   - two store-backed checks this layer owns: membership in the operator-managed
//     compromised-key blocklist (blocked_keys), and — opt-in per profile — a
//     subject key already certified for a different subject.
//
// Post-quantum / hybrid profiles do not reach this gate (their ML-DSA subject keys
// take dedicated issuance paths and are not subject to ROCA / Debian-weak-key
// structure); the gate is therefore RSA-and-classical focused by construction.

// KeyCheckConfig is a profile's pre-issuance key-quality policy. The default (a
// nil *KeyCheckConfig, or an all-zero value) runs the gate in enforce mode with
// the standard structural checks and the operator compromised-key blocklist —
// the safe default for any PKI, since a weak or compromised subject key is never
// something a CA should certify.
type KeyCheckConfig struct {
	// Disabled turns the key-quality gate off for the profile. Strongly
	// discouraged: it removes the BR §6.1.1.3 weak/compromised-key safety net.
	Disabled bool `json:"disabled,omitempty"`
	// Mode is the enforcement mode: "enforce" (default, blocks issuance on any
	// finding) or "warn" (records the finding — metric + audit — but issues anyway).
	Mode string `json:"mode,omitempty"`
	// DetectDuplicates opts into duplicate/reused subject-key detection: a request
	// whose subject public key was already certified for a different subject is
	// flagged. It is off by default because a shared key across subjects is
	// occasionally legitimate (e.g. re-keying with an intentionally shared key) and
	// because it costs an indexed inventory lookup per issuance.
	DetectDuplicates bool `json:"detect_duplicates,omitempty"`
	// MinRSABits overrides the minimum RSA modulus bit length (0 = 2048 default).
	MinRSABits int `json:"min_rsa_bits,omitempty"`
}

// weakKeyBlocklist is the process-wide Debian OpenSSL / operator weak-key
// blocklist installed at startup (see SetWeakKeyBlocklist). It is set once before
// serving, so reads need no locking. Nil means no file-based blocklist is loaded
// (the structural checks and the persisted compromised-key blocklist still run).
var weakKeyBlocklist *keycheck.Blocklist

// SetWeakKeyBlocklist installs the loaded Debian/operator weak-key fingerprint
// blocklist consulted by the pre-issuance key-quality gate. Passing nil disables
// the file-based blocklist check.
func SetWeakKeyBlocklist(b *keycheck.Blocklist) { weakKeyBlocklist = b }

// keyCheckEnabled reports whether the pre-issuance key-quality gate runs for the
// profile.
func (p Profile) keyCheckEnabled() bool {
	return p.KeyChecks == nil || !p.KeyChecks.Disabled
}

// keyCheckEnforced reports whether the gate blocks issuance (enforce mode) rather
// than only recording findings (warn mode). Enforce is the default.
func (p Profile) keyCheckEnforced() bool {
	return p.KeyChecks == nil || !strings.EqualFold(strings.TrimSpace(p.KeyChecks.Mode), "warn")
}

// keyCheckEvaluation is the side-effect-free outcome of the key-quality gate: the
// findings on the candidate subject key plus how the gate would act. checkKeyQuality
// wraps it for the issuance path (adding metrics, an audit event, and the fail-
// closed error); PreviewIssuance consumes it directly.
type keyCheckEvaluation struct {
	// applicable is false when the gate is disabled for the profile or there is no
	// subject key to inspect (nothing to enforce).
	applicable bool
	// enforce is true in enforce mode (findings block), false in warn mode.
	enforce bool
	// res carries the findings (and the inspected key's fingerprint).
	res keycheck.Result
	// err is a non-nil infrastructure fault (a blocklist/inventory read failed);
	// the gate then fails closed, since it cannot prove the key is acceptable.
	err error
}

// blocked reports whether the evaluation would reject issuance: an enforce-mode
// evaluation with findings, or an infrastructure fault.
func (e keyCheckEvaluation) blocked() bool {
	return e.err != nil || (e.enforce && !e.res.OK())
}

// evaluateKeyChecks is the pure core of the pre-issuance key-quality gate: it runs
// the stateless structural checks (internal/keycheck) and the two store-backed
// checks (operator compromised-key blocklist, and — when the profile opts in —
// reused-subject-key detection) WITHOUT recording metrics or audit events. The
// store reads it performs are read-only, so PreviewIssuance can call it directly.
func (m *Manager) evaluateKeyChecks(base pki.LeafCertRequest, profile Profile) keyCheckEvaluation {
	if !profile.keyCheckEnabled() || base.PublicKey == nil {
		return keyCheckEvaluation{applicable: false}
	}
	enforce := profile.keyCheckEnforced()

	pol := keycheck.DefaultPolicy(weakKeyBlocklist)
	if profile.KeyChecks != nil && profile.KeyChecks.MinRSABits > 0 {
		pol.MinRSABits = profile.KeyChecks.MinRSABits
	}
	res := keycheck.Inspect(base.PublicKey, pol)

	// Operator-managed compromised-key blocklist (persisted). Fail closed on a read
	// error: an unavailable blocklist must not silently let a compromised key through.
	if res.Fingerprint != "" {
		blocked, err := m.db.IsKeyBlocked(res.Fingerprint)
		if err != nil {
			return keyCheckEvaluation{applicable: true, enforce: enforce, res: res,
				err: fmt.Errorf("consulting compromised-key blocklist: %w", err)}
		}
		if blocked {
			res.Add(keycheck.CodeBlockedKey, "subject public key is on the operator-managed compromised-key blocklist")
		}
	}

	// Optional duplicate / reused subject-key detection: the same key certified for
	// a different subject. A renewal (same key, same subject) is excluded because
	// the query filters on a differing subject DN.
	if res.Fingerprint != "" && profile.KeyChecks != nil && profile.KeyChecks.DetectDuplicates {
		serial := ""
		if base.Serial != nil {
			serial = base.Serial.String()
		}
		subjects, err := m.db.DistinctSubjectsForKeyFingerprint(res.Fingerprint, serial)
		if err != nil {
			return keyCheckEvaluation{applicable: true, enforce: enforce, res: res,
				err: fmt.Errorf("checking for a reused subject key: %w", err)}
		}
		current := base.Subject.String()
		for _, s := range subjects {
			if s != current {
				res.Add(keycheck.CodeDuplicateKey,
					fmt.Sprintf("subject public key is already certified for a different subject (%q)", s))
				break
			}
		}
	}
	return keyCheckEvaluation{applicable: true, enforce: enforce, res: res}
}

// checkKeyQuality is the fail-closed pre-issuance key-quality gate on the issuance
// path. It records a metric for every run and, when there are findings, an audit
// event, then returns a non-nil error (fail-closed) when an enforce-mode check
// fails so the caller aborts before the HSM signs anything. Warn mode never blocks.
func (m *Manager) checkKeyQuality(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string) error {
	ev := m.evaluateKeyChecks(base, profile)
	if !ev.applicable {
		return nil
	}
	if ev.err != nil {
		metrics.CertificateKeyChecks.Inc("fail")
		return fmt.Errorf("pre-issuance key-quality check failed for profile %q: %w", profile.Name, ev.err)
	}

	// One outcome per run, plus one per finding (by code + mode) for alerting.
	switch {
	case ev.res.OK():
		metrics.CertificateKeyChecks.Inc("pass")
	case ev.enforce:
		metrics.CertificateKeyChecks.Inc("fail")
	default:
		metrics.CertificateKeyChecks.Inc("warn")
	}
	mode := "enforce"
	if !ev.enforce {
		mode = "warn"
	}
	for _, f := range ev.res.Findings {
		metrics.CertificateKeyCheckFindings.Inc(f.Code, mode)
	}

	if !ev.res.OK() {
		m.recordKeyCheckEvent(base, profile, issuerCA, requestedBy, ev)
	}
	if ev.enforce && !ev.res.OK() {
		return fmt.Errorf("pre-issuance key-quality check failed for profile %q: %s (%s)",
			profile.Name, ev.res.Summary(), keyCheckDetail(ev.res))
	}
	return nil
}

// recordKeyCheckEvent appends a tamper-evident audit event describing a key-quality
// result with findings. A blocking (enforce) result is ResultError; a warn-only
// result is ResultSuccess.
func (m *Manager) recordKeyCheckEvent(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string, ev keyCheckEvaluation) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	result := audit.ResultSuccess
	if ev.enforce {
		result = audit.ResultError
	}
	targetName := issuerCA.Label
	if cn := base.Subject.CommonName; cn != "" {
		targetName = cn
	}
	detail := fmt.Sprintf("profile=%s mode=%s %s fingerprint=%s",
		profile.Name, keyCheckModeLabel(ev.enforce), keyCheckDetail(ev.res), ev.res.Fingerprint)
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionCertKeyCheck,
		Target:     issuerCA.ID,
		TargetName: targetName,
		Result:     result,
		Detail:     detail,
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.keycheck audit event: %v", err)
	}
}

// keyCheckDetail renders the finding codes for an audit detail / error message.
func keyCheckDetail(res keycheck.Result) string {
	if res.OK() {
		return "findings=none"
	}
	return "findings=" + strings.Join(res.Codes(), ",")
}

func keyCheckModeLabel(enforce bool) string {
	if enforce {
		return "enforce"
	}
	return "warn"
}
