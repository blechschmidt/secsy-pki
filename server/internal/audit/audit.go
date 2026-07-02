// Package audit provides a tamper-evident, append-only event log for all
// security-sensitive operations (key generation, CA setup, certificate
// issuance/renewal/revocation, secret encryption/decryption, and access-control
// changes).
//
// Each event records who did what, when, against which target, and with what
// result. Events are linked into a hash chain: every entry stores the SHA-256
// hash of its canonical serialization concatenated with the previous entry's
// hash. Altering, reordering, or deleting any historical entry breaks the chain
// from that point forward, which VerifyChain detects. This gives append-only
// integrity without depending on the underlying store being immutable.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenesisHash is the synthetic "previous hash" of the very first event. Using a
// fixed, well-known value anchors the chain so the first entry is covered by the
// same hashing rule as every subsequent one.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Result classifies the outcome of an audited operation.
const (
	ResultSuccess = "success"
	ResultDenied  = "denied" // authorization was refused
	ResultError   = "error"  // the operation was authorized but failed
)

// Common action identifiers. Handlers may use any string, but sharing these
// constants keeps the log queryable and consistent.
const (
	ActionCACreate            = "ca.create"
	ActionCAInitRoot          = "ca.init_root"
	ActionCAIssueIntermediate = "ca.issue_intermediate"
	ActionCADelete            = "ca.delete"
	// Tenant lifecycle (Task 43). These are platform-level events (no owning
	// tenant of their own beyond the one they mutate).
	ActionTenantCreate = "tenant.create"
	ActionTenantUpdate = "tenant.update"
	ActionTenantDelete = "tenant.delete"
	ActionCertIssue    = "cert.issue"
	ActionCertRenew    = "cert.renew"
	ActionCertRevoke   = "cert.revoke"
	// ActionSVIDIssue records the minting of a SPIFFE X.509-SVID. The detail
	// carries the spiffe:// identity, trust domain, and profile.
	ActionSVIDIssue = "svid.issue"
	// ActionCRLPublish records the HSM-signed generation of a base or delta CRL
	// for a CA scope (full or a partition shard). The detail carries the scope,
	// kind, CRL number, and entry count.
	ActionCRLPublish = "crl.publish"
	// ActionCertLint records the outcome of the pre-issuance lint gate when it
	// produces findings: ResultError when an enforce-mode check blocked signing
	// (fail-closed), ResultSuccess when only warnings were emitted.
	ActionCertLint = "cert.lint"
	// ActionCertCAA records the outcome of the pre-issuance CAA gate (RFC 8659)
	// when it produces findings: ResultError when an enforce-mode check blocked
	// issuance (fail-closed), ResultSuccess when a permissive-mode check reported
	// a forbidding record without blocking.
	ActionCertCAA = "cert.caa"
	// ActionCertNameConstraint records the pre-issuance Name Constraints gate (RFC
	// 5280 §4.2.1.10) blocking a leaf whose subject or SAN falls outside the
	// issuing CA's permitted subtrees or inside an excluded subtree (fail-closed).
	ActionCertNameConstraint = "cert.nameconstraint"
	// ActionCertAutoRenew records a certificate reissued automatically by the
	// expiry monitor (actor "monitor"), ahead of its expiry.
	ActionCertAutoRenew = "cert.auto_renew"
	// ActionCertExpiryScan records a completed expiry-monitor scan cycle.
	ActionCertExpiryScan = "cert.expiry_scan"
	ActionCertSignSSH    = "cert.sign_ssh"
	ActionCertSignX509   = "cert.sign_x509"
	ActionSecretEncrypt  = "secret.encrypt"
	ActionSecretDecrypt  = "secret.decrypt"
	// ActionSecretEscrow records that a secret was sealed with an M-of-N key
	// escrow (the DEK Shamir-split across recovery agents). The target is the KEK
	// label; the detail records the threshold, agent count, and agent IDs.
	ActionSecretEscrow = "secret.escrow"
	// ActionSecretRecover records an escrow recovery ceremony: reconstructing a
	// data key from a quorum of recovery agents and decrypting the secret. The
	// detail records the participating agent IDs and the threshold met. Recovery
	// is a privileged, dual-control break-glass operation, logged distinctly from
	// routine secret.decrypt so it stands out in the audit trail.
	ActionSecretRecover     = "secret.recover"
	ActionPermissionGrant   = "permission.grant"
	ActionPermissionRevoke  = "permission.revoke"
	ActionGroupCreate       = "group.create"
	ActionGroupDelete       = "group.delete"
	ActionHSMProvisionAudit = "hsm.provision_audit"
	ActionHSMFactoryReset   = "hsm.factory_reset"
	// Key-ceremony, backup, and disaster-recovery lifecycle operations. A
	// ceremony records its start, each operator's M-of-N confirmation, and its
	// completion (or abort) alongside the underlying ca.init_root /
	// ca.issue_intermediate events. Backup/restore record DR bundle creation and
	// verification. None of these ever handle private key material.
	ActionCeremonyStart           = "ceremony.start"
	ActionCeremonyOperatorConfirm = "ceremony.operator_confirm"
	ActionCeremonyComplete        = "ceremony.complete"
	ActionCeremonyAbort           = "ceremony.abort"
	ActionHSMBackup               = "hsm.backup"
	ActionHSMRestore              = "hsm.restore"
	// Intermediate-CA key rotation / rollover (Task 24). Rotate records a new key
	// being cross-signed under the parent and the old key entering the overlap
	// window; Retire records the old key being revoked under its parent after the
	// overlap drains. No private key material is ever handled.
	ActionCARotate = "ca.rotate"
	ActionCARetire = "ca.retire"
	// ActionCACrossSign records an issuer CA cross-signing a subject public key
	// (Task 47): a second certificate for the same subordinate key, enabling
	// bridge-CA and root-transition alternate chains. No private key material is
	// handled; the subject key is certified, not imported.
	ActionCACrossSign = "ca.cross_sign"
	// ACME (RFC 8555) protocol operations. The actor for these is the ACME
	// account ("acme:<account-id>") rather than an OIDC/root principal, since
	// ACME clients authenticate with their own account keys.
	ActionACMEAccountNew    = "acme.account.new"
	ActionACMEOrderNew      = "acme.order.new"
	ActionACMEOrderFinalize = "acme.order.finalize"
	ActionACMEChallenge     = "acme.challenge"
	ActionACMECertRevoke    = "acme.cert.revoke"
	// ActionACMERenewalInfo records a served ARI (draft-ietf-acme-ari) renewal-info
	// lookup, and ActionACMEOrderReplaces records a newOrder that linked to a
	// predecessor certificate via the "replaces" field.
	ActionACMERenewalInfo   = "acme.renewal_info"
	ActionACMEOrderReplaces = "acme.order.replaces"

	// SCEP (RFC 8894) and EST (RFC 7030) device-enrollment actions. The actor is
	// the enrollment grant / authenticated principal rather than an OIDC subject,
	// since these protocols authenticate with a challenge password, HTTP Basic, or
	// a TLS client certificate.
	ActionSCEPGetCACert   = "scep.get_ca_cert"
	ActionSCEPEnroll      = "scep.enroll"
	ActionSCEPRenew       = "scep.renew"
	ActionESTCACerts      = "est.cacerts"
	ActionESTEnroll       = "est.simpleenroll"
	ActionESTReenroll     = "est.simplereenroll"
	ActionESTServerKeyGen = "est.serverkeygen"

	// RFC 3161 Time-Stamp Authority. A timestamp is issued anonymously (the
	// public /tsa endpoint), so the actor is a fixed pseudo-principal and the
	// target is the issued token serial.
	ActionTSATimestamp = "tsa.timestamp"

	// Lightweight CMP (RFC 9483) certificate-management actions. The actor is the
	// shared-secret reference value (PBM) or the subject of the signing
	// certificate, since CMP authenticates with its own message protection rather
	// than an OIDC subject.
	ActionCMPInitialization = "cmp.ir"
	ActionCMPCertification  = "cmp.cr"
	ActionCMPKeyUpdate      = "cmp.kur"
	ActionCMPRevocation     = "cmp.rr"
)

// Event is a single entry in the tamper-evident audit log. Seq is a
// monotonically increasing sequence number assigned by the store; PrevHash and
// Hash form the tamper-evidence chain and are populated by Seal.
type Event struct {
	Seq        int64     `json:"seq"`
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"` // authenticated subject (OIDC sub or "root")
	ActorName  string    `json:"actor_name,omitempty"`
	ActorRoles string    `json:"actor_roles,omitempty"` // roles held at the time of the action
	Action     string    `json:"action"`                // e.g. "cert.issue"
	// Tenant is the owning tenant of the acted-on resource (empty for
	// platform-level events not scoped to any tenant). It is bound into the hash
	// chain (see canonicalBytes) so an event cannot be silently re-attributed to a
	// different tenant, and the listing API filters on it so one tenant's auditors
	// never see another tenant's trail.
	Tenant     string `json:"tenant,omitempty"`
	Target     string `json:"target,omitempty"`      // stable id of the object acted on (CA id, serial)
	TargetName string `json:"target_name,omitempty"` // human label (CA label, common name)
	Result     string `json:"result"`                // ResultSuccess | ResultDenied | ResultError
	Detail     string `json:"detail,omitempty"`
	IP         string `json:"ip,omitempty"`
	// RequestID correlates this event with the structured request log line for
	// the HTTP request that produced it. It is contextual metadata and is
	// deliberately NOT part of the hash-chain canonicalization (see
	// canonicalBytes): it does not affect tamper-evidence, and excluding it keeps
	// the chain hashing rule stable and backward-compatible with logs written
	// before this field existed.
	RequestID string `json:"request_id,omitempty"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// canonicalBytes produces a deterministic, unambiguous serialization of the
// event's content bound to prevHash. Every field is length-prefixed so that no
// combination of field values can be rearranged to collide with another
// event (e.g. actor="ab", action="c" must not hash-equal actor="a", action="bc").
func canonicalBytes(e *Event, prevHash string) []byte {
	var b bytes.Buffer
	writeField := func(s string) {
		var lenbuf [4]byte
		binary.BigEndian.PutUint32(lenbuf[:], uint32(len(s)))
		b.Write(lenbuf[:])
		b.WriteString(s)
	}
	var seqbuf [8]byte
	binary.BigEndian.PutUint64(seqbuf[:], uint64(e.Seq))
	b.Write(seqbuf[:])
	writeField(prevHash)
	writeField(e.ID)
	// RFC3339Nano in UTC is a stable, round-trippable timestamp encoding.
	writeField(e.Timestamp.UTC().Format(time.RFC3339Nano))
	writeField(e.Actor)
	writeField(e.ActorName)
	writeField(e.ActorRoles)
	writeField(e.Action)
	writeField(e.Target)
	writeField(e.TargetName)
	writeField(e.Result)
	writeField(e.Detail)
	writeField(e.IP)
	// Tenant is appended conditionally: events written before multi-tenancy (and
	// platform-level events with no tenant) have an empty Tenant and hash exactly
	// as before, keeping historical chains verifiable. A tenant-scoped event binds
	// its tenant into the chain under a domain-separating "tenant" tag so it cannot
	// be re-attributed to another tenant without breaking verification.
	if e.Tenant != "" {
		writeField("tenant")
		writeField(e.Tenant)
	}
	return b.Bytes()
}

// ComputeHash returns the chain hash for an event given the previous entry's
// hash. It is deterministic and depends on every content field plus prevHash.
func ComputeHash(e *Event, prevHash string) string {
	sum := sha256.Sum256(canonicalBytes(e, prevHash))
	return hex.EncodeToString(sum[:])
}

// Seal assigns the sequence number, links the event to prevHash, and computes
// its hash. The store calls this inside the same critical section that reads the
// previous hash and inserts the row, so the chain stays consistent under
// concurrency.
func Seal(e *Event, seq int64, prevHash string) {
	if prevHash == "" {
		prevHash = GenesisHash
	}
	e.Seq = seq
	e.PrevHash = prevHash
	e.Hash = ComputeHash(e, prevHash)
}

// VerifyResult reports the outcome of verifying a chain.
type VerifyResult struct {
	Valid       bool   `json:"valid"`
	Count       int    `json:"count"`
	BrokenAtSeq int64  `json:"broken_at_seq,omitempty"` // sequence number of the first bad entry
	Reason      string `json:"reason,omitempty"`
}

// VerifyFullChain verifies a COMPLETE log (from the genesis entry onward). In
// addition to the checks in VerifyChain it requires the first entry to be the
// genesis (Seq == 1 with PrevHash == GenesisHash). This additionally detects
// head deletion and whole-log re-genesis, which VerifyChain (which tolerates a
// tail slice starting at an arbitrary Seq) cannot. Callers verifying the entire
// stored log should use this.
//
// Note: neither function can detect truncation of the newest entries without an
// externally anchored head checkpoint. Deployments needing that guarantee
// should periodically anchor the current (seq, hash) out-of-band — the
// HSM-signed audit log provides exactly such an Ed25519-signed anchor.
func VerifyFullChain(events []Event) VerifyResult {
	if len(events) > 0 {
		first := events[0]
		if first.Seq != 1 || !strings.EqualFold(first.PrevHash, GenesisHash) {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: first.Seq,
				Reason: "log does not start at the genesis entry (seq 1); head entries may have been deleted"}
		}
	}
	return VerifyChain(events)
}

// VerifyChain recomputes the hash chain over events (which must be ordered by
// ascending Seq) and reports the first inconsistency, if any. It detects
// content tampering, hash forgery, broken back-links, and reordering/deletion
// (via non-contiguous sequence numbers).
func VerifyChain(events []Event) VerifyResult {
	prevHash := GenesisHash
	var prevSeq int64
	for i := range events {
		e := &events[i]

		// Sequence numbers must be strictly increasing and, for a complete log
		// starting at the genesis, contiguous — a gap means an entry was
		// removed. We allow the first observed Seq to be any value so a caller
		// can verify a tail slice, but within the slice they must be contiguous.
		if i > 0 && e.Seq != prevSeq+1 {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: e.Seq,
				Reason: fmt.Sprintf("non-contiguous sequence: expected %d, got %d", prevSeq+1, e.Seq)}
		}
		// The recorded back-link must match the running hash.
		if i > 0 && e.PrevHash != prevHash {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: e.Seq,
				Reason: "prev_hash does not match preceding entry"}
		}
		want := ComputeHash(e, e.PrevHash)
		if !strings.EqualFold(want, e.Hash) {
			return VerifyResult{Valid: false, Count: len(events), BrokenAtSeq: e.Seq,
				Reason: "content hash mismatch (entry was modified)"}
		}
		prevHash = e.Hash
		prevSeq = e.Seq
	}
	return VerifyResult{Valid: true, Count: len(events)}
}
