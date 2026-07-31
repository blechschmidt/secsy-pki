package models

import "time"

// EvidenceRecord is the persisted RFC 4998 Evidence Record row (internal/ers,
// Task 161): a long-term-preservation attestation over a set of protected data
// objects (a batch of audit-log events, or a signed artifact). The DER of the
// Evidence Record itself lives in Record; the surrounding columns are the
// metadata the renewal job and operators query without decoding the DER.
type EvidenceRecord struct {
	ID string `json:"id"`
	// Scope classifies what is protected: "audit" (a range of event_log events,
	// re-derivable from FirstSeq..LastSeq) or "artifact" (external bytes the
	// caller supplies at verify/renew time).
	Scope string `json:"scope"`
	// Description is a human label (e.g. "audit events 101-160").
	Description string `json:"description,omitempty"`
	// FirstSeq..LastSeq is the inclusive event_log sequence range covered, for
	// the "audit" scope; both 0 otherwise. The renewal job re-fetches these
	// events to re-hash the protected objects.
	FirstSeq int64 `json:"first_seq"`
	LastSeq  int64 `json:"last_seq"`
	// ObjectIDs are the stable identifiers of the covered data objects, in the
	// order supplied at generation (stored as JSON).
	ObjectIDs []string `json:"object_ids"`
	// DigestAlg is the hash algorithm of the current (newest) ArchiveTimeStamp
	// chain — the algorithm a hash-tree renewal would replace.
	DigestAlg string `json:"digest_alg"`
	// Chains is the number of ArchiveTimeStampChains (grows by one per hash-tree
	// renewal).
	Chains int `json:"chains"`
	// Record is the DER of the RFC 4998 EvidenceRecord.
	Record []byte `json:"-"`
	// CreatedAt is when the record was first generated.
	CreatedAt time.Time `json:"created_at"`
	// RenewedAt is when the record was last renewed (nil until first renewal).
	RenewedAt *time.Time `json:"renewed_at,omitempty"`
	// LastGenTime is the genTime of the newest ArchiveTimeStamp.
	LastGenTime time.Time `json:"last_gen_time"`
	// TSANotAfter is the expiry of the newest embedded TSA certificate, driving
	// time-stamp renewal (nil when the token omitted its certificate).
	TSANotAfter *time.Time `json:"tsa_not_after,omitempty"`
}
