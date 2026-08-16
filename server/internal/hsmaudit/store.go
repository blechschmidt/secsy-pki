package hsmaudit

import (
	"context"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// Store is the durable state the audit subsystem needs. It is an interface so
// the collector and export paths can run against an in-memory fake in unit
// tests while production uses the SQL store in internal/database.
//
// Two invariants shape the method set:
//
//   - Device log entries must be persisted *before* they are acknowledged on
//     the device, because acknowledgement is irreversible and the device is the
//     only other place they exist. Hence AppendLogEntries is separate from the
//     device's ConsumeLog and returns an error the collector must respect.
//
//   - The signature ledger is append-only and hash-chained, so AppendLedger
//     assigns the sequence number and previous hash inside the same transaction
//     that writes the row. A caller cannot supply them; that is what stops a
//     row from being rewritten after the fact.
type Store interface {
	// LoadAuditState returns the pinned device identity, chain anchor, and
	// collection tail. It returns nil when the device has never been
	// provisioned, which is the only state in which a new anchor may be pinned.
	LoadAuditState(ctx context.Context) (*AuditState, error)
	// SaveAuditState pins the device serial and genesis anchor. It must refuse
	// to overwrite an existing anchor with a different value: re-pinning is how
	// an attacker would launder a forged history, so it is a fatal error rather
	// than an update.
	SaveAuditState(ctx context.Context, st *AuditState) error
	// UpdateTail advances the recorded collection tail after a verified segment
	// has been durably appended.
	UpdateTail(ctx context.Context, tail Tail) error

	// AppendLogEntries durably stores a verified segment of device log entries.
	// Entries are keyed by device entry number; re-appending an already-stored
	// entry with identical fields is a no-op, while an entry that differs from
	// the stored one is an error (the device log is immutable, so a changed
	// record means one of the two copies was tampered with).
	AppendLogEntries(ctx context.Context, entries []hsm.AuditLogEntry) error
	// LogEntries returns every stored device log entry in ascending entry-number
	// order — the full history since the factory reset.
	LogEntries(ctx context.Context) ([]hsm.AuditLogEntry, error)

	// AppendLedger seals e into the signature-ledger hash chain and persists it,
	// assigning Seq, PrevHash, and Hash. It is called on the signing path, so it
	// must be safe under concurrency.
	AppendLedger(ctx context.Context, e *LedgerEntry) error
	// Ledger returns every ledger entry in ascending sequence order.
	Ledger(ctx context.Context) ([]LedgerEntry, error)

	// AppendFreshnessProof persists an RFC 3161 attestation over the audit head,
	// assigning Seq. Proofs are append-only but not hash-chained: each one
	// already commits to the entire history through the two chain heads it
	// carries, and its own integrity rests on the TSA's signature rather than on
	// a neighbouring row.
	AppendFreshnessProof(ctx context.Context, p *FreshnessProof) error
	// FreshnessProofs returns every proof in ascending sequence order.
	FreshnessProofs(ctx context.Context) ([]FreshnessProof, error)
}

// AuditState is the pinned, per-device root of trust for the whole subsystem.
//
// Anchor is the load-bearing field. The device seeds its log chain with a value
// that is not derived from the sentinel entry's fields — verified on hardware:
// two factory resets of the same device produced sentinels with byte-identical
// all-0xff fields but different digests (225212b1e76170fed634a755a92a389f and
// 369a47bf3d7353d627b7ce4e9c117fba). So the anchor cannot be recomputed, only
// remembered. Pinning it at provisioning time — and refusing to change it — is
// what stops an attacker from presenting an internally consistent but wholly
// invented log: without a pinned anchor they could pick any starting digest and
// hash a forged history forward from it.
type AuditState struct {
	// DeviceSerial identifies the device this state belongs to. A serial change
	// means a different device and invalidates everything else here.
	DeviceSerial string `json:"device_serial"`
	// Anchor is the device chain digest of the device-init sentinel (entry 1),
	// lowercase hex. Recorded once, at provisioning, and never changed.
	Anchor string `json:"anchor"`
	// ProvisionedAt is when the anchor was pinned.
	ProvisionedAt time.Time `json:"provisioned_at"`
	// Tail is the last durably collected entry; a new segment must continue
	// from exactly here.
	Tail Tail `json:"tail"`
}
