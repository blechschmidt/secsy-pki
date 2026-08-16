package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
)

// SQL store for the HSM audit subsystem (Task 167).
//
// Three tables, each with a different immutability requirement:
//
//   - hsm_log_entries holds the device's own log. Entries are keyed by device
//     entry number and are never updated: the device log is immutable, so a
//     re-delivered entry that differs from the stored one means one of the two
//     copies is forged, and the write path says so instead of overwriting.
//   - hsm_signature_ledger is append-only and hash-chained, exactly like
//     event_log. Sequence and hashes are assigned inside the insert
//     transaction, so a row cannot be rewritten without breaking the chain.
//   - hsm_audit_state pins the device identity and genesis anchor. The anchor
//     is write-once by design; changing it is how a forged history would be
//     laundered, so an attempt to change it is an error.

// LoadAuditState implements hsmaudit.Store.
func (db *DB) LoadAuditState(ctx context.Context) (*hsmaudit.AuditState, error) {
	var st hsmaudit.AuditState
	var tailNumber sql.NullInt64
	var tailDigest sql.NullString
	err := db.queryRow(
		`SELECT device_serial, anchor, provisioned_at, tail_number, tail_digest FROM hsm_audit_state WHERE id = 1`).
		Scan(&st.DeviceSerial, &st.Anchor, &st.ProvisionedAt, &tailNumber, &tailDigest)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	st.Tail = hsmaudit.Tail{Number: uint16(tailNumber.Int64), Digest: tailDigest.String}
	return &st, nil
}

// SaveAuditState implements hsmaudit.Store. It refuses to change an anchor that
// is already pinned.
func (db *DB) SaveAuditState(ctx context.Context, st *hsmaudit.AuditState) error {
	if st == nil {
		return fmt.Errorf("hsm audit state: nothing to save")
	}
	existing, err := db.LoadAuditState(ctx)
	if err != nil {
		return err
	}
	if existing != nil {
		if !strings.EqualFold(existing.Anchor, st.Anchor) || !strings.EqualFold(existing.DeviceSerial, st.DeviceSerial) {
			return fmt.Errorf(
				"refusing to re-pin HSM audit state: stored device %s anchor %s, attempted device %s anchor %s. "+
					"The anchor is the root of trust for every export; replacing it would make a fabricated log verify",
				existing.DeviceSerial, existing.Anchor, st.DeviceSerial, st.Anchor)
		}
		return db.UpdateTail(ctx, st.Tail)
	}
	_, err = db.exec(
		`INSERT INTO hsm_audit_state (id, device_serial, anchor, provisioned_at, tail_number, tail_digest)
		 VALUES (1, ?, ?, ?, ?, ?)`,
		st.DeviceSerial, strings.ToLower(st.Anchor), st.ProvisionedAt.UTC(),
		int64(st.Tail.Number), strings.ToLower(st.Tail.Digest))
	return err
}

// UpdateTail implements hsmaudit.Store.
func (db *DB) UpdateTail(ctx context.Context, tail hsmaudit.Tail) error {
	_, err := db.exec(
		`UPDATE hsm_audit_state SET tail_number = ?, tail_digest = ? WHERE id = 1`,
		int64(tail.Number), strings.ToLower(tail.Digest))
	return err
}

// AppendLogEntries implements hsmaudit.Store.
//
// Storing is idempotent by device entry number so a segment that was persisted
// but not acknowledged can be re-offered safely. An entry that arrives with
// different content than the stored copy is rejected rather than merged: the
// device log cannot legitimately change, so a difference is evidence, not a
// conflict to resolve.
func (db *DB) AppendLogEntries(ctx context.Context, entries []hsm.AuditLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	sel, err := tx.Prepare(db.ph(
		`SELECT command, length, session_key, target_key, second_key, result, tick, hash
		   FROM hsm_log_entries WHERE number = ?`))
	if err != nil {
		return err
	}
	defer func() { _ = sel.Close() }()

	ins, err := tx.Prepare(db.ph(
		`INSERT INTO hsm_log_entries (number, command, length, session_key, target_key, second_key, result, tick, hash, collected_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()

	now := time.Now().UTC()
	for _, e := range entries {
		var have hsm.AuditLogEntry
		err := sel.QueryRow(int64(e.Number)).Scan(&have.Command, &have.Length, &have.SessionKey,
			&have.TargetKey, &have.SecondKey, &have.Result, &have.Tick, &have.Hash)
		switch {
		case err == sql.ErrNoRows:
			if _, err := ins.Exec(int64(e.Number), e.Command, e.Length, e.SessionKey, e.TargetKey,
				e.SecondKey, e.Result, e.Tick, strings.ToLower(e.Hash), now); err != nil {
				return fmt.Errorf("storing device log entry %d: %w", e.Number, err)
			}
		case err != nil:
			return err
		default:
			have.Number = e.Number
			if have.Hash = strings.ToLower(have.Hash); have != normalizeEntry(e) {
				return fmt.Errorf(
					"device log entry %d was already stored with different content (stored digest %s, offered %s): "+
						"the device log is immutable, so one of the two records is not genuine",
					e.Number, have.Hash, strings.ToLower(e.Hash))
			}
		}
	}
	return tx.Commit()
}

func normalizeEntry(e hsm.AuditLogEntry) hsm.AuditLogEntry {
	e.Hash = strings.ToLower(e.Hash)
	return e
}

// LogEntries implements hsmaudit.Store.
func (db *DB) LogEntries(ctx context.Context) ([]hsm.AuditLogEntry, error) {
	rows, err := db.query(
		`SELECT number, command, length, session_key, target_key, second_key, result, tick, hash
		   FROM hsm_log_entries ORDER BY number ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []hsm.AuditLogEntry
	for rows.Next() {
		var e hsm.AuditLogEntry
		if err := rows.Scan(&e.Number, &e.Command, &e.Length, &e.SessionKey, &e.TargetKey,
			&e.SecondKey, &e.Result, &e.Tick, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AppendLedger implements hsmaudit.Store, sealing e into the hash chain inside
// the insert transaction.
//
// hsmLedgerMu serializes appends for the same reason eventMu does for the event
// log: the read of the previous hash and the insert of the new row must not
// interleave, or two concurrent signatures would chain from the same
// predecessor and produce a fork that later verification reports as tampering.
// Signing is concurrent by design here (the session pool is bounded but
// parallel), so this is a live concern rather than a theoretical one.
func (db *DB) AppendLedger(ctx context.Context, e *hsmaudit.LedgerEntry) error {
	if e == nil {
		return fmt.Errorf("hsm signature ledger: nothing to append")
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	db.hsmLedgerMu.Lock()
	defer db.hsmLedgerMu.Unlock()

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var lastSeq sql.NullInt64
	var lastHash sql.NullString
	err = tx.QueryRow(db.ph(`SELECT seq, hash FROM hsm_signature_ledger ORDER BY seq DESC LIMIT 1`)).
		Scan(&lastSeq, &lastHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	prevHash := hsmaudit.LedgerGenesisHash
	nextSeq := int64(1)
	if lastSeq.Valid {
		nextSeq = lastSeq.Int64 + 1
		prevHash = lastHash.String
	}

	// Seal truncates the timestamp to microseconds before hashing, so the value
	// read back from PostgreSQL (which stores microsecond precision) is the one
	// that was hashed and the chain verifies natively on either backend.
	e.Seal(nextSeq, prevHash)

	if _, err := tx.Exec(db.ph(
		`INSERT INTO hsm_signature_ledger (seq, timestamp, key_label, key_id, digest, algorithm, purpose, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.Seq, e.Timestamp.UTC(), e.KeyLabel, int64(e.KeyID), e.Digest, e.Algorithm, e.Purpose, e.PrevHash, e.Hash,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// Ledger implements hsmaudit.Store.
func (db *DB) Ledger(ctx context.Context) ([]hsmaudit.LedgerEntry, error) {
	rows, err := db.query(
		`SELECT seq, timestamp, key_label, key_id, digest, algorithm, purpose, prev_hash, hash
		   FROM hsm_signature_ledger ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []hsmaudit.LedgerEntry
	for rows.Next() {
		var e hsmaudit.LedgerEntry
		var keyID int64
		if err := rows.Scan(&e.Seq, &e.Timestamp, &e.KeyLabel, &keyID, &e.Digest,
			&e.Algorithm, &e.Purpose, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.KeyID = uint16(keyID)
		e.Timestamp = e.Timestamp.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// AppendFreshnessProof implements hsmaudit.Store.
//
// It reuses hsmLedgerMu to serialize sequence assignment. Attestation is a
// background job with a single leader, so contention is nil, but sharing the
// mutex keeps the "read the last seq, then insert" pattern uniformly safe
// rather than relying on a caller-side singleton that a future change could
// remove without anyone noticing.
func (db *DB) AppendFreshnessProof(ctx context.Context, p *hsmaudit.FreshnessProof) error {
	if p == nil {
		return fmt.Errorf("hsm freshness proof: nothing to append")
	}
	if len(p.Token) == 0 {
		return fmt.Errorf("hsm freshness proof: refusing to store a proof with no timestamp token")
	}

	db.hsmLedgerMu.Lock()
	defer db.hsmLedgerMu.Unlock()

	var lastSeq sql.NullInt64
	err := db.queryRow(`SELECT seq FROM hsm_freshness_proofs ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	p.Seq = lastSeq.Int64 + 1

	_, err = db.exec(
		`INSERT INTO hsm_freshness_proofs
		   (seq, gen_time, obtained_at, source, device_serial, anchor, device_number, device_digest,
		    signatures, ledger_seq, ledger_hash, head_digest, token)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Seq, p.GenTime.UTC(), p.ObtainedAt.UTC(), p.Source,
		p.Head.DeviceSerial, strings.ToLower(p.Head.Anchor),
		int64(p.Head.DeviceNumber), strings.ToLower(p.Head.DeviceDigest), int64(p.Head.Signatures),
		p.Head.LedgerSeq, strings.ToLower(p.Head.LedgerHash),
		strings.ToLower(p.HeadDigest), p.Token)
	return err
}

// FreshnessProofs implements hsmaudit.Store.
func (db *DB) FreshnessProofs(ctx context.Context) ([]hsmaudit.FreshnessProof, error) {
	rows, err := db.query(
		`SELECT seq, gen_time, obtained_at, source, device_serial, anchor, device_number, device_digest,
		        signatures, ledger_seq, ledger_hash, head_digest, token
		   FROM hsm_freshness_proofs ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []hsmaudit.FreshnessProof
	for rows.Next() {
		var p hsmaudit.FreshnessProof
		var deviceNumber, signatures int64
		if err := rows.Scan(&p.Seq, &p.GenTime, &p.ObtainedAt, &p.Source,
			&p.Head.DeviceSerial, &p.Head.Anchor, &deviceNumber, &p.Head.DeviceDigest,
			&signatures, &p.Head.LedgerSeq, &p.Head.LedgerHash, &p.HeadDigest, &p.Token); err != nil {
			return nil, err
		}
		p.Head.DeviceNumber = uint16(deviceNumber)
		p.Head.Signatures = int(signatures)
		p.GenTime = p.GenTime.UTC()
		p.ObtainedAt = p.ObtainedAt.UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// Compile-time check that *DB satisfies the audit subsystem's store contract.
var _ hsmaudit.Store = (*DB)(nil)
