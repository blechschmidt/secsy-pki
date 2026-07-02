package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// AppendEvent seals e into the hash chain and persists it atomically. The
// caller supplies the content fields (actor, action, target, result, …); this
// method assigns Seq, PrevHash, Hash, and — if unset — Timestamp.
//
// Serialization: eventMu ensures only one append is in flight, and the
// read-of-last-hash + insert happen in a single transaction. Together these
// guarantee a gap-free, correctly linked chain even if the process serves
// concurrent requests (SQLite additionally caps to one connection; the mutex is
// what protects Postgres).
func (db *DB) AppendEvent(e *audit.Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	db.eventMu.Lock()
	defer db.eventMu.Unlock()

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var lastSeq sql.NullInt64
	var lastHash sql.NullString
	// Highest seq wins; its hash is the tail we chain onto.
	err = tx.QueryRow(db.ph(`SELECT seq, hash FROM event_log ORDER BY seq DESC LIMIT 1`)).Scan(&lastSeq, &lastHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	prevHash := audit.GenesisHash
	nextSeq := int64(1)
	if lastSeq.Valid {
		nextSeq = lastSeq.Int64 + 1
		prevHash = lastHash.String
	}

	audit.Seal(e, nextSeq, prevHash)

	if _, err := tx.Exec(db.ph(
		`INSERT INTO event_log (seq, id, timestamp, actor, actor_name, actor_roles, action, target, target_name, result, detail, ip, request_id, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.Seq, e.ID, e.Timestamp.UTC(), e.Actor, nullString(e.ActorName), nullString(e.ActorRoles),
		e.Action, nullString(e.Target), nullString(e.TargetName), e.Result, nullString(e.Detail),
		nullString(e.IP), nullString(e.RequestID), e.PrevHash, e.Hash,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// scanEvent reads one event_log row selected with eventColumns.
func scanEvent(s caScanner) (audit.Event, error) {
	var e audit.Event
	var actorName, actorRoles, target, targetName, detail, ip, requestID sql.NullString
	if err := s.Scan(
		&e.Seq, &e.ID, &e.Timestamp, &e.Actor, &actorName, &actorRoles,
		&e.Action, &target, &targetName, &e.Result, &detail, &ip, &requestID, &e.PrevHash, &e.Hash,
	); err != nil {
		return audit.Event{}, err
	}
	e.ActorName = actorName.String
	e.ActorRoles = actorRoles.String
	e.Target = target.String
	e.TargetName = targetName.String
	e.Detail = detail.String
	e.IP = ip.String
	e.RequestID = requestID.String
	return e, nil
}

const eventColumns = `seq, id, timestamp, actor, actor_name, actor_roles, action, target, target_name, result, detail, ip, request_id, prev_hash, hash`

// ListEvents returns a page of events in reverse-chronological order (newest
// first) for display, along with the total count. Use ListAllEventsAsc for
// integrity verification, which requires ascending order.
func (db *DB) ListEvents(action, actor string, limit, offset int) ([]audit.Event, int, error) {
	where := ""
	var args []interface{}
	add := func(clause string, v interface{}) {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += clause
		args = append(args, v)
	}
	if action != "" {
		add("action = ?", action)
	}
	if actor != "" {
		add("actor = ?", actor)
	}

	var total int
	if err := db.queryRow(`SELECT COUNT(*) FROM event_log`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT ` + eventColumns + ` FROM event_log` + where + ` ORDER BY seq DESC LIMIT ? OFFSET ?`
	rows, err := db.query(q, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []audit.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// ListAllEventsAsc returns every event ordered by ascending sequence number,
// suitable for feeding to audit.VerifyChain.
func (db *DB) ListAllEventsAsc() ([]audit.Event, error) {
	rows, err := db.query(`SELECT ` + eventColumns + ` FROM event_log ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []audit.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// ListEventsSince returns up to limit events with seq strictly greater than
// afterSeq, ordered by ascending sequence number. It is the read path for the
// SIEM exporter, which streams the log forward from its durable cursor. A limit
// <= 0 is treated as no limit (used by offline batch export).
func (db *DB) ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error) {
	q := `SELECT ` + eventColumns + ` FROM event_log WHERE seq > ? ORDER BY seq ASC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = db.query(q+` LIMIT ?`, afterSeq, limit)
	} else {
		rows, err = db.query(q, afterSeq)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []audit.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// ListEventsByTimeRange returns every event whose timestamp is in [from, to),
// ordered by ascending sequence number, for offline batch export. A zero from
// or to bound is treated as open-ended.
func (db *DB) ListEventsByTimeRange(from, to time.Time) ([]audit.Event, error) {
	q := `SELECT ` + eventColumns + ` FROM event_log`
	var args []interface{}
	where := ""
	add := func(clause string, v interface{}) {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += clause
		args = append(args, v)
	}
	if !from.IsZero() {
		add("timestamp >= ?", from.UTC())
	}
	if !to.IsZero() {
		add("timestamp < ?", to.UTC())
	}
	rows, err := db.query(q+where+` ORDER BY seq ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []audit.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// MaxEventSeq returns the highest sequence number in the event log (the head of
// the chain), or 0 when the log is empty. The SIEM exporter uses it to compute
// per-sink export lag.
func (db *DB) MaxEventSeq() (int64, error) {
	var maxSeq sql.NullInt64
	if err := db.queryRow(`SELECT MAX(seq) FROM event_log`).Scan(&maxSeq); err != nil {
		return 0, err
	}
	if !maxSeq.Valid {
		return 0, nil
	}
	return maxSeq.Int64, nil
}

// GetSIEMCursor returns the highest event sequence number durably delivered to
// the named sink, or 0 if the sink has never delivered (start from the genesis).
func (db *DB) GetSIEMCursor(sink string) (int64, error) {
	var seq int64
	err := db.queryRow(`SELECT last_seq FROM siem_export_cursor WHERE sink = ?`, sink).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// SetSIEMCursor durably advances the named sink's cursor to seq. It is called
// only after a successful delivery, so the persisted value is always a
// high-water mark of acknowledged events. The upsert is portable across SQLite
// and PostgreSQL.
func (db *DB) SetSIEMCursor(sink string, seq int64) error {
	_, err := db.exec(
		`INSERT INTO siem_export_cursor (sink, last_seq, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(sink) DO UPDATE SET last_seq = excluded.last_seq, updated_at = excluded.updated_at`,
		sink, seq, time.Now().UTC(),
	)
	return err
}

// VerifyEventChain loads the full event log and verifies its hash-chain
// integrity, returning the verification result and total entry count.
func (db *DB) VerifyEventChain() (audit.VerifyResult, error) {
	events, err := db.ListAllEventsAsc()
	if err != nil {
		return audit.VerifyResult{}, fmt.Errorf("loading event log: %w", err)
	}
	// This is the complete log, so require it to start at the genesis entry —
	// this also detects head deletion and whole-log re-genesis.
	return audit.VerifyFullChain(events), nil
}
