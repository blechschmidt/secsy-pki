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
		`INSERT INTO event_log (seq, id, timestamp, actor, actor_name, actor_roles, action, target, target_name, result, detail, ip, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.Seq, e.ID, e.Timestamp.UTC(), e.Actor, nullString(e.ActorName), nullString(e.ActorRoles),
		e.Action, nullString(e.Target), nullString(e.TargetName), e.Result, nullString(e.Detail),
		nullString(e.IP), e.PrevHash, e.Hash,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// scanEvent reads one event_log row selected with eventColumns.
func scanEvent(s caScanner) (audit.Event, error) {
	var e audit.Event
	var actorName, actorRoles, target, targetName, detail, ip sql.NullString
	if err := s.Scan(
		&e.Seq, &e.ID, &e.Timestamp, &e.Actor, &actorName, &actorRoles,
		&e.Action, &target, &targetName, &e.Result, &detail, &ip, &e.PrevHash, &e.Hash,
	); err != nil {
		return audit.Event{}, err
	}
	e.ActorName = actorName.String
	e.ActorRoles = actorRoles.String
	e.Target = target.String
	e.TargetName = targetName.String
	e.Detail = detail.String
	e.IP = ip.String
	return e, nil
}

const eventColumns = `seq, id, timestamp, actor, actor_name, actor_roles, action, target, target_name, result, detail, ip, prev_hash, hash`

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

// VerifyEventChain loads the full event log and verifies its hash-chain
// integrity, returning the verification result and total entry count.
func (db *DB) VerifyEventChain() (audit.VerifyResult, error) {
	events, err := db.ListAllEventsAsc()
	if err != nil {
		return audit.VerifyResult{}, fmt.Errorf("loading event log: %w", err)
	}
	return audit.VerifyChain(events), nil
}
