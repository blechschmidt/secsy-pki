package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// reasonCertificateHold is the RFC 5280 §5.3.1 CRL reason code (6) for a
// reversible certificate hold. It is duplicated here (rather than imported from
// internal/pki) to keep the database package dependency-free of the PKI encoding
// layer; the value is fixed by the standard.
const reasonCertificateHold = 6

// ErrNotRevoked is returned by ReleaseHold when the serial has no active
// revocation record — there is nothing to release.
var ErrNotRevoked = errors.New("certificate is not revoked")

// ErrNotOnHold is returned by ReleaseHold when the serial is revoked for a
// permanent reason (anything other than certificateHold). A permanent
// revocation — key compromise, cessation of operation, etc. — is irreversible
// and must never be silently un-revoked.
var ErrNotOnHold = errors.New("certificate is not on hold (revoked for a permanent reason); it cannot be released")

// SuspendCertificate places a certificate on hold (RFC 5280 certificateHold,
// reason 6). Unlike RevokeCertificate the state is reversible via ReleaseHold.
//
// It is atomic and idempotent: suspending an already-held serial refreshes its
// hold time and reports "not newly held". Suspending a serial that is already
// permanently revoked (any non-hold reason) is refused with ErrAlreadyPermanent
// — a withdrawn credential must not be downgraded to a reversible hold. Any
// stale released-hold marker for the serial is cleared so a re-suspended serial
// cannot both be held and carry a pending removeFromCRL delta entry.
//
// It returns whether the hold is newly effective (false if the serial was
// already on hold).
func (db *DB) SuspendCertificate(caID, serial string, when time.Time) (bool, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	// Conflict-tolerant insert of a fresh hold first (not check-then-insert), so
	// two concurrent suspends of the same serial resolve to one "newly held"
	// outcome instead of a primary-key violation on PostgreSQL — the same race
	// RevokeCertificate guards against.
	res, err := tx.Exec(db.insertOrIgnore("revoked_certificates", "ca_id, serial, revoked_at, reason", "?, ?, ?, ?"),
		caID, serial, when, reasonCertificateHold)
	if err != nil {
		return false, err
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	newly := inserted == 1
	if inserted == 0 {
		// A revocation row already exists: either a prior hold (idempotent refresh)
		// or a permanent revocation (which must not be downgraded to a hold). Lock
		// it for the read so a concurrent revoke/release cannot interleave.
		var existing int
		if err := tx.QueryRow(db.ph(`SELECT reason FROM revoked_certificates WHERE ca_id = ? AND serial = ?`+db.forUpdate()),
			caID, serial).Scan(&existing); err != nil {
			return false, err
		}
		if existing != reasonCertificateHold {
			return false, fmt.Errorf("serial %s is already revoked with reason %d; a permanent revocation cannot be converted to a hold", serial, existing)
		}
		if _, err := tx.Exec(db.ph(
			`UPDATE revoked_certificates SET revoked_at = ? WHERE ca_id = ? AND serial = ?`),
			when, caID, serial); err != nil {
			return false, err
		}
	}

	// Clear any prior release marker: the serial is on hold again, so no
	// removeFromCRL delta entry must be produced for it.
	if _, err := tx.Exec(db.ph(`DELETE FROM released_holds WHERE ca_id = ? AND serial = ?`),
		caID, serial); err != nil {
		return false, err
	}

	// Reflect the hold on the issued-certificate bookkeeping row (if any).
	if _, err := tx.Exec(db.ph(
		`UPDATE issued_certificates SET status = ?, revoked_at = ?, revocation_reason = ?
		 WHERE ca_id = ? AND serial = ?`),
		string(models.CertStatusHeld), when, reasonCertificateHold, caID, serial); err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return newly, nil
}

// ReleaseHold removes a certificate hold, returning the certificate to service.
// It succeeds only when the existing revocation reason is certificateHold:
//   - no revocation record  -> ErrNotRevoked
//   - a permanent reason    -> ErrNotOnHold
//
// On success the authoritative revocation row is deleted (so OCSP reports the
// serial good again and the next base CRL omits it) and a released_holds record
// is written so delta CRL generation can emit the removeFromCRL entry (RFC 5280
// §5.2.4). The issued-certificate bookkeeping row (if any) is returned to
// "valid". The operation is atomic; the revocation row is locked for the check
// so a concurrent revoke/release cannot interleave.
func (db *DB) ReleaseHold(caID, serial string, when time.Time) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var reason int
	var heldAt time.Time
	err = tx.QueryRow(db.ph(
		`SELECT reason, revoked_at FROM revoked_certificates WHERE ca_id = ? AND serial = ?`+db.forUpdate()),
		caID, serial).Scan(&reason, &heldAt)
	switch {
	case err == sql.ErrNoRows:
		return ErrNotRevoked
	case err != nil:
		return err
	case reason != reasonCertificateHold:
		return ErrNotOnHold
	}

	if _, err := tx.Exec(db.ph(`DELETE FROM revoked_certificates WHERE ca_id = ? AND serial = ?`),
		caID, serial); err != nil {
		return err
	}

	// Record the release so a delta CRL can carry removeFromCRL until a base CRL
	// cut after the release drops the serial for good. A hold always clears any
	// prior marker (see SuspendCertificate), so no row exists here; the defensive
	// delete keeps the write idempotent against any unexpected residue.
	if _, err := tx.Exec(db.ph(`DELETE FROM released_holds WHERE ca_id = ? AND serial = ?`),
		caID, serial); err != nil {
		return err
	}
	if _, err := tx.Exec(db.ph(
		`INSERT INTO released_holds (ca_id, serial, reason, held_at, released_at) VALUES (?, ?, ?, ?, ?)`),
		caID, serial, reason, heldAt, when); err != nil {
		return err
	}

	if _, err := tx.Exec(db.ph(
		`UPDATE issued_certificates SET status = ?, revoked_at = NULL, revocation_reason = 0
		 WHERE ca_id = ? AND serial = ?`),
		string(models.CertStatusValid), caID, serial); err != nil {
		return err
	}

	return tx.Commit()
}

// ListReleasedHolds returns every released-hold record for a CA, oldest release
// first. It is the input to the removeFromCRL entries of delta CRL generation.
func (db *DB) ListReleasedHolds(caID string) ([]models.ReleasedHold, error) {
	rows, err := db.query(
		`SELECT ca_id, serial, reason, held_at, released_at FROM released_holds WHERE ca_id = ? ORDER BY released_at`,
		caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ReleasedHold
	for rows.Next() {
		var rh models.ReleasedHold
		if err := rows.Scan(&rh.CAID, &rh.Serial, &rh.Reason, &rh.HeldAt, &rh.ReleasedAt); err != nil {
			return nil, err
		}
		out = append(out, rh)
	}
	return out, rows.Err()
}
