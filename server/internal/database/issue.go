package database

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// RecordIssuedCertificate stores the authority's copy of an end-entity
// certificate it has issued.
func (db *DB) RecordIssuedCertificate(c *models.IssuedCertificate) error {
	sans, _ := json.Marshal(c.SANs)
	status := c.Status
	if status == "" {
		status = models.CertStatusValid
	}
	_, err := db.exec(
		`INSERT INTO issued_certificates
			(id, ca_id, serial, subject, common_name, sans, profile, certificate,
			 not_before, not_after, status, requested_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.CAID, c.Serial, c.Subject, c.CommonName, string(sans), c.Profile,
		c.Certificate, c.NotBefore, c.NotAfter, string(status), nullString(c.RequestedBy),
	)
	return err
}

// issuedCertColumns is the canonical column list for issued-certificate reads.
const issuedCertColumns = `id, ca_id, serial, subject, common_name, sans, profile,
	certificate, not_before, not_after, status, revoked_at, revocation_reason,
	requested_by, created_at`

func scanIssuedCert(s caScanner) (*models.IssuedCertificate, error) {
	var c models.IssuedCertificate
	var subject, commonName, sans, profile, requestedBy sql.NullString
	var status string
	var notBefore, notAfter sql.NullTime
	var revokedAt sql.NullTime
	if err := s.Scan(
		&c.ID, &c.CAID, &c.Serial, &subject, &commonName, &sans, &profile,
		&c.Certificate, &notBefore, &notAfter, &status, &revokedAt, &c.RevocationReason,
		&requestedBy, &c.CreatedAt,
	); err != nil {
		return nil, err
	}
	c.Subject = subject.String
	c.CommonName = commonName.String
	c.Profile = profile.String
	c.RequestedBy = requestedBy.String
	c.Status = models.CertStatus(status)
	if notBefore.Valid {
		c.NotBefore = notBefore.Time
	}
	if notAfter.Valid {
		c.NotAfter = notAfter.Time
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		c.RevokedAt = &t
	}
	if sans.Valid && sans.String != "" {
		json.Unmarshal([]byte(sans.String), &c.SANs)
	}
	return &c, nil
}

// GetIssuedCertificate looks up an issued certificate by (CA, serial). Returns
// (nil, nil) if none matches.
func (db *DB) GetIssuedCertificate(caID, serial string) (*models.IssuedCertificate, error) {
	c, err := scanIssuedCert(db.queryRow(
		`SELECT `+issuedCertColumns+` FROM issued_certificates WHERE ca_id = ? AND serial = ?`,
		caID, serial))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

// ListIssuedCertificates returns all certificates issued by a CA, newest first.
func (db *DB) ListIssuedCertificates(caID string) ([]models.IssuedCertificate, error) {
	rows, err := db.query(
		`SELECT `+issuedCertColumns+` FROM issued_certificates WHERE ca_id = ? ORDER BY created_at DESC`,
		caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.IssuedCertificate
	for rows.Next() {
		c, err := scanIssuedCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// RevokeCertificate records a revocation for (CA, serial). It is atomic and
// idempotent: revoking an already-revoked serial updates its reason/time. The
// authoritative revoked_certificates row is always written; the matching
// issued_certificates row (if any) is updated to reflect the revocation.
//
// It returns whether the revocation is newly effective (false if the serial was
// already revoked).
func (db *DB) RevokeCertificate(caID, serial string, reason int, when time.Time) (bool, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var existing int
	err = tx.QueryRow(db.ph(
		`SELECT COUNT(*) FROM revoked_certificates WHERE ca_id = ? AND serial = ?`),
		caID, serial).Scan(&existing)
	if err != nil {
		return false, err
	}

	if existing == 0 {
		if _, err := tx.Exec(db.ph(
			`INSERT INTO revoked_certificates (ca_id, serial, revoked_at, reason) VALUES (?, ?, ?, ?)`),
			caID, serial, when, reason); err != nil {
			return false, err
		}
	} else {
		if _, err := tx.Exec(db.ph(
			`UPDATE revoked_certificates SET revoked_at = ?, reason = ? WHERE ca_id = ? AND serial = ?`),
			when, reason, caID, serial); err != nil {
			return false, err
		}
	}

	if _, err := tx.Exec(db.ph(
		`UPDATE issued_certificates SET status = ?, revoked_at = ?, revocation_reason = ?
		 WHERE ca_id = ? AND serial = ?`),
		string(models.CertStatusRevoked), when, reason, caID, serial); err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return existing == 0, nil
}

// GetRevokedCertificate returns the revocation record for (CA, serial), or
// (nil, nil) if the certificate is not revoked.
func (db *DB) GetRevokedCertificate(caID, serial string) (*models.RevokedCertificate, error) {
	var rc models.RevokedCertificate
	err := db.queryRow(
		`SELECT ca_id, serial, revoked_at, reason FROM revoked_certificates WHERE ca_id = ? AND serial = ?`,
		caID, serial).Scan(&rc.CAID, &rc.Serial, &rc.RevokedAt, &rc.Reason)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rc, nil
}

// ListRevokedCertificates returns every revocation recorded for a CA. This is
// the input to CRL generation.
func (db *DB) ListRevokedCertificates(caID string) ([]models.RevokedCertificate, error) {
	rows, err := db.query(
		`SELECT ca_id, serial, revoked_at, reason FROM revoked_certificates WHERE ca_id = ? ORDER BY revoked_at`,
		caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.RevokedCertificate
	for rows.Next() {
		var rc models.RevokedCertificate
		if err := rows.Scan(&rc.CAID, &rc.Serial, &rc.RevokedAt, &rc.Reason); err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

// NextCRLNumber atomically returns the next CRL number for a CA and advances the
// counter. It tolerates CAs created before the counter table existed by seeding
// a counter on first use.
func (db *DB) NextCRLNumber(caID string) (int64, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var next int64
	err = tx.QueryRow(db.ph(`SELECT next_number FROM ca_crl_counters WHERE ca_id = ?`), caID).Scan(&next)
	if err == sql.ErrNoRows {
		next = 1
		if _, err := tx.Exec(db.ph(
			`INSERT INTO ca_crl_counters (ca_id, next_number) VALUES (?, ?)`), caID, next+1); err != nil {
			return 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return next, nil
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(db.ph(
		`UPDATE ca_crl_counters SET next_number = ? WHERE ca_id = ?`), next+1, caID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

// MarkExpiredCertificates flips still-"valid" issued certificates whose
// not_after has passed to the "expired" status. It returns the number updated.
func (db *DB) MarkExpiredCertificates(caID string, now time.Time) (int64, error) {
	res, err := db.exec(
		`UPDATE issued_certificates SET status = ? WHERE ca_id = ? AND status = ? AND not_after < ?`,
		string(models.CertStatusExpired), caID, string(models.CertStatusValid), now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
