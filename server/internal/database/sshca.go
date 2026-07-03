package database

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// RecordSSHCertificate stores the authority's copy of an OpenSSH certificate it
// has signed (Task 57).
func (db *DB) RecordSSHCertificate(c *models.SSHCertificate) error {
	tenantID := c.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	status := c.Status
	if status == "" {
		status = models.CertStatusValid
	}
	_, err := db.exec(
		`INSERT INTO ssh_certificates
			(ca_id, serial, tenant_id, cert_type, key_id, principals, profile,
			 public_key_fingerprint, certificate, valid_after, valid_before, status, issued_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CAID, c.Serial, tenantID, c.CertType, c.KeyID, strings.Join(c.Principals, ","),
		c.Profile, c.PublicKeyFingerprint, c.Certificate, c.ValidAfter, c.ValidBefore,
		string(status), c.IssuedBy,
	)
	return err
}

// sshCertColumns is the canonical column list for SSH-certificate reads.
const sshCertColumns = `ca_id, serial, tenant_id, cert_type, key_id, principals,
	profile, public_key_fingerprint, certificate, valid_after, valid_before,
	status, issued_by, created_at`

func scanSSHCert(s caScanner) (*models.SSHCertificate, error) {
	var c models.SSHCertificate
	var tenantID, principals, status sql.NullString
	if err := s.Scan(
		&c.CAID, &c.Serial, &tenantID, &c.CertType, &c.KeyID, &principals,
		&c.Profile, &c.PublicKeyFingerprint, &c.Certificate, &c.ValidAfter,
		&c.ValidBefore, &status, &c.IssuedBy, &c.CreatedAt,
	); err != nil {
		return nil, err
	}
	if tenantID.Valid && tenantID.String != "" {
		c.TenantID = tenantID.String
	} else {
		c.TenantID = models.DefaultTenantID
	}
	if principals.Valid && principals.String != "" {
		c.Principals = strings.Split(principals.String, ",")
	}
	c.Status = models.CertStatus(status.String)
	return &c, nil
}

// GetSSHCertificate looks up a signed SSH certificate by (CA, serial). Returns
// (nil, nil) if none matches.
func (db *DB) GetSSHCertificate(caID, serial string) (*models.SSHCertificate, error) {
	c, err := scanSSHCert(db.queryRow(
		`SELECT `+sshCertColumns+` FROM ssh_certificates WHERE ca_id = ? AND serial = ?`,
		caID, serial))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

// ListSSHCertificates returns all SSH certificates signed by a CA, newest first.
func (db *DB) ListSSHCertificates(caID string) ([]models.SSHCertificate, error) {
	rows, err := db.query(
		`SELECT `+sshCertColumns+` FROM ssh_certificates WHERE ca_id = ? ORDER BY created_at DESC, serial DESC`,
		caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SSHCertificate
	for rows.Next() {
		c, err := scanSSHCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// RevokeSSHCertificate records an SSH revocation — by certificate serial or by
// key ID, per rev.Serial/rev.KeyID. It is atomic and idempotent: re-revoking an
// existing target updates its reason/time. The authoritative ssh_revocations row
// is always written; matching ssh_certificates rows (by serial, or every
// certificate bearing the key ID) are flipped to revoked.
//
// It returns whether the revocation is newly effective (false if the target was
// already revoked).
func (db *DB) RevokeSSHCertificate(rev *models.SSHRevocation) (bool, error) {
	if (rev.Serial == "") == (rev.KeyID == "") {
		return false, fmt.Errorf("ssh revocation must target exactly one of serial or key_id")
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var existing int
	err = tx.QueryRow(db.ph(
		`SELECT COUNT(*) FROM ssh_revocations WHERE ca_id = ? AND serial = ? AND key_id = ?`),
		rev.CAID, rev.Serial, rev.KeyID).Scan(&existing)
	if err != nil {
		return false, err
	}

	if existing == 0 {
		if _, err := tx.Exec(db.ph(
			`INSERT INTO ssh_revocations (ca_id, serial, key_id, reason, revoked_by, revoked_at)
			 VALUES (?, ?, ?, ?, ?, ?)`),
			rev.CAID, rev.Serial, rev.KeyID, rev.Reason, rev.RevokedBy, rev.RevokedAt); err != nil {
			return false, err
		}
	} else {
		if _, err := tx.Exec(db.ph(
			`UPDATE ssh_revocations SET reason = ?, revoked_by = ?, revoked_at = ?
			 WHERE ca_id = ? AND serial = ? AND key_id = ?`),
			rev.Reason, rev.RevokedBy, rev.RevokedAt, rev.CAID, rev.Serial, rev.KeyID); err != nil {
			return false, err
		}
	}

	// Reflect the revocation on the certificate inventory.
	if rev.Serial != "" {
		_, err = tx.Exec(db.ph(
			`UPDATE ssh_certificates SET status = ? WHERE ca_id = ? AND serial = ?`),
			string(models.CertStatusRevoked), rev.CAID, rev.Serial)
	} else {
		_, err = tx.Exec(db.ph(
			`UPDATE ssh_certificates SET status = ? WHERE ca_id = ? AND key_id = ?`),
			string(models.CertStatusRevoked), rev.CAID, rev.KeyID)
	}
	if err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return existing == 0, nil
}

// GetSSHRevocationBySerial returns the serial-targeted revocation for
// (CA, serial), or (nil, nil) if that serial is not revoked. Key-ID revocations
// are not consulted; use ListSSHRevocations for the full picture.
func (db *DB) GetSSHRevocationBySerial(caID, serial string) (*models.SSHRevocation, error) {
	rev, err := scanSSHRevocation(db.queryRow(
		`SELECT ca_id, serial, key_id, reason, revoked_by, revoked_at
		 FROM ssh_revocations WHERE ca_id = ? AND serial = ? AND key_id = ''`,
		caID, serial))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return rev, err
}

func scanSSHRevocation(s caScanner) (*models.SSHRevocation, error) {
	var rev models.SSHRevocation
	if err := s.Scan(&rev.CAID, &rev.Serial, &rev.KeyID, &rev.Reason, &rev.RevokedBy, &rev.RevokedAt); err != nil {
		return nil, err
	}
	return &rev, nil
}

// ListSSHRevocations returns every SSH revocation recorded for a CA, oldest
// first. This is the input to KRL generation.
func (db *DB) ListSSHRevocations(caID string) ([]models.SSHRevocation, error) {
	rows, err := db.query(
		`SELECT ca_id, serial, key_id, reason, revoked_by, revoked_at
		 FROM ssh_revocations WHERE ca_id = ? ORDER BY revoked_at, serial, key_id`,
		caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SSHRevocation
	for rows.Next() {
		rev, err := scanSSHRevocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rev)
	}
	return out, rows.Err()
}

// CountSSHRevocations returns the number of SSH revocations recorded for a CA.
// Revocations are only ever added, so this doubles as the monotonic KRL version.
func (db *DB) CountSSHRevocations(caID string) (int64, error) {
	var n int64
	err := db.queryRow(`SELECT COUNT(*) FROM ssh_revocations WHERE ca_id = ?`, caID).Scan(&n)
	return n, err
}

// IsSSHCertificateRevoked reports whether a certificate is revoked under a CA,
// either directly by serial or through a key-ID revocation matching its key ID.
// This is the verification-time analogue of what a KRL encodes.
func (db *DB) IsSSHCertificateRevoked(caID, serial, keyID string) (bool, error) {
	var n int
	err := db.queryRow(
		`SELECT COUNT(*) FROM ssh_revocations
		 WHERE ca_id = ? AND ((serial = ? AND serial != '') OR (key_id = ? AND key_id != ''))`,
		caID, serial, keyID).Scan(&n)
	return n > 0, err
}
