package ca

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// SuspendCertificate places a certificate on hold (RFC 5280 certificateHold,
// reason 6) — a reversible revocation, distinct from the permanent revocation
// performed by RevokeCertificate. While held the certificate is reported revoked
// by OCSP (reason certificateHold) and appears on the base CRL; the hold can be
// removed later with ReleaseCertificate.
//
// It returns whether the hold was newly applied (false if the serial was already
// on hold). Suspending a serial already permanently revoked is refused.
func (m *Manager) SuspendCertificate(ctx context.Context, caID, serial string) (bool, error) {
	if _, _, err := m.loadIssuer(caID); err != nil {
		return false, err
	}
	if _, ok := new(big.Int).SetString(serial, 10); !ok {
		return false, fmt.Errorf("serial %q is not a valid decimal integer", serial)
	}
	applied, err := m.db.SuspendCertificate(caID, serial, time.Now())
	if err == nil && applied {
		// Usage accounting only — a hold, like a revocation, is never quota-gated;
		// a suspended tenant's certificates must remain suspendable.
		m.accountTenantRevocation(caID)
	}
	return applied, err
}

// ReleaseCertificate removes a certificate hold, returning the certificate to
// service: OCSP reports it good again, the next base CRL omits it, and the next
// delta CRL carries a removeFromCRL (reason 8) entry so relying parties holding a
// base CRL that still lists the hold drop the serial (RFC 5280 §5.2.4).
//
// Release succeeds only for a certificate that is on hold. A permanently revoked
// certificate (any reason other than certificateHold) cannot be released:
// database.ErrNotOnHold is returned. A serial with no revocation record returns
// database.ErrNotRevoked. Both are surfaced verbatim so callers can map them to
// the right protocol status.
func (m *Manager) ReleaseCertificate(ctx context.Context, caID, serial string) error {
	if _, _, err := m.loadIssuer(caID); err != nil {
		return err
	}
	if _, ok := new(big.Int).SetString(serial, 10); !ok {
		return fmt.Errorf("serial %q is not a valid decimal integer", serial)
	}
	return m.db.ReleaseHold(caID, serial, time.Now())
}

// Re-exported release sentinels so callers can classify a ReleaseCertificate
// failure (permanent revocation vs. no revocation record) without importing the
// database package directly.
var (
	// ErrNotOnHold indicates a release was attempted on a certificate revoked for
	// a permanent reason. RFC 5280: a permanent revocation is irreversible.
	ErrNotOnHold = database.ErrNotOnHold
	// ErrNotRevoked indicates a release was attempted on a certificate that is not
	// revoked at all.
	ErrNotRevoked = database.ErrNotRevoked
)
