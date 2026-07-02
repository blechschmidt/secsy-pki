package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// FullScope is the shard value denoting the unsharded, complete CRL covering all
// of a CA's certificates.
const FullScope = -1

// CRL scope kinds persisted in ca_published_crls.kind.
const (
	crlKindBase  = "base"
	crlKindDelta = "delta"
)

// Default CRL validity windows. Base CRLs are long-lived and re-served from the
// store until near expiry; delta CRLs are short-lived so relying parties pick up
// new revocations quickly.
const (
	defaultDeltaValidity = 1 * time.Hour
	// baseRegenBuffer regenerates a base CRL once it is within this of NextUpdate,
	// so a served CRL is never on the verge of expiry.
	baseRegenBuffer = 1 * time.Hour
)

// CRLDistConfig is the process-wide CRL distribution policy: how many partitions
// (shards) a CA's revocation data is split across, how the public URLs stamped
// into certificates and CRL extensions are built, and the validity windows. It
// is installed once at startup via SetCRLConfig and read without locking.
type CRLDistConfig struct {
	// Shards is the number of CRL partitions. 0 or 1 means unsharded (a single
	// complete CRL). N >= 2 splits revocations deterministically across N shard
	// CRLs by hashing the certificate serial.
	Shards int
	// BaseURL is the externally reachable origin (e.g. https://pki.example.com)
	// used to build the absolute CRLDistributionPoints / IssuingDistributionPoint
	// / Freshest CRL URLs. When empty, certificates are not stamped with CDP URLs
	// and CRLs carry no distribution-point extensions (numbering/delta still work).
	BaseURL string
	// BaseValidity bounds a base CRL (default 7 days).
	BaseValidity time.Duration
	// DeltaValidity bounds a delta CRL (default 1 hour).
	DeltaValidity time.Duration
}

// crlConfig is the installed distribution policy. Zero value = unsharded, no
// stamped CDP URLs, default validities (backward-compatible with pre-Task-36).
var crlConfig CRLDistConfig

// SetCRLConfig installs the process-wide CRL distribution policy, applying
// defaults for unset validities. Call once before serving.
func SetCRLConfig(c CRLDistConfig) {
	if c.Shards < 0 {
		c.Shards = 0
	}
	if c.BaseValidity <= 0 {
		c.BaseValidity = defaultCRLValidity
	}
	if c.DeltaValidity <= 0 {
		c.DeltaValidity = defaultDeltaValidity
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	crlConfig = c
}

// CRLShardCount returns the configured number of CRL partitions (0/1 = unsharded).
func CRLShardCount() int { return crlConfig.Shards }

// crlSharded reports whether CRL partitioning is active.
func crlSharded() bool { return crlConfig.Shards >= 2 }

// ShardForSerial returns the partition index a serial maps to, or FullScope when
// sharding is disabled. The mapping is a deterministic hash of the serial so the
// CDP stamped into a certificate at issuance always resolves to the same shard
// CRL later — independent of any database state.
func ShardForSerial(serial *big.Int) int {
	if !crlSharded() || serial == nil {
		return FullScope
	}
	sum := sha256.Sum256(serial.Bytes())
	n := binary.BigEndian.Uint64(sum[:8])
	return int(n % uint64(crlConfig.Shards))
}

// scopeKey maps a shard index to its persisted scope string.
func scopeKey(shard int) string {
	if shard < 0 {
		return "full"
	}
	return "partition:" + strconv.Itoa(shard)
}

// scopeLabel is the coarse scope label ("full"|"partition") used for metrics.
func scopeLabel(shard int) string {
	if shard < 0 {
		return "full"
	}
	return "partition"
}

// crlURL builds the public base-CRL URL for a scope. Empty when no BaseURL is
// configured.
func crlURL(caID string, shard int) string {
	if crlConfig.BaseURL == "" {
		return ""
	}
	if shard < 0 {
		return fmt.Sprintf("%s/api/ca/%s/crl", crlConfig.BaseURL, caID)
	}
	return fmt.Sprintf("%s/api/ca/%s/crl/partition/%d", crlConfig.BaseURL, caID, shard)
}

// deltaURL builds the public delta-CRL URL for a scope. Empty when no BaseURL is
// configured.
func deltaURL(caID string, shard int) string {
	u := crlURL(caID, shard)
	if u == "" {
		return ""
	}
	return u + "/delta"
}

// leafCRLDistributionPoints returns the CRLDistributionPoints to stamp into a
// leaf certificate with the given serial: the URL of the shard the serial maps
// to (or the single complete-CRL URL when unsharded). Empty when no BaseURL is
// configured, in which case no CDP is stamped.
func leafCRLDistributionPoints(caID string, serial *big.Int) []string {
	u := crlURL(caID, ShardForSerial(serial))
	if u == "" {
		return nil
	}
	return []string{u}
}

// validateShard bounds-checks a requested shard index against the configuration.
func validateShard(shard int) error {
	if shard == FullScope {
		return nil
	}
	if !crlSharded() {
		return fmt.Errorf("CRL partitioning is disabled; only the complete CRL is available")
	}
	if shard < 0 || shard >= crlConfig.Shards {
		return fmt.Errorf("shard %d out of range (0..%d)", shard, crlConfig.Shards-1)
	}
	return nil
}

// nextCRLNumber allocates the next monotonic CRL number for a scope. The
// unsharded scope keeps using the legacy per-CA counter for backward
// compatibility; partitions use their own per-scope counters.
func (m *Manager) nextCRLNumber(caID string, shard int) (int64, error) {
	if shard < 0 {
		return m.db.NextCRLNumber(caID)
	}
	return m.db.NextScopedCRLNumber(caID, scopeKey(shard))
}

// scopedRevocationEntries returns the revoked certificates that fall in a scope.
// For a partition it keeps only the serials that hash to that shard; for the
// full scope it returns all. When sinceExclusive is non-nil, only entries revoked
// strictly after it are returned (used to build delta CRLs).
func (m *Manager) scopedRevocationEntries(caID string, shard int, sinceExclusive *time.Time) ([]pki.RevokedEntry, error) {
	revoked, err := m.db.ListRevokedCertificates(caID)
	if err != nil {
		return nil, fmt.Errorf("listing revoked certificates: %w", err)
	}
	entries := make([]pki.RevokedEntry, 0, len(revoked))
	for _, rc := range revoked {
		serial, ok := new(big.Int).SetString(rc.Serial, 10)
		if !ok {
			return nil, fmt.Errorf("stored revoked serial %q is not a valid integer", rc.Serial)
		}
		if shard != FullScope && ShardForSerial(serial) != shard {
			continue
		}
		if sinceExclusive != nil && !rc.RevokedAt.After(*sinceExclusive) {
			continue
		}
		entries = append(entries, pki.RevokedEntry{
			Serial:    serial,
			RevokedAt: rc.RevokedAt,
			Reason:    rc.Reason,
		})
	}
	return entries, nil
}

// GetBaseCRL returns the DER of the base (complete) CRL for a scope, serving the
// stored copy while it is still fresh and regenerating (HSM-signing) a new one
// otherwise. shard is FullScope for the unsharded CRL or a partition index. The
// returned CRL carries a Freshest CRL extension pointing at its delta and, for a
// partition, an Issuing Distribution Point matching the covered certs' CDP.
func (m *Manager) GetBaseCRL(ctx context.Context, caID string, shard int) ([]byte, error) {
	if err := validateShard(shard); err != nil {
		return nil, err
	}
	scope := scopeKey(shard)
	existing, err := m.db.GetPublishedCRL(caID, scope, crlKindBase)
	if err != nil {
		return nil, fmt.Errorf("loading published base CRL: %w", err)
	}
	if existing != nil && time.Now().Before(existing.NextUpdate.Add(-baseRegenBuffer)) {
		return existing.DER, nil
	}
	published, err := m.regenerateBaseCRL(ctx, caID, shard)
	if err != nil {
		return nil, err
	}
	return published.DER, nil
}

// regenerateBaseCRL builds, HSM-signs, and stores a fresh base CRL for a scope.
func (m *Manager) regenerateBaseCRL(ctx context.Context, caID string, shard int) (*database.PublishedCRL, error) {
	issuerCA, issuerCert, err := m.loadIssuer(caID)
	if err != nil {
		return nil, err
	}
	genTime := time.Now()
	entries, err := m.scopedRevocationEntries(caID, shard, nil)
	if err != nil {
		return nil, err
	}
	number, err := m.nextCRLNumber(caID, shard)
	if err != nil {
		return nil, fmt.Errorf("allocating CRL number: %w", err)
	}

	req := pki.CRLRequest{
		Number:     big.NewInt(number),
		ThisUpdate: genTime.Add(-clockSkew),
		NextUpdate: genTime.Add(crlConfig.BaseValidity),
		Revoked:    entries,
	}
	if u := deltaURL(caID, shard); u != "" {
		req.FreshestCRLURLs = []string{u}
	}
	if shard != FullScope {
		if u := crlURL(caID, shard); u != "" {
			req.IDP = &pki.IssuingDistributionPoint{
				DistributionPointURLs: []string{u},
				OnlyContainsUserCerts: true,
			}
		}
	}

	der, err := m.signCRL(ctx, issuerCA, issuerCert, req)
	if err != nil {
		return nil, err
	}

	published := &database.PublishedCRL{
		CAID:        caID,
		Scope:       scopeKey(shard),
		Kind:        crlKindBase,
		Number:      number,
		BaseNumber:  number,
		ThisUpdate:  req.ThisUpdate,
		NextUpdate:  req.NextUpdate,
		GeneratedAt: genTime,
		DER:         der,
	}
	if err := m.db.UpsertPublishedCRL(published); err != nil {
		return nil, fmt.Errorf("storing base CRL: %w", err)
	}
	metrics.CRLGenerated.Inc(crlKindBase, scopeLabel(shard))
	m.recordCRLEvent(issuerCA, shard, crlKindBase, number, len(entries))
	return published, nil
}

// GetDeltaCRL returns the DER of the delta CRL for a scope, relative to the
// scope's current published base CRL. It regenerates the base first if none has
// been published yet, then serves a stored delta while it is fresh and still
// references the current base, regenerating otherwise.
func (m *Manager) GetDeltaCRL(ctx context.Context, caID string, shard int) ([]byte, error) {
	if err := validateShard(shard); err != nil {
		return nil, err
	}
	scope := scopeKey(shard)

	base, err := m.db.GetPublishedCRL(caID, scope, crlKindBase)
	if err != nil {
		return nil, fmt.Errorf("loading published base CRL: %w", err)
	}
	if base == nil {
		// A delta CRL is meaningless without a base to be relative to.
		if base, err = m.regenerateBaseCRL(ctx, caID, shard); err != nil {
			return nil, err
		}
	}

	existing, err := m.db.GetPublishedCRL(caID, scope, crlKindDelta)
	if err != nil {
		return nil, fmt.Errorf("loading published delta CRL: %w", err)
	}
	if existing != nil && existing.BaseNumber == base.Number &&
		time.Now().Before(existing.NextUpdate) {
		return existing.DER, nil
	}
	return m.regenerateDeltaCRL(ctx, caID, shard, base)
}

// regenerateDeltaCRL builds, HSM-signs, and stores a fresh delta CRL for a scope,
// carrying the Delta CRL Indicator referencing base and listing only entries
// revoked since the base was cut.
func (m *Manager) regenerateDeltaCRL(ctx context.Context, caID string, shard int, base *database.PublishedCRL) ([]byte, error) {
	issuerCA, issuerCert, err := m.loadIssuer(caID)
	if err != nil {
		return nil, err
	}
	genTime := time.Now()
	since := base.GeneratedAt
	entries, err := m.scopedRevocationEntries(caID, shard, &since)
	if err != nil {
		return nil, err
	}
	number, err := m.nextCRLNumber(caID, shard)
	if err != nil {
		return nil, fmt.Errorf("allocating CRL number: %w", err)
	}

	req := pki.CRLRequest{
		Number:        big.NewInt(number),
		ThisUpdate:    genTime.Add(-clockSkew),
		NextUpdate:    genTime.Add(crlConfig.DeltaValidity),
		Revoked:       entries,
		BaseCRLNumber: big.NewInt(base.Number),
	}
	if shard != FullScope {
		if u := crlURL(caID, shard); u != "" {
			req.IDP = &pki.IssuingDistributionPoint{
				DistributionPointURLs: []string{u},
				OnlyContainsUserCerts: true,
			}
		}
	}

	der, err := m.signCRL(ctx, issuerCA, issuerCert, req)
	if err != nil {
		return nil, err
	}

	published := &database.PublishedCRL{
		CAID:        caID,
		Scope:       scopeKey(shard),
		Kind:        crlKindDelta,
		Number:      number,
		BaseNumber:  base.Number,
		ThisUpdate:  req.ThisUpdate,
		NextUpdate:  req.NextUpdate,
		GeneratedAt: genTime,
		DER:         der,
	}
	if err := m.db.UpsertPublishedCRL(published); err != nil {
		return nil, fmt.Errorf("storing delta CRL: %w", err)
	}
	metrics.CRLGenerated.Inc(crlKindDelta, scopeLabel(shard))
	m.recordCRLEvent(issuerCA, shard, crlKindDelta, number, len(entries))
	return der, nil
}

// signCRL opens the issuer's HSM signer and produces the DER CRL for req.
func (m *Manager) signCRL(ctx context.Context, issuerCA *models.CA, issuerCert *x509.Certificate, req pki.CRLRequest) ([]byte, error) {
	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()
	der, err := pki.CreateCRL(signer, issuerCert, req)
	if err != nil {
		return nil, fmt.Errorf("creating CRL: %w", err)
	}
	return der, nil
}

// recordCRLEvent appends a tamper-evident audit event for a freshly signed CRL.
func (m *Manager) recordCRLEvent(issuerCA *models.CA, shard int, kind string, number int64, entries int) {
	detail := fmt.Sprintf("scope=%s kind=%s number=%d entries=%d", scopeKey(shard), kind, number, entries)
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      "system",
		Action:     audit.ActionCRLPublish,
		Target:     issuerCA.ID,
		TargetName: issuerCA.Label,
		Result:     audit.ResultSuccess,
		Detail:     detail,
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append crl.publish audit event: %v", err)
	}
}
