package ca

import (
	"container/list"
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// OCSP pre-signing (Task 58) batch-signs a response for every serial the
// responder is likely to be asked about — everything issued (or revoked) by a
// CA plus serials recently queried online — on a background schedule. The
// results are placed in the shared response cache with an expiry equal to each
// response's own NextUpdate, so the public OCSP endpoint answers from memory
// without an HSM round-trip, and keeps answering for as long as the responses
// remain valid even if the HSM becomes unavailable. Nonce-bearing requests
// (RFC 8954) still bypass the cache and are signed freshly, per their whole
// point. The same pre-signed set feeds the static artifact publisher.

// DefaultOCSPPresignValidity is the NextUpdate window of pre-signed responses
// when none is configured. It matches the responder's own default validity and
// bounds both revocation-propagation delay for CDN-served responses and how
// long an HSM outage can be ridden out on pre-signed data.
const DefaultOCSPPresignValidity = 24 * time.Hour

// DefaultOCSPPresignExpiredGrace keeps pre-signing a certificate's serial for
// this long past its NotAfter, so clients validating around the expiry moment
// (or with skewed clocks) still get cached answers.
const DefaultOCSPPresignExpiredGrace = 24 * time.Hour

// PresignedOCSPResponse is one batch-signed OCSP response.
type PresignedOCSPResponse struct {
	// Serial is the certificate serial (decimal string) the response attests to.
	Serial string
	// Status is the attested status (pki.OCSPGood / OCSPRevoked / OCSPUnknown).
	Status int
	// DER is the fully signed OCSP response.
	DER []byte
	// ThisUpdate / NextUpdate bound the response's validity.
	ThisUpdate time.Time
	NextUpdate time.Time
}

// OCSPPresignerConfig tunes the presigner. The zero value is usable: default
// validity/grace, no cache fill, CA-key signing, no recent-query tracking.
type OCSPPresignerConfig struct {
	// Validity is the NextUpdate window of pre-signed responses. Non-positive
	// uses DefaultOCSPPresignValidity.
	Validity time.Duration
	// ExpiredGrace keeps a serial in the pre-signed set for this long past its
	// certificate's NotAfter. Negative disables the grace (expired serials are
	// dropped immediately); zero uses DefaultOCSPPresignExpiredGrace.
	ExpiredGrace time.Duration
	// Cache, when non-nil, receives every pre-signed response via PutUntil so
	// the online responder serves them. The presigner grows the cache bound to
	// fit its batches.
	Cache *OCSPCache
	// Delegated, when non-nil, signs pre-signed responses with the per-CA
	// short-lived delegated OCSP-signing certificate (falling back to the CA
	// key if the delegated responder cannot be produced), mirroring the online
	// responder. Share the instance wired into the HTTP layer so both paths
	// reuse one responder certificate.
	Delegated *DelegatedResponderCache
	// Recent, when non-nil, contributes serials recently queried through the
	// online responder (including ones unknown to the store) to each batch.
	Recent *RecentSerialTracker
}

// OCSPPresigner batch-signs OCSP responses for all known serials. It is safe
// for concurrent use, though batches are expected to run from a single loop.
type OCSPPresigner struct {
	mgr *Manager
	cfg OCSPPresignerConfig

	// mu guards latest: the most recent successful batch per CA, retained so
	// the static artifact publisher can publish exactly what the cache serves
	// without re-signing.
	mu     sync.Mutex
	latest map[string][]PresignedOCSPResponse

	// now is injectable for tests; nil means time.Now.
	now func() time.Time
}

func (p *OCSPPresigner) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// NewOCSPPresigner constructs a presigner over the manager's store and key
// provider, applying config defaults.
func NewOCSPPresigner(mgr *Manager, cfg OCSPPresignerConfig) *OCSPPresigner {
	if cfg.Validity <= 0 {
		cfg.Validity = DefaultOCSPPresignValidity
	}
	switch {
	case cfg.ExpiredGrace == 0:
		cfg.ExpiredGrace = DefaultOCSPPresignExpiredGrace
	case cfg.ExpiredGrace < 0:
		cfg.ExpiredGrace = 0
	}
	return &OCSPPresigner{
		mgr:    mgr,
		cfg:    cfg,
		latest: make(map[string][]PresignedOCSPResponse),
	}
}

// Validity returns the effective NextUpdate window of pre-signed responses.
func (p *OCSPPresigner) Validity() time.Duration { return p.cfg.Validity }

// Latest returns the most recent successful batch for a CA (nil if none yet).
// The returned slice is shared; callers must not mutate it.
func (p *OCSPPresigner) Latest(caID string) []PresignedOCSPResponse {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.latest[caID]
}

// OCSPPresignStats summarizes one presign run.
type OCSPPresignStats struct {
	// CAs is the number of CAs whose batch succeeded; Signed/Failed count
	// individual responses across all of them.
	CAs    int
	Signed int
	Failed int
}

// Run pre-signs responses for every X.509 CA whose certificate is still valid,
// records the batch metrics, and refreshes the cached-response gauge. A CA
// whose entire batch fails (e.g. the HSM is down) contributes an error but
// does not abort the run for other CAs; the previous pre-signed responses for
// it stay servable from the cache until their own NextUpdate.
func (p *OCSPPresigner) Run(ctx context.Context) (_ OCSPPresignStats, err error) {
	ctx, span := tracing.Start(ctx, "ca.ocsp_presign_run")
	defer func() { tracing.End(span, err) }()
	start := time.Now()

	var stats OCSPPresignStats
	cas, err := p.mgr.db.ListCAs()
	if err != nil {
		metrics.RecordOCSPPresignBatch(start, 0, 0, err)
		return stats, fmt.Errorf("listing CAs: %w", err)
	}

	var errs []error
	now := p.clock()
	for i := range cas {
		c := &cas[i]
		if c.Certificate == "" {
			continue // SSH-only signing key, no X.509 issuer to answer for
		}
		if c.NotAfter != nil && c.NotAfter.Before(now) {
			continue // expired CA certificate; nothing valid to attest to
		}
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		responses, signErr := p.PresignCA(ctx, c.ID)
		stats.Signed += len(responses)
		if signErr != nil {
			errs = append(errs, fmt.Errorf("CA %s (%s): %w", c.ID, c.Label, signErr))
			continue
		}
		stats.CAs++
	}
	stats.Failed = len(errs)

	if len(errs) > 0 {
		err = fmt.Errorf("ocsp presign: %d CA batch(es) failed: %v", len(errs), errs[0])
	}
	metrics.RecordOCSPPresignBatch(start, stats.Signed, stats.Failed, err)
	if p.cfg.Cache != nil {
		metrics.SetOCSPPresignedCached(p.cfg.Cache.PresignedCount())
	}
	span.SetAttributes(attribute.Int("presign.signed", stats.Signed), attribute.Int("presign.failed", stats.Failed))
	return stats, err
}

// PresignCA batch-signs responses for every known serial of one CA, fills the
// shared cache, and retains the batch for the publisher. The provider signer
// is opened once for the whole batch. On error nothing is cached or retained,
// so previously pre-signed responses keep being served.
func (p *OCSPPresigner) PresignCA(ctx context.Context, caID string) (_ []PresignedOCSPResponse, err error) {
	ctx, span := tracing.Start(ctx, "ca.ocsp_presign_ca", attribute.String("ca.id", caID))
	defer func() { tracing.End(span, err) }()

	issuerCA, issuerCert, err := p.mgr.loadIssuer(caID)
	if err != nil {
		return nil, err
	}

	serials, statuses, err := p.collectSerials(caID)
	if err != nil {
		return nil, err
	}
	if len(serials) == 0 {
		p.retain(caID, nil)
		return nil, nil
	}

	// Sign with the same key the online responder would use: the delegated
	// OCSP-signing certificate when configured (keeping the CA key cold), the
	// CA key otherwise. A delegated failure falls back to the CA key so a batch
	// never dies on responder-certificate reissue trouble alone.
	var responderCert *x509.Certificate
	signerRef := keyRefForCA(issuerCA)
	if p.cfg.Delegated != nil {
		cert, ref, derr := p.cfg.Delegated.Responder(ctx, p.mgr, caID)
		if derr == nil {
			responderCert = cert
			signerRef = keyprovider.KeyRef{Label: ref.Label, ID: ref.ID}
		} else {
			log.Printf("WARNING: ocsp presign: delegated responder for CA %s unavailable, signing with CA key: %v", caID, derr)
		}
	}

	signer, err := p.mgr.provider.Signer(ctx, signerRef)
	if err != nil {
		return nil, fmt.Errorf("%w: opening OCSP presign signer: %v", ErrOCSPTryLater, err)
	}
	defer signer.Close()

	now := p.clock()
	responses := make([]PresignedOCSPResponse, 0, len(serials))
	var failed int
	var firstErr error
	for _, serialStr := range serials {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		serial, ok := new(big.Int).SetString(serialStr, 10)
		if !ok {
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("stored serial %q is not a valid integer", serialStr)
			}
			continue
		}
		st := statuses[serialStr]
		spec := pki.OCSPResponseSpec{
			Serial:           serial,
			Status:           st.status,
			RevokedAt:        st.revokedAt,
			RevocationReason: st.reason,
			ThisUpdate:       now.Add(-clockSkew),
			NextUpdate:       now.Add(p.cfg.Validity),
			// IssuerHash zero = SHA-1, the RFC 6960 default and the certID hash
			// effectively all clients (openssl, RFC 5019 profiles) request with.
			Responder: responderCert,
		}
		der, signErr := pki.CreateOCSPResponse(signer, issuerCert, spec)
		if signErr != nil {
			failed++
			if firstErr == nil {
				firstErr = signErr
			}
			continue
		}
		responses = append(responses, PresignedOCSPResponse{
			Serial:     serialStr,
			Status:     st.status,
			DER:        der,
			ThisUpdate: spec.ThisUpdate,
			NextUpdate: spec.NextUpdate,
		})
	}

	// A batch where nothing signed is a failure (typically the HSM went away
	// mid-batch); partial success is served — every response we did produce is
	// valid and better in the cache than not.
	if len(responses) == 0 && failed > 0 {
		return nil, fmt.Errorf("%w: all %d OCSP presign signatures failed: %v", ErrOCSPTryLater, failed, firstErr)
	}
	if failed > 0 {
		log.Printf("WARNING: ocsp presign: CA %s: %d/%d responses failed to sign: %v", caID, failed, len(serials), firstErr)
	}

	if p.cfg.Cache != nil {
		// Fit the whole pre-signed set plus headroom for demand-filled entries so
		// the presigner never evicts itself.
		p.cfg.Cache.EnsureCapacity(2 * len(responses))
		for i := range responses {
			p.cfg.Cache.PutUntil(caID, responses[i].Serial, responses[i].DER, responses[i].NextUpdate)
		}
	}
	p.retain(caID, responses)
	return responses, nil
}

type serialStatus struct {
	status    int
	revokedAt time.Time
	reason    int
}

// collectSerials gathers the serials to pre-sign for a CA and their statuses:
// every issued certificate that is unexpired (within the grace window), every
// revocation record, and — when tracking is enabled — serials recently queried
// through the online responder. The result is sorted for deterministic batches
// and artifacts.
func (p *OCSPPresigner) collectSerials(caID string) ([]string, map[string]serialStatus, error) {
	now := p.clock()
	statuses := make(map[string]serialStatus)

	issued, err := p.mgr.db.ListIssuedCertificates(caID)
	if err != nil {
		return nil, nil, fmt.Errorf("listing issued certificates: %w", err)
	}
	for i := range issued {
		if issued[i].NotAfter.Add(p.cfg.ExpiredGrace).Before(now) {
			continue
		}
		statuses[issued[i].Serial] = serialStatus{status: pki.OCSPGood}
	}

	// Revocations override issued status and are always included: a revoked
	// response must stay servable even when the certificate row ages out.
	revoked, err := p.mgr.db.ListRevokedCertificates(caID)
	if err != nil {
		return nil, nil, fmt.Errorf("listing revoked certificates: %w", err)
	}
	for i := range revoked {
		statuses[revoked[i].Serial] = serialStatus{
			status:    pki.OCSPRevoked,
			revokedAt: revoked[i].RevokedAt,
			reason:    revoked[i].Reason,
		}
	}

	// Recently queried serials the store does not know get a signed "unknown",
	// so even scanners and pre-import certificates are answered from cache. The
	// tracker is bounded, which bounds the extra signing work.
	if p.cfg.Recent != nil {
		for _, s := range p.cfg.Recent.Recent(caID, now.Add(-p.cfg.Validity)) {
			if _, known := statuses[s]; !known {
				statuses[s] = serialStatus{status: pki.OCSPUnknown}
			}
		}
	}

	serials := make([]string, 0, len(statuses))
	for s := range statuses {
		serials = append(serials, s)
	}
	sort.Strings(serials)
	return serials, statuses, nil
}

func (p *OCSPPresigner) retain(caID string, responses []PresignedOCSPResponse) {
	p.mu.Lock()
	p.latest[caID] = responses
	p.mu.Unlock()
}

// -----------------------------------------------------------------------------
// Recently-queried serial tracking
// -----------------------------------------------------------------------------

// DefaultRecentSerialCapacity bounds the recently-queried tracker. The bound is
// a defense against adversarial floods of distinct serials: at worst the
// presigner signs this many extra "unknown" responses per batch.
const DefaultRecentSerialCapacity = 4096

// RecentSerialTracker is a bounded, LRU-evicting record of (CA, serial) pairs
// the online OCSP responder has been asked about, feeding the "recently
// queried" portion of presign batches. It is safe for concurrent use and cheap
// on the request path (one mutex, no allocation on re-observation).
type RecentSerialTracker struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List // front = most recently seen
	items map[string]*list.Element

	// now is injectable for tests; nil means time.Now.
	now func() time.Time
}

type recentSerial struct {
	caID   string
	serial string
	seen   time.Time
}

// NewRecentSerialTracker constructs a tracker holding at most capacity entries
// (non-positive uses DefaultRecentSerialCapacity).
func NewRecentSerialTracker(capacity int) *RecentSerialTracker {
	if capacity <= 0 {
		capacity = DefaultRecentSerialCapacity
	}
	return &RecentSerialTracker{
		cap:   capacity,
		ll:    list.New(),
		items: make(map[string]*list.Element),
	}
}

func (t *RecentSerialTracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// Record notes that the responder was queried for (caID, serial).
func (t *RecentSerialTracker) Record(caID, serial string) {
	if t == nil || caID == "" || serial == "" {
		return
	}
	key := caID + "\x00" + serial
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.items[key]; ok {
		el.Value.(*recentSerial).seen = t.clock()
		t.ll.MoveToFront(el)
		return
	}
	for t.ll.Len() >= t.cap {
		oldest := t.ll.Back()
		if oldest == nil {
			break
		}
		rs := oldest.Value.(*recentSerial)
		delete(t.items, rs.caID+"\x00"+rs.serial)
		t.ll.Remove(oldest)
	}
	t.items[key] = t.ll.PushFront(&recentSerial{caID: caID, serial: serial, seen: t.clock()})
}

// Recent returns the serials queried for caID at or after since.
func (t *RecentSerialTracker) Recent(caID string, since time.Time) []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for el := t.ll.Front(); el != nil; el = el.Next() {
		rs := el.Value.(*recentSerial)
		if rs.seen.Before(since) {
			// Entries are ordered most-recent first; everything past this point
			// is older still.
			break
		}
		if rs.caID == caID {
			out = append(out, rs.serial)
		}
	}
	return out
}

// Len reports the number of tracked (CA, serial) pairs.
func (t *RecentSerialTracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ll.Len()
}
