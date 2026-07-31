// Package anchor strengthens the hash-chained audit log (internal/audit)
// against whole-chain truncation and rewrite by periodically anchoring the
// chain head: it takes the newest event's (seq, hash), obtains an RFC 3161
// timestamp token over their canonical digest from a TSA — the deployment's
// internal HSM-backed one (internal/tsa) or an external URL for deployments
// that want independence — and persists the token in the audit_anchors table.
//
// The chain alone proves internal consistency; a writer who controls the store
// can still re-seal every entry or drop the newest ones and present a shorter,
// internally consistent log. An anchor token is signed by a TSA key the store
// writer does not hold, so after each anchor point the log's existence and
// exact head hash are independently attested: `secsy-ca audit verify` walks
// the anchors and fails on any truncation or rewrite behind one.
package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// Store is the slice of the persistence layer the anchor service needs;
// *database.DB satisfies it.
type Store interface {
	EventLogHead() (seq int64, hash, action string, err error)
	LatestAuditAnchor() (*audit.Anchor, error)
	InsertAuditAnchor(a *audit.Anchor) error
	AppendEvent(e *audit.Event) error
}

// Timestamper obtains RFC 3161 timestamp tokens over a SHA-256 digest.
type Timestamper interface {
	// Timestamp returns a DER TimeStampToken covering digest and the token's
	// genTime. Implementations validate the response themselves (granted
	// status, nonce echo, imprint match) so callers receive only usable tokens.
	Timestamp(ctx context.Context, digest []byte) (token []byte, genTime time.Time, err error)
	// Source identifies where tokens come from for anchor records and audit
	// events: "" for the in-process TSA, else the external TSA URL.
	Source() string
}

// tokenFetcher implements the shared request/response half of a Timestamper:
// it builds the TimeStampReq (fresh nonce, certReq so the token embeds the TSA
// certificate for later offline verification), delegates transport to
// roundTrip, and validates the returned token before handing it out.
type tokenFetcher struct {
	source    string
	roundTrip func(ctx context.Context, reqDER []byte) (respDER []byte, err error)
}

func (f *tokenFetcher) Source() string { return f.source }

func (f *tokenFetcher) Timestamp(ctx context.Context, digest []byte) ([]byte, time.Time, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: generating nonce: %w", err)
	}
	reqDER, err := tsa.MakeRequest(crypto.SHA256, digest, &tsa.RequestOptions{Nonce: nonce, CertReq: true})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: building timestamp request: %w", err)
	}
	respDER, err := f.roundTrip(ctx, reqDER)
	if err != nil {
		return nil, time.Time{}, err
	}
	token, err := tsa.ExtractToken(respDER)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: %w", err)
	}
	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("anchor: %w", err)
	}
	// Fail closed on a token that does not cover exactly what we asked for: a
	// mismatched imprint or nonce means the response answers some other request.
	if !bytes.Equal(info.HashedMessage, digest) {
		return nil, time.Time{}, errors.New("anchor: timestamp token does not cover the submitted digest")
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		return nil, time.Time{}, errors.New("anchor: timestamp token does not echo the request nonce")
	}
	return token, info.GenTime.UTC(), nil
}

// NewAuthorityTimestamper adapts the in-process RFC 3161 authority. A rejected
// request (a *protocol* rejection, not a transport error) is surfaced as an
// error since the anchor job has no signed-free fallback.
func NewAuthorityTimestamper(a *tsa.Authority) Timestamper {
	return &tokenFetcher{
		source: "",
		roundTrip: func(ctx context.Context, reqDER []byte) ([]byte, error) {
			res, err := a.Stamp(ctx, reqDER)
			if err != nil {
				return nil, fmt.Errorf("anchor: internal TSA: %w", err)
			}
			if !res.Granted {
				return nil, fmt.Errorf("anchor: internal TSA rejected the timestamp request: %s", res.Detail)
			}
			return res.Response, nil
		},
	}
}

// maxTSAResponseBytes bounds an external TSA response. A TimeStampResp is a
// token plus a small status — a few KB with the certificate chain embedded.
const maxTSAResponseBytes = 1 << 20

// NewHTTPTimestamper obtains tokens from an external RFC 3161 TSA over the
// standard HTTP transport (§3.4: POST application/timestamp-query). timeout <= 0
// defaults to 30s. Deployments use this when the anchor authority must be
// independent of the PKI being anchored.
func NewHTTPTimestamper(url string, timeout time.Duration) Timestamper {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return &tokenFetcher{
		source: url,
		roundTrip: func(ctx context.Context, reqDER []byte) ([]byte, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqDER))
			if err != nil {
				return nil, fmt.Errorf("anchor: building TSA request: %w", err)
			}
			req.Header.Set("Content-Type", "application/timestamp-query")
			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("anchor: external TSA %s: %w", url, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("anchor: external TSA %s returned HTTP %d", url, resp.StatusCode)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponseBytes+1))
			if err != nil {
				return nil, fmt.Errorf("anchor: reading TSA response: %w", err)
			}
			if len(body) > maxTSAResponseBytes {
				return nil, fmt.Errorf("anchor: TSA response exceeds %d bytes", maxTSAResponseBytes)
			}
			return body, nil
		},
	}
}

// Clock yields the anchor's creation time, having validated it. Now returns a
// non-nil error to force a fail-closed refusal when the host clock cannot be
// trusted against the configured external time source. *timesource.Checker
// satisfies it; the default is the host wall clock, which never fails. Keeping
// it a local interface leaves the anchor package decoupled from
// internal/timesource.
type Clock interface {
	Now(ctx context.Context) (time.Time, error)
}

// hostClock is the default, never-failing Clock: the host wall clock. It also
// backs the SetClock test seam.
type hostClock struct{ now func() time.Time }

func (c hostClock) Now(context.Context) (time.Time, error) { return c.now(), nil }

// Service anchors the audit chain's head on demand. It is safe for concurrent
// use, though anchoring is naturally serial (one background runner or an
// operator CLI invocation).
type Service struct {
	store Store
	ts    Timestamper
	clock Clock
	// actor identifies who anchored in the audit trail: "anchor" for the
	// background job, "secsy-ca-cli" for operator-initiated anchors.
	actor string
}

// NewService assembles an anchor service over the given store and token source.
func NewService(store Store, ts Timestamper) *Service {
	return &Service{store: store, ts: ts, clock: hostClock{now: time.Now}, actor: "anchor"}
}

// WithActor overrides the audit-event actor (e.g. the CLI).
func (s *Service) WithActor(actor string) *Service {
	s.actor = actor
	return s
}

// SetClock overrides the time source (tests only). It wraps now in a
// never-failing Clock, preserving the deterministic-createdAt test seam.
func (s *Service) SetClock(now func() time.Time) { s.clock = hostClock{now: now} }

// SetTrustedClock installs a fail-closed trusted-time clock (Task 163): before
// an anchor is created the host clock is cross-checked against the configured
// external time source(s), and AnchorOnce refuses (returns an error, persists
// nothing) when the drift exceeds the threshold. The zero-config default keeps
// the host wall clock, so this is only wired when a time.source is configured.
func (s *Service) SetTrustedClock(c Clock) {
	if c != nil {
		s.clock = c
	}
}

// SeedMetrics initializes the last-anchor gauges from the persisted state so a
// restarted server reports the true anchor age immediately instead of blanking
// the metric until its first new anchor. Best-effort: callers log the error.
func (s *Service) SeedMetrics() error {
	last, err := s.store.LatestAuditAnchor()
	if err != nil || last == nil {
		return err
	}
	metrics.SeedAuditAnchor(last.Seq, last.CreatedAt)
	return nil
}

// Result reports the outcome of one AnchorOnce call.
type Result struct {
	// Skipped is true when nothing needed anchoring (empty log, or no events
	// since the previous anchor); Reason says why.
	Skipped bool
	Reason  string
	// Anchor is the persisted anchor on success (nil when skipped).
	Anchor *audit.Anchor
}

// AnchorOnce anchors the current event-log head: it reads the newest entry,
// obtains an RFC 3161 token over the canonical (seq, hash) digest, persists
// the anchor, and appends an audit.anchor event. Unless force is set, it skips
// when the head has not moved since the last anchor — including the case where
// the only new entry is the previous anchor's own audit record, so an idle log
// does not re-anchor itself forever.
func (s *Service) AnchorOnce(ctx context.Context, force bool) (*Result, error) {
	seq, hash, action, err := s.store.EventLogHead()
	if err != nil {
		metrics.RecordAuditAnchorFailure()
		return nil, fmt.Errorf("anchor: reading event-log head: %w", err)
	}
	if seq == 0 {
		metrics.RecordAuditAnchorSkipped(0, 0)
		return &Result{Skipped: true, Reason: "event log is empty"}, nil
	}

	last, err := s.store.LatestAuditAnchor()
	if err != nil {
		metrics.RecordAuditAnchorFailure()
		return nil, fmt.Errorf("anchor: loading latest anchor: %w", err)
	}
	if !force && last != nil {
		if seq == last.Seq && strings.EqualFold(hash, last.HeadHash) {
			metrics.RecordAuditAnchorSkipped(last.Seq, seq)
			return &Result{Skipped: true, Reason: fmt.Sprintf("head (seq %d) is already anchored", seq)}, nil
		}
		if seq == last.Seq+1 && action == audit.ActionAuditAnchor {
			metrics.RecordAuditAnchorSkipped(last.Seq, seq)
			return &Result{Skipped: true,
				Reason: fmt.Sprintf("no new events since the last anchor (head seq %d is its own anchor record)", seq)}, nil
		}
	}

	// Fail closed on an untrusted clock: cross-check the host clock against the
	// configured external time source(s) BEFORE requesting a token, so a drifted
	// or compromised host clock cannot mint a falsely-dated anchor (and, for the
	// external-TSA path, cannot persist a CreatedAt the host cannot vouch for).
	// The default clock is the host wall clock, which never fails.
	createdAt, err := s.clock.Now(ctx)
	if err != nil {
		metrics.RecordAuditAnchorFailure()
		s.record(audit.ResultError, "", fmt.Sprintf("seq=%d head=%s trusted-time check failed: %v", seq, hash, err))
		return nil, fmt.Errorf("anchor: trusted-time check failed: %w", err)
	}

	token, genTime, err := s.ts.Timestamp(ctx, audit.AnchorDigest(seq, hash))
	if err != nil {
		metrics.RecordAuditAnchorFailure()
		s.record(audit.ResultError, "", fmt.Sprintf("seq=%d head=%s tsa=%s error=%v", seq, hash, s.sourceLabel(), err))
		return nil, err
	}

	a := &audit.Anchor{
		ID:        uuid.New().String(),
		Seq:       seq,
		HeadHash:  strings.ToLower(hash),
		Token:     token,
		TSASource: s.ts.Source(),
		GenTime:   genTime,
		CreatedAt: createdAt.UTC(),
	}
	if err := s.store.InsertAuditAnchor(a); err != nil {
		metrics.RecordAuditAnchorFailure()
		s.record(audit.ResultError, "", fmt.Sprintf("seq=%d head=%s tsa=%s error=persisting anchor: %v", seq, hash, s.sourceLabel(), err))
		return nil, fmt.Errorf("anchor: persisting anchor: %w", err)
	}

	metrics.RecordAuditAnchorSuccess(a.Seq, a.CreatedAt)
	// The event is appended after the anchor row so the anchor's own record is
	// the next chain entry (and reaches SIEM sinks as an external copy of the
	// anchored head). Its failure does not undo the anchor.
	s.record(audit.ResultSuccess, a.ID,
		fmt.Sprintf("seq=%d head=%s gen_time=%s tsa=%s", a.Seq, a.HeadHash, a.GenTime.Format(time.RFC3339), s.sourceLabel()))
	return &Result{Anchor: a}, nil
}

// sourceLabel is the human-readable TSA source for audit details and logs.
func (s *Service) sourceLabel() string {
	if src := s.ts.Source(); src != "" {
		return src
	}
	return "internal"
}

// record appends an audit.anchor event, best-effort: on the success path the
// anchor row is already the durable artifact, and on the failure path the
// caller surfaces the primary error — but the event is what SIEM sinks stream
// off-host, so a failure to write it is logged rather than silently dropped.
func (s *Service) record(result, target, detail string) {
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      s.actor,
		ActorRoles: "system",
		Action:     audit.ActionAuditAnchor,
		Target:     target,
		Result:     result,
		Detail:     detail,
	}
	if err := s.store.AppendEvent(e); err != nil {
		log.Printf("anchor: appending audit.anchor event: %v", err)
	}
}

// ---- Verification -----------------------------------------------------------

// CheckResult is the verification outcome for one anchor.
type CheckResult struct {
	ID       string    `json:"id"`
	Seq      int64     `json:"seq"`
	HeadHash string    `json:"head_hash"`
	TSA      string    `json:"tsa"` // "internal" or the external URL
	GenTime  time.Time `json:"gen_time"`
	Valid    bool      `json:"valid"`
	Reason   string    `json:"reason,omitempty"`
}

// VerifyAnchors validates every anchor against the (ascending-ordered, full)
// event log: the hash linkage — the anchored seq must still exist with the
// anchored hash, which detects truncation and post-anchor rewrites — and the
// RFC 3161 token itself (CMS signature by the embedded TSA certificate,
// message imprint over the canonical anchor bytes, time-stamping EKU). When
// roots are supplied the TSA certificate must additionally chain to them at
// the token's genTime; without roots the chain step is skipped, matching how
// `openssl ts -verify` separates token integrity from trust.
func VerifyAnchors(events []audit.Event, anchors []audit.Anchor, roots []*x509.Certificate, now time.Time) []CheckResult {
	if now.IsZero() {
		now = time.Now()
	}
	results := make([]CheckResult, 0, len(anchors))
	for _, a := range anchors {
		r := CheckResult{ID: a.ID, Seq: a.Seq, HeadHash: a.HeadHash, TSA: a.TSASource, GenTime: a.GenTime, Valid: true}
		if r.TSA == "" {
			r.TSA = "internal"
		}
		if err := audit.CheckAnchorAgainstChain(events, a); err != nil {
			r.Valid, r.Reason = false, err.Error()
		} else if err := VerifyAnchorToken(a, roots, now); err != nil {
			r.Valid, r.Reason = false, err.Error()
		}
		results = append(results, r)
	}
	return results
}

// clockSkew tolerates modest clock drift between the TSA and the verifier when
// judging whether a token's genTime lies in the future.
const clockSkew = 5 * time.Minute

// VerifyAnchorToken validates an anchor's RFC 3161 token end to end: the
// token's CMS signature against the TSA certificate it embeds, the message
// imprint over AnchorMessage(seq, headHash) — the binding that makes the token
// attest THIS head and no other —, the signer's time-stamping EKU, and a
// plausibility bound on genTime. When roots are non-empty the TSA certificate
// must chain to one of them for the time-stamping EKU at genTime.
func VerifyAnchorToken(a audit.Anchor, roots []*x509.Certificate, now time.Time) error {
	parsed, err := cms.ParseSignedData(a.Token)
	if err != nil {
		return fmt.Errorf("parsing timestamp token: %w", err)
	}
	if err := parsed.Verify(); err != nil {
		return fmt.Errorf("timestamp token signature: %w", err)
	}
	tsaCert := parsed.SignerCertificate()
	if tsaCert == nil {
		return errors.New("timestamp token does not embed the TSA certificate")
	}

	info, err := tsa.ParseTokenInfo(a.Token)
	if err != nil {
		return err
	}
	if !info.Hash.Available() {
		return fmt.Errorf("token imprint hash %v is not available", info.Hash)
	}
	h := info.Hash.New()
	h.Write(audit.AnchorMessage(a.Seq, a.HeadHash))
	if !bytes.Equal(h.Sum(nil), info.HashedMessage) {
		return errors.New("timestamp token does not cover this anchor's (seq, head hash)")
	}
	if info.GenTime.After(now.Add(clockSkew)) {
		return fmt.Errorf("token genTime %s is in the future", info.GenTime.UTC().Format(time.RFC3339))
	}

	hasTS := false
	for _, eku := range tsaCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTS = true
		}
	}
	if !hasTS {
		return errors.New("token signer lacks the id-kp-timeStamping extended key usage")
	}

	if len(roots) > 0 {
		rootPool := x509.NewCertPool()
		for _, r := range roots {
			rootPool.AddCert(r)
		}
		interPool := x509.NewCertPool()
		for _, c := range parsed.Certificates {
			if !bytes.Equal(c.Raw, tsaCert.Raw) {
				interPool.AddCert(c)
			}
		}
		if _, err := tsaCert.Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: interPool,
			CurrentTime:   info.GenTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		}); err != nil {
			return fmt.Errorf("TSA certificate chain: %w", err)
		}
	}
	return nil
}
