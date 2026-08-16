package hsmaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa/tstinfo"
)

// Freshness proofs answer the one question everything else in this package
// cannot: *when* was this true?
//
// A bundle that verifies perfectly proves the device signed exactly what the CA
// published — as of whatever moment the bundle was taken. Nothing inside it
// pins that moment down. ExportedAt is the exporting side's own clock, and the
// exporting side is precisely the party being audited. So an operator who
// abuses a key on Tuesday can hand an auditor Monday's bundle, which is
// internally flawless, and the auditor has no way to tell it is a month stale.
// Every check in VerifyBundle would pass.
//
// The fix is to have a third party periodically attest to the audit state. At a
// regular interval the CA computes its current head — the ledger chain hash,
// the device log tail digest, and the signature count — and obtains an RFC 3161
// timestamp token over a digest of it. The token says, in the TSA's words and
// under the TSA's signature: *this exact head existed at this time*.
//
// That gives an auditor two things a bundle alone cannot:
//
//   - Staleness detection. If the newest proof's genTime is three weeks old,
//     the CA has not attested to its state for three weeks, and the bundle
//     proves nothing about that window. VerifyFreshness fails on it rather than
//     reporting a confident OK over stale data.
//
//   - Interval bounding. Each proof pins a prefix of the history to a trusted
//     instant, so a signature appearing after proof N's head but before proof
//     N+1's is bounded on both sides. An abuse cannot be backdated into a period
//     an earlier proof already closed.
//
// The proofs are a separate sequence from the ledger rather than rows in it.
// Reconciliation depends on the ledger holding exactly one row per HSM
// signature — a surplus of device signatures over ledger rows is the abuse
// signal — so injecting non-signature rows would silently break the very check
// this subsystem exists for. Instead each proof *references* the ledger
// position it covers, which binds the two without conflating them.

// FreshnessInterval is the default cadence for the attestation job. Once a day
// is the usual anchoring cadence in this codebase (see internal/anchor), but the
// interval here is also the resolution of the interval-bounding guarantee: a
// signature can only be located to within the gap between two proofs. Deployments
// that need tighter bounds shorten it; the cost is one TSA round trip.
const FreshnessInterval = 6 * time.Hour

// DefaultMaxAge is the staleness threshold a verifier applies when the auditor
// does not choose one. It is deliberately generous relative to
// FreshnessInterval so a single missed attestation — a TSA outage, a restart —
// does not read as an incident, while a genuinely abandoned log does.
const DefaultMaxAge = 25 * time.Hour

// Timestamper obtains RFC 3161 timestamp tokens over a SHA-256 digest.
//
// It is declared here, structurally identical to anchor.Timestamper, so this
// package does not import internal/anchor for one interface — the audit
// subsystem must stay independent of the audit-chain anchoring it sits beside.
// anchor.NewHTTPTimestamper and anchor.NewAuthorityTimestamper satisfy it as-is,
// which is how the server and CLI supply one without any adapter.
type Timestamper interface {
	// Timestamp returns a DER TimeStampToken covering digest, and the genTime
	// the token asserts. Implementations validate the response (granted status,
	// nonce echo, imprint match) before returning it.
	Timestamp(ctx context.Context, digest []byte) (token []byte, genTime time.Time, err error)
	// Source identifies the token's origin: "" for the in-process TSA, else the
	// external TSA URL. It is recorded on the proof because the two prove
	// materially different things — see FreshnessProof.Source.
	Source() string
}

// Head is the audit state a freshness proof attests to.
//
// Every field is load-bearing. The two chain heads pin what was known; the
// signature count makes a proof falsifiable against the device log; and the
// device serial and genesis anchor scope the whole thing to one device history,
// so a token obtained for device A cannot be presented as covering device B.
type Head struct {
	// DeviceSerial and Anchor identify the history. Without them a proof would
	// attest to a pair of hashes with no statement about which device produced
	// them.
	DeviceSerial string `json:"device_serial"`
	Anchor       string `json:"anchor"`
	// DeviceNumber and DeviceDigest are the last collected device log entry and
	// its chain digest. Because each device digest folds in its predecessor,
	// this single value commits to the entire device log up to that point.
	DeviceNumber uint16 `json:"device_number"`
	DeviceDigest string `json:"device_digest"`
	// Signatures is how many successful signing operations the device log
	// contained at that point. It is what makes the proof checkable rather than
	// merely present: an auditor recounts it from the bundle's own entries, so a
	// proof claiming a count the log does not support is caught.
	Signatures int `json:"signatures"`
	// LedgerSeq and LedgerHash are the signature ledger's head.
	LedgerSeq  int64  `json:"ledger_seq"`
	LedgerHash string `json:"ledger_hash"`
}

// Message renders the head as the deterministic, length-prefixed byte string
// the timestamp token's message imprint is taken over.
//
// It carries a domain-separating prefix so a token obtained over this structure
// can never be replayed as a token over some other length-prefixed structure in
// this system — the audit-chain anchor messages in internal/audit being the
// obvious neighbour.
func (h Head) Message() []byte {
	var buf []byte
	appendString := func(s string) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(s)))
		buf = append(buf, b[:]...)
		buf = append(buf, s...)
	}
	appendUint64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		buf = append(buf, b[:]...)
	}
	appendString("secsy-pki:hsm-audit-head:v1")
	appendString(strings.ToLower(strings.TrimSpace(h.DeviceSerial)))
	appendString(strings.ToLower(strings.TrimSpace(h.Anchor)))
	appendUint64(uint64(h.DeviceNumber))
	appendString(strings.ToLower(strings.TrimSpace(h.DeviceDigest)))
	appendUint64(uint64(h.Signatures))
	appendUint64(uint64(h.LedgerSeq))
	appendString(strings.ToLower(strings.TrimSpace(h.LedgerHash)))
	return buf
}

// Digest is the SHA-256 over Message, lowercase hex. It is the value submitted
// to the TSA.
func (h Head) Digest() string {
	sum := sha256.Sum256(h.Message())
	return hex.EncodeToString(sum[:])
}

// FreshnessProof is one RFC 3161 attestation that a head existed at a time.
type FreshnessProof struct {
	// Seq is a gap-free monotonic counter over proofs.
	Seq int64 `json:"seq"`
	// Head is the state attested to.
	Head Head `json:"head"`
	// HeadDigest is Head.Digest() as submitted. A verifier recomputes it rather
	// than trusting it; it is stored so a mismatch names both values.
	HeadDigest string `json:"head_digest"`
	// GenTime is the time the TSA asserts, extracted from the token. This is the
	// trusted clock — the whole point of the exercise — and a verifier re-derives
	// it from Token rather than reading this field.
	GenTime time.Time `json:"gen_time"`
	// ObtainedAt is the CA's own clock when it requested the token. It is
	// informational: a large divergence from GenTime is worth an operator's
	// attention, but nothing in verification trusts it.
	ObtainedAt time.Time `json:"obtained_at"`
	// Source is "" for the in-process TSA and the URL for an external one.
	//
	// The distinction is not cosmetic. The in-process TSA signs with the very
	// HSM under audit, so against an adversary who holds that HSM its genTime is
	// worth exactly as much as the CA's own clock — which is to say nothing. An
	// external TSA is a genuinely independent witness. Verification reports
	// which was used and can be told to require the latter.
	Source string `json:"source,omitempty"`
	// Token is the DER-encoded RFC 3161 TimeStampToken, with the TSA certificate
	// embedded (the requests set certReq) so it verifies offline.
	Token []byte `json:"token"`
}

// currentHead reads the audit state, device log and ledger and assembles the
// head as it stands now.
func (s *Service) currentHead(ctx context.Context) (Head, error) {
	st, err := s.store.LoadAuditState(ctx)
	if err != nil {
		return Head{}, fmt.Errorf("loading hsm audit state: %w", err)
	}
	if st == nil {
		return Head{}, fmt.Errorf("device is not provisioned: there is no audit state to attest to")
	}
	entries, err := s.store.LogEntries(ctx)
	if err != nil {
		return Head{}, fmt.Errorf("reading stored device log: %w", err)
	}
	ledger, err := s.store.Ledger(ctx)
	if err != nil {
		return Head{}, fmt.Errorf("reading signature ledger: %w", err)
	}
	h := Head{
		DeviceSerial: st.DeviceSerial,
		Anchor:       strings.ToLower(st.Anchor),
		DeviceNumber: st.Tail.Number,
		DeviceDigest: strings.ToLower(st.Tail.Digest),
		Signatures:   countSignatures(entries),
	}
	if n := len(ledger); n > 0 {
		h.LedgerSeq = ledger[n-1].Seq
		h.LedgerHash = strings.ToLower(ledger[n-1].Hash)
	}
	return h, nil
}

// Timestamp obtains one freshness proof over the current head and stores it.
//
// It drains the device log first. Attesting to a head that omits signatures the
// device has already performed but the CA has not yet collected would place
// those signatures after the proof, weakening exactly the bound the proof
// exists to provide — and it is the collector, not this method, that verifies
// their continuity, so skipping it would also attest to unverified state.
func (s *Service) Timestamp(ctx context.Context, ts Timestamper) (*FreshnessProof, error) {
	if ts == nil {
		return nil, fmt.Errorf("no timestamp authority configured: freshness proofs need an RFC 3161 TSA")
	}
	if s.dev != nil {
		if _, err := NewCollector(s.dev, s.store, 0, nil).Collect(ctx); err != nil {
			return nil, fmt.Errorf("draining device log before attesting to its head: %w", err)
		}
	}

	head, err := s.currentHead(ctx)
	if err != nil {
		return nil, err
	}
	digestHex := head.Digest()
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, fmt.Errorf("encoding head digest: %w", err)
	}

	token, genTime, err := ts.Timestamp(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("obtaining timestamp over the audit head: %w", err)
	}

	p := &FreshnessProof{
		Head:       head,
		HeadDigest: digestHex,
		GenTime:    genTime.UTC(),
		ObtainedAt: s.now().UTC(),
		Source:     ts.Source(),
		Token:      token,
	}
	// Check the token before storing it. A token that does not cover the head we
	// submitted is useless, and storing it would leave a proof in the record that
	// fails verification later with no way to tell whether the TSA misbehaved or
	// the row was edited.
	if err := verifyProofToken(p, nil, time.Time{}); err != nil {
		return nil, fmt.Errorf("timestamp authority returned an unusable token: %w", err)
	}
	if err := s.store.AppendFreshnessProof(ctx, p); err != nil {
		return nil, fmt.Errorf("storing freshness proof: %w", err)
	}
	return p, nil
}

// verifyProofToken validates a proof's RFC 3161 token: the CMS signature, that
// the imprint really covers this proof's head, the signer's time-stamping EKU,
// and — when roots are supplied — that the TSA certificate chains to one of them
// at genTime.
//
// A zero now skips the future-genTime bound, which is what Timestamp wants: it
// has just obtained the token and has no independent clock to judge it against.
func verifyProofToken(p *FreshnessProof, roots []*x509.Certificate, now time.Time) error {
	if p == nil {
		return fmt.Errorf("no proof")
	}
	if len(p.Token) == 0 {
		return fmt.Errorf("proof carries no timestamp token")
	}

	// The digest is recomputed from the head fields, never read from the record:
	// a stored HeadDigest that disagrees with its own head is exactly what an
	// edited row looks like.
	want := p.Head.Digest()
	if !strings.EqualFold(want, p.HeadDigest) {
		return fmt.Errorf("recorded head digest %s does not match %s recomputed from the head fields: the record was altered",
			strings.ToLower(p.HeadDigest), want)
	}

	parsed, err := cms.ParseSignedData(p.Token)
	if err != nil {
		return fmt.Errorf("parsing timestamp token: %w", err)
	}
	if err := parsed.Verify(); err != nil {
		return fmt.Errorf("timestamp token signature: %w", err)
	}
	tsaCert := parsed.SignerCertificate()
	if tsaCert == nil {
		return fmt.Errorf("timestamp token does not embed the TSA certificate, so it cannot be verified offline")
	}

	info, err := tstinfo.ParseTokenInfo(p.Token)
	if err != nil {
		return err
	}
	if !info.Hash.Available() {
		return fmt.Errorf("token imprint hash %v is not available to this verifier", info.Hash)
	}
	h := info.Hash.New()
	h.Write(p.Head.Message())
	if !bytes.Equal(h.Sum(nil), info.HashedMessage) {
		return fmt.Errorf("timestamp token does not cover this proof's head: the token was obtained for some other state")
	}
	if !now.IsZero() && info.GenTime.After(now.Add(freshnessClockSkew)) {
		return fmt.Errorf("token genTime %s is in the future", info.GenTime.UTC().Format(time.RFC3339))
	}
	// The stored GenTime is a convenience field; verification uses the token's.
	// They must agree, or the record is misrepresenting what the TSA said.
	if !p.GenTime.IsZero() && !p.GenTime.UTC().Truncate(time.Second).Equal(info.GenTime.UTC().Truncate(time.Second)) {
		return fmt.Errorf("recorded genTime %s does not match the token's %s: the record was altered",
			p.GenTime.UTC().Format(time.RFC3339), info.GenTime.UTC().Format(time.RFC3339))
	}

	hasTS := false
	for _, eku := range tsaCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTS = true
		}
	}
	if !hasTS {
		return fmt.Errorf("token signer lacks the id-kp-timeStamping extended key usage")
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

// freshnessClockSkew tolerates modest drift between the TSA's clock and the
// verifier's when judging whether a genTime lies in the future.
const freshnessClockSkew = 5 * time.Minute

// FreshnessResult is the verdict on a bundle's freshness proofs.
type FreshnessResult struct {
	// OK is true when at least one proof verified, they form a consistent
	// forward-moving sequence over the bundle's own history, and the newest is
	// within the staleness threshold.
	OK bool `json:"ok"`
	// Proofs is how many proofs the bundle carried, Verified how many passed.
	Proofs   int `json:"proofs"`
	Verified int `json:"verified"`
	// NewestGenTime is the trusted instant the audit state was last attested to,
	// and Age how long ago that was relative to the verification time.
	NewestGenTime time.Time     `json:"newest_gen_time,omitempty"`
	Age           time.Duration `json:"-"`
	AgeSeconds    float64       `json:"age_seconds,omitempty"`
	// Stale is true when Age exceeds the configured threshold: the CA has stopped
	// proving its audit state is current, so the bundle may describe a state the
	// world has long since moved past.
	Stale bool `json:"stale"`
	// SignaturesSinceProof is how many device signatures the bundle contains
	// beyond the newest proof's head. Those are real and accounted for, but their
	// timing is bounded only from below — they happened after NewestGenTime.
	SignaturesSinceProof int `json:"signatures_since_proof"`
	// IndependentTSA is true when every verified proof came from an external TSA.
	// When false, at least one proof was signed by the HSM under audit, and an
	// adversary holding that HSM could have chosen its genTime freely.
	IndependentTSA bool `json:"independent_tsa"`
	// Findings lists every problem found.
	Findings []string `json:"findings,omitempty"`
	// Notes lists things that are not failures but limit what the result proves.
	Notes []string `json:"notes,omitempty"`
}

// Err renders a failed freshness check as an error, nil when it passed.
func (r *FreshnessResult) Err() error {
	if r.OK {
		return nil
	}
	if len(r.Findings) == 0 {
		return fmt.Errorf("hsm audit freshness verification failed")
	}
	return fmt.Errorf("hsm audit freshness verification failed: %s", strings.Join(r.Findings, "; "))
}

// FreshnessOptions parameterizes the freshness check.
type FreshnessOptions struct {
	// Now is the verifier's clock. Zero means time.Now.
	Now time.Time
	// MaxAge is how old the newest attestation may be before the log counts as
	// outdated. Zero selects DefaultMaxAge; negative disables the staleness check
	// (the sequence is still verified), which an auditor examining a deliberately
	// archived bundle wants.
	MaxAge time.Duration
	// Roots are the TSA trust anchors. When empty, token signatures are still
	// checked against the certificate each token embeds, but nothing establishes
	// that certificate belongs to a TSA the auditor trusts — so a forged token
	// from a self-made TSA would pass. Auditors doing this for real supply them.
	Roots []*x509.Certificate
	// RequireIndependentTSA fails the check when any proof was produced by the
	// in-process TSA, i.e. signed by the HSM being audited.
	RequireIndependentTSA bool
}

// VerifyFreshness checks a bundle's freshness proofs and reports how current the
// audit state has been shown to be.
//
// Each proof is verified in three layers, because each catches a different lie:
//
//  1. The token is genuine — it verifies against the TSA certificate, that
//     certificate chains to a trusted root, and the imprint covers this proof's
//     head. This stops a fabricated or transplanted token.
//  2. The head is real — the device entry number, digest and signature count it
//     names must match what the bundle's own log actually contains at that
//     point, and likewise for the ledger. This stops the CA from getting a
//     genuine timestamp over an invented state.
//  3. The sequence moves forward — later proofs must have later genTimes and
//     cover strictly longer prefixes. This stops old attestations being replayed
//     to make an abandoned log look maintained.
//
// Only then does the staleness threshold apply.
func VerifyFreshness(b *Bundle, opts FreshnessOptions) *FreshnessResult {
	res := &FreshnessResult{OK: true, IndependentTSA: true}
	fail := func(format string, args ...any) {
		res.OK = false
		res.Findings = append(res.Findings, fmt.Sprintf(format, args...))
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	maxAge := opts.MaxAge
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	if b == nil {
		fail("no bundle supplied")
		return res
	}
	res.Proofs = len(b.Freshness)

	if len(opts.Roots) == 0 {
		res.Notes = append(res.Notes, "no TSA trust anchors supplied (-tsa-roots): each token was checked against "+
			"the certificate it embeds, but nothing shows that certificate belongs to a timestamp authority you trust, "+
			"so a token minted by an authority the CA controls would pass")
	}

	if len(b.Freshness) == 0 {
		fail("the bundle carries no freshness proofs: nothing establishes when this audit state was current, " +
			"so it may be an arbitrarily old snapshot taken before an abuse")
		return res
	}

	// Index the bundle's own history so each proof's head can be checked against
	// it rather than taken on faith. runningSignatures[n] is the number of
	// successful signatures in entries up to and including device entry n.
	digestByNumber := make(map[uint16]string, len(b.LogEntries))
	runningSignatures := make(map[uint16]int, len(b.LogEntries))
	sigs := 0
	for _, e := range b.LogEntries {
		if _, isSign := hsm.SignCommands[e.Command]; isSign && signSucceeded(e) {
			sigs++
		}
		digestByNumber[e.Number] = strings.ToLower(e.Hash)
		runningSignatures[e.Number] = sigs
	}
	ledgerHashBySeq := make(map[int64]string, len(b.Ledger))
	for _, l := range b.Ledger {
		ledgerHashBySeq[l.Seq] = strings.ToLower(l.Hash)
	}

	proofs := append([]FreshnessProof(nil), b.Freshness...)
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].Seq < proofs[j].Seq })

	var newest *FreshnessProof
	var prev *FreshnessProof
	for i := range proofs {
		p := &proofs[i]
		label := fmt.Sprintf("freshness proof %d", p.Seq)

		if err := verifyProofToken(p, opts.Roots, now); err != nil {
			fail("%s: %v", label, err)
			continue
		}

		// Layer 2: the attested head must describe this bundle's actual history.
		if !strings.EqualFold(p.Head.DeviceSerial, b.Device.Serial) {
			fail("%s attests to device %q but the bundle is from %q", label, p.Head.DeviceSerial, b.Device.Serial)
			continue
		}
		if !strings.EqualFold(p.Head.Anchor, b.Anchor) {
			fail("%s attests to anchor %s but the bundle's is %s: the proof belongs to a different device history",
				label, strings.ToLower(p.Head.Anchor), strings.ToLower(b.Anchor))
			continue
		}
		if p.Head.DeviceNumber != 0 {
			have, ok := digestByNumber[p.Head.DeviceNumber]
			switch {
			case !ok:
				fail("%s attests to device log entry %d, which the bundle does not contain: "+
					"entries the CA had already timestamped are missing from this export",
					label, p.Head.DeviceNumber)
				continue
			case !strings.EqualFold(have, p.Head.DeviceDigest):
				fail("%s attests to digest %s for device log entry %d but the bundle has %s: "+
					"the log was rewritten after it was timestamped",
					label, strings.ToLower(p.Head.DeviceDigest), p.Head.DeviceNumber, have)
				continue
			case runningSignatures[p.Head.DeviceNumber] != p.Head.Signatures:
				fail("%s attests to %d signature(s) at device log entry %d but the bundle's log contains %d: "+
					"the timestamped state does not match the exported one",
					label, p.Head.Signatures, p.Head.DeviceNumber, runningSignatures[p.Head.DeviceNumber])
				continue
			}
		}
		if p.Head.LedgerSeq != 0 {
			have, ok := ledgerHashBySeq[p.Head.LedgerSeq]
			switch {
			case !ok:
				fail("%s attests to ledger entry %d, which the bundle does not contain: "+
					"ledger rows the CA had already timestamped were deleted", label, p.Head.LedgerSeq)
				continue
			case !strings.EqualFold(have, p.Head.LedgerHash):
				fail("%s attests to hash %s for ledger entry %d but the bundle has %s: "+
					"the ledger was rewritten after it was timestamped",
					label, strings.ToLower(p.Head.LedgerHash), p.Head.LedgerSeq, have)
				continue
			}
		}

		// Layer 3: the sequence must move forward on both clocks and both chains.
		if prev != nil {
			if p.GenTime.Before(prev.GenTime) {
				fail("%s has genTime %s, earlier than proof %d's %s: the attestation sequence goes backwards",
					label, p.GenTime.UTC().Format(time.RFC3339), prev.Seq, prev.GenTime.UTC().Format(time.RFC3339))
			}
			if p.Head.DeviceNumber < prev.Head.DeviceNumber || p.Head.LedgerSeq < prev.Head.LedgerSeq ||
				p.Head.Signatures < prev.Head.Signatures {
				fail("%s covers less history than proof %d (device entry %d/ledger %d/%d signature(s) "+
					"versus %d/%d/%d): an earlier state was re-attested, which would let an abandoned log look maintained",
					label, prev.Seq,
					p.Head.DeviceNumber, p.Head.LedgerSeq, p.Head.Signatures,
					prev.Head.DeviceNumber, prev.Head.LedgerSeq, prev.Head.Signatures)
			}
		}

		if p.Source == "" {
			res.IndependentTSA = false
			if opts.RequireIndependentTSA {
				fail("%s was produced by the CA's own in-process TSA, which signs with the HSM under audit: "+
					"an adversary holding that HSM could choose its genTime, so it does not prove freshness "+
					"against the threat this subsystem exists for", label)
			}
		}

		res.Verified++
		prev = p
		if newest == nil || p.GenTime.After(newest.GenTime) {
			newest = p
		}
	}

	if newest == nil {
		fail("no freshness proof verified: the bundle's age cannot be established")
		return res
	}

	res.NewestGenTime = newest.GenTime.UTC()
	res.Age = now.Sub(res.NewestGenTime)
	res.AgeSeconds = res.Age.Seconds()
	res.SignaturesSinceProof = sigs - newest.Head.Signatures

	if maxAge > 0 && res.Age > maxAge {
		res.Stale = true
		fail("the audit state was last attested to at %s, %s ago, which exceeds the %s freshness threshold: "+
			"this export may be an outdated snapshot and says nothing about what the HSM has signed since",
			res.NewestGenTime.Format(time.RFC3339), roundDuration(res.Age), roundDuration(maxAge))
	}
	if res.SignaturesSinceProof > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%d signature(s) were performed after the newest attestation at %s; they are accounted for by the ledger, "+
				"but their timing is bounded only from below",
			res.SignaturesSinceProof, res.NewestGenTime.Format(time.RFC3339)))
	}
	if !res.IndependentTSA && !opts.RequireIndependentTSA {
		res.Notes = append(res.Notes, "at least one proof came from the CA's own in-process TSA, which signs with the "+
			"HSM under audit; it establishes freshness against an outside attacker but not against an operator "+
			"holding the HSM. Configure an external TSA (yubihsm.audit_freshness_tsa_url) for that.")
	}
	return res
}

// roundDuration renders a duration at a resolution an operator reads easily.
func roundDuration(d time.Duration) time.Duration {
	switch {
	case d > 48*time.Hour:
		return d.Round(time.Hour)
	case d > time.Hour:
		return d.Round(time.Minute)
	default:
		return d.Round(time.Second)
	}
}
