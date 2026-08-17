package hsmaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa/tstinfo"
)

// Binding the audit log to the device that produced it (Task 178).
//
// Everything else in this package reasons about a log the device cannot sign.
// A YubiHSM 2 audit entry is sixteen bytes of fields plus a sixteen-byte digest
// chained over its predecessor, and that is all: no serial number, no key, no
// signature. The chain proves the entries are self-consistent. It does not prove
// they came from anywhere. A complete, internally flawless log can be fabricated
// offline in a few lines of Python, and Yubico's marketing claim that each row is
// signed has no command behind it (Yubico/yubihsm-shell#479, open since July
// 2025).
//
// Two mechanisms already narrow that gap and neither closes it:
//
//   - The pinned genesis anchor (genesis.go) is a value the auditor recorded at
//     commissioning. It is trust-on-first-use: it works, but the auditor has to
//     have been there.
//   - The freshness proofs (freshness.go) are RFC 3161 tokens over the audit
//     head. They say *when* a head existed. The TSA has never seen the device and
//     signs whatever digest it is handed, so a token over a fabricated head is
//     just as genuine as one over a real head.
//
// So until now the sentence "device 31650425 produced this log" had exactly one
// source: the CA operator, who is the party being audited.
//
// # The construction
//
// The device does hold one key whose output a third party can verify without
// ever touching it: the factory attestation key at object 0, whose certificate
// chains to Yubico's published attestation PKI. Certificates it signs carry
// device-asserted extensions, two of which matter here — the device serial
// (1.3.6.1.4.1.41482.4.2) and the attested object's 40-byte label
// (1.3.6.1.4.1.41482.4.9), which is host-supplied at key generation.
//
// A commitment is therefore: generate a throwaway key whose *label is a digest
// of the current audit head*, attest it with the factory key, delete it, and
// keep the certificate. The result is a statement
//
//	YubiHSM serial N asserts an object labelled H
//
// signed by a key that never left genuine Yubico hardware, where H commits to
// the device log tail, the ledger head, the signature count and the genesis
// anchor all at once.
//
// # Together with the timestamp
//
// The attestation certificate carries no date of its own: a clockless YubiHSM
// copies the attesting certificate's fixed 2017..2071 validity into every
// certificate it generates. So the commitment alone says a serial-bound
// assertion exists, not when it was made — which would let an operator
// pre-generate commitments. The RFC 3161 token in each Commitment closes that:
// its imprint is over the certificate's own DER, so a third party learns
//
//	YubiHSM serial N asserted head H, and that assertion existed at time T.
//
// That is the composition this file exists for. Each half is useless alone: the
// timestamp dates a statement nobody made, the attestation makes a statement
// nobody can date.
//
// # What it does not prove
//
// This is an operator commitment, not device-attested log authenticity. The
// label is whatever the host passed in; the HSM does not know it is attesting
// its own log state. A dishonest operator can fabricate a log, digest the
// fabrication and commit to that digest exactly as easily as an honest one.
//
// What it does establish, verifiably and transferably:
//
//   - A device with serial N was physically present when the commitment was made,
//     and N is Yubico-rooted rather than operator-asserted.
//   - That device committed to this specific head at a time a TSA witnessed.
//   - Because generating, attesting and deleting the commitment key are
//     themselves force-audited commands, each commitment leaves entries in the log
//     immediately after the head it committed to — and the next commitment's head
//     folds them in. The commitments are welded into the very chain they attest
//     to, so they cannot be produced out of band or reordered afterwards.
//
// The third point is why VerifyCommitments insists on finding those markers. It
// is what turns a sequence of independent snapshots into a ratchet.

// The label is the whole channel, so its layout is fixed by arithmetic rather
// than taste. A YubiHSM object label is exactly 40 bytes. The prefix takes four
// and the remaining thirty-six hold a base64url-encoded 27-byte truncation of
// the head digest — 36 characters is exactly what 27 bytes encode to, so the
// label is 40 characters with no padding on either side. That matters twice
// over: the device NUL-pads short labels to 40 bytes and strips the padding on
// the way back out, and a full-width label never enters that round trip.
//
// 216 bits is far past what a second-preimage on the head needs; the point of
// spending the whole field is that there is nothing else to spend it on.
const (
	// CommitmentLabelPrefix marks a device label as an audit-head commitment.
	CommitmentLabelPrefix = "sb1:"
	// CommitmentDigestBytes is how much of the head digest the label carries.
	CommitmentDigestBytes = 27
	// CommitmentLabelLen is the resulting label width, which is also the device's
	// label field width.
	CommitmentLabelLen = 40
)

// The commitment key lives in a reserved object-id range so the audit log
// distinguishes these three operations from work done with production keys at a
// glance — and so that verification can insist a commitment was not made by
// borrowing a CA key's handle, which would make the log entries against that
// handle ambiguous.
const (
	// CommitmentKeyIDMin and CommitmentKeyIDMax bound the reserved range.
	CommitmentKeyIDMin uint16 = 0xfb00
	CommitmentKeyIDMax uint16 = 0xfbff
	// DefaultCommitmentKeyID is the slot used unless a deployment picks another
	// within the range.
	DefaultCommitmentKeyID uint16 = 0xfb00
)

// CommitmentInterval is the default cadence for the commitment job.
//
// It matches FreshnessInterval because the two halves are only worth as much as
// the more stale of them: a head timestamped six hours ago but last bound to a
// device serial a month ago is bounded in time by the timestamp and bound to
// hardware by nothing more recent than the month-old assertion. Commitments cost
// at least three device log entries each plus session overhead, which is the real
// constraint — the ring holds 62 — so this is not a knob to turn down without
// also shortening the collector's interval.
const CommitmentInterval = 6 * time.Hour

// CommitmentLabel renders the device label that commits to a head.
//
// The digest is taken over exactly the bytes the freshness proof's timestamp
// imprint covers (Head.Message), so a commitment and a freshness proof over the
// same head are demonstrably about the same state — the label is a truncation of
// the very value the TSA signed. That is what lets the two mechanisms be read as
// one statement rather than two adjacent ones.
func CommitmentLabel(h Head) string {
	sum := sha256.Sum256(h.Message())
	return CommitmentLabelPrefix + base64.RawURLEncoding.EncodeToString(sum[:CommitmentDigestBytes])
}

// Commitment is one device-signed, timestamped binding of an audit head to a
// device serial number.
type Commitment struct {
	// Seq is a gap-free monotonic counter over commitments.
	Seq int64 `json:"seq"`
	// Head is the audit state committed to. A verifier recomputes the label from
	// it rather than trusting Label, and checks it against the bundle's own log.
	Head Head `json:"head"`
	// Label is CommitmentLabel(Head) as submitted to the device. It is stored so a
	// mismatch can name both values; verification recomputes it.
	Label string `json:"label"`
	// ObjectID is the reserved handle the throwaway key occupied. It appears in
	// the attestation certificate as the device's own assertion and in the log as
	// the target of the three operations the commitment performed.
	ObjectID uint16 `json:"object_id"`
	// CertificatePEM is the attestation certificate the device signed over the
	// throwaway key. This is the commitment itself.
	CertificatePEM string `json:"certificate_pem"`
	// DeviceCertificatePEM is the device's factory attestation certificate, read
	// from opaque object 0. It issues CertificatePEM and is the link to Yubico's
	// PKI, so it travels with the commitment: an auditor cannot read it off a
	// device they do not have.
	DeviceCertificatePEM string `json:"device_certificate_pem,omitempty"`
	// CreatedAt is the CA's own clock when the commitment was made.
	// Informational; nothing in verification trusts it.
	CreatedAt time.Time `json:"created_at"`

	// GenTime is the instant the TSA asserts for the certificate, extracted from
	// Token. A verifier re-derives it rather than reading this field.
	GenTime time.Time `json:"gen_time,omitempty"`
	// Source is "" for the in-process TSA and the URL for an external one. The
	// distinction matters exactly as much as it does for a freshness proof: the
	// in-process TSA signs with the HSM under audit.
	Source string `json:"source,omitempty"`
	// Token is the DER RFC 3161 TimeStampToken whose imprint is SHA-256 over the
	// attestation certificate's DER. Without it the commitment is undated, and
	// undated commitments can be produced in a batch ahead of time.
	Token []byte `json:"token,omitempty"`
}

// Certificate parses the commitment's attestation certificate.
func (c *Commitment) Certificate() (*x509.Certificate, error) {
	return c.attestation().Certificate()
}

// CertificateDER returns the DER the timestamp token's imprint is taken over.
func (c *Commitment) CertificateDER() ([]byte, error) {
	block, _ := pem.Decode([]byte(c.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("commitment certificate is not a PEM CERTIFICATE block")
	}
	return block.Bytes, nil
}

// attestation adapts the commitment to the shape hsmattest.Verify consumes, so
// the per-key attestation verifier is reused rather than reimplemented. The two
// certificates are produced by the same device command and carry the same seven
// extensions; only the question asked of them differs.
func (c *Commitment) attestation() *hsmattest.Attestation {
	return &hsmattest.Attestation{
		KeyLabel:             c.Label,
		CertificatePEM:       c.CertificatePEM,
		DeviceCertificatePEM: c.DeviceCertificatePEM,
		ProducedAt:           c.CreatedAt,
	}
}

// Committer produces one serial-bound commitment on the device.
//
// It is an interface for the same reason KeyAttester is: the export and
// verification paths must be exercisable against a fixture, and a Service built
// without one simply produces bundles with no commitments — which the verifier
// then reports as an unbound log rather than silently accepting.
type Committer interface {
	// CommitHead generates a throwaway key labelled label at objectID, attests it
	// with the device's factory attestation key, deletes it, and returns the
	// attestation.
	//
	// It may return a non-nil attestation *and* a non-nil error, and a caller must
	// keep the attestation when it does. That combination means the commitment
	// itself succeeded but the device was left in a state an operator should
	// attend to — the throwaway key could not be deleted, say. Discarding the
	// attestation then would throw away evidence the device has already logged
	// producing, which is strictly worse than an inert key in a reserved slot.
	CommitHead(ctx context.Context, objectID uint16, label string) (*hsmattest.Attestation, error)
}

// HardwareCommitter is the production Committer, reaching the YubiHSM through
// the native driver.
type HardwareCommitter struct {
	Cfg hsm.Config
	// AttestKeyID selects the attesting key; 0 (the default) is the
	// factory-provisioned one. Only that one chains to Yubico's PKI, so only that
	// one makes the serial in the certificate an assertion by Yubico-rooted
	// hardware rather than by whoever installed a replacement.
	AttestKeyID uint16
	// Capabilities is the throwaway key's capability mask; 0 (the default) gives
	// it none at all. See hsm.CommitmentRequest.Capabilities.
	Capabilities uint64
}

// NewHardwareCommitter returns a Committer backed by an attached YubiHSM.
func NewHardwareCommitter(cfg hsm.Config) *HardwareCommitter { return &HardwareCommitter{Cfg: cfg} }

// CommitHead implements Committer.
func (h *HardwareCommitter) CommitHead(ctx context.Context, objectID uint16, label string) (*hsmattest.Attestation, error) {
	certPEM, deviceCertPEM, err := hsm.CommitAuditHead(ctx, h.Cfg, hsm.CommitmentRequest{
		ObjectID:       objectID,
		Label:          label,
		ReservedPrefix: CommitmentLabelPrefix,
		AttestKeyID:    h.AttestKeyID,
		Capabilities:   h.Capabilities,
	})
	if certPEM == "" {
		return nil, err
	}
	// err may be non-nil here: the device signed the commitment but something
	// afterwards (the delete) went wrong. See the Committer contract.
	return &hsmattest.Attestation{
		KeyLabel:             label,
		CertificatePEM:       certPEM,
		DeviceCertificatePEM: deviceCertPEM,
		ProducedAt:           time.Now().UTC(),
	}, err
}

var _ Committer = (*HardwareCommitter)(nil)

// Commit binds the current audit head to the device's serial number and dates
// the binding, then stores the result.
//
// The order is load-bearing:
//
//  1. Drain the device log, so the head being committed to is the current one.
//     Committing to a stale head would leave the most recent signatures — the
//     window an abuser would aim for — outside every commitment.
//  2. Compute the head and its label, and have the device attest a key carrying
//     that label. This is the serial binding.
//  3. Check the device's own assertions against what was asked for. A device
//     that attests a different label, object or serial than the one requested is
//     not a record to keep for later analysis; it is a reason to stop.
//  4. Obtain the RFC 3161 token over the certificate. This is the date.
//  5. Store — whether or not step 4 succeeded. The device wrote its log entries
//     in step 2 and they cannot be taken back, so a record that omits the binding
//     leaves the log with operations nothing accounts for. An undated commitment
//     is not evidence and verification says so, but it is a truthful account of
//     what the device did, which a missing row is not.
//  6. Drain again. Step 2's operations are force-audited, so the log now holds
//     the markers that weld this commitment into the chain — and storing them
//     here means the very next export carries them rather than trailing them into
//     the one after.
//
// It returns a non-nil commitment together with a non-nil error when the binding
// was made and recorded but something around it failed: the date could not be
// obtained, or the device was left holding the throwaway key. Callers must treat
// that as a warning about the deployment rather than as a lost commitment.
func (s *Service) Commit(ctx context.Context, ts Timestamper) (*Commitment, error) {
	if s.committer == nil {
		return nil, fmt.Errorf("no committer configured: binding the audit log to the device serial needs a " +
			"YubiHSM that can attest a key (see docs/hsm/audit-log.md)")
	}
	objectID := s.commitKeyID
	if objectID == 0 {
		objectID = DefaultCommitmentKeyID
	}
	if objectID < CommitmentKeyIDMin || objectID > CommitmentKeyIDMax {
		return nil, fmt.Errorf("commitment key id 0x%04x is outside the reserved range 0x%04x..0x%04x",
			objectID, CommitmentKeyIDMin, CommitmentKeyIDMax)
	}

	c := NewCollector(s.dev, s.store, 0, nil)
	if s.dev != nil {
		if _, err := c.Collect(ctx); err != nil {
			return nil, fmt.Errorf("draining device log before committing to its head: %w", err)
		}
	}

	head, err := s.currentHead(ctx)
	if err != nil {
		return nil, err
	}
	label := CommitmentLabel(head)

	att, deviceErr := s.committer.CommitHead(ctx, objectID, label)
	if att == nil {
		return nil, fmt.Errorf("obtaining a device-signed commitment to the audit head: %w", deviceErr)
	}
	com := &Commitment{
		Head:                 head,
		Label:                label,
		ObjectID:             objectID,
		CertificatePEM:       att.CertificatePEM,
		DeviceCertificatePEM: att.DeviceCertificatePEM,
		CreatedAt:            s.now().UTC(),
	}
	// A certificate that binds a label other than the one asked for binds nothing,
	// so this is the one failure worth discarding the commitment over: recording
	// it would put a provably meaningless certificate in the audit record.
	if err := checkCommitmentClaims(com, head.DeviceSerial); err != nil {
		return nil, err
	}

	dateErr := s.dateCommitment(ctx, com, ts)

	if err := s.store.AppendCommitment(ctx, com); err != nil {
		return nil, fmt.Errorf("storing the audit-head commitment: %w", err)
	}
	if s.dev != nil {
		if _, err := c.Collect(ctx); err != nil {
			return com, fmt.Errorf("draining the log entries the commitment produced: %w", err)
		}
	}
	switch {
	case dateErr != nil:
		return com, fmt.Errorf("device %s bound itself to the audit head, and the binding was recorded, but it "+
			"could not be dated: %w. An undated binding is not evidence — an attestation certificate copies the "+
			"attesting certificate's fixed 2017..2071 validity, so nothing in it says when it was made — so the "+
			"next run must succeed for this stretch of history to be covered", head.DeviceSerial, dateErr)
	case deviceErr != nil:
		return com, fmt.Errorf("the commitment was made and recorded, but the device needs attention: %w", deviceErr)
	}
	return com, nil
}

// dateCommitment obtains and validates the RFC 3161 token over the commitment's
// certificate, leaving com undated when it cannot.
//
// It validates before keeping, for the same reason Timestamp does: a token that
// does not cover this certificate is not a date, and storing one would leave a
// record that fails verification later with no way to tell whether the authority
// misbehaved or the row was edited. Storing nothing is the honest alternative,
// and verification reports an undated binding for what it is.
func (s *Service) dateCommitment(ctx context.Context, com *Commitment, ts Timestamper) error {
	if ts == nil {
		return fmt.Errorf("no timestamp authority configured")
	}
	der, err := com.CertificateDER()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(der)
	token, genTime, err := ts.Timestamp(ctx, sum[:])
	if err != nil {
		return err
	}
	com.Token, com.GenTime, com.Source = token, genTime.UTC(), ts.Source()
	if err := verifyCommitmentToken(com, nil, time.Time{}); err != nil {
		com.Token, com.GenTime, com.Source = nil, time.Time{}, ""
		return fmt.Errorf("the timestamp authority returned an unusable token: %w", err)
	}
	return nil
}

// checkCommitmentClaims verifies that the device asserted what it was asked to
// assert, at commit time rather than at audit time.
func checkCommitmentClaims(com *Commitment, wantSerial string) error {
	cert, err := com.Certificate()
	if err != nil {
		return fmt.Errorf("the device returned an unusable commitment certificate: %w", err)
	}
	claims, err := hsmattest.ParseClaims(cert)
	if err != nil {
		return fmt.Errorf("the device returned a certificate with no YubiHSM attestation extensions: %w", err)
	}
	if claims.Label != com.Label {
		return fmt.Errorf("the device attested label %q, not the commitment %q: the certificate does not bind the audit head",
			claims.Label, com.Label)
	}
	if claims.ObjectID != com.ObjectID {
		return fmt.Errorf("the device attested object 0x%04x, not the commitment key 0x%04x",
			claims.ObjectID, com.ObjectID)
	}
	if wantSerial != "" && !strings.EqualFold(strings.TrimSpace(claims.DeviceSerial), strings.TrimSpace(wantSerial)) {
		return fmt.Errorf("the commitment was signed by device %s but the audit state belongs to device %s: "+
			"a different HSM is attached", claims.DeviceSerial, wantSerial)
	}
	return nil
}

// verifyCommitmentToken validates a commitment's RFC 3161 token: the CMS
// signature, that the imprint covers this commitment's certificate, the signer's
// time-stamping EKU, and — when roots are supplied — that the TSA certificate
// chains to one of them at genTime.
//
// A zero now skips the future-genTime bound, which is what Commit wants: it has
// just obtained the token and has no independent clock to judge it against.
func verifyCommitmentToken(com *Commitment, roots []*x509.Certificate, now time.Time) error {
	if len(com.Token) == 0 {
		return fmt.Errorf("commitment carries no timestamp token")
	}
	der, err := com.CertificateDER()
	if err != nil {
		return err
	}

	parsed, err := cms.ParseSignedData(com.Token)
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
	info, err := tstinfo.ParseTokenInfo(com.Token)
	if err != nil {
		return err
	}
	if !info.Hash.Available() {
		return fmt.Errorf("token imprint hash %v is not available to this verifier", info.Hash)
	}
	h := info.Hash.New()
	h.Write(der)
	if !bytes.Equal(h.Sum(nil), info.HashedMessage) {
		return fmt.Errorf("timestamp token does not cover this commitment's certificate: " +
			"the token was obtained for something else, so the commitment is undated")
	}
	if !now.IsZero() && info.GenTime.After(now.Add(freshnessClockSkew)) {
		return fmt.Errorf("token genTime %s is in the future", info.GenTime.UTC().Format(time.RFC3339))
	}
	if !com.GenTime.IsZero() && !com.GenTime.UTC().Truncate(time.Second).Equal(info.GenTime.UTC().Truncate(time.Second)) {
		return fmt.Errorf("recorded genTime %s does not match the token's %s: the record was altered",
			com.GenTime.UTC().Format(time.RFC3339), info.GenTime.UTC().Format(time.RFC3339))
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

// CommitmentOptions parameterizes the serial-binding check.
type CommitmentOptions struct {
	// Now is the verifier's clock. Zero means time.Now.
	Now time.Time
	// MaxAge is how old the newest commitment may be. Zero selects DefaultMaxAge;
	// negative disables the staleness check while still verifying the sequence.
	MaxAge time.Duration
	// TSARoots anchor the timestamp tokens. Without them a token minted by an
	// authority the CA controls would date a commitment to whatever it liked.
	TSARoots []*x509.Certificate
	// RequireIndependentTSA rejects commitments dated by the CA's own in-process
	// TSA, which signs with the HSM under audit.
	RequireIndependentTSA bool
	// AttestationPolicy overrides the trust anchors and chain requirement applied
	// to the commitment certificates. Nil applies hsmattest.DefaultPolicy, which
	// anchors to Yubico's embedded roots. The label, object id and serial
	// expectations are always set from the commitment and cannot be overridden:
	// those are the binding rather than the policy.
	AttestationPolicy *hsmattest.Policy
}

// CommitmentResult is the verdict on a bundle's serial bindings.
type CommitmentResult struct {
	// OK is true when at least one commitment verified, the sequence moves
	// forward over the bundle's own history, each is welded into the log, and the
	// newest is within the staleness threshold.
	OK bool `json:"ok"`
	// Commitments is how many the bundle carried, Verified how many passed, and
	// Undated how many were skipped because no timestamp authority dated them.
	// An undated binding is not counted as evidence; see VerifyCommitments.
	Commitments int `json:"commitments"`
	Verified    int `json:"verified"`
	Undated     int `json:"undated,omitempty"`
	// DeviceSerial is the serial the *device* asserted in a verified commitment,
	// as distinct from the serial the bundle claims. When SerialBound is true the
	// two agree and the log is bound to Yubico-rooted hardware.
	DeviceSerial string `json:"device_serial,omitempty"`
	SerialBound  bool   `json:"serial_bound"`
	// TrustAnchor names the attestation root the device certificate reached.
	TrustAnchor string `json:"trust_anchor,omitempty"`
	// NewestGenTime is the trusted instant of the newest verified commitment, and
	// Age how long ago that was.
	NewestGenTime time.Time     `json:"newest_gen_time,omitempty"`
	Age           time.Duration `json:"-"`
	AgeSeconds    float64       `json:"age_seconds,omitempty"`
	// Stale is true when Age exceeds the threshold: the device has not bound
	// itself to this log recently, so the recent history is device-unbound even
	// though the older part is not.
	Stale bool `json:"stale"`
	// SignaturesSinceCommitment is how many device signatures the bundle contains
	// beyond the newest commitment's head.
	SignaturesSinceCommitment int `json:"signatures_since_commitment"`
	// IndependentTSA is true when every verified commitment was dated by an
	// external authority.
	IndependentTSA bool     `json:"independent_tsa"`
	Findings       []string `json:"findings,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// Err renders a failed commitment check as an error, nil when it passed.
func (r *CommitmentResult) Err() error {
	if r == nil || r.OK {
		return nil
	}
	if len(r.Findings) == 0 {
		return fmt.Errorf("hsm audit log is not bound to the device that produced it")
	}
	return fmt.Errorf("hsm audit log is not bound to the device that produced it: %s", strings.Join(r.Findings, "; "))
}

// VerifyCommitments checks that the device itself has bound this log to its
// serial number, and that a timestamp authority dated each binding.
//
// Each commitment is checked in five layers, because each catches a different
// lie:
//
//  1. The certificate is a genuine YubiHSM attestation — signed by the
//     accompanying device attestation certificate, which chains to a trusted
//     attestation root. This is what makes the serial an assertion by hardware
//     Yubico vouches for rather than a string in a JSON file.
//  2. It commits to *this* head — the attested label equals the label recomputed
//     from the commitment's own head fields, and the object id is inside the
//     reserved commitment range. A commitment made with a production key's handle
//     would make the log entries against that handle ambiguous.
//  3. The head is real — device entry number, chain digest, signature count and
//     ledger head must match what the bundle's own log actually contains there.
//     This is the same check the freshness proofs get, for the same reason: a
//     device will happily attest a label committing to a state that never
//     existed.
//  4. It is welded into the log — the log must show the commitment key generated
//     at that handle after the committed entry. Since a later commitment's head
//     folds those entries in, the sequence forms a ratchet rather than a set of
//     detachable snapshots.
//  5. It is dated — an RFC 3161 token whose imprint covers the certificate's own
//     DER. Attestation certificates carry a fixed 2017..2071 validity copied from
//     the attesting certificate, so without this a commitment could have been
//     minted at any time, including in a batch prepared in advance.
//
// Only then does the sequence check (forward-moving on both chains and the
// clock) and the staleness threshold apply.
func VerifyCommitments(b *Bundle, opts CommitmentOptions) *CommitmentResult {
	res := &CommitmentResult{OK: true, IndependentTSA: true}
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
	res.Commitments = len(b.Commitments)

	if len(opts.TSARoots) == 0 {
		res.Notes = append(res.Notes, "no TSA trust anchors supplied (-tsa-roots): each commitment's date was "+
			"checked against the certificate its token embeds, but nothing shows that certificate belongs to a "+
			"timestamp authority you trust, so a commitment dated by an authority the CA controls would pass")
	}

	if len(b.Commitments) == 0 {
		fail("the bundle carries no device-signed commitments: nothing but the CA's own word connects this log to "+
			"device %s. A YubiHSM audit log carries no serial number and no signature, so an internally consistent "+
			"log can be fabricated offline; only a commitment signed by the device's factory attestation key ties "+
			"one to real hardware", b.Device.Serial)
		return res
	}

	ix := indexBundle(b)
	pol := hsmattest.DefaultPolicy()
	if opts.AttestationPolicy != nil {
		pol = *opts.AttestationPolicy
	}
	markers := newMarkerSet(b.LogEntries)

	commitments := append([]Commitment(nil), b.Commitments...)
	sort.Slice(commitments, func(i, j int) bool { return commitments[i].Seq < commitments[j].Seq })

	var newest, prev *Commitment
	for i := range commitments {
		com := &commitments[i]
		label := fmt.Sprintf("commitment %d", com.Seq)

		// Claim this commitment's log marker before anything else can reject it.
		// The claim is bookkeeping for the converse check below — a marker nobody
		// claimed is a binding missing from the record — and a commitment that
		// fails a later layer is present, not missing. Deciding that here rather
		// than after the checks is what stops one problem being reported as two.
		markerErr := markers.claim(com, label)

		// Layer 2 (first, because it decides what layer 1 is asked to confirm):
		// the label the device must have attested is recomputed here, never read
		// from the record.
		want := CommitmentLabel(com.Head)
		if com.ObjectID < CommitmentKeyIDMin || com.ObjectID > CommitmentKeyIDMax {
			fail("%s was made with object 0x%04x, outside the reserved commitment range 0x%04x..0x%04x: "+
				"a commitment made with a production key's handle makes the log entries against that handle ambiguous",
				label, com.ObjectID, CommitmentKeyIDMin, CommitmentKeyIDMax)
			continue
		}

		// Layer 1: a genuine YubiHSM attestation asserting exactly that label,
		// that object and the bundle's device.
		keyPol := pol
		keyPol.ExpectedLabel = want
		id := com.ObjectID
		keyPol.ExpectedObjectID = &id
		keyPol.ExpectedSerial = b.Device.Serial
		keyPol.ExpectedPublicKey = nil
		vr := hsmattest.Verify(com.attestation(), keyPol)
		if !vr.Verified {
			// Name the label mismatch explicitly. It is the failure that means
			// "this certificate does not commit to this history", as opposed to
			// the generic "the attestation did not verify". A certificate that did
			// not parse at all has no attested label to compare, so it falls
			// through to the problems hsmattest reported.
			if vr.KeyLabel != "" && vr.KeyLabel != want {
				fail("%s: the device attested the label %q but this record's head hashes to %q — "+
					"the certificate commits to a different audit state than the one recorded beside it",
					label, vr.KeyLabel, want)
			} else {
				fail("%s: %s", label, strings.Join(vr.Problems, "; "))
			}
			continue
		}
		if res.TrustAnchor == "" {
			res.TrustAnchor = vr.TrustAnchor
		}

		// Layer 3: the head must describe this bundle's actual history. The serial
		// the device asserted needs no separate check here — the policy above
		// forced it to the bundle's, and checkHead forces the head's to the same
		// value, so a disagreement between the certificate and the state it is
		// filed against surfaces as one of those two.
		if err := ix.checkHead(com.Head, b, label); err != nil {
			fail("%v", err)
			continue
		}

		// Layer 4: the commitment's own operations must appear in the log after
		// the entry it committed to.
		if markerErr != nil {
			fail("%v", markerErr)
			continue
		}

		// Layer 5: the date. An undated binding is not a lie, it is simply not
		// evidence — the certificate cannot say when it was made, so the binding
		// bounds nothing in time. Skipping it with a note rather than failing is
		// what keeps one unreachable timestamp authority from making every later
		// export unverifiable: the verdict then rests on the dated bindings, and
		// if none is dated the "no commitment verified" failure below is reached.
		if len(com.Token) == 0 {
			res.Undated++
			res.Notes = append(res.Notes, fmt.Sprintf(
				"%s carries no timestamp, so it establishes nothing about time: an attestation certificate copies "+
					"the attesting certificate's fixed 2017..2071 validity and could have been minted at any moment. "+
					"It is not counted as a binding", label))
			continue
		}
		if err := verifyCommitmentToken(com, opts.TSARoots, now); err != nil {
			fail("%s: %v", label, err)
			continue
		}
		if com.Source == "" {
			res.IndependentTSA = false
			if opts.RequireIndependentTSA {
				fail("%s was dated by the CA's own in-process TSA, which signs with the HSM under audit: "+
					"an adversary holding that HSM could choose the instant, so the binding is undated against "+
					"the threat it exists for", label)
			}
		}

		// The sequence must move forward on both chains and the clock, or an older
		// binding could be replayed to make an abandoned log look maintained.
		if prev != nil {
			if com.GenTime.Before(prev.GenTime) {
				fail("%s is dated %s, earlier than commitment %d's %s: the sequence goes backwards",
					label, com.GenTime.UTC().Format(time.RFC3339), prev.Seq, prev.GenTime.UTC().Format(time.RFC3339))
			}
			if com.Head.DeviceNumber < prev.Head.DeviceNumber || com.Head.LedgerSeq < prev.Head.LedgerSeq ||
				com.Head.Signatures < prev.Head.Signatures {
				fail("%s covers less history than commitment %d (device entry %d/ledger %d/%d signature(s) versus "+
					"%d/%d/%d): an earlier state was re-bound, which would let an abandoned log look maintained",
					label, prev.Seq,
					com.Head.DeviceNumber, com.Head.LedgerSeq, com.Head.Signatures,
					prev.Head.DeviceNumber, prev.Head.LedgerSeq, prev.Head.Signatures)
			}
		}

		res.Verified++
		res.DeviceSerial = vr.DeviceSerial
		prev = com
		if newest == nil || com.GenTime.After(newest.GenTime) {
			newest = com
		}
	}

	// The converse of the marker check: a commitment key created in the log that
	// no commitment in this bundle accounts for. That is either a binding the CA
	// dropped from the record, or — far more often — an attempt that failed after
	// the device had already written its entries, which no amount of later work
	// can retract.
	//
	// It is a note rather than a failure, and the asymmetry is the reason. A
	// dropped binding removes evidence *in the CA's favour*: commitments cover
	// cumulative prefixes, so any later one covers everything a missing one did
	// and more, and a drop between two exports is caught by VerifyContinuation
	// against a bundle the auditor retained. Failing here instead would let one
	// unreachable timestamp authority permanently convert every future export
	// into a tampering accusation, since the device's log entries are append-only
	// and the orphan can never be resolved.
	for _, n := range markers.unclaimed() {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"the log records a commitment key created at device entry %d that no commitment in this bundle "+
				"accounts for: a binding was attempted and is not in the record. Later bindings cover the same "+
				"history, so this weakens nothing on its own — but a bundle that keeps accumulating these is one "+
				"whose commitments are failing", n))
	}

	if newest == nil {
		if res.Undated == res.Commitments {
			fail("device %s bound itself to this log %d time(s) but none of those bindings is dated, so none "+
				"of them bounds anything in time: an attestation certificate carries the attesting certificate's "+
				"fixed 2017..2071 validity and could have been produced at any moment. Configure a reachable "+
				"timestamp authority (yubihsm.audit_freshness_tsa_url)", b.Device.Serial, res.Commitments)
			return res
		}
		fail("no commitment verified: nothing shows that device %s produced this log", b.Device.Serial)
		return res
	}

	res.SerialBound = strings.EqualFold(strings.TrimSpace(res.DeviceSerial), strings.TrimSpace(b.Device.Serial))
	res.NewestGenTime = newest.GenTime.UTC()
	res.Age = now.Sub(res.NewestGenTime)
	res.AgeSeconds = res.Age.Seconds()
	res.SignaturesSinceCommitment = ix.signatures - newest.Head.Signatures

	if maxAge > 0 && res.Age > maxAge {
		res.Stale = true
		fail("the device last bound itself to this log at %s, %s ago, which exceeds the %s threshold: "+
			"everything logged since is connected to device %s by the CA's word alone",
			res.NewestGenTime.Format(time.RFC3339), roundDuration(res.Age), roundDuration(maxAge), b.Device.Serial)
	}
	if res.SignaturesSinceCommitment > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%d signature(s) were performed after the newest commitment at %s; they are accounted for by the ledger, "+
				"but the device has not yet bound itself to a head that includes them",
			res.SignaturesSinceCommitment, res.NewestGenTime.Format(time.RFC3339)))
	}
	if !res.IndependentTSA && !opts.RequireIndependentTSA {
		res.Notes = append(res.Notes, "at least one commitment was dated by the CA's own in-process TSA, which "+
			"signs with the HSM under audit; the serial binding still holds, but its date does not against an "+
			"operator holding that HSM. Configure an external TSA (yubihsm.audit_freshness_tsa_url) for that.")
	}
	return res
}

// markerSet matches commitments to the log entries their own device operations
// left behind, in both directions.
//
// This is what makes the commitments a ratchet rather than a set of detachable
// snapshots. Generating the throwaway key is force-audited, so a genuine
// commitment necessarily leaves an entry naming its reserved handle immediately
// after the head it bound — and the next commitment's head folds that entry in.
//
// The matching is one-to-one and greedy in sequence order, which is what lets
// the two directions both be checked. A commitment with no marker was produced
// somewhere this log does not describe. A marker with no commitment is a binding
// the device signed that was then removed from the record — the move a
// per-commitment check cannot see, because every surviving commitment still
// finds a marker of its own.
//
// It tracks creations rather than attestations because SIGN ATTESTATION
// CERTIFICATE is also how per-key attestations are produced at export time, so
// the creation is the one operation unique to a commitment.
type markerSet struct {
	// creations are the successful commitment-key creations in ascending entry
	// order, each flagged once a commitment has claimed it.
	creations []marker
	// deleted records which commitment handles the log shows being deleted, so a
	// log that kept the deletion but lost the creation is reported as the
	// truncation it is rather than as a plain absence.
	deleted map[uint16]bool
}

type marker struct {
	number   uint16
	objectID uint16
	claimed  bool
}

func newMarkerSet(entries []hsm.AuditLogEntry) *markerSet {
	m := &markerSet{deleted: map[uint16]bool{}}
	for _, e := range entries {
		if e.TargetKey < CommitmentKeyIDMin || e.TargetKey > CommitmentKeyIDMax || !entrySucceeded(e) {
			continue
		}
		switch e.Command {
		case hsm.CmdGenerateAsymmetricKey:
			m.creations = append(m.creations, marker{number: e.Number, objectID: e.TargetKey})
		case hsm.CmdDeleteObject:
			m.deleted[e.TargetKey] = true
		}
	}
	sort.Slice(m.creations, func(i, j int) bool { return m.creations[i].number < m.creations[j].number })
	return m
}

// claim matches com to the earliest unclaimed creation of its handle after the
// entry it committed to.
func (m *markerSet) claim(com *Commitment, label string) error {
	for i := range m.creations {
		c := &m.creations[i]
		if c.claimed || c.number <= com.Head.DeviceNumber || c.objectID != com.ObjectID {
			continue
		}
		c.claimed = true
		return nil
	}
	if m.deleted[com.ObjectID] {
		return fmt.Errorf("%s: the log shows the commitment key 0x%04x deleted but records no matching creation "+
			"after device entry %d: entries are missing, so this commitment cannot be placed in the history it "+
			"claims to bind", label, com.ObjectID, com.Head.DeviceNumber)
	}
	return fmt.Errorf("%s: the log contains no creation of the commitment key 0x%04x after device entry %d. "+
		"Generating it is a force-audited command, so a commitment genuinely made against this device would have "+
		"left that entry — its absence means the certificate was produced somewhere this log does not describe",
		label, com.ObjectID, com.Head.DeviceNumber)
}

// unclaimed returns the creation entries no commitment accounted for.
func (m *markerSet) unclaimed() []uint16 {
	var out []uint16
	for _, c := range m.creations {
		if !c.claimed {
			out = append(out, c.number)
		}
	}
	return out
}
