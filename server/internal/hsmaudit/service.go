package hsmaudit

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// Auditor appends events to the tamper-evident, hash-chained event log.
// Satisfied by *database.DB.
type Auditor interface {
	AppendEvent(e *audit.Event) error
}

// Service ties the pieces together: it provisions a freshly reset device,
// records signatures into the ledger, and produces export bundles.
type Service struct {
	dev      Device
	store    Store
	attester KeyAttester
	auditor  Auditor
	actor    string
	now      func() time.Time
}

// NewService returns a Service over dev and store.
//
// A shell-backed device gets a shell-backed attester automatically, because the
// two are the same YubiHSM reached the same way and an export without key
// attestations is one a verifier will refuse. Callers that want a different
// attester — or none — set it explicitly with SetAttester.
func NewService(dev Device, store Store) *Service {
	s := &Service{dev: dev, store: store, now: time.Now}
	if sd, ok := dev.(*HardwareDevice); ok {
		s.attester = hsmattest.NewDeviceAttester(sd.Cfg)
	}
	return s
}

// SetAttester overrides the key attester. A nil attester produces bundles with
// no attestations, which verification then reports as unconfined keys.
func (s *Service) SetAttester(a KeyAttester) { s.attester = a }

// SetAuditor supplies the hash-chained event log Provision writes the pinned
// chain anchor into.
//
// This is what gives the anchor a time. The anchor itself cannot be shown to
// have come from a genuine factory reset — it is a device-chosen value with no
// derivable relationship to the sentinel it belongs to, see genesis.go — so the
// only thing that can distinguish a real anchor from one invented later is a
// witness that saw it early. The event log is hash-chained and periodically
// timestamped by an RFC 3161 authority (internal/anchor), so an anchor recorded
// there at commissioning time sits behind a third-party signature that an
// operator cannot backdate.
//
// Without an auditor Provision refuses to run, rather than pinning an anchor
// that nothing outside this system ever saw.
func (s *Service) SetAuditor(a Auditor) { s.auditor = a }

// SetActor labels the genesis audit event with whoever ran the commissioning.
// Empty (the default) records "system". Provisioning is always operator-driven,
// so the CLI passes its own actor label; "who commissioned this device" is a
// question the trail should be able to answer.
func (s *Service) SetActor(actor string) { s.actor = actor }

// EnableRecording returns a signature recorder for store when the device has
// been provisioned, and nil when it has not.
//
// Gating on provisioning rather than on a config flag keeps the two halves of
// the proof from drifting apart. The ledger is only meaningful next to a device
// log it can be reconciled against, and that log only exists once the device
// has been commissioned with a pinned anchor. Tying recording to the same fact
// means an operator cannot end up with a device that is force-audited but whose
// signatures are unattributed, nor with a ledger that reconciles against
// nothing — either of which would produce confident-looking verification
// output backed by half an argument.
//
// It needs no device handle: recording is purely a store write on the signing
// path, and going to the HSM there would put the shell on the hot path.
func EnableRecording(ctx context.Context, store Store) (keyprovider.SignatureRecorder, error) {
	st, err := store.LoadAuditState(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading hsm audit state: %w", err)
	}
	if st == nil {
		return nil, nil
	}
	return &Service{store: store, now: time.Now}, nil
}

// SetClock overrides the clock, for tests.
func (s *Service) SetClock(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// ProvisionResult reports what provisioning established.
type ProvisionResult struct {
	Device DeviceInfo `json:"device"`
	// Anchor is the pinned genesis digest. An operator must record this out of
	// band — it is the value every future export is checked against, and a
	// verifier that only ever learns it from the CA learns nothing.
	Anchor  string   `json:"anchor"`
	Options *Options `json:"options"`
	// Collected is how many device log entries were stored during provisioning.
	Collected int `json:"collected"`
}

// Provision prepares a factory-reset YubiHSM for audited operation and pins the
// chain anchor.
//
// It refuses to run on a device that is not freshly reset. That is not
// fussiness: the device log is a bounded ring that starts at the reset, so a
// device with prior history has already had operations that cannot be shown to
// be absent. Provisioning such a device would produce a chain that verifies
// perfectly and proves nothing about the period before it.
//
// The steps are ordered so that no window exists in which auditing is partially
// on:
//
//  1. Read the log and require that entry 1 is the factory-reset sentinel.
//  2. Pin the sentinel digest as the chain anchor, and store the pre-existing
//     entries, before changing anything on the device.
//  3. Record the anchor in the hash-chained event log, which is what gives it a
//     witnessed time — see SetAuditor. This happens before anything on the
//     device is changed irreversibly, so an event log that cannot be written
//     aborts provisioning rather than leaving a force-audited device whose
//     anchor nothing outside this system ever saw.
//  4. Force-audit every command that could produce or exfiltrate a signature.
//  5. Read the options back and verify they took, failing if the device
//     declined any of them.
//  6. Collect the entries provisioning itself generated.
func (s *Service) Provision(ctx context.Context) (*ProvisionResult, error) {
	info, err := s.dev.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading device info: %w", err)
	}

	if existing, err := s.store.LoadAuditState(ctx); err != nil {
		return nil, fmt.Errorf("loading hsm audit state: %w", err)
	} else if existing != nil {
		return nil, fmt.Errorf(
			"device %s is already provisioned with anchor %s (pinned %s): re-provisioning would replace the "+
				"pinned chain anchor, which is exactly how a forged history would be introduced. "+
				"Factory reset the device and clear the stored audit state deliberately if that is really intended",
			existing.DeviceSerial, existing.Anchor, existing.ProvisionedAt.UTC().Format(time.RFC3339))
	}

	// Checked before the device is read, let alone written: an anchor that
	// reaches no witness is one an operator could have chosen at any later date.
	if s.auditor == nil {
		return nil, fmt.Errorf("no audit log configured: the chain anchor must be recorded in the " +
			"hash-chained event log at provisioning time, because an anchor no third party ever witnessed " +
			"cannot be told apart from one invented later (see SetAuditor)")
	}

	resp, err := s.dev.FetchLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching device log: %w", err)
	}
	if resp.UnloggedBoots > 0 || resp.UnloggedAuthentications > 0 {
		return nil, fmt.Errorf("device reports %d unlogged boot(s) and %d unlogged authentication(s): "+
			"its log is already incomplete, so factory reset it before provisioning",
			resp.UnloggedBoots, resp.UnloggedAuthentications)
	}
	if err := hsm.CheckDeviceInitEntry(resp.Entries); err != nil {
		return nil, err
	}

	anchor := strings.ToLower(resp.Entries[0].Hash)
	st := &AuditState{
		DeviceSerial:  info.Serial,
		Anchor:        anchor,
		ProvisionedAt: s.now().UTC(),
	}

	// Verify the pre-existing entries chain before committing to them, so a
	// device that is lying about its own log is rejected at commissioning time
	// rather than at the first audit.
	if seg := VerifyChainFromGenesis(resp.Entries, Unlogged{}); !seg.OK {
		return nil, fmt.Errorf("initial device log does not verify: %w", seg.Err())
	}
	if err := s.store.AppendLogEntries(ctx, resp.Entries); err != nil {
		return nil, fmt.Errorf("storing initial device log: %w", err)
	}
	st.Tail = Tail{
		Number: resp.Entries[len(resp.Entries)-1].Number,
		Digest: strings.ToLower(resp.Entries[len(resp.Entries)-1].Hash),
	}
	if err := s.store.SaveAuditState(ctx, st); err != nil {
		return nil, fmt.Errorf("pinning hsm audit state: %w", err)
	}
	if err := s.recordGenesis(st); err != nil {
		return nil, err
	}
	if err := s.dev.ConsumeLog(ctx, st.Tail.Number); err != nil {
		return nil, fmt.Errorf("acknowledging initial device log: %w", err)
	}

	// Ask the device which commands it actually implements before deciding what
	// to force-audit. The set is derived from the attached firmware rather than
	// from a constant so that a command this build has never heard of — and so
	// cannot show to be incapable of signing — is force-audited too. See
	// Options.RequiredForced.
	before, err := s.dev.Options(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading device audit options: %w", err)
	}
	if _, err := s.dev.ProvisionAudit(ctx, before.RequiredForced()); err != nil {
		return nil, fmt.Errorf("enabling forced audit logging: %w", err)
	}

	opts, err := s.dev.Options(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading back device audit options: %w", err)
	}
	if err := opts.Verify(); err != nil {
		return nil, fmt.Errorf("device did not accept the required audit configuration: %w", err)
	}

	res := &ProvisionResult{Device: *info, Anchor: anchor, Options: opts}
	// Provisioning itself is audited (PUT OPTION was fixed first), so drain the
	// entries it produced.
	c := NewCollector(s.dev, s.store, 0, nil)
	if cr, err := c.Collect(ctx); err != nil {
		return res, fmt.Errorf("collecting provisioning log entries: %w", err)
	} else {
		res.Collected = cr.Collected
	}
	return res, nil
}

// GenesisDetail renders the audit-event detail Provision records for a pinned
// anchor. It is a function rather than an inline string so the offline reader of
// an exported event log and the writer agree on the wording, and so a test can
// assert the anchor is actually in there.
//
// The sentinel preimage is included even though it is a public constant, and for
// once that is the point: it states in the record itself which bytes the anchor
// is the digest of, so nobody reading the log later has to go looking for the
// reason the anchor is not simply the hash of them. See genesis.go.
func GenesisDetail(st *AuditState) string {
	return fmt.Sprintf(
		"chain anchor %s pinned from the factory-reset device-init sentinel (entry 1, preimage %s); "+
			"the anchor is the device's own digest of that entry and cannot be recomputed from it, "+
			"so this record is what dates it",
		strings.ToLower(st.Anchor), SentinelPreimageHex)
}

// recordGenesis writes the pinned anchor into the hash-chained event log.
//
// It fails closed. An anchor that reaches no witness is one an operator could
// have chosen at any later date, which is the single assumption the whole
// "the device signed nothing else" argument rests on — so a store that will not
// accept the event is a reason to stop, not a reason to continue quietly.
func (s *Service) recordGenesis(st *AuditState) error {
	actor := s.actor
	if actor == "" {
		actor = "system"
	}
	err := s.auditor.AppendEvent(&audit.Event{
		Timestamp:  st.ProvisionedAt,
		Actor:      actor,
		ActorRoles: "system",
		Action:     audit.ActionHSMProvisionAudit,
		Target:     st.DeviceSerial,
		Result:     audit.ResultSuccess,
		Detail:     GenesisDetail(st),
	})
	if err != nil {
		return fmt.Errorf("recording the chain anchor in the audit log: %w "+
			"(the anchor was pinned but nothing witnessed it, so provisioning stopped before "+
			"changing the device; clear the stored hsm audit state and retry)", err)
	}
	return nil
}

// ExportReport carries what an export could not do, for the operator running
// it. It is deliberately not part of the bundle: a verifier must reach its
// verdict from evidence, not from the audited party's explanation of why a
// piece of evidence is missing.
type ExportReport struct {
	// AttestedKeys is how many signing keys the device attested.
	AttestedKeys int
	// AttestationErrors describes each key the device would not or could not
	// attest, keyed by object ID. A bundle exported with any of these will fail
	// verification, which is the intended outcome — but an operator should see
	// why before handing it to an auditor.
	AttestationErrors map[uint16]string
}

// Export builds a bundle describing everything known about the device.
func (s *Service) Export(ctx context.Context) (*Bundle, error) {
	b, _, err := s.ExportWithReport(ctx)
	return b, err
}

// ExportWithReport builds a bundle and reports what it could not establish.
//
// It drains the device log first so the bundle is current: an export taken
// without collecting would omit exactly the most recent signatures, which is
// the window an abuser would aim for. It then attests every key that has
// signed, and drains once more — attestation is itself an audited device
// operation, so the second drain leaves the bundle describing its own
// production rather than trailing a few unexplained entries into the next one.
func (s *Service) ExportWithReport(ctx context.Context) (*Bundle, *ExportReport, error) {
	c := NewCollector(s.dev, s.store, 0, nil)
	if _, err := c.Collect(ctx); err != nil {
		return nil, nil, fmt.Errorf("draining device log before export: %w", err)
	}

	st, err := s.store.LoadAuditState(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("loading hsm audit state: %w", err)
	}
	if st == nil {
		return nil, nil, fmt.Errorf("device is not provisioned: nothing to export")
	}

	entries, err := s.store.LogEntries(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading stored device log: %w", err)
	}
	ledger, err := s.store.Ledger(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading signature ledger: %w", err)
	}

	atts, report := s.attestSigningKeys(ctx, entries, ledger)
	if len(atts) > 0 {
		if _, err := c.Collect(ctx); err != nil {
			return nil, nil, fmt.Errorf("draining the log the attestations produced: %w", err)
		}
		if entries, err = s.store.LogEntries(ctx); err != nil {
			return nil, nil, fmt.Errorf("re-reading stored device log: %w", err)
		}
	}

	info, err := s.dev.Info(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading device info: %w", err)
	}
	opts, err := s.dev.Options(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading device audit options: %w", err)
	}
	resp, err := s.dev.FetchLog(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading device unlogged counters: %w", err)
	}
	proofs, err := s.store.FreshnessProofs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading freshness proofs: %w", err)
	}

	return &Bundle{
		Version:    BundleVersion,
		ExportedAt: s.now().UTC(),
		Device:     *info,
		Options:    opts,
		Anchor:     st.Anchor,
		LogEntries: entries,
		Unlogged: Unlogged{
			Boots:           resp.UnloggedBoots,
			Authentications: resp.UnloggedAuthentications,
		},
		Ledger:          ledger,
		KeyAttestations: atts,
		Freshness:       proofs,
	}, report, nil
}

// attestSigningKeys asks the device to attest every key the bundle will make
// claims about.
//
// Failures are collected rather than returned. An attestation the device
// declines to produce is evidence that is simply absent, and the verifier
// already fails closed on absence; aborting the export instead would deny an
// auditor the rest of the evidence — including the log entries showing whatever
// happened to the key that can no longer be attested.
func (s *Service) attestSigningKeys(ctx context.Context, entries []hsm.AuditLogEntry, ledger []LedgerEntry) ([]hsmattest.Attestation, *ExportReport) {
	report := &ExportReport{AttestationErrors: map[uint16]string{}}
	if s.attester == nil {
		return nil, report
	}
	var out []hsmattest.Attestation
	for _, id := range SigningKeyIDs(entries, ledger) {
		if id == 0 {
			// Not a device handle: the CA failed to attribute those signatures to
			// an object at all. Reconciliation reports it; there is nothing to
			// attest.
			continue
		}
		att, err := s.attester.AttestObject(ctx, id)
		if err != nil {
			report.AttestationErrors[id] = err.Error()
			continue
		}
		out = append(out, *att)
	}
	report.AttestedKeys = len(out)
	return out, report
}

// Status is a quick operational view of the audit subsystem.
type Status struct {
	Provisioned bool        `json:"provisioned"`
	Device      *DeviceInfo `json:"device,omitempty"`
	Anchor      string      `json:"anchor,omitempty"`
	Options     *Options    `json:"options,omitempty"`
	// OptionsError is set when the device is not configured to guarantee that
	// every signature is logged.
	OptionsError string `json:"options_error,omitempty"`
	Tail         Tail   `json:"tail"`
	// StoredEntries is the number of device log entries durably collected, and
	// Signatures how many of them were successful signing operations.
	StoredEntries int `json:"stored_entries"`
	Signatures    int `json:"signatures"`
	// LedgerEntries is the number of signatures the CA recorded requesting. It
	// should equal Signatures; a difference is what reconciliation reports on.
	LedgerEntries int    `json:"ledger_entries"`
	LogUsed       string `json:"log_used,omitempty"`
	// SigningKeys lists the on-device handles that have signed. An export must
	// carry a device attestation for each, or verification cannot say that those
	// signatures are the complete history of a key rather than of a handle.
	SigningKeys []uint16 `json:"signing_keys,omitempty"`
	// CanAttest reports whether this process can obtain those attestations.
	CanAttest bool `json:"can_attest"`
	// FreshnessProofs counts the RFC 3161 attestations obtained so far, and
	// LastAttestedAt is the trusted time of the newest. An operator watching
	// LastAttestedAt fall behind is watching the export lose its ability to prove
	// it is current.
	FreshnessProofs int        `json:"freshness_proofs"`
	LastAttestedAt  *time.Time `json:"last_attested_at,omitempty"`
}

// Status reports the current state without changing anything.
func (s *Service) Status(ctx context.Context) (*Status, error) {
	out := &Status{}
	st, err := s.store.LoadAuditState(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading hsm audit state: %w", err)
	}
	if st != nil {
		out.Provisioned = true
		out.Anchor = st.Anchor
		out.Tail = st.Tail
	}
	if info, err := s.dev.Info(ctx); err == nil {
		out.Device = info
		out.LogUsed = info.LogUsed
	}
	if opts, err := s.dev.Options(ctx); err == nil {
		out.Options = opts
		if err := opts.Verify(); err != nil {
			out.OptionsError = err.Error()
		}
	}
	entries, err := s.store.LogEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading stored device log: %w", err)
	}
	out.StoredEntries = len(entries)
	out.Signatures = countSignatures(entries)
	ledger, err := s.store.Ledger(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading signature ledger: %w", err)
	}
	out.LedgerEntries = len(ledger)
	out.SigningKeys = SigningKeyIDs(entries, ledger)
	out.CanAttest = s.attester != nil
	proofs, err := s.store.FreshnessProofs(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading freshness proofs: %w", err)
	}
	out.FreshnessProofs = len(proofs)
	if n := len(proofs); n > 0 {
		t := proofs[n-1].GenTime.UTC()
		out.LastAttestedAt = &t
	}
	return out, nil
}

// RecordSignature implements keyprovider.SignatureRecorder, appending one row
// to the hash-chained signature ledger.
//
// It is on the hot signing path, so it does the minimum: seal and append. The
// chain sealing happens inside the store's transaction, which is what makes a
// later edit or deletion detectable.
func (s *Service) RecordSignature(ctx context.Context, rec keyprovider.SignatureRecord) error {
	e := &LedgerEntry{
		Timestamp: s.now().UTC(),
		KeyLabel:  rec.KeyLabel,
		KeyID:     parseKeyID(rec.KeyID),
		Digest:    hex.EncodeToString(rec.Digest),
		Algorithm: rec.Algorithm,
		Purpose:   PurposeOther,
	}
	return s.store.AppendLedger(ctx, e)
}

// Compile-time check that Service can be handed to keyprovider.Record.
var _ keyprovider.SignatureRecorder = (*Service)(nil)

// parseKeyID converts a provider key identifier into the on-device object ID
// the YubiHSM audit log reports in target_key.
//
// The YubiHSM PKCS#11 module sets CKA_ID to the two-byte big-endian object ID,
// so a hex CKA_ID maps directly. Anything else (a longer CKA_ID from a
// different token, an empty value) yields 0, which reconciliation surfaces as
// an unattributed key rather than silently mis-joining onto a real one.
func parseKeyID(s string) uint16 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	raw, err := hex.DecodeString(s)
	if err == nil {
		switch len(raw) {
		case 1:
			return uint16(raw[0])
		case 2:
			return uint16(raw[0])<<8 | uint16(raw[1])
		}
		return 0
	}
	// Some providers report a decimal identifier rather than hex.
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n)
	}
	return 0
}
