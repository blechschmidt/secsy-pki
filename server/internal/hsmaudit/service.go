package hsmaudit

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// Service ties the pieces together: it provisions a freshly reset device,
// records signatures into the ledger, and produces export bundles.
type Service struct {
	dev   Device
	store Store
	now   func() time.Time
}

// NewService returns a Service over dev and store.
func NewService(dev Device, store Store) *Service {
	return &Service{dev: dev, store: store, now: time.Now}
}

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
//  3. Force-audit every command that could produce or exfiltrate a signature.
//  4. Read the options back and verify they took, failing if the device
//     declined any of them.
//  5. Collect the entries provisioning itself generated.
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
	if _, err := hsm.ProvisionAuditLogging(deviceConfig(s.dev), before.RequiredForced()); err != nil {
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

// deviceConfig extracts the shell config from a ShellDevice so provisioning can
// reach the yubihsm-shell helpers. Non-shell devices (test fakes) provision
// through their own Options plumbing and get a zero config.
func deviceConfig(d Device) hsm.Config {
	if sd, ok := d.(*ShellDevice); ok {
		return sd.Cfg
	}
	return hsm.Config{}
}

// Export builds a bundle describing everything known about the device.
//
// It drains the device log first so the bundle is current: an export taken
// without collecting would omit exactly the most recent signatures, which is
// the window an abuser would aim for.
func (s *Service) Export(ctx context.Context) (*Bundle, error) {
	c := NewCollector(s.dev, s.store, 0, nil)
	if _, err := c.Collect(ctx); err != nil {
		return nil, fmt.Errorf("draining device log before export: %w", err)
	}

	st, err := s.store.LoadAuditState(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading hsm audit state: %w", err)
	}
	if st == nil {
		return nil, fmt.Errorf("device is not provisioned: nothing to export")
	}

	info, err := s.dev.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading device info: %w", err)
	}
	opts, err := s.dev.Options(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading device audit options: %w", err)
	}
	resp, err := s.dev.FetchLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading device unlogged counters: %w", err)
	}
	entries, err := s.store.LogEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading stored device log: %w", err)
	}
	ledger, err := s.store.Ledger(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading signature ledger: %w", err)
	}
	proofs, err := s.store.FreshnessProofs(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading freshness proofs: %w", err)
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
		Ledger:    ledger,
		Freshness: proofs,
	}, nil
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
