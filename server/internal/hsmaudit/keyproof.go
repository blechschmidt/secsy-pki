package hsmaudit

import (
	"context"
	"crypto"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
)

// Binding the audit log to a key rather than to a count of operations
// (Task 170).
//
// Everything else in this package reasons about object IDs: the device log
// records that handle 0x2f5d performed 412 signatures, and the ledger records
// that the CA asked for 412 signatures from handle 0x2f5d. That reconciles, but
// on its own it proves something weaker than it appears to. It says a number of
// operations happened on a device. It does not say *which key* performed them,
// and it says nothing at all about signatures made with a copy of that key
// somewhere else — which would leave no trace in any device log, because no
// device was involved.
//
// A relying party does not hold an object ID. They hold a public key: the one in
// the CA certificate they are about to trust. The question they actually have is
//
//	has this public key ever signed anything that was not published?
//
// Three facts, joined, answer it. Each comes from a different place and none is
// asserted by the CA operator:
//
//  1. The attestation (internal/hsmattest) is signed by the device's
//     factory-provisioned attestation key and says: object 0x2f5d holds *this*
//     public key, it was generated inside this device, and it holds no
//     capability permitting export. That is the public-key-to-handle join, and
//     it is also what rules out a copy signing elsewhere — private material that
//     was created on-device and cannot leave it has no second copy to misuse.
//  2. The device log, chained from the pinned factory-reset anchor, says object
//     0x2f5d was created exactly once, never deleted, never exported, and
//     performed exactly N signatures.
//  3. The ledger and the auditor's own collection of published artifacts say
//     those N signatures are these N published things.
//
// Take away (1) and a balanced reconciliation is compatible with the key having
// been imported from a laptop that kept a copy. Take away (2) and the
// attestation describes a handle whose history may have been erased and
// restarted under the same number. This file computes the join and refuses to
// state the conclusion when any link is missing.

// KeyAttester obtains a device-signed attestation for an on-device object.
//
// It is the subset of hsmattest.Attester that this package needs, declared here
// so the export path can be exercised against a fixture and so that a Service
// built on a non-attesting Device simply produces bundles without attestations
// (which the verifier then refuses, rather than silently accepting).
type KeyAttester interface {
	// AttestObject attests the asymmetric key with the given on-device object ID.
	AttestObject(ctx context.Context, objectID uint16) (*hsmattest.Attestation, error)
}

// Compile-time check that the production attester fits.
var _ KeyAttester = (*hsmattest.ShellAttester)(nil)

// SigningKeyIDs returns every on-device object ID that either signed something
// according to the device log or was recorded as signing something by the CA.
//
// The union is deliberate. A key in the log but not the ledger is the abuse case
// this package exists to catch; a key in the ledger but not the log means device
// records are missing. Both must be attested, because both are keys the bundle
// is making claims about.
func SigningKeyIDs(entries []hsm.AuditLogEntry, ledger []LedgerEntry) []uint16 {
	seen := map[uint16]bool{}
	for _, e := range entries {
		if _, isSign := hsm.SignCommands[e.Command]; isSign && entrySucceeded(e) {
			seen[e.TargetKey] = true
		}
	}
	for _, l := range ledger {
		seen[l.KeyID] = true
	}
	out := make([]uint16, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// KeyEvent is one device log entry that affected an object's existence.
type KeyEvent struct {
	// Entry is the device log entry number, so an operator can find it.
	Entry uint16 `json:"entry"`
	// Command and CommandName identify the operation.
	Command     uint8  `json:"command"`
	CommandName string `json:"command_name"`
	// Succeeded distinguishes an operation the device performed from one it
	// refused. A refused export is not an export, but it is worth seeing.
	Succeeded bool `json:"succeeded"`
}

// KeyLifecycle is everything the device log says about the existence of one
// object, as opposed to its use.
//
// The field conventions below were read off a YubiHSM 2 (firmware 2.4.0) rather
// than from documentation, because the log's two key fields carry different
// things depending on the command:
//
//	GENERATE ASYMMETRIC KEY 0x46  target=0x7e59  second=0xffff   (target is the new object)
//	DELETE OBJECT           0x58  target=0x2f5d  second=0xffff   (target is the deleted object)
//	EXPORT WRAPPED          0x4a  target=0x7e60  second=0x7e61   (target is the *wrap key*, second the exported object)
//
// Reading the wrong field would silently miss an export, so the wrap commands
// are matched on either field: a false positive is a loud rejection an operator
// can investigate, a false negative is exactly the hole this check exists to
// close.
type KeyLifecycle struct {
	ObjectID uint16 `json:"object_id"`
	// Generated lists successful GENERATE ASYMMETRIC KEY events for the object.
	Generated []KeyEvent `json:"generated,omitempty"`
	// Imported lists events that placed key material from outside onto the
	// device under this handle.
	Imported []KeyEvent `json:"imported,omitempty"`
	// Deleted lists successful DELETE OBJECT events.
	Deleted []KeyEvent `json:"deleted,omitempty"`
	// Exported lists successful wrap-export events naming this object.
	Exported []KeyEvent `json:"exported,omitempty"`
	// OK is true when the log shows a single on-device creation and nothing that
	// could have moved the private material or restarted the handle's history.
	OK bool `json:"ok"`
	// Findings explains every reason OK is false.
	Findings []string `json:"findings,omitempty"`
}

// wrapTransferCommands are the commands whose logged target_key is the wrap key
// rather than the object being moved. See KeyLifecycle.
var wrapTransferCommands = map[uint8]bool{
	hsm.CmdExportWrapped:       true,
	hsm.CmdImportWrapped:       true,
	hsm.CmdExportRSAWrapped:    true,
	hsm.CmdImportRSAWrapped:    true,
	hsm.CmdExportRSAWrappedObj: true,
	hsm.CmdImportRSAWrappedObj: true,
}

// exportCommands move key material off the device.
var exportCommands = map[uint8]bool{
	hsm.CmdExportWrapped:       true,
	hsm.CmdExportRSAWrapped:    true,
	hsm.CmdExportRSAWrappedObj: true,
}

// AnalyzeKeyLifecycle reports what the device log says about the existence of
// one object.
//
// entries must be the complete log from the pinned genesis anchor; a suffix
// would make "created exactly once" unanswerable, since the creation could
// simply be before the window.
func AnalyzeKeyLifecycle(entries []hsm.AuditLogEntry, objectID uint16) *KeyLifecycle {
	lc := &KeyLifecycle{ObjectID: objectID, OK: true}
	event := func(e hsm.AuditLogEntry) KeyEvent {
		name := hsm.AllCommands[e.Command]
		if name == "" {
			name = fmt.Sprintf("UNDOCUMENTED COMMAND 0x%02x", e.Command)
		}
		return KeyEvent{Entry: e.Number, Command: e.Command, CommandName: name, Succeeded: entrySucceeded(e)}
	}

	for _, e := range entries {
		switch {
		case wrapTransferCommands[e.Command]:
			if e.TargetKey != objectID && e.SecondKey != objectID {
				continue
			}
			ev := event(e)
			if !ev.Succeeded {
				continue
			}
			if exportCommands[e.Command] {
				lc.Exported = append(lc.Exported, ev)
			} else {
				lc.Imported = append(lc.Imported, ev)
			}
		case e.TargetKey != objectID:
			continue
		case e.Command == hsm.CmdGenerateAsymmetricKey:
			if ev := event(e); ev.Succeeded {
				lc.Generated = append(lc.Generated, ev)
			}
		case e.Command == cmdPutAsymmetricKey:
			if ev := event(e); ev.Succeeded {
				lc.Imported = append(lc.Imported, ev)
			}
		case e.Command == hsm.CmdDeleteObject:
			if ev := event(e); ev.Succeeded {
				lc.Deleted = append(lc.Deleted, ev)
			}
		}
	}

	fail := func(format string, args ...any) {
		lc.OK = false
		lc.Findings = append(lc.Findings, fmt.Sprintf(format, args...))
	}
	creations := len(lc.Generated) + len(lc.Imported)
	switch {
	case creations == 0:
		fail("the device log records no creation of object 0x%04x: the log begins at the pinned factory reset, "+
			"which erases every object, so a key present now that the log never saw created means log entries are "+
			"missing and this handle's history cannot be bounded", objectID)
	case creations > 1:
		fail("object 0x%04x was created %d times in this history (%s): the handle was reused, so signatures "+
			"recorded against it belong to more than one key and cannot all be attributed to the attested one",
			objectID, creations, describeEvents(append(append([]KeyEvent(nil), lc.Generated...), lc.Imported...)))
	case len(lc.Imported) == 1:
		fail("object 0x%04x was imported rather than generated on the device (%s): the private material existed "+
			"outside the HSM before it arrived, so no device log can bound what was signed with it",
			objectID, describeEvents(lc.Imported))
	}
	if len(lc.Deleted) > 0 {
		fail("object 0x%04x was deleted (%s): a deleted handle can be recreated with different key material, "+
			"so the log after that point does not describe the same key", objectID, describeEvents(lc.Deleted))
	}
	if len(lc.Exported) > 0 {
		fail("object 0x%04x was exported under a wrap key (%s): a copy of the private material may exist outside "+
			"the HSM, where it can sign without producing any log entry at all", objectID, describeEvents(lc.Exported))
	}
	return lc
}

// cmdPutAsymmetricKey is PUT ASYMMETRIC KEY. It has no constant in internal/hsm
// (nothing there issues it) but the audit log can carry it, and an imported key
// is precisely what this analysis must not mistake for a generated one.
const cmdPutAsymmetricKey uint8 = 0x45

func describeEvents(evs []KeyEvent) string {
	parts := make([]string, 0, len(evs))
	for _, e := range evs {
		parts = append(parts, fmt.Sprintf("entry %d %s", e.Entry, e.CommandName))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// AttestedKey is the per-object verdict: what the device says the key is, what
// the log says happened to it, and how much it signed.
type AttestedKey struct {
	// ObjectID is the on-device handle, as asserted by the attestation and used
	// to join against the log's target_key.
	ObjectID uint16 `json:"object_id"`
	// KeyLabel is the device's label for the object.
	KeyLabel string `json:"key_label,omitempty"`
	// SPKIFingerprint identifies the attested public key in the same
	// "SHA256:<base64>" form the certificate inventory uses, so an auditor can
	// match it against a CA certificate without parsing anything.
	SPKIFingerprint string `json:"spki_fingerprint,omitempty"`
	// Attestation is the full attestation verdict, re-derived from the
	// certificates in the bundle.
	Attestation *hsmattest.Result `json:"attestation"`
	// Lifecycle is what the device log says about the object's existence.
	Lifecycle *KeyLifecycle `json:"lifecycle"`
	// DeviceSignatures and LedgerSignatures are the reconciliation counts for
	// this object.
	DeviceSignatures int `json:"device_signatures"`
	LedgerSignatures int `json:"ledger_signatures"`
	// OK is true when the key is confined to the device, its handle has an
	// unbroken single-creation history, and its signature counts balance.
	OK       bool     `json:"ok"`
	Findings []string `json:"findings,omitempty"`

	// publicKey is the attested key, retained for expected-key matching.
	publicKey crypto.PublicKey
}

// AttestationResult is the bundle-wide verdict on key confinement.
type AttestationResult struct {
	// OK is true when every key that signed is attested as living inside the
	// device and nothing in the log contradicts that.
	OK bool `json:"ok"`
	// Keys holds one entry per attestation carried by the bundle, ordered by
	// object ID.
	Keys []*AttestedKey `json:"keys,omitempty"`
	// Unattested lists object IDs that signed but that no valid attestation
	// covers. These are the keys the bundle cannot show to be confined.
	Unattested []uint16 `json:"unattested,omitempty"`
	Findings   []string `json:"findings,omitempty"`
}

// Err renders a failed attestation verdict as an error, nil when it passed.
func (r *AttestationResult) Err() error {
	if r == nil || r.OK {
		return nil
	}
	if len(r.Findings) == 0 {
		return fmt.Errorf("hsm key attestation verification failed")
	}
	return fmt.Errorf("hsm key attestation verification failed: %s", strings.Join(r.Findings, "; "))
}

// Find returns the verdict for an object ID.
func (r *AttestationResult) Find(objectID uint16) *AttestedKey {
	if r == nil {
		return nil
	}
	for _, k := range r.Keys {
		if k.ObjectID == objectID {
			return k
		}
	}
	return nil
}

// FindByPublicKey returns the verdict for an attested public key.
func (r *AttestationResult) FindByPublicKey(pub crypto.PublicKey) *AttestedKey {
	if r == nil || pub == nil {
		return nil
	}
	for _, k := range r.Keys {
		if publicKeysEqual(k.publicKey, pub) {
			return k
		}
	}
	return nil
}

// VerifyAttestations checks every key attestation in a bundle and reports which
// signing keys are shown to be confined to the device.
//
// The policy is applied per attestation with the expected serial forced to the
// bundle's own device: an attestation from a different HSM would otherwise
// describe a genuinely non-exportable key that has nothing to do with the
// signatures in this log.
func VerifyAttestations(b *Bundle, pol hsmattest.Policy) *AttestationResult {
	res := &AttestationResult{OK: true}
	fail := func(format string, args ...any) {
		res.OK = false
		res.Findings = append(res.Findings, fmt.Sprintf(format, args...))
	}
	if b == nil {
		fail("no bundle supplied")
		return res
	}

	rec := Reconcile(b.LogEntries, b.Ledger)
	counts := map[uint16]KeyReconciliation{}
	for _, k := range rec.Keys {
		counts[k.KeyID] = k
	}

	seen := map[uint16]*AttestedKey{}
	for i := range b.KeyAttestations {
		att := b.KeyAttestations[i]
		keyPol := pol
		keyPol.ExpectedSerial = b.Device.Serial
		// The caller's policy configures what an attestation must show; the
		// identity expectations belong to this join and are set from the bundle,
		// never inherited.
		keyPol.ExpectedPublicKey = nil
		keyPol.ExpectedObjectID = nil
		keyPol.ExpectedLabel = ""

		vr := hsmattest.Verify(&att, keyPol)
		ak := &AttestedKey{
			ObjectID:        vr.ObjectID,
			KeyLabel:        vr.KeyLabel,
			SPKIFingerprint: vr.SPKIFingerprint,
			Attestation:     vr,
			OK:              true,
		}
		if cert, err := att.Certificate(); err == nil {
			ak.publicKey = cert.PublicKey
		}
		if !vr.Verified {
			ak.OK = false
			ak.Findings = append(ak.Findings, fmt.Sprintf("attestation for object 0x%04x is not valid: %s",
				vr.ObjectID, strings.Join(vr.Problems, "; ")))
		}

		// Two attestations for one handle can only disagree by describing
		// different key material, which would make every count against that
		// handle ambiguous.
		if prev, dup := seen[ak.ObjectID]; dup {
			if !publicKeysEqual(prev.publicKey, ak.publicKey) {
				fail("object 0x%04x is attested twice with different public keys (%s and %s): "+
					"the bundle cannot say which key the signatures recorded against that handle belong to",
					ak.ObjectID, prev.SPKIFingerprint, ak.SPKIFingerprint)
			}
			continue
		}
		seen[ak.ObjectID] = ak

		ak.Lifecycle = AnalyzeKeyLifecycle(b.LogEntries, ak.ObjectID)
		if !ak.Lifecycle.OK {
			ak.OK = false
			ak.Findings = append(ak.Findings, ak.Lifecycle.Findings...)
		}
		if c, ok := counts[ak.ObjectID]; ok {
			ak.DeviceSignatures = c.DeviceSignatures
			ak.LedgerSignatures = c.LedgerSignatures
		}
		if !ak.OK {
			res.OK = false
			res.Findings = append(res.Findings, ak.Findings...)
		}
		res.Keys = append(res.Keys, ak)
	}
	sort.Slice(res.Keys, func(i, j int) bool { return res.Keys[i].ObjectID < res.Keys[j].ObjectID })

	// Coverage: a key that signed and is not attested is a key the bundle
	// describes but cannot confine. Its signatures may have been made by a copy
	// that never touched this device, and no amount of log verification would
	// show it.
	for _, id := range SigningKeyIDs(b.LogEntries, b.Ledger) {
		ak := seen[id]
		if ak != nil && ak.OK {
			continue
		}
		res.Unattested = append(res.Unattested, id)
		switch {
		case id == 0:
			fail("signatures are recorded against object 0x0000, which is not a key handle: the CA could not "+
				"attribute %d ledger row(s) to a device object, so they cannot be attested or reconciled",
				counts[id].LedgerSignatures)
		case ak == nil:
			fail("key 0x%04x signed %d time(s) but the bundle carries no attestation for it: nothing shows that "+
				"the private key is confined to this HSM, so signatures made with a copy of it elsewhere would "+
				"leave no trace in this log", id, counts[id].DeviceSignatures)
		default:
			fail("key 0x%04x%s signed %d time(s) but its attestation did not verify", id,
				labelSuffix(ak.KeyLabel), counts[id].DeviceSignatures)
		}
	}
	return res
}

// ExpectedKey is a public key an auditor wants a bundle to account for.
type ExpectedKey struct {
	// Name identifies the key in the report — a file name, or a CA's subject.
	Name string
	// PublicKey is the key itself, taken from a certificate or a public-key file.
	PublicKey crypto.PublicKey
}

// KeyProofResult is the verdict on one public key an auditor asked about.
type KeyProofResult struct {
	// OK is the bottom line: this public key has produced no signature beyond
	// the ones the bundle accounts for, and none can exist outside the device.
	OK bool `json:"ok"`
	// Name and SPKIFingerprint identify the key that was asked about.
	Name            string `json:"name,omitempty"`
	SPKIFingerprint string `json:"spki_fingerprint,omitempty"`
	// Key is the matching attested object, nil when the bundle does not attest
	// this public key at all.
	Key *AttestedKey `json:"key,omitempty"`
	// Published is the artifact match restricted to this key's ledger rows, when
	// the auditor supplied published digests.
	Published *PublishedResult `json:"published,omitempty"`
	// Summary is the one-line conclusion, phrased as what it does and does not
	// establish.
	Summary  string   `json:"summary"`
	Findings []string `json:"findings,omitempty"`
}

// Err renders a failed key proof as an error, nil when it passed.
func (r *KeyProofResult) Err() error {
	if r == nil || r.OK {
		return nil
	}
	if len(r.Findings) == 0 {
		return fmt.Errorf("hsm key proof failed")
	}
	return fmt.Errorf("hsm key proof failed: %s", strings.Join(r.Findings, "; "))
}

// ProveKey answers, for one public key, whether the bundle shows that key has
// signed nothing beyond what was published.
//
// atts must be the result of VerifyAttestations over the same bundle. The
// published digests, when supplied, are matched against only this key's ledger
// rows, so the answer is about this key rather than about the deployment.
func ProveKey(b *Bundle, atts *AttestationResult, want ExpectedKey, publishedDigests []string) *KeyProofResult {
	res := &KeyProofResult{OK: true, Name: want.Name}
	fail := func(format string, args ...any) {
		res.OK = false
		res.Findings = append(res.Findings, fmt.Sprintf(format, args...))
	}
	if fp, err := keycheck.Fingerprint(want.PublicKey); err == nil {
		res.SPKIFingerprint = fp
	}
	if want.PublicKey == nil {
		fail("no public key supplied")
		res.Summary = "no public key supplied"
		return res
	}

	ak := atts.FindByPublicKey(want.PublicKey)
	if ak == nil {
		fail("no attestation in this bundle covers public key %s: the device has not stated that this key lives "+
			"inside it, so nothing here bounds what the key has signed — signatures made with it elsewhere would "+
			"not appear in any device log", res.SPKIFingerprint)
		res.Summary = fmt.Sprintf("NOT PROVEN: public key %s is not attested by device %s",
			res.SPKIFingerprint, b.Device.Serial)
		return res
	}
	res.Key = ak
	if !ak.OK {
		res.OK = false
		res.Findings = append(res.Findings, ak.Findings...)
	}

	// Reconciliation reports imbalances device-wide; restate this key's in the
	// terms the question was asked in, so a reader of the per-key verdict is not
	// left to infer it from a table elsewhere in the output.
	if surplus := ak.DeviceSignatures - ak.LedgerSignatures; surplus > 0 {
		fail("the device performed %d signature(s) with this key but the CA accounts for only %d: "+
			"%d signature(s) made with this key were never published",
			ak.DeviceSignatures, ak.LedgerSignatures, surplus)
	} else if surplus < 0 {
		fail("the CA recorded %d signature(s) with this key but the device log shows only %d: "+
			"device log entries are missing, so this key's history cannot be bounded",
			ak.LedgerSignatures, ak.DeviceSignatures)
	}

	// The published match is restricted to this key's rows. A deployment-wide
	// match would let another key's published artifact cover for a row of this
	// one, which is precisely the substitution the per-key question rules out.
	if publishedDigests != nil {
		var rows []LedgerEntry
		for _, l := range b.Ledger {
			if l.KeyID == ak.ObjectID {
				rows = append(rows, l)
			}
		}
		res.Published = MatchPublished(rows, publishedDigests)
		if err := res.Published.Err(); err != nil {
			fail("%v", err)
		}
	}

	res.Summary = summarizeKeyProof(res, ak, b, publishedDigests != nil)
	return res
}

func summarizeKeyProof(res *KeyProofResult, ak *AttestedKey, b *Bundle, published bool) string {
	if !res.OK {
		return fmt.Sprintf("NOT PROVEN for public key %s (object 0x%04x on device %s): %s",
			res.SPKIFingerprint, ak.ObjectID, b.Device.Serial, res.Findings[0])
	}
	scope := "the CA's signature ledger"
	if published {
		scope = "the artifacts published for it"
	}
	origin := "was generated inside"
	if !ak.Attestation.IsGeneratedOnDevice() {
		origin = "is confined to"
	}
	return fmt.Sprintf("OK: public key %s %s YubiHSM %s as object 0x%04x%s and cannot be exported from it; "+
		"the device performed %d signature(s) with it, all accounted for by %s — so this key has signed "+
		"nothing else, on or off the device",
		res.SPKIFingerprint, origin, b.Device.Serial, ak.ObjectID, labelSuffix(ak.KeyLabel),
		ak.DeviceSignatures, scope)
}

// publicKeysEqual compares two public keys structurally, tolerating nils.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if ae, ok := a.(equaler); ok {
		return ae.Equal(b)
	}
	return false
}
