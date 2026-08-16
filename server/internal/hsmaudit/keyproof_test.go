package hsmaudit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
)

// Fixtures captured from the YubiHSM 2 (serial 31650425, firmware 2.4.0) this
// subsystem was validated against, and reused here rather than synthesized: the
// encoding of the Yubico attestation extensions is not specified anywhere this
// code could be checked against, so a test built on invented DER would prove
// only that the code agrees with itself.
//
// The attested key is object 0x7e57 labelled "hsmaudit-test", an ECP256 signing
// key generated on-device with capability sign-ecdsa only — so it is both
// non-exportable and generated-on-device, which is what the audit join requires.
const fixtureAttestationPEM = `-----BEGIN CERTIFICATE-----
MIICuDCCAaCgAwIBAgIQAQfJA3sSkvv9gYuzpDEwrTANBgkqhkiG9w0BAQsFADAp
MScwJQYDVQQDDB5ZdWJpSFNNIEF0dGVzdGF0aW9uICgzMTY1MDQyNSkwIBcNMTcw
MTAxMDAwMDAwWhgPMjA3MTEwMDUwMDAwMDBaMCgxJjAkBgNVBAMMHVl1YmlIU00g
QXR0ZXN0YXRpb24gaWQ6MHg3ZTU3MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
9h5qab8Bq5iEUVC8zncnCz9g33ctB9baF7ICxl+KEUMp4QB2ra95bSRf2lwAE473
Ug705nI8OEl/DCKGFGQpHqOBpTCBojATBgorBgEEAYLECgQBBAUEAwIEADAUBgor
BgEEAYLECgQCBAYCBAHi8nkwEgYKKwYBBAGCxAoEAwQEAwIAATATBgorBgEEAYLE
CgQEBAUDAwAAATAZBgorBgEEAYLECgQFBAsDCQAAAAAAAAAAgDASBgorBgEEAYLE
CgQGBAQCAn5XMB0GCisGAQQBgsQKBAkEDwwNaHNtYXVkaXQtdGVzdDANBgkqhkiG
9w0BAQsFAAOCAQEAmfpUhnBfe5sU/X8QXcCHowQmUfeQynq2iMRLFfDMJug1Yj46
4Yh1HKJsksuJr8vEvJMmIrCzEXI2EXCCKUee8ZCqK81m4z6dJBllI3qMx7BBNikx
z3JvVg/QaebxRPYinY0A/G7CyEDdOK0uFFya9aIXe+n1E+sZ3DTjmHTK5VKuqEGR
S4FZdDc6KnepxS2N/ojyHGRLxDMjMAGl6osXxKrFge+ZZE3jGELmQRdq0f7dFR8/
d0J39hj4/2v4P9VMFTmKtgQefYmnOnD/wYC+tfRFnj/Ys94Wc+WvcclodKNziPnR
f0WKW1HTSE9MPKNkmhnTvO/NH6/mUT6fnL7DpA==
-----END CERTIFICATE-----
`

// fixtureDeviceCertPEM is the device attestation certificate read from opaque
// object 0x0000 on the same device. It issues fixtureAttestationPEM, which is
// what makes the assertions the device's rather than the exporter's.
const fixtureDeviceCertPEM = `-----BEGIN CERTIFICATE-----
MIIDWDCCAkCgAwIBAgIJAMe6avTqzrZvMA0GCSqGSIb3DQEBCwUAMCgxJjAkBgNV
BAMMHVl1YmljbyBZdWJpSFNNIDY3NDIwMzYgU3ViLUNBMCAXDTE3MDEwMTAwMDAw
MFoYDzIwNzExMDA1MDAwMDAwWjApMScwJQYDVQQDDB5ZdWJpSFNNIEF0dGVzdGF0
aW9uICgzMTY1MDQyNSkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDk
gZAmFVlK3T7USxTc07lVC1iL3gUmZccAZopsQVMcS60wgI8+Gg4Lwnh9XTrjTVwr
gVJmvy811QhzFrZyHyG04xzIkI1rbZ8vLo9vGCanxoMD3+KZ0aYR8MuDeH1Ft6eW
6U6cCoGrJr2ie+A648Eoa3PTAtyvgFZbxgdBTC92nE207ICgq0pYeD6dLqJn2Vvc
WGS+Wdg26opY3pijqrw3FQAs9kmK+eLXVGQx8DhYiC6F/Nu3DwST/utE66QG9wMI
dM/mx6XWYwdA0ltxfK7D5llK64rI1uuWNsdp30sqRfVUJba5+c6O6LsDsfUU0kSQ
tIYsItvj8IIxnyDZQTb5AgMBAAGjgYEwfzATBgorBgEEAYLECgQBBAUEAwIEADAU
BgorBgEEAYLECgQCBAYCBAHi8nkwHQYDVR0OBBYEFNyOCJsY8QprJUfDOdhENgUK
LuAeMB8GA1UdIwQYMBaAFORdpfNhsJGzDY8sb6BA22/vV5GOMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggEBABrmUlQTL7qVCrCYV+P7JcQ+O58Y
mseAwPXnA9LvK5ma4HWh+FvPmqT1MCBQ5Ni4d/gW3n8ptqa0KUsQRgdyjOdnICkp
SFnF2FN8sWdSRqoXJI/0pVB0XZlpmvO76w1TOPdf2IGtO0T/p9b+1hEnyg50LbeQ
Rkl9JyGEgHp09Un06fUIAXhPMpqmm8rxnZOUwf95zZNdjTO/+5/duYB0oNkAzzWY
2n5GH/RC4vHui2d1YbJXxIMTca59ap23tNLaWBG82Y8YNzXcxvOFh1M1JXFVpxW7
oFXZ1Az2XqxvooBIxeXhRWNKhuu/T6E7b8loHWZed4nc8HVHzrjKYQT1KGo=
-----END CERTIFICATE-----
`

// attestedKeyID is the on-device handle the fixture attests. Tests sign with
// this handle so that the full argument — public key to handle to log entries —
// is exercised end to end rather than only its last link.
const attestedKeyID uint16 = 0x7e57

func fixtureAttestation() hsmattest.Attestation {
	return hsmattest.Attestation{
		KeyLabel:             "hsmaudit-test",
		CertificatePEM:       fixtureAttestationPEM,
		DeviceCertificatePEM: fixtureDeviceCertPEM,
	}
}

// fixturePublicKey is the attested key itself, as an auditor would extract it
// from the CA certificate they are deciding whether to trust.
func fixturePublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	att := fixtureAttestation()
	cert, err := att.Certificate()
	if err != nil {
		t.Fatalf("parsing fixture attestation: %v", err)
	}
	return cert.PublicKey
}

// fakeAttester serves the captured fixture for the attested handle and fails
// for anything else, mirroring a device asked about an object it does not hold.
type fakeAttester struct {
	calls []uint16
	err   error
}

func (f *fakeAttester) AttestObject(ctx context.Context, objectID uint16) (*hsmattest.Attestation, error) {
	f.calls = append(f.calls, objectID)
	if f.err != nil {
		return nil, f.err
	}
	if objectID != attestedKeyID {
		return nil, errNoSuchObject
	}
	att := fixtureAttestation()
	return &att, nil
}

var errNoSuchObject = &objectError{}

type objectError struct{}

func (*objectError) Error() string { return "no asymmetric key with that object ID on the device" }

// genEntry builds the GENERATE ASYMMETRIC KEY entry a device writes when a key
// is created. The field layout is what a YubiHSM 2 on firmware 2.4.0 actually
// logs: the new object in target_key, 0xffff in second_key, and the request
// command with the high bit set as the result.
func genEntry(key uint16) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Command: hsm.CmdGenerateAsymmetricKey, Length: 53, SessionKey: 1,
		TargetKey: key, SecondKey: 0xffff, Result: hsm.CmdGenerateAsymmetricKey | 0x80, Tick: 50,
	}
}

// exportEntry builds the EXPORT WRAPPED entry a device writes when an object
// leaves under a wrap key. Hardware puts the *wrap key* in target_key and the
// exported object in second_key — the reverse of every other command — which is
// exactly the trap AnalyzeKeyLifecycle has to avoid falling into.
func exportEntry(wrapKey, object uint16) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Command: hsm.CmdExportWrapped, Length: 5, SessionKey: 1,
		TargetKey: wrapKey, SecondKey: object, Result: hsm.CmdExportWrapped | 0x80, Tick: 60,
	}
}

func deleteEntry(key uint16) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Command: hsm.CmdDeleteObject, Length: 3, SessionKey: 1,
		TargetKey: key, SecondKey: 0xffff, Result: hsm.CmdDeleteObject | 0x80, Tick: 70,
	}
}

// keyChain is chain() with the attested key's creation recorded first, as any
// real history would have it: the log starts at a factory reset, which erases
// every object, so a key that signs must have been created within the log.
func keyChain(anchor string, rest ...hsm.AuditLogEntry) []hsm.AuditLogEntry {
	return chain(anchor, append([]hsm.AuditLogEntry{genEntry(attestedKeyID)}, rest...)...)
}

// An export must carry the device's own statement about every key that signed:
// without it the bundle bounds what the device did, not what the key did.
func TestExportAttestsSigningKeys(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	b, report, err := svc.ExportWithReport(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(b.KeyAttestations) != 1 {
		t.Fatalf("export carried %d key attestation(s), want 1", len(b.KeyAttestations))
	}
	if report.AttestedKeys != 1 || len(report.AttestationErrors) != 0 {
		t.Fatalf("report says %d attested, %d error(s)", report.AttestedKeys, len(report.AttestationErrors))
	}
	if b.Version != BundleVersion {
		t.Fatalf("bundle version %d, want %d", b.Version, BundleVersion)
	}
}

// The whole point of Task 170: an auditor holding a public key gets an answer
// about that key, not about a count of device operations.
func TestVerifyBundleProvesNamedPublicKey(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, attestedKeyID, "bb")

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		ExpectedSerial: "31650425",
		SkipFreshness:  true,
		ExpectedKeys:   []ExpectedKey{{Name: "ca.pem", PublicKey: fixturePublicKey(t)}},
	})
	if !res.OK {
		t.Fatalf("a genuine key proof was rejected: %v", res.Err())
	}
	if len(res.Keys) != 1 {
		t.Fatalf("got %d key verdict(s), want 1", len(res.Keys))
	}
	k := res.Keys[0]
	if !k.OK {
		t.Fatalf("key proof failed: %v", k.Err())
	}
	if k.Key.ObjectID != attestedKeyID {
		t.Fatalf("public key bound to object 0x%04x, want 0x%04x", k.Key.ObjectID, attestedKeyID)
	}
	if k.Key.DeviceSignatures != 2 || k.Key.LedgerSignatures != 2 {
		t.Fatalf("counts device=%d ledger=%d, want 2 and 2", k.Key.DeviceSignatures, k.Key.LedgerSignatures)
	}
	if !k.Key.Attestation.IsNonExportable() || !k.Key.Attestation.IsGeneratedOnDevice() {
		t.Fatal("the attested key was not reported as generated on-device and non-exportable")
	}
	// The summary is what an operator reads; it must make the key-scoped claim
	// rather than the device-scoped one.
	if !strings.Contains(k.Summary, "cannot be exported") || !strings.Contains(k.Summary, "signed nothing else") {
		t.Fatalf("summary does not state the key-scoped conclusion: %q", k.Summary)
	}
}

// A key the bundle does not attest is a key whose signatures could equally have
// been produced by a copy of it somewhere else, where no device log exists.
func TestVerifyBundleRejectsUnattestedSigningKey(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	svc.SetAttester(nil) // a deployment that never attests
	addLedger(t, store, attestedKeyID, "aa")

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(b.KeyAttestations) != 0 {
		t.Fatal("bundle unexpectedly carries attestations")
	}
	res := VerifyBundle(b, VerifyOptions{ExpectedAnchor: testAnchor, SkipFreshness: true})
	if res.OK {
		t.Fatal("a bundle that cannot show its signing key is confined to the HSM verified")
	}
	if !strings.Contains(res.Err().Error(), "no attestation") {
		t.Fatalf("finding does not name the missing attestation: %v", res.Err())
	}

	// The escape hatch reports rather than fails, and says so.
	relaxed := VerifyBundle(b, VerifyOptions{ExpectedAnchor: testAnchor, SkipFreshness: true, AllowUnattestedKeys: true})
	if !relaxed.OK {
		t.Fatalf("-allow-unattested-keys did not downgrade the failure: %v", relaxed.Err())
	}
	if len(relaxed.Findings) == 0 || !strings.Contains(relaxed.Findings[0], "IGNORED") {
		t.Fatalf("the downgrade was silent: %v", relaxed.Findings)
	}
}

// Asking about a key the device never attested must not be answered with the
// device's clean bill of health for some other key.
func TestProveKeyRejectsForeignPublicKey(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		SkipFreshness:  true,
		ExpectedKeys:   []ExpectedKey{{Name: "other-ca.pem", PublicKey: foreign.Public()}},
	})
	if res.OK {
		t.Fatal("a bundle verified as proving a key it never mentions")
	}
	if !strings.Contains(res.Keys[0].Summary, "NOT PROVEN") {
		t.Fatalf("verdict for an unattested key: %q", res.Keys[0].Summary)
	}
}

// A surplus must be reported against the key that produced it, in the terms the
// auditor asked the question.
func TestProveKeyReportsSurplusForThatKey(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa") // one row for two device signatures

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	res := VerifyBundle(b, VerifyOptions{
		ExpectedAnchor: testAnchor,
		SkipFreshness:  true,
		ExpectedKeys:   []ExpectedKey{{Name: "ca.pem", PublicKey: fixturePublicKey(t)}},
	})
	if res.OK {
		t.Fatal("an unpublished signature by the named key was not reported")
	}
	if !strings.Contains(res.Keys[0].Err().Error(), "never published") {
		t.Fatalf("key verdict does not name the unpublished signature: %v", res.Keys[0].Err())
	}
}

// A handle created twice has held two different keys, so signature counts
// against it cannot all be attributed to the attested one.
func TestKeyLifecycleDetectsHandleReuse(t *testing.T) {
	entries := chain(testAnchor,
		genEntry(attestedKeyID),
		signEntry(attestedKeyID),
		deleteEntry(attestedKeyID),
		genEntry(attestedKeyID),
		signEntry(attestedKeyID),
	)
	lc := AnalyzeKeyLifecycle(entries, attestedKeyID)
	if lc.OK {
		t.Fatal("a reused object handle was accepted")
	}
	joined := strings.Join(lc.Findings, "; ")
	if !strings.Contains(joined, "created 2 times") {
		t.Fatalf("finding does not identify the reuse: %v", lc.Findings)
	}
	if !strings.Contains(joined, "deleted") {
		t.Fatalf("finding does not identify the deletion: %v", lc.Findings)
	}
}

// An object that left the device under a wrap key may have a copy elsewhere,
// which would sign without producing any log entry at all. The hardware puts
// the exported object in second_key, so reading target_key alone would miss it.
func TestKeyLifecycleDetectsWrapExport(t *testing.T) {
	entries := chain(testAnchor,
		genEntry(attestedKeyID),
		exportEntry(0x7e60, attestedKeyID),
		signEntry(attestedKeyID),
	)
	lc := AnalyzeKeyLifecycle(entries, attestedKeyID)
	if lc.OK {
		t.Fatal("an object exported under wrap was accepted as confined")
	}
	if !strings.Contains(strings.Join(lc.Findings, "; "), "exported under a wrap key") {
		t.Fatalf("finding does not identify the export: %v", lc.Findings)
	}
	if len(lc.Exported) != 1 {
		t.Fatalf("recorded %d export event(s), want 1", len(lc.Exported))
	}
}

// The log begins at a factory reset, which erases every object. A key that
// signs but that the log never saw created means entries are missing.
func TestKeyLifecycleRequiresCreationInLog(t *testing.T) {
	entries := chain(testAnchor, signEntry(attestedKeyID))
	lc := AnalyzeKeyLifecycle(entries, attestedKeyID)
	if lc.OK {
		t.Fatal("a key with no recorded creation was accepted")
	}
	if !strings.Contains(strings.Join(lc.Findings, "; "), "records no creation") {
		t.Fatalf("finding does not identify the missing creation: %v", lc.Findings)
	}
}

// An imported key existed in software before it arrived, so no device log can
// bound what was signed with it.
func TestKeyLifecycleRejectsImportedKey(t *testing.T) {
	imported := hsm.AuditLogEntry{
		Command: cmdPutAsymmetricKey, Length: 100, SessionKey: 1,
		TargetKey: attestedKeyID, SecondKey: 0xffff, Result: cmdPutAsymmetricKey | 0x80,
	}
	entries := chain(testAnchor, imported, signEntry(attestedKeyID))
	lc := AnalyzeKeyLifecycle(entries, attestedKeyID)
	if lc.OK {
		t.Fatal("an imported key was accepted as confined")
	}
	if !strings.Contains(strings.Join(lc.Findings, "; "), "imported rather than generated") {
		t.Fatalf("finding does not identify the import: %v", lc.Findings)
	}
}

// An attestation from a different HSM describes a genuinely confined key that
// has nothing to do with the signatures in this log.
func TestVerifyAttestationsRejectsForeignDevice(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")

	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	b.Device.Serial = "99999999" // the bundle claims a different device
	res := VerifyAttestations(b, hsmattest.DefaultPolicy())
	if res.OK {
		t.Fatal("an attestation from another device was accepted for this log")
	}
	if !strings.Contains(res.Err().Error(), "serial") {
		t.Fatalf("finding does not name the serial mismatch: %v", res.Err())
	}
}

// Dropping a key attestation between exports would let a CA quietly stop
// showing that the key behind its signatures is confined to the device.
func TestContinuationDetectsDroppedKeyAttestation(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, dev, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	prev, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("first export: %v", err)
	}

	dev.entries = keyChain(testAnchor, signEntry(attestedKeyID), signEntry(attestedKeyID))
	addLedger(t, store, attestedKeyID, "bb")
	svc.SetAttester(nil)
	next, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("second export: %v", err)
	}

	cont := VerifyContinuation(prev, next)
	if cont.OK {
		t.Fatal("an export that dropped a previously published attestation was accepted")
	}
	if !strings.Contains(cont.Err().Error(), "is not attested now") {
		t.Fatalf("finding does not name the dropped attestation: %v", cont.Err())
	}
}

// A v1 bundle predates key attestation. It is still readable — an auditor
// holding an old export should get a verdict, not a parse error — but it cannot
// establish confinement, and the verdict has to say so rather than pass.
func TestLegacyBundleVersionIsReadableButUnproven(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	b, err := svc.Export(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	b.Version = 1
	b.KeyAttestations = nil

	res := VerifyBundle(b, VerifyOptions{ExpectedAnchor: testAnchor, SkipFreshness: true})
	if res.OK {
		t.Fatal("a bundle with no key attestations verified")
	}
	if strings.Contains(res.Err().Error(), "unsupported bundle version") {
		t.Fatalf("a v1 bundle was refused outright rather than reported on: %v", res.Err())
	}
	if !strings.Contains(res.Err().Error(), "no attestation") {
		t.Fatalf("finding does not explain what a v1 bundle cannot show: %v", res.Err())
	}
}

// Signatures the CA could not attribute to a device handle land on object
// 0x0000, which is not a key. They can be neither attested nor reconciled.
func TestUnattributedSignaturesAreReported(t *testing.T) {
	entries := keyChain(testAnchor, signEntry(attestedKeyID))
	svc, _, store := provisioned(t, entries)
	addLedger(t, store, attestedKeyID, "aa")
	addLedger(t, store, 0, "cc") // a signature with no resolvable key handle

	b, report, err := svc.ExportWithReport(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(report.AttestationErrors) != 0 {
		t.Fatalf("the export tried to attest object 0x0000: %v", report.AttestationErrors)
	}
	res := VerifyBundle(b, VerifyOptions{ExpectedAnchor: testAnchor, SkipFreshness: true})
	if res.OK {
		t.Fatal("an unattributable ledger row was accepted")
	}
	if !strings.Contains(res.Err().Error(), "not a key handle") {
		t.Fatalf("finding does not explain the unattributed row: %v", res.Err())
	}
}

// SigningKeyIDs must span both sides: a key the device used but the CA never
// recorded is the abuse case, and a key the CA recorded but the device never
// logged means records are missing. Both need attesting.
func TestSigningKeyIDsUnionsBothSides(t *testing.T) {
	entries := chain(testAnchor, signEntry(0x1111))
	ledger := []LedgerEntry{{KeyID: 0x2222}}
	got := SigningKeyIDs(entries, ledger)
	if len(got) != 2 || got[0] != 0x1111 || got[1] != 0x2222 {
		t.Fatalf("SigningKeyIDs = %#x, want [0x1111 0x2222]", got)
	}
}
