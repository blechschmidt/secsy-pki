package hsmaudit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
)

// A synthetic YubiHSM attestation certificate authority, for the commitment
// tests.
//
// The key-attestation tests can use a fixture captured from real hardware
// because the thing being attested — one long-lived CA key — is fixed. A
// commitment cannot: its label is a digest of the audit head, which every test
// changes by construction, so the certificate has to be minted during the test.
//
// That is exactly the situation where a synthesizer quietly drifts from the
// hardware and the tests keep passing. TestSyntheticAttestationMatchesHardware
// closes that by re-encoding the captured fixture's own claims through this
// builder and requiring the resulting extension bytes to be identical to the
// ones the device emitted. If Yubico's encoding is ever misread here, that test
// fails rather than the commitment tests silently checking a private convention.

// yubicoAttestOIDs, duplicated from internal/hsmattest, which keeps them
// unexported. Repeating them here is deliberate: a test that imported the
// constants it is checking would agree with the implementation by construction.
var (
	testOIDFirmware     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 1}
	testOIDDeviceSerial = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 2}
	testOIDOrigin       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 3}
	testOIDDomains      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 4}
	testOIDCapabilities = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 5}
	testOIDObjectID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 6}
	testOIDLabel        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4, 9}
)

// attestClaims are the assertions a synthetic attestation certificate carries.
type attestClaims struct {
	Firmware     [3]byte
	Serial       string
	Origin       uint8
	Domains      uint16
	Capabilities uint64
	ObjectID     uint16
	Label        string
}

// commitmentClaims are what a genuine commitment attestation asserts: an object
// in the reserved range, generated on-device, holding no capability at all.
func commitmentClaims(serial string, objectID uint16, label string) attestClaims {
	return attestClaims{
		Firmware:     [3]byte{2, 4, 0},
		Serial:       serial,
		Origin:       hsmattest.OriginGenerated,
		Domains:      1,
		Capabilities: 0,
		ObjectID:     objectID,
		Label:        label,
	}
}

// yubicoExtensions encodes the seven attestation extensions the way a YubiHSM 2
// on firmware 2.4.0 does. See TestSyntheticAttestationMatchesHardware.
func yubicoExtensions(t *testing.T, c attestClaims) []pkix.Extension {
	t.Helper()
	marshal := func(v any) []byte {
		raw, err := asn1.Marshal(v)
		if err != nil {
			t.Fatalf("encoding attestation extension: %v", err)
		}
		return raw
	}
	serial, ok := new(big.Int).SetString(c.Serial, 10)
	if !ok {
		t.Fatalf("device serial %q is not a decimal integer", c.Serial)
	}
	// The device encodes origin, domains and capabilities as BIT STRINGs whose
	// content is the big-endian mask with no unused bits, at the natural width of
	// each field: one byte, two bytes, eight bytes.
	bits := func(b []byte) asn1.BitString {
		return asn1.BitString{Bytes: b, BitLength: len(b) * 8}
	}
	be := func(v uint64, n int) []byte {
		out := make([]byte, n)
		for i := n - 1; i >= 0; i-- {
			out[i] = byte(v)
			v >>= 8
		}
		return out
	}
	return []pkix.Extension{
		{Id: testOIDFirmware, Value: marshal(c.Firmware[:])},
		{Id: testOIDDeviceSerial, Value: marshal(serial)},
		{Id: testOIDOrigin, Value: marshal(bits([]byte{c.Origin}))},
		{Id: testOIDDomains, Value: marshal(bits(be(uint64(c.Domains), 2)))},
		{Id: testOIDCapabilities, Value: marshal(bits(be(c.Capabilities, 8)))},
		{Id: testOIDObjectID, Value: marshal(int(c.ObjectID))},
		{Id: testOIDLabel, Value: marshal(asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(c.Label)})},
	}
}

// fakeDeviceCA is a stand-in for a YubiHSM's factory attestation key and the
// Yubico PKI above it: a root, a device attestation certificate issued by it,
// and the ability to mint per-object attestation certificates.
type fakeDeviceCA struct {
	serial  string
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	devCert *x509.Certificate
	devKey  *ecdsa.PrivateKey
}

func newFakeDeviceCA(t *testing.T, serial string) *fakeDeviceCA {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating attestation root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test YubiHSM Attestation Root CA"},
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(40 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root := selfSign(t, rootTmpl, rootKey)

	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating device attestation key: %v", err)
	}
	// The subject mirrors the hardware's — "YubiHSM Attestation (31650425)" —
	// because hsmattest warns when the device certificate's common name does not
	// mention the serial the key attestation asserts.
	devTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("YubiHSM Attestation (%s)", serial)},
		// A clockless YubiHSM stamps a fixed 2017..2071 validity into these.
		NotBefore:             time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2071, 10, 5, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, devTmpl, root, &devKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("issuing device attestation certificate: %v", err)
	}
	devCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing device attestation certificate: %v", err)
	}
	return &fakeDeviceCA{serial: serial, root: root, rootKey: rootKey, devCert: devCert, devKey: devKey}
}

func selfSign(t *testing.T, tmpl *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signing %s: %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing %s: %v", tmpl.Subject.CommonName, err)
	}
	return cert
}

// attest mints an attestation certificate over a freshly generated key, the way
// SIGN ATTESTATION CERTIFICATE does on the device.
func (f *fakeDeviceCA) attest(t *testing.T, c attestClaims) string {
	t.Helper()
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating attested key: %v", err)
	}
	return f.attestKey(t, c, &subjectKey.PublicKey)
}

// attestKey mints an attestation certificate over a caller-supplied public key,
// for a test that needs the same key attested twice.
func (f *fakeDeviceCA) attestKey(t *testing.T, c attestClaims, pub *ecdsa.PublicKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: fmt.Sprintf("YubiHSM Attestation id:0x%04x", c.ObjectID)},
		NotBefore:       time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:        time.Date(2071, 10, 5, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: yubicoExtensions(t, c),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.devCert, pub, f.devKey)
	if err != nil {
		t.Fatalf("signing attestation certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (f *fakeDeviceCA) deviceCertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.devCert.Raw}))
}

// policy returns an attestation policy that trusts this fake CA's root *and*
// Yubico's embedded ones, so a bundle carrying both a synthetic commitment and
// the captured hardware key attestation verifies under a single policy — which
// is also the shape a deployment with a replaced attestation key would use.
//
// The embedded pool is cloned rather than added to: it is process-wide, and a
// test that mutated it would leak a private root into every later test.
func (f *fakeDeviceCA) policy() *hsmattest.Policy {
	pol := hsmattest.DefaultPolicy()
	pool := hsmattest.EmbeddedRoots().Clone()
	pool.AddCert(f.root)
	pol.Roots = pool
	pol.Intermediates = hsmattest.EmbeddedIntermediates()
	return &pol
}

// TestSyntheticAttestationMatchesHardware is what licenses every other use of
// the synthesizer above.
//
// It parses the attestation certificate captured from a real YubiHSM 2, feeds
// the claims it finds back through the encoder, and requires the resulting
// extension bytes to be byte-identical to the device's. Yubico documents none of
// this encoding, so without this test the commitment tests would only establish
// that the verifier agrees with a convention invented here.
func TestSyntheticAttestationMatchesHardware(t *testing.T) {
	att := fixtureAttestation()
	cert, err := att.Certificate()
	if err != nil {
		t.Fatalf("parsing hardware fixture: %v", err)
	}
	claims, err := hsmattest.ParseClaims(cert)
	if err != nil {
		t.Fatalf("parsing hardware fixture claims: %v", err)
	}
	if len(claims.Missing) != 0 {
		t.Fatalf("the hardware fixture is missing extensions %v; the fixture, not the encoder, is wrong", claims.Missing)
	}

	var fw [3]byte
	if _, err := fmt.Sscanf(claims.FirmwareVersion, "%d.%d.%d", &fw[0], &fw[1], &fw[2]); err != nil {
		t.Fatalf("parsing fixture firmware %q: %v", claims.FirmwareVersion, err)
	}
	var domains uint16
	for _, d := range claims.Domains {
		domains |= 1 << uint(d-1)
	}
	got := yubicoExtensions(t, attestClaims{
		Firmware:     fw,
		Serial:       claims.DeviceSerial,
		Origin:       claims.Origin,
		Domains:      domains,
		Capabilities: uint64(claims.Capabilities),
		ObjectID:     claims.ObjectID,
		Label:        claims.Label,
	})

	// The Yubico attestation arc is 1.3.6.1.4.1.41482.4.x, so an extension
	// belongs to it when its first eight arcs match.
	yubicoArc := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 4}
	want := map[string][]byte{}
	for _, e := range cert.Extensions {
		if len(e.Id) == len(yubicoArc)+1 && e.Id[:len(yubicoArc)].Equal(yubicoArc) {
			want[e.Id.String()] = e.Value
		}
	}
	if len(want) != 7 {
		t.Fatalf("the hardware fixture carries %d Yubico attestation extensions, want 7", len(want))
	}
	for _, e := range got {
		w, ok := want[e.Id.String()]
		if !ok {
			t.Errorf("encoder produced extension %s, which the device does not emit", e.Id)
			continue
		}
		if string(e.Value) != string(w) {
			t.Errorf("extension %s: encoder produced %x, device emitted %x", e.Id, e.Value, w)
		}
		delete(want, e.Id.String())
	}
	for oid := range want {
		t.Errorf("the device emits extension %s, which the encoder does not produce", oid)
	}
}

// The synthesizer has to survive the verifier it is used against, or the
// commitment tests would be checking a certificate hsmattest rejects for
// reasons unrelated to what they are about.
func TestSyntheticAttestationVerifies(t *testing.T) {
	ca := newFakeDeviceCA(t, "31650425")
	att := &hsmattest.Attestation{
		CertificatePEM:       ca.attest(t, commitmentClaims("31650425", DefaultCommitmentKeyID, "sb1:test")),
		DeviceCertificatePEM: ca.deviceCertPEM(),
	}
	res := hsmattest.Verify(att, *ca.policy())
	if !res.Verified {
		t.Fatalf("a synthetic attestation was rejected: %v", res.Problems)
	}
	if !res.ChainAnchored {
		t.Fatal("the synthetic device certificate did not chain to the fake root")
	}
	if !res.DeviceBound {
		t.Fatal("the synthetic attestation was not bound to the device certificate")
	}
	if !res.NonExportable || !res.GeneratedOnDevice {
		t.Fatalf("a zero-capability generated key read as exportable=%v generated=%v",
			!res.NonExportable, res.GeneratedOnDevice)
	}
	if res.ObjectID != DefaultCommitmentKeyID {
		t.Fatalf("attested object 0x%04x, want 0x%04x", res.ObjectID, DefaultCommitmentKeyID)
	}
	if _, err := strconv.Atoi(res.DeviceSerial); err != nil || res.DeviceSerial != "31650425" {
		t.Fatalf("attested serial %q, want 31650425", res.DeviceSerial)
	}
}
