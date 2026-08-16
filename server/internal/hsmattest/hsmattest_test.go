package hsmattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// realAttestation returns an Attestation built from the captured hardware
// fixtures.
func realAttestation() *Attestation {
	return &Attestation{
		KeyLabel:             "hsmaudit-test",
		CertificatePEM:       realAttestationPEM,
		DeviceCertificatePEM: realDeviceCertPEM,
	}
}

func TestParseClaimsFromRealDevice(t *testing.T) {
	cert, err := realAttestation().Certificate()
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	claims, err := ParseClaims(cert)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}

	if got, want := claims.FirmwareVersion, "2.4.0"; got != want {
		t.Errorf("firmware = %q, want %q", got, want)
	}
	if got, want := claims.DeviceSerial, "31650425"; got != want {
		t.Errorf("device serial = %q, want %q", got, want)
	}
	if got, want := claims.ObjectID, uint16(0x7e57); got != want {
		t.Errorf("object id = 0x%04x, want 0x%04x", got, want)
	}
	if got, want := claims.Label, "hsmaudit-test"; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
	if got, want := claims.Capabilities, Capabilities(0x80); got != want {
		t.Errorf("capabilities = 0x%016x, want 0x%016x", uint64(got), uint64(want))
	}
	if got, want := strings.Join(claims.CapabilityNames, ","), "sign-ecdsa"; got != want {
		t.Errorf("capability names = %q, want %q", got, want)
	}
	if got, want := len(claims.Domains), 1; got != want || claims.Domains[0] != 1 {
		t.Errorf("domains = %v, want [1]", claims.Domains)
	}
	if len(claims.Missing) != 0 {
		t.Errorf("Missing = %v, want none — the device emits all seven extensions", claims.Missing)
	}

	// The security-relevant conclusions.
	if claims.Exportable() {
		t.Error("Exportable() = true; the fixture key does not hold exportable-under-wrap")
	}
	if !claims.GeneratedOnDevice() {
		t.Errorf("GeneratedOnDevice() = false; origin was %s", claims.OriginString())
	}
	if got, want := claims.OriginString(), "generated"; got != want {
		t.Errorf("origin = %q, want %q", got, want)
	}
	if !claims.Capabilities.CanSign() {
		t.Error("CanSign() = false for a sign-ecdsa key")
	}
}

func TestVerifyRealDeviceAttestation(t *testing.T) {
	res := Verify(realAttestation(), DefaultPolicy())

	if !res.Verified {
		t.Fatalf("Verified = false, problems: %v", res.Problems)
	}
	if !res.NonExportable {
		t.Error("NonExportable = false")
	}
	if !res.GeneratedOnDevice {
		t.Error("GeneratedOnDevice = false")
	}
	if !res.DeviceBound {
		t.Error("DeviceBound = false; the leaf is signed by the accompanying device certificate")
	}
	if got, want := res.PublicKeyAlgorithm, "ECDSA"; got != want {
		t.Errorf("PublicKeyAlgorithm = %q, want %q", got, want)
	}
	if got, want := res.PublicKeyDetail, "P-256"; got != want {
		t.Errorf("PublicKeyDetail = %q, want %q", got, want)
	}
	if !strings.HasPrefix(res.SPKIFingerprint, "SHA256:") {
		t.Errorf("SPKIFingerprint = %q, want the canonical SHA256: form", res.SPKIFingerprint)
	}

	// Real hardware anchors with no configuration. Yubico publishes both the
	// root and this device's issuing sub-CA, and both ship embedded, so the
	// default policy's anchoring requirement is satisfied by stock hardware.
	if !res.ChainAnchored {
		t.Errorf("ChainAnchored = false; the fixture device must chain to the embedded Yubico roots (problems=%v warnings=%v)",
			res.Problems, res.Warnings)
	}
	if got, want := res.TrustAnchor, "Yubico YubiHSM Root CA"; got != want {
		t.Errorf("TrustAnchor = %q, want %q", got, want)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none for stock hardware", res.Warnings)
	}
	if !strings.Contains(res.Summary, "cannot be exported") {
		t.Errorf("Summary = %q, want it to state the key cannot be exported", res.Summary)
	}
}

// The default policy demands an anchored chain, so a device certificate that
// does not chain to a Yubico root must fail rather than pass on the device's
// own say-so.
func TestVerifyRequireAnchoredChainFails(t *testing.T) {
	att := realAttestation()
	// A self-signed stand-in for the device certificate: structurally a device
	// cert, but issued by nobody Yubico vouches for.
	att.DeviceCertificatePEM = selfSignedPEM(t)

	res := Verify(att, DefaultPolicy())
	if res.Verified {
		t.Fatal("Verified = true despite an unanchorable device certificate")
	}
	if !containsSubstr(res.Problems, "does not chain to a trusted attestation root") &&
		!containsSubstr(res.Problems, "do not belong together") {
		t.Errorf("problems = %v, want the anchoring or binding failure", res.Problems)
	}
}

// An unanchored chain is nearly always a sub-CA published after this binary was
// built, so the verdict must name the URL that fixes it rather than leaving the
// operator to guess.
func TestUnanchoredChainNamesThePublishedIntermediate(t *testing.T) {
	att := realAttestation()
	pol := DefaultPolicy()
	pol.Roots = x509.NewCertPool() // trust nothing; the device cert is genuine
	pol.Intermediates = nil

	res := Verify(att, pol)
	if res.Verified {
		t.Fatal("Verified = true with an empty trust store")
	}
	const want = "https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem"
	if !containsSubstr(res.Problems, want) {
		t.Errorf("problems = %v, want them to name %s", res.Problems, want)
	}
}

// The published-intermediate URL is derived from the device certificate's
// authority key identifier, which is how an operator locates the one file that
// anchors their device.
func TestYubicoIntermediateURL(t *testing.T) {
	dev, err := realAttestation().DeviceCertificate()
	if err != nil {
		t.Fatal(err)
	}
	const want = "https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem"
	if got := YubicoIntermediateURL(dev); got != want {
		t.Errorf("YubicoIntermediateURL = %q, want %q", got, want)
	}
	if got := YubicoIntermediateURL(nil); got != "" {
		t.Errorf("YubicoIntermediateURL(nil) = %q, want empty", got)
	}
}

// The embedded bundle must actually contain the YubiHSM 2 attestation PKI —
// the one a YubiHSM's pre-loaded certificate chains through — and not only the
// YubiKey-family PKI that superficially resembles it.
func TestEmbeddedRootsIncludeYubiHSMPKI(t *testing.T) {
	var foundRoot, foundSubCA bool
	for _, c := range EmbeddedIntermediates() {
		if c.Subject.CommonName == "Yubico YubiHSM 6742036 Sub-CA" {
			foundSubCA = true
			if c.Issuer.CommonName != "Yubico YubiHSM Root CA" {
				t.Errorf("sub-CA issuer = %q, want %q", c.Issuer.CommonName, "Yubico YubiHSM Root CA")
			}
		}
	}
	if !foundSubCA {
		t.Error("the published YubiHSM 2 sub-CA is not embedded")
	}
	dev, err := realAttestation().DeviceCertificate()
	if err != nil {
		t.Fatal(err)
	}
	inter := x509.NewCertPool()
	for _, c := range EmbeddedIntermediates() {
		inter.AddCert(c)
	}
	chains, err := dev.Verify(x509.VerifyOptions{
		Roots: EmbeddedRoots(), Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("real device certificate does not chain to the embedded roots: %v", err)
	}
	if got := chains[0][len(chains[0])-1].Subject.CommonName; got == "Yubico YubiHSM Root CA" {
		foundRoot = true
	} else {
		t.Errorf("chain terminates at %q, want %q", got, "Yubico YubiHSM Root CA")
	}
	if !foundRoot {
		t.Error("the YubiHSM 2 attestation root is not embedded")
	}
}

// The binding to a specific key is what makes an attestation meaningful; a
// mismatch must fail rather than pass on the device's other assertions.
func TestVerifyExpectedPublicKeyMismatch(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pol := DefaultPolicy()
	pol.ExpectedPublicKey = &other.PublicKey

	res := Verify(realAttestation(), pol)
	if res.Verified {
		t.Fatal("Verified = true for an attestation of a different key")
	}
	if res.KeyMatched == nil || *res.KeyMatched {
		t.Errorf("KeyMatched = %v, want false", res.KeyMatched)
	}

	// The same attestation against the key it actually describes must pass.
	cert, err := realAttestation().Certificate()
	if err != nil {
		t.Fatal(err)
	}
	pol.ExpectedPublicKey = cert.PublicKey
	if res := Verify(realAttestation(), pol); !res.Verified {
		t.Fatalf("Verified = false for the matching key: %v", res.Problems)
	}
}

func TestVerifyExpectedIdentityMismatch(t *testing.T) {
	wrongID := uint16(0x1234)
	for name, mutate := range map[string]func(*Policy){
		"label":     func(p *Policy) { p.ExpectedLabel = "some-other-key" },
		"serial":    func(p *Policy) { p.ExpectedSerial = "99999999" },
		"object-id": func(p *Policy) { p.ExpectedObjectID = &wrongID },
	} {
		t.Run(name, func(t *testing.T) {
			pol := DefaultPolicy()
			mutate(&pol)
			if res := Verify(realAttestation(), pol); res.Verified {
				t.Fatalf("Verified = true despite a %s mismatch", name)
			}
		})
	}
}

// An attestation whose device certificate does not issue it must be rejected:
// this is what pairing a genuine attestation with an unrelated device
// certificate looks like.
func TestVerifyRejectsMismatchedDeviceCertificate(t *testing.T) {
	att := realAttestation()
	att.DeviceCertificatePEM = selfSignedPEM(t)

	res := Verify(att, DefaultPolicy())
	if res.Verified {
		t.Fatal("Verified = true for an attestation not signed by the accompanying device certificate")
	}
	if res.DeviceBound {
		t.Error("DeviceBound = true")
	}
	if !containsSubstr(res.Problems, "not signed by the accompanying device attestation certificate") {
		t.Errorf("problems = %v, want the signature failure", res.Problems)
	}
}

// Without a device certificate the assertions are unauthenticated, and the
// default policy says so rather than reporting the key as verified.
func TestVerifyRequiresDeviceBinding(t *testing.T) {
	att := realAttestation()
	att.DeviceCertificatePEM = ""

	if res := Verify(att, DefaultPolicy()); res.Verified {
		t.Fatal("Verified = true without a device attestation certificate")
	}

	pol := DefaultPolicy()
	pol.RequireDeviceBinding = false
	res := Verify(att, pol)
	if !res.Verified {
		t.Fatalf("Verified = false with device binding not required: %v", res.Problems)
	}
	if res.DeviceBound {
		t.Error("DeviceBound = true without a device certificate")
	}
}

// An exportable key is the case this whole feature exists to catch.
func TestVerifyExportableKeyFails(t *testing.T) {
	att := &Attestation{CertificatePEM: rewriteCapabilities(t, 0x80|1<<CapExportableUnderWrap)}

	pol := DefaultPolicy()
	pol.RequireDeviceBinding = false
	res := Verify(att, pol)

	if res.Verified {
		t.Fatal("Verified = true for a key holding exportable-under-wrap")
	}
	if res.NonExportable {
		t.Error("NonExportable = true for a key holding exportable-under-wrap")
	}
	if !containsSubstr(res.Problems, "exportable-under-wrap") {
		t.Errorf("problems = %v, want the exportability failure", res.Problems)
	}

	// Inspection mode reports the fact without failing.
	pol.RequireNonExportable = false
	res = Verify(att, pol)
	if !res.Verified {
		t.Fatalf("Verified = false with RequireNonExportable off: %v", res.Problems)
	}
	if res.NonExportable {
		t.Error("NonExportable = true")
	}
	if !containsSubstr(res.Warnings, "exportable-under-wrap") {
		t.Errorf("warnings = %v, want the exportability warning", res.Warnings)
	}
}

// An attestation stripped of the extensions being checked must not verify;
// otherwise omitting an inconvenient assertion would be a way to pass.
func TestVerifyRejectsStrippedExtensions(t *testing.T) {
	att := &Attestation{CertificatePEM: dropExtension(t, oidCapabilities)}

	pol := DefaultPolicy()
	pol.RequireDeviceBinding = false
	res := Verify(att, pol)

	if res.Verified {
		t.Fatal("Verified = true for an attestation missing the capabilities extension")
	}
	if !containsSubstr(res.Problems, "omits YubiHSM extension") {
		t.Errorf("problems = %v, want the completeness failure", res.Problems)
	}
}

// A certificate with no Yubico extensions at all is not a YubiHSM attestation.
func TestVerifyRejectsNonAttestationCertificate(t *testing.T) {
	res := Verify(&Attestation{CertificatePEM: selfSignedPEM(t)}, DefaultPolicy())
	if res.Verified {
		t.Fatal("Verified = true for a certificate carrying no attestation extensions")
	}
	if !containsSubstr(res.Problems, "no YubiHSM attestation extensions") {
		t.Errorf("problems = %v", res.Problems)
	}
}

func TestVerifyForbiddenCapabilities(t *testing.T) {
	pol := DefaultPolicy()
	pol.RequireDeviceBinding = false
	pol.ForbiddenCapabilities = []string{"sign-ecdsa"}

	res := Verify(realAttestation(), pol)
	if res.Verified {
		t.Fatal("Verified = true despite holding a forbidden capability")
	}
	if !containsSubstr(res.Problems, "capabilities the policy forbids: sign-ecdsa") {
		t.Errorf("problems = %v", res.Problems)
	}

	pol.ForbiddenCapabilities = []string{"not-a-capability"}
	if res := Verify(realAttestation(), pol); res.Verified {
		t.Fatal("Verified = true with an unparseable forbidden-capability list; policy errors must fail closed")
	}
}

func TestCapabilityTable(t *testing.T) {
	// The two constants the security verdicts hang on.
	if n := CapabilityName(CapExportableUnderWrap); n != "exportable-under-wrap" {
		t.Errorf("bit %d = %q, want exportable-under-wrap", CapExportableUnderWrap, n)
	}
	if n := CapabilityName(CapSignAttestationCertificate); n != "sign-attestation-certificate" {
		t.Errorf("bit %d = %q, want sign-attestation-certificate", CapSignAttestationCertificate, n)
	}
	// Bits 0..55 are assigned and unique.
	if got, want := len(capabilityNames), 56; got != want {
		t.Errorf("capability table has %d entries, want %d", got, want)
	}
	seen := map[string]uint8{}
	for bit, name := range capabilityNames {
		if bit > 55 {
			t.Errorf("capability %q at bit %d is outside the assigned range", name, bit)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("capability %q assigned to both bit %d and bit %d", name, prev, bit)
		}
		seen[name] = bit
	}

	mask, err := ParseCapabilityNames([]string{"exportable-under-wrap", " Sign-ECDSA "})
	if err != nil {
		t.Fatalf("ParseCapabilityNames: %v", err)
	}
	if want := Capabilities(1<<16 | 1<<7); mask != want {
		t.Errorf("mask = 0x%x, want 0x%x", uint64(mask), uint64(want))
	}
	if _, err := ParseCapabilityNames([]string{"nope"}); err == nil {
		t.Error("ParseCapabilityNames accepted an unknown name")
	}

	// An unnamed bit must be surfaced, not dropped.
	c := Capabilities(1 << 63)
	if got := c.Unknown(); len(got) != 1 || got[0] != 63 {
		t.Errorf("Unknown() = %v, want [63]", got)
	}
}

func TestEmbeddedRootsLoad(t *testing.T) {
	if len(EmbeddedIntermediates()) == 0 {
		t.Fatal("no embedded Yubico intermediates")
	}
	pool := EmbeddedRoots()
	if pool == nil || len(pool.Subjects()) == 0 { //nolint:staticcheck // Subjects is fine for an embedded pool
		t.Fatal("no embedded Yubico root")
	}
	// Every embedded intermediate must chain to the embedded root, or the
	// bundle we ship is not internally consistent.
	inter := x509.NewCertPool()
	for _, c := range EmbeddedIntermediates() {
		inter.AddCert(c)
	}
	for _, c := range EmbeddedIntermediates() {
		if _, err := c.Verify(x509.VerifyOptions{
			Roots: pool, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Errorf("embedded intermediate %q does not chain to the embedded root: %v", c.Subject.CommonName, err)
		}
	}
}

// --- helpers ---

func containsSubstr(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// selfSignedPEM returns an unrelated self-signed certificate.
func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// reissue re-signs the fixture's TBS content under a fresh key after applying
// mutate to its extensions, so tests can exercise capability values and missing
// extensions that the attached hardware will not produce on demand. The result
// is no longer device-signed, which is why callers disable device binding.
func reissue(t *testing.T, mutate func([]pkix.Extension) []pkix.Extension) string {
	t.Helper()
	orig, err := realAttestation().Certificate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exts := mutate(append([]pkix.Extension(nil), orig.Extensions...))

	tmpl := &x509.Certificate{
		SerialNumber:    orig.SerialNumber,
		Subject:         orig.Subject,
		NotBefore:       orig.NotBefore,
		NotAfter:        orig.NotAfter,
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, orig.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// rewriteCapabilities re-emits the fixture with a different capability mask.
func rewriteCapabilities(t *testing.T, mask uint64) string {
	t.Helper()
	raw := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		raw[i] = byte(mask)
		mask >>= 8
	}
	value, err := asn1.Marshal(asn1.BitString{Bytes: raw, BitLength: 64})
	if err != nil {
		t.Fatal(err)
	}
	return reissue(t, func(exts []pkix.Extension) []pkix.Extension {
		for i := range exts {
			if exts[i].Id.Equal(oidCapabilities) {
				exts[i].Value = value
			}
		}
		return exts
	})
}

// dropExtension re-emits the fixture with one attestation extension removed.
func dropExtension(t *testing.T, oid asn1.ObjectIdentifier) string {
	t.Helper()
	return reissue(t, func(exts []pkix.Extension) []pkix.Extension {
		out := exts[:0]
		for _, e := range exts {
			if !e.Id.Equal(oid) {
				out = append(out, e)
			}
		}
		return out
	})
}

// A synthetic root -> device -> leaf chain, exercising the anchoring success
// path against operator-supplied anchors rather than the embedded Yubico ones.
// This is the case of a device whose factory attestation key was replaced with
// an owner-generated one, which is the only reason Policy.Roots exists.
func TestVerifyAnchoredChain(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("Test Attestation Root"),
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	// The device certificate, issued by that root.
	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkixName("YubiHSM Attestation (31650425)"),
		IsCA:                  true,
		MaxPathLen:            0,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	devDER, err := x509.CreateCertificate(rand.Reader, devTmpl, root, &devKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	devCert, err := x509.ParseCertificate(devDER)
	if err != nil {
		t.Fatal(err)
	}

	// The key attestation, carrying the real device's extensions but signed by
	// the synthetic device key.
	orig, err := realAttestation().Certificate()
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         orig.Subject,
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: orig.Extensions,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, devCert, orig.PublicKey, devKey)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	pol := DefaultPolicy()
	pol.Roots = roots
	pol.RequireAnchoredChain = true

	att := &Attestation{
		CertificatePEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		DeviceCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: devDER})),
	}
	res := Verify(att, pol)

	if !res.Verified {
		t.Fatalf("Verified = false: %v", res.Problems)
	}
	if !res.ChainAnchored {
		t.Error("ChainAnchored = false for a chain that reaches the configured root")
	}
	if got, want := res.TrustAnchor, "Test Attestation Root"; got != want {
		t.Errorf("TrustAnchor = %q, want %q", got, want)
	}
	if !res.DeviceBound {
		t.Error("DeviceBound = false")
	}
	if strings.Contains(res.Summary, "not anchored") {
		t.Errorf("Summary = %q, should not mention anchoring", res.Summary)
	}
}

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
