package dnsrecords

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"golang.org/x/crypto/ssh"
)

// Known-answer fixtures. The certificates and their DANE digests were produced
// independently with OpenSSL 3:
//
//	openssl x509 -in leaf.pem -outform DER | openssl dgst -sha256           # full cert
//	openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256  # SPKI
//
// so these assertions verify our SHA-256 selection/matching logic against a
// reference implementation, not merely against ourselves.
const (
	testCAPEM = `-----BEGIN CERTIFICATE-----
MIIBsDCCAVWgAwIBAgICEjQwCgYIKoZIzj0EAwIwNjEgMB4GA1UEAwwXU2Vjc3kg
REFORSBUZXN0IFJvb3QgQ0ExEjAQBgNVBAoMCVNlY3N5IFBLSTAeFw0yNjA3MDQw
NDI5NDVaFw0zNjA3MDEwNDI5NDVaMDYxIDAeBgNVBAMMF1NlY3N5IERBTkUgVGVz
dCBSb290IENBMRIwEAYDVQQKDAlTZWNzeSBQS0kwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASVDj/GiQ931QgyPGsFd00SJ57HyP9CsoW2PCOr9bxgplUGCZKaIg8D
FUTejxKxPNXsA1tEgb9/5z17pQt1W+Mbo1MwUTAdBgNVHQ4EFgQULFHOhRK2MtoY
5vZOMVp1ecE9ItswHwYDVR0jBBgwFoAULFHOhRK2MtoY5vZOMVp1ecE9ItswDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAvIf6KVJ+QeG5YGnN0Og9
It22mN4SPwNsTvio8ZW0YrYCIQComfTcKbUDYBcEc/0AztOsckOZmwJRp13aah5i
hx1BLQ==
-----END CERTIFICATE-----`

	testLeafPEM = `-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIDAKvNMAoGCCqGSM49BAMCMDYxIDAeBgNVBAMMF1NlY3N5
IERBTkUgVGVzdCBSb290IENBMRIwEAYDVQQKDAlTZWNzeSBQS0kwHhcNMjYwNzA0
MDQyOTQ1WhcNMjcwNzA0MDQyOTQ1WjAgMR4wHAYDVQQDDBVob3N0LmRhbmUuZXhh
bXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASS6vxqwXrJJrvyc9vr
+VrnbeE6SRi6p4KhQNxzJd8PHxKs89/uWCD844rIQi3zHJEA9fwSzfrKBqGQy48v
GrIoo3IwcDAMBgNVHRMBAf8EAjAAMCAGA1UdEQQZMBeCFWhvc3QuZGFuZS5leGFt
cGxlLmNvbTAdBgNVHQ4EFgQU8udYVkEGeRYCF+/rzMCFBOTt2NEwHwYDVR0jBBgw
FoAULFHOhRK2MtoY5vZOMVp1ecE9ItswCgYIKoZIzj0EAwIDSAAwRQIhAOqu1t+D
Hef08FixiYiV/7YxBWlYggpE2WJZGXfvu7NLAiBYzjnUdUgCkMpDmlJZLixTcjiV
XdBI/9bKqqGhNVDgxg==
-----END CERTIFICATE-----`

	// SHA-256 of the leaf's full DER and its SubjectPublicKeyInfo (from OpenSSL).
	leafFullSHA256 = "a37379fb57c24a6d45a0b72c0caa278e35acd6d6ae5b211f89fdb3488bbbdac9"
	leafSPKISHA256 = "a59269b3426dc2c6e4385c649c3161bb098a57a1e9104667f1e9770d12802951"
	// SHA-256 of the CA's full DER and its SubjectPublicKeyInfo (from OpenSSL).
	caFullSHA256 = "9fb782b27578d13049be72224571ec2e96b306c7e1b23a5586fead4e21470a7f"
	caSPKISHA256 = "a8b6387c7fef7f750ad8cd7fa32e2a825364ad2b79df11bb59f2d6dec6111b48"
	// The complete DER of the leaf, lowercase hex (matching type 0, selector 0).
	leafFullDERHex = "308201b93082015fa003020102020300abcd300a06082a8648ce3d04030230363120301e06035504030c1753656373792044414e45205465737420526f6f7420434131123010060355040a0c09536563737920504b49301e170d3236303730343034323934355a170d3237303730343034323934355a3020311e301c06035504030c15686f73742e64616e652e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d0301070342000492eafc6ac17ac926bbf273dbebf95ae76de13a4918baa782a140dc7325df0f1f12acf3dfee5820fce38ac8422df31c9100f5fc12cdfaca06a190cb8f2f1ab228a3723070300c0603551d130101ff0402300030200603551d11041930178215686f73742e64616e652e6578616d706c652e636f6d301d0603551d0e04160414f2e75856410679160217efebccc08504e4edd8d1301f0603551d230418301680142c51ce8512b632da18e6f64e315a7579c13d22db300a06082a8648ce3d0403020348003045022100eaaed6df831de7f4f058b1898895ffb631056958820a44d962591977efbbb34b022058ce39d475480290ca439a52592e2c537238955dd048ffd6caaaa1a13550e0c6"
)

// SSHFP fixtures. The public keys and their expected fingerprints were produced
// with "ssh-keygen -r host.ssh.example.com", the canonical SSHFP implementation.
const (
	testEd25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHXr5x01wKSPHQKhi6H0yI5O4SckW/xCzeptwmbK+1I/"
	testEd25519FP1 = "9cbc4b4381e7cbae75b26655332b7ced80af2084"
	testEd25519FP2 = "ac8972c526e5fc032b20f5c76bc968dff53d7383e26dfbae4dcfd47e0eac467e"

	testECDSAPub = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLQ6QIxNJ3gjk99gYIPFn+MbptkR6LsO63YdkQfmsYhcJ0NnZA/9mIKcL1729EGhK9EQSTL2+ENNdDzYndRQSfE="
	testECDSAFP1 = "bb3762b66fe819212cdbc4f4969d4a86518473b9"
	testECDSAFP2 = "7494c0cd46b8ee99265cac5d21d8c519b24277bad8ee69eec77f8410b1c3d08a"

	testRSAPub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCUZ8crg0CT2Z4z+bQB/H82NKKrLY0f+OWfI3DcY77HzMZ4+GgNnUqZnQ15C/5JQW+etwfhT0ayBZq2yJC8GHQhNF86dR9jLPRcZ69lDsOunBX6oUYu8ip9oXT3xsNLmYUD33qU71r3ZtDJhWm8kL4r3hj+8ZF7hizE4BGeZyVyKBMT3KheGKtsyuhszvfbG4TUgQ2n8sB5uFLOOJ1dgGo5xZYG2Z0qbKG6vQBe0bt9jwFx+qqj1G6VzuczCXK1PQwztJ1nVvvm0QAkFgUNNE9dfFe/VFDIqen52iDHQ2CXw+7hpeen6TiKsND6cdu5tGBbLMgnFRI+9K6Zg60VNkrgy+MgzEXfb8QtCAYEOxQ1QIsB4gPaMkU3tE2roh1mLG+i+p+LkKKewC4OcfUG3u2bdTwwzgx/ygJuxX8Aq5clTep3mwscul41RKsML/Fb1l8kUDOzQVTl+0Ja6FzvjS3Fdvfw3se2UpzOq9LZzkTWkd197Ux4s/4GFHJcV8qpU5E="
	testRSAFP1 = "ebbf4dbdac2eeae80029c3ad97dd23e60d169029"
	testRSAFP2 = "3f439d3296d798cd58cdccf43adebf2efa48a3fc9d2a888dc3b550f07a62e243"
)

func mustParseCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	c, err := pki.ParseCertificatePEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("parsing test certificate: %v", err)
	}
	return c
}

func mustParseSSH(t *testing.T, pub string) ssh.PublicKey {
	t.Helper()
	key, err := ParseSSHPublicKey([]byte(pub))
	if err != nil {
		t.Fatalf("ParseSSHPublicKey: %v", err)
	}
	return key
}

func TestTLSAOwnerName(t *testing.T) {
	cases := []struct {
		host, protocol string
		port           int
		want           string
	}{
		{"host.example.com", "tcp", 443, "_443._tcp.host.example.com."},
		{"host.example.com.", "tcp", 443, "_443._tcp.host.example.com."}, // trailing dot tolerated
		{"mail.example.com", "", 25, "_25._tcp.mail.example.com."},       // protocol defaults to tcp
		{"host.example.com", "_udp", 853, "_853._udp.host.example.com."}, // leading underscore tolerated
		{"host.example.com", "tcp", 8443, "_8443._tcp.host.example.com."},
	}
	for _, c := range cases {
		got := TLSAOwnerName(c.host, c.port, c.protocol)
		if got != c.want {
			t.Errorf("TLSAOwnerName(%q,%d,%q) = %q, want %q", c.host, c.port, c.protocol, got, c.want)
		}
	}
}

func TestLeafTLSARecords(t *testing.T) {
	leaf := mustParseCert(t, testLeafPEM)
	owner := TLSAOwnerName("host.dane.example.com", 443, "tcp")
	recs, err := LeafTLSARecords(owner, leaf)
	if err != nil {
		t.Fatalf("LeafTLSARecords: %v", err)
	}
	// Four records: selector {SPKI,full} × matching {SHA-256,full}, all DANE-EE.
	if len(recs) != 4 {
		t.Fatalf("got %d leaf records, want 4", len(recs))
	}
	byKey := indexTLSA(recs)

	// Every leaf record must carry usage DANE-EE(3) and the service owner name.
	for _, r := range recs {
		if r.Usage != TLSAUsageDANEEE {
			t.Errorf("leaf record %+v: usage = %d, want 3", r, r.Usage)
		}
		if r.Name != "_443._tcp.host.dane.example.com." {
			t.Errorf("leaf record owner = %q, want _443._tcp.host.dane.example.com.", r.Name)
		}
	}

	// Known-answer digests against OpenSSL's output.
	if got := byKey[k(3, TLSASelectorSPKI, TLSAMatchingSHA256)].Data; got != leafSPKISHA256 {
		t.Errorf("3 1 1 data = %s, want %s", got, leafSPKISHA256)
	}
	if got := byKey[k(3, TLSASelectorFullCert, TLSAMatchingSHA256)].Data; got != leafFullSHA256 {
		t.Errorf("3 0 1 data = %s, want %s", got, leafFullSHA256)
	}
	// Full (matching type 0) content records.
	if got := byKey[k(3, TLSASelectorFullCert, TLSAMatchingFull)].Data; got != leafFullDERHex {
		t.Errorf("3 0 0 data = %s, want the full DER hex", got)
	}
	// The verbatim SPKI record must hash to the same digest as the 3 1 1 record.
	spkiFull := byKey[k(3, TLSASelectorSPKI, TLSAMatchingFull)].Data
	if got := sha256OfHex(t, spkiFull); got != leafSPKISHA256 {
		t.Errorf("sha256(3 1 0 content) = %s, want %s", got, leafSPKISHA256)
	}

	// Exact zone-line formatting for the recommended record.
	wantZone := "_443._tcp.host.dane.example.com. IN TLSA 3 1 1 " + leafSPKISHA256
	if got := byKey[k(3, TLSASelectorSPKI, TLSAMatchingSHA256)].Zone; got != wantZone {
		t.Errorf("3 1 1 zone = %q, want %q", got, wantZone)
	}
	// Record ordering: 3 1 1 first, 3 0 0 last.
	if recs[0].Selector != TLSASelectorSPKI || recs[0].MatchingType != TLSAMatchingSHA256 {
		t.Errorf("first record = sel %d mt %d, want SPKI/SHA-256", recs[0].Selector, recs[0].MatchingType)
	}
	last := recs[len(recs)-1]
	if last.Selector != TLSASelectorFullCert || last.MatchingType != TLSAMatchingFull {
		t.Errorf("last record = sel %d mt %d, want full/full", last.Selector, last.MatchingType)
	}
}

func TestIssuerTLSARecords(t *testing.T) {
	ca := mustParseCert(t, testCAPEM)
	owner := TLSAOwnerName("host.dane.example.com", 443, "tcp")
	recs, err := IssuerTLSARecords(owner, ca)
	if err != nil {
		t.Fatalf("IssuerTLSARecords: %v", err)
	}
	// Two usages (PKIX-CA, DANE-TA) × four selector/matching combinations.
	if len(recs) != 8 {
		t.Fatalf("got %d issuer records, want 8", len(recs))
	}
	byKey := indexTLSA(recs)

	usages := map[int]bool{}
	for _, r := range recs {
		usages[r.Usage] = true
	}
	if !usages[TLSAUsagePKIXTA] || !usages[TLSAUsageDANETA] {
		t.Errorf("issuer records must include both PKIX-CA(0) and DANE-TA(2); got usages %v", usages)
	}

	// Both usages pin the same CA material, so both must carry the CA's digests.
	for _, usage := range []int{TLSAUsagePKIXTA, TLSAUsageDANETA} {
		if got := byKey[k(usage, TLSASelectorSPKI, TLSAMatchingSHA256)].Data; got != caSPKISHA256 {
			t.Errorf("%d 1 1 data = %s, want %s", usage, got, caSPKISHA256)
		}
		if got := byKey[k(usage, TLSASelectorFullCert, TLSAMatchingSHA256)].Data; got != caFullSHA256 {
			t.Errorf("%d 0 1 data = %s, want %s", usage, got, caFullSHA256)
		}
	}

	wantZone := "_443._tcp.host.dane.example.com. IN TLSA 2 1 1 " + caSPKISHA256
	if got := byKey[k(2, TLSASelectorSPKI, TLSAMatchingSHA256)].Zone; got != wantZone {
		t.Errorf("2 1 1 zone = %q, want %q", got, wantZone)
	}
}

func TestNewTLSARecordErrors(t *testing.T) {
	leaf := mustParseCert(t, testLeafPEM)
	if _, err := NewTLSARecord("x.", 3, 9, TLSAMatchingSHA256, leaf); err == nil {
		t.Error("expected error for unknown selector")
	}
	if _, err := NewTLSARecord("x.", 3, TLSASelectorSPKI, 9, leaf); err == nil {
		t.Error("expected error for unknown matching type")
	}
	if _, err := NewTLSARecord("x.", 3, TLSASelectorSPKI, TLSAMatchingSHA256, nil); err == nil {
		t.Error("expected error for nil certificate")
	}
}

func TestSSHFPRecords(t *testing.T) {
	cases := []struct {
		name     string
		pub      string
		wantAlgo int
		wantFP1  string
		wantFP2  string
		hostArg  string
	}{
		{"ed25519", testEd25519Pub, SSHFPAlgoEd25519, testEd25519FP1, testEd25519FP2, "host.ssh.example.com"},
		{"ecdsa-nistp256", testECDSAPub, SSHFPAlgoECDSA, testECDSAFP1, testECDSAFP2, "host.ssh.example.com."}, // trailing dot tolerated
		{"rsa", testRSAPub, SSHFPAlgoRSA, testRSAFP1, testRSAFP2, "host.ssh.example.com"},
	}
	const wantOwner = "host.ssh.example.com."
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := mustParseSSH(t, c.pub)
			recs, err := SSHFPRecords(c.hostArg, key)
			if err != nil {
				t.Fatalf("SSHFPRecords: %v", err)
			}
			if len(recs) != 2 {
				t.Fatalf("got %d records, want 2 (SHA-1 and SHA-256)", len(recs))
			}
			r1, r2 := recs[0], recs[1]
			if r1.FPType != SSHFPTypeSHA1 || r2.FPType != SSHFPTypeSHA256 {
				t.Fatalf("fptypes = %d,%d, want 1,2", r1.FPType, r2.FPType)
			}
			for _, r := range recs {
				if r.Algorithm != c.wantAlgo {
					t.Errorf("algorithm = %d, want %d", r.Algorithm, c.wantAlgo)
				}
				if r.Name != wantOwner {
					t.Errorf("owner = %q, want %q", r.Name, wantOwner)
				}
			}
			if r1.Data != c.wantFP1 {
				t.Errorf("SHA-1 fp = %s, want %s", r1.Data, c.wantFP1)
			}
			if r2.Data != c.wantFP2 {
				t.Errorf("SHA-256 fp = %s, want %s", r2.Data, c.wantFP2)
			}
			wantZone1 := wantOwner + " IN SSHFP " + strconv.Itoa(c.wantAlgo) + " 1 " + c.wantFP1
			wantZone2 := wantOwner + " IN SSHFP " + strconv.Itoa(c.wantAlgo) + " 2 " + c.wantFP2
			if r1.Zone != wantZone1 {
				t.Errorf("SHA-1 zone = %q, want %q", r1.Zone, wantZone1)
			}
			if r2.Zone != wantZone2 {
				t.Errorf("SHA-256 zone = %q, want %q", r2.Zone, wantZone2)
			}
		})
	}
}

// TestSSHFPFromCertificate confirms the fingerprint is taken over the certified
// host key, not the certificate blob: a certificate wrapping the fixed key must
// yield the same records as the bare key.
func TestSSHFPFromCertificate(t *testing.T) {
	key := mustParseSSH(t, testEd25519Pub)
	bare, err := SSHFPRecords("host.ssh.example.com", key)
	if err != nil {
		t.Fatalf("SSHFPRecords(key): %v", err)
	}
	cert := &ssh.Certificate{Key: key, CertType: ssh.HostCert}
	fromCert, err := SSHFPRecords("host.ssh.example.com", cert)
	if err != nil {
		t.Fatalf("SSHFPRecords(cert): %v", err)
	}
	if len(bare) != len(fromCert) {
		t.Fatalf("record count mismatch: %d vs %d", len(bare), len(fromCert))
	}
	for i := range bare {
		if bare[i] != fromCert[i] {
			t.Errorf("record %d differs: bare %+v, cert %+v", i, bare[i], fromCert[i])
		}
	}
}

func TestSSHFPUnsupportedKeyType(t *testing.T) {
	if _, err := SSHFPRecords("host.", fakeKey{}); err == nil {
		t.Error("expected error for unsupported SSH key type")
	}
	if _, err := SSHFPRecords("host.", nil); err == nil {
		t.Error("expected error for nil key")
	}
}

func TestZone(t *testing.T) {
	recs, err := SSHFPRecords("h.example.com", mustParseSSH(t, testEd25519Pub))
	if err != nil {
		t.Fatalf("SSHFPRecords: %v", err)
	}
	lines := SSHFPZoneLines(recs)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	block := Zone(lines)
	want := lines[0] + "\n" + lines[1]
	if block != want {
		t.Errorf("Zone = %q, want %q", block, want)
	}
}

// --- test helpers ---

func indexTLSA(recs []TLSARecord) map[string]TLSARecord {
	m := make(map[string]TLSARecord, len(recs))
	for _, r := range recs {
		m[k(r.Usage, r.Selector, r.MatchingType)] = r
	}
	return m
}

func k(usage, selector, matching int) string {
	return strconv.Itoa(usage) + "/" + strconv.Itoa(selector) + "/" + strconv.Itoa(matching)
}

func sha256OfHex(t *testing.T, hexStr string) string {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("decoding hex: %v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// fakeKey is an ssh.PublicKey with an unrecognized algorithm name, used to
// exercise the unsupported-key-type error path.
type fakeKey struct{}

func (fakeKey) Type() string                        { return "bogus-key-type" }
func (fakeKey) Marshal() []byte                     { return []byte{0x00} }
func (fakeKey) Verify([]byte, *ssh.Signature) error { return nil }
