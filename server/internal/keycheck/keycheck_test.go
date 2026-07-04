package keycheck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"
)

// publishedROCAModulus is a real ROCA-vulnerable (CVE-2017-15361) RSA modulus,
// the mod01 test vector published by the CRoCS roca detector
// (github.com/crocs-muni/roca, roca/tests/data/mod01.txt). It carries the genuine
// Infineon RSALib fingerprint, so it is the authoritative known-answer input for
// IsROCAVulnerable.
const publishedROCAModulus = "944e13208a280c37efc31c3114485e590192adbb8e11c87cad60cdef0037ce99278330d3f471a2538fa667802ed2a3c44a8b7dea826e888d0aa341fd664f7fa7"

func mustModulus(t *testing.T, hexN string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(hexN, 16)
	if !ok {
		t.Fatalf("bad hex modulus")
	}
	return n
}

func TestIsROCAVulnerable_PublishedVector(t *testing.T) {
	n := mustModulus(t, publishedROCAModulus)
	if !IsROCAVulnerable(n) {
		t.Fatal("published ROCA (CVE-2017-15361) modulus was NOT detected as vulnerable")
	}
}

func TestIsROCAVulnerable_NormalKeysNotFlagged(t *testing.T) {
	// A freshly generated RSA key is not RSALib-structured; over several keys the
	// fingerprint must never (falsely) match.
	for i := 0; i < 8; i++ {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		if IsROCAVulnerable(k.N) {
			t.Fatalf("normal RSA-2048 key #%d was falsely flagged as ROCA-vulnerable", i)
		}
	}
	// Degenerate inputs must not panic or match.
	if IsROCAVulnerable(nil) || IsROCAVulnerable(big.NewInt(0)) || IsROCAVulnerable(big.NewInt(-1)) {
		t.Fatal("degenerate modulus flagged as ROCA-vulnerable")
	}
}

func TestInspect_ROCAViaPublishedModulus(t *testing.T) {
	// Wrap the published modulus in an *rsa.PublicKey (with a valid exponent) so the
	// only structural finding is ROCA.
	pub := &rsa.PublicKey{N: mustModulus(t, publishedROCAModulus), E: 65537}
	res := Inspect(pub, DefaultPolicy(nil))
	if !hasCode(res, CodeROCA) {
		t.Fatalf("expected ROCA finding, got %v", res.Codes())
	}
	// The 512-bit published vector also trips the small-modulus check under the
	// 2048-bit default minimum — both are legitimate reasons to reject.
	if !hasCode(res, CodeSmallModulus) {
		t.Errorf("expected small-modulus finding for the 512-bit vector, got %v", res.Codes())
	}
}

func TestInspect_ExponentPolicy(t *testing.T) {
	n, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		e    int
		want bool // want a weak_exponent finding
	}{
		{"f4-ok", 65537, false},
		{"e3-too-small", 3, true},
		{"e17-too-small", 17, true},
		{"even-large", 65538, true},
		{"below-f4-odd", 65535, true},
		{"large-odd-ok", 4294967297, false}, // 2^32+1, odd and >= 65537
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := &rsa.PublicKey{N: n.N, E: tc.e}
			res := Inspect(pub, Policy{CheckExponent: true})
			if got := hasCode(res, CodeWeakExponent); got != tc.want {
				t.Errorf("e=%d: weak_exponent=%v, want %v (codes=%v)", tc.e, got, tc.want, res.Codes())
			}
		})
	}
}

func TestInspect_ModulusSanity(t *testing.T) {
	// Even modulus.
	even := &rsa.PublicKey{N: big.NewInt(0).Mul(big.NewInt(2), big.NewInt(3)), E: 65537}
	if res := Inspect(even, Policy{CheckModulus: true}); !hasCode(res, CodeEvenModulus) {
		t.Errorf("even modulus not flagged: %v", res.Codes())
	}
	// Small (odd) modulus, below the 2048-bit floor.
	small := &rsa.PublicKey{N: big.NewInt(0).SetBit(big.NewInt(1), 1024, 1), E: 65537} // ~1024-bit, odd? set explicitly
	small.N = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 1024), big.NewInt(1))   // odd
	if res := Inspect(small, Policy{CheckModulus: true, MinRSABits: 2048}); !hasCode(res, CodeSmallModulus) {
		t.Errorf("small modulus not flagged: %v", res.Codes())
	}
	// A healthy 2048-bit key trips none of the modulus checks.
	ok, _ := rsa.GenerateKey(rand.Reader, 2048)
	if res := Inspect(&ok.PublicKey, DefaultPolicy(nil)); !res.OK() {
		t.Errorf("healthy RSA-2048 key produced findings: %v", res.Codes())
	}
}

func TestInspect_NonRSAKeysPassStructural(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res := Inspect(&ec.PublicKey, DefaultPolicy(nil))
	if !res.OK() {
		t.Errorf("EC key produced structural findings (should be RSA-only): %v", res.Codes())
	}
	if res.Fingerprint == "" || !strings.HasPrefix(res.Fingerprint, "SHA256:") {
		t.Errorf("EC key fingerprint malformed: %q", res.Fingerprint)
	}
}

func TestFingerprint_Format(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint %q missing SHA256: prefix", fp)
	}
	// Deterministic: the same key hashes to the same value; a different key does not.
	if fp2, _ := Fingerprint(&k.PublicKey); fp2 != fp {
		t.Errorf("fingerprint not deterministic: %q vs %q", fp, fp2)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if ofp, _ := Fingerprint(&other.PublicKey); ofp == fp {
		t.Error("distinct keys produced the same fingerprint")
	}
}

func hasCode(r Result, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
