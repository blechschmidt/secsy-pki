package tsa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// ---- helpers ---------------------------------------------------------------

// selfSignedCert mints a throwaway certificate. It uses an in-process ECDSA key
// on purpose: nothing in this file exercises signing, so there is no reason to
// pay for RSA key generation or to touch a keystore/HSM. LoadAuthorityConfig and
// parseChainPEM only ever parse certificates — the RSA/EKU requirements are
// enforced later, by New().
func selfSignedCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// writePEMFile writes the concatenation of blocks to a fresh file and returns
// its path.
func writePEMFile(t *testing.T, name string, blocks ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	var buf []byte
	for _, b := range blocks {
		buf = append(buf, b...)
	}
	writeFile(t, path, buf)
	return path
}

// ---- parseDottedOID --------------------------------------------------------

// TestParseDottedOID exercises the policy-OID parser exhaustively. It runs at
// startup on operator-supplied configuration, and anything it accepts is
// asserted verbatim in every token this TSA ever signs — so an OID that parses
// but cannot be DER-encoded is not a cosmetic problem: it either fails every
// single /tsa request at signing time, or (worse, for negative arcs) encodes to
// a zero-length OBJECT IDENTIFIER that no verifier can read back.
func TestParseDottedOID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want asn1.ObjectIdentifier
	}{
		// Valid.
		{"two arcs", "1.2", asn1.ObjectIdentifier{1, 2}},
		{"example arc", "2.999.1.1", asn1.ObjectIdentifier{2, 999, 1, 1}},
		{"zero arcs allowed", "0.0", asn1.ObjectIdentifier{0, 0}},
		{"second arc 39 under arc 1", "1.39", asn1.ObjectIdentifier{1, 39}},
		{"large arc under joint-iso-itu-t", "2.16.840.1.101.3.4.2.1",
			asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		{"long chain of zeros", "1.2.0.0.0", asn1.ObjectIdentifier{1, 2, 0, 0, 0}},
		// strconv.Atoi accepts a leading '+', so this is accepted. That is
		// harmless precisely because the arc it yields is non-negative and
		// therefore encodes identically to "1.2" — the round-trip assertion
		// below is what makes that claim rather than assuming it.
		{"explicit plus sign is tolerated", "+1.2", asn1.ObjectIdentifier{1, 2}},

		// Malformed input: every one of these must be rejected.
		{"empty string", "", nil},
		{"single arc", "1", nil},
		{"single zero", "0", nil},
		{"just a dot", ".", nil},
		{"leading dot", ".1.2", nil},
		{"trailing dot", "1.2.", nil},
		{"double dot", "1..2", nil},
		{"only dots", "...", nil},
		{"non-numeric arc", "1.2.abc", nil},
		{"hex arc", "1.2.0x10", nil},
		{"whitespace around arc", "1. 2", nil},
		{"leading whitespace", " 1.2", nil},
		{"trailing newline", "1.2\n", nil},
		{"comma separated", "1,2", nil},
		// strconv.Atoi accepts a sign, but a negative arc has no ASN.1 encoding:
		// encoding/asn1 does not reject it, it emits an EMPTY OBJECT IDENTIFIER,
		// so accepting this here would silently corrupt every issued token.
		{"negative first arc", "-1.2", nil},
		{"negative second arc", "1.-2", nil},
		{"all negative", "-1.-2", nil},
		// Arcs that overflow a Go int must be refused, not wrapped around.
		{"arc overflows int64", "1.2.99999999999999999999999999", nil},
		{"arc just past int64", "1.2.9223372036854775808", nil},
		// X.690 §8.19 packs the first two arcs into one subidentifier, so arc1
		// must be 0..2 and arc2 < 40 unless arc1 == 2. These parse as integers
		// but cannot be encoded; catching them here turns an every-request 500
		// into a startup error.
		{"first arc 3", "3.1", nil},
		{"first arc 4", "4.999.1", nil},
		{"second arc 40 under arc 0", "0.40", nil},
		{"second arc 40 under arc 1", "1.40", nil},
		{"second arc 100 under arc 1", "1.100.2", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDottedOID(tc.in)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("parseDottedOID(%q) = %v, want an error", tc.in, got)
				}
				if got != nil {
					t.Fatalf("parseDottedOID(%q) returned %v alongside error %v", tc.in, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDottedOID(%q): %v", tc.in, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parseDottedOID(%q) = %v, want %v", tc.in, got, tc.want)
			}
			// Anything accepted must survive a DER round trip, because that is
			// what happens to it inside every TSTInfo.
			der, err := asn1.Marshal(got)
			if err != nil {
				t.Fatalf("parseDottedOID(%q) returned %v, which asn1.Marshal rejects: %v", tc.in, got, err)
			}
			var back asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(der, &back); err != nil {
				t.Fatalf("parseDottedOID(%q) encoded to % x, which does not decode: %v", tc.in, der, err)
			}
			if !back.Equal(tc.want) {
				t.Fatalf("parseDottedOID(%q) round-tripped to %v, want %v", tc.in, back, tc.want)
			}
		})
	}
}

// TestParseDottedOIDPolicyReachesTheToken closes the loop: a configured policy
// OID must show up, decodable, in the TSTInfo of a real signed token.
func TestParseDottedOIDPolicyReachesTheToken(t *testing.T) {
	oid, err := parseDottedOID("1.3.6.1.4.1.99999.3.1")
	if err != nil {
		t.Fatalf("parseDottedOID: %v", err)
	}
	h := newHarness(t)
	h.authority.cfg.PolicyOID = oid

	digest := sha256.Sum256([]byte("policy round trip"))
	reqDER, err := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Policy: oid})
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if !result.Granted {
		t.Fatalf("request rejected: %s", result.Detail)
	}
	info, err := ParseTokenInfo(parseGrantedResp(t, result.Response))
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if !info.Policy.Equal(oid) {
		t.Fatalf("token policy = %v, want %v", info.Policy, oid)
	}
}

// ---- hashByName ------------------------------------------------------------

// TestHashByName pins the config hash-name mapping. The zero return is not an
// error channel — LoadAuthorityConfig feeds it straight into Config, where
// withDefaults turns 0 into SHA-256 and an empty accepted-hash list into the
// SHA-2 family. So the names this function does NOT recognize decide what a
// typo'd config silently falls back to (see
// TestLoadAuthorityConfigHashNameTypos).
func TestHashByName(t *testing.T) {
	tests := []struct {
		in   string
		want crypto.Hash
	}{
		{"sha1", crypto.SHA1},
		{"sha256", crypto.SHA256},
		{"sha384", crypto.SHA384},
		{"sha512", crypto.SHA512},

		{"", 0},
		{"SHA256", 0},  // case sensitive
		{"Sha256", 0},  //
		{"sha-256", 0}, // the hyphenated spelling is not accepted
		{"sha_256", 0}, //
		{"sha256 ", 0}, // trailing space is not trimmed
		{" sha256", 0}, // leading space is not trimmed
		{"sha2", 0},    //
		{"sha224", 0},  // deliberately unsupported
		{"sha512/256", 0},
		{"sha3-256", 0},
		{"md5", 0},
		{"none", 0},
		{"0", 0},
	}
	for _, tc := range tests {
		name := tc.in
		if name == "" {
			name = "empty string"
		}
		t.Run(name, func(t *testing.T) {
			got := hashByName(tc.in)
			if got != tc.want {
				t.Fatalf("hashByName(%q) = %v, want %v", tc.in, got, tc.want)
			}
			if got != 0 && !got.Available() {
				t.Fatalf("hashByName(%q) = %v, which is not linked into the binary", tc.in, got)
			}
		})
	}
}

// ---- parseChainPEM ---------------------------------------------------------

// TestParseChainPEM covers the PEM chain reader. It is fed an operator-supplied
// file, so the interesting cases are the ones where it must NOT silently return
// a short or empty chain that a later stage then mistakes for a valid one.
func TestParseChainPEM(t *testing.T) {
	leaf := selfSignedCert(t, "leaf")
	mid := selfSignedCert(t, "intermediate")
	root := selfSignedCert(t, "root")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// A CERTIFICATE block whose payload is not a certificate at all.
	garbageDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	// A CERTIFICATE block holding a valid DER value of the wrong type.
	notACert, err := asn1.Marshal(struct{ A, B int }{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	wrongDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: notACert})
	// A truncated certificate: valid base64, DER cut in half.
	truncated := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw[:len(leaf.Raw)/2]})
	// A block whose base64 body is corrupt: pem.Decode cannot find a block at
	// all, so this must come out as "no certificates", never as a partial parse.
	badBase64 := []byte("-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n-----END CERTIFICATE-----\n")

	tests := []struct {
		name    string
		in      []byte
		want    []string // expected subject CNs, in order
		wantErr bool
	}{
		{"nil input", nil, nil, false},
		{"empty input", []byte{}, nil, false},
		{"no PEM at all", []byte("just some text\n"), nil, false},
		{"single certificate", pemCert(leaf), []string{"leaf"}, false},
		{"three-certificate chain", concat(pemCert(leaf), pemCert(mid), pemCert(root)),
			[]string{"leaf", "intermediate", "root"}, false},
		// Order is preserved verbatim, including a chain built upside down:
		// parseChainPEM does not reorder, so chain[0] is whatever came first.
		{"reversed chain is returned in file order", concat(pemCert(root), pemCert(mid), pemCert(leaf)),
			[]string{"root", "intermediate", "leaf"}, false},
		{"duplicate certificates are kept", concat(pemCert(leaf), pemCert(leaf)),
			[]string{"leaf", "leaf"}, false},
		// Non-CERTIFICATE blocks are skipped, not fatal: a file that also holds
		// the key (as some tools emit) still yields its certificates.
		{"private key block is skipped", concat(keyPEM, pemCert(leaf)), []string{"leaf"}, false},
		{"key between certificates", concat(pemCert(leaf), keyPEM, pemCert(root)),
			[]string{"leaf", "root"}, false},
		{"only a private key", keyPEM, nil, false},
		{"leading and trailing noise", concat([]byte("# comment\n"), pemCert(leaf), []byte("trailing\n")),
			[]string{"leaf"}, false},
		{"corrupt base64 yields no certificates", badBase64, nil, false},
		// A CERTIFICATE block that is not a certificate must be an error, never
		// a silently skipped block: skipping it would let a chain file that the
		// operator believes carries the issuer load as leaf-only.
		{"CERTIFICATE block with garbage DER", garbageDER, nil, true},
		{"CERTIFICATE block with valid DER of the wrong type", wrongDER, nil, true},
		{"truncated certificate DER", truncated, nil, true},
		{"good certificate then a bad one", concat(pemCert(leaf), garbageDER), nil, true},
		{"bad certificate then a good one", concat(garbageDER, pemCert(leaf)), nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseChainPEM(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseChainPEM accepted the input and returned %d certificates", len(got))
				}
				if got != nil {
					t.Fatalf("parseChainPEM returned %d certificates alongside error %v", len(got), err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseChainPEM: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseChainPEM returned %d certificates, want %d", len(got), len(tc.want))
			}
			for i, cn := range tc.want {
				if got[i].Subject.CommonName != cn {
					t.Fatalf("certificate %d has CN %q, want %q", i, got[i].Subject.CommonName, cn)
				}
			}
		})
	}
}

// TestParseChainPEMPreservesRawDER checks the parsed certificates carry the
// original DER. The chain is re-emitted into CMS SignedData on certReq, so a
// re-encoded (rather than preserved) body would break signatures over it.
func TestParseChainPEMPreservesRawDER(t *testing.T) {
	leaf := selfSignedCert(t, "leaf")
	got, err := parseChainPEM(pemCert(leaf))
	if err != nil {
		t.Fatalf("parseChainPEM: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d certificates, want 1", len(got))
	}
	if string(got[0].Raw) != string(leaf.Raw) {
		t.Fatal("parseChainPEM did not preserve the original certificate DER")
	}
}

// TestParseChainPEMIgnoresPEMHeaders confirms a CERTIFICATE block carrying PEM
// headers (RFC 1421 "Proc-Type:" style lines, which some exporters add) is still
// decoded; pem.Decode handles them, and dropping the block would silently
// shorten the chain.
func TestParseChainPEMIgnoresPEMHeaders(t *testing.T) {
	leaf := selfSignedCert(t, "leaf")
	withHeaders := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{"X-Origin": "test"},
		Bytes:   leaf.Raw,
	})
	got, err := parseChainPEM(withHeaders)
	if err != nil {
		t.Fatalf("parseChainPEM: %v", err)
	}
	if len(got) != 1 || got[0].Subject.CommonName != "leaf" {
		t.Fatalf("got %d certificates, want the leaf", len(got))
	}
}

// ---- LoadAuthorityConfig ---------------------------------------------------

// TestLoadAuthorityConfigFileErrors covers the failure modes that must stop the
// server at startup rather than produce a half-configured authority.
func TestLoadAuthorityConfigFileErrors(t *testing.T) {
	leaf := selfSignedCert(t, "tsa")
	garbage := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")})

	tests := []struct {
		name    string
		tc      config.TSAConfig
		wantErr string
	}{
		{
			name:    "certificate_file unset",
			tc:      config.TSAConfig{},
			wantErr: "reading tsa.certificate_file",
		},
		{
			name:    "certificate_file missing",
			tc:      config.TSAConfig{CertificateFile: filepath.Join(t.TempDir(), "absent.pem")},
			wantErr: "reading tsa.certificate_file",
		},
		{
			name:    "certificate_file is a directory",
			tc:      config.TSAConfig{CertificateFile: t.TempDir()},
			wantErr: "reading tsa.certificate_file",
		},
		{
			name:    "empty file",
			tc:      config.TSAConfig{CertificateFile: writePEMFile(t, "empty.pem")},
			wantErr: "contains no certificates",
		},
		{
			name:    "file with no PEM blocks",
			tc:      config.TSAConfig{CertificateFile: writePEMFile(t, "text.pem", []byte("hello\n"))},
			wantErr: "contains no certificates",
		},
		{
			name: "file with only a non-certificate block",
			tc: config.TSAConfig{CertificateFile: writePEMFile(t, "key.pem",
				pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01}}))},
			wantErr: "contains no certificates",
		},
		{
			name:    "certificate block with unparseable DER",
			tc:      config.TSAConfig{CertificateFile: writePEMFile(t, "bad.pem", garbage)},
			wantErr: "parsing tsa.certificate_file",
		},
		{
			name: "certificate block with invalid base64",
			tc: config.TSAConfig{CertificateFile: writePEMFile(t, "b64.pem",
				[]byte("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n"))},
			wantErr: "contains no certificates",
		},
		{
			name: "unparseable policy OID",
			tc: config.TSAConfig{
				CertificateFile: writePEMFile(t, "ok.pem", pemCert(leaf)),
				PolicyOID:       "not-an-oid",
			},
			wantErr: "tsa.policy_oid",
		},
		{
			name: "policy OID with a negative arc",
			tc: config.TSAConfig{
				CertificateFile: writePEMFile(t, "ok.pem", pemCert(leaf)),
				PolicyOID:       "-1.2.3",
			},
			wantErr: "tsa.policy_oid",
		},
		{
			name: "policy OID that cannot be DER-encoded",
			tc: config.TSAConfig{
				CertificateFile: writePEMFile(t, "ok.pem", pemCert(leaf)),
				PolicyOID:       "1.40.1",
			},
			wantErr: "tsa.policy_oid",
		},
		{
			name: "single-arc policy OID",
			tc: config.TSAConfig{
				CertificateFile: writePEMFile(t, "ok.pem", pemCert(leaf)),
				PolicyOID:       "1",
			},
			wantErr: "tsa.policy_oid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// db is nil: none of these cases reaches the database, because
			// either the file fails to load or the file already carries the
			// chain. A nil dereference here would itself be the finding.
			cfg, err := LoadAuthorityConfig(nil, tc.tc)
			if err == nil {
				t.Fatalf("LoadAuthorityConfig accepted the config: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoadAuthorityConfigValid checks a fully specified config maps onto the
// Authority Config field by field, including that the first certificate in the
// file becomes the signing certificate and the whole file becomes the chain.
func TestLoadAuthorityConfigValid(t *testing.T) {
	leaf := selfSignedCert(t, "tsa-leaf")
	issuer := selfSignedCert(t, "tsa-issuer")
	path := writePEMFile(t, "chain.pem", pemCert(leaf), pemCert(issuer))

	cfg, err := LoadAuthorityConfig(nil, config.TSAConfig{
		Path:            "/timestamp",
		KeyLabel:        "tsa-key",
		CertificateFile: path,
		PolicyOID:       "1.3.6.1.4.1.99999.1",
		AccuracySeconds: 1,
		AccuracyMillis:  500,
		AccuracyMicros:  250,
		Ordering:        true,
		SignatureDigest: "sha384",
		AcceptedHashes:  []string{"sha256", "sha512"},
		IncludeTSAName:  true,
		// CAID is set but the file already carries two certificates, so the
		// database is never consulted — which is why a nil db is safe here.
		CAID: "some-ca",
	})
	if err != nil {
		t.Fatalf("LoadAuthorityConfig: %v", err)
	}
	if cfg.Path != "/timestamp" {
		t.Errorf("Path = %q, want /timestamp", cfg.Path)
	}
	if cfg.KeyLabel != "tsa-key" {
		t.Errorf("KeyLabel = %q, want tsa-key", cfg.KeyLabel)
	}
	if cfg.Certificate == nil || cfg.Certificate.Subject.CommonName != "tsa-leaf" {
		t.Errorf("Certificate = %v, want the first certificate in the file", cfg.Certificate)
	}
	if len(cfg.Chain) != 2 || cfg.Chain[0] != cfg.Certificate ||
		cfg.Chain[1].Subject.CommonName != "tsa-issuer" {
		t.Errorf("Chain = %v, want [leaf, issuer] with Chain[0] == Certificate", cfg.Chain)
	}
	if cfg.Accuracy != (Accuracy{Seconds: 1, Millis: 500, Micros: 250}) {
		t.Errorf("Accuracy = %+v", cfg.Accuracy)
	}
	if !cfg.Ordering {
		t.Error("Ordering was not carried through")
	}
	if cfg.SignatureDigest != crypto.SHA384 {
		t.Errorf("SignatureDigest = %v, want SHA-384", cfg.SignatureDigest)
	}
	if !cfg.IncludeTSAName {
		t.Error("IncludeTSAName was not carried through")
	}
	want := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	if !cfg.PolicyOID.Equal(want) {
		t.Errorf("PolicyOID = %v, want %v", cfg.PolicyOID, want)
	}
	if len(cfg.AcceptedHashes) != 2 ||
		cfg.AcceptedHashes[0] != crypto.SHA256 || cfg.AcceptedHashes[1] != crypto.SHA512 {
		t.Errorf("AcceptedHashes = %v, want [SHA-256 SHA-512]", cfg.AcceptedHashes)
	}
}

// TestLoadAuthorityConfigDefaults records what an otherwise-empty TSA block
// yields. The zero values are meaningful: withDefaults later turns
// SignatureDigest 0 into SHA-256 and an empty AcceptedHashes into SHA-2 only,
// so leaving them zero here IS the documented default path.
func TestLoadAuthorityConfigDefaults(t *testing.T) {
	leaf := selfSignedCert(t, "tsa")
	cfg, err := LoadAuthorityConfig(nil, config.TSAConfig{
		CertificateFile: writePEMFile(t, "leaf.pem", pemCert(leaf)),
	})
	if err != nil {
		t.Fatalf("LoadAuthorityConfig: %v", err)
	}
	if cfg.PolicyOID != nil {
		t.Errorf("PolicyOID = %v, want nil so withDefaults can install DefaultPolicyOID", cfg.PolicyOID)
	}
	if cfg.SignatureDigest != 0 {
		t.Errorf("SignatureDigest = %v, want 0 so withDefaults can install SHA-256", cfg.SignatureDigest)
	}
	if len(cfg.AcceptedHashes) != 0 {
		t.Errorf("AcceptedHashes = %v, want empty so withDefaults can install the SHA-2 family", cfg.AcceptedHashes)
	}
	defaults := cfg.withDefaults()
	if defaults.Path != "/tsa" {
		t.Errorf("default Path = %q, want /tsa", defaults.Path)
	}
	if !defaults.PolicyOID.Equal(DefaultPolicyOID) {
		t.Errorf("default PolicyOID = %v, want %v", defaults.PolicyOID, DefaultPolicyOID)
	}
	if defaults.SignatureDigest != crypto.SHA256 {
		t.Errorf("default SignatureDigest = %v, want SHA-256", defaults.SignatureDigest)
	}
	// SHA-1 must not be in the default accepted set.
	for _, h := range defaults.AcceptedHashes {
		if h == crypto.SHA1 {
			t.Error("SHA-1 is in the default accepted-hash set")
		}
	}
}

// TestLoadAuthorityConfigHashNameTypos documents how a misspelled hash name
// behaves. Both fields fail OPEN rather than erroring, which is worth pinning:
// an operator who writes accepted_hashes: [sha-256] intending to narrow the
// allowlist ends up with the full SHA-2 default set instead, and a misspelled
// signature_digest silently becomes SHA-256. Neither is unsafe today (the
// fallbacks are the strong defaults), but the behavior must not drift into
// accepting SHA-1 or a weaker signature digest unnoticed.
func TestLoadAuthorityConfigHashNameTypos(t *testing.T) {
	leaf := selfSignedCert(t, "tsa")
	cfg, err := LoadAuthorityConfig(nil, config.TSAConfig{
		CertificateFile: writePEMFile(t, "leaf.pem", pemCert(leaf)),
		SignatureDigest: "SHA-384",                              // misspelled
		AcceptedHashes:  []string{"sha-256", "sha2", "md5", ""}, // all unrecognized
	})
	if err != nil {
		t.Fatalf("LoadAuthorityConfig: %v", err)
	}
	if cfg.SignatureDigest != 0 {
		t.Fatalf("SignatureDigest = %v, want 0 for an unrecognized name", cfg.SignatureDigest)
	}
	if len(cfg.AcceptedHashes) != 0 {
		t.Fatalf("AcceptedHashes = %v, want empty: unrecognized names are dropped", cfg.AcceptedHashes)
	}
	// What the authority actually ends up enforcing.
	effective := cfg.withDefaults()
	if effective.SignatureDigest != crypto.SHA256 {
		t.Fatalf("effective SignatureDigest = %v, want the SHA-256 fallback", effective.SignatureDigest)
	}
	for _, h := range effective.AcceptedHashes {
		if h == crypto.SHA1 {
			t.Fatal("a typo'd accepted_hashes list must never fall back to allowing SHA-1")
		}
	}
	// A partially valid list keeps only the names that were understood.
	cfg2, err := LoadAuthorityConfig(nil, config.TSAConfig{
		CertificateFile: writePEMFile(t, "leaf2.pem", pemCert(leaf)),
		AcceptedHashes:  []string{"sha-512", "sha256", "bogus"},
	})
	if err != nil {
		t.Fatalf("LoadAuthorityConfig: %v", err)
	}
	if len(cfg2.AcceptedHashes) != 1 || cfg2.AcceptedHashes[0] != crypto.SHA256 {
		t.Fatalf("AcceptedHashes = %v, want [SHA-256]", cfg2.AcceptedHashes)
	}
}

// TestLoadAuthorityConfigSkipsDatabaseWhenChainInFile is the guard on the
// "append the CA chain" branch: it must only fire for a leaf-only file. With two
// certificates present the database is not touched at all — passing a nil *DB
// proves it, since any call would panic.
func TestLoadAuthorityConfigSkipsDatabaseWhenChainInFile(t *testing.T) {
	leaf := selfSignedCert(t, "tsa-leaf")
	issuer := selfSignedCert(t, "tsa-issuer")
	for _, tc := range []config.TSAConfig{
		{CAID: "ca-1"},
		{CALabel: "some-label"},
		{CAID: "ca-1", CALabel: "some-label"},
	} {
		tc.CertificateFile = writePEMFile(t, "chain.pem", pemCert(leaf), pemCert(issuer))
		cfg, err := LoadAuthorityConfig(nil, tc)
		if err != nil {
			t.Fatalf("LoadAuthorityConfig(%+v): %v", tc, err)
		}
		if len(cfg.Chain) != 2 {
			t.Fatalf("Chain has %d certificates, want the 2 from the file", len(cfg.Chain))
		}
	}

	// A leaf-only file with NEITHER ca_id nor ca_label also skips the database:
	// the chain is just the leaf, and certReq responses carry only it.
	cfg, err := LoadAuthorityConfig(nil, config.TSAConfig{
		CertificateFile: writePEMFile(t, "leaf.pem", pemCert(leaf)),
	})
	if err != nil {
		t.Fatalf("LoadAuthorityConfig: %v", err)
	}
	if len(cfg.Chain) != 1 || cfg.Chain[0].Subject.CommonName != "tsa-leaf" {
		t.Fatalf("Chain = %v, want just the leaf", cfg.Chain)
	}
}

// TestLoadAuthorityConfigBase64Sanity is a sanity check that the invalid-base64
// fixture used above really is invalid, so the "contains no certificates" case
// is testing what it claims rather than passing for the wrong reason.
func TestLoadAuthorityConfigBase64Sanity(t *testing.T) {
	if _, err := base64.StdEncoding.DecodeString("@@@@"); err == nil {
		t.Fatal("the invalid-base64 fixture decodes cleanly; the PEM test case is vacuous")
	}
	block, _ := pem.Decode([]byte("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n"))
	if block != nil {
		t.Fatal("pem.Decode accepted the corrupt block; the PEM test case is vacuous")
	}
}

// ---- Authority.Path --------------------------------------------------------

// TestAuthorityPath checks Path() reports the NORMALIZED mount path, because it
// is used both to register the handler and to advertise the endpoint elsewhere;
// if the two disagree the advertised URL 404s.
func TestAuthorityPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "/tsa"},
		{"/tsa", "/tsa"},
		{"tsa", "/tsa"},
		{"tsa/", "/tsa"},
		{"/tsa/", "/tsa"},
		{"///tsa///", "/tsa"},
		{"/", "/"},
		{"//", "/"},
		{"timestamp", "/timestamp"},
		{"/api/v1/timestamp/", "/api/v1/timestamp"},
	}
	for _, tc := range tests {
		name := tc.in
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			a := &Authority{cfg: Config{Path: tc.in}.withDefaults()}
			if got := a.Path(); got != tc.want {
				t.Fatalf("Path() for %q = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestAuthorityPathMatchesRegisteredRoute ties Path() to the route Register
// actually mounts: a POST to Path() must reach the TSA handler.
func TestAuthorityPathMatchesRegisteredRoute(t *testing.T) {
	h := newHarness(t)
	h.authority.cfg.Path = "api/v1/timestamp/" // unnormalized on purpose
	h.authority.cfg = h.authority.cfg.withDefaults()

	mux := http.NewServeMux()
	h.authority.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if h.authority.Path() != "/api/v1/timestamp" {
		t.Fatalf("Path() = %q, want /api/v1/timestamp", h.authority.Path())
	}
	digest := sha256.Sum256([]byte("routed"))
	reqDER, err := MakeRequest(crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	resp, err := http.Post(srv.URL+h.authority.Path(), contentTypeQuery, strings.NewReader(string(reqDER)))
	if err != nil {
		t.Fatalf("POST %s: %v", h.authority.Path(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s returned %d; Path() does not match the registered route",
			h.authority.Path(), resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != contentTypeReply {
		t.Fatalf("Content-Type = %q, want %q", ct, contentTypeReply)
	}
}

// ---- SetTrustedClock -------------------------------------------------------

// failingClock is a Clock that refuses to vouch for the host time, which is what
// a timesource checker does once drift exceeds the configured threshold.
type failingClock struct{ err error }

func (c failingClock) Now(context.Context) (time.Time, error) { return time.Time{}, c.err }

// fixedClock is a trusted clock that always agrees on one instant.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now(context.Context) (time.Time, error) { return c.at, nil }

// TestSetTrustedClockFailClosed is the point of the trusted-clock seam: when the
// external time source cannot be corroborated the TSA must refuse to sign and
// return the RFC 3161 timeNotAvailable rejection — not sign with the host clock,
// and not fail the HTTP request.
func TestSetTrustedClockFailClosed(t *testing.T) {
	h := newHarness(t)
	h.authority.SetTrustedClock(failingClock{err: errors.New("NTP drift 42s exceeds threshold")})

	digest := sha256.Sum256([]byte("untrusted clock"))
	reqDER, err := MakeRequest(crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Stamp returned a transport error instead of a rejection: %v", err)
	}
	if result.Granted {
		t.Fatal("a token was issued despite the trusted clock refusing to vouch for the time")
	}
	assertRejection(t, result.Response, FailureTimeNotAvailable)
	if !strings.Contains(result.Detail, "NTP drift 42s") {
		t.Errorf("Detail = %q, want it to carry the clock's reason", result.Detail)
	}
}

// TestSetTrustedClockNilIsIgnored guards the nil check. SetTrustedClock is wired
// only when a time.source is configured, and the wiring code may hand it a nil
// interface; installing that would nil-panic on the first request instead of
// leaving the host clock in place.
func TestSetTrustedClockNilIsIgnored(t *testing.T) {
	h := newHarness(t)
	fixed := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	h.authority.SetClock(func() time.Time { return fixed })

	h.authority.SetTrustedClock(nil)

	digest := sha256.Sum256([]byte("nil clock"))
	reqDER, err := MakeRequest(crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if !result.Granted {
		t.Fatalf("SetTrustedClock(nil) broke the existing clock: %s", result.Detail)
	}
	info, err := ParseTokenInfo(parseGrantedResp(t, result.Response))
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if !info.GenTime.Equal(fixed) {
		t.Fatalf("genTime = %v, want the previously installed clock's %v", info.GenTime, fixed)
	}
}

// TestSetTrustedClockOverridesGenTime confirms a trusted clock's instant, not
// the host wall clock, is what lands in the token.
func TestSetTrustedClockOverridesGenTime(t *testing.T) {
	h := newHarness(t)
	// Sub-second precision on purpose: TSTInfo genTime is truncated to whole
	// seconds, so the token must report the truncated instant.
	at := time.Date(2026, 9, 23, 11, 22, 33, 987654321, time.UTC)
	h.authority.SetTrustedClock(fixedClock{at: at})

	digest := sha256.Sum256([]byte("trusted clock"))
	reqDER, err := MakeRequest(crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil || !result.Granted {
		t.Fatalf("Stamp: err=%v detail=%s", err, result.Detail)
	}
	info, err := ParseTokenInfo(parseGrantedResp(t, result.Response))
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if want := at.Truncate(time.Second); !info.GenTime.Equal(want) {
		t.Fatalf("genTime = %v, want %v", info.GenTime, want)
	}
}

// ---- clientIP --------------------------------------------------------------

// TestClientIP pins the audit-log address extraction. X-Forwarded-For is wholly
// client-controlled unless a proxy overwrites it, so the value is only ever used
// as an audit/log annotation — never for authorization or rate limiting (the TSA
// actor is the fixed pseudo-principal "tsa:anonymous"). These cases document
// exactly what lands in the audit row, including the fact that the full hop list
// is stored verbatim rather than reduced to one address: truncating to the first
// hop would DISCARD the one address the operator's proxy actually appended.
func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{"no header, address with port", "", "192.0.2.10:54321", "192.0.2.10:54321"},
		{"no header, address without port", "", "192.0.2.10", "192.0.2.10"},
		{"no header, IPv6 literal with port", "", "[2001:db8::1]:443", "[2001:db8::1]:443"},
		{"no header, empty RemoteAddr", "", "", ""},
		{"header wins over RemoteAddr", "198.51.100.7", "192.0.2.10:54321", "198.51.100.7"},
		{"empty header falls back", "", "192.0.2.10:1", "192.0.2.10:1"},
		// Multiple hops: the whole list is kept, so a spoofed leading hop is
		// visible next to the proxy-appended one instead of replacing it.
		{"multiple hops", "203.0.113.1, 198.51.100.7", "192.0.2.10:1", "203.0.113.1, 198.51.100.7"},
		{"three hops", "203.0.113.1, 203.0.113.2, 198.51.100.7", "192.0.2.10:1",
			"203.0.113.1, 203.0.113.2, 198.51.100.7"},
		{"hops without spaces", "203.0.113.1,198.51.100.7", "192.0.2.10:1", "203.0.113.1,198.51.100.7"},
		// No trimming happens here, unlike middleware.clientIP (which trims and
		// keeps only the first hop). The two therefore record different strings
		// for the same request; pinned so the divergence is deliberate rather
		// than discovered while correlating an access log with an audit row.
		{"surrounding whitespace is preserved", "  203.0.113.1  ", "192.0.2.10:1", "  203.0.113.1  "},
		{"IPv6 in the header", "2001:db8::1", "192.0.2.10:1", "2001:db8::1"},
		{"IPv6 with port in the header", "[2001:db8::1]:443", "192.0.2.10:1", "[2001:db8::1]:443"},
		// Junk in the header is stored as-is; it is a log annotation, so the
		// only requirement is that it cannot mask the real RemoteAddr silently
		// by being dropped.
		{"non-address header value", "not-an-ip", "192.0.2.10:1", "not-an-ip"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/tsa", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientIPMultipleHeaderValues covers the repeated-header form: Go joins
// duplicate X-Forwarded-For headers only when read with Header.Values, while
// Header.Get returns the first. Whichever it is, clientIP must return something
// derived from the header and never panic on the multi-value slice.
func TestClientIPMultipleHeaderValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/tsa", nil)
	r.RemoteAddr = "192.0.2.10:1"
	r.Header.Add("X-Forwarded-For", "203.0.113.1")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")

	got := clientIP(r)
	if got == "192.0.2.10:1" {
		t.Fatal("clientIP ignored a present X-Forwarded-For header")
	}
	if !strings.Contains(got, "203.0.113.1") {
		t.Fatalf("clientIP() = %q, want it to include the first forwarded hop", got)
	}
}

// ---- RequestError ----------------------------------------------------------

// TestRequestErrorSurfacesThroughParseRequest checks the error contract the HTTP
// layer depends on: a validation failure must arrive as a *RequestError carrying
// the PKIFailureInfo bit, and its Error() must be the same human-readable text
// that ends up in the response statusString and the audit row. If Error() ever
// returned something else, the rejection a client sees would stop matching the
// reason the server logged.
func TestRequestErrorSurfacesThroughParseRequest(t *testing.T) {
	// A TimeStampReq with an unknown hash OID: well-formed, unacceptable.
	badAlg, err := asn1.Marshal(timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}},
			HashedMessage: make([]byte, 32),
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	_, err = ParseRequest(badAlg)
	if err == nil {
		t.Fatal("ParseRequest accepted an unknown hash OID")
	}
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error is %T, want *RequestError so the HTTP layer can map it to a failInfo bit", err)
	}
	if re.Failure != FailureBadAlg {
		t.Errorf("Failure = %d, want FailureBadAlg (%d)", re.Failure, FailureBadAlg)
	}
	if re.Error() != re.Message {
		t.Errorf("Error() = %q, want the Message %q", re.Error(), re.Message)
	}
	if re.Message == "" {
		t.Error("Message is empty, so the statusString and audit detail would be blank")
	}

	// The same text must reach Result.Detail, which is what gets audited.
	h := newHarness(t)
	result, err := h.authority.Stamp(context.Background(), badAlg)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if result.Granted {
		t.Fatal("a request with an unknown hash OID was granted")
	}
	if result.Detail != re.Message {
		t.Errorf("Result.Detail = %q, want the RequestError message %q", result.Detail, re.Message)
	}
	assertRejection(t, result.Response, FailureBadAlg)
}

// TestRequestErrorZeroValue makes sure Error() is safe on a bare value: reject()
// constructs one directly from a non-RequestError error, so the zero/partial
// forms must not panic.
func TestRequestErrorZeroValue(t *testing.T) {
	var e error = &RequestError{}
	if e.Error() != "" {
		t.Fatalf("Error() = %q, want the empty Message", e.Error())
	}
	e = &RequestError{Failure: FailureSystemFailure, Message: "boom"}
	if e.Error() != "boom" {
		t.Fatalf("Error() = %q, want boom", e.Error())
	}
}

// TestRejectWrapsNonRequestError covers reject()'s fallback path: an error that
// is not a *RequestError must still yield a well-formed rejection response with
// the generic badRequest bit rather than an internal error.
func TestRejectWrapsNonRequestError(t *testing.T) {
	h := newHarness(t)
	result, err := h.authority.reject(errors.New("something else went wrong"))
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if result.Granted {
		t.Fatal("reject produced a granted result")
	}
	if result.Detail != "something else went wrong" {
		t.Fatalf("Detail = %q", result.Detail)
	}
	assertRejection(t, result.Response, FailureBadRequest)
}

// concat joins byte slices; PEM fixtures are assembled from several blocks.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
