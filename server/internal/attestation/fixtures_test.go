package attestation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

// This file builds self-contained, SoftHSM-independent attestation fixtures: a
// synthetic manufacturer PKI (root + intermediate) standing in for a hardware
// vendor's attestation roots, plus helpers that assemble YubiKey-style PIV
// attestation certificates, Apple/TPM WebAuthn attestation objects, and the
// minimal CBOR/COSE encodings they require. Everything is generated in-process
// so the tests are deterministic and need no network, HSM, or real device.

// testPKI is a two-level manufacturer PKI used as trusted attestation roots.
type testPKI struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := selfSign(t, pkix.Name{CommonName: "Test Manufacturer Root"}, rootKey)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Manufacturer Attestation CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	inter := createCert(t, interTmpl, root, rootKey, &interKey.PublicKey)
	return &testPKI{root: root, rootKey: rootKey, inter: inter, interKey: interKey}
}

// verifier builds a Verifier trusting this PKI's root, with the given profile
// modes, at a fixed clock inside the fixtures' validity window.
func (p *testPKI) verifier(t *testing.T, def Mode, profiles map[string]Mode) *Verifier {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	v, err := NewVerifier(Options{
		Roots:         roots,
		Intermediates: []*x509.Certificate{p.inter},
		DefaultMode:   def,
		ProfileModes:  profiles,
		Now:           func() time.Time { return time.Now() },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func selfSign(t *testing.T, subject pkix.Name, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	return createCert(t, tmpl, tmpl, key, &key.PublicKey)
}

func createCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey crypto.Signer, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// ---- YubiKey PIV-style attestation leaf ------------------------------------

// yubicoAttestationLeaf issues an attestation certificate for deviceKey carrying
// the YubiKey PIV firmware and serial extensions, signed by the intermediate.
func (p *testPKI) yubicoAttestationLeaf(t *testing.T, deviceKey crypto.PublicKey, serial int64) *x509.Certificate {
	t.Helper()
	fwExt, err := asn1.Marshal([]byte{5, 7, 1}) // firmware 5.7.1 as an OCTET STRING
	if err != nil {
		t.Fatal(err)
	}
	serExt, err := asn1.Marshal(serial) // serial as an INTEGER
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "YubiKey PIV Attestation"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(20 * 365 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidYubicoFirmware, Value: fwExt},
			{Id: oidYubicoSerial, Value: serExt},
		},
	}
	return createCert(t, tmpl, p.inter, p.interKey, deviceKey)
}

// genericAttestationLeaf issues a plain attestation certificate for deviceKey
// with no vendor-specific extensions (the FormatCertChain case).
func (p *testPKI) genericAttestationLeaf(t *testing.T, deviceKey crypto.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject:      pkix.Name{CommonName: "Generic HW Attestation"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(20 * 365 * 24 * time.Hour),
	}
	return createCert(t, tmpl, p.inter, p.interKey, deviceKey)
}

// ---- Apple WebAuthn attestation object -------------------------------------

// buildAppleAttObj builds a WebAuthn "apple" attestation object for deviceKey,
// committing to keyAuth. The returned attestation leaf certifies deviceKey and
// carries the Apple nonce extension = SHA-256(authData || SHA-256(keyAuth)).
func (p *testPKI) buildAppleAttObj(t *testing.T, deviceKey crypto.PublicKey, keyAuth string) []byte {
	t.Helper()
	authData := buildAuthData(t, deviceKey)
	clientDataHash := sha256.Sum256([]byte(keyAuth))

	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash[:])
	nonce := h.Sum(nil)

	nonceExt := struct {
		Nonce []byte `asn1:"explicit,tag:1"`
	}{Nonce: nonce}
	nonceDER, err := asn1.Marshal(nonceExt)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2001),
		Subject:         pkix.Name{CommonName: "Apple App Attest"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(365 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidAppleAttestationNonce, Value: nonceDER}},
	}
	leaf := createCert(t, tmpl, p.inter, p.interKey, deviceKey)

	return cborEncode(cborMap(
		kv("fmt", "apple"),
		kv("attStmt", cborMap(
			kv("x5c", cborArr(leaf.Raw, p.inter.Raw)),
		)),
		kv("authData", authData),
	))
}

// ---- TPM WebAuthn attestation object ---------------------------------------

// buildTPMAttObj builds a WebAuthn "tpm" attestation object certifying the RSA
// deviceKey with an AK issued by this PKI, committing to keyAuth.
func (p *testPKI) buildTPMAttObj(t *testing.T, deviceKey *rsa.PublicKey, keyAuth string) []byte {
	t.Helper()
	authData := buildAuthData(t, deviceKey)
	clientDataHash := sha256.Sum256([]byte(keyAuth))

	// Attestation identity key + certificate.
	akKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	akTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3001),
		Subject:      pkix.Name{CommonName: "TPM AK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	akCert := createCert(t, akTmpl, p.inter, p.interKey, &akKey.PublicKey)

	pubArea := tpmRSAPubArea(deviceKey)

	// attToBeSigned = authData || clientDataHash; extraData = SHA-256(that).
	attHash := sha256.New()
	attHash.Write(authData)
	attHash.Write(clientDataHash[:])
	extraData := attHash.Sum(nil)

	nameDigest := sha256.Sum256(pubArea)
	name := append([]byte{0x00, 0x0b}, nameDigest[:]...) // TPM_ALG_SHA256 || H(pubArea)

	certInfo := tpmCertInfo(extraData, name)

	digest := sha256.Sum256(certInfo)
	sig, err := rsa.SignPKCS1v15(rand.Reader, akKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	return cborEncode(cborMap(
		kv("fmt", "tpm"),
		kv("attStmt", cborMap(
			kv("ver", "2.0"),
			kv("alg", int64(coseAlgRS256)),
			kv("x5c", cborArr(akCert.Raw, p.inter.Raw)),
			kv("sig", sig),
			kv("certInfo", certInfo),
			kv("pubArea", pubArea),
		)),
		kv("authData", authData),
	))
}

// tpmRSAPubArea serializes a minimal TPMT_PUBLIC for an RSA signing key.
func tpmRSAPubArea(pub *rsa.PublicKey) []byte {
	var b bytes.Buffer
	putU16(&b, tpmAlgRSA)    // type
	putU16(&b, tpmAlgSHA256) // nameAlg
	putU32(&b, 0x00040072)   // objectAttributes (opaque to the parser)
	putU16(&b, 0)            // authPolicy TPM2B (empty)
	putU16(&b, tpmAlgNull)   // symmetric = NULL
	putU16(&b, tpmAlgNull)   // scheme = NULL
	putU16(&b, uint16(pub.N.BitLen()))
	putU32(&b, 0) // exponent 0 => 65537
	modulus := pub.N.Bytes()
	putU16(&b, uint16(len(modulus)))
	b.Write(modulus)
	return b.Bytes()
}

// tpmCertInfo serializes a minimal TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY.
func tpmCertInfo(extraData, name []byte) []byte {
	var b bytes.Buffer
	putU32(&b, tpmGeneratedValue) // magic
	putU16(&b, tpmSTAttestCertify)
	putU16(&b, 0) // qualifiedSigner TPM2B (empty)
	putU16(&b, uint16(len(extraData)))
	b.Write(extraData)
	// clockInfo: clock(8) resetCount(4) restartCount(4) safe(1).
	putU64(&b, 0)
	putU32(&b, 0)
	putU32(&b, 0)
	b.WriteByte(1)
	putU64(&b, 0) // firmwareVersion
	putU16(&b, uint16(len(name)))
	b.Write(name)
	putU16(&b, 0) // qualifiedName TPM2B (empty)
	return b.Bytes()
}

func putU16(b *bytes.Buffer, v uint16) {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], v)
	b.Write(x[:])
}
func putU32(b *bytes.Buffer, v uint32) {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	b.Write(x[:])
}
func putU64(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}

// ---- WebAuthn authenticator data + COSE keys -------------------------------

func buildAuthData(t *testing.T, credPub crypto.PublicKey) []byte {
	t.Helper()
	var b bytes.Buffer
	rp := sha256.Sum256([]byte("secsy-pki"))
	b.Write(rp[:])                               // rpIdHash
	b.WriteByte(authDataFlagAT | authDataFlagUP) // flags
	b.Write([]byte{0, 0, 0, 0})                  // signCount
	b.Write(make([]byte, 16))                    // aaguid
	credID := []byte("credential-id-01")         // 16 bytes
	b.Write([]byte{0, byte(len(credID))})        // credIdLen
	b.Write(credID)
	b.Write(coseKey(t, credPub))
	return b.Bytes()
}

func coseKey(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		return cborEncode(cborMap(
			kv(int64(coseKty), int64(coseKtyEC2)),
			kv(int64(coseAlg), int64(coseAlgES256)),
			kv(int64(coseECCrv), int64(coseCrvP256)),
			kv(int64(coseECX), leftPad(k.X.Bytes(), size)),
			kv(int64(coseECY), leftPad(k.Y.Bytes(), size)),
		))
	case *rsa.PublicKey:
		eBytes := big.NewInt(int64(k.E)).Bytes()
		return cborEncode(cborMap(
			kv(int64(coseKty), int64(coseKtyRSA)),
			kv(int64(coseAlg), int64(coseAlgRS256)),
			kv(int64(coseRSAN), k.N.Bytes()),
			kv(int64(coseRSAE), eBytes),
		))
	default:
		t.Fatalf("unsupported COSE key type %T", pub)
		return nil
	}
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// ---- minimal CBOR encoder (test-only) --------------------------------------

// cborRaw is an already-encoded CBOR fragment, emitted verbatim.
type cborRaw []byte

// pair is one entry of an ordered CBOR map.
type pair struct {
	k interface{}
	v interface{}
}

func kv(k, v interface{}) pair { return pair{k: k, v: v} }

// cborMap encodes an ordered map (definite length).
func cborMap(pairs ...pair) cborRaw {
	var b bytes.Buffer
	cborWriteHead(&b, 5, uint64(len(pairs)))
	for _, p := range pairs {
		b.Write(cborEncode(p.k))
		b.Write(cborEncode(p.v))
	}
	return cborRaw(b.Bytes())
}

// cborArr encodes a definite-length array.
func cborArr(items ...interface{}) cborRaw {
	var b bytes.Buffer
	cborWriteHead(&b, 4, uint64(len(items)))
	for _, it := range items {
		b.Write(cborEncode(it))
	}
	return cborRaw(b.Bytes())
}

func cborEncode(v interface{}) []byte {
	var b bytes.Buffer
	switch x := v.(type) {
	case cborRaw:
		b.Write(x)
	case string:
		cborWriteHead(&b, 3, uint64(len(x)))
		b.WriteString(x)
	case []byte:
		cborWriteHead(&b, 2, uint64(len(x)))
		b.Write(x)
	case int:
		cborWriteInt(&b, int64(x))
	case int64:
		cborWriteInt(&b, x)
	case uint64:
		cborWriteHead(&b, 0, x)
	default:
		panic("cborEncode: unsupported type")
	}
	return b.Bytes()
}

func cborWriteInt(b *bytes.Buffer, n int64) {
	if n >= 0 {
		cborWriteHead(b, 0, uint64(n))
		return
	}
	cborWriteHead(b, 1, uint64(-1-n))
}

func cborWriteHead(b *bytes.Buffer, major byte, n uint64) {
	mb := major << 5
	switch {
	case n < 24:
		b.WriteByte(mb | byte(n))
	case n < 1<<8:
		b.WriteByte(mb | 24)
		b.WriteByte(byte(n))
	case n < 1<<16:
		b.WriteByte(mb | 25)
		var x [2]byte
		binary.BigEndian.PutUint16(x[:], uint16(n))
		b.Write(x[:])
	case n < 1<<32:
		b.WriteByte(mb | 26)
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], uint32(n))
		b.Write(x[:])
	default:
		b.WriteByte(mb | 27)
		var x [8]byte
		binary.BigEndian.PutUint64(x[:], n)
		b.Write(x[:])
	}
}
