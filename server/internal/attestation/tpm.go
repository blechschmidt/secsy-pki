package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // only used to hash the pubArea NAME when a TPM selects SHA-1 as nameAlg; not a security primitive here
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// TPM 2.0 constants (TCG TPM 2.0 Structures) needed to parse the pubArea
// (TPMT_PUBLIC) and certInfo (TPMS_ATTEST) of a WebAuthn "tpm" statement.
const (
	tpmGeneratedValue  = 0xff544347 // "TCG\0" magic prefixing a TPMS_ATTEST
	tpmSTAttestCertify = 0x8017     // TPM_ST_ATTEST_CERTIFY
	tpmAlgNull         = 0x0010
	tpmAlgRSA          = 0x0001
	tpmAlgECC          = 0x0023
	tpmAlgSHA1         = 0x0004
	tpmAlgSHA256       = 0x000b
	tpmAlgSHA384       = 0x000c
	tpmAlgSHA512       = 0x000d
	tpmECCNistP256     = 0x0003
	tpmECCNistP384     = 0x0004
	tpmECCNistP521     = 0x0005
)

// COSE signature algorithm identifiers (RFC 8152) used in a TPM attestation
// statement's "alg" field.
const (
	coseAlgES256 = -7
	coseAlgES384 = -35
	coseAlgES512 = -36
	coseAlgRS256 = -257
	coseAlgRS384 = -258
	coseAlgRS512 = -259
	coseAlgPS256 = -37
	coseAlgPS384 = -38
	coseAlgPS512 = -39
)

// verifyTPMStatement verifies a WebAuthn "tpm" attestation statement (TPM 2.0).
// It confirms: the attestation identity key (AK) certificate chains to a trusted
// TPM manufacturer root; the AK's signature over certInfo is valid; certInfo is
// a well-formed TPMS_ATTEST that certifies pubArea and commits to this challenge
// via extraData; and pubArea describes the credential (device) key attested in
// authData.
func (v *Verifier) verifyTPMStatement(obj *attestationObject, ad *authenticatorData, clientDataHash []byte) (*Result, error) {
	res := &Result{Format: FormatTPM, Manufacturer: "TPM"}

	alg, err := stmtInt(obj.attStmt, "alg")
	if err != nil {
		return nil, err
	}
	sig, err := stmtBytes(obj.attStmt, "sig")
	if err != nil {
		return nil, err
	}
	certInfo, err := stmtBytes(obj.attStmt, "certInfo")
	if err != nil {
		return nil, err
	}
	pubArea, err := stmtBytes(obj.attStmt, "pubArea")
	if err != nil {
		return nil, err
	}
	chain, err := x5cChain(obj.attStmt)
	if err != nil {
		return nil, err
	}
	akCert := chain[0]

	// 1. AK certificate must chain to a trusted manufacturer root.
	if _, err := v.verifyChain(akCert, chain[1:]); err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("tpm AK certificate chain is untrusted: %w", err)
	}
	if m := tpmManufacturer(akCert); m != "" {
		res.Manufacturer = "TPM:" + m
	}

	// 2. pubArea must describe the attested credential (device) key.
	pubKey, nameAlg, err := parseTPMTPublic(pubArea)
	if err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("tpm pubArea: %w", err)
	}
	if ad.credPublicKey == nil {
		res.Reason = "tpm authData carried no credential key"
		return res, errors.New(res.Reason)
	}
	if !publicKeysEqual(pubKey, ad.credPublicKey) {
		res.Reason = "tpm pubArea key does not match the attested credential key"
		return res, errors.New(res.Reason)
	}

	// 3. certInfo (TPMS_ATTEST) must certify pubArea and commit to this challenge.
	att, err := parseTPMSAttest(certInfo)
	if err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("tpm certInfo: %w", err)
	}
	if att.magic != tpmGeneratedValue {
		res.Reason = "tpm certInfo has bad magic"
		return res, errors.New(res.Reason)
	}
	if att.attestType != tpmSTAttestCertify {
		res.Reason = "tpm certInfo is not a CERTIFY attestation"
		return res, errors.New(res.Reason)
	}
	// extraData = hashAlg(authData || clientDataHash), hashAlg per the COSE alg.
	sigHash, err := coseHash(alg)
	if err != nil {
		res.Reason = err.Error()
		return res, err
	}
	h := sigHash.New()
	h.Write(ad.raw)
	h.Write(clientDataHash)
	if !constantTimeEqual(att.extraData, h.Sum(nil)) {
		res.Reason = "tpm certInfo extraData does not commit to this challenge"
		return res, errors.New(res.Reason)
	}
	// attested.name = nameAlgID || H_nameAlg(pubArea).
	nameHash, err := tpmHash(nameAlg)
	if err != nil {
		res.Reason = err.Error()
		return res, err
	}
	nh := nameHash.New()
	nh.Write(pubArea)
	expectedName := append(tpmAlgID(nameAlg), nh.Sum(nil)...)
	if !constantTimeEqual(att.name, expectedName) {
		res.Reason = "tpm certInfo name does not match pubArea"
		return res, errors.New(res.Reason)
	}

	// 4. AK signature over certInfo.
	if err := verifyCOSESignature(akCert.PublicKey, alg, certInfo, sig); err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("tpm AK signature: %w", err)
	}

	res.AttestedKey = ad.credPublicKey
	res.Verified = true
	res.HardwareResident = true
	res.NonExportable = true
	res.Reason = "tpm hardware attestation verified"
	return res, nil
}

// ---- statement accessors --------------------------------------------------

func stmtInt(stmt map[interface{}]interface{}, key string) (int64, error) {
	v, ok := cborMapGet(stmt, key)
	if !ok {
		return 0, fmt.Errorf("tpm statement missing %q", key)
	}
	n, ok := cborInt(v)
	if !ok {
		return 0, fmt.Errorf("tpm statement %q is not an integer", key)
	}
	return n, nil
}

func stmtBytes(stmt map[interface{}]interface{}, key string) ([]byte, error) {
	v, ok := cborMapGet(stmt, key)
	if !ok {
		return nil, fmt.Errorf("tpm statement missing %q", key)
	}
	b, ok := cborBytes(v)
	if !ok {
		return nil, fmt.Errorf("tpm statement %q is not a byte string", key)
	}
	return b, nil
}

// ---- TPM structure parsing ------------------------------------------------

// tpmReader is a big-endian cursor over a TPM structure.
type tpmReader struct {
	buf []byte
	pos int
}

func (r *tpmReader) u16() (uint16, error) {
	if r.pos+2 > len(r.buf) {
		return 0, errors.New("tpm: truncated uint16")
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *tpmReader) u32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, errors.New("tpm: truncated uint32")
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *tpmReader) u64() (uint64, error) { //nolint:unparam // symmetric fixed-width reader API (u8/u16/u32/u64); some call sites advance past a field without consuming its value.
	if r.pos+8 > len(r.buf) {
		return 0, errors.New("tpm: truncated uint64")
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// tpm2b reads a TPM2B (uint16 length-prefixed byte block).
func (r *tpmReader) tpm2b() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	if r.pos+int(n) > len(r.buf) {
		return nil, errors.New("tpm: truncated TPM2B")
	}
	b := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return b, nil
}

// parseTPMTPublic parses a TPMT_PUBLIC (the pubArea), returning the described
// public key and the object's nameAlg. Only RSA and ECC (NIST curves) keys are
// supported, matching what platform TPMs emit for WebAuthn credential keys.
func parseTPMTPublic(pubArea []byte) (crypto.PublicKey, uint16, error) {
	r := &tpmReader{buf: pubArea}
	typ, err := r.u16()
	if err != nil {
		return nil, 0, err
	}
	nameAlg, err := r.u16()
	if err != nil {
		return nil, 0, err
	}
	if _, err := r.u32(); err != nil { // objectAttributes
		return nil, 0, err
	}
	if _, err := r.tpm2b(); err != nil { // authPolicy
		return nil, 0, err
	}

	switch typ {
	case tpmAlgRSA:
		key, err := parseTPMRSA(r)
		return key, nameAlg, err
	case tpmAlgECC:
		key, err := parseTPMECC(r)
		return key, nameAlg, err
	default:
		return nil, 0, fmt.Errorf("unsupported TPMT_PUBLIC type 0x%04x", typ)
	}
}

func parseTPMRSA(r *tpmReader) (crypto.PublicKey, error) {
	// TPMS_RSA_PARMS.
	symmetric, err := r.u16()
	if err != nil {
		return nil, err
	}
	if symmetric != tpmAlgNull {
		// keyBits + mode for a decryption key; not expected for a signing key.
		if _, err := r.u16(); err != nil {
			return nil, err
		}
		if _, err := r.u16(); err != nil {
			return nil, err
		}
	}
	scheme, err := r.u16()
	if err != nil {
		return nil, err
	}
	if scheme != tpmAlgNull {
		if _, err := r.u16(); err != nil { // scheme hashAlg
			return nil, err
		}
	}
	keyBits, err := r.u16()
	if err != nil {
		return nil, err
	}
	exponent, err := r.u32()
	if err != nil {
		return nil, err
	}
	if exponent == 0 {
		exponent = 65537
	}
	modulus, err := r.tpm2b()
	if err != nil {
		return nil, err
	}
	if len(modulus)*8 != int(keyBits) && keyBits != 0 {
		// Tolerate leading-zero trimming differences, but the modulus must be
		// non-empty.
		if len(modulus) == 0 {
			return nil, errors.New("tpm RSA modulus empty")
		}
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponent)}, nil
}

func parseTPMECC(r *tpmReader) (crypto.PublicKey, error) {
	// TPMS_ECC_PARMS.
	symmetric, err := r.u16()
	if err != nil {
		return nil, err
	}
	if symmetric != tpmAlgNull {
		if _, err := r.u16(); err != nil {
			return nil, err
		}
		if _, err := r.u16(); err != nil {
			return nil, err
		}
	}
	scheme, err := r.u16()
	if err != nil {
		return nil, err
	}
	if scheme != tpmAlgNull {
		if _, err := r.u16(); err != nil { // scheme hashAlg
			return nil, err
		}
	}
	curveID, err := r.u16()
	if err != nil {
		return nil, err
	}
	kdf, err := r.u16()
	if err != nil {
		return nil, err
	}
	if kdf != tpmAlgNull {
		if _, err := r.u16(); err != nil { // kdf hashAlg
			return nil, err
		}
	}
	// TPMS_ECC_POINT unique = { x TPM2B, y TPM2B }.
	xb, err := r.tpm2b()
	if err != nil {
		return nil, err
	}
	yb, err := r.tpm2b()
	if err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch curveID {
	case tpmECCNistP256:
		curve = elliptic.P256()
	case tpmECCNistP384:
		curve = elliptic.P384()
	case tpmECCNistP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported TPM ECC curve 0x%04x", curveID)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) { //nolint:staticcheck // SA1019: crypto/ecdh exposes no big.Int X/Y to rebuild the key this attestation path needs; the deprecated on-curve check is retained deliberately.
		return nil, errors.New("tpm ECC point is not on the curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// tpmAttest is the subset of TPMS_ATTEST needed for CERTIFY verification.
type tpmAttest struct {
	magic      uint32
	attestType uint16
	extraData  []byte
	name       []byte // attested.name (TPMS_CERTIFY_INFO.name)
}

func parseTPMSAttest(certInfo []byte) (*tpmAttest, error) {
	r := &tpmReader{buf: certInfo}
	magic, err := r.u32()
	if err != nil {
		return nil, err
	}
	attestType, err := r.u16()
	if err != nil {
		return nil, err
	}
	if _, err := r.tpm2b(); err != nil { // qualifiedSigner
		return nil, err
	}
	extraData, err := r.tpm2b()
	if err != nil {
		return nil, err
	}
	// clockInfo: clock(8) resetCount(4) restartCount(4) safe(1) = 17 bytes.
	if _, err := r.u64(); err != nil {
		return nil, err
	}
	if _, err := r.u32(); err != nil {
		return nil, err
	}
	if _, err := r.u32(); err != nil {
		return nil, err
	}
	if r.pos+1 > len(r.buf) {
		return nil, errors.New("tpm: truncated clockInfo.safe")
	}
	r.pos++                            // safe
	if _, err := r.u64(); err != nil { // firmwareVersion
		return nil, err
	}
	// TPMS_CERTIFY_INFO: name TPM2B, qualifiedName TPM2B.
	name, err := r.tpm2b()
	if err != nil {
		return nil, err
	}
	return &tpmAttest{magic: magic, attestType: attestType, extraData: extraData, name: name}, nil
}

// ---- algorithm helpers ----------------------------------------------------

// tpmAlgID returns the 2-byte big-endian TPM_ALG_ID for a hash algorithm.
func tpmAlgID(alg uint16) []byte {
	return []byte{byte(alg >> 8), byte(alg)}
}

func tpmHash(alg uint16) (crypto.Hash, error) {
	switch alg {
	case tpmAlgSHA1:
		return crypto.SHA1, nil
	case tpmAlgSHA256:
		return crypto.SHA256, nil
	case tpmAlgSHA384:
		return crypto.SHA384, nil
	case tpmAlgSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported TPM hash alg 0x%04x", alg)
	}
}

func coseHash(alg int64) (crypto.Hash, error) {
	switch alg {
	case coseAlgES256, coseAlgRS256, coseAlgPS256:
		return crypto.SHA256, nil
	case coseAlgES384, coseAlgRS384, coseAlgPS384:
		return crypto.SHA384, nil
	case coseAlgES512, coseAlgRS512, coseAlgPS512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported COSE signature alg %d", alg)
	}
}

// verifyCOSESignature verifies sig over signed using the AK public key and the
// signature scheme identified by the COSE alg.
func verifyCOSESignature(pub crypto.PublicKey, alg int64, signed, sig []byte) error {
	hash, err := coseHash(alg)
	if err != nil {
		return err
	}
	var digest []byte
	switch hash {
	case crypto.SHA1:
		s := sha1.Sum(signed) //nolint:gosec
		digest = s[:]
	case crypto.SHA256:
		s := sha256.Sum256(signed)
		digest = s[:]
	case crypto.SHA384:
		s := sha512.Sum384(signed)
		digest = s[:]
	case crypto.SHA512:
		s := sha512.Sum512(signed)
		digest = s[:]
	}

	switch alg {
	case coseAlgRS256, coseAlgRS384, coseAlgRS512:
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("AK key is not RSA for an RS* signature")
		}
		return rsa.VerifyPKCS1v15(rp, hash, digest, sig)
	case coseAlgPS256, coseAlgPS384, coseAlgPS512:
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("AK key is not RSA for a PS* signature")
		}
		return rsa.VerifyPSS(rp, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case coseAlgES256, coseAlgES384, coseAlgES512:
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("AK key is not ECDSA for an ES* signature")
		}
		if !ecdsa.VerifyASN1(ep, digest, sig) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported COSE signature alg %d", alg)
	}
}
