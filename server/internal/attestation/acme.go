package attestation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// oidAppleAttestationNonce is the certificate extension Apple places on its
// anonymous attestation leaf; its value is a SEQUENCE containing, at context
// tag [1], the nonce = SHA-256(authenticatorData || clientDataHash).
var oidAppleAttestationNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// VerifyACMEDeviceAttest is the ACME-facing entry point for the
// device-attest-01 challenge (draft-ietf-acme-device-attest). It parses and
// verifies a WebAuthn attestation object (Apple or TPM statement), binding it to
// the challenge's key authorization, and applies the profile's enforcement mode.
//
// keyAuth is the ACME key authorization for the challenge; per the draft the
// clientDataHash the attestation must commit to is SHA-256(keyAuth). attObj is
// the raw CBOR attestation object (already base64url-decoded by the caller).
func (v *Verifier) VerifyACMEDeviceAttest(profile string, attObj []byte, keyAuth string) Decision {
	if v.Mode(profile) == ModeOff {
		return v.decide(profile, nil, nil)
	}
	if len(attObj) == 0 {
		return v.decide(profile, nil, ErrNoAttestation)
	}
	clientDataHash := sha256.Sum256([]byte(keyAuth))
	res, err := v.verifyAttestationObject(attObj, clientDataHash[:])
	return v.decide(profile, res, err)
}

// attestationObject is a decoded WebAuthn attestation object.
type attestationObject struct {
	fmt      string
	attStmt  map[interface{}]interface{}
	authData []byte
}

func parseAttestationObject(der []byte) (*attestationObject, error) {
	v, err := decodeCBOR(der)
	if err != nil {
		return nil, fmt.Errorf("decoding attestation object: %w", err)
	}
	m, ok := v.(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("attestation object is not a CBOR map")
	}
	fmtVal, ok := cborMapGet(m, "fmt")
	if !ok {
		return nil, errors.New("attestation object missing fmt")
	}
	fmtStr, ok := fmtVal.(string)
	if !ok {
		return nil, errors.New("attestation object fmt is not a string")
	}
	stmtVal, ok := cborMapGet(m, "attStmt")
	if !ok {
		return nil, errors.New("attestation object missing attStmt")
	}
	stmt, ok := stmtVal.(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("attestation object attStmt is not a map")
	}
	adVal, ok := cborMapGet(m, "authData")
	if !ok {
		return nil, errors.New("attestation object missing authData")
	}
	authData, ok := cborBytes(adVal)
	if !ok {
		return nil, errors.New("attestation object authData is not a byte string")
	}
	return &attestationObject{fmt: fmtStr, attStmt: stmt, authData: authData}, nil
}

// verifyAttestationObject dispatches on the attestation statement format.
func (v *Verifier) verifyAttestationObject(der, clientDataHash []byte) (*Result, error) {
	obj, err := parseAttestationObject(der)
	if err != nil {
		return nil, err
	}
	ad, err := parseAuthenticatorData(obj.authData)
	if err != nil {
		return nil, err
	}
	switch obj.fmt {
	case "apple", "apple-appattest":
		return v.verifyAppleStatement(obj, ad, clientDataHash)
	case "tpm":
		return v.verifyTPMStatement(obj, ad, clientDataHash)
	default:
		return nil, fmt.Errorf("unsupported attestation format %q", obj.fmt)
	}
}

// x5cChain extracts the x5c certificate chain (leaf first) from an attestation
// statement.
func x5cChain(stmt map[interface{}]interface{}) ([]*x509.Certificate, error) {
	v, ok := cborMapGet(stmt, "x5c")
	if !ok {
		return nil, errors.New("attestation statement missing x5c")
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil, errors.New("attestation statement x5c is empty")
	}
	chain := make([]*x509.Certificate, 0, len(arr))
	for i, e := range arr {
		der, ok := cborBytes(e)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] is not a byte string", i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c[%d]: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// verifyAppleStatement verifies an Apple anonymous attestation statement
// (WebAuthn "apple" format / Apple App Attest). The leaf certifies the
// credential public key, and carries a nonce extension committing to
// SHA-256(authData || clientDataHash).
func (v *Verifier) verifyAppleStatement(obj *attestationObject, ad *authenticatorData, clientDataHash []byte) (*Result, error) {
	chain, err := x5cChain(obj.attStmt)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	res := &Result{Format: FormatApple, Manufacturer: "Apple"}

	if _, err := v.verifyChain(leaf, chain[1:]); err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("apple attestation chain is untrusted: %w", err)
	}

	// The nonce extension must equal SHA-256(authData || clientDataHash),
	// committing the whole attested statement to this specific challenge.
	nonce, err := appleNonce(leaf)
	if err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("apple attestation nonce: %w", err)
	}
	h := sha256.New()
	h.Write(ad.raw)
	h.Write(clientDataHash)
	expected := h.Sum(nil)
	if !constantTimeEqual(nonce, expected) {
		res.Reason = "apple attestation nonce does not commit to this challenge"
		return res, errors.New(res.Reason)
	}

	// The credential (device) key attested in authData must equal the key the
	// leaf certifies.
	if ad.credPublicKey == nil {
		res.Reason = "apple attestation authData carried no credential key"
		return res, errors.New(res.Reason)
	}
	if !publicKeysEqual(leaf.PublicKey, ad.credPublicKey) {
		res.Reason = "apple attestation leaf key does not match the attested credential key"
		return res, errors.New(res.Reason)
	}

	res.AttestedKey = ad.credPublicKey
	res.Verified = true
	res.HardwareResident = true
	res.NonExportable = true
	res.Reason = "apple hardware attestation verified"
	return res, nil
}

// appleNonce extracts the nonce octet string from the Apple attestation nonce
// extension: SEQUENCE { [1] EXPLICIT OCTET STRING }.
func appleNonce(leaf *x509.Certificate) ([]byte, error) {
	raw, ok := extensionValue(leaf, oidAppleAttestationNonce)
	if !ok {
		return nil, errors.New("leaf missing Apple attestation nonce extension")
	}
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return nil, fmt.Errorf("parsing nonce extension: %w", err)
	}
	// Inside the SEQUENCE: [1] EXPLICIT OCTET STRING.
	rest := seq.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, err
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 1 {
			var octet []byte
			if _, err := asn1.Unmarshal(field.Bytes, &octet); err != nil {
				return nil, fmt.Errorf("parsing nonce octet string: %w", err)
			}
			return octet, nil
		}
	}
	return nil, errors.New("nonce extension missing [1] field")
}
