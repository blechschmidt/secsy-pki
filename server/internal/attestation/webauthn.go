package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// authenticatorData is the parsed WebAuthn authenticator data (the authData
// field of an attestation object). Only the fields needed for attestation
// verification are retained.
type authenticatorData struct {
	raw           []byte // the full authData, needed for signature verification
	rpIDHash      []byte // 32-byte SHA-256 of the RP ID
	flags         byte
	signCount     uint32           // the authenticator's signature counter
	credentialID  []byte           // the attested credential id (AT flag set)
	credPublicKey crypto.PublicKey // the attested credential (device) public key
}

const (
	authDataFlagUP = 0x01 // user present
	authDataFlagAT = 0x40 // attested credential data included
)

// parseAuthenticatorData parses WebAuthn authenticator data (WebAuthn §6.1),
// including the attested credential public key (a COSE key) when the AT flag is
// set. The device-attest-01 flow always sets AT, since the whole point is to
// attest a freshly generated credential key.
func parseAuthenticatorData(data []byte) (*authenticatorData, error) {
	if len(data) < 37 {
		return nil, fmt.Errorf("authData too short: %d bytes", len(data))
	}
	ad := &authenticatorData{
		raw:       data,
		rpIDHash:  data[:32],
		flags:     data[32],
		signCount: binary.BigEndian.Uint32(data[33:37]),
	}
	if ad.flags&authDataFlagAT == 0 {
		return ad, nil
	}
	// Attested credential data: aaguid(16) || credIdLen(2) || credId || COSEKey.
	rest := data[37:]
	if len(rest) < 18 {
		return nil, errors.New("authData: truncated attested credential data")
	}
	credIDLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if len(rest) < credIDLen {
		return nil, errors.New("authData: truncated credential id")
	}
	ad.credentialID = append([]byte(nil), rest[:credIDLen]...)
	rest = rest[credIDLen:]

	key, err := parseCOSEKey(rest)
	if err != nil {
		return nil, fmt.Errorf("authData: credential public key: %w", err)
	}
	ad.credPublicKey = key
	return ad, nil
}

// WebAuthnAuthData is a public view of parsed WebAuthn authenticator data,
// exposed so the operator-authentication step-up package (internal/authn) can
// reuse this package's COSE/authData parsing rather than duplicating it. Only
// the fields a step-up ceremony needs are surfaced.
type WebAuthnAuthData struct {
	Raw          []byte           // the full authData bytes (for signature verification)
	RPIDHash     []byte           // SHA-256 of the RP ID
	UserPresent  bool             // the UP flag was set
	UserVerified bool             // the UV flag was set
	SignCount    uint32           // the authenticator signature counter
	CredentialID []byte           // attested credential id (nil when AT unset)
	PublicKey    crypto.PublicKey // attested credential public key (nil when AT unset)
}

const authDataFlagUV = 0x04 // user verified

// ParseWebAuthnAuthData parses raw WebAuthn authenticator data for the step-up
// package. When the attested-credential (AT) flag is set — as it is on a
// registration response — the credential id and public key are populated.
func ParseWebAuthnAuthData(data []byte) (*WebAuthnAuthData, error) {
	ad, err := parseAuthenticatorData(data)
	if err != nil {
		return nil, err
	}
	return &WebAuthnAuthData{
		Raw:          ad.raw,
		RPIDHash:     ad.rpIDHash,
		UserPresent:  ad.flags&authDataFlagUP != 0,
		UserVerified: ad.flags&authDataFlagUV != 0,
		SignCount:    ad.signCount,
		CredentialID: ad.credentialID,
		PublicKey:    ad.credPublicKey,
	}, nil
}

// ParseWebAuthnCOSEKey decodes a COSE_Key (CBOR) into a Go public key, exposed
// for the step-up package to reconstruct a stored credential's public key.
func ParseWebAuthnCOSEKey(coseKey []byte) (crypto.PublicKey, error) {
	return parseCOSEKey(coseKey)
}

// ParseWebAuthnAttestationObject extracts the authenticator data (and the parsed
// attested credential within it) from a WebAuthn registration attestation
// object (CBOR). It is exposed for the step-up package's passkey registration.
// The attestation statement itself is not verified: step-up proves possession of
// a passkey the operator registered, not the authenticator's make/model.
func ParseWebAuthnAttestationObject(attestationObject []byte) (*WebAuthnAuthData, error) {
	obj, err := parseAttestationObject(attestationObject)
	if err != nil {
		return nil, err
	}
	ad, err := parseAuthenticatorData(obj.authData)
	if err != nil {
		return nil, err
	}
	return &WebAuthnAuthData{
		Raw:          ad.raw,
		RPIDHash:     ad.rpIDHash,
		UserPresent:  ad.flags&authDataFlagUP != 0,
		UserVerified: ad.flags&authDataFlagUV != 0,
		SignCount:    ad.signCount,
		CredentialID: ad.credentialID,
		PublicKey:    ad.credPublicKey,
	}, nil
}

// COSE key common label / value constants (RFC 8152) needed to reconstruct the
// small set of key types WebAuthn authenticators emit.
const (
	coseKty   = 1
	coseAlg   = 3
	coseECCrv = -1
	coseECX   = -2
	coseECY   = -3
	coseRSAN  = -1
	coseRSAE  = -2

	coseKtyEC2 = 2
	coseKtyRSA = 3

	coseCrvP256 = 1
	coseCrvP384 = 2
	coseCrvP521 = 3
)

// parseCOSEKey decodes a COSE_Key (a CBOR map with integer labels) into a Go
// public key. Only the EC2 (P-256/384/521) and RSA key types used by WebAuthn
// authenticators are supported.
func parseCOSEKey(der []byte) (crypto.PublicKey, error) {
	v, err := decodeCBOR(der)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[interface{}]interface{})
	if !ok {
		return nil, errors.New("COSE key is not a map")
	}
	ktyVal, ok := cborMapGet(m, coseKty)
	if !ok {
		return nil, errors.New("COSE key missing kty")
	}
	kty, ok := cborInt(ktyVal)
	if !ok {
		return nil, errors.New("COSE key kty is not an integer")
	}
	switch kty {
	case coseKtyEC2:
		return parseCOSEEC2(m)
	case coseKtyRSA:
		return parseCOSERSA(m)
	default:
		return nil, fmt.Errorf("unsupported COSE key type %d", kty)
	}
}

func parseCOSEEC2(m map[interface{}]interface{}) (crypto.PublicKey, error) {
	crvVal, ok := cborMapGet(m, coseECCrv)
	if !ok {
		return nil, errors.New("EC2 COSE key missing curve")
	}
	crv, _ := cborInt(crvVal)
	var curve elliptic.Curve
	switch crv {
	case coseCrvP256:
		curve = elliptic.P256()
	case coseCrvP384:
		curve = elliptic.P384()
	case coseCrvP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %d", crv)
	}
	xVal, ok1 := cborMapGet(m, coseECX)
	yVal, ok2 := cborMapGet(m, coseECY)
	xb, okx := cborBytes(xVal)
	yb, oky := cborBytes(yVal)
	if !ok1 || !ok2 || !okx || !oky {
		return nil, errors.New("EC2 COSE key missing coordinates")
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) { //nolint:staticcheck // SA1019: crypto/ecdh exposes no big.Int X/Y to rebuild the key this path needs; the deprecated on-curve check is retained deliberately.
		return nil, errors.New("EC2 COSE key point is not on the curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseCOSERSA(m map[interface{}]interface{}) (crypto.PublicKey, error) {
	nVal, ok1 := cborMapGet(m, coseRSAN)
	eVal, ok2 := cborMapGet(m, coseRSAE)
	nb, okn := cborBytes(nVal)
	eb, oke := cborBytes(eVal)
	if !ok1 || !ok2 || !okn || !oke {
		return nil, errors.New("RSA COSE key missing modulus/exponent")
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() <= 0 {
		return nil, errors.New("RSA COSE key exponent out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
