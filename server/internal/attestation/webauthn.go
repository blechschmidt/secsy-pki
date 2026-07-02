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
		raw:      data,
		rpIDHash: data[:32],
		flags:    data[32],
	}
	// data[33:37] is the 4-byte signature counter (unused here).
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
	rest = rest[credIDLen:]

	key, err := parseCOSEKey(rest)
	if err != nil {
		return nil, fmt.Errorf("authData: credential public key: %w", err)
	}
	ad.credPublicKey = key
	return ad, nil
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
	if !curve.IsOnCurve(x, y) {
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
