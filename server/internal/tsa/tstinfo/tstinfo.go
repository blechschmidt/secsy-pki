// Package tstinfo decodes RFC 3161 timestamp responses and tokens.
//
// It is the read-only half of internal/tsa, split out because it has no
// dependencies beyond internal/cms while the authority half needs the database
// (to resolve the signing CA and record audit events). Several packages want
// only the decoding: the audit-chain anchoring service, the CAdES signing and
// verification paths, RFC 4998 evidence records, and the HSM audit subsystem —
// and that last one is imported *by* the database layer, so a dependency on the
// full tsa package would close an import cycle.
//
// internal/tsa re-exports everything here, so callers continue to use
// tsa.ParseTokenInfo and tsa.TokenInfo unchanged; this package is for the ones
// that cannot afford the authority's dependencies.
//
// The types here are DECODING layouts and deliberately differ from the
// marshaling layouts in internal/tsa — see parsedTSTInfo for why that
// distinction is load-bearing rather than incidental.
package tstinfo

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// PKIStatus values from RFC 3161 §2.4.2 that carry a token.
const (
	StatusGranted        = 0
	StatusGrantedWithMod = 1
)

// OIDTSTInfo (id-ct-TSTInfo) is the eContentType of a TimeStampToken's
// encapsulated content.
var OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// DigestForOID maps a digest-algorithm OID to its crypto.Hash, reporting false
// for one that is not an accepted message-imprint hash.
func DigestForOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	case oid.Equal(oidSHA1):
		return crypto.SHA1, true
	default:
		return 0, false
	}
}

// timeStampRespParsed mirrors TimeStampResp for decoding: the status is always
// present, the token only on granted/grantedWithMods.
type timeStampRespParsed struct {
	Status asn1.RawValue
	Token  asn1.RawValue `asn1:"optional"`
}

// pkiStatusInfoParsed decodes just the leading status integer of a
// PKIStatusInfo; statusString/failInfo are optional trailing fields we surface
// only in the error message.
type pkiStatusInfoParsed struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// messageImprint is the RFC 3161 MessageImprint: the hash algorithm and the
// digest of the data being time-stamped.
type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// rawAccuracy is the DER layout of RFC 3161 Accuracy. millis/micros are
// [0]/[1] IMPLICIT and, like seconds, omitted when zero. It is decoded only to
// consume the field; the value is not surfaced.
type rawAccuracy struct {
	Seconds int `asn1:"optional,default:0"`
	Millis  int `asn1:"optional,default:0,tag:0"`
	Micros  int `asn1:"optional,default:0,tag:1"`
}

// ExtractToken pulls the TimeStampToken (a CMS ContentInfo DER) out of a
// DER-encoded TimeStampResp. It returns an error when the response reports a
// non-granted status (and therefore carries no token).
func ExtractToken(respDER []byte) ([]byte, error) {
	var resp timeStampRespParsed
	rest, err := asn1.Unmarshal(respDER, &resp)
	if err != nil {
		return nil, fmt.Errorf("tsa: parsing TimeStampResp: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("tsa: trailing data after TimeStampResp")
	}
	var status pkiStatusInfoParsed
	if _, err := asn1.Unmarshal(resp.Status.FullBytes, &status); err != nil {
		return nil, fmt.Errorf("tsa: parsing PKIStatusInfo: %w", err)
	}
	if status.Status != StatusGranted && status.Status != StatusGrantedWithMod {
		return nil, fmt.Errorf("tsa: request was rejected (status %d, failInfo bits %v)", status.Status, status.FailInfo.BitLength)
	}
	if len(resp.Token.FullBytes) == 0 {
		return nil, errors.New("tsa: granted TimeStampResp carries no token")
	}
	return resp.Token.FullBytes, nil
}

// TokenInfo is the decoded TSTInfo of a TimeStampToken: the fields a verifier
// or operator display needs.
type TokenInfo struct {
	Policy       asn1.ObjectIdentifier
	SerialNumber *big.Int
	GenTime      time.Time
	// Hash / HashedMessage are the message imprint the token binds to the time.
	Hash          crypto.Hash
	HashedMessage []byte
	Nonce         *big.Int
}

// parsedTSTInfo is the TSTInfo layout for DECODING. It deliberately differs
// from the marshaling layout (internal/tsa's rawTSTInfo): there the optional
// accuracy is a pre-encoded RawValue, but an optional RawValue field matches ANY
// tag when unmarshaling, so on a token without accuracy it would swallow the
// nonce INTEGER. Concrete field types make Go's asn1 dispatch optionals by tag
// (accuracy SEQUENCE, ordering BOOLEAN, nonce INTEGER, tsa [0], extensions [1]).
type parsedTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       rawAccuracy      `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// ParseTokenInfo decodes a TimeStampToken (a CMS SignedData whose eContent is a
// TSTInfo) and returns the TSTInfo fields. It does NOT verify the token's
// signature or certificate chain — pair it with a cms verification of the token
// when trust matters.
func ParseTokenInfo(tokenDER []byte) (*TokenInfo, error) {
	parsed, err := cms.ParseSignedData(tokenDER)
	if err != nil {
		return nil, fmt.Errorf("tsa: parsing TimeStampToken: %w", err)
	}
	if got := parsed.EncapContentType(); !got.Equal(OIDTSTInfo) {
		return nil, fmt.Errorf("tsa: encapsulated content type is %v, want id-ct-TSTInfo", got)
	}
	if len(parsed.Content) == 0 {
		return nil, errors.New("tsa: TimeStampToken has no encapsulated TSTInfo")
	}
	var info parsedTSTInfo
	if _, err := asn1.Unmarshal(parsed.Content, &info); err != nil {
		return nil, fmt.Errorf("tsa: parsing TSTInfo: %w", err)
	}
	if info.Version != 1 {
		return nil, fmt.Errorf("tsa: unsupported TSTInfo version %d", info.Version)
	}
	hash, ok := DigestForOID(info.MessageImprint.HashAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("tsa: unsupported message-imprint hash %v", info.MessageImprint.HashAlgorithm.Algorithm)
	}
	return &TokenInfo{
		Policy:        info.Policy,
		SerialNumber:  info.SerialNumber,
		GenTime:       info.GenTime,
		Hash:          hash,
		HashedMessage: info.MessageImprint.HashedMessage,
		Nonce:         info.Nonce,
	}, nil
}
