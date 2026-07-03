package tsa

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"crypto/x509/pkix"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

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

// ExtractToken pulls the TimeStampToken (a CMS ContentInfo DER) out of a
// DER-encoded TimeStampResp. It returns an error when the response reports a
// non-granted status (and therefore carries no token). It is the client-side
// counterpart of the response builders: callers that drive Authority.Stamp
// programmatically (the artifact-signing countersignature path) use it to embed
// the token itself rather than the response wrapper.
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
// from the marshaling layout (rawTSTInfo): there the optional accuracy is a
// pre-encoded RawValue, but an optional RawValue field matches ANY tag when
// unmarshaling, so on a token without accuracy it would swallow the nonce
// INTEGER. Concrete field types make Go's asn1 dispatch optionals by tag
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
// when trust matters (the signing package does both).
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
	hash, ok := digestForOID(info.MessageImprint.HashAlgorithm.Algorithm)
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
