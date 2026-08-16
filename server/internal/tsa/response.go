package tsa

import (
	"github.com/blechschmidt/secsy-pki/server/internal/tsa/tstinfo"
)

// The decoding half of RFC 3161 lives in internal/tsa/tstinfo, which depends on
// nothing but internal/cms. This package additionally needs the database — to
// resolve the signing CA and record audit events — and that made it unusable
// from internal/hsmaudit, which the database layer itself imports.
//
// These aliases keep the split invisible to callers: tsa.ParseTokenInfo,
// tsa.TokenInfo and tsa.ExtractToken continue to work exactly as before, while
// packages that cannot take on the authority's dependencies import tstinfo
// directly.

// TokenInfo is the decoded TSTInfo of a TimeStampToken. See tstinfo.TokenInfo.
type TokenInfo = tstinfo.TokenInfo

// ExtractToken pulls the TimeStampToken out of a DER-encoded TimeStampResp,
// erroring when the response reports a non-granted status.
func ExtractToken(respDER []byte) ([]byte, error) { return tstinfo.ExtractToken(respDER) }

// ParseTokenInfo decodes a TimeStampToken's TSTInfo. It does not verify the
// token's signature or certificate chain.
func ParseTokenInfo(tokenDER []byte) (*TokenInfo, error) { return tstinfo.ParseTokenInfo(tokenDER) }
