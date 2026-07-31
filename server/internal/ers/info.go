package ers

import (
	"crypto"
	"crypto/x509"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// TimestampInfo describes one ArchiveTimeStamp for inspection and renewal
// decisioning.
type TimestampInfo struct {
	Chain      int       `json:"chain"`
	Index      int       `json:"index"`
	Hash       string    `json:"hash"`
	GenTime    time.Time `json:"gen_time"`
	TSASubject string    `json:"tsa_subject,omitempty"`
	// TSANotAfter is the embedded TSA certificate's expiry (zero when the token
	// omits its certificate). Time-stamp renewal is driven off the newest one.
	TSANotAfter time.Time `json:"tsa_not_after,omitempty"`
}

// Info is a structured summary of an EvidenceRecord for display and export.
type Info struct {
	Version          int             `json:"version"`
	Chains           int             `json:"chains"`
	DigestAlgorithms []string        `json:"digest_algorithms"`
	CurrentHash      string          `json:"current_hash"`
	FirstGenTime     time.Time       `json:"first_gen_time"`
	LatestGenTime    time.Time       `json:"latest_gen_time"`
	Timestamps       []TimestampInfo `json:"timestamps"`
}

// ChainCount returns the number of ArchiveTimeStampChains (1 for a fresh record,
// one more per hash-tree renewal).
func (er *EvidenceRecord) ChainCount() int { return len(er.wire.ArchiveTimeStampSequence) }

// CurrentHash reports the hash algorithm of the newest (current)
// ArchiveTimeStampChain — the algorithm hash-tree renewal would replace.
func (er *EvidenceRecord) CurrentHash() (crypto.Hash, error) {
	seq := er.wire.ArchiveTimeStampSequence
	if len(seq) == 0 {
		return 0, ErrNoTimestamp
	}
	return chainHashAlg(seq[len(seq)-1])
}

// latestATS returns the newest ArchiveTimeStamp (last stamp of the last chain).
func (er *EvidenceRecord) latestATS() (archiveTimeStamp, bool) {
	seq := er.wire.ArchiveTimeStampSequence
	if len(seq) == 0 {
		return archiveTimeStamp{}, false
	}
	chain := seq[len(seq)-1]
	if len(chain) == 0 {
		return archiveTimeStamp{}, false
	}
	return chain[len(chain)-1], true
}

// LatestToken returns the DER of the newest embedded RFC 3161 timestamp token.
func (er *EvidenceRecord) LatestToken() ([]byte, bool) {
	ats, ok := er.latestATS()
	if !ok || len(ats.TimeStamp.FullBytes) == 0 {
		return nil, false
	}
	return ats.TimeStamp.FullBytes, true
}

// LatestSignerNotAfter returns the expiry of the TSA certificate embedded in the
// newest token, and whether it could be determined. Time-stamp renewal is
// scheduled a configurable lookahead before this instant.
func (er *EvidenceRecord) LatestSignerNotAfter() (time.Time, bool) {
	token, ok := er.LatestToken()
	if !ok {
		return time.Time{}, false
	}
	cert := tokenSigner(token)
	if cert == nil {
		return time.Time{}, false
	}
	return cert.NotAfter, true
}

// LatestGenTime returns the genTime of the newest ArchiveTimeStamp.
func (er *EvidenceRecord) LatestGenTime() (time.Time, bool) {
	token, ok := er.LatestToken()
	if !ok {
		return time.Time{}, false
	}
	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		return time.Time{}, false
	}
	return info.GenTime.UTC(), true
}

// Info assembles a structured summary, parsing each embedded token for its
// genTime and TSA certificate. Best-effort per token: an unparseable token still
// appears with the fields that could be read.
func (er *EvidenceRecord) Info() Info {
	seq := er.wire.ArchiveTimeStampSequence
	info := Info{Version: er.wire.Version, Chains: len(seq)}
	for _, alg := range er.wire.DigestAlgorithms {
		if h, ok := digestForOID(alg.Algorithm); ok {
			info.DigestAlgorithms = append(info.DigestAlgorithms, HashName(h))
		} else {
			info.DigestAlgorithms = append(info.DigestAlgorithms, alg.Algorithm.String())
		}
	}
	if h, err := er.CurrentHash(); err == nil {
		info.CurrentHash = HashName(h)
	}
	for ci, chain := range seq {
		for j, ats := range chain {
			ti := TimestampInfo{Chain: ci, Index: j}
			if h, err := chainHashAlg(chain); err == nil {
				ti.Hash = HashName(h)
			}
			if tinfo, err := tsa.ParseTokenInfo(ats.TimeStamp.FullBytes); err == nil {
				ti.GenTime = tinfo.GenTime.UTC()
				if info.FirstGenTime.IsZero() || ti.GenTime.Before(info.FirstGenTime) {
					info.FirstGenTime = ti.GenTime
				}
				if ti.GenTime.After(info.LatestGenTime) {
					info.LatestGenTime = ti.GenTime
				}
			}
			if cert := tokenSigner(ats.TimeStamp.FullBytes); cert != nil {
				ti.TSASubject = cert.Subject.String()
				ti.TSANotAfter = cert.NotAfter
			}
			info.Timestamps = append(info.Timestamps, ti)
		}
	}
	return info
}

// tokenSigner extracts the TSA signing certificate embedded in a timestamp
// token, or nil when the token embeds no certificate / cannot be parsed.
func tokenSigner(token []byte) *x509.Certificate {
	parsed, err := cms.ParseSignedData(token)
	if err != nil {
		return nil
	}
	// The token embeds the signer certificate (certReq was set at minting). Match
	// it by the SignerInfo, falling back to the first embedded certificate.
	if err := parsed.Verify(); err == nil {
		if c := parsed.SignerCertificate(); c != nil {
			return c
		}
	}
	if len(parsed.Certificates) > 0 {
		return parsed.Certificates[0]
	}
	return nil
}
