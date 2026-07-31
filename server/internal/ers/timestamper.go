package ers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// Timestamper obtains RFC 3161 timestamp tokens over a tree/group root. Unlike
// the audit-anchor Timestamper (internal/anchor), which is fixed to SHA-256, an
// Evidence Record's message imprint hash MUST track the hash algorithm of the
// current ArchiveTimeStampChain — so hash-tree renewal to a stronger algorithm
// can obtain a token whose imprint is SHA-384/512. The hash is therefore an
// explicit parameter.
type Timestamper interface {
	// Timestamp returns a DER TimeStampToken (a ContentInfo) whose message
	// imprint is (hash, digest), plus the token's genTime. digest MUST already be
	// the hash-sized root. Implementations validate the granted status, nonce
	// echo, and imprint match before returning, so callers receive only tokens
	// that cover exactly what they asked for.
	Timestamp(ctx context.Context, hash crypto.Hash, digest []byte) (token []byte, genTime time.Time, err error)
	// Source identifies where tokens come from for records and audit events: ""
	// for the in-process TSA, else the external TSA URL.
	Source() string
}

// Authority is the in-process TSA surface the AuthorityTimestamper drives. The
// internal *tsa.Authority satisfies it; tests supply a software-backed one.
type Authority interface {
	Stamp(ctx context.Context, reqDER []byte) (*tsa.Result, error)
}

// tokenFetcher implements the shared request/validate half of a Timestamper: it
// builds a TimeStampReq (fresh nonce, certReq so the token embeds the TSA
// certificate for later offline verification), delegates transport to roundTrip,
// and validates the returned token against exactly what was requested.
type tokenFetcher struct {
	source    string
	roundTrip func(ctx context.Context, reqDER []byte) (respDER []byte, err error)
}

func (f *tokenFetcher) Source() string { return f.source }

func (f *tokenFetcher) Timestamp(ctx context.Context, hash crypto.Hash, digest []byte) ([]byte, time.Time, error) {
	if !hash.Available() {
		return nil, time.Time{}, &UnsupportedHashError{Hash: hash}
	}
	if len(digest) != hash.Size() {
		return nil, time.Time{}, fmt.Errorf("ers: root digest length %d does not match %v size %d", len(digest), hash, hash.Size())
	}
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ers: generating nonce: %w", err)
	}
	reqDER, err := tsa.MakeRequest(hash, digest, &tsa.RequestOptions{Nonce: nonce, CertReq: true})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ers: building timestamp request: %w", err)
	}
	respDER, err := f.roundTrip(ctx, reqDER)
	if err != nil {
		return nil, time.Time{}, err
	}
	token, err := tsa.ExtractToken(respDER)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ers: %w", err)
	}
	info, err := tsa.ParseTokenInfo(token)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ers: %w", err)
	}
	// Fail closed on a token that does not cover exactly what we asked for.
	if info.Hash != hash {
		return nil, time.Time{}, fmt.Errorf("ers: timestamp token imprint hash %v does not match the requested %v", info.Hash, hash)
	}
	if !bytes.Equal(info.HashedMessage, digest) {
		return nil, time.Time{}, errors.New("ers: timestamp token does not cover the submitted root")
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		return nil, time.Time{}, errors.New("ers: timestamp token does not echo the request nonce")
	}
	return token, info.GenTime.UTC(), nil
}

// NewAuthorityTimestamper adapts the in-process RFC 3161 authority. A protocol
// rejection (not a transport error) is surfaced as an error since evidence
// generation has no signature-free fallback.
func NewAuthorityTimestamper(a Authority) Timestamper {
	return &tokenFetcher{
		source: "",
		roundTrip: func(ctx context.Context, reqDER []byte) ([]byte, error) {
			res, err := a.Stamp(ctx, reqDER)
			if err != nil {
				return nil, fmt.Errorf("ers: internal TSA: %w", err)
			}
			if !res.Granted {
				return nil, fmt.Errorf("ers: internal TSA rejected the timestamp request: %s", res.Detail)
			}
			return res.Response, nil
		},
	}
}

// maxTSAResponseBytes bounds an external TSA response (a token plus a small
// status; a few KB with the certificate chain embedded).
const maxTSAResponseBytes = 1 << 20

// NewHTTPTimestamper obtains tokens from an external RFC 3161 TSA over the
// standard HTTP transport (RFC 3161 §3.4). timeout <= 0 defaults to 30s.
// Deployments use this when the archive-timestamp authority must be independent
// of the PKI being preserved.
func NewHTTPTimestamper(url string, timeout time.Duration) Timestamper {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return &tokenFetcher{
		source: url,
		roundTrip: func(ctx context.Context, reqDER []byte) ([]byte, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqDER))
			if err != nil {
				return nil, fmt.Errorf("ers: building TSA request: %w", err)
			}
			req.Header.Set("Content-Type", "application/timestamp-query")
			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("ers: external TSA %s: %w", url, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("ers: external TSA %s returned HTTP %d", url, resp.StatusCode)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponseBytes+1))
			if err != nil {
				return nil, fmt.Errorf("ers: reading TSA response: %w", err)
			}
			if len(body) > maxTSAResponseBytes {
				return nil, fmt.Errorf("ers: TSA response exceeds %d bytes", maxTSAResponseBytes)
			}
			return body, nil
		},
	}
}
