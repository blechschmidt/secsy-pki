package ct

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// addPreChainPath is the RFC 6962 §4.2 endpoint, relative to a log's base URL.
const addPreChainPath = "ct/v1/add-pre-chain"

// maxSCTResponseBytes bounds an add-pre-chain response body to guard against a
// misbehaving or hostile log.
const maxSCTResponseBytes = 1 << 20 // 1 MiB

// Log is a configured Certificate Transparency log endpoint.
type Log struct {
	// Name is the operator-facing identifier used in profiles and audit records.
	Name string
	// Operator is the name of the organization that runs this log (e.g.
	// "Google", "Cloudflare", "DigiCert"). CT operator-diversity policies
	// (Chrome, Apple) count distinct operators rather than distinct logs, so two
	// logs sharing an Operator satisfy a diversity requirement only once. Empty
	// means the operator is unknown; a diversity policy then treats the log as an
	// independent operator keyed by its own name, and it can never satisfy a
	// required-operator allowlist entry.
	Operator string
	// URL is the log's base URL (the RFC 6962 ct/v1/* paths are appended to it).
	URL string
	// PublicKey, when set, is the log's public key. It enables verification of
	// returned SCT signatures and identification of the expected log id.
	PublicKey crypto.PublicKey
	// LogID is the SHA-256 of the log's SubjectPublicKeyInfo, derived from
	// PublicKey when present. A returned SCT's log id must match it.
	LogID [32]byte
	// mmd is the log's Maximum Merge Delay: the deadline by which the log
	// promises to incorporate a certificate it issued an SCT for into its
	// Merkle tree (RFC 6962 §3). The inclusion monitor only expects a proof
	// once mmd has elapsed since the SCT's timestamp.
	mmd     time.Duration
	hasKey  bool
	hasID   bool
	httpDo  func(*http.Request) (*http.Response, error)
	rootURL string // trimmed base URL, e.g. "https://ct.example/log"
	baseURL string // add-pre-chain endpoint
}

// defaultMMD is the standard Maximum Merge Delay assumed when a log's config
// does not set one; 24 hours is the value the major public logs advertise.
const defaultMMD = 24 * time.Hour

// LogConfig configures a single CT log.
type LogConfig struct {
	Name string
	URL  string
	// Operator names the organization that runs the log; see Log.Operator.
	// Optional — when empty it can be filled from a Google-style CT log list via
	// LoadOperatorMap / ApplyOperators before the submitter is built.
	Operator string
	// PublicKeyPEM is the log's public key as a PEM SubjectPublicKeyInfo block.
	// Optional: when empty, SCT signatures from this log are accepted without
	// cryptographic verification (count-only policy).
	PublicKeyPEM string
	// MMD is the log's Maximum Merge Delay. Zero uses defaultMMD (24h).
	MMD time.Duration
}

// NewLog builds a Log from its configuration, validating the URL and (when
// supplied) the public key.
func NewLog(cfg LogConfig, client *http.Client) (*Log, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("ct log: name is required")
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("ct log %q: url is required", cfg.Name)
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	mmd := cfg.MMD
	if mmd <= 0 {
		mmd = defaultMMD
	}
	rootURL := strings.TrimRight(cfg.URL, "/")
	l := &Log{
		Name:     cfg.Name,
		Operator: strings.TrimSpace(cfg.Operator),
		URL:      cfg.URL,
		mmd:      mmd,
		rootURL:  rootURL,
		baseURL:  rootURL + "/" + addPreChainPath,
		httpDo:   client.Do,
	}
	if pemStr := strings.TrimSpace(cfg.PublicKeyPEM); pemStr != "" {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return nil, fmt.Errorf("ct log %q: public_key is not valid PEM", cfg.Name)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ct log %q: parsing public key: %w", cfg.Name, err)
		}
		l.PublicKey = pub
		l.hasKey = true
		l.LogID = sha256.Sum256(block.Bytes)
		l.hasID = true
	}
	return l, nil
}

// MMD returns the log's Maximum Merge Delay.
func (l *Log) MMD() time.Duration { return l.mmd }

// HasKey reports whether the log's public key is configured, i.e. whether SCT
// and STH signatures from it can be cryptographically verified.
func (l *Log) HasKey() bool { return l.hasKey }

// addPreChainRequest is the JSON body of an add-pre-chain call: the
// precertificate followed by the issuing chain, each base64 DER (RFC 6962 §4.2).
type addPreChainRequest struct {
	Chain []string `json:"chain"`
}

// submit sends chain (precertificate first, then issuer chain) to the log once
// and returns the resulting SCT. It does not retry; submitWithPolicy adds the
// retry/timeout envelope.
func (l *Log) submit(ctx context.Context, chain [][]byte) (*SCT, error) {
	encoded := make([]string, len(chain))
	for i, der := range chain {
		encoded[i] = base64.StdEncoding.EncodeToString(der)
	}
	body, err := json.Marshal(addPreChainRequest{Chain: encoded})
	if err != nil {
		return nil, fmt.Errorf("encoding add-pre-chain request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := l.httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("submitting to log %q: %w", l.Name, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxSCTResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading log %q response: %w", l.Name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log %q returned HTTP %d: %s", l.Name, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	sct, err := parseSCTResponse(respBody)
	if err != nil {
		return nil, err
	}
	if l.hasID && sct.LogID != l.LogID {
		return nil, fmt.Errorf("log %q returned SCT for a different log id", l.Name)
	}
	return sct, nil
}

// submitWithPolicy submits to the log with a per-attempt timeout and up to
// retries additional attempts on failure. On success it verifies the SCT
// signature when the log's public key is configured.
func (l *Log) submitWithPolicy(ctx context.Context, chain [][]byte, ikh [32]byte, tbs []byte, timeout time.Duration, retries int) (*SCT, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx := ctx
		cancel := func() {}
		if timeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		sct, err := l.submit(attemptCtx, chain)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if l.hasKey {
			if err := sct.verify(l.PublicKey, ikh, tbs); err != nil {
				lastErr = fmt.Errorf("log %q: %w", l.Name, err)
				continue
			}
		}
		return sct, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("log %q: no attempts made", l.Name)
	}
	return nil, lastErr
}
