package ct

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Submitter holds the configured registry of CT logs and orchestrates
// precertificate submission across them under a per-issuance policy. It is safe
// for concurrent use: the log set is fixed at construction and never mutated.
type Submitter struct {
	logs map[string]*Log
}

// NewSubmitter builds a Submitter from a set of log configurations sharing an
// HTTP client. Log names must be unique.
func NewSubmitter(configs []LogConfig, client *http.Client) (*Submitter, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	logs := make(map[string]*Log, len(configs))
	for _, cfg := range configs {
		l, err := NewLog(cfg, client)
		if err != nil {
			return nil, err
		}
		if _, dup := logs[l.Name]; dup {
			return nil, fmt.Errorf("duplicate ct log name %q", l.Name)
		}
		logs[l.Name] = l
	}
	return &Submitter{logs: logs}, nil
}

// LogNames returns the sorted names of all registered logs.
func (s *Submitter) LogNames() []string {
	names := make([]string, 0, len(s.logs))
	for name := range s.logs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Has reports whether a log with the given name is registered.
func (s *Submitter) Has(name string) bool {
	_, ok := s.logs[name]
	return ok
}

// LogByID returns the registered log whose SHA-256 log id matches id, if any.
// The inclusion monitor uses it to resolve the log an embedded SCT names (SCTs
// carry the log id, not the operator's log name) so it can fetch that log's
// signed tree head and inclusion proofs. Only logs with a configured public key
// have a known id, so count-only logs are never returned here.
func (s *Submitter) LogByID(id [32]byte) (*Log, bool) {
	for _, l := range s.logs {
		if l.hasID && l.LogID == id {
			return l, true
		}
	}
	return nil, false
}

// Logs returns every registered log, sorted by name, for the inclusion monitor
// and diagnostics. The returned slice is a fresh copy; the pointers are shared
// (logs are immutable after construction).
func (s *Submitter) Logs() []*Log {
	out := make([]*Log, 0, len(s.logs))
	for _, name := range s.LogNames() {
		out = append(out, s.logs[name])
	}
	return out
}

// SubmitRequest describes one precertificate submission across a set of logs.
type SubmitRequest struct {
	// Logs names the logs to submit to. Empty means every registered log.
	Logs []string
	// PrecertDER is the DER-encoded, HSM-signed precertificate (poison present).
	PrecertDER []byte
	// Issuer is the issuing CA certificate (for the issuer key hash used in SCT
	// verification).
	Issuer *x509.Certificate
	// IssuerChainDER is the issuer certificate chain in DER (issuer first, up to
	// the root), appended after the precertificate in the add-pre-chain request.
	IssuerChainDER [][]byte
	// Timeout bounds each individual log attempt. Zero means no per-attempt
	// timeout (the caller's context still applies).
	Timeout time.Duration
	// Retries is the number of additional attempts per log after the first.
	Retries int
}

// LogResult reports the outcome of submitting to a single log.
type LogResult struct {
	Log   string `json:"log"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// SubmitResult aggregates a fan-out submission.
type SubmitResult struct {
	SCTs    []*SCT
	Results []LogResult
}

// Submit fans out the precertificate to the requested logs concurrently and
// collects the SCTs that succeed (and, where a log key is configured, verify).
// It never returns an error for individual log failures — those are reported per
// log in Results so the caller can apply its min-SCT and fail-open/closed
// policy. It returns an error only for a misconfigured request.
func (s *Submitter) Submit(ctx context.Context, req SubmitRequest) (*SubmitResult, error) {
	if req.Issuer == nil {
		return nil, fmt.Errorf("ct submit: issuer certificate is required")
	}
	if len(req.PrecertDER) == 0 {
		return nil, fmt.Errorf("ct submit: precertificate is required")
	}

	logs, err := s.selectLogs(req.Logs)
	if err != nil {
		return nil, err
	}

	// The chain a CT log signs over: the precertificate's TBS with the poison
	// extension removed, plus the issuer key hash.
	tbs, err := TBSWithoutExtension(req.PrecertDER, OIDPoison)
	if err != nil {
		return nil, fmt.Errorf("ct submit: deriving precertificate TBS: %w", err)
	}
	ikh := issuerKeyHash(req.Issuer)

	chain := make([][]byte, 0, 1+len(req.IssuerChainDER))
	chain = append(chain, req.PrecertDER)
	chain = append(chain, req.IssuerChainDER...)

	scts := make([]*SCT, len(logs))
	results := make([]LogResult, len(logs))
	var wg sync.WaitGroup
	for i, lg := range logs {
		wg.Add(1)
		go func(i int, lg *Log) {
			defer wg.Done()
			sct, err := lg.submitWithPolicy(ctx, chain, ikh, tbs, req.Timeout, req.Retries)
			if err != nil {
				results[i] = LogResult{Log: lg.Name, OK: false, Error: err.Error()}
				return
			}
			scts[i] = sct
			results[i] = LogResult{Log: lg.Name, OK: true}
		}(i, lg)
	}
	wg.Wait()

	out := &SubmitResult{Results: results}
	for _, sct := range scts {
		if sct != nil {
			out.SCTs = append(out.SCTs, sct)
		}
	}
	return out, nil
}

// selectLogs resolves the named logs, or every registered log when names is
// empty. Unknown names are an error so a misconfigured profile fails loudly
// rather than silently submitting to fewer logs than intended.
func (s *Submitter) selectLogs(names []string) ([]*Log, error) {
	if len(names) == 0 {
		logs := make([]*Log, 0, len(s.logs))
		for _, name := range s.LogNames() {
			logs = append(logs, s.logs[name])
		}
		if len(logs) == 0 {
			return nil, fmt.Errorf("ct submit: no logs are registered")
		}
		return logs, nil
	}
	logs := make([]*Log, 0, len(names))
	for _, name := range names {
		lg, ok := s.logs[name]
		if !ok {
			return nil, fmt.Errorf("ct submit: unknown log %q", name)
		}
		logs = append(logs, lg)
	}
	return logs, nil
}
