package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// stateFileName is the agent's bookkeeping file inside the state dir.
const stateFileName = "state.json"

// agentState is persisted between runs so renewal choices (notably the
// ARI-selected moment) survive restarts and `status` can report outcomes.
type agentState struct {
	Certificates map[string]*certState `json:"certificates"`

	dirty bool   `json:"-"`
	path  string `json:"-"`
}

// certState is the per-certificate bookkeeping.
type certState struct {
	// Serial of the currently installed certificate.
	Serial string `json:"serial,omitempty"`
	// EnrolledVia records the protocol that produced the current certificate.
	EnrolledVia string `json:"enrolled_via,omitempty"`
	// ARI caches the last renewal-info answer and the selected renewal moment.
	ARI *ariState `json:"ari,omitempty"`
	// LastRenewal is when the certificate was last successfully installed.
	LastRenewal time.Time `json:"last_renewal,omitempty"`
	// LastAttempt / LastOutcome / LastError describe the most recent pass.
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastOutcome string    `json:"last_outcome,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	// ConsecutiveFailures drives retry backoff.
	ConsecutiveFailures int `json:"consecutive_failures,omitempty"`
	// NextAttempt, when set, suppresses retries until then (backoff after
	// failures).
	NextAttempt time.Time `json:"next_attempt,omitempty"`
}

// ariState caches one renewal-info response.
type ariState struct {
	CertID      string    `json:"cert_id"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Selected    time.Time `json:"selected"`
	RetryAfter  int64     `json:"retry_after_seconds"`
	FetchedAt   time.Time `json:"fetched_at"`
}

// loadState reads (or initializes) the state file in dir.
func loadState(dir string) (*agentState, error) {
	st := &agentState{
		Certificates: make(map[string]*certState),
		path:         filepath.Join(dir, stateFileName),
	}
	data, err := os.ReadFile(st.path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}
	if err := json.Unmarshal(data, st); err != nil {
		// A corrupt state file must not brick the agent: renewal decisions
		// degrade gracefully (ARI re-fetches, jitter is deterministic anyway).
		return &agentState{ //nolint:nilerr // a corrupt state file is deliberately recovered into a fresh state (see comment); the nil error is intentional.
			Certificates: make(map[string]*certState),
			path:         filepath.Join(dir, stateFileName),
		}, nil
	}
	if st.Certificates == nil {
		st.Certificates = make(map[string]*certState)
	}
	return st, nil
}

// cert returns (creating if needed) the state entry for name.
func (s *agentState) cert(name string) *certState {
	cs, ok := s.Certificates[name]
	if !ok {
		cs = &certState{}
		s.Certificates[name] = cs
		s.dirty = true
	}
	return cs
}

// save persists the state atomically if it changed.
func (s *agentState) save() error {
	if !s.dirty {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	if err := writeFileAtomic(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	s.dirty = false
	return nil
}
