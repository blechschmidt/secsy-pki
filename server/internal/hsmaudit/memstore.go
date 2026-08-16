package hsmaudit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// MemStore is an in-memory Store. It exists so the collector, provisioning and
// export paths can be exercised without a database, and it enforces the same
// invariants the SQL store does — write-once anchor, immutable device entries,
// sealed ledger chain — so a test passing against it is not passing against a
// weaker contract than production.
type MemStore struct {
	mu        sync.Mutex
	state     *AuditState
	entries   map[uint16]hsm.AuditLogEntry
	ledger    []LedgerEntry
	freshness []FreshnessProof
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{entries: map[uint16]hsm.AuditLogEntry{}}
}

func (m *MemStore) LoadAuditState(ctx context.Context) (*AuditState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return nil, nil
	}
	cp := *m.state
	return &cp, nil
}

func (m *MemStore) SaveAuditState(ctx context.Context, st *AuditState) error {
	if st == nil {
		return fmt.Errorf("hsm audit state: nothing to save")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != nil {
		if !strings.EqualFold(m.state.Anchor, st.Anchor) || !strings.EqualFold(m.state.DeviceSerial, st.DeviceSerial) {
			return fmt.Errorf("refusing to re-pin HSM audit state: stored device %s anchor %s, attempted device %s anchor %s",
				m.state.DeviceSerial, m.state.Anchor, st.DeviceSerial, st.Anchor)
		}
	}
	cp := *st
	cp.Anchor = strings.ToLower(cp.Anchor)
	m.state = &cp
	return nil
}

func (m *MemStore) UpdateTail(ctx context.Context, tail Tail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return fmt.Errorf("hsm audit state not initialised")
	}
	m.state.Tail = Tail{Number: tail.Number, Digest: strings.ToLower(tail.Digest)}
	return nil
}

func (m *MemStore) AppendLogEntries(ctx context.Context, entries []hsm.AuditLogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range entries {
		e.Hash = strings.ToLower(e.Hash)
		if have, ok := m.entries[e.Number]; ok {
			if have != e {
				return fmt.Errorf("device log entry %d was already stored with different content", e.Number)
			}
			continue
		}
		m.entries[e.Number] = e
	}
	return nil
}

func (m *MemStore) LogEntries(ctx context.Context) ([]hsm.AuditLogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]hsm.AuditLogEntry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out, nil
}

func (m *MemStore) AppendLedger(ctx context.Context, e *LedgerEntry) error {
	if e == nil {
		return fmt.Errorf("hsm signature ledger: nothing to append")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := LedgerGenesisHash
	seq := int64(1)
	if n := len(m.ledger); n > 0 {
		prev = m.ledger[n-1].Hash
		seq = m.ledger[n-1].Seq + 1
	}
	e.Seal(seq, prev)
	m.ledger = append(m.ledger, *e)
	return nil
}

func (m *MemStore) Ledger(ctx context.Context) ([]LedgerEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]LedgerEntry(nil), m.ledger...), nil
}

func (m *MemStore) AppendFreshnessProof(ctx context.Context, p *FreshnessProof) error {
	if p == nil {
		return fmt.Errorf("hsm freshness proof: nothing to append")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p.Seq = int64(len(m.freshness)) + 1
	m.freshness = append(m.freshness, *p)
	return nil
}

func (m *MemStore) FreshnessProofs(ctx context.Context) ([]FreshnessProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]FreshnessProof(nil), m.freshness...), nil
}

var _ Store = (*MemStore)(nil)
