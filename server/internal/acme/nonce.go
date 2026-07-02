package acme

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// nonceTTL bounds how long an issued anti-replay nonce remains valid.
const nonceTTL = 30 * time.Minute

// nonceStore issues and validates single-use anti-replay nonces (RFC 8555 §6.5).
// Nonces are held in memory: they are short-lived, single-use tokens, so losing
// them on restart merely forces clients to fetch a fresh one (badNonce → retry),
// which every conformant client already handles.
type nonceStore struct {
	mu     sync.Mutex
	issued map[string]time.Time
	now    func() time.Time
}

func newNonceStore(now func() time.Time) *nonceStore {
	if now == nil {
		now = time.Now
	}
	return &nonceStore{issued: make(map[string]time.Time), now: now}
}

// Issue mints a fresh nonce and records it as valid.
func (n *nonceStore) Issue() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b[:])

	n.mu.Lock()
	defer n.mu.Unlock()
	n.gcLocked()
	n.issued[nonce] = n.now().Add(nonceTTL)
	return nonce, nil
}

// Consume validates a nonce and, on success, removes it so it cannot be reused.
// It reports whether the nonce was valid and unexpired.
func (n *nonceStore) Consume(nonce string) bool {
	if nonce == "" {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	exp, ok := n.issued[nonce]
	if !ok {
		return false
	}
	delete(n.issued, nonce)
	return n.now().Before(exp)
}

// gcLocked evicts expired nonces. Called opportunistically on Issue while the
// lock is held so the map cannot grow without bound.
func (n *nonceStore) gcLocked() {
	now := n.now()
	for k, exp := range n.issued {
		if now.After(exp) {
			delete(n.issued, k)
		}
	}
}
