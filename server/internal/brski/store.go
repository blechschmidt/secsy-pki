package brski

import (
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"time"
)

// pledgeGrant is a device authorized (by a successful voucher exchange) to
// perform exactly the EST enrollment that follows BRSKI bootstrapping.
type pledgeGrant struct {
	serial  string
	profile string
	expires time.Time
}

// pledgeStore tracks pledges that have completed the voucher exchange and are
// therefore authorized to EST-enroll their operational LDevID. It is keyed by a
// hash of the IDevID's SubjectPublicKeyInfo (the identity the pledge presents as
// its TLS client certificate on the follow-up EST connection), so the grant is
// bound to the exact device that bootstrapped and survives IDevID serial reuse.
//
// Grants are time-bounded; enrollment must follow bootstrapping promptly. Expiry
// is lazy (checked on read) plus opportunistically swept on write, so a device
// that never returns does not leak an entry indefinitely.
type pledgeStore struct {
	mu     sync.Mutex
	grants map[string]pledgeGrant
	now    func() time.Time
}

func newPledgeStore(now func() time.Time) *pledgeStore {
	if now == nil {
		now = time.Now
	}
	return &pledgeStore{grants: make(map[string]pledgeGrant), now: now}
}

// spkiKey is the stable per-device key: SHA-256 over the certificate's
// SubjectPublicKeyInfo. Returns "" when the key cannot be marshaled.
func spkiKey(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(spki)
	return string(sum[:])
}

// authorize records (or refreshes) a grant for the pledge identified by idevid,
// valid for ttl.
func (s *pledgeStore) authorize(idevid *x509.Certificate, serial, profile string, ttl time.Duration) {
	key := spkiKey(idevid)
	if key == "" {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	s.grants[key] = pledgeGrant{serial: serial, profile: profile, expires: now.Add(ttl)}
}

// lookup returns the unexpired grant for the presenter, if any.
func (s *pledgeStore) lookup(cert *x509.Certificate) (pledgeGrant, bool) {
	key := spkiKey(cert)
	if key == "" {
		return pledgeGrant{}, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[key]
	if !ok {
		return pledgeGrant{}, false
	}
	if !now.Before(g.expires) {
		delete(s.grants, key)
		return pledgeGrant{}, false
	}
	return g, true
}

// sweepLocked drops expired grants. The caller holds s.mu.
func (s *pledgeStore) sweepLocked(now time.Time) {
	for k, g := range s.grants {
		if !now.Before(g.expires) {
			delete(s.grants, k)
		}
	}
}
