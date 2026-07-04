//go:build sqlite

// These tests exercise the shared/durable anti-replay nonce store (Task 97).
// They model a multi-replica deployment as two acme.Server instances backed by
// one shared Store and assert the cross-replica correctness the previous
// in-process nonce map could not provide.
package acme

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// newNonceServer builds a bare ACME server over the given shared store. The key
// provider is only needed to satisfy New (nonces never touch the HSM), so a
// throwaway software provider suffices.
func newNonceServer(t *testing.T, db *database.DB) *Server {
	t.Helper()
	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })
	return New(db, provider, Config{CAID: "unused"})
}

func sharedNonceDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", t.TempDir()+"/nonce.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestNonceSharedAcrossInstances is the core Task 97 requirement: two server
// instances sharing one store behave like two replicas behind a load balancer.
// Instance A mints a nonce; instance B accepts it (no spurious badNonce); and a
// replay — on either instance — is rejected.
func TestNonceSharedAcrossInstances(t *testing.T) {
	db := sharedNonceDB(t)
	a := newNonceServer(t, db)
	b := newNonceServer(t, db)

	// Both replicas must derive the same signing secret from the shared store;
	// otherwise B could not even verify A's nonce.
	if !bytes.Equal(a.nonces.secret, b.nonces.secret) {
		t.Fatal("instances sharing a store must derive the same nonce-signing secret")
	}

	nonce, err := a.nonces.Issue()
	if err != nil {
		t.Fatalf("A.Issue: %v", err)
	}

	// The other replica accepts a nonce it never minted — the whole point.
	if !b.nonces.Consume(nonce) {
		t.Fatal("instance B must accept a nonce minted by instance A")
	}
	// Replaying it on B is rejected (already consumed).
	if b.nonces.Consume(nonce) {
		t.Fatal("instance B must reject a replayed nonce")
	}
	// Replaying it on A is likewise rejected — the consumed-set is shared, so the
	// first consume on B already spent it everywhere.
	if a.nonces.Consume(nonce) {
		t.Fatal("instance A must reject a nonce already consumed on B")
	}
}

// TestNonceRejectsForgedAndMalformed verifies the cheap, DB-free fast path:
// empty, garbage, and tampered nonces are rejected without ever reaching the
// backend. A nonce signed by a foreign secret must not verify on our instance.
func TestNonceRejectsForgedAndMalformed(t *testing.T) {
	db := sharedNonceDB(t)
	s := newNonceServer(t, db)

	if s.nonces.Consume("") {
		t.Fatal("empty nonce must be rejected")
	}
	if s.nonces.Consume("not-base64-!!!") {
		t.Fatal("non-base64 nonce must be rejected")
	}
	if s.nonces.Consume("AAAA") {
		t.Fatal("wrong-length nonce must be rejected")
	}

	// A valid nonce with a single flipped MAC byte fails the HMAC check.
	nonce, err := s.nonces.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tampered := tamperNonceMAC(t, nonce)
	if s.nonces.Consume(tampered) {
		t.Fatal("tampered nonce must be rejected")
	}
	// The original still works exactly once (tampering did not consume it).
	if !s.nonces.Consume(nonce) {
		t.Fatal("original nonce must still be valid after a tampered replay attempt")
	}

	// A nonce minted with a different secret (a foreign server / rotated key) must
	// not verify here — self-authentication is what binds a nonce to our fleet.
	foreign := newNonceStore(db, []byte("a-totally-different-32-byte-secret!!"), s.nonces.now)
	fn, _ := foreign.Issue()
	if s.nonces.Consume(fn) {
		t.Fatal("a nonce signed by a foreign secret must not verify")
	}
}

// TestNonceExpiry verifies TTL enforcement across the clock: a nonce minted at
// t0 is accepted just inside the TTL and rejected once the consuming replica's
// clock has advanced past it. Both nonces are minted on A at the same base time;
// B consumes them at different points on its own clock.
func TestNonceExpiry(t *testing.T) {
	db := sharedNonceDB(t)
	a := newNonceServer(t, db)
	b := newNonceServer(t, db)

	base := time.Now()
	a.SetClock(func() time.Time { return base })
	within, err := a.nonces.Issue()
	if err != nil {
		t.Fatalf("Issue within: %v", err)
	}
	expired, err := a.nonces.Issue()
	if err != nil {
		t.Fatalf("Issue expired: %v", err)
	}

	// Just inside the TTL: accepted.
	b.SetClock(func() time.Time { return base.Add(nonceTTL - time.Minute) })
	if !b.nonces.Consume(within) {
		t.Fatal("a nonce within its TTL must be accepted")
	}

	// Past the TTL: rejected as expired (never reaches the consumed-set).
	b.SetClock(func() time.Time { return base.Add(nonceTTL + time.Minute) })
	if b.nonces.Consume(expired) {
		t.Fatal("a nonce past its TTL must be rejected")
	}
}

// TestNonceGC verifies the background GC prunes expired consumed records and
// leaves unexpired ones in place.
func TestNonceGC(t *testing.T) {
	db := sharedNonceDB(t)
	s := newNonceServer(t, db)

	base := time.Now()
	s.SetClock(func() time.Time { return base })
	nonce, err := s.nonces.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !s.nonces.Consume(nonce) {
		t.Fatalf("Consume: expected fresh")
	}

	// GC at issue time collects nothing (the record expires at base+TTL).
	if n, err := s.nonces.gc(); err != nil || n != 0 {
		t.Fatalf("early GC removed %d (err=%v), want 0", n, err)
	}

	// Advance past the TTL and GC collects the record.
	s.SetClock(func() time.Time { return base.Add(nonceTTL + time.Minute) })
	if n, err := s.nonces.gc(); err != nil || n != 1 {
		t.Fatalf("late GC removed %d (err=%v), want 1", n, err)
	}
}

// tamperNonceMAC decodes a nonce, flips its last byte (a MAC byte), and re-
// encodes it. Flipping at the byte level (rather than a base64 character at the
// padding boundary) deterministically breaks the HMAC while keeping the string a
// clean, decodable RawURLEncoding value.
func tamperNonceMAC(t *testing.T, nonce string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatalf("decoding nonce to tamper: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	return base64.RawURLEncoding.EncodeToString(raw)
}
