package acme

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"log"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

const (
	// nonceTTL bounds how long an issued anti-replay nonce remains valid.
	nonceTTL = 30 * time.Minute
	// nonceClockSkew tolerates modest clock differences between replicas so a
	// nonce minted on a replica whose clock runs slightly ahead is not rejected as
	// "future-dated" by a replica whose clock is slightly behind.
	nonceClockSkew = 5 * time.Minute

	// nonceVersion tags the wire format so it can evolve without ambiguity.
	nonceVersion = 0x01
	// nonceRandomLen is the per-nonce random component (128 bits), which makes the
	// consumed-set key unique even for two nonces minted in the same millisecond.
	nonceRandomLen = 16
	// nonceMACLen is the HMAC-SHA256 tag length, truncated to 128 bits — standard
	// and secure, and it keeps the encoded nonce short.
	nonceMACLen = 16
	// noncePayloadLen is version(1) + issuedAt-unix-millis(8) + random.
	noncePayloadLen = 1 + 8 + nonceRandomLen
	// nonceTotalLen is the full token length before base64url encoding.
	nonceTotalLen = noncePayloadLen + nonceMACLen
	// nonceMinSecretLen is the smallest acceptable signing secret (128 bits).
	nonceMinSecretLen = 16
)

// nonceBackend is the shared, durable persistence the nonce store relies on for
// cross-replica single-use enforcement: a consumed-set keyed by nonce hash. It
// is satisfied by *database.DB; the narrow interface keeps the store unit-
// testable and documents exactly what a replica-shared store must provide.
type nonceBackend interface {
	// ConsumeACMENonce records nonceHash as consumed, returning true the first
	// time it is seen (valid) and false if it was already present (replay).
	// expiresAt bounds retention for GC.
	ConsumeACMENonce(nonceHash string, expiresAt time.Time) (bool, error)
	// GCACMENonces deletes consumed-nonce records whose expiry has passed.
	GCACMENonces(now time.Time) (int64, error)
}

// nonceStore issues and validates single-use anti-replay nonces (RFC 8555 §6.5)
// correctly across replicas (Task 97).
//
// Nonces are self-authenticating: each is an HMAC over a version byte, an
// issue timestamp, and random bytes, keyed by a secret shared by every replica
// through the store. Any replica can therefore mint a nonce that any other
// replica can verify with no shared in-memory state — the flaw the previous
// per-instance map had behind a load balancer, where a nonce minted by one
// replica was rejected as badNonce by another.
//
// Single use is enforced by a shared consumed-set on the backend: the first
// Consume of a nonce inserts its hash and succeeds; a replay — on this or any
// other replica — finds the row and is rejected.
//
// The validation fast path is deliberately cheap and DB-free for every rejected
// nonce: a malformed, forged (wrong-key), or expired nonce is rejected by the
// in-process HMAC and timestamp checks before the backend is touched, so only a
// well-formed, authentic, unexpired nonce ever reaches the single consumed-set
// write. That HMAC gate also shields the backend from insert floods — a forged
// nonce never reaches it. Issuance performs no I/O at all.
type nonceStore struct {
	backend nonceBackend
	secret  []byte
	ttl     time.Duration
	now     func() time.Time
}

// newNonceStore builds a nonce store over the given shared backend and signing
// secret. All replicas that share a backend and secret form one logical store.
func newNonceStore(backend nonceBackend, secret []byte, now func() time.Time) *nonceStore {
	if now == nil {
		now = time.Now
	}
	return &nonceStore{backend: backend, secret: secret, ttl: nonceTTL, now: now}
}

// Issue mints a fresh, self-authenticating nonce and records it as valid. It
// performs no I/O: the nonce carries its own proof of authenticity and issue
// time, so no per-issue store write is needed (only the eventual Consume writes).
func (n *nonceStore) Issue() (string, error) {
	var payload [noncePayloadLen]byte
	payload[0] = nonceVersion
	binary.BigEndian.PutUint64(payload[1:9], uint64(n.now().UnixMilli()))
	if _, err := rand.Read(payload[9:]); err != nil {
		metrics.ACMENonces.Inc("error")
		return "", err
	}
	tok := make([]byte, 0, nonceTotalLen)
	tok = append(tok, payload[:]...)
	tok = append(tok, n.mac(payload[:])...)
	metrics.ACMENonces.Inc("issued")
	return base64.RawURLEncoding.EncodeToString(tok), nil
}

// Consume validates a nonce and enforces single use, reporting whether the nonce
// was authentic, unexpired, and previously unused. Every false return maps to a
// badNonce problem, which conformant clients retry with a fresh nonce.
func (n *nonceStore) Consume(nonce string) bool {
	if nonce == "" {
		metrics.ACMENonces.Inc("invalid")
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != nonceTotalLen || raw[0] != nonceVersion {
		metrics.ACMENonces.Inc("invalid")
		return false
	}
	payload := raw[:noncePayloadLen]
	gotMAC := raw[noncePayloadLen:]
	if subtle.ConstantTimeCompare(gotMAC, n.mac(payload)) != 1 {
		// Forged, or signed with a different (foreign or rotated) secret.
		metrics.ACMENonces.Inc("invalid")
		return false
	}
	issuedAt := time.UnixMilli(int64(binary.BigEndian.Uint64(payload[1:9])))
	now := n.now()
	if now.Sub(issuedAt) > n.ttl || issuedAt.After(now.Add(nonceClockSkew)) {
		metrics.ACMENonces.Inc("expired")
		return false
	}

	// Authentic and unexpired: the one durable write. The shared consumed-set is
	// what makes the nonce single-use across every replica.
	fresh, err := n.backend.ConsumeACMENonce(nonceHash(nonce), issuedAt.Add(n.ttl))
	if err != nil {
		// Fail closed: a store error rejects the nonce (the client simply retries
		// with a fresh one) rather than risk accepting a replay. A persistently
		// unreachable store fails the rest of the ACME flow anyway (accounts and
		// orders live there), so this does not mask an otherwise-working server.
		log.Printf("acme: nonce consume: backend error: %v", err)
		metrics.ACMENonces.Inc("error")
		return false
	}
	if !fresh {
		metrics.ACMENonces.Inc("replayed")
		return false
	}
	metrics.ACMENonces.Inc("valid")
	return true
}

// gc evicts expired consumed-nonce records and reports how many were removed. An
// expired nonce is rejected by Consume's timestamp check before the consumed-set
// is consulted, so pruning its record is safe and merely bounds table growth.
func (n *nonceStore) gc() (int64, error) {
	return n.backend.GCACMENonces(n.now())
}

// mac computes the truncated HMAC-SHA256 tag over a nonce payload.
func (n *nonceStore) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, n.secret)
	h.Write(payload)
	return h.Sum(nil)[:nonceMACLen]
}

// nonceHash is the consumed-set key: the SHA-256 of the whole nonce token. The
// nonce is not secret, but hashing yields a fixed-length key and avoids storing
// the raw token verbatim.
func nonceHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}
