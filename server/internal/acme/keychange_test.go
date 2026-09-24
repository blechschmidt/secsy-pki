//go:build sqlite

package acme

// Coverage for account key rollover (RFC 8555 §7.3.5) — the classic ACME
// account-takeover surface. The outer JWS proves possession of the *current*
// account key; the inner JWS must independently prove possession of the *new*
// key and name both the account and the key being replaced. Every one of those
// bindings is asserted here, and every rejection also asserts the account key was
// left untouched (so a rejected rollover cannot half-apply).
//
// The inner JWS is built byte by byte from crypto/ecdsa + encoding/json +
// base64url rather than through the server's own helpers, so a test can present
// a protected header whose embedded "jwk" does not match the signing key — the
// exact shape an attacker would use to rebind an account to a key they do not
// control.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// ---- independent JWS / JWK builders ---------------------------------------

// ecPubJWK renders a P-256 public key as a JWK (RFC 7518 §6.2.1), hand-built from
// the curve coordinates.
func ecPubJWK(t *testing.T, pub *ecdsa.PublicKey) json.RawMessage {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	b, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y),
	})
	if err != nil {
		t.Fatalf("marshal EC JWK: %v", err)
	}
	return b
}

// ecPrivJWK renders a P-256 *private* key as a JWK, so a test can check the
// server refuses an inner "jwk" that leaks (or smuggles) private material.
func ecPrivJWK(t *testing.T, key *ecdsa.PrivateKey) json.RawMessage {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	d := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	key.D.FillBytes(d)
	b, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y), "d": b64(d),
	})
	if err != nil {
		t.Fatalf("marshal EC private JWK: %v", err)
	}
	return b
}

// flatJWS builds a flattened-JSON JWS (RFC 7515 §7.2.2) with an explicit
// protected header and an ES256 signature produced by signKey. Because the header
// is supplied verbatim, signKey and the header's embedded "jwk" need not agree —
// which is what makes the "signed by the wrong key" cases expressible.
func flatJWS(t *testing.T, hdr map[string]any, payload []byte, signKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}
	prot := b64(hb)
	pl := b64(payload)
	sig := ""
	if signKey != nil {
		digest := sha256.Sum256([]byte(prot + "." + pl))
		r, s, err := ecdsa.Sign(rand.Reader, signKey, digest[:])
		if err != nil {
			t.Fatalf("ecdsa sign: %v", err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		sig = b64(raw)
	}
	out, err := json.Marshal(map[string]string{"protected": prot, "payload": pl, "signature": sig})
	if err != nil {
		t.Fatalf("marshal JWS: %v", err)
	}
	return out
}

// keyChangeURL fetches the directory's advertised key-change resource.
func keyChangeURL(t *testing.T, dirURL string) string {
	t.Helper()
	resp, err := http.Get(dirURL)
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var dir struct {
		KeyChange  string `json:"keyChange"`
		RevokeCert string `json:"revokeCert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	if dir.KeyChange == "" {
		t.Fatal("directory does not advertise a keyChange resource")
	}
	return dir.KeyChange
}

// innerKeyChange assembles the RFC 8555 §7.3.5 inner JWS: protected header
// {alg, jwk: newKeyJWK, url}, payload {account, oldKey}, signed by signKey.
func innerKeyChange(t *testing.T, alg string, newKeyJWK json.RawMessage, url, account string,
	oldKeyJWK json.RawMessage, signKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	hdr := map[string]any{"alg": alg, "url": url}
	if newKeyJWK != nil {
		hdr["jwk"] = newKeyJWK
	}
	payload, err := json.Marshal(map[string]any{"account": account, "oldKey": oldKeyJWK})
	if err != nil {
		t.Fatalf("marshal inner payload: %v", err)
	}
	return flatJWS(t, hdr, payload, signKey)
}

// storedKeyThumbprint returns the account's currently persisted key thumbprint,
// the ground truth a rejected rollover must not have changed.
func storedKeyThumbprint(t *testing.T, env *testEnv, acctURL string) string {
	t.Helper()
	acct, err := env.db.GetACMEAccount(idFromURL(acctURL))
	if err != nil || acct == nil {
		t.Fatalf("GetACMEAccount(%q): %v", acctURL, err)
	}
	return acct.Thumbprint
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return k
}

// ---- happy path -----------------------------------------------------------

// TestACME_KeyChange_Success asserts a well-formed rollover really replaces the
// account key: the stored JWK and thumbprint become the new key's, the new key
// authenticates the account afterwards, and — the property that matters — the OLD
// key no longer does.
func TestACME_KeyChange_Success(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()
	kcURL := keyChangeURL(t, env.dirURL)

	oldKey := rc.key
	oldTP := storedKeyThumbprint(t, env, rc.kid)
	newKey := newP256(t)

	inner := innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
		ecPubJWK(t, &oldKey.PublicKey), newKey)
	resp, body := rc.post(kcURL, inner, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("key-change status = %d, want 200: %s", resp.StatusCode, body)
	}

	// The persisted key is the new one.
	newTP := storedKeyThumbprint(t, env, rc.kid)
	if newTP == oldTP {
		t.Fatal("stored thumbprint unchanged after a successful key-change")
	}
	wantTP, err := jwkThumbprint(&jose.JSONWebKey{Key: newKey.Public()})
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if newTP != wantTP {
		t.Errorf("stored thumbprint = %q, want the new key's %q", newTP, wantTP)
	}
	// And the stored JWK really is the new key, not merely a matching thumbprint.
	acct, _ := env.db.GetACMEAccount(idFromURL(rc.kid))
	var stored jose.JSONWebKey
	if err := json.Unmarshal([]byte(acct.JWK), &stored); err != nil {
		t.Fatalf("stored JWK is not a JWK: %v (%s)", err, acct.JWK)
	}
	storedPub, ok := stored.Key.(*ecdsa.PublicKey)
	if !ok || !storedPub.Equal(&newKey.PublicKey) {
		t.Errorf("stored JWK is not the new public key: %#v", stored.Key)
	}

	// The new key authenticates the account.
	rc.key = newKey
	if r, b := rc.post(rc.kid, nil, false); r.StatusCode != http.StatusOK {
		t.Fatalf("POST-as-GET with the new key = %d, want 200: %s", r.StatusCode, b)
	}

	// The old key does NOT. This is the whole point of a rollover: after a key
	// compromise the retired key must be dead.
	rc.key = oldKey
	r, b := rc.post(rc.kid, nil, false)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST-as-GET with the retired key = %d, want 401: %s", r.StatusCode, b)
	}
	var prob Problem
	_ = json.Unmarshal(b, &prob)
	if prob.Type != probUnauthorized {
		t.Errorf("retired-key problem type = %q, want %q: %s", prob.Type, probUnauthorized, b)
	}
}

// ---- rejections -----------------------------------------------------------

// TestACME_KeyChange_Rejections walks every malformed or unauthorized rollover
// and asserts (a) the request is refused and (b) the account key is unchanged and
// the original key still authenticates. A pass on any of these would let a client
// rebind an account — its own or, worse, someone else's key — without proving
// possession of the new key.
func TestACME_KeyChange_Rejections(t *testing.T) {
	env := newTestEnv(t)
	kcURL := keyChangeURL(t, env.dirURL)

	cases := []struct {
		name string
		// build returns the outer payload (the inner JWS bytes).
		build      func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte
		wantStatus int
		wantType   string
	}{
		{
			// The inner JWS advertises the new key but is signed by the current
			// account key: no proof of possession of the new key at all.
			name: "inner-signed-by-old-key",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), rc.key)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			// Signed by a third key that is neither the old nor the advertised new
			// key — a forged binding to a victim's public key.
			name: "inner-signed-by-a-third-key",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), newP256(t))
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-signature-corrupted",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				inner := innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), newKey)
				var m map[string]string
				if err := json.Unmarshal(inner, &m); err != nil {
					t.Fatalf("re-decode inner JWS: %v", err)
				}
				// Flip the first signature byte.
				sig := []byte(m["signature"])
				if sig[0] == 'A' {
					sig[0] = 'B'
				} else {
					sig[0] = 'A'
				}
				m["signature"] = string(sig)
				out, _ := json.Marshal(m)
				return out
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-no-signature",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), nil)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			// The inner payload names a DIFFERENT account than the outer JWS
			// authenticated: a rollover aimed at somebody else's account.
			name: "inner-account-is-another-account",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				other := newRawClient(t, env.dirURL)
				other.register()
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, other.kid,
					ecPubJWK(t, &rc.key.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-account-missing",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, "",
					ecPubJWK(t, &rc.key.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			// oldKey is some unrelated key rather than the account's current key.
			name: "inner-oldkey-is-an-unrelated-key",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				stranger := newP256(t)
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &stranger.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-oldkey-is-the-new-key",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &newKey.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-oldkey-missing",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid, nil, newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-oldkey-not-a-jwk",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					json.RawMessage(`"not-a-jwk"`), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			// The inner url binds the inner signature to this endpoint; a mismatch
			// means the inner JWS was minted for somewhere else.
			name: "inner-url-mismatch",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL+"-elsewhere",
					rc.kid, ecPubJWK(t, &rc.key.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-no-jwk",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", nil, kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-jwk-is-private",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "ES256", ecPrivJWK(t, newKey), kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-alg-none",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "none", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), nil)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			// A symmetric alg has no key pair behind it, so it can never prove
			// possession of the new account key.
			name: "inner-alg-hs256",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return innerKeyChange(t, "HS256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
					ecPubJWK(t, &rc.key.PublicKey), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "outer-payload-is-not-a-jws",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return []byte(`{"account":"x","oldKey":{}}`)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "outer-payload-empty",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return nil
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "inner-payload-is-not-json",
			build: func(t *testing.T, rc *rawClient, newKey *ecdsa.PrivateKey) []byte {
				return flatJWS(t, map[string]any{
					"alg": "ES256", "url": kcURL, "jwk": ecPubJWK(t, &newKey.PublicKey),
				}, []byte("not json at all"), newKey)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRawClient(t, env.dirURL)
			rc.register()
			beforeTP := storedKeyThumbprint(t, env, rc.kid)
			newKey := newP256(t)

			resp, body := rc.post(kcURL, tc.build(t, rc, newKey), false)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("key-change status = %d, want %d: %s", resp.StatusCode, tc.wantStatus, body)
			}
			var prob Problem
			if err := json.Unmarshal(body, &prob); err != nil {
				t.Fatalf("response is not a problem document: %v (%s)", err, body)
			}
			if prob.Type != tc.wantType {
				t.Errorf("problem type = %q, want %q: %s", prob.Type, tc.wantType, body)
			}

			// The account key must be untouched, and the original key must still work.
			if after := storedKeyThumbprint(t, env, rc.kid); after != beforeTP {
				t.Fatalf("account key changed on a rejected rollover: %q -> %q", beforeTP, after)
			}
			if r, b := rc.post(rc.kid, nil, false); r.StatusCode != http.StatusOK {
				t.Errorf("original key stopped authenticating after a rejected rollover: %d %s", r.StatusCode, b)
			}
			// And the would-be new key must not have been bound to anything.
			tp, err := jwkThumbprint(&jose.JSONWebKey{Key: newKey.Public()})
			if err != nil {
				t.Fatalf("thumbprint: %v", err)
			}
			if acct, _ := env.db.GetACMEAccountByThumbprint(tp); acct != nil {
				t.Errorf("the rejected new key is bound to account %s", acct.ID)
			}
		})
	}
}

// TestACME_KeyChange_NewKeyAlreadyInUse asserts a rollover onto a key that
// already identifies another account is refused with 409 + a Location pointing at
// the conflicting account (RFC 8555 §7.3.5), and that neither account moves. If
// this passed, two accounts would share one key and the thumbprint lookup that
// authenticates every request would become ambiguous.
func TestACME_KeyChange_NewKeyAlreadyInUse(t *testing.T) {
	env := newTestEnv(t)
	kcURL := keyChangeURL(t, env.dirURL)

	victim := newRawClient(t, env.dirURL)
	victim.register()
	attacker := newRawClient(t, env.dirURL)
	attacker.register()

	victimTPBefore := storedKeyThumbprint(t, env, victim.kid)
	attackerTPBefore := storedKeyThumbprint(t, env, attacker.kid)

	// The attacker cannot sign with the victim's private key, so the inner JWS is
	// signed by the victim key only in a test that *has* it; here we model the
	// realistic case where the operator of the second account legitimately holds
	// the key (e.g. a key reused across two registrations) and still must be
	// refused.
	inner := innerKeyChange(t, "ES256", ecPubJWK(t, &victim.key.PublicKey), kcURL, attacker.kid,
		ecPubJWK(t, &attacker.key.PublicKey), victim.key)
	resp, body := attacker.post(kcURL, inner, false)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("key-change onto an in-use key = %d, want 409: %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != victim.kid {
		t.Errorf("Location = %q, want the conflicting account %q", loc, victim.kid)
	}
	if got := storedKeyThumbprint(t, env, attacker.kid); got != attackerTPBefore {
		t.Errorf("attacker account key changed: %q -> %q", attackerTPBefore, got)
	}
	if got := storedKeyThumbprint(t, env, victim.kid); got != victimTPBefore {
		t.Errorf("victim account key changed: %q -> %q", victimTPBefore, got)
	}
	// The victim still owns their key and their account.
	if r, b := victim.post(victim.kid, nil, false); r.StatusCode != http.StatusOK {
		t.Errorf("victim lost access to their account: %d %s", r.StatusCode, b)
	}
}

// TestACME_KeyChange_ReplayRejected asserts a captured rollover cannot be
// replayed. Re-POSTing the identical outer JWS is refused by the anti-replay
// nonce, and re-attempting the rollover with a freshly-signed outer JWS fails
// because the retired key no longer authenticates the account.
func TestACME_KeyChange_ReplayRejected(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()
	kcURL := keyChangeURL(t, env.dirURL)

	oldKey := rc.key
	newKey := newP256(t)
	inner := innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
		ecPubJWK(t, &oldKey.PublicKey), newKey)

	// Capture the exact outer JWS so it can be replayed byte for byte.
	outer := rc.serializeJWS(kcURL, inner, false)
	if resp, body := sendJWS(t, kcURL, outer); resp.StatusCode != http.StatusOK {
		t.Fatalf("key-change status = %d, want 200: %s", resp.StatusCode, body)
	}
	afterTP := storedKeyThumbprint(t, env, rc.kid)

	// Byte-identical replay: the nonce is spent.
	resp, body := sendJWS(t, kcURL, outer)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed key-change = %d, want 400: %s", resp.StatusCode, body)
	}
	var prob Problem
	_ = json.Unmarshal(body, &prob)
	if prob.Type != probBadNonce {
		t.Errorf("replay problem type = %q, want %q: %s", prob.Type, probBadNonce, body)
	}

	// Re-signing the same rollover with the retired key fails at authentication.
	rc.key = oldKey
	resp2, body2 := rc.post(kcURL, inner, false)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("re-rollover with the retired key = %d, want 401: %s", resp2.StatusCode, body2)
	}
	if got := storedKeyThumbprint(t, env, rc.kid); got != afterTP {
		t.Errorf("account key moved on a replayed rollover: %q -> %q", afterTP, got)
	}
}

// TestACME_KeyChange_RequiresAccountAuth asserts the outer JWS must be
// account-authenticated ("kid"): an embedded-jwk outer JWS — which proves nothing
// about account ownership — cannot drive a rollover.
func TestACME_KeyChange_RequiresAccountAuth(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()
	kcURL := keyChangeURL(t, env.dirURL)

	newKey := newP256(t)
	inner := innerKeyChange(t, "ES256", ecPubJWK(t, &newKey.PublicKey), kcURL, rc.kid,
		ecPubJWK(t, &rc.key.PublicKey), newKey)

	beforeTP := storedKeyThumbprint(t, env, rc.kid)
	resp, body := rc.post(kcURL, inner, true) // embedJWK instead of kid
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("key-change with an embedded jwk = %d, want 400: %s", resp.StatusCode, body)
	}
	if got := storedKeyThumbprint(t, env, rc.kid); got != beforeTP {
		t.Errorf("account key changed on an unauthenticated rollover: %q -> %q", beforeTP, got)
	}
}

// ---- raw-JWS plumbing shared with the replay test -------------------------

// serializeJWS signs a request exactly as rawClient.post does but returns the
// serialized JWS instead of sending it, so a test can transmit the same bytes
// more than once.
func (rc *rawClient) serializeJWS(url string, payload []byte, embedJWK bool) string {
	rc.t.Helper()
	opts := &jose.SignerOptions{NonceSource: rc}
	opts.EmbedJWK = embedJWK
	opts.WithHeader("url", url)
	if !embedJWK {
		opts.WithHeader("kid", rc.kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: rc.key}, opts)
	if err != nil {
		rc.t.Fatalf("new signer: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		rc.t.Fatalf("sign: %v", err)
	}
	return jws.FullSerialize()
}

// sendJWS POSTs a pre-serialized JWS body.
func sendJWS(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, b
}
