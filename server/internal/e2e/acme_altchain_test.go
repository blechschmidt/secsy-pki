//go:build sqlite

// This file exercises RFC 8555 §7.4.2 alternate certificate chains end-to-end
// against the HSM-backed CA (SoftHSM in CI). It reuses the setupACME harness and
// adds a second, HSM-backed root that cross-signs the ACME issuing CA's key
// (Task 47) — the Let's-Encrypt-style two-root fixture — so the same leaf can be
// downloaded on two differently-rooted trust paths.
//
// The golang.org/x/crypto/acme client used by the other ACME e2e tests exposes
// neither the certificate response's Link headers nor the alternate URLs, so this
// test drives a minimal raw-JWS ACME client (the same shape a chain-selecting
// client such as certbot's --preferred-chain uses).
package e2e

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestACMEAlternateChainsHSM proves that a standard ACME client can select an
// HSM-cross-signed alternate root over the wire: the primary certificate response
// advertises the alternate via Link;rel="alternate", and the alternate URL serves
// the same leaf on a chain that validates to the second HSM-backed root and not
// the first.
func TestACMEAlternateChainsHSM(t *testing.T) {
	env := setupACME(t)
	ctx := context.Background()

	// --- Two-root cross-sign fixture: a second HSM-backed root certifies the ACME
	// issuing CA's key, yielding one differently-rooted alternate trust path. ---
	mgr := ca.NewManager(env.db, hsmProvider(t))
	secondRoot, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "acme-alt-root2"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy ACME Alternate Root CA", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot second root: %v", err)
	}
	if _, err := mgr.CrossSign(ctx, ca.CrossSignSpec{
		IssuerCAID:  secondRoot.ID, // second root signs...
		SubjectCAID: env.caID,      // ...the ACME issuing CA's key
	}); err != nil {
		t.Fatalf("CrossSign issuing CA under second root: %v", err)
	}

	// --- Drive a full HSM-signed order with the raw-JWS client. ---
	rc := newRawACME(t, env)
	rc.register()
	domain := "alt.hsm.acme.example.test"
	ord, orderURL := rc.newOrder(domain)
	rc.solveHTTP01(ord)
	rc.waitStatus(orderURL, "ready")

	finalized := rc.finalize(ord.Finalize, domain)
	if finalized.Certificate == "" {
		t.Fatalf("finalized order carries no certificate URL")
	}

	// --- Primary download: HSM-signed, rooted at the FIRST root, and advertising
	// exactly one alternate chain. ---
	presp, primary := rc.postAsGet(finalized.Certificate)
	if presp.StatusCode != http.StatusOK {
		t.Fatalf("primary download status = %d: %s", presp.StatusCode, primary)
	}
	if ct := presp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("primary Content-Type = %q, want application/pem-certificate-chain", ct)
	}
	alts := rawAlternateLinks(presp.Header.Values("Link"))
	if len(alts) != 1 {
		t.Fatalf("primary advertised %d alternate Link(s), want 1: %v", len(alts), presp.Header.Values("Link"))
	}
	primaryLeaf := verifyChainAt(t, primary, env.roots, "primary")

	// --- Alternate download: same leaf, rooted at the SECOND root. ---
	aresp, alt := rc.postAsGet(alts[0])
	if aresp.StatusCode != http.StatusOK {
		t.Fatalf("alternate download status = %d: %s", aresp.StatusCode, alt)
	}
	if ct := aresp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("alternate Content-Type = %q, want application/pem-certificate-chain", ct)
	}
	secondRootPool := x509.NewCertPool()
	secondRootPool.AddCert(mustParse(t, secondRoot.Certificate))
	altLeaf := verifyChainAt(t, alt, secondRootPool, "alternate")

	if !altLeaf.Equal(primaryLeaf) {
		t.Errorf("alternate chain serves a different leaf than the primary")
	}
	// Differently rooted: the alternate must not chain to the first root, nor the
	// primary to the second.
	if err := verifyChainErr(t, alt, env.roots); err == nil {
		t.Errorf("alternate chain unexpectedly validated to the first root; not differently rooted")
	}
	if err := verifyChainErr(t, primary, secondRootPool); err == nil {
		t.Errorf("primary chain unexpectedly validated to the second root")
	}
}

// --- minimal raw-JWS ACME client ------------------------------------------

type rawACME struct {
	t   *testing.T
	env *acmeTestEnv
	key *ecdsa.PrivateKey
	dir struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
	}
	kid string
}

type rawACMEOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

func newRawACME(t *testing.T, env *acmeTestEnv) *rawACME {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	rc := &rawACME{t: t, env: env, key: key}
	resp, err := http.Get(env.dirURL)
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(&rc.dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	return rc
}

// Nonce implements jose.NonceSource.
func (rc *rawACME) Nonce() (string, error) {
	resp, err := http.Get(rc.dir.NewNonce)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", fmt.Errorf("new-nonce returned no Replay-Nonce")
	}
	return n, nil
}

// post signs and sends a JWS. embedJWK selects newAccount (jwk) vs kid auth; a
// nil payload is a POST-as-GET (RFC 8555 §6.3).
func (rc *rawACME) post(url string, payload []byte, embedJWK bool) (*http.Response, []byte) {
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
	serialized := jws.FullSerialize()
	// go-jose omits an empty payload; POST-as-GET requires a present "payload":"".
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(serialized), &m); err != nil {
		rc.t.Fatalf("re-decode JWS: %v", err)
	}
	if _, ok := m["payload"]; !ok {
		m["payload"] = json.RawMessage(`""`)
		fixed, _ := json.Marshal(m)
		serialized = string(fixed)
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(serialized))
	if err != nil {
		rc.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		rc.t.Fatalf("POST %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

// postAsGet issues an authenticated POST-as-GET.
func (rc *rawACME) postAsGet(url string) (*http.Response, []byte) {
	return rc.post(url, nil, false)
}

func (rc *rawACME) register() {
	rc.t.Helper()
	resp, body := rc.post(rc.dir.NewAccount, []byte(`{"termsOfServiceAgreed":true}`), true)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		rc.t.Fatalf("newAccount status %d: %s", resp.StatusCode, body)
	}
	rc.kid = resp.Header.Get("Location")
	if rc.kid == "" {
		rc.t.Fatalf("newAccount missing Location (account URL)")
	}
}

func (rc *rawACME) newOrder(domain string) (rawACMEOrder, string) {
	rc.t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"identifiers": []map[string]string{{"type": "dns", "value": domain}},
	})
	resp, body := rc.post(rc.dir.NewOrder, payload, false)
	if resp.StatusCode != http.StatusCreated {
		rc.t.Fatalf("newOrder status %d: %s", resp.StatusCode, body)
	}
	var ord rawACMEOrder
	if err := json.Unmarshal(body, &ord); err != nil {
		rc.t.Fatalf("decode order: %v (%s)", err, body)
	}
	return ord, resp.Header.Get("Location")
}

// solveHTTP01 satisfies every authorization of an order via http-01.
func (rc *rawACME) solveHTTP01(ord rawACMEOrder) {
	rc.t.Helper()
	tp := rc.thumbprint()
	for _, au := range ord.Authorizations {
		_, ab := rc.postAsGet(au)
		var az struct {
			Challenges []struct {
				Type  string `json:"type"`
				URL   string `json:"url"`
				Token string `json:"token"`
			} `json:"challenges"`
		}
		if err := json.Unmarshal(ab, &az); err != nil {
			rc.t.Fatalf("decode authz: %v (%s)", err, ab)
		}
		var chURL, token string
		for _, ch := range az.Challenges {
			if ch.Type == "http-01" {
				chURL, token = ch.URL, ch.Token
			}
		}
		if chURL == "" {
			rc.t.Fatalf("no http-01 challenge offered: %s", ab)
		}
		rc.env.httpMu.Lock()
		rc.env.httpResp[token] = token + "." + tp
		rc.env.httpMu.Unlock()
		if r, b := rc.post(chURL, []byte(`{}`), false); r.StatusCode != http.StatusOK {
			rc.t.Fatalf("accept challenge status %d: %s", r.StatusCode, b)
		}
		rc.waitStatus(au, "valid")
	}
}

func (rc *rawACME) finalize(finalizeURL, domain string) rawACMEOrder {
	rc.t.Helper()
	csr := base64.RawURLEncoding.EncodeToString(rawCSR(rc.t, domain))
	resp, body := rc.post(finalizeURL, []byte(`{"csr":"`+csr+`"}`), false)
	if resp.StatusCode != http.StatusOK {
		rc.t.Fatalf("finalize status %d: %s", resp.StatusCode, body)
	}
	var ord rawACMEOrder
	if err := json.Unmarshal(body, &ord); err != nil {
		rc.t.Fatalf("decode finalized order: %v (%s)", err, body)
	}
	return ord
}

func (rc *rawACME) waitStatus(url, want string) {
	rc.t.Helper()
	for i := 0; i < 80; i++ {
		_, body := rc.postAsGet(url)
		var obj struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(body, &obj)
		if obj.Status == want {
			return
		}
		if obj.Status == "invalid" {
			rc.t.Fatalf("%s became invalid awaiting %q: %s", url, want, body)
		}
		time.Sleep(25 * time.Millisecond)
	}
	rc.t.Fatalf("%s did not reach %q in time", url, want)
}

func (rc *rawACME) thumbprint() string {
	rc.t.Helper()
	tp, err := (&jose.JSONWebKey{Key: rc.key.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		rc.t.Fatalf("thumbprint: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// --- helpers ---------------------------------------------------------------

func rawCSR(t *testing.T, domain string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

// rawAlternateLinks returns the target URLs of Link;rel="alternate" values.
func rawAlternateLinks(values []string) []string {
	var out []string
	for _, v := range values {
		if !strings.Contains(v, `rel="alternate"`) && !strings.Contains(v, "rel=alternate") {
			continue
		}
		i := strings.IndexByte(v, '<')
		j := strings.IndexByte(v, '>')
		if i >= 0 && j > i {
			out = append(out, v[i+1:j])
		}
	}
	return out
}

// verifyChainAt verifies a served chain's leaf against roots using the chain's
// own intermediates, failing on error and returning the leaf.
func verifyChainAt(t *testing.T, chainPEM []byte, roots *x509.CertPool, label string) *x509.Certificate {
	t.Helper()
	if err := verifyChainErr(t, chainPEM, roots); err != nil {
		t.Fatalf("%s chain failed to verify: %v", label, err)
	}
	leaf, _ := splitLeafChain(t, chainPEM)
	return leaf
}

func verifyChainErr(t *testing.T, chainPEM []byte, roots *x509.CertPool) error {
	t.Helper()
	leaf, inters := splitLeafChain(t, chainPEM)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func splitLeafChain(t *testing.T, chainPEM []byte) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	var leaf *x509.Certificate
	inters := x509.NewCertPool()
	rest := chainPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse cert in chain: %v", err)
		}
		if leaf == nil {
			leaf = cert
			continue
		}
		inters.AddCert(cert)
	}
	if leaf == nil {
		t.Fatalf("chain has no certificate: %s", chainPEM)
	}
	return leaf, inters
}
