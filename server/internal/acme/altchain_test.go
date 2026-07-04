//go:build sqlite

package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestACME_AlternateChains covers RFC 8555 §7.4.2 alternate certificate chains
// end-to-end. A second, independent root cross-signs the ACME issuing CA's key
// (Task 47), so the same leaf can be served on two differently-rooted trust
// paths — the Let's-Encrypt-style scenario where a client picks whichever root a
// relying party trusts. The test drives a full order with the raw-JWS client,
// then asserts:
//
//   - the primary certificate response advertises the alternate via a
//     Link;rel="alternate" header (and still carries the rel="index" pointer),
//     with the correct application/pem-certificate-chain content type;
//   - the alternate URL returns the SAME leaf on a chain rooted at the SECOND
//     root, and NOT the original one; and
//   - the primary chain still roots at the ORIGINAL root, unchanged.
func TestACME_AlternateChains(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// --- Cross-sign fixture: an independent second root certifies the ACME
	// issuing CA's key, producing one differently-rooted alternate trust path. ---
	secondRoot, err := env.srv.caMgr.InitRoot(ctx, ca.RootSpec{
		Label:    "acme-alt-second-root",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "ACME Alternate Second Root"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot second root: %v", err)
	}
	if _, err := env.srv.caMgr.CrossSign(ctx, ca.CrossSignSpec{
		IssuerCAID:  secondRoot.ID, // second root signs...
		SubjectCAID: env.caID,      // ...the ACME issuing intermediate's key
	}); err != nil {
		t.Fatalf("CrossSign issuing CA under second root: %v", err)
	}

	// --- Drive a full order to a certificate via the raw-JWS client. ---
	rc := newRawClient(t, env.dirURL)
	rc.register()
	domain := "altchain.example.test"
	resp, body, ord, orderURL := rc.newOrder("", domain)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", resp.StatusCode, body)
	}
	tp := rc.thumbprint()
	for _, au := range ord.Authorizations {
		_, ab := rc.post(au, nil, false) // POST-as-GET
		var az rawAuthz
		if err := json.Unmarshal(ab, &az); err != nil {
			t.Fatalf("decode authz: %v (%s)", err, ab)
		}
		var chURL, token string
		for _, ch := range az.Challenges {
			if ch.Type == "http-01" {
				chURL, token = ch.URL, ch.Token
			}
		}
		if chURL == "" {
			t.Fatalf("no http-01 challenge offered: %s", ab)
		}
		env.httpMu.Lock()
		env.httpResp[token] = keyAuthorization(token, tp)
		env.httpMu.Unlock()
		if r, b := rc.post(chURL, []byte(`{}`), false); r.StatusCode != http.StatusOK {
			t.Fatalf("accept challenge: status %d: %s", r.StatusCode, b)
		}
		rc.waitStatus(au, "valid")
	}
	rc.waitStatus(orderURL, "ready")
	csr := base64.RawURLEncoding.EncodeToString(csrFor(t, domain))
	fresp, fbody := rc.post(ord.Finalize, []byte(`{"csr":"`+csr+`"}`), false)
	if fresp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d, want 200: %s", fresp.StatusCode, fbody)
	}
	var finalized rawOrder
	if err := json.Unmarshal(fbody, &finalized); err != nil {
		t.Fatalf("decode finalized order: %v", err)
	}
	if finalized.Certificate == "" {
		t.Fatalf("finalized order has no certificate URL: %s", fbody)
	}

	// --- Primary certificate download. ---
	presp, primaryChain := rc.post(finalized.Certificate, nil, false)
	if presp.StatusCode != http.StatusOK {
		t.Fatalf("download primary status = %d: %s", presp.StatusCode, primaryChain)
	}
	if ct := presp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("primary Content-Type = %q, want application/pem-certificate-chain", ct)
	}
	links := presp.Header.Values("Link")
	if !hasLinkRel(links, "index") {
		t.Errorf("primary response missing rel=\"index\" Link: %v", links)
	}
	altURLs := linkTargets(links, "alternate")
	if len(altURLs) != 1 {
		t.Fatalf("primary advertised %d alternate Link(s), want exactly 1 (one cross-sign): %v", len(altURLs), links)
	}

	// The primary chain must validate to the ORIGINAL root.
	primaryLeaf := verifyServedChain(t, primaryChain, env.roots, "primary")

	// --- Alternate certificate download. ---
	aresp, altChain := rc.post(altURLs[0], nil, false)
	if aresp.StatusCode != http.StatusOK {
		t.Fatalf("download alternate status = %d: %s", aresp.StatusCode, altChain)
	}
	if ct := aresp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("alternate Content-Type = %q, want application/pem-certificate-chain", ct)
	}

	secondRootPool := x509.NewCertPool()
	secondRootPool.AddCert(mustCert(t, secondRoot.Certificate))

	// The alternate chain must validate to the SECOND root...
	altLeaf := verifyServedChain(t, altChain, secondRootPool, "alternate")
	// ...serving the very same leaf on a different trust path (RFC 8555 §7.4.2)...
	if !altLeaf.Equal(primaryLeaf) {
		t.Errorf("alternate chain serves a different leaf than the primary chain")
	}
	// ...and it must be GENUINELY differently rooted: the alternate must not build
	// to the original root, nor the primary to the second root.
	if err := verifyServedChainErr(t, altChain, env.roots); err == nil {
		t.Errorf("alternate chain unexpectedly validated to the original root; it is not differently rooted")
	}
	if err := verifyServedChainErr(t, primaryChain, secondRootPool); err == nil {
		t.Errorf("primary chain unexpectedly validated to the second root")
	}
}

// TestACME_AlternateCertificate_NotFound confirms that requesting an
// out-of-range or malformed alternate index for a finalized order is rejected
// (RFC 8555: only advertised alternates exist), while the account still owns the
// order. With no cross-signs configured, no alternate index is valid.
func TestACME_AlternateCertificate_NotFound(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	domain := "no-alt.example.test"
	resp, body, ord, orderURL := rc.newOrder("", domain)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", resp.StatusCode, body)
	}
	tp := rc.thumbprint()
	for _, au := range ord.Authorizations {
		_, ab := rc.post(au, nil, false)
		var az rawAuthz
		if err := json.Unmarshal(ab, &az); err != nil {
			t.Fatalf("decode authz: %v (%s)", err, ab)
		}
		var chURL, token string
		for _, ch := range az.Challenges {
			if ch.Type == "http-01" {
				chURL, token = ch.URL, ch.Token
			}
		}
		env.httpMu.Lock()
		env.httpResp[token] = keyAuthorization(token, tp)
		env.httpMu.Unlock()
		if r, b := rc.post(chURL, []byte(`{}`), false); r.StatusCode != http.StatusOK {
			t.Fatalf("accept challenge: status %d: %s", r.StatusCode, b)
		}
		rc.waitStatus(au, "valid")
	}
	rc.waitStatus(orderURL, "ready")
	csr := base64.RawURLEncoding.EncodeToString(csrFor(t, domain))
	fresp, fbody := rc.post(ord.Finalize, []byte(`{"csr":"`+csr+`"}`), false)
	if fresp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d: %s", fresp.StatusCode, fbody)
	}

	// The primary carries no alternate links when nothing is cross-signed.
	presp, _ := rc.post(finalizedCertURL(t, fbody), nil, false)
	if got := linkTargets(presp.Header.Values("Link"), "alternate"); len(got) != 0 {
		t.Errorf("expected no alternate Links without a cross-sign, got %v", got)
	}

	// A request for alternate index 1 must be a 404-class problem.
	altURL := env.baseURL + "/acme/cert/" + orderURL[strings.LastIndex(orderURL, "/")+1:] + "/1"
	nresp, nbody := rc.post(altURL, nil, false)
	if nresp.StatusCode != http.StatusNotFound {
		t.Fatalf("alternate index 1 status = %d, want 404: %s", nresp.StatusCode, nbody)
	}
}

// finalizedCertURL extracts the certificate URL from a finalized-order body.
func finalizedCertURL(t *testing.T, body []byte) string {
	t.Helper()
	var fo rawOrder
	if err := json.Unmarshal(body, &fo); err != nil {
		t.Fatalf("decode finalized order: %v (%s)", err, body)
	}
	if fo.Certificate == "" {
		t.Fatalf("finalized order has no certificate URL: %s", body)
	}
	return fo.Certificate
}

// --- Link-header and chain helpers -----------------------------------------

// linkTargets returns the target URLs of every Link header value carrying the
// given relation type, e.g. `<url>;rel="alternate"`.
func linkTargets(values []string, rel string) []string {
	var out []string
	for _, v := range values {
		if linkRel(v) == rel {
			if u := linkTarget(v); u != "" {
				out = append(out, u)
			}
		}
	}
	return out
}

// hasLinkRel reports whether any Link header value carries the given relation.
func hasLinkRel(values []string, rel string) bool {
	for _, v := range values {
		if linkRel(v) == rel {
			return true
		}
	}
	return false
}

// linkTarget extracts the target between the first "<" and ">" of a Link value.
func linkTarget(v string) string {
	i := strings.IndexByte(v, '<')
	j := strings.IndexByte(v, '>')
	if i < 0 || j <= i {
		return ""
	}
	return v[i+1 : j]
}

// linkRel extracts the (unquoted) rel token of a Link value, tolerating both
// quoted (`rel="alternate"`) and bare (`rel=alternate`) forms.
func linkRel(v string) string {
	idx := strings.Index(v, "rel=")
	if idx < 0 {
		return ""
	}
	rel := strings.TrimSpace(v[idx+len("rel="):])
	if strings.HasPrefix(rel, "\"") {
		rel = rel[1:]
		if k := strings.IndexByte(rel, '"'); k >= 0 {
			rel = rel[:k]
		}
	} else if k := strings.IndexAny(rel, "; ,"); k >= 0 {
		rel = rel[:k]
	}
	return rel
}

// parseServedChain splits a served application/pem-certificate-chain into its
// leaf (first certificate) and the intermediates/roots that follow it.
func parseServedChain(t *testing.T, chainPEM []byte) (*x509.Certificate, *x509.CertPool) {
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
			t.Fatalf("parse certificate in served chain: %v", err)
		}
		if leaf == nil {
			leaf = cert
			continue
		}
		inters.AddCert(cert)
	}
	if leaf == nil {
		t.Fatalf("served chain contained no certificate: %s", chainPEM)
	}
	return leaf, inters
}

// verifyServedChain verifies a served chain's leaf against the given roots using
// the chain's own intermediates, failing the test on error and returning the leaf.
func verifyServedChain(t *testing.T, chainPEM []byte, roots *x509.CertPool, label string) *x509.Certificate {
	t.Helper()
	if err := verifyServedChainErr(t, chainPEM, roots); err != nil {
		t.Fatalf("%s chain failed to verify: %v", label, err)
	}
	leaf, _ := parseServedChain(t, chainPEM)
	return leaf
}

// verifyServedChainErr is verifyServedChain without the fatal, so negative cases
// (a chain that must NOT validate to a given root) can assert on the error.
func verifyServedChainErr(t *testing.T, chainPEM []byte, roots *x509.CertPool) error {
	t.Helper()
	leaf, inters := parseServedChain(t, chainPEM)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// mustCert parses the first CERTIFICATE block of a PEM string.
func mustCert(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(mustDER(t, pemStr))
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
