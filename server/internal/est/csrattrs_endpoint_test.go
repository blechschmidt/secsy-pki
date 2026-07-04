//go:build sqlite

// End-to-end tests for the EST /csrattrs endpoint (RFC 7030 §4.5) against the
// software key provider, reusing the newTestEST harness in server_test.go.
package est

import (
	"encoding/asn1"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// getCSRAttrs performs a GET /csrattrs and returns the status, content type, and
// decoded DER (base64 with EST's CRLF line wrapping stripped).
func getCSRAttrs(t *testing.T, url string, basicUser, basicPass string) (int, string, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", url+"/.well-known/est/csrattrs", nil)
	if err != nil {
		t.Fatal(err)
	}
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, resp.Header.Get("Content-Type"), nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	if err != nil {
		t.Fatalf("base64 decode csrattrs: %v (body %q)", err, body)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), der
}

// collectOIDs walks a DER blob and returns the set of every OBJECT IDENTIFIER it
// contains (at any depth), as dotted strings.
func collectOIDs(t *testing.T, der []byte) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	var walk func(cryptobyte.String)
	walk = func(s cryptobyte.String) {
		for !s.Empty() {
			if s.PeekASN1Tag(cryptobyte_asn1.OBJECT_IDENTIFIER) {
				var oid asn1.ObjectIdentifier
				if !s.ReadASN1ObjectIdentifier(&oid) {
					return
				}
				found[oid.String()] = true
				continue
			}
			var child cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !s.ReadAnyASN1(&child, &tag) {
				return
			}
			if tag == cryptobyte_asn1.SEQUENCE || tag == cryptobyte_asn1.SET {
				walk(child)
			}
		}
	}
	walk(cryptobyte.String(der))
	return found
}

func TestEST_CSRAttrs_DefaultProfile(t *testing.T) {
	// Default profile is "client": an EC key-type hint and clientAuth EKU.
	_, ts, _ := newTestEST(t, Config{}, false)

	code, ct, der := getCSRAttrs(t, ts.URL, "", "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(ct, "application/csrattrs") {
		t.Fatalf("content-type = %q, want application/csrattrs", ct)
	}
	oids := collectOIDs(t, der)
	if !oids["1.2.840.10045.2.1"] {
		t.Error("csrattrs should advertise id-ecPublicKey for the client profile")
	}
	if !oids["1.3.6.1.5.5.7.3.2"] {
		t.Error("csrattrs should advertise the clientAuth EKU")
	}
	if oids["1.2.840.113549.1.1.1"] {
		t.Error("client profile must not advertise rsaEncryption")
	}
}

func TestEST_CSRAttrs_UserProfileTailoring(t *testing.T) {
	// A credential bound to the RSA-oriented "server" profile; anonymous requests
	// still see the default "client" profile.
	_, ts, _ := newTestEST(t, Config{
		Users: map[string]User{"srv": {Password: "pw", Profile: "server"}},
	}, false)

	_, _, der := getCSRAttrs(t, ts.URL, "srv", "pw")
	oids := collectOIDs(t, der)
	if !oids["1.2.840.113549.1.1.1"] {
		t.Error("server profile (keyEncipherment) should advertise rsaEncryption")
	}
	if !oids["1.3.6.1.5.5.7.3.1"] {
		t.Error("server profile should advertise the serverAuth EKU")
	}

	// Anonymous -> default client profile (EC + clientAuth).
	_, _, anonDER := getCSRAttrs(t, ts.URL, "", "")
	anon := collectOIDs(t, anonDER)
	if !anon["1.2.840.10045.2.1"] || anon["1.2.840.113549.1.1.1"] {
		t.Error("anonymous csrattrs should reflect the default client profile (EC, not RSA)")
	}
}

func TestEST_CSRAttrs_Override(t *testing.T) {
	// An explicit override for the client profile advertises a bare
	// challengePassword and nothing derived.
	_, ts, _ := newTestEST(t, Config{
		CSRAttrs: map[string][]CSRAttr{
			"client": {{OID: "1.2.840.113549.1.9.7"}},
		},
	}, false)

	_, _, der := getCSRAttrs(t, ts.URL, "", "")
	oids := collectOIDs(t, der)
	if !oids["1.2.840.113549.1.9.7"] {
		t.Error("override should advertise challengePassword")
	}
	if oids["1.2.840.10045.2.1"] {
		t.Error("override should replace the derived attributes (no id-ecPublicKey)")
	}
}

func TestEST_CSRAttrs_EmptyOverrideIs204(t *testing.T) {
	_, ts, _ := newTestEST(t, Config{
		CSRAttrs: map[string][]CSRAttr{"client": {}},
	}, false)
	code, _, _ := getCSRAttrs(t, ts.URL, "", "")
	if code != http.StatusNoContent {
		t.Fatalf("empty override status = %d, want 204", code)
	}
}
