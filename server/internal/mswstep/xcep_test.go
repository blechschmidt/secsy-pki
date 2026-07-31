//go:build sqlite

package mswstep

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestGetPolicies_Shape verifies the MS-XCEP GetPolicies response has the
// expected SOAP/WS-Addressing framing and advertises the issuing CA, the CES URL,
// and the policyID, echoing the request MessageID.
func TestGetPolicies_Shape(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", nil)
	secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopeTenant, "issuer")

	const msgID = "urn:uuid:11111111-1111-1111-1111-111111111111"
	status, body := postSOAP(t, env.ts.URL+"/mswstep/policy", getPoliciesEnvelope(msgID), tokenAuth(secret))
	if status != 200 {
		t.Fatalf("status = %d, want 200\n%s", status, body)
	}

	raw := string(body)
	// Correct default namespace and response action on the wire.
	if !strings.Contains(raw, `xmlns="`+nsEnrollPolicy+`"`) {
		t.Errorf("response is missing the enrollmentpolicy namespace\n%s", raw)
	}
	if !strings.Contains(raw, actionGetPoliciesResponse) {
		t.Errorf("response is missing the GetPoliciesResponse action")
	}

	gpr := parseGPR(t, body)
	if gpr.Header.RelatesTo != msgID {
		t.Errorf("RelatesTo = %q, want %q", gpr.Header.RelatesTo, msgID)
	}
	if gpr.Body.Resp.Response.PolicyID == "" {
		t.Error("policyID is empty")
	}
	if gpr.Body.Resp.Response.NextUpdateHours != 8 {
		t.Errorf("nextUpdateHours = %d, want 8", gpr.Body.Resp.Response.NextUpdateHours)
	}
	if len(gpr.Body.Resp.CAs.CA) != 1 {
		t.Fatalf("advertised %d CAs, want 1", len(gpr.Body.Resp.CAs.CA))
	}
	caEntry := gpr.Body.Resp.CAs.CA[0]

	// The advertised CA certificate must be the issuing CA's DER.
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(caEntry.Certificate), ""))
	if err != nil {
		t.Fatalf("decoding advertised CA cert: %v", err)
	}
	if string(der) != string(env.rootCert.Raw) {
		t.Error("advertised CA certificate does not match the issuing CA")
	}
	// The CES enrollment URL must be advertised with certificate client-auth.
	if len(caEntry.URIs) != 1 || caEntry.URIs[0].URI != "https://ces.example.test/mswstep/enroll" {
		t.Fatalf("CES URI not advertised correctly: %+v", caEntry.URIs)
	}
	if caEntry.URIs[0].ClientAuthentication != clientAuthUsername {
		// Only the token authenticator is configured in this env, so username/password.
		t.Errorf("clientAuthentication = %d, want %d (username)", caEntry.URIs[0].ClientAuthentication, clientAuthUsername)
	}
}

// TestGetPolicies_ProfileMapping verifies each configured template is advertised
// as a policy with its own template OID (group 9) and the validity taken from the
// mapped profile.
func TestGetPolicies_ProfileMapping(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", nil)
	secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopeTenant, "issuer")

	_, body := postSOAP(t, env.ts.URL+"/mswstep/policy", getPoliciesEnvelope("urn:uuid:abc"), tokenAuth(secret))
	gpr := parseGPR(t, body)

	if len(gpr.Body.Resp.Response.Policies) != 2 {
		t.Fatalf("advertised %d policies, want 2", len(gpr.Body.Resp.Response.Policies))
	}
	if len(gpr.Body.Resp.OIDs.OID) != 2 {
		t.Fatalf("advertised %d oIDs, want 2", len(gpr.Body.Resp.OIDs.OID))
	}

	names := map[string]bool{}
	for _, p := range gpr.Body.Resp.Response.Policies {
		names[p.Attributes.CommonName] = true
		if p.Attributes.PolicySchema != 2 {
			t.Errorf("template %q policySchema = %d, want 2", p.Attributes.CommonName, p.Attributes.PolicySchema)
		}
		if !p.Attributes.Permission.Enroll || !p.Attributes.Permission.AutoEnroll {
			t.Errorf("template %q permissions = %+v, want enroll+autoenroll", p.Attributes.CommonName, p.Attributes.Permission)
		}
		if p.Attributes.Validity.ValidityPeriodSeconds <= 0 {
			t.Errorf("template %q has no validity period", p.Attributes.CommonName)
		}
		if p.Attributes.PrivateKey.MinimalKeyLength != 2048 {
			t.Errorf("template %q minimalKeyLength = %d, want 2048", p.Attributes.CommonName, p.Attributes.PrivateKey.MinimalKeyLength)
		}
		// Every policy must point at the single advertised CA.
		if len(p.CAReferences) != 1 || p.CAReferences[0] != 0 {
			t.Errorf("template %q cAReferences = %v, want [0]", p.Attributes.CommonName, p.CAReferences)
		}
	}
	if !names["SecsyUser"] || !names["SecsyWebServer"] {
		t.Errorf("advertised template names = %v, want SecsyUser + SecsyWebServer", names)
	}

	// The template OIDs must be distinct and carry the certificate-template group.
	oids := map[string]bool{}
	for _, o := range gpr.Body.Resp.OIDs.OID {
		if o.Group != oidGroupTemplate {
			t.Errorf("oID %q group = %d, want %d", o.Value, o.Group, oidGroupTemplate)
		}
		if oids[o.Value] {
			t.Errorf("duplicate template OID %q", o.Value)
		}
		oids[o.Value] = true
	}
}

// TestGetPolicies_ClientAuthCert verifies the advertised client-auth value
// reflects the configured mechanisms (certificate takes precedence over token).
func TestGetPolicies_ClientAuthCert(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", func(c *Config) {
		c.AllowClientCertIssuedByCA = true
	})
	secret := env.mintToken(t, models.DefaultTenantID, models.TokenScopeTenant, "issuer")

	_, body := postSOAP(t, env.ts.URL+"/mswstep/policy", getPoliciesEnvelope("urn:uuid:def"), tokenAuth(secret))
	gpr := parseGPR(t, body)
	if len(gpr.Body.Resp.CAs.CA) != 1 || len(gpr.Body.Resp.CAs.CA[0].URIs) != 1 {
		t.Fatalf("unexpected CA/URI shape: %+v", gpr.Body.Resp.CAs)
	}
	if got := gpr.Body.Resp.CAs.CA[0].URIs[0].ClientAuthentication; got != clientAuthCert {
		t.Errorf("clientAuthentication = %d, want %d (certificate)", got, clientAuthCert)
	}
}

// TestGetPolicies_Unauthenticated verifies the policy endpoint fails closed
// without a credential and with an invalid token.
func TestGetPolicies_Unauthenticated(t *testing.T) {
	env := newTestEnv(t, softwareProvider(t), "", nil)

	status, _ := postSOAP(t, env.ts.URL+"/mswstep/policy", getPoliciesEnvelope("urn:uuid:1"), "")
	if status != 401 {
		t.Errorf("no-credential status = %d, want 401", status)
	}
	status, _ = postSOAP(t, env.ts.URL+"/mswstep/policy", getPoliciesEnvelope("urn:uuid:2"), tokenAuth("secsy_pat_bogus"))
	if status != 401 {
		t.Errorf("bad-token status = %d, want 401", status)
	}
}
