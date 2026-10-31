//go:build sqlite

// The raw PKCS#11 inspector (Task 218) end-to-end: the console's PKCS#11 view
// driven through the real route table, auth, RBAC and audit middleware against
// a real token, exactly as the browser drives it.
//
// The console holds no privileges of its own, so proving these two API flows
// against the HSM proves the view. Three things are asserted that no unit test
// can:
//
//   - the module view names the slot this deployment resolved to, and the token
//     in it is the one the CA signs on;
//   - the object dump finds the CA keys this test's own InitRoot /
//     IssueIntermediate created, with the attributes they were created with
//     (CKA_SENSITIVE true, CKA_EXTRACTABLE false) — i.e. the inspector sees the
//     PKI's own keys as the PKI believes them to be;
//   - no private key material crosses the HTTP boundary, checked over the
//     serialised response body rather than over Go structs.
package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// pkcs11Inspection is the response shape of both endpoints, decoded here rather
// than imported so the test fails if the JSON contract changes.
type pkcs11Inspection struct {
	Provider      string                  `json:"provider"`
	Tokens        []keyprovider.TokenView `json:"tokens"`
	AllAttributes bool                    `json:"all_attributes"`
}

func TestConsolePKCS11Inspector(t *testing.T) {
	env := setupConsole(t)

	// --- the module view ---------------------------------------------------
	status, body := env.req(t, "GET", "/api/pkcs11/module", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/pkcs11/module = %d: %s", status, body)
	}
	var mv pkcs11Inspection
	if err := json.Unmarshal(body, &mv); err != nil {
		t.Fatalf("decoding the module view: %v", err)
	}
	if mv.Provider != string(keyprovider.ProviderPKCS11) {
		t.Errorf("provider = %q, want %q", mv.Provider, keyprovider.ProviderPKCS11)
	}
	if len(mv.Tokens) != 1 {
		t.Fatalf("got %d token view(s) for a single-token deployment", len(mv.Tokens))
	}
	mod := mv.Tokens[0].Module
	if mod == nil {
		t.Fatalf("no module view: %+v", mv.Tokens[0])
	}
	if mod.LibraryDescription == "" || mod.CryptokiVersion == "" {
		t.Errorf("C_GetInfo came back empty: %+v", mod)
	}
	var selected *pki.SlotInfo
	for i := range mod.Slots {
		if mod.Slots[i].Selected {
			selected = &mod.Slots[i]
		}
	}
	if selected == nil || selected.Token == nil {
		t.Fatalf("no slot is marked as this deployment's token (%d slot(s) reported)", len(mod.Slots))
	}
	if selected.Token.SerialNumber == "" {
		t.Error("the selected token reports no serial number")
	}
	var signing bool
	for _, m := range selected.Mechanisms {
		if m.Name == "CKM_ECDSA" {
			signing = true
		}
	}
	if !signing {
		t.Error("the mechanism list does not offer CKM_ECDSA, which this CA signs with")
	}

	// ?mechanisms=0 drops the bulk of the payload.
	status, body = env.req(t, "GET", "/api/pkcs11/module?mechanisms=0", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/pkcs11/module?mechanisms=0 = %d: %s", status, body)
	}
	var lean pkcs11Inspection
	if err := json.Unmarshal(body, &lean); err != nil {
		t.Fatalf("decoding the lean module view: %v", err)
	}
	for _, s := range lean.Tokens[0].Module.Slots {
		if len(s.Mechanisms) != 0 {
			t.Errorf("slot %d still carries %d mechanism(s) with mechanisms=0", s.SlotID, len(s.Mechanisms))
		}
	}
	if len(body) >= len(bodyOfModuleView(t, env)) {
		t.Error("mechanisms=0 did not shrink the payload")
	}

	// --- the object dump ---------------------------------------------------
	status, body = env.req(t, "GET", "/api/pkcs11/objects?max_objects=2000", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/pkcs11/objects = %d: %s", status, body)
	}
	var ov pkcs11Inspection
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("decoding the object dump: %v", err)
	}
	set := ov.Tokens[0].Objects
	if set == nil || len(set.Objects) == 0 {
		t.Fatalf("no objects enumerated: %+v", ov.Tokens[0])
	}
	if set.Counts["CKO_PRIVATE_KEY"] == 0 {
		t.Errorf("class counts %v hold no private key", set.Counts)
	}

	// The intermediate CA's own key, as the token describes it. setupConsole
	// created it through the key provider, so the inspector must see it with
	// the attributes a CA key is required to have.
	status, caBody := env.req(t, "GET", "/api/keys", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/keys = %d: %s", status, caBody)
	}
	var cas []struct {
		ID        string `json:"id"`
		Label     string `json:"label"`
		PKCS11URI string `json:"pkcs11_uri"`
	}
	if err := json.Unmarshal(caBody, &cas); err != nil {
		t.Fatalf("decoding the CA list: %v", err)
	}
	var wantLabel string
	for _, c := range cas {
		if c.ID == env.interID {
			wantLabel = pki.ExtractKeyLabel(c.PKCS11URI)
			if wantLabel == "" {
				wantLabel = c.Label
			}
		}
	}
	if wantLabel == "" {
		t.Fatalf("could not resolve the intermediate CA's key label from %d CA record(s)", len(cas))
	}

	var found *pki.Object
	for i := range set.Objects {
		o := &set.Objects[i]
		if o.ClassName == "CKO_PRIVATE_KEY" && o.Label == wantLabel {
			found = o
		}
	}
	if found == nil {
		t.Fatalf("the inspection did not find the intermediate CA's private key %q among %d object(s)",
			wantLabel, len(set.Objects))
	}
	attrs := map[string]pki.ObjectAttribute{}
	for _, a := range found.Attributes {
		attrs[a.Name] = a
	}
	for name, want := range map[string]string{
		"CKA_SENSITIVE":   "true",
		"CKA_EXTRACTABLE": "false",
		"CKA_SIGN":        "true",
		"CKA_TOKEN":       "true",
	} {
		if got := attrs[name]; got.Status != pki.AttrStatusPresent || got.Value != want {
			t.Errorf("the CA key's %s = %q (status %q), want %q", name, got.Value, got.Status, want)
		}
	}
	if got := attrs["CKA_KEY_TYPE"].Value; !strings.HasPrefix(got, "CKK_EC") {
		t.Errorf("CKA_KEY_TYPE = %q, want CKK_EC for the P-256 CA key", got)
	}

	// --- no key material crosses the boundary ------------------------------
	// Checked over the serialised body: every attribute that could carry key
	// material must arrive as a withheld row with no bytes at all.
	withheld := 0
	for _, o := range set.Objects {
		if o.ClassName != "CKO_PRIVATE_KEY" && o.ClassName != "CKO_SECRET_KEY" {
			continue
		}
		for _, a := range o.Attributes {
			if a.Status != pki.AttrStatusWithheld {
				continue
			}
			withheld++
			if a.Raw != "" || a.Value != "" || a.Length != 0 {
				t.Errorf("%s on object %s crossed the API with data (len=%d)", a.Name, o.HandleHex, a.Length)
			}
		}
	}
	if withheld == 0 {
		t.Error("no withheld attribute rows were returned at all; the policy is untested")
	}
	for _, forbidden := range []string{"CKA_PRIVATE_EXPONENT\",\"kind\":\"biginteger\",\"status\":\"present\""} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("the response body reports a private-key attribute as present: %s", forbidden)
		}
	}

	// --- ?all=1 widens the catalogue ---------------------------------------
	status, allBody := env.req(t, "GET", "/api/pkcs11/objects?all=1&max_objects=3", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/pkcs11/objects?all=1 = %d: %s", status, allBody)
	}
	var all pkcs11Inspection
	if err := json.Unmarshal(allBody, &all); err != nil {
		t.Fatalf("decoding the whole-catalogue dump: %v", err)
	}
	if !all.AllAttributes {
		t.Error("the response does not echo all_attributes")
	}
	if len(all.Tokens[0].Objects.Objects) != 3 || !all.Tokens[0].Objects.Truncated {
		t.Errorf("max_objects=3 returned %d object(s), truncated=%v",
			len(all.Tokens[0].Objects.Objects), all.Tokens[0].Objects.Truncated)
	}
	var unsupported int
	for _, a := range all.Tokens[0].Objects.Objects[0].Attributes {
		if a.Status == pki.AttrStatusUnavailable {
			unsupported++
		}
	}
	if unsupported == 0 {
		t.Error("the whole-catalogue dump reported no refused attribute")
	}

	// --- the dump is audited ------------------------------------------------
	status, events := env.req(t, "GET", "/api/events?action=hsm.inspect&limit=10", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/events = %d: %s", status, events)
	}
	if !strings.Contains(string(events), "hsm.inspect") {
		t.Errorf("no hsm.inspect event was recorded for the object dumps: %s", events)
	}
	if !strings.Contains(string(events), "object(s)") {
		t.Errorf("the hsm.inspect event detail does not report what was read: %s", events)
	}
}

// bodyOfModuleView re-fetches the full module view, for the payload-size
// comparison above.
func bodyOfModuleView(t *testing.T, env *consoleEnv) []byte {
	t.Helper()
	status, body := env.req(t, "GET", "/api/pkcs11/module", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/pkcs11/module = %d: %s", status, body)
	}
	return body
}
