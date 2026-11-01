package celpolicy

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// sampleSigningInput is a complete fact set for an SSH certificate signature,
// the richest of the three operations.
func sampleSigningInput() SigningInput {
	after := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	return SigningInput{
		Signing: SigningRequest{
			Operation:   OpSignSSHCert,
			Source:      SourceREST,
			Tenant:      "acme",
			RequestedBy: "ops@example.com",
			Purpose:     "CHG-10482",
			Key: SigningKeyInfo{
				Name:      "ssh-user-ca",
				Label:     "ssh-user-ca",
				Algorithm: "Ed25519",
				Type:      "ed25519",
				Provider:  "pkcs11",
				Tenant:    "acme",
			},
			Payload: PayloadInfo{Present: true, Size: 512, DigestAlgorithm: "SHA-256"},
			SSH: SSHCertInfo{
				Present:              true,
				CertType:             "user",
				KeyID:                "ops@example.com",
				Principals:           []string{"deploy", "ops"},
				PrincipalCount:       2,
				Extensions:           []string{"permit-pty"},
				CriticalOptions:      []string{"force-command"},
				CriticalOptionValues: map[string]string{"force-command": "/usr/local/bin/session-wrapper"},
				Profile:              "ssh-user-default",
				Serial:               "17",
				ValidAfter:           after,
				ValidBefore:          after.Add(8 * time.Hour),
				Validity:             8 * time.Hour,
				ValidityDays:         0,
				PublicKey: SSHKeyInfo{
					Type:           "sk-ssh-ed25519@openssh.com",
					Fingerprint:    "SHA256:abc",
					HardwareBacked: true,
				},
				CA: CAInfo{ID: "ca-1", Label: "ssh-user-ca", Tenant: "acme"},
			},
		},
		JWT:       map[string]interface{}{"sub": "ops@example.com", "iss": "https://idp.example.com"},
		URL:       RequestURL{Method: "POST", Path: "/api/ssh/cas/ca-1/sign", Present: true},
		Body:      map[string]interface{}{"reason": "CHG-10482"},
		Principal: Principal{Subject: "ops@example.com", Roles: []string{"issuer"}, Authenticated: true},
		Now:       after,
	}
}

func evalSigning(t *testing.T, expr string, in SigningInput) Decision {
	t.Helper()
	rule := Rule{Kind: KindSigning, Name: "under-test", Expression: expr, Enabled: true}
	if err := rule.Validate(); err != nil {
		t.Fatalf("rule %q does not validate: %v", expr, err)
	}
	return NewEngine().EvaluateSigning([]Rule{rule}, in)
}

func TestSigningVocabularyReachesEveryFact(t *testing.T) {
	in := sampleSigningInput()
	// One expression per declared fact group, so a renamed field is a test
	// failure rather than a rule that silently reads a zero value.
	cases := []struct {
		expr string
		want bool
	}{
		{`signing.operation == "ssh-certificate"`, true},
		{`signing.source == "rest"`, true},
		{`signing.tenant == "acme"`, true},
		{`signing.requested_by == "ops@example.com"`, true},
		{`signing.purpose.startsWith("CHG-")`, true},
		{`signing.key.name == "ssh-user-ca" && signing.key.provider == "pkcs11"`, true},
		{`signing.key.algorithm == "Ed25519" && signing.key.type == "ed25519"`, true},
		{`signing.payload.present && signing.payload.size == 512 && !signing.payload.prehashed`, true},
		{`signing.payload.digest_algorithm == "SHA-256"`, true},
		{`signing.ssh.present && signing.ssh.cert_type == "user"`, true},
		{`signing.ssh.key_id == "ops@example.com"`, true},
		{`signing.ssh.principals.exists(p, p == "deploy") && signing.ssh.principal_count == 2`, true},
		{`"permit-pty" in signing.ssh.extensions`, true},
		{`"force-command" in signing.ssh.critical_options`, true},
		{`signing.ssh.critical_option_values["force-command"].endsWith("session-wrapper")`, true},
		{`signing.ssh.profile == "ssh-user-default" && signing.ssh.serial == "17"`, true},
		{`signing.ssh.validity <= duration("12h") && signing.ssh.validity_days == 0`, true},
		{`signing.ssh.valid_before > signing.ssh.valid_after`, true},
		{`signing.ssh.public_key.hardware_backed && signing.ssh.public_key.type.startsWith("sk-")`, true},
		{`signing.ssh.ca.label == "ssh-user-ca" && signing.ssh.ca.tenant == "acme"`, true},
		{`signing.artifact.present`, false},
		{`signing.data.present`, false},
		// The shared fact sets are the same ones a certificate rule reads.
		{`has(jwt.iss) && string(jwt.iss).startsWith("https://idp.")`, true},
		{`url.present && url.path.endsWith("/sign")`, true},
		{`path == "/api/ssh/cas/ca-1/sign"`, true},
		{`has(body.reason) && string(body.reason) == "CHG-10482"`, true},
		{`principal.authenticated && "issuer" in principal.roles`, true},
		{`now.getHours() == 9`, true},
	}
	for _, tc := range cases {
		d := evalSigning(t, tc.expr, in)
		// A require-effect rule denies when the expression is false.
		if got := d.Allowed; got != tc.want {
			t.Errorf("%s: allowed=%v, want %v (violations: %v)", tc.expr, got, tc.want, d.Violations)
		}
	}
}

func TestSigningRuleCannotReachCertificateVocabulary(t *testing.T) {
	// The two kinds are separate environments precisely so this is a compile
	// error: in a merged one it would evaluate against an empty certificate
	// request and read as a working rule that never fires.
	if err := ValidateFor(KindSigning, `request.dns_names.size() == 0`); err == nil {
		t.Fatal("a signing rule referencing request.* must not compile")
	}
	if err := ValidateFor(KindCertificate, `signing.key.name == "x"`); err == nil {
		t.Fatal("a certificate rule referencing signing.* must not compile")
	}
	// A misspelled signing field is a load error too, with a column in it.
	err := ValidateFor(KindSigning, `signing.ssh.principal == ["root"]`)
	if err == nil {
		t.Fatal("a misspelled signing field must not compile")
	}
	if !strings.Contains(err.Error(), "principal") {
		t.Errorf("the compile error should name the offending field: %v", err)
	}
}

func TestSigningExamplesCompileAndEvaluate(t *testing.T) {
	in := sampleSigningInput()
	for _, ex := range SigningExamples() {
		rule := Rule{
			Kind: KindSigning, Name: "example", Expression: ex.Expression,
			Message: ex.Message, Effect: ex.Effect, Enabled: true,
		}
		if err := rule.Validate(); err != nil {
			t.Errorf("example %q does not compile: %v", ex.Title, err)
			continue
		}
		// Evaluating must not error — a rule that cannot be evaluated becomes a
		// violation naming itself, which is how this test catches one.
		d := NewEngine().EvaluateSigning([]Rule{rule}, in)
		for _, v := range d.Violations {
			if v.Error != "" {
				t.Errorf("example %q failed at evaluation: %s", ex.Title, v.Error)
			}
		}
	}
}

func TestSigningExamplesRefuseWhatTheyDescribe(t *testing.T) {
	// A sample of the examples against facts they are meant to refuse: an
	// example that cannot refuse anything is decoration.
	in := sampleSigningInput()
	in.Signing.SSH.Principals = []string{"root"}
	rule := Rule{
		Kind: KindSigning, Name: "no-root", Enabled: true, Effect: EffectDeny,
		Expression: `signing.ssh.present && signing.ssh.principals.exists(p, p.lowerAscii() in ["root", "admin", "ec2-user"])`,
		Message:    "no root",
	}
	d := NewEngine().EvaluateSigning([]Rule{rule}, in)
	if d.Allowed {
		t.Error("a certificate naming root must be refused by the deny-effect example")
	}
	if len(d.Violations) != 1 || d.Violations[0].Message != "no root" {
		t.Errorf("unexpected violations: %+v", d.Violations)
	}
}

func TestSigningSelectors(t *testing.T) {
	in := sampleSigningInput()
	deny := Rule{Kind: KindSigning, Name: "deny-all", Expression: `false`, Enabled: true}

	cases := []struct {
		name    string
		mutate  func(r *Rule)
		applies bool
	}{
		{"no selectors", func(r *Rule) {}, true},
		{"operation matches", func(r *Rule) { r.Operations = []string{OpSignSSHCert} }, true},
		{"operation does not", func(r *Rule) { r.Operations = []string{OpSignArtifact} }, false},
		{"key by name", func(r *Rule) { r.Keys = []string{"ssh-user-ca"} }, true},
		{"key by glob", func(r *Rule) { r.Keys = []string{"ssh-*"} }, true},
		{"key mismatch", func(r *Rule) { r.Keys = []string{"release-signing"} }, false},
		{"ssh profile", func(r *Rule) { r.Profiles = []string{"ssh-user-*"} }, true},
		{"ssh profile mismatch", func(r *Rule) { r.Profiles = []string{"ssh-host-default"} }, false},
		{"ca by id", func(r *Rule) { r.CAs = []string{"ca-1"} }, true},
		{"ca mismatch", func(r *Rule) { r.CAs = []string{"other"} }, false},
		{"tenant", func(r *Rule) { r.TenantID = "acme" }, true},
		{"other tenant", func(r *Rule) { r.TenantID = "other" }, false},
	}
	for _, tc := range cases {
		rule := deny
		tc.mutate(&rule)
		d := NewEngine().EvaluateSigning([]Rule{rule}, in)
		applied := !d.Allowed
		if applied != tc.applies {
			t.Errorf("%s: applied=%v, want %v", tc.name, applied, tc.applies)
		}
		if tc.applies && d.Evaluated != 1 {
			t.Errorf("%s: evaluated=%d, want 1", tc.name, d.Evaluated)
		}
		if !tc.applies && d.Skipped != 1 {
			t.Errorf("%s: skipped=%d, want 1", tc.name, d.Skipped)
		}
	}
}

func TestKindsDoNotCrossOver(t *testing.T) {
	certRule := Rule{Name: "cert", Expression: `false`, Enabled: true} // kind defaults to certificate
	signRule := Rule{Kind: KindSigning, Name: "sign", Expression: `false`, Enabled: true}
	engine := NewEngine()

	// The signing gate must not consult a certificate rule…
	d := engine.EvaluateSigning([]Rule{certRule, signRule}, sampleSigningInput())
	if d.Evaluated != 1 || d.Skipped != 1 {
		t.Errorf("signing evaluation considered the wrong rules: evaluated=%d skipped=%d", d.Evaluated, d.Skipped)
	}
	// …and the issuance gate must not consult a signing rule, which would fail
	// to compile in its environment and refuse every certificate.
	cd := engine.Evaluate([]Rule{certRule, signRule}, Input{Request: CertRequest{Profile: "server"}})
	if cd.Evaluated != 1 || cd.Skipped != 1 {
		t.Errorf("certificate evaluation considered the wrong rules: evaluated=%d skipped=%d", cd.Evaluated, cd.Skipped)
	}
	if len(cd.Violations) != 1 || cd.Violations[0].Rule != "cert" {
		t.Errorf("unexpected certificate violations: %+v", cd.Violations)
	}
}

func TestSigningRuleFailsClosed(t *testing.T) {
	in := sampleSigningInput()
	// A runtime error: a map key that is not present.
	broken := Rule{
		Kind: KindSigning, Name: "broken", Enabled: true,
		Expression: `signing.ssh.critical_option_values["source-address"] == "10.0.0.0/8"`,
	}
	d := NewEngine().EvaluateSigning([]Rule{broken}, in)
	if d.Allowed {
		t.Fatal("a signing rule that errors at evaluation must refuse the signature")
	}
	if len(d.Violations) != 1 || d.Violations[0].Error == "" {
		t.Fatalf("the violation should carry the rule error: %+v", d.Violations)
	}

	broken.FailOpen = true
	if d := NewEngine().EvaluateSigning([]Rule{broken}, in); !d.Allowed {
		t.Error("a fail-open rule that errors must permit the signature")
	}
}

func TestSigningMonitorModeDoesNotBlock(t *testing.T) {
	rule := Rule{
		Kind: KindSigning, Name: "watching", Enabled: true, Mode: ModeMonitor,
		Expression: `false`, Message: "would refuse",
	}
	d := NewEngine().EvaluateSigning([]Rule{rule}, sampleSigningInput())
	if !d.Allowed {
		t.Error("a monitor-mode rule must not block")
	}
	if len(d.Violations) != 1 || d.Violations[0].Mode != ModeMonitor {
		t.Errorf("the monitor finding must still be reported: %+v", d.Violations)
	}
	if len(d.Enforced()) != 0 {
		t.Error("a monitor finding is not an enforced violation")
	}
}

func TestSigningDenyErrorNamesTheOperation(t *testing.T) {
	rules := []Rule{
		{Kind: KindSigning, Name: "a", Expression: `false`, Message: "first reason", Enabled: true},
		{Kind: KindSigning, Name: "b", Expression: `false`, Message: "second reason", Enabled: true},
	}
	in := sampleSigningInput()
	_, err := NewEngine().CheckSigning(rules, in)
	if err == nil {
		t.Fatal("two denying rules must produce an error")
	}
	msg := err.Error()
	for _, want := range []string{"SSH certificate request denied", "first reason", "second reason"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q should contain %q", msg, want)
		}
	}
	// One reason reads as the reason itself, with the rule named.
	_, err = NewEngine().CheckSigning(rules[:1], in)
	if got := err.Error(); got != `first reason (policy rule "a")` {
		t.Errorf("single-reason message = %q", got)
	}

	in.Signing.Operation = OpSignArtifact
	in.Signing.SSH = SSHCertInfo{}
	in.Signing.Artifact = ArtifactInfo{Present: true, Signer: "release"}
	_, err = NewEngine().CheckSigning(rules, in)
	if err == nil || !strings.Contains(err.Error(), "artifact signature request denied") {
		t.Errorf("an artifact refusal should name itself: %v", err)
	}
}

func TestSigningRuleValidation(t *testing.T) {
	cases := []struct {
		name    string
		rule    Rule
		wantErr string
	}{
		{
			name:    "selectors on a certificate rule",
			rule:    Rule{Name: "x", Expression: `true`, Keys: []string{"k"}},
			wantErr: "signing rule",
		},
		{
			name:    "unknown operation",
			rule:    Rule{Kind: KindSigning, Name: "x", Expression: `true`, Operations: []string{"timestamp"}},
			wantErr: "not a signing operation",
		},
		{
			name: "known operation",
			rule: Rule{Kind: KindSigning, Name: "x", Expression: `true`, Operations: []string{OpSignData}},
		},
		{
			name: "operation glob",
			rule: Rule{Kind: KindSigning, Name: "x", Expression: `true`, Operations: []string{"ssh-*"}},
		},
		{
			name:    "unknown kind",
			rule:    Rule{Kind: "sign", Name: "x", Expression: `true`},
			wantErr: `kind "sign"`,
		},
	}
	for _, tc := range cases {
		err := tc.rule.Validate()
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s: expected an error containing %q", tc.name, tc.wantErr)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s: error %q should contain %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestSigningReferenceIsBuiltFromTheEnvironment(t *testing.T) {
	ref, err := BuildReferenceFor(KindSigning)
	if err != nil {
		t.Fatalf("BuildReferenceFor: %v", err)
	}
	if ref.Kind != KindSigning {
		t.Errorf("kind = %q", ref.Kind)
	}
	if len(ref.Operations) != len(SigningOperations()) {
		t.Errorf("operations = %v", ref.Operations)
	}
	var signing *VarDoc
	for i := range ref.Variables {
		if ref.Variables[i].Name == VarSigning {
			signing = &ref.Variables[i]
		}
		if ref.Variables[i].Name == VarRequest {
			t.Error("the signing reference must not advertise the certificate request")
		}
	}
	if signing == nil {
		t.Fatal("the signing reference must document the signing variable")
	}
	// Spot-check that the fields come from the Go struct, including the nested
	// objects' CEL type names.
	want := map[string]string{
		"operation": "string",
		"ssh":       "celpolicy.SSHCertInfo",
		"artifact":  "celpolicy.ArtifactInfo",
		"data":      "celpolicy.DataInfo",
		"jwt_svid":  "celpolicy.JWTSVIDInfo",
		"key":       "celpolicy.SigningKeyInfo",
		"payload":   "celpolicy.PayloadInfo",
	}
	got := map[string]string{}
	for _, f := range signing.Fields {
		got[f.Name] = f.Type
	}
	for name, typ := range want {
		if got[name] != typ {
			t.Errorf("signing.%s has type %q, want %q", name, got[name], typ)
		}
	}
	if len(ref.Examples) == 0 {
		t.Error("the signing reference must carry worked examples")
	}
	// The certificate reference must still be the certificate one.
	certRef, err := BuildReferenceFor(KindCertificate)
	if err != nil {
		t.Fatalf("BuildReferenceFor(certificate): %v", err)
	}
	for _, v := range certRef.Variables {
		if v.Name == VarSigning {
			t.Error("the certificate reference must not advertise the signing facts")
		}
	}
}

func TestHashName(t *testing.T) {
	cases := map[crypto.Hash]string{
		0:             "",
		crypto.SHA256: "SHA-256",
		crypto.SHA384: "SHA-384",
		crypto.SHA512: "SHA-512",
		crypto.SHA1:   "SHA-1",
	}
	for h, want := range cases {
		if got := HashName(h); got != want {
			t.Errorf("HashName(%v) = %q, want %q", h, got, want)
		}
	}
}

func TestSigningInputNormalizesAbsentFacts(t *testing.T) {
	// A fact set built by a CLI path: no HTTP request, no token.
	in := (*Facts)(nil).SigningInput(SigningRequest{Key: SigningKeyInfo{Name: "k"}})
	act := in.Activation()
	if got := act[VarSigning].(SigningRequest).Operation; got != OpSignData {
		t.Errorf("operation defaulted to %q", got)
	}
	if got := act[VarSigning].(SigningRequest).Source; got != SourceUnknown {
		t.Errorf("source defaulted to %q", got)
	}
	for _, v := range []string{VarJWT, VarBody} {
		if act[v] == nil {
			t.Errorf("%s must be an empty map, not nil", v)
		}
	}
	// Every declared variable must be present, or evaluation errors — which on
	// this path means a refused signature.
	env, err := SigningEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range env.Vars() {
		if _, ok := act[v.Name()]; !ok {
			t.Errorf("activation is missing declared variable %q", v.Name())
		}
	}
	// The unauthenticated reading is what makes a token rule refuse a CLI call.
	d := evalSigning(t, `principal.authenticated`, in)
	if d.Allowed {
		t.Error("an unauthenticated fact set must not satisfy a principal.authenticated rule")
	}
}

func TestSigningFactsFromContextCarryHTTPFacts(t *testing.T) {
	f := NewFacts()
	f.SetURL(RequestURL{Method: "POST", Path: "/api/sign", Present: true})
	f.SetJWT(map[string]interface{}{"repository": "example/product"})
	f.SetBody(map[string]interface{}{"signer": "release-signing"})
	f.SetPrincipal(Principal{Subject: "ci@example.com", Authenticated: true})

	in := f.SigningInput(SigningRequest{Operation: OpSignArtifact})
	if in.Signing.Source != SourceREST {
		t.Errorf("source = %q, want rest (derived from the URL)", in.Signing.Source)
	}
	if in.Signing.RequestedBy != "ci@example.com" {
		t.Errorf("requested_by = %q", in.Signing.RequestedBy)
	}
	d := evalSigning(t, `has(jwt.repository) && string(jwt.repository) == "example/product" && has(body.signer) && url.path == "/api/sign"`, in)
	if !d.Allowed {
		t.Errorf("the HTTP facts should be visible to a signing rule: %+v", d.Violations)
	}

	// An explicit source wins over the derived one.
	f.SetSource(SourceCLI)
	if got := f.SigningInput(SigningRequest{}).Signing.Source; got != SourceCLI {
		t.Errorf("explicit source = %q", got)
	}
}

func TestFactSetAcceptsDurationStrings(t *testing.T) {
	// The audience that writes a fact set by hand — the console's dry-run box, a
	// -facts file, a curl body — writes "8h", not 28800000000000. Both must
	// decode, and the echo must come back in the readable form so it can be
	// pasted into the next run.
	cases := []struct {
		name string
		body string
		want time.Duration
	}{
		{"duration string", `{"signing":{"ssh":{"validity":"8h"}}}`, 8 * time.Hour},
		{"nanoseconds", `{"signing":{"ssh":{"validity":28800000000000}}}`, 8 * time.Hour},
		{"empty string", `{"signing":{"ssh":{"validity":""}}}`, 0},
		{"absent", `{"signing":{"ssh":{"cert_type":"user"}}}`, 0},
		{"null", `{"signing":{"ssh":{"validity":null}}}`, 0},
	}
	for _, tc := range cases {
		var in SigningInput
		if err := json.Unmarshal([]byte(tc.body), &in); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if in.Signing.SSH.Validity != tc.want {
			t.Errorf("%s: validity = %s, want %s", tc.name, in.Signing.SSH.Validity, tc.want)
		}
	}

	// A bad duration is an error naming what to write instead, not a silent zero
	// — a lifetime rule against a silently-zero validity would report that
	// nothing is refused.
	var in SigningInput
	err := json.Unmarshal([]byte(`{"signing":{"ssh":{"validity":"8 hours"}}}`), &in)
	if err == nil {
		t.Fatal("a malformed duration must not decode")
	}
	if !strings.Contains(err.Error(), "90m, 8h or 30s") {
		t.Errorf("the error should say how to write one: %v", err)
	}

	// The other duration-carrying facts behave the same way.
	if err := json.Unmarshal([]byte(`{"signing":{"jwt_svid":{"ttl":"15m"}}}`), &in); err != nil {
		t.Fatalf("jwt_svid.ttl: %v", err)
	}
	if in.Signing.JWTSVID.TTL != 15*time.Minute {
		t.Errorf("ttl = %s", in.Signing.JWTSVID.TTL)
	}
	var certIn Input
	if err := json.Unmarshal([]byte(`{"request":{"validity":"90m"}}`), &certIn); err != nil {
		t.Fatalf("request.validity: %v", err)
	}
	if certIn.Request.Validity != 90*time.Minute {
		t.Errorf("request validity = %s", certIn.Request.Validity)
	}

	// Round-trip: the echo is readable and decodes back to the same window.
	out, err := json.Marshal(SigningInput{Signing: SigningRequest{
		SSH:     SSHCertInfo{Present: true, Validity: 8 * time.Hour},
		JWTSVID: JWTSVIDInfo{TTL: 15 * time.Minute},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"validity":"8h0m0s"`) || !strings.Contains(string(out), `"ttl":"15m0s"`) {
		t.Errorf("the echo should carry readable durations: %s", out)
	}
	var back SigningInput
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if back.Signing.SSH.Validity != 8*time.Hour || back.Signing.JWTSVID.TTL != 15*time.Minute {
		t.Errorf("round-trip lost the durations: %+v", back.Signing)
	}

	// Every other field still decodes through the custom unmarshaller.
	if err := json.Unmarshal([]byte(`{"signing":{"ssh":{"cert_type":"host","principals":["a","b"],"validity":"1h"}}}`), &in); err != nil {
		t.Fatal(err)
	}
	if in.Signing.SSH.CertType != "host" || len(in.Signing.SSH.Principals) != 2 {
		t.Errorf("the shadow decode dropped a field: %+v", in.Signing.SSH)
	}
}

func TestSigningSelectorsBindEveryCAKeyOperation(t *testing.T) {
	// A CA selector should bind everything that CA's key signs. An OpenSSH
	// certificate and a JWT-SVID are both minted with the issuer key, so a rule
	// scoped to the CA has to see both — otherwise "restrict what this authority
	// signs" would quietly mean "restrict its SSH certificates".
	svid := SigningInput{Signing: SigningRequest{
		Operation: OpSignJWTSVID,
		Key:       SigningKeyInfo{Name: "issuing-ca"},
		JWTSVID: JWTSVIDInfo{
			Present: true, SPIFFEID: "spiffe://example.org/ns/prod/sa/web",
			Audience: []string{"spiffe://example.org/ns/prod/sa/db"},
			CA:       CAInfo{ID: "ca-7", Label: "issuing-ca"},
		},
	}}
	for _, tc := range []struct {
		name    string
		rule    Rule
		applies bool
	}{
		{"ca by label", Rule{CAs: []string{"issuing-ca"}}, true},
		{"ca by id", Rule{CAs: []string{"ca-7"}}, true},
		{"ca by glob", Rule{CAs: []string{"issuing-*"}}, true},
		{"other ca", Rule{CAs: []string{"ssh-user-ca"}}, false},
		{"key by name", Rule{Keys: []string{"issuing-ca"}}, true},
		{"operation", Rule{Operations: []string{OpSignJWTSVID}}, true},
		{"other operation", Rule{Operations: []string{OpSignSSHCert}}, false},
		{"ssh profile selector does not match a token", Rule{Profiles: []string{"ssh-user-default"}}, false},
	} {
		rule := tc.rule
		rule.Kind, rule.Name, rule.Expression, rule.Enabled = KindSigning, "deny-all", `false`, true
		d := NewEngine().EvaluateSigning([]Rule{rule}, svid)
		if applied := !d.Allowed; applied != tc.applies {
			t.Errorf("%s: applied=%v, want %v", tc.name, applied, tc.applies)
		}
	}
}
