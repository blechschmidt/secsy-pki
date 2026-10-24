package doctor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// The auth.oidc.pkce check answers a question an operator cannot answer from
// the config file: does the identity provider actually implement the proof-key
// exchange the console's login relies on? The server sends an S256 challenge
// either way, so an IdP that ignores it leaves intercepted authorization codes
// redeemable — and says nothing about it at login time.
//
// Severity follows the deployment's own stance: with require_pkce set the
// server would refuse to start, so the check fails; without it, the same
// finding is a warning; an unreadable discovery document is never more than a
// warning, because doctor often runs from a host with different egress.

// pkceIDP serves a discovery document advertising the given methods. A nil
// slice omits the field entirely, as a few conformant IdPs do.
func pkceIDP(t *testing.T, methods []string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		doc := `{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/authorize"`
		if methods != nil {
			doc += `,"code_challenge_methods_supported":["` + strings.Join(methods, `","`) + `"]`
		}
		doc += `}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// pkceCheckResult runs checkOIDCLogin over cfg and returns its single result.
func pkceCheckResult(t *testing.T, cfg *config.Config) Result {
	t.Helper()
	r := &Report{OK: true}
	opts := Options{}
	opts.applyDefaults()
	checkOIDCLogin(context.Background(), r, cfg, opts)
	if len(r.Checks) != 1 || r.Checks[0].Name != "auth.oidc.pkce" {
		t.Fatalf("checkOIDCLogin produced %+v, want one auth.oidc.pkce result", r.Checks)
	}
	return r.Checks[0]
}

// oidcCfg builds a console-login config for one provider at issuer.
func oidcCfg(issuer string, requirePKCE bool) *config.Config {
	cfg := &config.Config{}
	cfg.Auth.OIDC.Enabled = true
	cfg.Auth.OIDC.IssuerURL = issuer
	cfg.Auth.OIDC.ClientID = "console"
	cfg.Auth.OIDC.RedirectURL = "https://pki.example.com/auth/callback"
	cfg.Auth.OIDC.RequirePKCE = requirePKCE
	return cfg
}

func TestOIDCPKCECheck(t *testing.T) {
	cases := []struct {
		name       string
		methods    []string
		require    bool
		want       Status
		wantDetail string
	}{
		{"advertised", []string{"S256"}, false, StatusPass, "S256 advertised"},
		{"advertised and required", []string{"plain", "S256"}, true, StatusPass, "S256 advertised"},
		{"only plain", []string{"plain"}, false, StatusWarn, "no S256"},
		{"field omitted", nil, false, StatusWarn, "no S256"},
		{"required but absent", []string{"plain"}, true, StatusFail, "refuse to start"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := pkceIDP(t, tc.methods)
			got := pkceCheckResult(t, oidcCfg(idp.URL, tc.require))
			if got.Status != tc.want {
				t.Errorf("status = %v, want %v (detail: %s)", got.Status, tc.want, got.Detail)
			}
			if !strings.Contains(got.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to mention %q", got.Detail, tc.wantDetail)
			}
		})
	}
}

// TestOIDCPKCECheckUnreachableIdPWarns asserts an IdP this host cannot reach is
// never reported as a failure: doctor runs before the server starts, often from
// somewhere else on the network, and "I could not look" is not "it is broken".
func TestOIDCPKCECheckUnreachableIdPWarns(t *testing.T) {
	idp := pkceIDP(t, []string{"S256"})
	url := idp.URL
	idp.Close() // nothing listens there any more

	got := pkceCheckResult(t, oidcCfg(url, true))
	if got.Status != StatusWarn {
		t.Errorf("status = %v, want WARN for an unreachable IdP (detail: %s)", got.Status, got.Detail)
	}
	if !strings.Contains(got.Detail, "discovery unreadable") {
		t.Errorf("detail = %q, want it to say the discovery document could not be read", got.Detail)
	}
}

// TestOIDCPKCECheckSkipsWhenLoginDisabled keeps the check quiet for the many
// deployments that authenticate operators some other way.
func TestOIDCPKCECheckSkipsWhenLoginDisabled(t *testing.T) {
	got := pkceCheckResult(t, &config.Config{})
	if got.Status != StatusSkip {
		t.Errorf("status = %v, want SKIP when interactive login is disabled", got.Status)
	}
}

// TestOIDCPKCECheckReportsEveryProvider asserts a federated deployment gets a
// per-provider verdict, and that the worst one decides the check's status —
// otherwise a second, weaker IdP could hide behind a healthy first one.
func TestOIDCPKCECheckReportsEveryProvider(t *testing.T) {
	good := pkceIDP(t, []string{"S256"})
	weak := pkceIDP(t, []string{"plain"})

	cfg := &config.Config{}
	cfg.Auth.OIDC.Enabled = true
	cfg.Auth.OIDC.RedirectURL = "https://pki.example.com/auth/callback"
	cfg.Auth.OIDC.RequirePKCE = true
	cfg.Auth.OIDC.Providers = []config.AuthOIDCProviderConfig{
		{Name: "corp", IssuerURL: good.URL, ClientID: "console-corp"},
		{Name: "partner", IssuerURL: weak.URL, ClientID: "console-partner"},
	}

	got := pkceCheckResult(t, cfg)
	if got.Status != StatusFail {
		t.Errorf("status = %v, want FAIL — one required provider does not advertise S256", got.Status)
	}
	for _, want := range []string{"corp: S256 advertised", "partner:"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail = %q, want it to report %q", got.Detail, want)
		}
	}

	// Relaxing the demand for that one provider downgrades the finding to a
	// warning, without silencing it.
	relaxed := false
	cfg.Auth.OIDC.Providers[1].RequirePKCE = &relaxed
	if got := pkceCheckResult(t, cfg); got.Status != StatusWarn {
		t.Errorf("status = %v, want WARN once the weak provider's require_pkce is cleared", got.Status)
	}
}
