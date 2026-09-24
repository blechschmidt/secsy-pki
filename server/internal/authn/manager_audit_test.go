package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// This file covers the audit plumbing every authentication decision flows
// through: the actor/IP/request-id attribution in Manager.record, the client
// address parser it uses, and the role serializer. A wrong answer here does not
// let anyone in, but it destroys the forensic record of who did what — and the
// login handlers depend on record never failing the authentication.

// --- clientIP ---

// TestClientIPFromRemoteAddr asserts the port is stripped from a direct
// connection's address (so audit rows for one host are comparable) and that odd
// addresses degrade to the raw value rather than something mangled.
func TestClientIPFromRemoteAddr(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"ipv4 with port", "192.0.2.10:44321", "192.0.2.10"},
		{"ipv4 without port", "192.0.2.10", "192.0.2.10"},
		{"ipv6 literal with port", "[2001:db8::1]:443", "2001:db8::1"},
		{"ipv6 literal without port", "2001:db8::1", "2001:db8::1"},
		{"bracketed ipv6 without port", "[2001:db8::1]", "[2001:db8::1]"},
		{"unix socket style", "@", "@"},
		{"empty", "", ""},
		{"port only", ":8443", ""},
		{"trailing colon", "192.0.2.10:", "192.0.2.10"},
		{"garbage", "not-an-address", "not-an-address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if got := clientIP(r); got != tc.want {
				t.Errorf("clientIP(RemoteAddr=%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}

// TestClientIPPrefersForwardedFor asserts X-Forwarded-For wins over the socket
// address (the deployment terminates TLS at a trusted proxy) and that an absent
// or empty header falls back to the socket.
//
// NOTE (reported): this implementation returns the X-Forwarded-For header
// *verbatim* — the whole hop list, untrimmed — whereas internal/middleware and
// internal/ratelimit return only the first hop with surrounding space trimmed.
// The value only reaches the audit event's IP field here (it is never used for an
// authorization or rate-limiting decision), but it means an authn audit row and
// the corresponding request-log row can disagree for the same request. The
// multi-hop and whitespace cases below therefore assert the *current* behaviour
// deliberately: if this starts returning only the first hop the divergence has
// been fixed, and this test plus the clientIP doc comment should be updated
// together.
func TestClientIPPrefersForwardedFor(t *testing.T) {
	cases := []struct {
		name string
		xff  string
		want string
	}{
		{"single hop", "203.0.113.7", "203.0.113.7"},
		{"multiple hops kept verbatim", "203.0.113.1, 198.51.100.2, 10.0.0.1", "203.0.113.1, 198.51.100.2, 10.0.0.1"},
		{"inner whitespace kept", " 203.0.113.9 ", " 203.0.113.9 "},
		{"ipv6 hop", "2001:db8::1", "2001:db8::1"},
		{"ipv6 hop with port", "[2001:db8::1]:443", "[2001:db8::1]:443"},
		{"bogus value is not validated", "not-an-ip", "not-an-ip"},
		{"spoofed header wins over the socket", "10.0.0.1", "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "192.0.2.10:44321"
			r.Header.Set("X-Forwarded-For", tc.xff)
			if got := clientIP(r); got != tc.want {
				t.Errorf("clientIP(XFF=%q) = %q, want %q", tc.xff, got, tc.want)
			}
		})
	}

	// An empty or absent header must not shadow the socket address.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.10:44321"
	if got := clientIP(r); got != "192.0.2.10" {
		t.Errorf("clientIP with no XFF = %q, want 192.0.2.10", got)
	}
	r.Header.Set("X-Forwarded-For", "")
	if got := clientIP(r); got != "192.0.2.10" {
		t.Errorf("clientIP with an empty XFF = %q, want the socket address", got)
	}
}

// --- joinStrings ---

// TestJoinStrings asserts the audit role serializer matches strings.Join for
// every shape a resolved role list can take. The result lands in the audit
// event's ActorRoles column, which is what an auditor reads to see the privileges
// an action was taken with.
func TestJoinStrings(t *testing.T) {
	cases := [][]string{
		nil,
		{},
		{"admin"},
		{"admin", "issuer"},
		{"admin", "issuer", "auditor"},
		{""},
		{"", ""},
		{"admin", ""},
		{"a,b", "c"}, // an embedded comma is not escaped; documented behaviour
	}
	for _, in := range cases {
		want := strings.Join(in, ",")
		if got := joinStrings(in); got != want {
			t.Errorf("joinStrings(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- record ---

// TestRecordAttributesActorAndContext asserts the audit event carries the
// principal, its effective roles, the client IP and the request correlation id,
// and that root is always attributed as root.
func TestRecordAttributesActorAndContext(t *testing.T) {
	e := newLoginEnv(t)
	req := func(xff string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/auth/login/password", nil)
		r.RemoteAddr = "192.0.2.10:1234"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	cases := []struct {
		name      string
		user      *models.UserInfo
		xff       string
		wantActor string
		wantName  string
		wantRoles string
		wantIP    string
	}{
		{
			name: "root is attributed as root",
			// Even with explicit roles, root must be recorded as root: it is a
			// superuser regardless of the role list.
			user:      &models.UserInfo{Subject: "root", Name: "Root User", IsRoot: true, Roles: []string{"issuer"}},
			wantActor: "root", wantName: "Root User", wantRoles: "root", wantIP: "192.0.2.10",
		},
		{
			name:      "platform roles are joined",
			user:      &models.UserInfo{Subject: "op@example.com", Name: "Op", Roles: []string{"admin", "auditor"}},
			xff:       "203.0.113.5",
			wantActor: "op@example.com", wantName: "Op", wantRoles: "admin,auditor", wantIP: "203.0.113.5",
		},
		{
			name:      "no roles yields an empty role list",
			user:      &models.UserInfo{Subject: "nobody@example.com"},
			wantActor: "nobody@example.com", wantRoles: "", wantIP: "192.0.2.10",
		},
		{
			name: "no principal leaves the actor unset",
			user: nil,
			// A rejected login has no established actor; inventing one would
			// misattribute the event.
			wantActor: "", wantRoles: "", wantIP: "192.0.2.10",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e.sink.reset()
			e.mgr.record(req(tc.xff), tc.user, audit.ActionAuthLogin, "target-1", audit.ResultSuccess, "detail-1")
			ev := e.sink.withAction(audit.ActionAuthLogin)
			if len(ev) != 1 {
				t.Fatalf("recorded %d events, want 1", len(ev))
			}
			got := ev[0]
			if got.Actor != tc.wantActor || got.ActorName != tc.wantName || got.ActorRoles != tc.wantRoles {
				t.Errorf("actor = (%q, %q, %q), want (%q, %q, %q)",
					got.Actor, got.ActorName, got.ActorRoles, tc.wantActor, tc.wantName, tc.wantRoles)
			}
			if got.IP != tc.wantIP {
				t.Errorf("IP = %q, want %q", got.IP, tc.wantIP)
			}
			if got.Target != "target-1" || got.Result != audit.ResultSuccess || got.Detail != "detail-1" {
				t.Errorf("unexpected event body: %+v", got)
			}
			if got.RequestID != "req-abc" {
				t.Errorf("RequestID = %q, want the injected correlation id", got.RequestID)
			}
			if got.ID == "" {
				t.Error("every audit event needs its own id")
			}
		})
	}

	// Event ids must be unique, so two logins cannot be conflated or overwrite
	// each other in the tamper-evident chain.
	e.sink.reset()
	ids := map[string]bool{}
	for i := 0; i < 10; i++ {
		e.mgr.record(req(""), nil, audit.ActionAuthLoginFailed, "", audit.ResultDenied, "x")
	}
	for _, ev := range e.sink.withAction(audit.ActionAuthLoginFailed) {
		if ids[ev.ID] {
			t.Fatalf("duplicate audit event id %q", ev.ID)
		}
		ids[ev.ID] = true
	}
}

// TestRecordToleratesAuditOutage asserts authentication does not fail because the
// audit log did: a nil sink and a failing sink must both leave the login working.
// (Fail-closed on the audit write would turn a log-storage problem into a
// console-wide outage; the tamper-evident chain is protected by its seal, not by
// refusing logins.)
func TestRecordToleratesAuditOutage(t *testing.T) {
	// Nil sink: record must be a no-op, not a nil dereference.
	quiet := NewManager(ManagerOptions{Sessions: NewSessionStore(time.Hour, time.Minute)})
	quiet.SetPasswordAuthenticator(func(u, p string) (*models.UserInfo, bool) {
		return &models.UserInfo{Subject: "x"}, u == "x"
	})
	quiet.record(httptest.NewRequest(http.MethodGet, "/", nil), nil, audit.ActionAuthLogin, "", audit.ResultSuccess, "")
	r := httptest.NewRequest(http.MethodPost, "/auth/login/password", strings.NewReader(`{"username":"x","password":"y"}`))
	w := httptest.NewRecorder()
	quiet.LoginPassword(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("login with no audit sink = %d, want 200", w.Code)
	}

	// Failing sink: the login still succeeds and still issues a session.
	e := newLoginEnv(t)
	e.sink.err = errors.New("audit storage unavailable")
	rec := e.postLogin(`{"username":"root","password":"` + opRootPass + `"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login with a failing audit sink = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	id := cookieNamed(rec, DefaultSessionCookie)
	if id == nil {
		t.Fatal("no session issued while the audit sink was failing")
	}
	if _, ok := e.sessions.Get(id.Value); !ok {
		t.Error("the session was not stored while the audit sink was failing")
	}
	// The logout path must survive it too.
	if got := e.logout(id.Value); got.Code != http.StatusOK {
		t.Errorf("logout with a failing audit sink = %d, want 200", got.Code)
	}
	if _, ok := e.sessions.Get(id.Value); ok {
		t.Error("logout did not terminate the session when the audit write failed")
	}
}

// TestFailedLoginAuditRecordsAttemptedIdentity asserts the rejected username is
// preserved for operators (brute-force detection needs it) even though it is
// withheld from the client, and that the credential itself is never recorded.
func TestFailedLoginAuditRecordsAttemptedIdentity(t *testing.T) {
	e := newLoginEnv(t)
	rec := e.postLogin(`{"username":"victim@example.com","password":"` + opRootPass + `"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	ev := e.sink.withAction(audit.ActionAuthLoginFailed)
	if len(ev) != 1 {
		t.Fatalf("failed-login events = %d, want 1", len(ev))
	}
	if !strings.Contains(ev[0].Detail, "user=victim@example.com") {
		t.Errorf("audit detail = %q, want the attempted username", ev[0].Detail)
	}
	if !strings.Contains(ev[0].Detail, "method=password") {
		t.Errorf("audit detail = %q, want the authentication method", ev[0].Detail)
	}
	if strings.Contains(ev[0].Detail, opRootPass) {
		t.Fatalf("the audit detail contains the submitted password: %q", ev[0].Detail)
	}
	// The client, by contrast, learns nothing about the account.
	if strings.Contains(rec.Body.String(), "victim@example.com") {
		t.Errorf("the response echoes the attempted username: %s", rec.Body.String())
	}
}
