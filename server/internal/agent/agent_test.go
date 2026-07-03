package agent

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// TestAgentESTLifecycle drives the full agent flow against the fake EST
// server: initial enrollment, steady state, clock-forced fraction renewal
// (via simplereenroll), hook execution, and metrics.
func TestAgentESTLifecycle(t *testing.T) {
	ca := newTestCA(t, "Lifecycle Root")
	fake := &fakeEST{ca: ca, username: "device", password: "pw", validity: 24 * time.Hour}

	var hookLog string
	a, spec, _ := newESTAgent(t, fake, func(cfg *Config) {
		hookLog = filepath.Join(filepath.Dir(cfg.Certificates[0].KeyFile), "hook.log")
		cfg.Certificates[0].Reload = &ReloadConfig{
			Command: CommandLine{"sh", "-c", "echo fired >> " + hookLog},
			Timeout: Duration(10 * time.Second),
		}
		cfg.Metrics.Textfile = filepath.Join(cfg.StateDir, "agent.prom")
	})

	// Pass 1: initial enrollment.
	report, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 || got[0] != "web" {
		t.Fatalf("renewed = %v, want [web]", got)
	}
	if fake.enrolls != 1 || fake.reenrolls != 0 {
		t.Fatalf("enrolls=%d reenrolls=%d, want 1/0", fake.enrolls, fake.reenrolls)
	}
	firstCert, err := os.ReadFile(spec.CertFile)
	if err != nil {
		t.Fatalf("cert not installed: %v", err)
	}
	if data, err := os.ReadFile(hookLog); err != nil || strings.Count(string(data), "fired") != 1 {
		t.Fatalf("hook after install: %v / %q", err, data)
	}

	// Pass 2: nothing to do.
	report, err = a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 2: %v", err)
	}
	if len(report.Renewed()) != 0 || len(report.Failed()) != 0 {
		t.Fatalf("steady-state pass should be all fresh: %+v", report.Outcomes)
	}
	if report.Outcomes[0].Action != "fresh" || report.Outcomes[0].RenewAt == nil {
		t.Fatalf("fresh outcome should carry renew_at: %+v", report.Outcomes[0])
	}

	// Pass 3: clock jumps past the renewal fraction → renewal via reenroll.
	a.SetClock(func() time.Time { return time.Now().Add(20 * time.Hour) })
	report, err = a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce 3: %v", err)
	}
	if got := report.Renewed(); len(got) != 1 {
		t.Fatalf("forced pass renewed %v, want [web]", got)
	}
	if fake.reenrolls != 1 {
		t.Fatalf("renewal should use simplereenroll, got enrolls=%d reenrolls=%d", fake.enrolls, fake.reenrolls)
	}
	secondCert, _ := os.ReadFile(spec.CertFile)
	if string(secondCert) == string(firstCert) {
		t.Fatal("certificate file did not change on renewal")
	}
	if data, _ := os.ReadFile(hookLog); strings.Count(string(data), "fired") != 2 {
		t.Fatalf("hook should have fired twice, log: %q", data)
	}

	// Metrics textfile exists and carries the expiry gauge.
	prom, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "agent.prom"))
	if err != nil {
		t.Fatalf("metrics textfile: %v", err)
	}
	for _, want := range []string{
		`secsy_agent_certificate_not_after_seconds{certificate="web"}`,
		`secsy_agent_certificate_present{certificate="web"} 1`,
		"secsy_agent_last_run_seconds",
	} {
		if !strings.Contains(string(prom), want) {
			t.Errorf("metrics textfile missing %q:\n%s", want, prom)
		}
	}

	// State was persisted with the renewal outcome.
	st, err := loadState(a.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Certificates["web"] == nil || st.Certificates["web"].LastOutcome != "renewed" {
		t.Errorf("state outcome = %+v", st.Certificates["web"])
	}

	assertNoTempLitter(t, filepath.Dir(spec.CertFile))
}

// TestAgentESTFailureSetsBackoffAndExitState verifies failed enrollments are
// reported, recorded, and retried with backoff in daemon passes.
func TestAgentESTFailure(t *testing.T) {
	ca := newTestCA(t, "Fail Root")
	fake := &fakeEST{ca: ca, username: "device", password: "pw"}
	a, _, _ := newESTAgent(t, fake, func(cfg *Config) {
		cfg.EST.Password = "wrong" // server will 401
	})

	report, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := report.Failed(); len(got) != 1 || got[0] != "web" {
		t.Fatalf("failed = %v, want [web]", got)
	}
	st := a.state.cert("web")
	if st.ConsecutiveFailures != 1 || st.LastOutcome != "failed" || st.NextAttempt.IsZero() {
		t.Errorf("failure bookkeeping: %+v", st)
	}

	// A daemon pass inside the backoff window skips the retry.
	outcome := a.processSpec(context.Background(), a.cfg.Certificates[0], false)
	if outcome.Action != "backoff" {
		t.Errorf("daemon pass action = %q, want backoff", outcome.Action)
	}
	// `once` (force) retries regardless.
	outcome = a.processSpec(context.Background(), a.cfg.Certificates[0], true)
	if outcome.Action != "failed" {
		t.Errorf("forced pass action = %q, want failed (retried)", outcome.Action)
	}
	if st.ConsecutiveFailures != 2 {
		t.Errorf("failures = %d, want 2", st.ConsecutiveFailures)
	}
}

func TestBackoffDelay(t *testing.T) {
	base := 5 * time.Minute
	for i, want := range map[int]time.Duration{1: base, 2: 2 * base, 3: 4 * base, 10: time.Hour} {
		if got := backoffDelay(base, i); got != want {
			t.Errorf("backoffDelay(%d) = %s, want %s", i, got, want)
		}
	}
}

// TestAgentStatus checks the status document before and after install.
func TestAgentStatus(t *testing.T) {
	ca := newTestCA(t, "Status Root")
	fake := &fakeEST{ca: ca, username: "device", password: "pw"}
	a, _, _ := newESTAgent(t, fake, nil)

	st := a.Status()
	if len(st.Certificates) != 1 {
		t.Fatalf("status has %d certs", len(st.Certificates))
	}
	if st.Certificates[0].Present || !st.Certificates[0].Due {
		t.Errorf("pre-install status wrong: %+v", st.Certificates[0])
	}

	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	st = a.Status()
	cs := st.Certificates[0]
	if !cs.Present || cs.Due || cs.Serial == "" || cs.NotAfter == nil || cs.RenewAt == nil {
		t.Errorf("post-install status wrong: %+v", cs)
	}
	if cs.RenewSource != "lifetime" {
		t.Errorf("renew source = %q, want lifetime", cs.RenewSource)
	}
	if want := "dns:web.example.test"; len(cs.SANs) != 1 || cs.SANs[0] != want {
		t.Errorf("status SANs = %v, want [%s]", cs.SANs, want)
	}
}

// TestARICertIDGolden pins the CertID encoding to the draft-ietf-acme-ari
// worked example: AKI 0x69885b6b874640... serial 0x87654321 →
// "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE". ariCertID reads only the two
// identity fields, so a bare certificate value suffices.
func TestARICertIDGolden(t *testing.T) {
	aki, err := base64.RawURLEncoding.DecodeString("aYhba4dGQEHhs3uEe6CuLN4ByNQ")
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{AuthorityKeyId: aki, SerialNumber: big.NewInt(0x87654321)}
	got, err := ariCertID(leaf)
	if err != nil {
		t.Fatal(err)
	}
	want := "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
	if got != want {
		t.Errorf("ariCertID = %q, want %q", got, want)
	}
}

func TestSerialContentOctets(t *testing.T) {
	cases := []struct {
		serial int64
		want   []byte
	}{
		{0x7f, []byte{0x7f}},
		{0x80, []byte{0x00, 0x80}}, // top bit set → leading zero
		{0, []byte{0x00}},
		{0x0102, []byte{0x01, 0x02}},
	}
	for _, tc := range cases {
		got, err := serialContentOctets(big.NewInt(tc.serial))
		if err != nil {
			t.Fatalf("serial %x: %v", tc.serial, err)
		}
		if string(got) != string(tc.want) {
			t.Errorf("serial %x → %x, want %x", tc.serial, got, tc.want)
		}
	}
}

// TestListenerSolver exercises the standalone http-01 responder.
func TestListenerSolver(t *testing.T) {
	s := &listenerSolver{addr: "127.0.0.1:0"}
	if err := s.provision("tok1", "tok1.keyauth"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	defer s.close() //nolint:errcheck

	addr := s.boundAddr()
	if addr == "" {
		t.Fatal("listener did not bind")
	}
	resp, err := http.Get("http://" + addr + challengePathPrefix + "tok1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "tok1.keyauth" {
		t.Errorf("challenge response = %d %q", resp.StatusCode, body)
	}

	// Unknown and cleaned-up tokens 404.
	resp, _ = http.Get("http://" + addr + challengePathPrefix + "other")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown token status = %d, want 404", resp.StatusCode)
	}
	s.cleanup("tok1")
	resp, _ = http.Get("http://" + addr + challengePathPrefix + "tok1")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("cleaned token status = %d, want 404", resp.StatusCode)
	}

	// close() releases the port; provisioning again rebinds.
	if err := s.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := s.provision("tok2", "ka2"); err != nil {
		t.Fatalf("re-provision after close: %v", err)
	}
	if s.boundAddr() == "" {
		t.Fatal("listener did not rebind")
	}
	s.close() //nolint:errcheck
}

func TestWebrootSolver(t *testing.T) {
	dir := t.TempDir()
	s := &webrootSolver{dir: dir}
	if err := s.provision("tok", "keyauth-body"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	path := filepath.Join(dir, ".well-known", "acme-challenge", "tok")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keyauth-body" {
		t.Fatalf("webroot file: %v %q", err, data)
	}
	s.cleanup("tok")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("webroot file not cleaned up")
	}
}

// TestTrustBundleParsing covers PEM and PKCS#7 bundle bodies.
func TestTrustBundleParsing(t *testing.T) {
	ca := newTestCA(t, "Bundle Root")

	certs, err := parseBundleBody(encodeChainPEM([]*x509.Certificate{ca.cert}))
	if err != nil || len(certs) != 1 {
		t.Fatalf("PEM bundle: %v (%d certs)", err, len(certs))
	}

	// EST cacerts style: base64 PKCS#7 with line wraps.
	der, err := cms.DegenerateCertsOnly([]*x509.Certificate{ca.cert})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	var wrapped strings.Builder
	for len(b64) > 60 {
		wrapped.WriteString(b64[:60] + "\r\n")
		b64 = b64[60:]
	}
	wrapped.WriteString(b64 + "\r\n")
	certs, err = parseBundleBody([]byte(wrapped.String()))
	if err != nil || len(certs) != 1 {
		t.Fatalf("PKCS#7 bundle: %v (%d certs)", err, len(certs))
	}
	if !certs[0].Equal(ca.cert) {
		t.Error("PKCS#7 bundle returned a different certificate")
	}

	if _, err := parseBundleBody([]byte("not a bundle at all")); err == nil {
		t.Error("garbage bundle should error")
	}
}
