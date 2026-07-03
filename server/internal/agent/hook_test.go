package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func hookAgent() *Agent { return &Agent{cfg: &Config{}, now: time.Now} }

func hookLeafSpec(t *testing.T, r *ReloadConfig) (*Agent, *CertSpec) {
	t.Helper()
	spec := &CertSpec{
		Name:     "hooked",
		KeyFile:  "/tmp/hooked.key",
		CertFile: "/tmp/hooked.crt",
		Reload:   r,
	}
	return hookAgent(), spec
}

func TestHookCommandReceivesEnvironment(t *testing.T) {
	out := filepath.Join(t.TempDir(), "env.txt")
	a, spec := hookLeafSpec(t, &ReloadConfig{
		Command: CommandLine{"sh", "-c", `echo "$SECSY_CERT_NAME $SECSY_CERT_FILE $SECSY_CERT_SERIAL" > ` + out},
		Timeout: Duration(10 * time.Second),
	})
	ca := newTestCA(t, "Hook Root")
	leaf := ca.issueFor(t, ca.key.Public(), "h", []string{"h.example.test"}, issueOpts{serial: 424242})

	if err := a.runHook(spec, leaf); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(data))
	want := "hooked /tmp/hooked.crt 424242"
	if got != want {
		t.Errorf("hook env = %q, want %q", got, want)
	}
}

func TestHookCommandTimeout(t *testing.T) {
	a, spec := hookLeafSpec(t, &ReloadConfig{
		Command: CommandLine{"sh", "-c", "sleep 30"},
		Timeout: Duration(300 * time.Millisecond),
	})
	ca := newTestCA(t, "Hook Root")
	leaf := ca.issueFor(t, ca.key.Public(), "h", []string{"h.example.test"}, issueOpts{})

	start := time.Now()
	err := a.runHook(spec, leaf)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("timeout took %s, should be ~300ms", elapsed)
	}
}

func TestHookSignalPIDFile(t *testing.T) {
	// Spawn a real child process and SIGHUP it via the pid file; SIGHUP's
	// default disposition terminates it, which Wait() reports.
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting child: %v", err)
	}
	pidFile := filepath.Join(t.TempDir(), "svc.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, spec := hookLeafSpec(t, &ReloadConfig{Signal: "HUP", PIDFile: pidFile, Timeout: Duration(5 * time.Second)})
	ca := newTestCA(t, "Hook Root")
	leaf := ca.issueFor(t, ca.key.Public(), "h", []string{"h.example.test"}, issueOpts{})

	if err := a.runHook(spec, leaf); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "hangup") {
			t.Errorf("child exit = %v, want SIGHUP termination", err)
		}
	case <-time.After(5 * time.Second):
		cmd.Process.Kill() //nolint:errcheck
		t.Fatal("child did not receive SIGHUP")
	}
}

func TestHookSignalBadPIDFile(t *testing.T) {
	a, spec := hookLeafSpec(t, &ReloadConfig{Signal: "HUP", PIDFile: "/nonexistent/x.pid", Timeout: Duration(time.Second)})
	ca := newTestCA(t, "Hook Root")
	leaf := ca.issueFor(t, ca.key.Public(), "h", []string{"h.example.test"}, issueOpts{})
	if err := a.runHook(spec, leaf); err == nil {
		t.Fatal("missing pid file should error")
	}
}

func TestParseSignal(t *testing.T) {
	for _, ok := range []string{"HUP", "hup", "SIGHUP", "USR1", "SIGUSR2", "TERM", "INT"} {
		if _, err := parseSignal(ok); err != nil {
			t.Errorf("parseSignal(%q): %v", ok, err)
		}
	}
	if _, err := parseSignal("KILL"); err == nil {
		t.Error("KILL should be rejected as a reload signal")
	}
}
