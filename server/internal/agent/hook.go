package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// parseSignal maps a name like "HUP" or "SIGUSR1" to a signal.
func parseSignal(name string) (syscall.Signal, error) {
	switch strings.ToUpper(strings.TrimPrefix(strings.ToUpper(name), "SIG")) {
	case "HUP":
		return syscall.SIGHUP, nil
	case "USR1":
		return syscall.SIGUSR1, nil
	case "USR2":
		return syscall.SIGUSR2, nil
	case "TERM":
		return syscall.SIGTERM, nil
	case "INT":
		return syscall.SIGINT, nil
	default:
		return 0, fmt.Errorf("unsupported reload signal %q (want HUP, USR1, USR2, TERM, or INT)", name)
	}
}

// runHook executes the spec's post-renew reload hook, if any. The new files
// are already in place when it runs; a non-nil error triggers rollback.
func (a *Agent) runHook(spec *CertSpec, leaf *x509.Certificate) error {
	r := spec.Reload
	if r == nil || (len(r.Command) == 0 && r.Signal == "") {
		return nil
	}
	if r.Signal != "" {
		return signalPIDFile(r)
	}
	return a.runHookCommand(spec, r, leaf)
}

// runHookCommand runs the configured command with certificate context in the
// environment, bounded by the hook timeout.
func (a *Agent) runHookCommand(spec *CertSpec, r *ReloadConfig, leaf *x509.Certificate) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout.Std())
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Command[0], r.Command[1:]...)
	// Run the hook in its own process group and kill the whole group on
	// timeout: otherwise a grandchild (e.g. `sh -c` spawning a service) could
	// outlive the deadline and hold the output pipe open indefinitely.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 3 * time.Second
	cmd.Env = append(os.Environ(),
		"SECSY_CERT_NAME="+spec.Name,
		"SECSY_KEY_FILE="+spec.KeyFile,
		"SECSY_CERT_FILE="+spec.CertFile,
		"SECSY_CHAIN_FILE="+spec.ChainFile,
		"SECSY_FULLCHAIN_FILE="+spec.FullchainFile,
		"SECSY_CERT_SERIAL="+leaf.SerialNumber.String(),
		"SECSY_CERT_NOT_AFTER="+leaf.NotAfter.UTC().Format(time.RFC3339),
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("command timed out after %s", r.Timeout.Std())
	}
	if err != nil {
		return fmt.Errorf("command %q: %w (output: %s)", strings.Join(r.Command, " "), err, summarizeBody(output.Bytes()))
	}
	return nil
}

// signalPIDFile sends the configured signal to the process named by the pid
// file (e.g. SIGHUP to nginx).
func signalPIDFile(r *ReloadConfig) error {
	sig, err := parseSignal(r.Signal)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(r.PIDFile)
	if err != nil {
		return fmt.Errorf("reading pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return fmt.Errorf("pid file %s does not contain a valid pid", r.PIDFile)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}
	if err := proc.Signal(sig); err != nil {
		return fmt.Errorf("signaling pid %d with %s: %w", pid, r.Signal, err)
	}
	return nil
}
