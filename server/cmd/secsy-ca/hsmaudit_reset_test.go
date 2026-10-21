//go:build sqlite

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// The commissioning path's first refusal has to name a command that exists.
//
// `provision` requires a device log that begins at the device-init sentinel, and
// the only way to get one is a factory reset. hsm.CheckDeviceInitEntry tells the
// operator exactly that, by naming `secsy-ca hsm-audit reset` — which was not a
// subcommand. This test ties the advice to the surface: whatever hsm-audit
// subcommand the refusal recommends must be one the CLI lists.
func TestTheProvisioningRefusalNamesAnHSMAuditSubcommandThatExists(t *testing.T) {
	usage := captureHSMAuditUsage(t)
	recommend := regexp.MustCompile(`secsy-ca hsm-audit ([a-z-]+)`)

	// Both refusals: an empty log and one that does not start at the sentinel.
	for _, err := range []error{
		hsm.CheckDeviceInitEntry(nil),
		hsm.CheckDeviceInitEntry([]hsm.AuditLogEntry{{Number: 7, Command: 0x56}}),
	} {
		if err == nil {
			t.Fatal("CheckDeviceInitEntry accepted a log that does not start at the sentinel")
		}
		m := recommend.FindStringSubmatch(err.Error())
		if m == nil {
			t.Fatalf("the refusal recommends no hsm-audit subcommand, so an operator is left "+
				"to guess how to reset the device: %v", err)
		}
		sub := m[1]
		if !strings.Contains(usage, "\n  "+sub) {
			t.Errorf("the refusal tells the operator to run `secsy-ca hsm-audit %s`, which the CLI "+
				"does not list:\n%s", sub, usage)
		}
	}
}

// reset is dispatched, and it is on the side of the dispatch that does not open
// the append-only device-log file.
//
// Two things at once, because they are the same line of code. A reset destroys
// the device log rather than collecting it, so it belongs with `status` ahead of
// the sink wiring: a file created here would begin one commissioning before the
// sentinel that the next `provision` writes, and `verify-file -anchor` refuses a
// file that does not begin at the anchor.
//
// The connector URL points at a port nothing serves so the device read fails the
// same way on a machine with a YubiHSM attached as on one without.
func TestHSMAuditResetIsDispatchedAndDoesNotCreateTheLogFile(t *testing.T) {
	resetConfiguredAuditLogFile(t)
	path := filepath.Join(t.TempDir(), "device-log.jsonl")
	cfg := &config.Config{}
	cfg.YubiHSM.AuditLogFile = path
	cfg.YubiHSM.ConnectorURL = "http://127.0.0.1:1"

	err := cmdHSMAudit(hsmAuditTestDB(t), cfg, []string{"reset"})
	if err == nil {
		t.Fatal("`hsm-audit reset` succeeded against an unreachable device")
	}
	if strings.Contains(err.Error(), "unknown subcommand") {
		t.Fatalf("`hsm-audit reset` is not dispatched: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("`hsm-audit reset` created %s (stat err: %v)", path, err)
	}
}

// An operator has seen their device's serial in two spellings — zero-padded from
// the USB descriptor, plain from the device itself — and either must confirm.
// Nothing else may, least of all an empty flag.
func TestResetConfirmedAcceptsEitherSerialSpelling(t *testing.T) {
	for _, tc := range []struct {
		name    string
		device  string
		confirm string
		want    bool
	}{
		{"plain", "31650425", "31650425", true},
		{"padded confirm", "31650425", "0031650425", true},
		{"padded device", "0031650425", "31650425", true},
		{"surrounding space", "31650425", "  31650425\n", true},
		{"empty", "31650425", "", false},
		{"zeroes only", "31650425", "0000", false},
		{"another device", "31650425", "36799667", false},
		{"prefix of the serial", "31650425", "3165", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resetConfirmed(tc.device, tc.confirm); got != tc.want {
				t.Errorf("resetConfirmed(%q, %q) = %v, want %v", tc.device, tc.confirm, got, tc.want)
			}
		})
	}
}

// The inventory is what the operator confirms against, so every object is named
// with its label: "DEFAULT AUTHKEY CHANGE THIS ASAP" and "issuing-ca root key"
// are very different things to erase.
func TestResetDeviceObjectsNamesEveryObject(t *testing.T) {
	out := resetDeviceObjects([]hsm.ObjectInfo{
		{ID: 1, Type: "authentication-key", Algo: "aes128-yubico-authentication", Label: "DEFAULT AUTHKEY CHANGE THIS ASAP"},
		{ID: 0x1939, Type: "asymmetric-key", Algo: "ecp384", Label: "issuing-ca"},
	})
	for _, want := range []string{"0x0001", "authentication-key", "DEFAULT AUTHKEY CHANGE THIS ASAP",
		"0x1939", "ecp384", "issuing-ca"} {
		if !strings.Contains(out, want) {
			t.Errorf("the inventory does not mention %q:\n%s", want, out)
		}
	}
	if got := resetDeviceObjects(nil); !strings.Contains(got, "(none)") {
		t.Errorf("an empty device should say so, got %q", got)
	}
}

func captureHSMAuditUsage(t *testing.T) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	hsmAuditUsage()
	os.Stderr = orig
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The watchdog is what keeps a reset from being a command that never returns.
//
// A reset takes the device off the USB bus, and a read waiting on a device that
// is no longer there can block in usbfs rather than fail — over USB/IP until the
// client's virtual port is detached. Everything after the reset therefore runs
// under runBounded, which has to report the difference between "it answered" and
// "we stopped waiting", because the first decides whether an error is real and
// the second decides what the operator is told.
func TestRunBoundedReportsWhetherTheCallReturned(t *testing.T) {
	t.Run("a call that returns", func(t *testing.T) {
		want := errors.New("device said no")
		err, completed := runBounded(10*time.Second, func() error { return want })
		if !completed {
			t.Fatal("a call that returned immediately was reported as abandoned")
		}
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	})

	t.Run("a call that blocks", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		start := time.Now()
		err, completed := runBounded(50*time.Millisecond, func() error {
			<-release
			return nil
		})
		if completed {
			t.Fatal("a call that never returned was reported as completed")
		}
		if err != nil {
			t.Fatalf("an abandoned call must not invent an error, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("the watchdog waited %s for a 50ms bound", elapsed)
		}
	})
}

// A reset that the device never answers is the normal outcome, so the command
// cannot take the absence of an error as proof — nor an error from an abandoned
// call as a failure. Both halves show up in what the operator is told.
func TestDescribeProbeNamesTheRoute(t *testing.T) {
	if got := describeProbe(""); got != "direct USB" {
		t.Errorf("an empty connector URL is direct USB, got %q", got)
	}
	if got := describeProbe("http://127.0.0.1:12345"); got != "http://127.0.0.1:12345" {
		t.Errorf("a connector URL should be named as given, got %q", got)
	}
}

// "I could not read the log" and "I read the log and the sentinel is not there"
// are different facts, and only one of them means the operator has to reset
// again. The first hardware run of `hsm-audit reset` printed the second for the
// first: the device had come back half a second earlier and the session failed,
// so a device that was in exactly the right state was reported as being in the
// wrong one.
func TestResetSentinelLineSeparatesUnreadableFromAbsent(t *testing.T) {
	ok := resetSentinelLine(&hsmAuditResetResult{Sentinel: true})
	if !strings.Contains(ok, "starts at the device-init sentinel") {
		t.Errorf("a verified sentinel should say so, got %q", ok)
	}

	unread := resetSentinelLine(&hsmAuditResetResult{SentinelError: "no reply from the device"})
	if strings.Contains(unread, "WARNING") || strings.Contains(unread, "does not start") {
		t.Errorf("an unreadable log must not be reported as a missing sentinel, got %q", unread)
	}
	if !strings.Contains(unread, "no reply from the device") || !strings.Contains(unread, "hsm-audit status") {
		t.Errorf("an unreadable log should name the failure and where to look next, got %q", unread)
	}

	absent := resetSentinelLine(&hsmAuditResetResult{})
	if !strings.Contains(absent, "WARNING") || !strings.Contains(absent, "does not start") {
		t.Errorf("a log that was read and has no sentinel is the one case that warrants the warning, got %q", absent)
	}
}
