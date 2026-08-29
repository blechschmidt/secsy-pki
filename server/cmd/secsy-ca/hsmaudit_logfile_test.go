package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
)

// `hsm-audit verify-file` is the auditor's tool for the append-only device log,
// and it is dispatched in main before any configuration is read, so these tests
// pass it nothing but a path — as a third party holding a shipped copy would.

// testAnchor is the chain digest this fixture's device-init sentinel carries.
// A real one is whatever the device produced at its factory reset and is
// recorded out of band at provisioning; nothing derives it from the sentinel.
const testAnchor = "369a47bf3d7353d627b7ce4e9c117fba"

// writeLogFile produces a small append-only file, optionally starting at the
// device-init sentinel, and returns its path along with the last entry number.
func writeLogFile(t *testing.T, fromGenesis bool) (path string, last uint16) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "hsm-audit.jsonl")

	const anchor = testAnchor
	entries := []hsm.AuditLogEntry{{
		Number: 1, Command: 0xff, Length: 0xffff, SessionKey: 0xffff,
		TargetKey: 0xffff, SecondKey: 0xffff, Result: 0xff, Tick: 0xffffffff, Hash: anchor,
	}}
	prev, err := hex.DecodeString(anchor)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e := hsm.AuditLogEntry{
			Number: uint16(i + 2), Command: hsm.CmdSignECDSA, Length: 34, SessionKey: 1,
			TargetKey: 0xfe19, SecondKey: 0xffff, Result: hsm.CmdSignECDSA | 0x80, Tick: uint32(1000 + i),
		}
		e.Hash = hsm.ComputeEntryHash(e, prev)
		prev, _ = hex.DecodeString(e.Hash)
		entries = append(entries, e)
	}
	if !fromGenesis {
		entries = entries[1:]
	}

	f, err := hsmaudit.OpenLogFile(path)
	if err != nil {
		t.Fatalf("OpenLogFile: %v", err)
	}
	if err := f.AppendEntries(context.Background(), "31650425", entries); err != nil {
		t.Fatalf("AppendEntries: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path, entries[len(entries)-1].Number
}

func TestVerifyFileAcceptsAGenuineFile(t *testing.T) {
	path, last := writeLogFile(t, true)
	if err := cmdHSMAuditVerifyFile([]string{"-file", path}); err != nil {
		t.Fatalf("a genuine file was rejected: %v", err)
	}
	// -strict adds "and it covers the whole history it claims to", which a file
	// written from the sentinel does.
	if err := cmdHSMAuditVerifyFile([]string{"-file", path, "-strict"}); err != nil {
		t.Fatalf("a file starting at the device-init sentinel failed -strict: %v", err)
	}
	if err := cmdHSMAuditVerifyFile([]string{
		"-file", path, "-serial", "31650425", "-tail", strconv.Itoa(int(last)),
	}); err != nil {
		t.Fatalf("the serial and tail of a genuine file were rejected: %v", err)
	}
}

func TestVerifyFileRequiresAPath(t *testing.T) {
	if err := cmdHSMAuditVerifyFile(nil); err == nil {
		t.Fatal("verify-file ran without -file")
	}
}

func TestVerifyFileRejectsAnEditedRecord(t *testing.T) {
	path, _ := writeLogFile(t, true)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(body), `"target_key":65049`, `"target_key":1`, 1)
	if edited == string(body) {
		t.Fatal("test setup: nothing to edit")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdHSMAuditVerifyFile([]string{"-file", path}); err == nil {
		t.Fatal("an edited record passed verification")
	}
}

// Records removed from the end leave a shorter chain that still verifies on its
// own, which is exactly why -tail exists: the collection tail is an independent
// statement of how far the log got.
func TestVerifyFileCatchesTruncationOnlyWithATail(t *testing.T) {
	path, last := writeLogFile(t, true)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if err := os.WriteFile(path, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cmdHSMAuditVerifyFile([]string{"-file", path}); err != nil {
		t.Fatalf("a truncated file should still verify against itself (that is the point of -tail): %v", err)
	}
	err = cmdHSMAuditVerifyFile([]string{"-file", path, "-tail", strconv.Itoa(int(last))})
	if err == nil {
		t.Fatal("truncation passed even with the expected tail supplied")
	}
	if !strings.Contains(err.Error(), "removed from the end") {
		t.Fatalf("the error does not name the truncation: %v", err)
	}
}

// A file opened partway through a device's life is honest but incomplete: it
// verifies, and -strict is what makes an auditor's "this must be the whole
// history" requirement explicit.
func TestVerifyFileStrictRejectsADocumentedGap(t *testing.T) {
	path, _ := writeLogFile(t, false)
	if err := cmdHSMAuditVerifyFile([]string{"-file", path}); err != nil {
		t.Fatalf("a file with a documented gap failed plain verification: %v", err)
	}
	err := cmdHSMAuditVerifyFile([]string{"-file", path, "-strict"})
	if err == nil {
		t.Fatal("-strict accepted a file that documents a gap in its coverage")
	}
	if !strings.Contains(err.Error(), "gap") {
		t.Fatalf("the error does not name the gap: %v", err)
	}
}

// The anchor is the only thing in the file that distinguishes one device's
// history from another's: the sentinel's own bytes are a constant on every
// YubiHSM, and every other record chains from a digest that is not derivable
// from them. A verifier that accepted the flag and ignored the value would
// report OK on a fabricated-but-consistent chain, which is the exact failure the
// anchor exists to catch.
func TestVerifyFileChecksTheAnchor(t *testing.T) {
	path, _ := writeLogFile(t, true)

	if err := cmdHSMAuditVerifyFile([]string{"-file", path, "-anchor", testAnchor}); err != nil {
		t.Fatalf("the genuine anchor was rejected: %v", err)
	}
	// Case-insensitively, as everywhere else digests are compared.
	if err := cmdHSMAuditVerifyFile([]string{"-file", path, "-anchor", strings.ToUpper(testAnchor)}); err != nil {
		t.Fatalf("the genuine anchor was rejected in upper case: %v", err)
	}

	err := cmdHSMAuditVerifyFile([]string{
		"-file", path, "-anchor", "00000000000000000000000000000000",
	})
	if err == nil {
		t.Fatal("a file whose sentinel carries a different anchor passed the anchor check")
	}
	if !strings.Contains(err.Error(), "does not match the pinned anchor") {
		t.Fatalf("the error does not name the anchor mismatch: %v", err)
	}
}

// An anchor pins a genesis, so there has to be one to pin. A file that opens
// partway through a device's life has no sentinel, and silently accepting an
// anchor against it would suggest a binding that was never checked.
func TestVerifyFileRejectsAnAnchorWithoutAGenesis(t *testing.T) {
	path, _ := writeLogFile(t, false)
	err := cmdHSMAuditVerifyFile([]string{"-file", path, "-anchor", testAnchor})
	if err == nil {
		t.Fatal("an anchor was accepted against a file that does not start at the sentinel")
	}
	if !strings.Contains(err.Error(), "nothing for it to pin") {
		t.Fatalf("the error does not explain why the anchor is unusable: %v", err)
	}
}

func TestVerifyFileRejectsTheWrongSerial(t *testing.T) {
	path, _ := writeLogFile(t, true)
	err := cmdHSMAuditVerifyFile([]string{"-file", path, "-serial", "99999999"})
	if err == nil {
		t.Fatal("a file from another device passed the serial check")
	}
	if !strings.Contains(err.Error(), "99999999") {
		t.Fatalf("the error does not name the expected serial: %v", err)
	}
}
