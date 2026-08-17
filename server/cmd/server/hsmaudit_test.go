package main

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// Collection follows the HSM operations rather than a timer (Task 181). What
// remains configurable is the backstop sweep, and the key that used to set the
// polling cadence still has to mean something sensible: a deployment that tuned
// audit_collect_interval_seconds down did so because its device log filled, and
// silently discarding that value would reintroduce exactly the problem the
// operator was working around.
func TestHSMAuditBackstopResolution(t *testing.T) {
	for _, tc := range []struct {
		name     string
		yubi     config.YubiHSMConfig
		want     time.Duration
		deprecat bool
	}{
		{
			name: "unset selects the default",
			want: hsmaudit.BackstopInterval,
		},
		{
			name: "explicit backstop wins",
			yubi: config.YubiHSMConfig{AuditCollectBackstopSeconds: 90},
			want: 90 * time.Second,
		},
		{
			name:     "the deprecated interval is honoured as the backstop",
			yubi:     config.YubiHSMConfig{AuditCollectIntervalSeconds: 15},
			want:     15 * time.Second,
			deprecat: true,
		},
		{
			name: "the new key beats the deprecated one",
			yubi: config.YubiHSMConfig{AuditCollectBackstopSeconds: 120, AuditCollectIntervalSeconds: 15},
			want: 120 * time.Second,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{YubiHSM: tc.yubi}
			if got := hsmAuditBackstop(cfg); got != tc.want {
				t.Fatalf("backstop = %s, want %s", got, tc.want)
			}
		})
	}
}

// Per-operation collection is the default, and stays on unless an operator
// explicitly turns it off. An unprovisioned or misread config must not quietly
// fall back to polling: the whole reason the device log is trustworthy is that
// it is complete, and a log sitting undrained in a volatile 62-entry ring is
// the part of it most likely to be lost.
func TestPerOperationCollectionDefaultsOn(t *testing.T) {
	if !perOperationCollection(&config.Config{}) {
		t.Fatal("per-operation collection is off by default")
	}
	on, off := true, false
	if !perOperationCollection(&config.Config{YubiHSM: config.YubiHSMConfig{AuditCollectPerOperation: &on}}) {
		t.Fatal("explicitly enabling per-operation collection turned it off")
	}
	if perOperationCollection(&config.Config{YubiHSM: config.YubiHSMConfig{AuditCollectPerOperation: &off}}) {
		t.Fatal("an operator could not turn per-operation collection off")
	}
}

// recordHSMSignatures is the chokepoint every key provider passes through. With
// no provisioned device it must return the provider untouched, so a deployment
// that never commissioned a YubiHSM pays nothing — and, more importantly, does
// not acquire a signing-path hook pointing at a collector that does not exist.
func TestRecordHSMSignaturesIsInertWithoutAProvisionedDevice(t *testing.T) {
	prevRec, prevCol, prevNotify := signatureRecorder, hsmAuditCollector, hsmAuditNotify
	t.Cleanup(func() { signatureRecorder, hsmAuditCollector, hsmAuditNotify = prevRec, prevCol, prevNotify })

	signatureRecorder, hsmAuditCollector = nil, nil
	p, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	if got := recordHSMSignatures(p); got != keyprovider.Provider(p) {
		t.Fatal("the provider was wrapped even though no device is provisioned")
	}
}
