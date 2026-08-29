package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
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
	unforced := &optionsDevice{opts: &hsmaudit.Options{ForceAudit: hsmaudit.AuditOff}}
	if !perOperationCollection(&config.Config{}, unforced) {
		t.Fatal("per-operation collection is off by default")
	}
	on, off := true, false
	if !perOperationCollection(&config.Config{YubiHSM: config.YubiHSMConfig{AuditCollectPerOperation: &on}}, unforced) {
		t.Fatal("explicitly enabling per-operation collection turned it off")
	}
	if perOperationCollection(&config.Config{YubiHSM: config.YubiHSMConfig{AuditCollectPerOperation: &off}}, unforced) {
		t.Fatal("an operator could not turn per-operation collection off on a device that is not force-audited")
	}
	if unforced.calls == 0 {
		t.Fatal("the device was never asked whether it force-audits")
	}
}

// On a force-audited device the drain is not a preference. The device stops
// serving audited commands once 62 entries accumulate, so honouring
// audit_collect_per_operation: false there would let a configuration knob take
// the CA offline — and do it silently, minutes after startup, presenting as an
// HSM failure rather than as the setting that caused it.
func TestPerOperationCollectionIgnoresTheKnobOnAForceAuditedDevice(t *testing.T) {
	off := false
	cfg := &config.Config{YubiHSM: config.YubiHSMConfig{AuditCollectPerOperation: &off}}

	for _, level := range []hsmaudit.AuditLevel{hsmaudit.AuditOn, hsmaudit.AuditFixed} {
		dev := &optionsDevice{opts: &hsmaudit.Options{ForceAudit: level}}
		if !perOperationCollection(cfg, dev) {
			t.Errorf("force-audit=%s: per-operation collection was turned off; the device will wedge", level)
		}
	}

	// A device that cannot be asked is treated as force-audited. Guessing the
	// other way turns an unreachable device into an undrained one.
	unreadable := &optionsDevice{err: errors.New("device busy")}
	if !perOperationCollection(cfg, unreadable) {
		t.Error("per-operation collection was turned off although the device options could not be read")
	}
}

// optionsDevice is a hsmaudit.Device that only answers Options; the wiring
// under test asks nothing else, and a fake that pretended to serve log entries
// would invite a future test to depend on behaviour it does not have.
type optionsDevice struct {
	opts  *hsmaudit.Options
	err   error
	calls int
}

func (d *optionsDevice) Options(context.Context) (*hsmaudit.Options, error) {
	d.calls++
	return d.opts, d.err
}

func (d *optionsDevice) Info(context.Context) (*hsmaudit.DeviceInfo, error) {
	return nil, errors.New("optionsDevice: Info is not implemented")
}

func (d *optionsDevice) FetchLog(context.Context) (*hsm.LogResponse, error) {
	return nil, errors.New("optionsDevice: FetchLog is not implemented")
}

func (d *optionsDevice) ConsumeLog(context.Context, uint16) error {
	return errors.New("optionsDevice: ConsumeLog is not implemented")
}

func (d *optionsDevice) ProvisionAudit(context.Context, []uint8) (string, error) {
	return "", errors.New("optionsDevice: ProvisionAudit is not implemented")
}

// The append-only log file is opened before the first drain, and a path that
// cannot be written has to be found then rather than at the first collection.
func TestOpenAuditLogFile(t *testing.T) {
	if got := openAuditLogFile(&config.Config{}); got != nil {
		t.Fatal("a file was opened although none is configured")
	}
	path := filepath.Join(t.TempDir(), "nested", "hsm-audit.jsonl")
	f := openAuditLogFile(&config.Config{YubiHSM: config.YubiHSMConfig{AuditLogFile: path}})
	if f == nil {
		t.Fatal("the configured log file was not opened")
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the configured log file was not created: %v", err)
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
