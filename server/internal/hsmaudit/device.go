package hsmaudit

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
)

// Unlogged carries the device's own report of operations it could not record
// because the log was full. Non-zero values mean the device log has holes, so
// the completeness argument collapses and verification must fail.
type Unlogged struct {
	Boots           uint16 `json:"boots"`
	Authentications uint16 `json:"authentications"`
}

// Any reports whether the device admitted to any unrecorded operation.
func (u Unlogged) Any() bool { return u.Boots > 0 || u.Authentications > 0 }

// AuditLevel is the per-command (or global force-audit) audit setting.
type AuditLevel uint8

// YubiHSM audit option values. "Fixed" is the security-relevant one: it means
// the setting is locked until the next factory reset, so an operator who later
// steals the authentication key still cannot disable logging to sign unobserved.
const (
	AuditOff   AuditLevel = 0x00
	AuditOn    AuditLevel = 0x01
	AuditFixed AuditLevel = 0x02
)

func (l AuditLevel) String() string {
	switch l {
	case AuditOff:
		return "off"
	case AuditOn:
		return "on"
	case AuditFixed:
		return "fixed"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(l))
	}
}

// Options is the device's audit configuration: the global force-audit setting
// plus the per-command audit levels.
type Options struct {
	ForceAudit   AuditLevel           `json:"force_audit"`
	CommandAudit map[uint8]AuditLevel `json:"command_audit"`
}

// BaselineForcedCommands lists the commands this build knows to be dangerous
// and that must therefore be at AuditFixed for the "the HSM cannot have signed
// anything unlogged" claim to hold.
//
// It covers every signing command, plus the operations that could otherwise be
// used to obtain signing capability off the books: generating or importing a
// key, changing authentication keys, deleting objects (which would erase the
// evidence of a key's existence), and every wrap/export path (which could carry
// a private key off the device where it could sign without the HSM at all).
//
// It is a baseline, not the whole requirement. A hardcoded list can only cover
// commands that existed when it was written, and hardware validation showed
// that is not enough: a YubiHSM 2 running firmware 2.4.0 reports audit settings
// for commands 0x07 and 0x09, neither of which appears in Yubico's published
// command reference or in the yh_cmd enum of their own SDK header. Whatever
// those commands do, nothing here can prove they cannot sign or export a key.
// Options.RequiredForced therefore extends this baseline with every command the
// attached device reports that this build does not recognise. See that method.
var BaselineForcedCommands = []uint8{
	hsm.CmdSignECDSA,
	hsm.CmdSignEdDSA,
	hsm.CmdSignRSAPKCS1,
	hsm.CmdSignRSAPSS,
	0x53, // SIGN HMAC
	0x5d, // SIGN SSH CERTIFICATE
	0x64, // SIGN ATTESTATION CERTIFICATE
	hsm.CmdGenerateAsymmetricKey,
	0x45, // PUT ASYMMETRIC KEY
	hsm.CmdPutAuthKey,
	hsm.CmdChangeAuthKey,
	hsm.CmdDeleteObject,
	hsm.CmdPutWrapKey,
	hsm.CmdGenerateWrapKey,
	hsm.CmdPutPubWrapKey,
	hsm.CmdExportWrapped,
	hsm.CmdImportWrapped,
	hsm.CmdExportRSAWrapped,
	hsm.CmdImportRSAWrapped,
	hsm.CmdExportRSAWrappedObj,
	hsm.CmdImportRSAWrappedObj,
	hsm.CmdPutOption, // so audit settings cannot be changed unobserved
}

// RequiredForced returns the commands that must be at AuditFixed on the
// specific device these options came from.
//
// It is the union of two sets:
//
//   - BaselineForcedCommands, the commands this build knows can sign or move
//     key material.
//   - Every command the device reports an audit setting for that this build
//     does not recognise. This is the important half. The device enumerates its
//     entire command set in the command-audit option, so an unrecognised entry
//     is a capability of the attached firmware that this code has no model of.
//     Treating it as harmless would mean the completeness claim rests on the
//     command table having been exhaustive, which hardware showed it is not
//     (see BaselineForcedCommands). Forcing it costs a log entry on the rare
//     occasions it runs and closes the hole permanently, including for firmware
//     released after this code was written.
//
// Deriving the set from the device rather than from a constant is what makes
// this work offline too: the command-audit map travels in the export bundle, so
// an auditor recomputes the same requirement from the bundle alone.
func (o *Options) RequiredForced() []uint8 {
	if o == nil {
		return nil
	}
	seen := make(map[uint8]bool, len(o.CommandAudit))
	var out []uint8
	add := func(c uint8) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, c := range BaselineForcedCommands {
		add(c)
	}
	for c := range o.CommandAudit {
		if _, known := hsm.AllCommands[c]; !known {
			add(c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Verify checks that the device is configured so that no signature can be
// produced without a log entry. It returns nil only when force-audit is fixed
// and every command in RequiredForced is fixed.
//
// AuditOn is deliberately not accepted: a merely-enabled setting can be turned
// off again by anyone holding the authentication key, and the whole point of
// the exercise is to hold even against an operator who has that key.
func (o *Options) Verify() error {
	if o == nil {
		return fmt.Errorf("device audit options unknown")
	}
	var problems []string
	if o.ForceAudit != AuditFixed {
		problems = append(problems, fmt.Sprintf(
			"force-audit is %s, want fixed (the device must refuse operations rather than overwrite log entries)",
			o.ForceAudit))
	}

	// A baseline command that the options do not mention at all is not a device
	// that happens to lack it — every YubiHSM 2 implements all of them. It is an
	// options set with the awkward entries removed, which is exactly how a
	// fabricated bundle would try to pass this check. Report it as missing
	// rather than silently skipping the requirement.
	var missing []string
	for _, cmd := range BaselineForcedCommands {
		if _, present := o.CommandAudit[cmd]; !present {
			missing = append(missing, fmt.Sprintf("0x%02x %s", cmd, hsm.AllCommands[cmd]))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		problems = append(problems, "device reports no audit setting for commands it must support: "+
			strings.Join(missing, ", ")+" (the options set is incomplete or was edited)")
	}

	var weak []string
	for _, cmd := range o.RequiredForced() {
		if _, present := o.CommandAudit[cmd]; !present {
			continue // already reported above
		}
		if o.CommandAudit[cmd] != AuditFixed {
			name := hsm.AllCommands[cmd]
			if name == "" {
				name = "UNDOCUMENTED COMMAND (not in this build's command table; " +
					"cannot be shown to be incapable of signing or key export)"
			}
			weak = append(weak, fmt.Sprintf("0x%02x %s=%s", cmd, name, o.CommandAudit[cmd]))
		}
	}
	if len(weak) > 0 {
		sort.Strings(weak)
		problems = append(problems, "commands not force-audited: "+strings.Join(weak, ", "))
	}
	if len(problems) > 0 {
		return fmt.Errorf("device audit configuration is insufficient: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ForceAuditEnabled reports whether the device is set to refuse auditable
// commands rather than overwrite log entries once its ring is full.
//
// "On" counts as well as "fixed". The two differ in whether an operator can
// turn the setting off again, which is what Verify cares about — but for
// deciding how urgently the log has to be drained they are identical: both make
// a full ring stop the HSM, so both make collection a liveness requirement
// rather than housekeeping.
func (o *Options) ForceAuditEnabled() bool { return o != nil && o.ForceAudit != AuditOff }

// ForceAuditEnabled reads dev's options and reports whether force-audit is on.
//
// It is the question the drain wiring asks at startup: a force-audited device
// stops serving the CA once 62 unacknowledged entries accumulate, so on such a
// device per-operation collection is not a tuning preference that configuration
// may switch off.
func ForceAuditEnabled(ctx context.Context, dev Device) (bool, error) {
	opts, err := dev.Options(ctx)
	if err != nil {
		return false, err
	}
	return opts.ForceAuditEnabled(), nil
}

// DeviceInfo identifies the device an export came from.
type DeviceInfo struct {
	Serial     string `json:"serial"`
	Version    string `json:"version"`
	PartNumber string `json:"part_number,omitempty"`
	// LogUsed is the device's "used/capacity" report for its log ring buffer,
	// e.g. "12/62". The collector watches it to drain before the device wedges.
	LogUsed string `json:"log_used,omitempty"`
}

// Device is the subset of YubiHSM operations the audit subsystem needs. It is
// an interface so the collector and export paths can be exercised against a
// scripted fake in unit tests, with the shell-backed implementation reserved
// for the hardware tests.
type Device interface {
	// Info returns device identity and log-usage information.
	Info(ctx context.Context) (*DeviceInfo, error)
	// FetchLog returns unconsumed entries and the unlogged-operation counters
	// without acknowledging anything.
	FetchLog(ctx context.Context) (*hsm.LogResponse, error)
	// ConsumeLog acknowledges entries up to and including upTo.
	ConsumeLog(ctx context.Context, upTo uint16) error
	// Options returns the device audit configuration.
	Options(ctx context.Context) (*Options, error)
	// ProvisionAudit raises the audit level of every command in forced to
	// "fixed", irreversibly until a factory reset, and returns a report.
	//
	// It is on the interface rather than reached through a config value because
	// this is the one irreversible operation in the subsystem, and the config
	// route was actively dangerous: a Device that was not a HardwareDevice
	// yielded a zero hsm.Config, whose empty connector URL resolves to the
	// default direct-USB one — so provisioning a scripted fake silently
	// force-audited whatever YubiHSM happened to be plugged into the machine.
	// Requiring the device itself to perform the step means a fake can only
	// provision itself.
	ProvisionAudit(ctx context.Context, forced []uint8) (string, error)
}

// HardwareDevice is the production Device, reaching the YubiHSM through the
// native driver in internal/yubihsm.
type HardwareDevice struct {
	Cfg hsm.Config
}

// NewHardwareDevice returns a Device backed by an attached YubiHSM.
func NewHardwareDevice(cfg hsm.Config) *HardwareDevice { return &HardwareDevice{Cfg: cfg} }

// ProvisionAudit force-audits the given commands on the attached device.
func (d *HardwareDevice) ProvisionAudit(ctx context.Context, forced []uint8) (string, error) {
	return hsm.ProvisionAuditLogging(ctx, d.Cfg, forced)
}

func (d *HardwareDevice) Info(ctx context.Context) (*DeviceInfo, error) {
	info, err := hsm.GetDeviceInfo(ctx, d.Cfg)
	if err != nil {
		return nil, err
	}
	return &DeviceInfo{
		Serial:     info.Serial,
		Version:    info.Version,
		PartNumber: info.PartNumber,
		LogUsed:    info.LogUsed,
	}, nil
}

func (d *HardwareDevice) FetchLog(ctx context.Context) (*hsm.LogResponse, error) {
	return hsm.FetchLog(ctx, d.Cfg)
}

func (d *HardwareDevice) ConsumeLog(ctx context.Context, upTo uint16) error {
	return hsm.ConsumeLog(ctx, d.Cfg, upTo)
}

func (d *HardwareDevice) Options(ctx context.Context) (*Options, error) {
	raw, err := hsm.GetAuditOptions(ctx, d.Cfg)
	if err != nil {
		return nil, err
	}
	opts := &Options{
		ForceAudit:   AuditLevel(raw.ForceAudit),
		CommandAudit: make(map[uint8]AuditLevel, len(raw.CommandAudit)),
	}
	for cmd, level := range raw.CommandAudit {
		opts.CommandAudit[cmd] = AuditLevel(level)
	}
	return opts, nil
}
