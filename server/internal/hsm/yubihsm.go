// Package hsm provides YubiHSM audit-log verification, device attestation, and
// the device operations the audit and attestation subsystems need.
//
// Every device operation goes through internal/yubihsm, a native driver that
// speaks the YubiHSM's own SCP03 protocol over USB or a yubihsm-connector. It
// replaced a layer that shelled out to the yubihsm-shell binary and recovered
// results by regular expression over its human-readable output; see that
// package's documentation for why that mattered beyond tidiness.
package hsm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

type Config struct {
	ConnectorURL string
	AuthKeyID    int
	Password     string
}

type AuditLogEntry struct {
	Number     uint16 `json:"number"`
	Command    uint8  `json:"command"`
	Length     uint16 `json:"length"`
	SessionKey uint16 `json:"session_key"`
	TargetKey  uint16 `json:"target_key"`
	SecondKey  uint16 `json:"second_key"`
	Result     uint8  `json:"result"`
	Tick       uint32 `json:"tick"`
	Hash       string `json:"hash"`
}

type AuditLog struct {
	DeviceSerial string          `json:"device_serial"`
	Entries      []AuditLogEntry `json:"entries"`
	ExportedAt   time.Time       `json:"exported_at"`
}

// auditSigningKeyID is the on-device asymmetric key that signs audit-log heads
// and freshness attestations. Object ids are per-type on a YubiHSM, so this does
// not collide with the authentication key of the same id.
const auditSigningKeyID uint16 = 0x0001

// deviceAttestationObjectID is the opaque object holding the factory device
// attestation certificate, which anchors per-key attestations to Yubico's PKI.
const deviceAttestationObjectID uint16 = 0x0000

// nativeConfig adapts the package's configuration to the driver's.
//
// The connector is resolved the same way the PKCS#11 module resolves it, so a
// deployment that configured only YUBIHSM_PKCS11_CONF keeps working: the audit
// path and the signing path must address the same device, or the audit log would
// describe hardware other than the one holding the CA key.
func (c Config) nativeConfig() yubihsm.Config {
	return yubihsm.Config{
		ConnectorURL: connectorArg(c),
		AuthKeyID:    uint16(c.AuthKeyID),
		Password:     c.Password,
	}
}

func connectorArg(cfg Config) string {
	if cfg.ConnectorURL != "" {
		return cfg.ConnectorURL
	}
	if v := os.Getenv("YUBIHSM_PKCS11_CONF"); v != "" {
		data, err := os.ReadFile(v)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "connector") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	}
	return "yhusb://"
}

// withClient runs fn against an authenticated session and closes it afterwards.
//
// One session per operation, rather than one per device command: the shell-based
// predecessor opened and tore down a session for every single command, so a
// signed audit-log export cost four authentications and four device log entries
// where one now suffices.
func withClient(ctx context.Context, cfg Config, fn func(*yubihsm.Client) error) error {
	return yubihsm.WithSession(ctx, cfg.nativeConfig(), fn)
}

// YubiHSM command codes for audit log entries
const (
	CmdPutOption             = 0x4f
	CmdGenerateAsymmetricKey = 0x46
	CmdSignECDSA             = 0x56
	CmdSignEdDSA             = 0x6a
	CmdSignRSAPKCS1          = 0x47
	CmdSignRSAPSS            = 0x55
	CmdPutAuthKey            = 0x44
	CmdChangeAuthKey         = 0x6c
	CmdDeleteObject          = 0x58
	CmdPutWrapKey            = 0x4c
	CmdGenerateWrapKey       = 0x5b
	CmdPutPubWrapKey         = 0x73
	CmdExportRSAWrapped      = 0x74
	CmdImportRSAWrapped      = 0x75
	CmdExportRSAWrappedObj   = 0x76
	CmdImportRSAWrappedObj   = 0x77
	CmdExportWrapped         = 0x4a
	CmdImportWrapped         = 0x4b
)

// CryptoCommands lists all commands that involve signing or key generation.
var CryptoCommands = map[uint8]string{
	CmdGenerateAsymmetricKey: "GENERATE ASYMMETRIC KEY",
	CmdSignECDSA:             "SIGN ECDSA",
	CmdSignEdDSA:             "SIGN EDDSA",
	CmdSignRSAPKCS1:          "SIGN RSA PKCS1",
	CmdSignRSAPSS:            "SIGN RSA PSS",
}

// AllCommands maps every known YubiHSM command code to its name.
// The verifier must reject any entry with a command not in this map.
var AllCommands = map[uint8]string{
	0xff: "DEVICE INIT", // "When the device initializes after a reset, a log entry with all fields set to 0xff is logged." — https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html
	0x00: "BOOT",
	0x01: "ECHO",
	0x03: "CREATE SESSION",
	0x04: "AUTHENTICATE SESSION",
	0x05: "SESSION MESSAGE",
	0x06: "GET DEVICE INFO",
	0x08: "RESET DEVICE",
	0x0a: "GET DEVICE PUBKEY",
	0x40: "CLOSE SESSION",
	0x41: "GET STORAGE INFO",
	0x42: "PUT OPAQUE",
	0x43: "GET OPAQUE",
	0x44: "PUT AUTHENTICATION KEY",
	0x45: "PUT ASYMMETRIC KEY",
	0x46: "GENERATE ASYMMETRIC KEY",
	0x47: "SIGN PKCS1",
	0x48: "LIST OBJECTS",
	0x49: "DECRYPT PKCS1",
	0x4a: "EXPORT WRAPPED",
	0x4b: "IMPORT WRAPPED",
	0x4c: "PUT WRAP KEY",
	0x4d: "GET LOG ENTRIES",
	0x4e: "GET OBJECT INFO",
	0x4f: "SET OPTION",
	0x50: "GET OPTION",
	0x51: "GET PSEUDO RANDOM",
	0x52: "PUT HMAC KEY",
	0x53: "SIGN HMAC",
	0x54: "GET PUBLIC KEY",
	0x55: "SIGN PSS",
	0x56: "SIGN ECDSA",
	0x57: "DERIVE ECDH",
	0x58: "DELETE OBJECT",
	0x59: "DECRYPT OAEP",
	0x5a: "GENERATE HMAC KEY",
	0x5b: "GENERATE WRAP KEY",
	0x5c: "VERIFY HMAC",
	0x5d: "SIGN SSH CERTIFICATE",
	0x5e: "PUT TEMPLATE",
	0x5f: "GET TEMPLATE",
	0x60: "DECRYPT OTP",
	0x61: "CREATE OTP AEAD",
	0x62: "RANDOMIZE OTP AEAD",
	0x63: "REWRAP OTP AEAD",
	0x64: "SIGN ATTESTATION CERTIFICATE",
	0x65: "PUT OTP AEAD KEY",
	0x66: "GENERATE OTP AEAD KEY",
	0x67: "SET LOG INDEX",
	0x68: "WRAP DATA",
	0x69: "UNWRAP DATA",
	0x6a: "SIGN EDDSA",
	0x6b: "BLINK DEVICE",
	0x6c: "CHANGE AUTHENTICATION KEY",
	0x6d: "PUT SYMMETRIC KEY",
	0x6e: "GENERATE SYMMETRIC KEY",
	0x6f: "DECRYPT ECB",
	0x70: "ENCRYPT ECB",
	0x71: "DECRYPT CBC",
	0x72: "ENCRYPT CBC",
	0x73: "PUT PUBLIC WRAPKEY",
	0x74: "GET RSA WRAPPED KEY",
	0x75: "PUT RSA WRAPPED KEY",
	0x76: "EXPORT RSA WRAPPED",
	0x77: "IMPORT RSA WRAPPED",
}

// FactoryReset performs a factory reset of the YubiHSM, erasing all keys and logs.
func FactoryReset(ctx context.Context, cfg Config) error {
	if err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		return c.Reset(ctx)
	}); err != nil {
		return fmt.Errorf("factory reset failed: %w", err)
	}
	return nil
}

// IsBootSentinel returns true if the entry is a boot sentinel (first entry after factory reset).
func IsBootSentinel(e AuditLogEntry) bool {
	return e.Number == 1 && e.Command == 0xff && e.Length == 0xffff &&
		e.SessionKey == 0xffff && e.TargetKey == 0xffff &&
		e.SecondKey == 0xffff && e.Result == 0xff && e.Tick == 0xffffffff
}

// CheckDeviceInitEntry checks if the given entries start with a device init entry,
// proving the device was factory reset. Pass entries from the DB or HSM.
func CheckDeviceInitEntry(entries []AuditLogEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf(
			"no audit log entries found — cannot verify device state.\n" +
				"Please factory reset the device first:\n" +
				"  secsy-ca hsm-audit reset\n" +
				"Then re-run provisioning")
	}
	if !IsBootSentinel(entries[0]) {
		return fmt.Errorf(
			"audit log does not start with a device init entry (entry 1, all 0xff fields).\n" +
				"The device was not factory reset before provisioning.\n" +
				"There may be unaudited operations. Please factory reset the device first:\n" +
				"  secsy-ca hsm-audit reset\n" +
				"Then re-run provisioning")
	}
	return nil
}

// ProvisionAuditLogging enables forced, irreversible audit logging on the
// YubiHSM for every command in forced. It returns a human-readable report of the
// resulting device state.
//
// Ordering is deliberate and load-bearing:
//
//  1. PUT OPTION (0x4f) is set to audit level "fixed" before anything else, so
//     every subsequent option change — including the ones this function makes —
//     is itself recorded in the device log and can never stop being recorded.
//     Provisioning that is not self-auditing could be silently undone.
//  2. force-audit is set to "fixed" next, so the device begins refusing
//     auditable commands once the log fills rather than overwriting entries.
//     Setting it before the per-command levels means there is no window in
//     which a command is audited but its entries may be discarded.
//  3. Each command in forced is set to "fixed".
//
// Every level is 0x02 ("fixed"), not 0x01 ("on"), because "on" can be turned
// off again by anyone holding the authentication key. Level 0x02 survives until
// a factory reset, which itself writes a device-init entry that makes the break
// in history obvious.
//
// The caller must verify the device-init entry (CheckDeviceInitEntry) first, so
// that auditing is provisioned on a device with no prior unaudited operations.
func ProvisionAuditLogging(ctx context.Context, cfg Config, forced []uint8) (string, error) {
	var report string
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		// Enabling command-audit for PUT OPTION at level "on" first, then raising
		// it to "fixed", means the transition to fixed is itself the first
		// recorded option change.
		steps := [][2]byte{
			{CmdPutOption, 0x01},
			{CmdPutOption, 0x02},
		}
		for _, cmd := range forced {
			if cmd == CmdPutOption {
				continue // already fixed above
			}
			steps = append(steps, [2]byte{cmd, 0x02})
		}

		if err := c.PutOption(ctx, yubihsm.OptionCommandAudit, []byte{steps[0][0], steps[0][1]}); err != nil {
			return err
		}
		if err := c.PutOption(ctx, yubihsm.OptionCommandAudit, []byte{steps[1][0], steps[1][1]}); err != nil {
			return err
		}
		// force-audit is raised before the remaining per-command levels so there
		// is no window in which a command is audited but its entries may be
		// silently overwritten.
		if err := c.PutOption(ctx, yubihsm.OptionForceAudit, []byte{0x02}); err != nil {
			return err
		}
		for _, step := range steps[2:] {
			if err := c.PutOption(ctx, yubihsm.OptionCommandAudit, []byte{step[0], step[1]}); err != nil {
				return err
			}
		}

		// Read the settings back from the device and check them, rather than
		// reporting what was requested: the point of the exercise is that the
		// device, not this process, is the authority on whether logging can still
		// be disabled. A write the device declined must not be reported as
		// provisioning, because the operator's next step is to generate keys on
		// the strength of it.
		opts, err := readAuditOptions(ctx, c)
		if err != nil {
			return err
		}
		report = opts.Report()
		if opts.ForceAudit != 0x02 {
			return fmt.Errorf("device did not accept force-audit=fixed (it reports %s)", auditLevelName(opts.ForceAudit))
		}
		if !opts.signCommandsFixed() {
			return fmt.Errorf("device did not fix the audit level for every signing and key-generation command:\n%s", report)
		}
		return nil
	})
	if err != nil {
		return report, fmt.Errorf("provisioning forced audit logging: %w", err)
	}
	return report, nil
}

// SignedAuditLog is an audit log with a cryptographic signature from the HSM's
// attestation key over the last entry's hash. The last hash is the HSM's own
// commitment to the entire chain (each hash depends on all previous ones).
// The signature proves this specific HSM produced this chain.
type SignedAuditLog struct {
	DeviceSerial       string          `json:"device_serial"`
	Entries            []AuditLogEntry `json:"entries"`
	LastHash           string          `json:"last_hash"`            // hex last entry's hash (HSM-computed chain commitment)
	Signature          string          `json:"signature"`            // base64 Ed25519 signature of the last hash bytes
	AttestationCertPEM string          `json:"attestation_cert_pem"` // X.509 cert for the signing key
	DeviceCertPEM      string          `json:"device_cert_pem"`      // device attestation cert
	ExportedAt         time.Time       `json:"exported_at"`
}

// signLastHash signs the last entry's hash with the audit signing key and
// collects the certificates a remote verifier needs to check it.
func signLastHash(ctx context.Context, c *yubihsm.Client, lastHash string) (signature, attestCertPEM, deviceCertPEM string, err error) {
	if lastHash == "" {
		return "", "", "", fmt.Errorf("no entries to sign")
	}
	hashBytes, err := hex.DecodeString(lastHash)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid last hash: %w", err)
	}

	sig, err := c.SignEdDSA(ctx, auditSigningKeyID, hashBytes)
	if err != nil {
		return "", "", "", fmt.Errorf("signing last hash: %w", err)
	}

	attestDER, err := c.AttestAsymmetricKey(ctx, auditSigningKeyID, 0)
	if err != nil {
		return "", "", "", fmt.Errorf("getting attestation cert: %w", err)
	}
	deviceDER, err := c.GetOpaque(ctx, deviceAttestationObjectID)
	if err != nil {
		return "", "", "", fmt.Errorf("getting device cert: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig),
		encodeCertPEM(attestDER),
		encodeCertPEM(deviceDER),
		nil
}

func encodeCertPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// GetSignedAuditLog fetches the audit log and signs the last entry's hash
// with the HSM's audit signing key. The last hash is the HSM's own chain
// commitment — it depends on every previous entry.
func GetSignedAuditLog(ctx context.Context, cfg Config) (*SignedAuditLog, error) {
	var out *SignedAuditLog
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			return err
		}
		log, err := c.GetLogEntries(ctx)
		if err != nil {
			return err
		}
		entries := convertEntries(log.Entries)
		if len(entries) == 0 {
			return fmt.Errorf("no audit log entries")
		}
		lastHash := entries[len(entries)-1].Hash
		sig, attestCert, deviceCert, err := signLastHash(ctx, c, lastHash)
		if err != nil {
			return err
		}
		out = &SignedAuditLog{
			DeviceSerial:       info.Serial,
			Entries:            entries,
			LastHash:           lastHash,
			Signature:          sig,
			AttestationCertPEM: attestCert,
			DeviceCertPEM:      deviceCert,
			ExportedAt:         time.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SignAuditEntries signs the last entry's hash for pre-collected entries (e.g., from a database).
func SignAuditEntries(ctx context.Context, cfg Config, entries []AuditLogEntry) (*SignedAuditLog, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries to sign")
	}
	var out *SignedAuditLog
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			return err
		}
		lastHash := entries[len(entries)-1].Hash
		sig, attestCert, deviceCert, err := signLastHash(ctx, c, lastHash)
		if err != nil {
			return err
		}
		out = &SignedAuditLog{
			DeviceSerial:       info.Serial,
			Entries:            entries,
			LastHash:           lastHash,
			Signature:          sig,
			AttestationCertPEM: attestCert,
			DeviceCertPEM:      deviceCert,
			ExportedAt:         time.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SignCommands is the subset of CryptoCommands that are signing operations (not keygen).
var SignCommands = map[uint8]string{
	CmdSignECDSA:    "SIGN ECDSA",
	CmdSignEdDSA:    "SIGN EDDSA",
	CmdSignRSAPKCS1: "SIGN RSA PKCS1",
	CmdSignRSAPSS:   "SIGN RSA PSS",
}

// LogResponse is a full parse of one GET LOG ENTRIES response: the entries plus
// the device's unlogged-operation counters.
type LogResponse struct {
	Entries []AuditLogEntry `json:"entries"`
	// UnloggedBoots and UnloggedAuthentications are non-zero only when the log
	// overflowed. Any non-zero value invalidates the completeness claim.
	UnloggedBoots           uint16 `json:"unlogged_boots"`
	UnloggedAuthentications uint16 `json:"unlogged_authentications"`
}

// convertEntries maps driver log records to this package's representation. The
// digest is kept as lowercase hex because it is stored and transported that way
// throughout the audit subsystem.
func convertEntries(in []yubihsm.LogEntry) []AuditLogEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]AuditLogEntry, 0, len(in))
	for _, e := range in {
		out = append(out, AuditLogEntry{
			Number:     e.Number,
			Command:    e.Command,
			Length:     e.Length,
			SessionKey: e.SessionKey,
			TargetKey:  e.TargetKey,
			SecondKey:  e.SecondKey,
			Result:     e.Result,
			Tick:       e.Tick,
			Hash:       hex.EncodeToString(e.Digest[:]),
		})
	}
	return out
}

// FetchLog retrieves the unconsumed device log entries and the
// unlogged-operation counters without acknowledging anything.
//
// Fetching and consuming are deliberately separate calls. Acknowledging frees
// the device's log slots and is irreversible: entries dropped after the
// acknowledgement but before they are durably stored are gone from the only
// place they existed. Callers must persist and verify a segment first, then
// call ConsumeLog.
func FetchLog(ctx context.Context, cfg Config) (*LogResponse, error) {
	var out *LogResponse
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		log, err := c.GetLogEntries(ctx)
		if err != nil {
			return err
		}
		out = &LogResponse{
			Entries:                 convertEntries(log.Entries),
			UnloggedBoots:           log.UnloggedBoots,
			UnloggedAuthentications: log.UnloggedAuthentications,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConsumeLog acknowledges device log entries up to and including upTo, freeing
// those ring-buffer slots. Call it only after the segment is durably stored and
// its continuity verified.
func ConsumeLog(ctx context.Context, cfg Config, upTo uint16) error {
	return withClient(ctx, cfg, func(c *yubihsm.Client) error {
		return c.SetLogIndex(ctx, upTo)
	})
}

// FetchAndConsumeAuditLog retrieves audit log entries and acknowledges them so
// the HSM can reuse the log slots.
//
// Deprecated: this acknowledges entries before the caller can store them, so a
// failure in between loses them permanently. Use FetchLog, persist, then
// ConsumeLog.
func FetchAndConsumeAuditLog(ctx context.Context, cfg Config) ([]AuditLogEntry, error) {
	var entries []AuditLogEntry
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		log, err := c.GetLogEntries(ctx)
		if err != nil {
			return err
		}
		entries = convertEntries(log.Entries)
		if len(entries) == 0 {
			return nil
		}
		last := entries[len(entries)-1].Number
		if err := c.SetLogIndex(ctx, last); err != nil {
			return fmt.Errorf("fetched %d entries but failed to consume: %w", len(entries), err)
		}
		return nil
	})
	if err != nil {
		return entries, err
	}
	return entries, nil
}

// GetDeviceAttestation returns the factory device attestation certificate in
// DER form.
func GetDeviceAttestation(ctx context.Context, cfg Config) ([]byte, error) {
	var der []byte
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		b, err := c.GetOpaque(ctx, deviceAttestationObjectID)
		if err != nil {
			return err
		}
		der = b
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("getting device attestation: %w", err)
	}
	return der, nil
}

type DeviceInfo struct {
	Version          string `json:"version"`
	Serial           string `json:"serial"`
	PartNumber       string `json:"part_number"`
	LogUsed          string `json:"log_used"`
	ForceAudit       bool   `json:"force_audit"`
	AuditProvisioned bool   `json:"audit_provisioned"` // all sign commands are force-audited
}

func GetDeviceInfo(ctx context.Context, cfg Config) (*DeviceInfo, error) {
	out := &DeviceInfo{}
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			return err
		}
		out.Version = info.Version
		out.Serial = info.Serial
		out.PartNumber = info.PartNumber
		out.LogUsed = info.LogCapacity()

		opts, err := readAuditOptions(ctx, c)
		if err != nil {
			return err
		}
		out.ForceAudit = opts.ForceAudit == 0x02
		out.AuditProvisioned = opts.signCommandsFixed()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuditOptions is the device's raw audit configuration.
type AuditOptions struct {
	// ForceAudit is the global force-audit setting: 0 off, 1 on, 2 fixed.
	ForceAudit uint8 `json:"force_audit"`
	// CommandAudit maps a command byte to its audit level (0 off, 1 on, 2 fixed).
	CommandAudit map[uint8]uint8 `json:"command_audit"`
}

// signCommandsFixed reports whether every signing and key-generation command is
// at level "fixed", the state in which the device cannot be made to sign without
// recording it.
func (o *AuditOptions) signCommandsFixed() bool {
	for _, cmd := range []uint8{
		CmdSignECDSA, CmdSignEdDSA, CmdSignRSAPKCS1, CmdSignRSAPSS, CmdGenerateAsymmetricKey,
	} {
		if o.CommandAudit[cmd] != 0x02 {
			return false
		}
	}
	return true
}

// Report renders the audit configuration for an operator, listing the commands
// that are not irreversibly audited rather than only summarising.
func (o *AuditOptions) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "force-audit: %s\n", auditLevelName(o.ForceAudit))
	cmds := make([]int, 0, len(o.CommandAudit))
	for cmd := range o.CommandAudit {
		cmds = append(cmds, int(cmd))
	}
	sort.Ints(cmds)
	var notFixed []string
	for _, cmd := range cmds {
		if level := o.CommandAudit[uint8(cmd)]; level != 0x02 {
			name := AllCommands[uint8(cmd)]
			if name == "" {
				name = "UNDOCUMENTED COMMAND"
			}
			notFixed = append(notFixed, fmt.Sprintf("0x%02x %s=%s", cmd, name, auditLevelName(level)))
		}
	}
	fmt.Fprintf(&b, "command-audit: %d commands, %d not fixed\n", len(cmds), len(notFixed))
	for _, s := range notFixed {
		fmt.Fprintf(&b, "  %s\n", s)
	}
	return b.String()
}

func auditLevelName(level uint8) string {
	switch level {
	case 0x00:
		return "off"
	case 0x01:
		return "on"
	case 0x02:
		return "fixed"
	default:
		return fmt.Sprintf("unknown(0x%02x)", level)
	}
}

// GetAuditOptions reads the force-audit and command-audit device options.
func GetAuditOptions(ctx context.Context, cfg Config) (*AuditOptions, error) {
	var out *AuditOptions
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		opts, err := readAuditOptions(ctx, c)
		if err != nil {
			return err
		}
		out = opts
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func readAuditOptions(ctx context.Context, c *yubihsm.Client) (*AuditOptions, error) {
	force, err := c.GetOption(ctx, yubihsm.OptionForceAudit)
	if err != nil {
		return nil, err
	}
	if len(force) != 1 {
		return nil, fmt.Errorf("force-audit option: expected 1 byte, got %d (%x)", len(force), force)
	}
	cmdAudit, err := c.GetOption(ctx, yubihsm.OptionCommandAudit)
	if err != nil {
		return nil, err
	}
	if len(cmdAudit)%2 != 0 {
		return nil, fmt.Errorf("command-audit option: expected (command, level) pairs, got %d bytes (%x)", len(cmdAudit), cmdAudit)
	}
	opts := &AuditOptions{ForceAudit: force[0], CommandAudit: make(map[uint8]uint8, len(cmdAudit)/2)}
	for i := 0; i+1 < len(cmdAudit); i += 2 {
		opts.CommandAudit[cmdAudit[i]] = cmdAudit[i+1]
	}
	return opts, nil
}

// GetDeviceSerial reads the device serial over an authenticated session.
//
// The device answers GET DEVICE INFO outside a session too, which would be one
// round trip cheaper — but this serial is stamped into audit exports as the
// identity of the device they describe, and an unauthenticated answer is one
// that anything able to reply on the transport could have written. Liveness
// probing, where that does not matter, uses yubihsm.TransportDeviceInfo.
func GetDeviceSerial(ctx context.Context, cfg Config) (string, error) {
	var serial string
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			return err
		}
		serial = info.Serial
		return nil
	})
	if err != nil {
		return "", err
	}
	return serial, nil
}

func GetAuditLog(ctx context.Context, cfg Config) (*AuditLog, error) {
	var out *AuditLog
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		info, err := c.DeviceInfo(ctx)
		if err != nil {
			return err
		}
		log, err := c.GetLogEntries(ctx)
		if err != nil {
			return err
		}
		entries := convertEntries(log.Entries)
		if len(entries) == 0 {
			return fmt.Errorf("no audit log entries found")
		}
		out = &AuditLog{
			DeviceSerial: info.Serial,
			Entries:      entries,
			ExportedAt:   time.Now().UTC(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EntryData renders the 16 bytes of an entry that go into the chain digest,
// exactly as they appear on the wire.
//
// entry_data = number(2) + cmd(1) + length(2) + session_key(2) + target_key(2) +
// second_key(2) + result(1) + systick(4), all multi-byte fields big-endian
// (network byte order), matching the YubiHSM SDK's yh_verify_logs.
//
// It is exported because it is the *preimage* a verifier reasons about, not
// merely an implementation detail of the digest: whether a given chain digest
// can be re-derived at all is a question about this byte string. See
// hsmaudit.SentinelPreimage.
func EntryData(e AuditLogEntry) []byte {
	buf := make([]byte, 16)
	buf[0] = byte(e.Number >> 8)
	buf[1] = byte(e.Number)
	buf[2] = e.Command
	buf[3] = byte(e.Length >> 8)
	buf[4] = byte(e.Length)
	buf[5] = byte(e.SessionKey >> 8)
	buf[6] = byte(e.SessionKey)
	buf[7] = byte(e.TargetKey >> 8)
	buf[8] = byte(e.TargetKey)
	buf[9] = byte(e.SecondKey >> 8)
	buf[10] = byte(e.SecondKey)
	buf[11] = e.Result
	buf[12] = byte(e.Tick >> 24)
	buf[13] = byte(e.Tick >> 16)
	buf[14] = byte(e.Tick >> 8)
	buf[15] = byte(e.Tick)
	return buf
}

// ComputeEntryHash computes the expected hash for an audit log entry.
// The hash is SHA256(EntryData(e) || prev_hash)[:16].
func ComputeEntryHash(e AuditLogEntry, prevHash []byte) string {
	data := append(EntryData(e), prevHash...)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:16])
}

// VerifyHashChain verifies the integrity of a sequence of audit log entries.
// Returns per-entry pass/fail results. The first entry is the chain anchor.
func VerifyHashChain(entries []AuditLogEntry) ([]bool, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries to verify")
	}

	results := make([]bool, len(entries))
	results[0] = true // first entry is the anchor

	for i := 1; i < len(entries); i++ {
		prevHash, err := hex.DecodeString(entries[i-1].Hash)
		if err != nil {
			return results, fmt.Errorf("invalid hash at entry %d: %w", i-1, err)
		}
		computed := ComputeEntryHash(entries[i], prevHash)
		results[i] = computed == entries[i].Hash
	}

	return results, nil
}
