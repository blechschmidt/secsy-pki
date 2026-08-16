// Package hsm provides YubiHSM audit-log verification, device attestation, and yubihsm-shell-backed helpers.
package hsm

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	return "http://localhost:12345"
}

func runShell(cfg Config, commands string) (string, error) {
	connector := connectorArg(cfg)
	authKey := cfg.AuthKeyID
	if authKey == 0 {
		authKey = 1
	}
	password := cfg.Password
	if password == "" {
		password = "password"
	}

	script := fmt.Sprintf("connect\nsession open %d %s\n%s\nsession close 0\nexit\n", authKey, password, commands)
	cmd := exec.Command("yubihsm-shell", "-C", connector)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("yubihsm-shell failed: %w\nOutput: %s", err, out)
	}
	if failure := scriptFailure(string(out)); failure != "" {
		return string(out), fmt.Errorf("yubihsm-shell reported failure: %s\nOutput: %s", failure, out)
	}
	return string(out), nil
}

// shellFailureRe matches the in-band error lines yubihsm-shell prints.
//
// The binary exits 0 even when a scripted command fails — a rejected "put
// option", a refused session, an unreachable connector all produce an error
// line on stdout and status 0. Trusting the exit status alone would let
// provisioning report that force-audit is enabled when the device rejected the
// change, which is precisely the state in which unlogged signing becomes
// possible. Every command therefore has its output scanned.
var shellFailureRe = regexp.MustCompile(`(?im)^\s*(Failed [^\n]*|Unable to [^\n]*|Not connected[^\n]*|Invalid argument[^\n]*|Command failed[^\n]*|Error: [^\n]*)$`)

// scriptFailure returns the first in-band failure line in the shell output, or
// "" when the output is clean.
func scriptFailure(out string) string {
	m := shellFailureRe.FindStringSubmatch(out)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
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
func FactoryReset(cfg Config) error {
	out, err := runShell(cfg, "reset 0")
	if err != nil {
		return fmt.Errorf("factory reset failed: %w\n%s", err, out)
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
				"  yubihsm-shell> reset 0\n" +
				"Then re-run provisioning")
	}
	if !IsBootSentinel(entries[0]) {
		return fmt.Errorf(
			"audit log does not start with a device init entry (entry 1, all 0xff fields).\n" +
				"The device was not factory reset before provisioning.\n" +
				"There may be unaudited operations. Please factory reset the device first:\n" +
				"  yubihsm-shell> reset 0\n" +
				"Then re-run provisioning")
	}
	return nil
}

// ProvisionAuditLogging enables forced, irreversible audit logging on the
// YubiHSM for every command in forced.
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
func ProvisionAuditLogging(cfg Config, forced []uint8) (string, error) {
	cmds := []string{
		fmt.Sprintf("put option 0 command-audit %02x01", CmdPutOption),
		fmt.Sprintf("put option 0 command-audit %02x02", CmdPutOption),
		"put option 0 force-audit 02",
	}
	for _, c := range forced {
		if c == CmdPutOption {
			continue // already fixed above
		}
		cmds = append(cmds, fmt.Sprintf("put option 0 command-audit %02x02", c))
	}
	cmds = append(cmds,
		"get option 0 command-audit",
		"get option 0 force-audit",
	)
	return runShell(cfg, strings.Join(cmds, "\n"))
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

// signLastHash signs the last entry's hash with the attestation key and returns
// the signature, attestation cert, and device cert.
func signLastHash(cfg Config, lastHash string) (signature, attestCertPEM, deviceCertPEM string, err error) {
	if lastHash == "" {
		return "", "", "", fmt.Errorf("no entries to sign")
	}

	hashBytes, err := hex.DecodeString(lastHash)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid last hash: %w", err)
	}

	hashFile, err := os.CreateTemp("", "audit-hash-*.bin")
	if err != nil {
		return "", "", "", err
	}
	if _, err := hashFile.Write(hashBytes); err != nil {
		return "", "", "", err
	}
	if err := hashFile.Close(); err != nil {
		return "", "", "", err
	}
	defer func() { _ = os.Remove(hashFile.Name()) }()

	sigOut, err := runShell(cfg, fmt.Sprintf("sign eddsa 0 0x0001 ed25519 %s", hashFile.Name()))
	if err != nil {
		return "", "", "", fmt.Errorf("signing last hash: %w", err)
	}
	for _, line := range strings.Split(sigOut, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 40 && !strings.Contains(line, " ") {
			signature = line
		}
	}
	if signature == "" {
		return "", "", "", fmt.Errorf("could not parse signature from output: %s", sigOut)
	}

	attestOut, err := runShell(cfg, "attest asymmetric 0 0x0001")
	if err != nil {
		return "", "", "", fmt.Errorf("getting attestation cert: %w", err)
	}
	attestCertPEM = extractPEM(attestOut)
	if attestCertPEM == "" {
		return "", "", "", fmt.Errorf("could not parse attestation cert")
	}

	derBytes, err := GetDeviceAttestation(cfg)
	if err != nil {
		return "", "", "", fmt.Errorf("getting device cert: %w", err)
	}
	deviceCertPEM = string(pemEncode("CERTIFICATE", derBytes))

	return signature, attestCertPEM, deviceCertPEM, nil
}

// GetSignedAuditLog fetches the audit log and signs the last entry's hash
// with the HSM's attestation key (0x0001). The last hash is the HSM's own
// chain commitment — it depends on every previous entry.
func GetSignedAuditLog(cfg Config) (*SignedAuditLog, error) {
	auditLog, err := GetAuditLog(cfg)
	if err != nil {
		return nil, fmt.Errorf("getting audit log: %w", err)
	}
	if len(auditLog.Entries) == 0 {
		return nil, fmt.Errorf("no audit log entries")
	}

	lastHash := auditLog.Entries[len(auditLog.Entries)-1].Hash
	sig, attestCert, deviceCert, err := signLastHash(cfg, lastHash)
	if err != nil {
		return nil, err
	}

	return &SignedAuditLog{
		DeviceSerial:       auditLog.DeviceSerial,
		Entries:            auditLog.Entries,
		LastHash:           lastHash,
		Signature:          sig,
		AttestationCertPEM: attestCert,
		DeviceCertPEM:      deviceCert,
		ExportedAt:         time.Now().UTC(),
	}, nil
}

// GetKeyAttestationCert gets an attestation certificate for a key by its label.
func GetKeyAttestationCert(cfg Config, keyLabel string) (string, error) {
	// First find the key's object ID
	out, err := runShell(cfg, "list objects 0")
	if err != nil {
		return "", err
	}
	// Parse "id: 0x50dd, type: asymmetric-key, ..., label: ssh-pki-root-ca"
	re := regexp.MustCompile(`id:\s+0x([0-9a-fA-F]+),\s+type:\s+asymmetric-key,.*label:\s+` + regexp.QuoteMeta(keyLabel))
	m := re.FindStringSubmatch(out)
	if len(m) < 2 {
		return "", fmt.Errorf("key %q not found on HSM", keyLabel)
	}
	keyID := m[1]

	attestOut, err := runShell(cfg, fmt.Sprintf("attest asymmetric 0 0x%s", keyID))
	if err != nil {
		return "", fmt.Errorf("attesting key 0x%s: %w", keyID, err)
	}
	cert := extractPEM(attestOut)
	if cert == "" {
		return "", fmt.Errorf("could not parse attestation cert for key 0x%s", keyID)
	}
	return cert, nil
}

// SignAuditEntries signs the last entry's hash for pre-collected entries (e.g., from a database).
func SignAuditEntries(cfg Config, entries []AuditLogEntry) (*SignedAuditLog, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries to sign")
	}

	serial, _ := GetDeviceSerial(cfg)
	lastHash := entries[len(entries)-1].Hash

	sig, attestCert, deviceCert, err := signLastHash(cfg, lastHash)
	if err != nil {
		return nil, err
	}

	return &SignedAuditLog{
		DeviceSerial:       serial,
		Entries:            entries,
		LastHash:           lastHash,
		Signature:          sig,
		AttestationCertPEM: attestCert,
		DeviceCertPEM:      deviceCert,
		ExportedAt:         time.Now().UTC(),
	}, nil
}

func extractPEM(output string) string {
	start := strings.Index(output, "-----BEGIN CERTIFICATE-----")
	if start < 0 {
		return ""
	}
	end := strings.Index(output[start:], "-----END CERTIFICATE-----")
	if end < 0 {
		return ""
	}
	return output[start : start+end+len("-----END CERTIFICATE-----")]
}

func pemEncode(blockType string, data []byte) []byte {
	return []byte("-----BEGIN " + blockType + "-----\n" +
		base64Encode(data) +
		"-----END " + blockType + "-----\n")
}

func base64Encode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var lines string
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		lines += encoded[i:end] + "\n"
	}
	return lines
}

// SignCommands is the subset of CryptoCommands that are signing operations (not keygen).
var SignCommands = map[uint8]string{
	CmdSignECDSA:    "SIGN ECDSA",
	CmdSignEdDSA:    "SIGN EDDSA",
	CmdSignRSAPKCS1: "SIGN RSA PKCS1",
	CmdSignRSAPSS:   "SIGN RSA PSS",
}

// FetchLog retrieves the unconsumed device log entries and the
// unlogged-operation counters without acknowledging anything.
//
// Fetching and consuming are deliberately separate calls. Acknowledging frees
// the device's log slots and is irreversible: entries dropped after the
// acknowledgement but before they are durably stored are gone from the only
// place they existed. Callers must persist and verify a segment first, then
// call ConsumeLog.
func FetchLog(cfg Config) (*LogResponse, error) {
	out, err := runShell(cfg, "audit get 0")
	if err != nil {
		return nil, err
	}
	return ParseLogResponse(out)
}

// ConsumeLog acknowledges device log entries up to and including upTo, freeing
// those ring-buffer slots. Call it only after the segment is durably stored and
// its continuity verified.
func ConsumeLog(cfg Config, upTo uint16) error {
	if _, err := runShell(cfg, fmt.Sprintf("audit set 0 %d", upTo)); err != nil {
		return fmt.Errorf("consuming device log up to entry %d: %w", upTo, err)
	}
	return nil
}

// FetchAndConsumeAuditLog retrieves audit log entries and acknowledges them so
// the HSM can reuse the log slots.
//
// Deprecated: this acknowledges entries before the caller can store them, so a
// failure in between loses them permanently. Use FetchLog, persist, then
// ConsumeLog.
func FetchAndConsumeAuditLog(cfg Config) ([]AuditLogEntry, error) {
	resp, err := FetchLog(cfg)
	if err != nil {
		return nil, err
	}
	if len(resp.Entries) == 0 {
		return nil, nil
	}
	last := resp.Entries[len(resp.Entries)-1].Number
	if err := ConsumeLog(cfg, last); err != nil {
		return resp.Entries, fmt.Errorf("fetched %d entries but failed to consume: %w", len(resp.Entries), err)
	}
	return resp.Entries, nil
}

func GetDeviceAttestation(cfg Config) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "yubihsm-cert-*.der")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	out, err := runShell(cfg, fmt.Sprintf("get opaque 0 0 %s", tmpPath))
	if err != nil {
		return nil, fmt.Errorf("getting device attestation: %w\n%s", err, out)
	}
	return os.ReadFile(tmpPath)
}

type DeviceInfo struct {
	Version          string `json:"version"`
	Serial           string `json:"serial"`
	PartNumber       string `json:"part_number"`
	LogUsed          string `json:"log_used"`
	ForceAudit       bool   `json:"force_audit"`
	AuditProvisioned bool   `json:"audit_provisioned"` // all sign commands are force-audited
}

func GetDeviceInfo(cfg Config) (*DeviceInfo, error) {
	out, err := runShell(cfg, "get deviceinfo\nget option 0 force-audit\nget option 0 command-audit")
	if err != nil {
		return nil, err
	}

	info := &DeviceInfo{}

	if m := regexp.MustCompile(`Version number:\s+(.+)`).FindStringSubmatch(out); len(m) > 1 {
		info.Version = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`Serial number:\s+(\d+)`).FindStringSubmatch(out); len(m) > 1 {
		info.Serial = m[1]
	}
	if m := regexp.MustCompile(`Part number:\s+(.+)`).FindStringSubmatch(out); len(m) > 1 {
		info.PartNumber = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`Log used:\s+(.+)`).FindStringSubmatch(out); len(m) > 1 {
		info.LogUsed = strings.TrimSpace(m[1])
	}

	// Parse force-audit and command-audit options
	// They appear as "Option value is: XX" lines in order
	optionValues := regexp.MustCompile(`Option value is:\s+([0-9a-fA-F]+)`).FindAllStringSubmatch(out, -1)
	if len(optionValues) >= 1 {
		info.ForceAudit = optionValues[0][1] == "02"
	}
	if len(optionValues) >= 2 {
		info.AuditProvisioned = checkSignCommandsAudited(optionValues[1][1])
	}

	return info, nil
}

// checkSignCommandsAudited parses the command-audit hex string and verifies
// all sign commands are set to 0x02 (force-audited, irreversible).
func checkSignCommandsAudited(hexStr string) bool {
	// The hex string is pairs of (command_byte, audit_level) concatenated
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data)%2 != 0 {
		return false
	}

	required := map[byte]bool{
		CmdSignECDSA:             false,
		CmdSignEdDSA:             false,
		CmdSignRSAPKCS1:          false,
		CmdSignRSAPSS:            false,
		CmdGenerateAsymmetricKey: false,
	}

	for i := 0; i < len(data)-1; i += 2 {
		cmd := data[i]
		level := data[i+1]
		if _, need := required[cmd]; need {
			required[cmd] = (level == 0x02)
		}
	}

	for _, ok := range required {
		if !ok {
			return false
		}
	}
	return true
}

// AuditOptions is the device's raw audit configuration.
type AuditOptions struct {
	// ForceAudit is the global force-audit setting: 0 off, 1 on, 2 fixed.
	ForceAudit uint8 `json:"force_audit"`
	// CommandAudit maps a command byte to its audit level (0 off, 1 on, 2 fixed).
	CommandAudit map[uint8]uint8 `json:"command_audit"`
}

var optionValueRe = regexp.MustCompile(`(?i)Option value is:\s+([0-9a-fA-F]+)`)

// GetAuditOptions reads the force-audit and command-audit device options.
//
// The two options are fetched in separate shell invocations on purpose: the
// device prints them in an untagged "Option value is: <hex>" form, so reading
// both from one combined output means guessing which line is which from
// ordering. Separate calls remove that ambiguity — misreading the option that
// proves logging cannot be disabled would silently weaken every downstream
// claim.
func GetAuditOptions(cfg Config) (*AuditOptions, error) {
	force, err := getOptionValue(cfg, "force-audit")
	if err != nil {
		return nil, err
	}
	if len(force) != 1 {
		return nil, fmt.Errorf("force-audit option: expected 1 byte, got %d (%x)", len(force), force)
	}
	cmdAudit, err := getOptionValue(cfg, "command-audit")
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

func getOptionValue(cfg Config, name string) ([]byte, error) {
	out, err := runShell(cfg, "get option 0 "+name)
	if err != nil {
		return nil, fmt.Errorf("reading %s option: %w", name, err)
	}
	m := optionValueRe.FindStringSubmatch(out)
	if len(m) < 2 {
		return nil, fmt.Errorf("reading %s option: no value in output: %s", name, strings.TrimSpace(out))
	}
	raw, err := hex.DecodeString(m[1])
	if err != nil {
		return nil, fmt.Errorf("reading %s option: value %q is not hex: %w", name, m[1], err)
	}
	return raw, nil
}

func GetDeviceSerial(cfg Config) (string, error) {
	out, err := runShell(cfg, "get deviceinfo")
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`Serial number:\s+(\d+)`)
	m := re.FindStringSubmatch(out)
	if len(m) < 2 {
		return "", fmt.Errorf("could not parse device serial from output: %s", out)
	}
	return m[1], nil
}

func GetAuditLog(cfg Config) (*AuditLog, error) {
	out, err := runShell(cfg, "audit get 0")
	if err != nil {
		return nil, err
	}

	serial, _ := GetDeviceSerial(cfg)

	entries, err := ParseAuditLogOutput(out)
	if err != nil {
		return nil, err
	}

	return &AuditLog{
		DeviceSerial: serial,
		Entries:      entries,
		ExportedAt:   time.Now().UTC(),
	}, nil
}

var auditLineRe = regexp.MustCompile(
	`item:\s+(\d+)\s+--\s+cmd:\s+0x([0-9a-fA-F]+)\s+--\s+length:\s+(\d+)\s+--\s+session key:\s+0x([0-9a-fA-F]+)\s+--\s+target key:\s+0x([0-9a-fA-F]+)\s+--\s+second key:\s+0x([0-9a-fA-F]+)\s+--\s+result:\s+0x([0-9a-fA-F]+)\s+--\s+tick:\s+(\d+)\s+--\s+hash:\s+([0-9a-fA-F]+)`,
)

// The device reports, alongside the entries, how many boots and authentications
// it could not record because the log was full. Those counters are the device
// admitting its own log is incomplete, so they must be parsed and surfaced —
// discarding them would let unrecorded operations pass as a clean log.
var (
	unloggedBootsRe = regexp.MustCompile(`(\d+)\s+unlogged\s+boots?\s+found`)
	unloggedAuthsRe = regexp.MustCompile(`(\d+)\s+unlogged\s+authentications?\s+found`)
)

// LogResponse is a full parse of one "get-logs" response: the entries plus the
// device's unlogged-operation counters.
type LogResponse struct {
	Entries []AuditLogEntry `json:"entries"`
	// UnloggedBoots and UnloggedAuthentications are non-zero only when the log
	// overflowed. Any non-zero value invalidates the completeness claim.
	UnloggedBoots           uint16 `json:"unlogged_boots"`
	UnloggedAuthentications uint16 `json:"unlogged_authentications"`
}

// ParseLogResponse parses the full "get-logs" output, including the
// unlogged-operation counters. An empty entry list is not an error: a freshly
// consumed log legitimately has nothing new to report.
func ParseLogResponse(output string) (*LogResponse, error) {
	resp := &LogResponse{}
	if m := unloggedBootsRe.FindStringSubmatch(output); len(m) > 1 {
		n, err := strconv.ParseUint(m[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parsing unlogged boot count %q: %w", m[1], err)
		}
		resp.UnloggedBoots = uint16(n)
	}
	if m := unloggedAuthsRe.FindStringSubmatch(output); len(m) > 1 {
		n, err := strconv.ParseUint(m[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parsing unlogged authentication count %q: %w", m[1], err)
		}
		resp.UnloggedAuthentications = uint16(n)
	}
	entries, err := parseAuditLogEntries(output)
	if err != nil {
		return nil, err
	}
	resp.Entries = entries
	return resp, nil
}

// ParseAuditLogOutput parses only the entries and treats an empty log as an
// error. Prefer ParseLogResponse, which also surfaces the unlogged counters.
func ParseAuditLogOutput(output string) ([]AuditLogEntry, error) {
	entries, err := parseAuditLogEntries(output)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no audit log entries found in output")
	}
	return entries, nil
}

func parseAuditLogEntries(output string) ([]AuditLogEntry, error) {
	matches := auditLineRe.FindAllStringSubmatch(output, -1)

	// Field widths are enforced rather than discarded: an out-of-range value
	// means the output does not describe a YubiHSM log entry, and silently
	// truncating it would fabricate an entry that then fails to hash-verify for
	// the wrong reason.
	var entries []AuditLogEntry
	for _, m := range matches {
		var (
			num, cmd, length, sessionKey, targetKey, secondKey, result, tick uint64
			err                                                              error
		)
		for _, f := range []struct {
			dst     *uint64
			text    string
			base    int
			bitSize int
			name    string
		}{
			{&num, m[1], 10, 16, "item"},
			{&cmd, m[2], 16, 8, "cmd"},
			{&length, m[3], 10, 16, "length"},
			{&sessionKey, m[4], 16, 16, "session key"},
			{&targetKey, m[5], 16, 16, "target key"},
			{&secondKey, m[6], 16, 16, "second key"},
			{&result, m[7], 16, 8, "result"},
			{&tick, m[8], 10, 32, "tick"},
		} {
			if *f.dst, err = strconv.ParseUint(f.text, f.base, f.bitSize); err != nil {
				return nil, fmt.Errorf("audit log entry %q: field %s: %w", m[0], f.name, err)
			}
		}
		hash := strings.ToLower(m[9])

		entries = append(entries, AuditLogEntry{
			Number:     uint16(num),
			Command:    uint8(cmd),
			Length:     uint16(length),
			SessionKey: uint16(sessionKey),
			TargetKey:  uint16(targetKey),
			SecondKey:  uint16(secondKey),
			Result:     uint8(result),
			Tick:       uint32(tick),
			Hash:       hash,
		})
	}
	return entries, nil
}

// ComputeEntryHash computes the expected hash for an audit log entry.
// The hash is SHA256(entry_struct_BE || prev_hash)[:16].
// entry_struct_BE = number(2) + cmd(1) + length(2) + session_key(2) + target_key(2) + second_key(2) + result(1) + systick(4)
// All multi-byte fields are big-endian (network byte order), matching the YubiHSM SDK's yh_verify_logs.
func ComputeEntryHash(e AuditLogEntry, prevHash []byte) string {
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

	data := append(buf, prevHash...)
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
