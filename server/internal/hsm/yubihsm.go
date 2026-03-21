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
	return string(out), nil
}

// YubiHSM command codes for audit log entries
const (
	CmdPutOption              = 0x4f
	CmdGenerateAsymmetricKey  = 0x46
	CmdSignECDSA              = 0x56
	CmdSignEdDSA              = 0x6a
	CmdSignRSAPKCS1           = 0x47
	CmdSignRSAPSS             = 0x55
	CmdPutAuthKey             = 0x44
	CmdChangeAuthKey          = 0x6c
	CmdDeleteObject           = 0x58
	CmdPutWrapKey             = 0x4c
	CmdGenerateWrapKey        = 0x5b
	CmdPutPubWrapKey          = 0x73
	CmdExportRSAWrapped       = 0x74
	CmdImportRSAWrapped       = 0x75
	CmdExportRSAWrappedObj    = 0x76
	CmdImportRSAWrappedObj    = 0x77
	CmdExportWrapped          = 0x4a
	CmdImportWrapped          = 0x4b
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
	0xff: "BOOT SENTINEL",
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

// ProvisionAuditLogging enables forced, irreversible audit logging for all
// cryptographic operations on the YubiHSM. This follows the protocol described in:
// https://gist.github.com/karalabe/fb7ac43f3899f511b5547279c036bf4e
//
// After provisioning:
// - PUT OPTION itself is force-audited (irreversible)
// - All sign commands (ECDSA, EdDSA, RSA) are force-audited
// - Asymmetric key generation is force-audited
// - Auth key operations are force-audited
// - Force-audit mode prevents log overwrites (HSM refuses ops until logs are consumed)
func ProvisionAuditLogging(cfg Config) (string, error) {
	commands := strings.Join([]string{
		// First enable PUT OPTION auditing (reversible), then force it (irreversible)
		"put option 0 command-audit 4f01",
		"put option 0 command-audit 4f02",
		// Force audit consumption (irreversible) — HSM refuses ops when log is full
		"put option 0 force-audit 02",
		// Force-audit all signing commands
		"put option 0 command-audit 5602", // SIGN ECDSA
		"put option 0 command-audit 6a02", // SIGN EDDSA
		"put option 0 command-audit 4702", // SIGN RSA PKCS1
		"put option 0 command-audit 5502", // SIGN RSA PSS
		// Force-audit key generation
		"put option 0 command-audit 4602", // GENERATE ASYMMETRIC KEY
		// Force-audit auth key operations
		"put option 0 command-audit 4402", // PUT AUTH KEY
		"put option 0 command-audit 6c02", // CHANGE AUTH KEY
		"put option 0 command-audit 5802", // DELETE OBJECT
		// Force-audit wrapping operations
		"put option 0 command-audit 4c02", // PUT WRAP KEY
		"put option 0 command-audit 5b02", // GENERATE WRAP KEY
		"put option 0 command-audit 7302", // PUT PUBLIC WRAP KEY
		"put option 0 command-audit 7402", // EXPORT RSA WRAPPED KEY
		"put option 0 command-audit 7502", // IMPORT RSA WRAPPED KEY
		"put option 0 command-audit 7602", // EXPORT RSA WRAPPED OBJECT
		"put option 0 command-audit 7702", // IMPORT RSA WRAPPED OBJECT
		"put option 0 command-audit 4a02", // EXPORT WRAPPED
		"put option 0 command-audit 4b02", // IMPORT WRAPPED
		// Retrieve the resulting audit log and options for verification
		"get option 0 command-audit",
		"get option 0 force-audit",
		"audit get 0",
	}, "\n")

	return runShell(cfg, commands)
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
	hashFile.Write(hashBytes)
	hashFile.Close()
	defer os.Remove(hashFile.Name())

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

// FetchAndConsumeAuditLog retrieves audit log entries and acknowledges them
// so the HSM can reuse the log slots. Returns only new entries.
func FetchAndConsumeAuditLog(cfg Config) ([]AuditLogEntry, error) {
	out, err := runShell(cfg, "audit get 0")
	if err != nil {
		return nil, err
	}

	entries, err := ParseAuditLogOutput(out)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	// Acknowledge up to the last entry so the HSM frees log slots
	lastNum := entries[len(entries)-1].Number
	_, err = runShell(cfg, fmt.Sprintf("audit set 0 %d", lastNum))
	if err != nil {
		return entries, fmt.Errorf("fetched %d entries but failed to consume: %w", len(entries), err)
	}

	return entries, nil
}

func GetDeviceAttestation(cfg Config) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "yubihsm-cert-*.der")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	out, err := runShell(cfg, fmt.Sprintf("get opaque 0 0 %s", tmpPath))
	if err != nil {
		return nil, fmt.Errorf("getting device attestation: %w\n%s", err, out)
	}
	return os.ReadFile(tmpPath)
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

func ParseAuditLogOutput(output string) ([]AuditLogEntry, error) {
	matches := auditLineRe.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no audit log entries found in output")
	}

	var entries []AuditLogEntry
	for _, m := range matches {
		num, _ := strconv.ParseUint(m[1], 10, 16)
		cmd, _ := strconv.ParseUint(m[2], 16, 8)
		length, _ := strconv.ParseUint(m[3], 10, 16)
		sessionKey, _ := strconv.ParseUint(m[4], 16, 16)
		targetKey, _ := strconv.ParseUint(m[5], 16, 16)
		secondKey, _ := strconv.ParseUint(m[6], 16, 16)
		result, _ := strconv.ParseUint(m[7], 16, 8)
		tick, _ := strconv.ParseUint(m[8], 10, 32)
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
