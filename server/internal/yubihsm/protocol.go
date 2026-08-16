package yubihsm

import (
	"encoding/binary"
	"fmt"
)

// YubiHSM 2 wire protocol: framing, command codes, and device error codes.
//
// Every message — on USB, through the connector, and inside an SCP03 session —
// is the same three-byte header followed by its payload:
//
//	command (1) | length (2, big endian) | data (length)
//
// A successful response echoes the command with the high bit set; a failure
// comes back as cmdError with a single device error byte, whatever the command
// was. There is no other in-band signalling, which is the point of moving off
// yubihsm-shell: the shell reports the same information as English prose on
// stdout, with a zero exit status even for a rejected command, so callers had to
// recognise failure by regular expression (see the removed scriptFailure).

// Command codes. Only the subset this codebase issues is listed; the full table
// of command *names*, needed to interpret audit-log entries, lives in
// internal/hsm.AllCommands.
const (
	cmdEcho                  byte = 0x01
	cmdCreateSession         byte = 0x03
	cmdAuthenticateSession   byte = 0x04
	cmdSessionMessage        byte = 0x05
	cmdGetDeviceInfo         byte = 0x06
	cmdResetDevice           byte = 0x08
	cmdCloseSession          byte = 0x40
	cmdGetOpaque             byte = 0x43
	cmdPutAsymmetricKey      byte = 0x45
	cmdGenerateAsymmetricKey byte = 0x46
	cmdListObjects           byte = 0x48
	cmdGetLogEntries         byte = 0x4d
	cmdGetObjectInfo         byte = 0x4e
	cmdPutOption             byte = 0x4f
	cmdGetOption             byte = 0x50
	cmdGetPseudoRandom       byte = 0x51
	cmdGetPublicKey          byte = 0x54
	cmdSignECDSA             byte = 0x56
	cmdDeleteObject          byte = 0x58
	cmdSignAttestationCert   byte = 0x64
	cmdSetLogIndex           byte = 0x67
	cmdSignEdDSA             byte = 0x6a

	// cmdError is the response code for any failed command.
	cmdError byte = 0x7f
	// responseFlag is ORed into the command code of a successful response.
	responseFlag byte = 0x80
)

// Option identifiers for GET/PUT OPTION.
const (
	// OptionForceAudit is the global "refuse auditable commands once the log is
	// full" switch.
	OptionForceAudit byte = 0x01
	// OptionCommandAudit is the per-command audit level map, encoded as
	// (command, level) byte pairs.
	OptionCommandAudit byte = 0x03
	// OptionAlgorithmToggle enables or disables individual algorithms.
	OptionAlgorithmToggle byte = 0x04
	// OptionFIPSMode reports/sets FIPS mode on YubiHSM 2 FIPS devices.
	OptionFIPSMode byte = 0x05
)

// Object types.
const (
	ObjectTypeOpaque            byte = 0x01
	ObjectTypeAuthenticationKey byte = 0x02
	ObjectTypeAsymmetricKey     byte = 0x03
	ObjectTypeWrapKey           byte = 0x04
	ObjectTypeHMACKey           byte = 0x05
	ObjectTypeTemplate          byte = 0x06
	ObjectTypeOTPAEADKey        byte = 0x07
	ObjectTypeSymmetricKey      byte = 0x08
)

// ObjectTypeName renders a device object type for humans.
func ObjectTypeName(t byte) string {
	switch t {
	case ObjectTypeOpaque:
		return "opaque"
	case ObjectTypeAuthenticationKey:
		return "authentication-key"
	case ObjectTypeAsymmetricKey:
		return "asymmetric-key"
	case ObjectTypeWrapKey:
		return "wrap-key"
	case ObjectTypeHMACKey:
		return "hmac-key"
	case ObjectTypeTemplate:
		return "template"
	case ObjectTypeOTPAEADKey:
		return "otp-aead-key"
	case ObjectTypeSymmetricKey:
		return "symmetric-key"
	default:
		return fmt.Sprintf("unknown(0x%02x)", t)
	}
}

// List-objects filter tags.
const (
	listFilterID   byte = 0x01
	listFilterType byte = 0x02
)

// DeviceError is a failure reported by the device itself, as opposed to a
// transport or protocol failure on the host.
type DeviceError byte

// Device error codes, from the YubiHSM 2 command reference.
const (
	ErrOK                       DeviceError = 0x00
	ErrInvalidCommand           DeviceError = 0x01
	ErrInvalidData              DeviceError = 0x02
	ErrInvalidSession           DeviceError = 0x03
	ErrAuthenticationFailed     DeviceError = 0x04
	ErrSessionsFull             DeviceError = 0x05
	ErrSessionFailed            DeviceError = 0x06
	ErrStorageFailed            DeviceError = 0x07
	ErrWrongLength              DeviceError = 0x08
	ErrInsufficientPermissions  DeviceError = 0x09
	ErrLogFull                  DeviceError = 0x0a
	ErrObjectNotFound           DeviceError = 0x0b
	ErrInvalidID                DeviceError = 0x0c
	ErrSSHCAConstraintViolation DeviceError = 0x0e
	ErrInvalidOTP               DeviceError = 0x0f
	ErrDemoMode                 DeviceError = 0x10
	ErrCommandUnexecuted        DeviceError = 0x11
	ErrDisabled                 DeviceError = 0x12
)

func (e DeviceError) Error() string {
	if s := deviceErrorNames[e]; s != "" {
		return fmt.Sprintf("device error 0x%02x (%s)", byte(e), s)
	}
	return fmt.Sprintf("device error 0x%02x", byte(e))
}

var deviceErrorNames = map[DeviceError]string{
	ErrOK:                       "ok",
	ErrInvalidCommand:           "invalid command",
	ErrInvalidData:              "invalid data",
	ErrInvalidSession:           "invalid session",
	ErrAuthenticationFailed:     "authentication failed",
	ErrSessionsFull:             "sessions full",
	ErrSessionFailed:            "session failed",
	ErrStorageFailed:            "storage failed",
	ErrWrongLength:              "wrong length",
	ErrInsufficientPermissions:  "insufficient permissions",
	ErrLogFull:                  "log full — the device is refusing auditable commands until the log is drained",
	ErrObjectNotFound:           "object not found",
	ErrInvalidID:                "invalid object id",
	ErrSSHCAConstraintViolation: "ssh ca constraint violation",
	ErrInvalidOTP:               "invalid otp",
	ErrDemoMode:                 "demo mode",
	ErrCommandUnexecuted:        "command not executed",
	ErrDisabled:                 "algorithm or capability disabled",
}

// maxMessageSize bounds a single protocol message. The device's own buffer is
// 2048 bytes of payload; the bound exists so a corrupt length field cannot make
// the host allocate or wait for an arbitrary amount of data.
const maxMessageSize = 3 + 2048

// frame builds a protocol message: command, big-endian length, payload.
func frame(cmd byte, data []byte) ([]byte, error) {
	if len(data) > maxMessageSize-3 {
		return nil, fmt.Errorf("message payload of %d bytes exceeds the device limit of %d", len(data), maxMessageSize-3)
	}
	msg := make([]byte, 3+len(data))
	msg[0] = cmd
	binary.BigEndian.PutUint16(msg[1:3], uint16(len(data)))
	copy(msg[3:], data)
	return msg, nil
}

// parseResponse validates a response frame against the command that produced it
// and returns the payload. A cmdError frame is turned into a DeviceError.
func parseResponse(want byte, raw []byte) ([]byte, error) {
	if len(raw) < 3 {
		return nil, fmt.Errorf("truncated response: %d bytes, want at least 3", len(raw))
	}
	n := int(binary.BigEndian.Uint16(raw[1:3]))
	if len(raw) < 3+n {
		return nil, fmt.Errorf("truncated response: header declares %d payload bytes, got %d", n, len(raw)-3)
	}
	body := raw[3 : 3+n]

	switch raw[0] {
	case want | responseFlag:
		return body, nil
	case cmdError:
		if len(body) < 1 {
			return nil, fmt.Errorf("device reported an error with no error code")
		}
		return nil, DeviceError(body[0])
	default:
		return nil, fmt.Errorf("unexpected response command 0x%02x for command 0x%02x", raw[0], want)
	}
}
