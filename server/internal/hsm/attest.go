package hsm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// YubiHSM key attestation (Task 168).
//
// `attest asymmetric` makes the device sign a short-lived X.509 certificate
// over the public key of one of its own asymmetric objects, using the
// factory-provisioned attestation key. The certificate's Yubico extensions
// carry the device's assertions about that object — origin, capabilities,
// domains, on-device handle — which is how a relying party learns, without
// trusting the CA operator, that a CA signing key was generated inside the HSM
// and cannot be exported from it.
//
// Decoding and verification live in internal/hsmattest; this file only obtains
// the material.

// ObjectInfo is one row of the device object inventory.
type ObjectInfo struct {
	ID    uint16
	Type  string
	Algo  string
	Label string
}

// objectLine matches a `list objects` row. The label runs to end of line
// because YubiHSM labels may contain spaces and separators.
var objectLine = regexp.MustCompile(`id:\s*0x([0-9a-fA-F]{1,4}),\s*type:\s*(\S+?),\s*algo:\s*(\S+?),\s*sequence:\s*\d+,\s*label:\s*(.*)$`)

// ListObjects returns the device object inventory.
func ListObjects(cfg Config) ([]ObjectInfo, error) {
	out, err := runShell(cfg, "list objects 0")
	if err != nil {
		return nil, fmt.Errorf("listing HSM objects: %w", err)
	}
	var objs []ObjectInfo
	for _, line := range strings.Split(out, "\n") {
		m := objectLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		id, err := strconv.ParseUint(m[1], 16, 16)
		if err != nil {
			continue
		}
		objs = append(objs, ObjectInfo{
			ID:    uint16(id),
			Type:  strings.TrimSuffix(m[2], ","),
			Algo:  strings.TrimSuffix(m[3], ","),
			Label: strings.TrimSpace(m[4]),
		})
	}
	return objs, nil
}

// FindAsymmetricKey resolves a key label to its on-device object ID.
//
// The label must match exactly. An earlier implementation matched a prefix,
// which on a device holding both "ca-root" and "ca-root-backup" could attest a
// different key than the caller named — and an attestation naming the wrong
// key is worse than none, because it still verifies. A label shared by two
// objects is likewise refused rather than resolved arbitrarily.
func FindAsymmetricKey(cfg Config, label string) (uint16, error) {
	objs, err := ListObjects(cfg)
	if err != nil {
		return 0, err
	}
	var matches []ObjectInfo
	for _, o := range objs {
		if o.Type == "asymmetric-key" && o.Label == label {
			matches = append(matches, o)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("no asymmetric key labelled %q on the HSM", label)
	case 1:
		return matches[0].ID, nil
	default:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, fmt.Sprintf("0x%04x", m.ID))
		}
		return 0, fmt.Errorf("label %q is shared by %d asymmetric keys (%s); attest by object ID instead",
			label, len(matches), strings.Join(ids, ", "))
	}
}

// AttestAsymmetricKey asks the device to attest the asymmetric key with the
// given object ID and returns the attestation certificate in PEM form.
//
// attestKeyID selects the attesting key; 0 selects the factory-provisioned
// attestation key, whose certificate chains to Yubico's attestation PKI. A
// device owner may install their own attestation key instead, in which case
// the resulting certificate chains to whatever they installed — which is why
// the verifier reports the anchor it reached rather than assuming Yubico's.
func AttestAsymmetricKey(cfg Config, objectID, attestKeyID uint16) (string, error) {
	out, err := runShell(cfg, fmt.Sprintf("attest asymmetric 0 0x%04x 0x%04x", objectID, attestKeyID))
	if err != nil {
		return "", fmt.Errorf("attesting key 0x%04x: %w", objectID, err)
	}
	certPEM := extractPEM(out)
	if certPEM == "" {
		return "", fmt.Errorf("attesting key 0x%04x: no certificate in yubihsm-shell output", objectID)
	}
	return certPEM, nil
}
