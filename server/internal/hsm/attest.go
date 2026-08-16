package hsm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/yubihsm"
)

// YubiHSM key attestation (Task 168).
//
// SIGN ATTESTATION CERTIFICATE makes the device sign a short-lived X.509
// certificate over the public key of one of its own asymmetric objects, using
// the factory-provisioned attestation key. The certificate's Yubico extensions
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

// ListObjects returns the device object inventory.
func ListObjects(ctx context.Context, cfg Config) ([]ObjectInfo, error) {
	var objs []ObjectInfo
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		handles, err := c.ListObjects(ctx, 0)
		if err != nil {
			return err
		}
		for _, h := range handles {
			// The listing carries only ids and types, so the label and algorithm
			// come from a per-object query. Only a deletion racing the listing is
			// tolerated; any other failure aborts, because this inventory is what
			// `hsm-attest audit` walks to decide which keys pass policy, and an
			// inventory silently short of the failing key would read as a clean
			// device.
			info, err := c.GetObjectInfo(ctx, h.ID, h.Type)
			if err != nil {
				var devErr yubihsm.DeviceError
				if errors.As(err, &devErr) && devErr == yubihsm.ErrObjectNotFound {
					continue
				}
				return err
			}
			objs = append(objs, ObjectInfo{
				ID:    h.ID,
				Type:  yubihsm.ObjectTypeName(h.Type),
				Algo:  yubihsm.AlgorithmName(info.Algorithm),
				Label: info.Label,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing HSM objects: %w", err)
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
func FindAsymmetricKey(ctx context.Context, cfg Config, label string) (uint16, error) {
	var id uint16
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		found, err := findAsymmetricKey(ctx, c, label)
		if err != nil {
			return err
		}
		id = found
		return nil
	})
	return id, err
}

func findAsymmetricKey(ctx context.Context, c *yubihsm.Client, label string) (uint16, error) {
	handles, err := c.ListObjects(ctx, yubihsm.ObjectTypeAsymmetricKey)
	if err != nil {
		return 0, err
	}
	var matches []uint16
	for _, h := range handles {
		info, err := c.GetObjectInfo(ctx, h.ID, h.Type)
		if err != nil {
			return 0, err
		}
		if info.Label == label {
			matches = append(matches, h.ID)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("no asymmetric key labelled %q on the HSM", label)
	case 1:
		return matches[0], nil
	default:
		ids := make([]string, 0, len(matches))
		for _, m := range matches {
			ids = append(ids, fmt.Sprintf("0x%04x", m))
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
func AttestAsymmetricKey(ctx context.Context, cfg Config, objectID, attestKeyID uint16) (string, error) {
	var certPEM string
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		der, err := c.AttestAsymmetricKey(ctx, objectID, attestKeyID)
		if err != nil {
			return err
		}
		certPEM = encodeCertPEM(der)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("attesting key 0x%04x: %w", objectID, err)
	}
	return certPEM, nil
}

// GetKeyAttestationCert gets an attestation certificate for a key by its label.
//
// Label resolution is exact; see FindAsymmetricKey for why a prefix match here
// was a correctness bug rather than a convenience. Resolution and attestation
// share one session, so the key cannot be swapped between the two steps.
func GetKeyAttestationCert(ctx context.Context, cfg Config, keyLabel string) (string, error) {
	var certPEM string
	err := withClient(ctx, cfg, func(c *yubihsm.Client) error {
		objectID, err := findAsymmetricKey(ctx, c, keyLabel)
		if err != nil {
			return err
		}
		der, err := c.AttestAsymmetricKey(ctx, objectID, 0)
		if err != nil {
			return fmt.Errorf("attesting key 0x%04x: %w", objectID, err)
		}
		certPEM = encodeCertPEM(der)
		return nil
	})
	if err != nil {
		return "", err
	}
	return certPEM, nil
}
