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

// LabelledKeyRequest describes one throwaway key created solely so that a
// host-supplied label reaches a certificate the device's attestation key signs.
//
// The construction is deliberately indirect. A YubiHSM has no command that signs
// a caller-supplied blob with the factory attestation key, so a nonce or a log
// digest cannot simply be handed to it. What it will do is generate a key with a
// host-supplied 40-byte label and then attest that key — and the attestation
// certificate carries both the label and, in a separate device-asserted
// extension, the device's own serial number. Putting a value in the label
// therefore produces a statement of the form
//
//	YubiHSM serial N holds an object labelled L
//
// signed by a key that has never left genuine Yubico hardware.
//
// Two callers exercise it, and they read the same statement in opposite
// directions. The audit subsystem puts a digest of the audit head in L and reads
// the serial (internal/hsmaudit/commitment.go); device authentication puts a
// verifier-chosen nonce in L and reads the signature (internal/hsmattest/
// device.go), because a device that answers a fresh challenge is one that holds
// the attestation private key right now rather than a copy of some device's
// published certificate.
type LabelledKeyRequest struct {
	// ObjectID is where the throwaway key is created. It must come from a range
	// reserved for this purpose so the log distinguishes these three operations
	// from work done with production keys.
	ObjectID uint16
	// Label is the value being carried into the certificate, at most 40 bytes.
	Label string
	// ReservedPrefix marks a label as belonging to the caller's scheme. An object
	// left at ObjectID by a run that crashed between generating and deleting is
	// removed when its label carries the prefix; anything else is refused rather
	// than deleted, because an object this code did not create is not its to
	// destroy.
	ReservedPrefix string
	// AttestKeyID selects the attesting key; 0 is the factory-provisioned one,
	// which is the only one that chains to Yubico's PKI and therefore the only
	// one that makes the serial an assertion rather than a claim.
	AttestKeyID uint16
	// Capabilities is the throwaway key's capability mask. 0 — the default — is
	// what both callers want: the key exists only to carry a label into a
	// certificate, and one that can do nothing cannot be repurposed if a run is
	// interrupted before the delete. It also keeps the object out of the audit
	// subsystem's own signing-key analysis, which reasons about keys that can
	// sign. It is a field rather than a constant only so that firmware refusing a
	// capability-less key can be given a harmless one; nothing in verification
	// depends on the value.
	Capabilities uint64
}

// CommitmentRequest is the audit subsystem's name for a LabelledKeyRequest,
// kept because a commitment is what that caller is making.
type CommitmentRequest = LabelledKeyRequest

// AttestLabelledKey generates a throwaway key carrying req.Label, attests it,
// and returns the resulting attestation certificate together with the device's
// own.
//
// All four device operations share one session so nothing can be swapped between
// them, and the key is deleted before returning: the evidence is the
// certificate, not the key, and a key left in a reserved slot is a liability
// with no purpose. The deletion is best-effort in the sense that its failure is
// reported alongside a successful attestation rather than discarding it — an
// undeleted key is an operational problem, while throwing away evidence the
// device has already logged producing would leave the log with a marker for
// something nobody holds.
//
// Every step here is an audited command (GENERATE ASYMMETRIC KEY, SIGN
// ATTESTATION CERTIFICATE, DELETE OBJECT are all force-audited by provisioning),
// so each call leaves its own trace in the device log. For the audit caller that
// is load-bearing: the commitment lands immediately after the head it commits
// to, and the next commitment's head folds those entries in, which is what stops
// commitments from being produced out of band.
func AttestLabelledKey(ctx context.Context, cfg Config, req LabelledKeyRequest) (certPEM, deviceCertPEM string, err error) {
	if len(req.Label) == 0 || len(req.Label) > 40 {
		return "", "", fmt.Errorf("attestation label is %d bytes, want 1..40", len(req.Label))
	}
	err = withClient(ctx, cfg, func(c *yubihsm.Client) error {
		if err := clearReservedSlot(ctx, c, req); err != nil {
			return err
		}
		domains := sessionDomains(ctx, c, cfg)
		id, err := c.GenerateAsymmetricKey(ctx, yubihsm.KeySpec{
			ID:           req.ObjectID,
			Label:        req.Label,
			Domains:      domains,
			Capabilities: req.Capabilities,
			Algorithm:    yubihsm.AlgorithmECP256,
		})
		if err != nil {
			if req.Capabilities == 0 {
				return fmt.Errorf("generating the capability-less throwaway key at 0x%04x in domain(s) 0x%04x: %w "+
					"(if this firmware refuses a key with no capabilities, give LabelledKeyRequest.Capabilities a "+
					"harmless one such as sign-ecdsa — verification does not depend on the value)",
					req.ObjectID, domains, err)
			}
			return fmt.Errorf("generating the throwaway key at 0x%04x in domain(s) 0x%04x: %w", req.ObjectID, domains, err)
		}
		if id != req.ObjectID {
			// The device allocated elsewhere, which would put the object outside
			// the reserved range. Clean up and refuse.
			_ = c.DeleteObject(ctx, id, yubihsm.ObjectTypeAsymmetricKey)
			return fmt.Errorf("device created the throwaway key at 0x%04x rather than the requested 0x%04x", id, req.ObjectID)
		}

		der, err := c.AttestAsymmetricKey(ctx, req.ObjectID, req.AttestKeyID)
		if err != nil {
			_ = c.DeleteObject(ctx, req.ObjectID, yubihsm.ObjectTypeAsymmetricKey)
			return fmt.Errorf("attesting the throwaway key at 0x%04x: %w", req.ObjectID, err)
		}

		// The device attestation certificate is read before the key is deleted and
		// its absence is fatal, unlike in a per-key attestation. There, a missing
		// device certificate degrades the attestation into an unauthenticated set
		// of claims that a verifier reports as such. Here the whole point is the
		// chain to Yubico's PKI, so the result without it could never verify —
		// producing one would consume the device's log slots to record evidence
		// nobody can use.
		raw, err := c.GetOpaque(ctx, deviceAttestationObjectID)
		if err != nil || len(raw) == 0 {
			_ = c.DeleteObject(ctx, req.ObjectID, yubihsm.ObjectTypeAsymmetricKey)
			return fmt.Errorf("reading the device attestation certificate from opaque object 0x%04x: %w "+
				"(without it the attestation chains to nothing and could not be verified)",
				deviceAttestationObjectID, err)
		}

		certPEM = encodeCertPEM(der)
		deviceCertPEM = encodeCertPEM(raw)

		// From here the evidence exists and the caller must keep it, so a delete
		// failure is reported alongside it rather than in place of it: the device
		// has already logged producing this certificate, and discarding it would
		// leave the log with entries nothing accounts for. The next run's
		// clearReservedSlot removes the leftover.
		if err := c.DeleteObject(ctx, req.ObjectID, yubihsm.ObjectTypeAsymmetricKey); err != nil {
			return fmt.Errorf("the attestation was produced but its throwaway key could not be deleted from 0x%04x: %w",
				req.ObjectID, err)
		}
		return nil
	})
	return certPEM, deviceCertPEM, err
}

// CommitAuditHead performs one serial-bound audit-head commitment. See
// internal/hsmaudit/commitment.go for what that does and does not establish.
func CommitAuditHead(ctx context.Context, cfg Config, req CommitmentRequest) (certPEM, deviceCertPEM string, err error) {
	return AttestLabelledKey(ctx, cfg, req)
}

// clearReservedSlot removes a leftover throwaway key so a run interrupted
// between generating and deleting does not wedge every future one.
//
// It will only delete an object whose label carries the reserved prefix. A
// different object sitting in the reserved range means an operator put it there,
// and silently destroying it would be far worse than refusing to proceed.
func clearReservedSlot(ctx context.Context, c *yubihsm.Client, req LabelledKeyRequest) error {
	info, err := c.GetObjectInfo(ctx, req.ObjectID, yubihsm.ObjectTypeAsymmetricKey)
	if err != nil {
		var devErr yubihsm.DeviceError
		if errors.As(err, &devErr) && devErr == yubihsm.ErrObjectNotFound {
			return nil // the usual case: the slot is free
		}
		return err
	}
	if req.ReservedPrefix == "" || !strings.HasPrefix(info.Label, req.ReservedPrefix) {
		return fmt.Errorf("object 0x%04x is labelled %q and is not a leftover of this scheme (prefix %q): "+
			"the object id is reserved, so refusing to delete something else to make room",
			req.ObjectID, info.Label, req.ReservedPrefix)
	}
	return c.DeleteObject(ctx, req.ObjectID, yubihsm.ObjectTypeAsymmetricKey)
}

// sessionDomains returns the domains the throwaway key should be created in:
// the authentication key's own, since a session can only create objects in
// domains its authentication key holds. It falls back to domain 1 — the
// conventional first domain — when the device will not describe the auth key,
// so a device whose auth key cannot be read still gets a commitment attempt
// rather than a hard failure with no diagnosis.
//
// The zero auth key id means key 1 here, as it does everywhere else in this
// package (see Config.nativeConfig and yubihsm.Open); looking up object 0 would
// fail and silently take the fallback.
func sessionDomains(ctx context.Context, c *yubihsm.Client, cfg Config) uint16 {
	authKeyID := uint16(cfg.AuthKeyID)
	if authKeyID == 0 {
		authKeyID = 1
	}
	info, err := c.GetObjectInfo(ctx, authKeyID, yubihsm.ObjectTypeAuthenticationKey)
	if err == nil && info.Domains != 0 {
		return info.Domains
	}
	return 1
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
