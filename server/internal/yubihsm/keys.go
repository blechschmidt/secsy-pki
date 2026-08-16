package yubihsm

import (
	"context"
	"encoding/binary"
	"fmt"
)

// Object lifecycle commands.
//
// The PKI itself creates and uses keys through PKCS#11 (see internal/keyprovider);
// these exist for the operations PKCS#11 has no notion of and for provisioning
// and hardware conformance testing, where the point is to drive the device
// directly rather than through another layer's abstraction.

// KeySpec describes an asymmetric key to create or import.
type KeySpec struct {
	// ID is the object id; 0 asks the device to allocate one.
	ID uint16
	// Label is the human-readable name, at most 40 bytes.
	Label string
	// Domains is the bitmask of domains the key belongs to. 0 is rejected by the
	// device, so 1 (the first domain) is a sane default.
	Domains uint16
	// Capabilities is the 64-bit capability mask. Bit positions are Yubico's;
	// internal/hsmattest holds the authoritative name table.
	Capabilities uint64
	// Algorithm is the key algorithm identifier.
	Algorithm byte
}

func (k KeySpec) encodeHeader() ([]byte, error) {
	if len(k.Label) > labelLen {
		return nil, fmt.Errorf("label %q is %d bytes, above the device limit of %d", k.Label, len(k.Label), labelLen)
	}
	if k.Domains == 0 {
		return nil, fmt.Errorf("key %q must belong to at least one domain", k.Label)
	}
	if k.Algorithm == 0 {
		return nil, fmt.Errorf("key %q has no algorithm", k.Label)
	}
	// The label field is fixed width and NUL padded.
	out := make([]byte, 0, 2+labelLen+2+8+1)
	out = binary.BigEndian.AppendUint16(out, k.ID)
	label := make([]byte, labelLen)
	copy(label, k.Label)
	out = append(out, label...)
	out = binary.BigEndian.AppendUint16(out, k.Domains)
	out = binary.BigEndian.AppendUint64(out, k.Capabilities)
	out = append(out, k.Algorithm)
	return out, nil
}

// GenerateAsymmetricKey creates a key inside the device and returns its object
// id. The private half never exists outside the HSM, which is what an
// attestation over the resulting key can later assert.
func (c *Client) GenerateAsymmetricKey(ctx context.Context, spec KeySpec) (uint16, error) {
	req, err := spec.encodeHeader()
	if err != nil {
		return 0, err
	}
	body, err := c.Command(ctx, cmdGenerateAsymmetricKey, req)
	if err != nil {
		return 0, fmt.Errorf("generating asymmetric key %q: %w", spec.Label, err)
	}
	if len(body) != 2 {
		return 0, fmt.Errorf("generate-key response is %d bytes, want 2", len(body))
	}
	return binary.BigEndian.Uint16(body), nil
}

// PutAsymmetricKey imports a private key. For an EC key, material is the private
// scalar in big-endian form, padded to the curve's byte length.
//
// An imported key is marked as such by the device and its attestation says so,
// which is the difference a relying party cares about: only a generated key can
// be claimed never to have existed outside the HSM.
func (c *Client) PutAsymmetricKey(ctx context.Context, spec KeySpec, material []byte) (uint16, error) {
	req, err := spec.encodeHeader()
	if err != nil {
		return 0, err
	}
	req = append(req, material...)
	body, err := c.Command(ctx, cmdPutAsymmetricKey, req)
	if err != nil {
		return 0, fmt.Errorf("importing asymmetric key %q: %w", spec.Label, err)
	}
	if len(body) != 2 {
		return 0, fmt.Errorf("put-key response is %d bytes, want 2", len(body))
	}
	return binary.BigEndian.Uint16(body), nil
}

// DeleteObject removes an object from the device.
func (c *Client) DeleteObject(ctx context.Context, id uint16, objectType byte) error {
	req := binary.BigEndian.AppendUint16(nil, id)
	req = append(req, objectType)
	if _, err := c.Command(ctx, cmdDeleteObject, req); err != nil {
		return fmt.Errorf("deleting object 0x%04x (%s): %w", id, ObjectTypeName(objectType), err)
	}
	return nil
}

// SignECDSA signs a digest with an EC key on the device and returns the DER
// ECDSA signature. The digest must already be hashed; the device does not hash.
func (c *Client) SignECDSA(ctx context.Context, keyID uint16, digest []byte) ([]byte, error) {
	req := binary.BigEndian.AppendUint16(nil, keyID)
	req = append(req, digest...)
	sig, err := c.Command(ctx, cmdSignECDSA, req)
	if err != nil {
		return nil, fmt.Errorf("signing with ECDSA key 0x%04x: %w", keyID, err)
	}
	return sig, nil
}

// GetPublicKey reads the public half of an asymmetric key. The returned bytes
// are the algorithm's raw public form — for EC, the uncompressed point without
// its 0x04 prefix; for Ed25519, the 32-byte public key.
func (c *Client) GetPublicKey(ctx context.Context, keyID uint16) (algorithm byte, key []byte, err error) {
	body, err := c.Command(ctx, cmdGetPublicKey, binary.BigEndian.AppendUint16(nil, keyID))
	if err != nil {
		return 0, nil, fmt.Errorf("reading public key 0x%04x: %w", keyID, err)
	}
	if len(body) < 2 {
		return 0, nil, fmt.Errorf("public-key response is %d bytes, want at least 2", len(body))
	}
	return body[0], body[1:], nil
}
