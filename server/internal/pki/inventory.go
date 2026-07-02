package pki

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	"github.com/miekg/pkcs11"
)

// HSMKeyInfo describes a single key object discovered on a PKCS#11 token by
// ListKeys. It carries only non-sensitive metadata — never private key material.
// Extractable/Sensitive reflect the token's CKA_EXTRACTABLE / CKA_SENSITIVE
// attributes and let an operator verify the key non-extractability invariant
// directly against the hardware during a key ceremony or DR drill.
type HSMKeyInfo struct {
	// Label is the CKA_LABEL of the private-key object.
	Label string
	// ID is the hex-encoded CKA_ID, if the object has one.
	ID string
	// KeyType is a canonical key-type string (matching the keyprovider
	// KeyType* constants where derivable), or a best-effort descriptor.
	KeyType string
	// Extractable reports CKA_EXTRACTABLE: false is required for CA/KEK keys —
	// the private key cannot be read off the token.
	Extractable bool
	// Sensitive reports CKA_SENSITIVE: true means attribute reads of the private
	// value are refused by the token.
	Sensitive bool
}

// ListKeys enumerates the private-key objects on the configured token, returning
// non-sensitive metadata for each (label, id, key type, and the extractability /
// sensitivity flags). It never reads or returns private key material: only
// public attributes and the boolean policy flags are fetched.
//
// It performs the same connect/login sequence as Probe and NewPKCS11Signer, and
// releases every resource it opens before returning.
func ListKeys(cfg PKCS11Config) (keys []HSMKeyInfo, err error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}
	if initErr := ctx.Initialize(); initErr != nil {
		if e, ok := initErr.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return nil, fmt.Errorf("initializing PKCS#11: %w", initErr)
		}
	}

	var (
		session  pkcs11.SessionHandle
		haveSess bool
		loggedIn bool
	)
	defer func() {
		if loggedIn {
			ctx.Logout(session)
		}
		if haveSess {
			ctx.CloseSession(session)
		}
		ctx.Finalize()
		ctx.Destroy()
	}()

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("getting slots: %w", err)
	}
	slotID, err := findToken(ctx, slots, cfg)
	if err != nil {
		return nil, err
	}
	session, err = ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("opening session: %w", err)
	}
	haveSess = true
	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.Pin); err != nil {
		return nil, fmt.Errorf("logging in: %w", err)
	}
	loggedIn = true

	// Enumerate every private-key object on the token.
	if err := ctx.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}); err != nil {
		return nil, fmt.Errorf("find init: %w", err)
	}
	var handles []pkcs11.ObjectHandle
	for {
		batch, _, ferr := ctx.FindObjects(session, 64)
		if ferr != nil {
			ctx.FindObjectsFinal(session)
			return nil, fmt.Errorf("find objects: %w", ferr)
		}
		if len(batch) == 0 {
			break
		}
		handles = append(handles, batch...)
	}
	ctx.FindObjectsFinal(session)

	for _, h := range handles {
		info := HSMKeyInfo{}

		// Non-sensitive metadata: label, id, key type, policy flags. We request
		// them individually so one unsupported attribute does not blank the rest.
		if attrs, aerr := ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		}); aerr == nil {
			for _, a := range attrs {
				switch a.Type {
				case pkcs11.CKA_LABEL:
					info.Label = string(a.Value)
				case pkcs11.CKA_ID:
					if len(a.Value) > 0 {
						info.ID = hex.EncodeToString(a.Value)
					}
				case pkcs11.CKA_KEY_TYPE:
					info.KeyType = keyTypeName(session, ctx, h, a.Value)
				}
			}
		}

		// CKA_SENSITIVE / CKA_EXTRACTABLE default to the safe (locked-down)
		// interpretation if the token refuses to report them.
		info.Sensitive = true
		if attrs, aerr := ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		}); aerr == nil {
			for _, a := range attrs {
				if len(a.Value) == 0 {
					continue
				}
				switch a.Type {
				case pkcs11.CKA_EXTRACTABLE:
					info.Extractable = a.Value[0] != 0
				case pkcs11.CKA_SENSITIVE:
					info.Sensitive = a.Value[0] != 0
				}
			}
		}

		keys = append(keys, info)
	}
	return keys, nil
}

// keyTypeName maps a CKA_KEY_TYPE value to a canonical key-type string. For EC
// keys it reads CKA_EC_PARAMS to resolve the specific curve (or Ed25519).
func keyTypeName(session pkcs11.SessionHandle, ctx *pkcs11.Ctx, h pkcs11.ObjectHandle, raw []byte) string {
	if len(raw) == 0 {
		return "unknown"
	}
	// CKA_KEY_TYPE is a CK_ULONG; its low byte suffices to distinguish the
	// handful of types we support.
	switch raw[0] {
	case byte(pkcs11.CKK_RSA):
		if bits := rsaModulusBits(session, ctx, h); bits > 0 {
			return fmt.Sprintf("rsa-%d", bits)
		}
		return "rsa"
	case CKK_EC_EDWARDS:
		return "ed25519"
	case byte(pkcs11.CKK_EC):
		return ecCurveName(session, ctx, h)
	default:
		return fmt.Sprintf("ckk-0x%x", raw[0])
	}
}

// rsaModulusBits returns the modulus size in bits for an RSA key, or 0 if it
// cannot be determined. It reads only public attributes.
func rsaModulusBits(session pkcs11.SessionHandle, ctx *pkcs11.Ctx, h pkcs11.ObjectHandle) int {
	attrs, err := ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	})
	if err != nil {
		return 0
	}
	for _, a := range attrs {
		if a.Type == pkcs11.CKA_MODULUS && len(a.Value) > 0 {
			return len(a.Value) * 8
		}
	}
	return 0
}

// ecCurveName resolves an EC key's curve from CKA_EC_PARAMS, reusing the same
// OID/Ed25519 detection as the signer's public-key parsing.
func ecCurveName(session pkcs11.SessionHandle, ctx *pkcs11.Ctx, h pkcs11.ObjectHandle) string {
	attrs, err := ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return "ecdsa"
	}
	var params []byte
	for _, a := range attrs {
		if a.Type == pkcs11.CKA_EC_PARAMS {
			params = a.Value
		}
	}
	if len(params) == 0 {
		return "ecdsa"
	}
	if isEdwards25519(params) {
		return "ed25519"
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err == nil {
		switch {
		case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}):
			return "ecdsa-sha2-nistp256"
		case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}):
			return "ecdsa-sha2-nistp384"
		case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}):
			return "ecdsa-sha2-nistp521"
		}
	}
	return "ecdsa"
}
