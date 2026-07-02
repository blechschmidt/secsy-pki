package pki

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

// This file adds the decryption / key-wrapping primitives needed for
// HSM-backed envelope encryption (see internal/secret). A key-encryption key
// (KEK) is an RSA key pair whose private half never leaves the token: data
// encryption keys are wrapped with the public key (which can be done offline,
// with no HSM present) and unwrapped by asking the token to RSA-OAEP decrypt
// them via C_Decrypt.
//
// The KEK is generated with least privilege: the private key may only DECRYPT
// (not SIGN) and the public key may only ENCRYPT (not VERIFY). This keeps a
// wrapping key from being repurposed as a signing key, and vice-versa.

// Decrypt implements crypto.Decrypter for an RSA key held on the token, using
// the RSA-OAEP mechanism. It is the counterpart to wrapping a data key with
// rsa.EncryptOAEP against the exported public key.
//
// The OAEP hash (which also selects the MGF1 hash) is taken from opts: pass a
// *rsa.OAEPOptions with Hash set to SHA-256 (preferred) or SHA-1. A nil opts
// defaults to SHA-256. Only these two are offered; SoftHSM, for example,
// supports only SHA-1 for OAEP, whereas production HSMs support SHA-256 — the
// caller (internal/secret) negotiates which to use and records it in the
// ciphertext. PKCS#1 v1.5 decryption is deliberately not offered, to avoid the
// Bleichenbacher padding-oracle class of attacks.
func (s *PKCS11Signer) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if _, ok := s.pubKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("pkcs11 decrypt: key is not RSA (type %T)", s.pubKey)
	}
	return decryptOAEPOnSession(s.ctx, s.session, s.privHandle, ciphertext, opts)
}

// decryptOAEPOnSession performs an RSA-OAEP unwrap for a key resolved on the
// given session. It is the shared decryption core used by both the one-shot
// PKCS11Signer.Decrypt and the pooled decrypter. The caller is responsible for
// verifying the key is RSA before calling. The session must already be
// authenticated and must be the one the priv handle was resolved on.
func decryptOAEPOnSession(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, priv pkcs11.ObjectHandle, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	hashAlg, mgf, err := oaepMechParams(opts)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("pkcs11 decrypt: empty ciphertext")
	}

	params := pkcs11.NewOAEPParams(hashAlg, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}

	if err := ctx.DecryptInit(session, mech, priv); err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt init: %w", err)
	}
	plaintext, err := ctx.Decrypt(session, ciphertext)
	if err != nil {
		// Do not surface the low-level error verbatim to callers that might act
		// as a padding oracle; the wrapper in internal/secret returns a generic
		// message. Here we keep detail for server-side logs.
		return nil, fmt.Errorf("pkcs11 decrypt: %w", err)
	}
	return plaintext, nil
}

// decryptPKCS1v15OnSession performs an RSA PKCS#1 v1.5 (CKM_RSA_PKCS) unwrap for
// a key resolved on the given session. This padding mode is required by the SCEP
// (RFC 8894) pkiMessage EnvelopedData key-transport recipient info, which uses
// the rsaEncryption OID rather than RSA-OAEP. The caller must have verified the
// key is RSA. As with OAEP, the private key never leaves the token: the unwrap
// runs on the device via C_Decrypt.
//
// SECURITY: PKCS#1 v1.5 decryption is susceptible to Bleichenbacher-style
// padding-oracle attacks. Callers must return a single generic error to remote
// peers on any failure (whether padding, length, or content), never signalling
// which stage failed. The CMS layer that drives SCEP does exactly this.
func decryptPKCS1v15OnSession(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, priv pkcs11.ObjectHandle, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("pkcs11 decrypt: empty ciphertext")
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := ctx.DecryptInit(session, mech, priv); err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt init: %w", err)
	}
	plaintext, err := ctx.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 decrypt: %w", err)
	}
	return plaintext, nil
}

// oaepMechParams maps the requested DecrypterOpts to the PKCS#11 OAEP hash and
// MGF mechanism identifiers, enforcing an empty OAEP label and a consistent
// hash/MGF pair.
func oaepMechParams(opts crypto.DecrypterOpts) (hashAlg, mgf uint, err error) {
	hash := crypto.SHA256
	if opts != nil {
		oaep, ok := opts.(*rsa.OAEPOptions)
		if !ok {
			return 0, 0, fmt.Errorf("pkcs11 decrypt: unsupported decrypter options %T (only RSA-OAEP)", opts)
		}
		if len(oaep.Label) != 0 {
			return 0, 0, fmt.Errorf("pkcs11 decrypt: non-empty OAEP label is not supported")
		}
		if oaep.Hash != 0 {
			hash = oaep.Hash
		}
		if oaep.MGFHash != 0 && oaep.MGFHash != hash {
			return 0, 0, fmt.Errorf("pkcs11 decrypt: OAEP MGF hash must match the OAEP hash")
		}
	}
	switch hash {
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	default:
		return 0, 0, fmt.Errorf("pkcs11 decrypt: unsupported OAEP hash %v (only SHA-256 or SHA-1)", hash)
	}
}

// GenerateRSAKEKOnHSM creates an RSA key-encryption key pair on the token with
// least-privilege usage attributes: the private key can DECRYPT (and unwrap)
// but not SIGN, and it is marked sensitive and non-extractable so the wrapping
// key material can never leave the HSM. Supported sizes are 2048 and 4096 bits.
//
// It returns the same GeneratedHSMKey shape as GenerateKeyOnHSM so callers can
// treat a KEK uniformly with signing keys for metadata purposes.
func GenerateRSAKEKOnHSM(cfg PKCS11Config, label string, bits int) (*GeneratedHSMKey, error) {
	if bits != 2048 && bits != 4096 {
		return nil, fmt.Errorf("unsupported KEK size %d (must be 2048 or 4096)", bits)
	}

	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return nil, fmt.Errorf("initializing PKCS#11: %w", err)
		}
	}
	defer func() {
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

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("opening session: %w", err)
	}
	defer ctx.CloseSession(session)

	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.Pin); err != nil {
		return nil, fmt.Errorf("logging in: %w", err)
	}
	defer ctx.Logout(session)

	return generateRSAKEKOnSession(ctx, session, cfg, label, bits)
}

// generateRSAKEKOnSession creates an RSA key-encryption key pair on an already
// authenticated R/W session, with least-privilege usage (decrypt/unwrap only,
// sensitive and non-extractable). It is the shared generation core used by both
// the one-shot GenerateRSAKEKOnHSM and the pooled provider.
func generateRSAKEKOnSession(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, cfg PKCS11Config, label string, bits int) (*GeneratedHSMKey, error) {
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	pubAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
	}
	privAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	pubHandle, _, err := ctx.GenerateKeyPair(session, mechanism, pubAttrs, privAttrs)
	if err != nil {
		return nil, fmt.Errorf("generating KEK on HSM: %w", err)
	}

	readAttrs, err := ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("reading KEK public key from HSM: %w", err)
	}

	keyType := "rsa-2048"
	if bits == 4096 {
		keyType = "rsa-4096"
	}
	sshPub, err := hsmPubKeyToSSH(readAttrs, keyType)
	if err != nil {
		return nil, fmt.Errorf("converting KEK public key: %w", err)
	}

	return &GeneratedHSMKey{
		PKCS11URI:    BuildPKCS11URI(cfg, label),
		KeyType:      keyType,
		SSHPublicKey: sshPub,
	}, nil
}
