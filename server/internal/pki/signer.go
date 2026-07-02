package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/ssh"
)

// CKM_EDDSA is not in miekg/pkcs11 (PKCS#11 v3.0)
const CKM_EDDSA = 0x00001057

type PKCS11Signer struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	privHandle pkcs11.ObjectHandle
	pubKey     crypto.PublicKey
	keyType    string
	isEdDSA    bool
}

type PKCS11Config struct {
	ModulePath        string
	Pin               string
	TokenLabel        string
	TokenSerial       string
	TokenManufacturer string
}

// findToken locates the PKCS#11 slot matching the config's token attributes.
func findToken(ctx *pkcs11.Ctx, slots []uint, cfg PKCS11Config) (uint, error) {
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		label := strings.TrimRight(info.Label, " ")
		serial := strings.TrimRight(info.SerialNumber, " ")
		mfr := strings.TrimRight(info.ManufacturerID, " ")
		if cfg.TokenLabel != "" && label != cfg.TokenLabel {
			continue
		}
		if cfg.TokenSerial != "" && serial != cfg.TokenSerial {
			continue
		}
		if cfg.TokenManufacturer != "" && mfr != cfg.TokenManufacturer {
			continue
		}
		return s, nil
	}
	return 0, fmt.Errorf("no token found matching label=%q serial=%q manufacturer=%q", cfg.TokenLabel, cfg.TokenSerial, cfg.TokenManufacturer)
}

// BuildPKCS11URI constructs a PKCS#11 URI from the config and key label.
func BuildPKCS11URI(cfg PKCS11Config, keyLabel string) string {
	parts := []string{}
	if cfg.TokenLabel != "" {
		parts = append(parts, "token="+cfg.TokenLabel)
	}
	if cfg.TokenSerial != "" {
		parts = append(parts, "serial="+cfg.TokenSerial)
	}
	if cfg.TokenManufacturer != "" {
		parts = append(parts, "manufacturer="+cfg.TokenManufacturer)
	}
	parts = append(parts, "object="+keyLabel, "type=private")
	return "pkcs11:" + strings.Join(parts, ";")
}

func NewPKCS11Signer(cfg PKCS11Config, keyLabel string) (*PKCS11Signer, error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return nil, fmt.Errorf("initializing PKCS#11: %w", err)
		}
	}

	// Track resource state so that any error after this point releases the
	// session, login, and loaded module. Leaking a logged-in session breaks
	// subsequent operations on tokens (e.g. SoftHSM) whose login state is
	// per-application rather than per-session: the next Login fails with
	// CKR_USER_ALREADY_LOGGED_IN. On success, ownership transfers to the
	// returned signer and cleanup is skipped.
	var (
		session   pkcs11.SessionHandle
		haveSess  bool
		loggedIn  bool
		succeeded bool
	)
	defer func() {
		if succeeded {
			return
		}
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

	// Find private key
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return nil, fmt.Errorf("find init: %w", err)
	}
	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("find objects: %w", err)
	}
	ctx.FindObjectsFinal(session)
	if len(objs) == 0 {
		return nil, fmt.Errorf("private key %q not found", keyLabel)
	}

	// Find public key
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
	}
	if err := ctx.FindObjectsInit(session, pubTmpl); err != nil {
		return nil, fmt.Errorf("find pub init: %w", err)
	}
	pubObjs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("find pub objects: %w", err)
	}
	ctx.FindObjectsFinal(session)

	signer := &PKCS11Signer{
		ctx:        ctx,
		session:    session,
		privHandle: objs[0],
	}

	if len(pubObjs) > 0 {
		// Try EC attributes first
		attrs, err := ctx.GetAttributeValue(session, pubObjs[0], []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
		if err == nil {
			signer.parsePublicKey(attrs)
		}
		// If no key found, try RSA attributes
		if signer.pubKey == nil {
			attrs, err = ctx.GetAttributeValue(session, pubObjs[0], []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
			})
			if err == nil {
				signer.parseRSAPublicKey(attrs)
			}
		}
	}

	succeeded = true
	return signer, nil
}

func (s *PKCS11Signer) parsePublicKey(attrs []*pkcs11.Attribute) {
	var ecParams, ecPoint []byte
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_EC_PARAMS:
			ecParams = a.Value
		case pkcs11.CKA_EC_POINT:
			ecPoint = a.Value
		}
	}
	if ecParams == nil || ecPoint == nil {
		return
	}

	// Check for Ed25519: YubiHSM uses PrintableString "edwards25519",
	// standard PKCS#11 v3.0 uses OID 1.3.101.112
	if isEdwards25519(ecParams) {
		raw := extractECPoint(ecPoint)
		if len(raw) == 32 {
			s.pubKey = ed25519.PublicKey(raw)
			s.keyType = "ssh-ed25519"
			s.isEdDSA = true
			return
		}
	}

	// Try standard EC curves via OID
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ecParams, &oid); err != nil {
		return
	}

	var curve elliptic.Curve
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}):
		curve = elliptic.P256()
		s.keyType = "ecdsa-sha2-nistp256"
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}):
		curve = elliptic.P384()
		s.keyType = "ecdsa-sha2-nistp384"
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}):
		curve = elliptic.P521()
		s.keyType = "ecdsa-sha2-nistp521"
	default:
		return
	}

	pointBytes := extractECPoint(ecPoint)
	x, y := elliptic.Unmarshal(curve, pointBytes)
	if x == nil {
		return
	}
	s.pubKey = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

func (s *PKCS11Signer) parseRSAPublicKey(attrs []*pkcs11.Attribute) {
	var modulus, exponent []byte
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_MODULUS:
			modulus = a.Value
		case pkcs11.CKA_PUBLIC_EXPONENT:
			exponent = a.Value
		}
	}
	if len(modulus) == 0 || len(exponent) == 0 {
		return
	}
	n := new(big.Int).SetBytes(modulus)
	e := new(big.Int).SetBytes(exponent)
	s.pubKey = &rsa.PublicKey{N: n, E: int(e.Int64())}
	s.keyType = "ssh-rsa"
}

// isEdwards25519 checks if ec_params represents Ed25519.
// YubiHSM returns ASN.1 PrintableString "edwards25519".
// Standard PKCS#11 v3.0 returns OID 1.3.101.112.
func isEdwards25519(params []byte) bool {
	// Try PrintableString / UTF8String
	var s string
	if _, err := asn1.Unmarshal(params, &s); err == nil {
		return s == "edwards25519"
	}
	// Try OID
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err == nil {
		return oid.Equal(asn1.ObjectIdentifier{1, 3, 101, 112})
	}
	return false
}

// extractECPoint unwraps a DER OCTET STRING if present, otherwise returns raw bytes.
func extractECPoint(data []byte) []byte {
	var raw []byte
	if _, err := asn1.Unmarshal(data, &raw); err != nil {
		return data
	}
	return raw
}

func (s *PKCS11Signer) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *PKCS11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.isEdDSA {
		return s.signEdDSA(digest)
	}
	if _, ok := s.pubKey.(*rsa.PublicKey); ok {
		return s.signRSA(digest, opts)
	}
	return s.signECDSA(digest)
}

func (s *PKCS11Signer) signEdDSA(data []byte) ([]byte, error) {
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EDDSA, nil)}

	if err := s.ctx.SignInit(s.session, mechanism, s.privHandle); err != nil {
		return nil, fmt.Errorf("EdDSA sign init: %w", err)
	}

	// EdDSA signs the raw message, not a digest
	sig, err := s.ctx.Sign(s.session, data)
	if err != nil {
		return nil, fmt.Errorf("EdDSA sign: %w", err)
	}

	// Ed25519 signature is 64 bytes, returned as-is (no ASN.1 wrapping)
	return sig, nil
}

func (s *PKCS11Signer) signECDSA(digest []byte) ([]byte, error) {
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}

	if err := s.ctx.SignInit(s.session, mechanism, s.privHandle); err != nil {
		return nil, fmt.Errorf("ECDSA sign init: %w", err)
	}

	sig, err := s.ctx.Sign(s.session, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign: %w", err)
	}

	// PKCS#11 returns r||s concatenated, convert to ASN.1 DER
	n := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:n])
	sInt := new(big.Int).SetBytes(sig[n:])

	type ecdsaSig struct {
		R, S *big.Int
	}
	derSig, err := asn1.Marshal(ecdsaSig{r, sInt})
	if err != nil {
		return nil, fmt.Errorf("marshal ECDSA signature: %w", err)
	}
	return derSig, nil
}

func (s *PKCS11Signer) signRSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}

	// PKCS#1 v1.5: prepend DigestInfo ASN.1 structure
	hash := opts.HashFunc()
	var prefix []byte
	switch hash {
	case crypto.SHA256:
		prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	case crypto.SHA512:
		prefix = []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}
	case crypto.SHA1:
		prefix = []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}
	default:
		return nil, fmt.Errorf("unsupported hash for RSA signing: %v", hash)
	}
	data := append(prefix, digest...)

	if err := s.ctx.SignInit(s.session, mechanism, s.privHandle); err != nil {
		return nil, fmt.Errorf("RSA sign init: %w", err)
	}
	sig, err := s.ctx.Sign(s.session, data)
	if err != nil {
		return nil, fmt.Errorf("RSA sign: %w", err)
	}
	return sig, nil
}

func (s *PKCS11Signer) KeyType() string {
	return s.keyType
}

func (s *PKCS11Signer) Close() {
	s.ctx.Logout(s.session)
	s.ctx.CloseSession(s.session)
	s.ctx.Finalize()
	s.ctx.Destroy()
}

func (s *PKCS11Signer) SSHPublicKey() (ssh.PublicKey, error) {
	if s.pubKey == nil {
		return nil, fmt.Errorf("no public key available")
	}
	return ssh.NewPublicKey(s.pubKey)
}

// GeneratedHSMKey holds the result of generating a key pair on the HSM.
type GeneratedHSMKey struct {
	PKCS11URI    string
	KeyType      string
	SSHPublicKey string
}

// CKM_EC_EDWARDS_KEY_PAIR_GEN (PKCS#11 v3.0)
const CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055

// CKK_EC_EDWARDS (PKCS#11 v3.0)
const CKK_EC_EDWARDS = 0x00000040

// GenerateKeyOnHSM creates a new key pair on the HSM and returns its metadata.
// Supported key types: "ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521".
func GenerateKeyOnHSM(cfg PKCS11Config, label string, keyType string) (*GeneratedHSMKey, error) {
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

	var mechanism []*pkcs11.Mechanism
	var pubAttrs, privAttrs []*pkcs11.Attribute

	switch keyType {
	case "ed25519":
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)}
		// YubiHSM expects ASN.1 PrintableString "edwards25519", not the DER OID
		ed25519Params, _ := asn1.Marshal("edwards25519")
		pubAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519Params),
		}
		privAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
	case "ecdsa-sha2-nistp256":
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
		ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
		pubAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		}
		privAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
	case "ecdsa-sha2-nistp384":
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
		ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
		pubAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		}
		privAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
	case "ecdsa-sha2-nistp521":
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
		ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35})
		pubAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		}
		privAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
	case "rsa-2048", "rsa-4096":
		bits := 2048
		if keyType == "rsa-4096" {
			bits = 4096
		}
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
		pubAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}), // 65537
		}
		privAttrs = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
	default:
		return nil, fmt.Errorf("unsupported key type for HSM generation: %s", keyType)
	}

	pubHandle, _, err := ctx.GenerateKeyPair(session, mechanism, pubAttrs, privAttrs)
	if err != nil {
		return nil, fmt.Errorf("generating key pair on HSM: %w", err)
	}

	// Read back the public key
	var readAttrs []*pkcs11.Attribute
	if keyType == "rsa-2048" || keyType == "rsa-4096" {
		readAttrs, err = ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		})
	} else {
		readAttrs, err = ctx.GetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
	}
	if err != nil {
		return nil, fmt.Errorf("reading public key from HSM: %w", err)
	}

	// Convert to SSH public key
	sshPubKeyStr, err := hsmPubKeyToSSH(readAttrs, keyType)
	if err != nil {
		return nil, fmt.Errorf("converting HSM public key to SSH format: %w", err)
	}

	uri := BuildPKCS11URI(cfg, label)

	return &GeneratedHSMKey{
		PKCS11URI:    uri,
		KeyType:      keyType,
		SSHPublicKey: sshPubKeyStr,
	}, nil
}

func hsmPubKeyToSSH(attrs []*pkcs11.Attribute, keyType string) (string, error) {
	// RSA keys
	if keyType == "rsa-2048" || keyType == "rsa-4096" {
		var modulus, exponent []byte
		for _, a := range attrs {
			switch a.Type {
			case pkcs11.CKA_MODULUS:
				modulus = a.Value
			case pkcs11.CKA_PUBLIC_EXPONENT:
				exponent = a.Value
			}
		}
		if len(modulus) == 0 || len(exponent) == 0 {
			return "", fmt.Errorf("RSA key missing modulus or exponent")
		}
		n := new(big.Int).SetBytes(modulus)
		e := new(big.Int).SetBytes(exponent)
		rsaPub := &rsa.PublicKey{N: n, E: int(e.Int64())}
		sshPub, err := ssh.NewPublicKey(rsaPub)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
	}

	var ecParams, ecPoint []byte
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_EC_PARAMS:
			ecParams = a.Value
		case pkcs11.CKA_EC_POINT:
			ecPoint = a.Value
		}
	}

	raw := extractECPoint(ecPoint)

	if keyType == "ed25519" || isEdwards25519(ecParams) {
		if len(raw) != 32 {
			return "", fmt.Errorf("unexpected Ed25519 public key length: %d", len(raw))
		}
		sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(raw))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
	}

	// ECDSA
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ecParams, &oid); err != nil {
		return "", fmt.Errorf("parsing EC params OID: %w", err)
	}

	var curve elliptic.Curve
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}):
		curve = elliptic.P256()
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}):
		curve = elliptic.P384()
	case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}):
		curve = elliptic.P521()
	default:
		return "", fmt.Errorf("unsupported EC curve OID: %v", oid)
	}

	x, y := elliptic.Unmarshal(curve, raw)
	if x == nil {
		return "", fmt.Errorf("failed to unmarshal EC point")
	}

	sshPub, err := ssh.NewPublicKey(&ecdsa.PublicKey{Curve: curve, X: x, Y: y})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

var _ crypto.Signer = (*PKCS11Signer)(nil)
