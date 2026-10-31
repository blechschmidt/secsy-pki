package pki

// The raw PKCS#11 inspector (Task 218): the token as Cryptoki itself describes
// it, rather than as this PKI chooses to summarise it.
//
// Everywhere else in the codebase the HSM is behind an abstraction that answers
// the questions a CA asks — "give me a signer for this label", "is any key
// extractable". That is the right shape for issuing certificates and the wrong
// shape for the two situations an operator actually ends up in:
//
//   - something is on the token that this PKI did not put there, or did not
//     expect: a key left behind by a vendor tool, a certificate object imported
//     by a migration, an object whose CKA_LABEL is empty, a second object
//     sharing a label (which is how a label lookup starts pairing the public
//     half of one key with the private half of another);
//   - the module and the token disagree with the documentation: a mechanism the
//     firmware does not actually offer, a CKA_* the module answers differently
//     from the spec, a token whose flags say it is write-protected or whose PIN
//     is one try from locking.
//
// Neither is visible through an abstraction that only reports what it looks
// for. So this file reads out everything Cryptoki can be asked: C_GetInfo for
// the module, C_GetSlotList / C_GetSlotInfo / C_GetTokenInfo for every slot
// (not only the configured one), C_GetMechanismList plus C_GetMechanismInfo for
// each mechanism, and then C_FindObjects with an EMPTY template — every object
// the session can see, whatever class — followed by C_GetAttributeValue for
// every attribute the catalogue in pkcs11attrs.go defines for its class.
//
// It reads. It never creates, modifies or destroys an object, and it never asks
// for private key material (see the policy note in pkcs11attrs.go).
//
// Session discipline matches the rest of the package: nothing here loads or
// finalizes a module on its own. The pooled entry points run on the serving
// pool's already-authenticated session, and the one-shot entry points go
// through withModule/withModuleSession, which reference-count both the module
// and the login — the mistake Task 208 was.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/miekg/pkcs11"
)

// DefaultInspectMaxObjects bounds how many objects one inspection enumerates.
// A token holding more is reported as truncated rather than streamed in full:
// the view is for a human reading attribute tables, and an unbounded dump of a
// 10,000-object token is neither readable nor safe to hold in memory.
const DefaultInspectMaxObjects = 500

// DefaultInspectMaxValueBytes bounds the hex rendering of one attribute value.
// A certificate body or a 4096-bit modulus is interesting; 64 KiB of an
// application data object is not, and the full value's SHA-256 is reported
// alongside so a truncated value can still be compared or recognised.
const DefaultInspectMaxValueBytes = 2048

// InspectOptions tunes one inspection.
type InspectOptions struct {
	// AllAttributes asks every object for every attribute in the catalogue,
	// instead of only those the standard defines for the object's class. It is
	// how a module's non-standard answers are discovered — and it also keeps
	// the attributes a token reports as unsupported, which are otherwise
	// dropped as noise.
	AllAttributes bool
	// MaxObjects caps object enumeration; <= 0 selects DefaultInspectMaxObjects.
	MaxObjects int
	// MaxValueBytes caps one value's hex rendering; <= 0 selects
	// DefaultInspectMaxValueBytes.
	MaxValueBytes int
	// SkipMechanisms omits the per-slot mechanism lists, which are the bulk of
	// a module view (a YubiHSM offers ~70, SoftHSM ~180) and cost a
	// C_GetMechanismInfo round trip each.
	SkipMechanisms bool
}

func (o InspectOptions) maxObjects() int {
	if o.MaxObjects <= 0 {
		return DefaultInspectMaxObjects
	}
	return o.MaxObjects
}

func (o InspectOptions) maxValueBytes() int {
	if o.MaxValueBytes <= 0 {
		return DefaultInspectMaxValueBytes
	}
	return o.MaxValueBytes
}

// Flags renders a Cryptoki bit field: the raw value plus the CKF_ names set in
// it, so a reader does not have to decode 0x0004050D by hand. Unrecognized bits
// are reported as "0x…" entries rather than dropped.
type Flags struct {
	Value uint     `json:"value"`
	Hex   string   `json:"hex"`
	Names []string `json:"names"`
}

// ModuleInfo is C_GetInfo plus every slot the module reports.
type ModuleInfo struct {
	// ModulePath is the shared object this view was read through.
	ModulePath         string     `json:"module_path"`
	CryptokiVersion    string     `json:"cryptoki_version"`
	ManufacturerID     string     `json:"manufacturer_id"`
	LibraryDescription string     `json:"library_description"`
	LibraryVersion     string     `json:"library_version"`
	Flags              Flags      `json:"flags"`
	Slots              []SlotInfo `json:"slots"`
}

// SlotInfo is CK_SLOT_INFO for one slot, with the token in it (when present)
// and the mechanisms it offers.
type SlotInfo struct {
	SlotID          uint   `json:"slot_id"`
	Description     string `json:"description"`
	ManufacturerID  string `json:"manufacturer_id"`
	Flags           Flags  `json:"flags"`
	HardwareVersion string `json:"hardware_version"`
	FirmwareVersion string `json:"firmware_version"`
	TokenPresent    bool   `json:"token_present"`
	// Selected marks the slot this deployment's token selectors resolved to —
	// the one the CA actually signs on. A module may present several.
	Selected   bool            `json:"selected"`
	Token      *TokenInfo      `json:"token,omitempty"`
	Mechanisms []MechanismInfo `json:"mechanisms,omitempty"`
	// Error carries a per-slot failure (a token that refuses C_GetTokenInfo,
	// say) so one bad slot does not fail the whole view.
	Error string `json:"error,omitempty"`
}

// TokenInfo is CK_TOKEN_INFO. The counts are strings because Cryptoki
// overloads them: CK_UNAVAILABLE_INFORMATION (~0) and CK_EFFECTIVELY_INFINITE
// (0) are sentinels, not quantities — and ~0 as a JSON number loses precision
// in every JavaScript consumer.
type TokenInfo struct {
	Label              string `json:"label"`
	ManufacturerID     string `json:"manufacturer_id"`
	Model              string `json:"model"`
	SerialNumber       string `json:"serial_number"`
	Flags              Flags  `json:"flags"`
	MaxSessionCount    string `json:"max_session_count"`
	SessionCount       string `json:"session_count"`
	MaxRwSessionCount  string `json:"max_rw_session_count"`
	RwSessionCount     string `json:"rw_session_count"`
	MaxPinLen          string `json:"max_pin_len"`
	MinPinLen          string `json:"min_pin_len"`
	TotalPublicMemory  string `json:"total_public_memory"`
	FreePublicMemory   string `json:"free_public_memory"`
	TotalPrivateMemory string `json:"total_private_memory"`
	FreePrivateMemory  string `json:"free_private_memory"`
	HardwareVersion    string `json:"hardware_version"`
	FirmwareVersion    string `json:"firmware_version"`
	UTCTime            string `json:"utc_time"`
}

// MechanismInfo is one CK_MECHANISM_TYPE with its CK_MECHANISM_INFO.
type MechanismInfo struct {
	Type       uint   `json:"type"`
	Hex        string `json:"hex"`
	Name       string `json:"name"`
	MinKeySize uint   `json:"min_key_size"`
	MaxKeySize uint   `json:"max_key_size"`
	Flags      Flags  `json:"flags"`
	Error      string `json:"error,omitempty"`
}

// Attribute status values. They separate three very different answers a token
// gives, which a bare empty value would conflate.
const (
	// AttrStatusPresent — the token returned a value.
	AttrStatusPresent = "present"
	// AttrStatusUnavailable — the token refused: the object has no such
	// attribute, or it is sensitive. Reason carries the CKR_ name, and that
	// refusal is itself evidence (CKR_ATTRIBUTE_SENSITIVE on a CA key is the
	// token asserting the private value cannot be read).
	AttrStatusUnavailable = "unavailable"
	// AttrStatusWithheld — the inspector did not ask: the value would be
	// private key material.
	AttrStatusWithheld = "withheld"
	// AttrStatusNotRead — the inspector cannot ask portably (a CK_ATTRIBUTE
	// array attribute).
	AttrStatusNotRead = "not-read"
)

// ObjectAttribute is one CK_ATTRIBUTE read (or deliberately not read) from one
// object.
type ObjectAttribute struct {
	Type    uint   `json:"type"`
	TypeHex string `json:"type_hex"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	// Length is the byte length the token returned for the value.
	Length int `json:"length"`
	// Value is the decoded rendering: "true", a decimal, a CKM_ name, a curve
	// name, a distinguished name, a certificate summary.
	Value string `json:"value,omitempty"`
	// Raw is the hex of the value's bytes, capped at MaxValueBytes.
	Raw string `json:"raw,omitempty"`
	// RawTruncated reports that Raw is a prefix of the value.
	RawTruncated bool `json:"raw_truncated,omitempty"`
	// SHA256 is over the WHOLE value (not the truncated prefix), present for
	// values long enough that comparing them by eye is impractical.
	SHA256 string `json:"sha256,omitempty"`
	// Reason explains a non-present status: a CKR_ name, or the policy.
	Reason string `json:"reason,omitempty"`
}

// Object is one object on the token: its handle, the identity attributes
// promoted for display, and every attribute read from it.
type Object struct {
	Handle    uint   `json:"handle"`
	HandleHex string `json:"handle_hex"`
	Class     uint   `json:"class"`
	ClassName string `json:"class_name"`
	// Label / ID / KeyType / CertType are promoted out of Attributes so a list
	// of objects is readable without expanding each one. They are exactly the
	// values in the attribute table, not a second source of truth.
	Label   string `json:"label"`
	ID      string `json:"id,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	// Size is C_GetObjectSize, which many modules decline; empty when declined.
	Size       string            `json:"size,omitempty"`
	Attributes []ObjectAttribute `json:"attributes"`
}

// ObjectSet is the result of enumerating one token's objects.
type ObjectSet struct {
	SlotID      uint     `json:"slot_id"`
	TokenLabel  string   `json:"token_label,omitempty"`
	TokenSerial string   `json:"token_serial,omitempty"`
	Objects     []Object `json:"objects"`
	// Truncated reports that the token holds more objects than MaxObjects.
	Truncated bool `json:"truncated,omitempty"`
	// Counts summarises the set by class name, so "what is on this token" is
	// answerable without reading every row.
	Counts map[string]int `json:"counts"`
}

// --- rendering helpers -----------------------------------------------------

func hexNum(v uint) string { return "0x" + strconv.FormatUint(uint64(v), 16) }

func version(v pkcs11.Version) string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// trimPad strips the blank padding Cryptoki specifies for the fixed-width
// character fields of CK_INFO / CK_SLOT_INFO / CK_TOKEN_INFO.
func trimPad(s string) string { return strings.TrimRight(s, " \x00") }

// ulongValue renders a CK_ULONG field of CK_TOKEN_INFO, naming the two
// sentinels the standard reserves.
func ulongValue(v uint) string {
	if v == pkcs11.CK_UNAVAILABLE_INFORMATION {
		return "unavailable"
	}
	return strconv.FormatUint(uint64(v), 10)
}

// sessionCount renders a session-count field, where 0 additionally means
// CK_EFFECTIVELY_INFINITE for the two maxima.
func sessionCount(v uint, maximum bool) string {
	if maximum && v == pkcs11.CK_EFFECTIVELY_INFINITE {
		return "effectively infinite"
	}
	return ulongValue(v)
}

// flagNames decodes a bit field against a table of bit -> CKF_ name. Bits with
// no entry are kept as hex so nothing silently disappears.
func flagNames(v uint, table map[uint]string) Flags {
	f := Flags{Value: v, Hex: fmt.Sprintf("0x%08X", v), Names: []string{}}
	bits := make([]uint, 0, len(table))
	for bit := range table {
		bits = append(bits, bit)
	}
	sort.Slice(bits, func(i, j int) bool { return bits[i] < bits[j] })
	rest := v
	for _, bit := range bits {
		if v&bit != 0 {
			f.Names = append(f.Names, table[bit])
			rest &^= bit
		}
	}
	for bit := uint(1); bit != 0 && rest != 0; bit <<= 1 {
		if rest&bit != 0 {
			f.Names = append(f.Names, hexNum(bit))
			rest &^= bit
		}
	}
	return f
}

// The three CKF_ namespaces. Cryptoki reuses the same bit values across slot,
// token and mechanism flags with entirely different meanings, so they cannot
// share one table — 0x00000002 is CKF_REMOVABLE_DEVICE on a slot,
// CKF_WRITE_PROTECTED on a token and CKF_DECRYPT on a mechanism.
var slotFlagNames = map[uint]string{
	pkcs11.CKF_TOKEN_PRESENT:    "CKF_TOKEN_PRESENT",
	pkcs11.CKF_REMOVABLE_DEVICE: "CKF_REMOVABLE_DEVICE",
	pkcs11.CKF_HW_SLOT:          "CKF_HW_SLOT",
}

var tokenFlagNames = map[uint]string{
	pkcs11.CKF_RNG:                           "CKF_RNG",
	pkcs11.CKF_WRITE_PROTECTED:               "CKF_WRITE_PROTECTED",
	pkcs11.CKF_LOGIN_REQUIRED:                "CKF_LOGIN_REQUIRED",
	pkcs11.CKF_USER_PIN_INITIALIZED:          "CKF_USER_PIN_INITIALIZED",
	pkcs11.CKF_RESTORE_KEY_NOT_NEEDED:        "CKF_RESTORE_KEY_NOT_NEEDED",
	pkcs11.CKF_CLOCK_ON_TOKEN:                "CKF_CLOCK_ON_TOKEN",
	pkcs11.CKF_PROTECTED_AUTHENTICATION_PATH: "CKF_PROTECTED_AUTHENTICATION_PATH",
	pkcs11.CKF_DUAL_CRYPTO_OPERATIONS:        "CKF_DUAL_CRYPTO_OPERATIONS",
	pkcs11.CKF_TOKEN_INITIALIZED:             "CKF_TOKEN_INITIALIZED",
	pkcs11.CKF_SECONDARY_AUTHENTICATION:      "CKF_SECONDARY_AUTHENTICATION",
	pkcs11.CKF_USER_PIN_COUNT_LOW:            "CKF_USER_PIN_COUNT_LOW",
	pkcs11.CKF_USER_PIN_FINAL_TRY:            "CKF_USER_PIN_FINAL_TRY",
	pkcs11.CKF_USER_PIN_LOCKED:               "CKF_USER_PIN_LOCKED",
	pkcs11.CKF_USER_PIN_TO_BE_CHANGED:        "CKF_USER_PIN_TO_BE_CHANGED",
	pkcs11.CKF_SO_PIN_COUNT_LOW:              "CKF_SO_PIN_COUNT_LOW",
	pkcs11.CKF_SO_PIN_FINAL_TRY:              "CKF_SO_PIN_FINAL_TRY",
	pkcs11.CKF_SO_PIN_LOCKED:                 "CKF_SO_PIN_LOCKED",
	pkcs11.CKF_SO_PIN_TO_BE_CHANGED:          "CKF_SO_PIN_TO_BE_CHANGED",
	pkcs11.CKF_ERROR_STATE:                   "CKF_ERROR_STATE",
}

var mechanismFlagNames = map[uint]string{
	pkcs11.CKF_HW:                "CKF_HW",
	pkcs11.CKF_ENCRYPT:           "CKF_ENCRYPT",
	pkcs11.CKF_DECRYPT:           "CKF_DECRYPT",
	pkcs11.CKF_DIGEST:            "CKF_DIGEST",
	pkcs11.CKF_SIGN:              "CKF_SIGN",
	pkcs11.CKF_SIGN_RECOVER:      "CKF_SIGN_RECOVER",
	pkcs11.CKF_VERIFY:            "CKF_VERIFY",
	pkcs11.CKF_VERIFY_RECOVER:    "CKF_VERIFY_RECOVER",
	pkcs11.CKF_GENERATE:          "CKF_GENERATE",
	pkcs11.CKF_GENERATE_KEY_PAIR: "CKF_GENERATE_KEY_PAIR",
	pkcs11.CKF_WRAP:              "CKF_WRAP",
	pkcs11.CKF_UNWRAP:            "CKF_UNWRAP",
	pkcs11.CKF_DERIVE:            "CKF_DERIVE",
	pkcs11.CKF_EC_F_P:            "CKF_EC_F_P",
	pkcs11.CKF_EC_F_2M:           "CKF_EC_F_2M",
	pkcs11.CKF_EC_ECPARAMETERS:   "CKF_EC_ECPARAMETERS",
	pkcs11.CKF_EC_NAMEDCURVE:     "CKF_EC_NAMEDCURVE",
	pkcs11.CKF_EC_UNCOMPRESS:     "CKF_EC_UNCOMPRESS",
	pkcs11.CKF_EC_COMPRESS:       "CKF_EC_COMPRESS",
	pkcs11.CKF_EXTENSION:         "CKF_EXTENSION",
}

var libraryFlagNames = map[uint]string{
	pkcs11.CKF_LIBRARY_CANT_CREATE_OS_THREADS: "CKF_LIBRARY_CANT_CREATE_OS_THREADS",
	pkcs11.CKF_OS_LOCKING_OK:                  "CKF_OS_LOCKING_OK",
}

// ckrName names a Cryptoki return value, which is how a refused attribute read
// reports itself. A non-Cryptoki error (the module is gone, the session died)
// is passed through as its own text.
func ckrName(err error) string {
	var ckr pkcs11.Error
	if ok := asPKCS11Error(err, &ckr); ok {
		if n, found := ckrNames[uint(ckr)]; found {
			return n
		}
		return "CKR_" + hexNum(uint(ckr))
	}
	return err.Error()
}

// asPKCS11Error unwraps err to a pkcs11.Error. The binding returns the bare
// value type, so this is a type assertion rather than errors.As plumbing — kept
// as a function so every caller treats a wrapped error the same way.
func asPKCS11Error(err error, out *pkcs11.Error) bool {
	for err != nil {
		if e, ok := err.(pkcs11.Error); ok { //nolint:errorlint // the binding returns a bare value type
			*out = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// cryptoki is the subset of the PKCS#11 module API the inspector calls.
// *pkcs11.Ctx satisfies it, and nothing else does in production — the point of
// naming it is the tests: a fake module exercises the branches a healthy token
// never produces (a slot that refuses C_GetSlotInfo, a mechanism whose
// C_GetMechanismInfo fails, a module that answers a batch with the wrong number
// of attributes), which is most of the error handling in this file. Those are
// exactly the paths that matter when a module misbehaves, and exactly the ones
// a SoftHSM-backed test cannot reach.
type cryptoki interface {
	GetInfo() (pkcs11.Info, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error)
	GetMechanismInfo(slotID uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error)
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	GetObjectSize(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) (uint, error)
}

var _ cryptoki = (*pkcs11.Ctx)(nil)

// --- module / slot / token view -------------------------------------------

// moduleInfoOnCtx reads C_GetInfo and every slot, on a module context the
// caller already holds a reference to. selected, when non-nil, marks the slot
// this deployment resolved to.
func moduleInfoOnCtx(ctx cryptoki, modulePath string, selected *uint, opts InspectOptions) (*ModuleInfo, error) {
	info, err := ctx.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("C_GetInfo: %w", err)
	}
	out := &ModuleInfo{
		ModulePath:         modulePath,
		CryptokiVersion:    version(info.CryptokiVersion),
		ManufacturerID:     trimPad(info.ManufacturerID),
		LibraryDescription: trimPad(info.LibraryDescription),
		LibraryVersion:     version(info.LibraryVersion),
		Flags:              flagNames(info.Flags, libraryFlagNames),
		Slots:              []SlotInfo{},
	}

	// Every slot, not only those with a token: an empty slot is the answer to
	// "why does the token selector not match anything".
	slots, err := ctx.GetSlotList(false)
	if err != nil {
		return nil, fmt.Errorf("C_GetSlotList: %w", err)
	}
	for _, id := range slots {
		s := SlotInfo{SlotID: id, Selected: selected != nil && *selected == id}
		si, serr := ctx.GetSlotInfo(id)
		if serr != nil {
			s.Error = "C_GetSlotInfo: " + ckrName(serr)
			out.Slots = append(out.Slots, s)
			continue
		}
		s.Description = trimPad(si.SlotDescription)
		s.ManufacturerID = trimPad(si.ManufacturerID)
		s.Flags = flagNames(si.Flags, slotFlagNames)
		s.HardwareVersion = version(si.HardwareVersion)
		s.FirmwareVersion = version(si.FirmwareVersion)
		s.TokenPresent = si.Flags&pkcs11.CKF_TOKEN_PRESENT != 0

		if s.TokenPresent {
			if ti, terr := ctx.GetTokenInfo(id); terr != nil {
				s.Error = "C_GetTokenInfo: " + ckrName(terr)
			} else {
				s.Token = tokenInfoOf(ti)
			}
		}
		if !opts.SkipMechanisms && s.TokenPresent {
			s.Mechanisms = mechanismsOf(ctx, id)
		}
		out.Slots = append(out.Slots, s)
	}
	return out, nil
}

func tokenInfoOf(ti pkcs11.TokenInfo) *TokenInfo {
	return &TokenInfo{
		Label:              trimPad(ti.Label),
		ManufacturerID:     trimPad(ti.ManufacturerID),
		Model:              trimPad(ti.Model),
		SerialNumber:       trimPad(ti.SerialNumber),
		Flags:              flagNames(ti.Flags, tokenFlagNames),
		MaxSessionCount:    sessionCount(ti.MaxSessionCount, true),
		SessionCount:       sessionCount(ti.SessionCount, false),
		MaxRwSessionCount:  sessionCount(ti.MaxRwSessionCount, true),
		RwSessionCount:     sessionCount(ti.RwSessionCount, false),
		MaxPinLen:          ulongValue(ti.MaxPinLen),
		MinPinLen:          ulongValue(ti.MinPinLen),
		TotalPublicMemory:  ulongValue(ti.TotalPublicMemory),
		FreePublicMemory:   ulongValue(ti.FreePublicMemory),
		TotalPrivateMemory: ulongValue(ti.TotalPrivateMemory),
		FreePrivateMemory:  ulongValue(ti.FreePrivateMemory),
		HardwareVersion:    version(ti.HardwareVersion),
		FirmwareVersion:    version(ti.FirmwareVersion),
		UTCTime:            trimPad(ti.UTCTime),
	}
}

// mechanismsOf lists a slot's mechanisms with their key-size ranges and flags.
// A mechanism whose C_GetMechanismInfo fails is still listed, carrying the
// error: the module offering it at all is the interesting part.
func mechanismsOf(ctx cryptoki, slotID uint) []MechanismInfo {
	list, err := ctx.GetMechanismList(slotID)
	if err != nil {
		return []MechanismInfo{{Error: "C_GetMechanismList: " + ckrName(err)}}
	}
	out := make([]MechanismInfo, 0, len(list))
	for _, m := range list {
		mi := MechanismInfo{
			Type: m.Mechanism,
			Hex:  fmt.Sprintf("0x%08X", m.Mechanism),
			Name: mechanismName(m.Mechanism),
		}
		if info, ierr := ctx.GetMechanismInfo(slotID, []*pkcs11.Mechanism{pkcs11.NewMechanism(m.Mechanism, nil)}); ierr != nil {
			mi.Error = "C_GetMechanismInfo: " + ckrName(ierr)
		} else {
			mi.MinKeySize = info.MinKeySize
			mi.MaxKeySize = info.MaxKeySize
			mi.Flags = flagNames(info.Flags, mechanismFlagNames)
		}
		out = append(out, mi)
	}
	return out
}

// mechanismName names a mechanism, keeping a vendor-defined one identifiable.
func mechanismName(m uint) string {
	if n, ok := ckmNames[m]; ok {
		return n
	}
	if m&pkcs11.CKM_VENDOR_DEFINED != 0 {
		return "CKM_VENDOR_DEFINED+" + hexNum(m&^pkcs11.CKM_VENDOR_DEFINED)
	}
	return "CKM_" + hexNum(m)
}

// --- object enumeration ----------------------------------------------------

// objectsOnSession enumerates every object the session can see and reads the
// catalogued attributes of each.
//
// The find template is empty on purpose: C_FindObjectsInit with no attributes
// matches all objects, which is the only way to see one this PKI did not
// create. What the session can see still depends on the login state — private
// objects require an authenticated session — so the inspector runs on the
// serving pool's logged-in session, or logs in itself for the one-shot path.
func objectsOnSession(ctx cryptoki, session pkcs11.SessionHandle, slotID uint, opts InspectOptions) (*ObjectSet, error) {
	if err := ctx.FindObjectsInit(session, nil); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit: %w", err)
	}
	limit := opts.maxObjects()
	var (
		handles   []pkcs11.ObjectHandle
		truncated bool
	)
	for {
		batch, more, ferr := ctx.FindObjects(session, 64)
		if ferr != nil {
			// Close the search before reporting the failure, so the session is
			// not left with one active (which refuses the next C_FindObjectsInit).
			// The request has already failed; a failure to close cannot change that.
			_ = ctx.FindObjectsFinal(session)
			return nil, fmt.Errorf("C_FindObjects: %w", ferr)
		}
		if len(batch) == 0 {
			break
		}
		handles = append(handles, batch...)
		if len(handles) > limit {
			truncated = true
			handles = handles[:limit]
			break
		}
		// `more` is the module's hint that the buffer was filled; an empty
		// batch is the reliable terminator, so it is only used to stop early.
		if !more && len(batch) < 64 {
			break
		}
	}
	if err := ctx.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("C_FindObjectsFinal: %w", err)
	}

	set := &ObjectSet{SlotID: slotID, Truncated: truncated, Objects: []Object{}, Counts: map[string]int{}}
	if ti, err := ctx.GetTokenInfo(slotID); err == nil {
		set.TokenLabel = trimPad(ti.Label)
		set.TokenSerial = trimPad(ti.SerialNumber)
	}
	for _, h := range handles {
		obj := inspectObject(ctx, session, h, opts)
		set.Counts[obj.ClassName]++
		set.Objects = append(set.Objects, obj)
	}
	return set, nil
}

// inspectObject reads one object: its class first (the class decides which
// attributes the standard defines for it), then every applicable attribute.
func inspectObject(ctx cryptoki, session pkcs11.SessionHandle, h pkcs11.ObjectHandle, opts InspectOptions) Object {
	obj := Object{
		Handle:    uint(h),
		HandleHex: hexNum(uint(h)),
		ClassName: "unknown",
	}

	// CKA_CLASS on its own: it steers everything else, and an object that
	// refuses it still gets the storage attributes asked of it.
	class := uint(0)
	classKnown := false
	if attrs, err := ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	}); err == nil && len(attrs) == 1 && len(attrs[0].Value) > 0 {
		class = uint(bytesToULong(attrs[0].Value))
		classKnown = true
		obj.Class = class
		if n, ok := ckoNames[class]; ok {
			obj.ClassName = n
		} else {
			obj.ClassName = hexNum(class)
		}
	}

	// C_GetObjectSize is optional and widely unimplemented — SoftHSM answers
	// CK_UNAVAILABLE_INFORMATION rather than an error — so both "it refused"
	// and "it declined to say" leave the field empty instead of printing a
	// non-answer.
	if size, err := ctx.GetObjectSize(session, h); err == nil && size != pkcs11.CK_UNAVAILABLE_INFORMATION {
		obj.Size = ulongValue(size)
	}

	// Which attributes to ask for. Withheld and unreadable ones are recorded
	// without a round trip; the rest are fetched in as few C_GetAttributeValue
	// calls as the token's refusals allow.
	var (
		wanted []uint
		specs  = map[uint]attrSpec{}
	)
	for _, a := range pkcs11Attributes {
		if !opts.AllAttributes && classKnown && !a.spec.applies(class) {
			continue
		}
		specs[a.typ] = a.spec
		switch {
		case a.spec.withheldFor(class):
			obj.Attributes = append(obj.Attributes, ObjectAttribute{
				Type: a.typ, TypeHex: fmt.Sprintf("0x%08X", a.typ), Name: attributeName(a.typ),
				Kind: string(a.spec.kind), Status: AttrStatusWithheld,
				Reason: "not requested: the value is private key material",
			})
		case a.spec.kind == kindTemplate:
			obj.Attributes = append(obj.Attributes, ObjectAttribute{
				Type: a.typ, TypeHex: fmt.Sprintf("0x%08X", a.typ), Name: attributeName(a.typ),
				Kind: string(a.spec.kind), Status: AttrStatusNotRead,
				Reason: "not requested: a CK_ATTRIBUTE array cannot be read without a caller-built template",
			})
		default:
			wanted = append(wanted, a.typ)
		}
	}

	values := readAttributes(sessionFetcher(ctx, session, h), wanted)
	for _, typ := range wanted {
		obj.Attributes = append(obj.Attributes, renderAttribute(typ, specs[typ], class, values[typ], opts))
	}

	// Sort into catalogue order: withheld/not-read rows were appended as the
	// catalogue was walked, the fetched ones after, so one pass restores it.
	order := map[uint]int{}
	for i, a := range pkcs11Attributes {
		order[a.typ] = i
	}
	sort.SliceStable(obj.Attributes, func(i, j int) bool {
		return order[obj.Attributes[i].Type] < order[obj.Attributes[j].Type]
	})

	// Drop the attributes the token says the object simply does not have,
	// unless the caller asked for the whole catalogue — "CKA_PIXEL_X:
	// CKR_ATTRIBUTE_TYPE_INVALID" is noise, while a sensitive refusal is not.
	if !opts.AllAttributes {
		kept := obj.Attributes[:0]
		for _, a := range obj.Attributes {
			if a.Status == AttrStatusUnavailable && a.Reason == "CKR_ATTRIBUTE_TYPE_INVALID" {
				continue
			}
			kept = append(kept, a)
		}
		obj.Attributes = kept
	}

	// Promote the identity attributes for the list view.
	for _, a := range obj.Attributes {
		switch a.Type {
		case pkcs11.CKA_LABEL:
			obj.Label = a.Value
		case pkcs11.CKA_ID:
			obj.ID = a.Raw
		case pkcs11.CKA_KEY_TYPE, pkcs11.CKA_CERTIFICATE_TYPE:
			if obj.KeyType == "" {
				obj.KeyType = a.Value
			}
		}
	}
	return obj
}

// attrResult is one attribute's outcome: its bytes, or the token's refusal.
type attrResult struct {
	value []byte
	err   error
}

// readAttributes fetches a set of attributes in as few calls as possible.
//
// C_GetAttributeValue is all-or-nothing through this binding: one unsupported
// or sensitive attribute in the template and the whole call returns an error
// with no values. (The standard lets a module fill in the attributes that did
// succeed and flag the rest with CK_UNAVAILABLE_INFORMATION; the binding
// discards them.) Asking for each attribute individually is therefore the only
// reliable way — but that is ~60 round trips per object, which on a token
// reached over a USB connector is seconds per object.
//
// So: ask for the whole batch, and on refusal split it in half and recurse.
// A token that answers everything costs one call; each refused attribute costs
// O(log n) extra, and the common case (a handful of refusals among many
// supported attributes) lands much closer to one call than to n.
func readAttributes(fetch attrFetcher, types []uint) map[uint]attrResult {
	out := make(map[uint]attrResult, len(types))
	readAttributeBatch(fetch, types, out)
	return out
}

// attrFetcher is one C_GetAttributeValue call: the types asked for, and either
// the values the token returned (positionally) or its refusal. Keeping the
// Cryptoki call behind a function makes the subdivision above testable without
// a token, which matters because its failure mode — a misaligned result — is
// one that silently attributes one attribute's bytes to another.
type attrFetcher func(types []uint) ([]*pkcs11.Attribute, error)

// sessionFetcher is the production attrFetcher: one C_GetAttributeValue against
// an object on a session.
func sessionFetcher(ctx cryptoki, session pkcs11.SessionHandle, h pkcs11.ObjectHandle) attrFetcher {
	return func(types []uint) ([]*pkcs11.Attribute, error) {
		tmpl := make([]*pkcs11.Attribute, 0, len(types))
		for _, t := range types {
			tmpl = append(tmpl, pkcs11.NewAttribute(t, nil))
		}
		return ctx.GetAttributeValue(session, h, tmpl)
	}
}

func readAttributeBatch(fetch attrFetcher, types []uint, out map[uint]attrResult) {
	if len(types) == 0 {
		return
	}
	attrs, err := fetch(types)
	if err == nil {
		// Positional: C_GetAttributeValue fills the template in place, so
		// attrs[i] is the answer for types[i]. A module returning a different
		// count is not trusted to have kept the order — each extra or missing
		// entry would shift every attribute after it onto the wrong name — so
		// the batch is re-read one attribute at a time instead.
		if len(attrs) == len(types) {
			for i, a := range attrs {
				out[types[i]] = attrResult{value: a.Value}
			}
			return
		}
		if len(types) == 1 {
			out[types[0]] = attrResult{err: fmt.Errorf("module returned %d values for 1 attribute", len(attrs))}
			return
		}
	} else if len(types) == 1 {
		out[types[0]] = attrResult{err: err}
		return
	}
	mid := len(types) / 2
	readAttributeBatch(fetch, types[:mid], out)
	readAttributeBatch(fetch, types[mid:], out)
}

// renderAttribute turns one raw result into a display row.
func renderAttribute(typ uint, spec attrSpec, class uint, res attrResult, opts InspectOptions) ObjectAttribute {
	a := ObjectAttribute{
		Type:    typ,
		TypeHex: fmt.Sprintf("0x%08X", typ),
		Name:    attributeName(typ),
		Kind:    string(spec.kind),
	}
	if res.err != nil {
		a.Status = AttrStatusUnavailable
		a.Reason = ckrName(res.err)
		return a
	}
	a.Status = AttrStatusPresent
	a.Length = len(res.value)
	a.Value = renderValue(typ, spec.kind, class, res.value)

	// The hex of the bytes, capped. The SHA-256 is over the whole value, so a
	// truncated certificate body or modulus can still be compared.
	limit := opts.maxValueBytes()
	raw := res.value
	if len(raw) > limit {
		raw = raw[:limit]
		a.RawTruncated = true
	}
	if spec.kind != kindString && len(raw) > 0 {
		a.Raw = hex.EncodeToString(raw)
	} else if spec.kind == kindString && a.RawTruncated {
		// A truncated string still gets its bytes, since Value was elided.
		a.Raw = hex.EncodeToString(raw)
	}
	if len(res.value) > 32 {
		sum := sha256.Sum256(res.value)
		a.SHA256 = hex.EncodeToString(sum[:])
	}
	return a
}

// renderValue decodes an attribute value according to its Cryptoki type. It is
// display only: Raw always carries the bytes, so a decoding this does not know
// how to do costs nothing.
func renderValue(typ uint, kind attrKind, class uint, v []byte) string {
	if len(v) == 0 {
		return ""
	}
	switch kind {
	case kindBool:
		if len(v) != 1 {
			return fmt.Sprintf("(%d-byte CK_BBOOL)", len(v))
		}
		if v[0] != 0 {
			return "true"
		}
		return "false"
	case kindULong:
		return ulongValue(uint(bytesToULong(v)))
	case kindString:
		return printableString(v)
	case kindBigInt:
		n := new(big.Int).SetBytes(v)
		return fmt.Sprintf("%d bits, 0x%s", n.BitLen(), strings.ToUpper(n.Text(16)))
	case kindDate:
		return renderDate(v)
	case kindClass:
		return namedValue(ckoNames, uint(bytesToULong(v)))
	case kindKeyType:
		return namedValue(ckkNames, uint(bytesToULong(v)))
	case kindCertType:
		return namedValue(ckcNames, uint(bytesToULong(v)))
	case kindHWFeature:
		return namedValue(ckhNames, uint(bytesToULong(v)))
	case kindMechanism:
		return mechanismName(uint(bytesToULong(v)))
	case kindMechList:
		return renderMechanismList(v)
	case kindDER:
		return renderDER(typ, v)
	case kindBytes:
		return renderBytes(typ, class, v)
	}
	return ""
}

// bytesToULong reads a CK_ULONG as the module wrote it. Cryptoki's CK_ULONG is
// native-endian and platform-width, and every module in use here is
// little-endian LP64 — but a module compiled 32-bit against a 64-bit caller
// writes 4 bytes, so the length is honoured rather than assumed.
func bytesToULong(v []byte) uint64 {
	var n uint64
	for i := len(v) - 1; i >= 0; i-- {
		n = n<<8 | uint64(v[i])
	}
	return n
}

// renderDate decodes CK_DATE (8 ASCII digits, YYYYMMDD). An all-zero or empty
// value is the standard's "unset", which is what an unexpired key looks like.
func renderDate(v []byte) string {
	trimmed := strings.TrimRight(string(v), "\x00 ")
	if trimmed == "" || strings.Trim(trimmed, "0") == "" {
		return "(unset)"
	}
	if t, err := time.Parse("20060102", trimmed); err == nil {
		return t.Format("2006-01-02")
	}
	return printableString(v)
}

// renderMechanismList decodes a CK_MECHANISM_TYPE array (CKA_ALLOWED_MECHANISMS).
func renderMechanismList(v []byte) string {
	// The element width is the module's CK_ULONG width, inferred from the
	// value: 8 bytes per element on LP64, 4 on a 32-bit module.
	width := 8
	if len(v)%8 != 0 && len(v)%4 == 0 {
		width = 4
	}
	if len(v) < width {
		return ""
	}
	names := make([]string, 0, len(v)/width)
	for i := 0; i+width <= len(v); i += width {
		names = append(names, mechanismName(uint(bytesToULong(v[i:i+width]))))
	}
	return strings.Join(names, ", ")
}

// renderDER decodes the DER-encoded attributes worth decoding: a curve OID into
// its curve name, a distinguished name into its RFC 4514 form, a certificate
// serial into an integer, an EC point out of its OCTET STRING wrapper, and an
// SPKI into its algorithm. Anything else is left to Raw.
func renderDER(typ uint, v []byte) string {
	switch typ {
	case pkcs11.CKA_EC_PARAMS:
		return renderECParams(v)
	case pkcs11.CKA_SUBJECT, pkcs11.CKA_ISSUER, pkcs11.CKA_AC_ISSUER, pkcs11.CKA_OWNER:
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(v, &rdn); err == nil {
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			return name.String()
		}
	case pkcs11.CKA_SERIAL_NUMBER:
		serial := new(big.Int)
		if _, err := asn1.Unmarshal(v, &serial); err == nil {
			return fmt.Sprintf("%d (0x%s)", serial, strings.ToUpper(serial.Text(16)))
		}
	case pkcs11.CKA_EC_POINT:
		var point []byte
		if _, err := asn1.Unmarshal(v, &point); err == nil && len(point) > 0 {
			form := "uncompressed"
			if point[0] == 0x02 || point[0] == 0x03 {
				form = "compressed"
			}
			return fmt.Sprintf("%s point, %d bytes", form, len(point))
		}
	case pkcs11.CKA_PUBLIC_KEY_INFO:
		if pub, err := x509.ParsePKIXPublicKey(v); err == nil {
			return fmt.Sprintf("SubjectPublicKeyInfo, %T", pub)
		}
	case pkcs11.CKA_OBJECT_ID:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(v, &oid); err == nil {
			return oid.String()
		}
	}
	return ""
}

// namedCurves maps the curve OIDs a PKCS#11 CKA_EC_PARAMS carries to their
// usual names. The attribute is the DER of an ECParameters CHOICE, and in
// practice always the namedCurve alternative — a bare OID.
var namedCurves = map[string]string{
	"1.2.840.10045.3.1.7": "P-256 (prime256v1 / secp256r1)",
	"1.3.132.0.34":        "P-384 (secp384r1)",
	"1.3.132.0.35":        "P-521 (secp521r1)",
	"1.3.132.0.10":        "secp256k1",
	"1.2.840.10045.3.1.1": "P-192 (prime192v1 / secp192r1)",
	"1.3.132.0.33":        "P-224 (secp224r1)",
	"1.3.101.112":         "Ed25519",
	"1.3.101.110":         "X25519",
	"1.3.101.113":         "Ed448",
	"1.3.101.111":         "X448",
}

func renderECParams(v []byte) string {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(v, &oid); err == nil {
		if name, ok := namedCurves[oid.String()]; ok {
			return name + " [" + oid.String() + "]"
		}
		return "curve OID " + oid.String()
	}
	// Some modules store Ed25519 parameters as a PrintableString curve name.
	if s := printableString(v); s != "" {
		return s
	}
	return "explicit ECParameters"
}

// shortBytesLimit is the length up to which an opaque byte value is rendered as
// its own hex rather than as a byte count. A CKA_ID, a CKA_CHECK_VALUE or a
// public-key hash is short and IS its bytes; a certificate body or a wrapped
// blob is not, and a line of hex in place of "1174 bytes" helps nobody (the
// full hex is in Raw either way).
const shortBytesLimit = 32

// renderBytes summarises an opaque byte attribute. CKA_VALUE on a certificate
// object is the one case worth parsing: the object list is far more useful when
// a certificate row says whose certificate it is.
func renderBytes(typ uint, class uint, v []byte) string {
	if typ == pkcs11.CKA_VALUE && class == pkcs11.CKO_CERTIFICATE {
		if cert, err := x509.ParseCertificate(v); err == nil {
			return fmt.Sprintf("X.509: subject %s, issuer %s, serial %s, not after %s",
				cert.Subject.String(), cert.Issuer.String(),
				cert.SerialNumber.String(), cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if len(v) <= shortBytesLimit {
		return "0x" + hex.EncodeToString(v)
	}
	return fmt.Sprintf("%d bytes", len(v))
}

// printableString renders a Cryptoki character attribute, keeping it safe to
// put in a terminal or a browser: printable runes pass through, anything else
// is elided in favour of the hex in Raw.
func printableString(v []byte) string {
	s := strings.TrimRight(string(v), "\x00")
	if !utf8.ValidString(s) {
		return fmt.Sprintf("(%d non-UTF-8 bytes)", len(v))
	}
	for _, r := range s {
		if r != '\t' && r != '\n' && !unicode.IsPrint(r) {
			return fmt.Sprintf("(%d bytes, not printable)", len(v))
		}
	}
	return s
}

// --- entry points ----------------------------------------------------------

// Inspection is a complete raw view of one token: the module and its slots,
// plus the objects on the token this configuration resolves to.
type Inspection struct {
	Module  *ModuleInfo `json:"module"`
	Objects *ObjectSet  `json:"objects,omitempty"`
}

// InspectModule reads the module, slot and token view without enumerating
// objects, opening no session: C_GetInfo, C_GetSlotList, C_GetSlotInfo,
// C_GetTokenInfo and the mechanism lists need no login. It still takes a
// reference on the shared module context rather than loading its own, so it
// cannot finalize a module the serving pool is using.
func InspectModule(cfg PKCS11Config, opts InspectOptions) (*ModuleInfo, error) {
	ctx, err := acquireModule(cfg.ModulePath)
	if err != nil {
		return nil, err
	}
	defer releaseModule(cfg.ModulePath)

	// Best-effort: mark the slot the configuration selects, when it resolves.
	var selected *uint
	if slots, serr := ctx.GetSlotList(true); serr == nil {
		if id, ferr := findToken(ctx, slots, cfg); ferr == nil {
			selected = &id
		}
	}
	return moduleInfoOnCtx(ctx, cfg.ModulePath, selected, opts)
}

// Inspect reads the module view and enumerates the objects on the configured
// token, over a short-lived authenticated session. It is the one-shot path used
// by the CLI; a running server inspects through its session pool instead.
func Inspect(cfg PKCS11Config, opts InspectOptions) (*Inspection, error) {
	out := &Inspection{}
	err := withModuleSession(cfg, false, func(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) error {
		si, serr := ctx.GetSessionInfo(session)
		if serr != nil {
			return fmt.Errorf("C_GetSessionInfo: %w", serr)
		}
		mod, merr := moduleInfoOnCtx(ctx, cfg.ModulePath, &si.SlotID, opts)
		if merr != nil {
			return merr
		}
		out.Module = mod
		objs, oerr := objectsOnSession(ctx, session, si.SlotID, opts)
		if oerr != nil {
			return oerr
		}
		out.Objects = objs
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InspectModule reports the module/slot/token view through the pool's existing
// module reference — no second dlopen, no login, and no effect on the sessions
// the server is signing with.
func (p *SessionPool) InspectModule(_ context.Context, opts InspectOptions) (*ModuleInfo, error) {
	slot := p.slotID
	return moduleInfoOnCtx(p.ctx, p.cfg.ModulePath, &slot, opts)
}

// Inspect enumerates the token's objects on a borrowed pool session — already
// authenticated, so private objects are visible — and returns them with the
// module view.
func (p *SessionPool) Inspect(ctx context.Context, opts InspectOptions) (*Inspection, error) {
	mod, err := p.InspectModule(ctx, opts)
	if err != nil {
		return nil, err
	}
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	objs, err := objectsOnSession(p.ctx, s.handle, p.slotID, opts)
	if err != nil {
		return nil, err
	}
	return &Inspection{Module: mod, Objects: objs}, nil
}
