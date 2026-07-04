package pki

// RFC 7512 PKCS#11 URI parsing and serialization.
//
// The historical ExtractKeyLabel only pulled the object= attribute out of a
// pkcs11: URI and ignored every other RFC 7512 attribute. This file implements a
// complete parser so a key can be addressed the way RFC 7512 intends — by any
// combination of token (label/serial/model/manufacturer), slot (slot-id /
// slot-description / slot-manufacturer), library, and object (object / id / type)
// attributes — plus the query attributes that configure the module and PIN
// (module-name / module-path / pin-source / pin-value).
//
// This matters beyond tidiness: in a multi-token HA deployment (see the
// hsm-ha / pkcs11-duplicate-label notes) replicas deliberately share one
// CKA_LABEL, so addressing a key by token serial or slot-id — or by CKA_ID
// instead of label — is the only unambiguous way to pin an operation to a
// specific token. The keyprovider package maps a parsed URI onto a KeyRef so the
// CA/TSA/secret signing paths can use exactly that addressing.

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// pkcs11Scheme is the URI scheme, matched case-insensitively per RFC 3986.
const pkcs11Scheme = "pkcs11:"

// Recognized RFC 7512 object type= values (CKA_CLASS selectors).
const (
	PKCS11TypePublic    = "public"
	PKCS11TypePrivate   = "private"
	PKCS11TypeCert      = "cert"
	PKCS11TypeSecretKey = "secret-key"
	PKCS11TypeData      = "data"
)

// PKCS11URI is a parsed RFC 7512 "pkcs11:" URI. Every standard path attribute
// and query attribute is represented as a typed field; unrecognized (vendor)
// attributes are preserved in Unknown so the URI round-trips and diagnostics can
// surface them. A zero value is a valid "match anything" URI ("pkcs11:").
type PKCS11URI struct {
	// --- path attributes: token selection ---
	Token        string // CK_TOKEN_INFO.label
	Manufacturer string // CK_TOKEN_INFO.manufacturerID
	Serial       string // CK_TOKEN_INFO.serialNumber
	Model        string // CK_TOKEN_INFO.model

	// --- path attributes: library selection ---
	LibraryManufacturer string // CK_INFO.manufacturerID
	LibraryDescription  string // CK_INFO.libraryDescription
	LibraryVersion      string // CK_INFO.libraryVersion ("major.minor")

	// --- path attributes: slot selection ---
	SlotManufacturer string // CK_SLOT_INFO.manufacturerID
	SlotDescription  string // CK_SLOT_INFO.slotDescription
	SlotID           *int64 // CK_SLOT_ID (decimal); nil when absent

	// --- path attributes: object selection ---
	Object string // CKA_LABEL
	Type   string // CKA_CLASS selector: one of the PKCS11Type* constants
	ID     []byte // CKA_ID (raw bytes; percent-decoded)

	// --- query attributes: module + PIN ---
	ModuleName string // PKCS#11 module name (without path/extension)
	ModulePath string // absolute path to the PKCS#11 module library
	PinSource  string // where to read the PIN (an RFC 3986 URI, typically file:)
	PinValue   string // the literal PIN (a plaintext-at-rest credential)

	// Unknown preserves vendor/unrecognized attributes (decoded values) keyed by
	// their lowercase attribute name, so String round-trips them and the doctor
	// URI check can report them rather than silently dropping a typo.
	Unknown map[string]string
}

// ParsePKCS11URI parses a complete RFC 7512 "pkcs11:" URI. It requires the
// "pkcs11:" scheme (matched case-insensitively), percent-decodes every attribute
// value, validates the structural grammar (single "=" per attribute, no
// duplicate attributes, well-formed type/slot-id), and returns a typed
// PKCS11URI. It does not touch any token; resolution against a live token is the
// keyprovider's job.
func ParsePKCS11URI(raw string) (*PKCS11URI, error) {
	s := strings.TrimSpace(raw)
	if len(s) < len(pkcs11Scheme) || !strings.EqualFold(s[:len(pkcs11Scheme)], pkcs11Scheme) {
		return nil, fmt.Errorf("pkcs11 uri: missing %q scheme in %q", pkcs11Scheme, raw)
	}
	body := s[len(pkcs11Scheme):]

	// Split the path component from the optional query component. RFC 7512 uses
	// ";" to separate path attributes and "&" to separate query attributes.
	pathPart, queryPart := body, ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		pathPart, queryPart = body[:i], body[i+1:]
	}

	u := &PKCS11URI{}
	// A single seen-set spans path and query: RFC 7512 forbids any attribute from
	// appearing more than once, and the two attribute name-spaces are disjoint.
	seen := make(map[string]bool)

	if err := u.parseComponents(pathPart, ';', seen, true, raw); err != nil {
		return nil, err
	}
	if err := u.parseComponents(queryPart, '&', seen, false, raw); err != nil {
		return nil, err
	}
	return u, nil
}

// parseComponents splits a path (isPath) or query segment on sep and applies each
// "name=value" attribute to u. It rejects empty components, missing "=", and
// duplicate attribute names.
func (u *PKCS11URI) parseComponents(segment string, sep byte, seen map[string]bool, isPath bool, raw string) error {
	if segment == "" {
		return nil
	}
	for _, comp := range strings.Split(segment, string(sep)) {
		if comp == "" {
			return fmt.Errorf("pkcs11 uri: empty attribute (stray %q) in %q", string(sep), raw)
		}
		eq := strings.IndexByte(comp, '=')
		if eq < 0 {
			return fmt.Errorf("pkcs11 uri: attribute %q missing %q in %q", comp, "=", raw)
		}
		name := strings.ToLower(comp[:eq])
		rawVal := comp[eq+1:]
		if seen[name] {
			return fmt.Errorf("pkcs11 uri: duplicate attribute %q in %q", name, raw)
		}
		seen[name] = true

		decoded, err := pctDecode(rawVal)
		if err != nil {
			return fmt.Errorf("pkcs11 uri: attribute %q: %w", name, err)
		}
		if err := u.setAttribute(name, decoded, isPath); err != nil {
			return fmt.Errorf("pkcs11 uri: %w", err)
		}
	}
	return nil
}

// setAttribute assigns one decoded attribute to the appropriate typed field.
// isPath disambiguates which name-space the attribute belongs to (all the
// recognized names are unique across the two, so it is only used to place an
// unknown attribute for round-tripping).
func (u *PKCS11URI) setAttribute(name string, val []byte, isPath bool) error {
	sv := string(val)
	switch name {
	// Token selection.
	case "token":
		u.Token = sv
	case "manufacturer":
		u.Manufacturer = sv
	case "serial":
		u.Serial = sv
	case "model":
		u.Model = sv
	// Library selection.
	case "library-manufacturer":
		u.LibraryManufacturer = sv
	case "library-description":
		u.LibraryDescription = sv
	case "library-version":
		if !validLibraryVersion(sv) {
			return fmt.Errorf("library-version %q is not \"major[.minor]\"", sv)
		}
		u.LibraryVersion = sv
	// Slot selection.
	case "slot-manufacturer":
		u.SlotManufacturer = sv
	case "slot-description":
		u.SlotDescription = sv
	case "slot-id":
		n, err := strconv.ParseInt(sv, 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("slot-id %q is not a non-negative decimal integer", sv)
		}
		u.SlotID = &n
	// Object selection.
	case "object":
		u.Object = sv
	case "type", "object-type":
		if !validObjectType(sv) {
			return fmt.Errorf("type %q is not one of public/private/cert/secret-key/data", sv)
		}
		u.Type = sv
	case "id":
		// CKA_ID is an opaque byte string; keep the raw decoded bytes.
		u.ID = val
	// Query: module + PIN.
	case "module-name":
		u.ModuleName = sv
	case "module-path":
		u.ModulePath = sv
	case "pin-source":
		u.PinSource = sv
	case "pin-value":
		u.PinValue = sv
	default:
		if u.Unknown == nil {
			u.Unknown = make(map[string]string)
		}
		u.Unknown[name] = sv
		_ = isPath
	}
	return nil
}

// HasObjectSelector reports whether the URI names a specific object (by label or
// CKA_ID). A URI without one addresses "the token", not "a key on it".
func (u *PKCS11URI) HasObjectSelector() bool {
	return u.Object != "" || len(u.ID) > 0
}

// IDHex returns the CKA_ID as a lowercase hex string ("" when no id= is present),
// matching how HSMKeyInfo.ID and keyprovider.KeyRef.ID carry a CKA_ID.
func (u *PKCS11URI) IDHex() string {
	if len(u.ID) == 0 {
		return ""
	}
	return hex.EncodeToString(u.ID)
}

// String re-serializes the URI in RFC 7512 form with percent-encoding. Attributes
// are emitted in a stable order so the output is deterministic; parsing the
// result yields an equivalent PKCS11URI. It is used for canonical diagnostic
// output and for redacting an embedded pin-value.
func (u *PKCS11URI) String() string {
	var path []string
	add := func(name, val string) {
		if val != "" {
			path = append(path, name+"="+encodePath(val))
		}
	}
	// Object selectors first (the part operators care about most), then token,
	// slot, and library selectors.
	add("object", u.Object)
	if len(u.ID) > 0 {
		path = append(path, "id="+encodePathBytes(u.ID))
	}
	add("type", u.Type)
	add("token", u.Token)
	add("serial", u.Serial)
	add("model", u.Model)
	add("manufacturer", u.Manufacturer)
	if u.SlotID != nil {
		path = append(path, "slot-id="+strconv.FormatInt(*u.SlotID, 10))
	}
	add("slot-description", u.SlotDescription)
	add("slot-manufacturer", u.SlotManufacturer)
	add("library-description", u.LibraryDescription)
	add("library-manufacturer", u.LibraryManufacturer)
	add("library-version", u.LibraryVersion)
	for _, name := range sortedKeys(u.Unknown) {
		path = append(path, name+"="+encodePath(u.Unknown[name]))
	}

	var query []string
	addq := func(name, val string) {
		if val != "" {
			query = append(query, name+"="+encodeQuery(val))
		}
	}
	addq("module-name", u.ModuleName)
	addq("module-path", u.ModulePath)
	addq("pin-source", u.PinSource)
	addq("pin-value", u.PinValue)

	out := pkcs11Scheme + strings.Join(path, ";")
	if len(query) > 0 {
		out += "?" + strings.Join(query, "&")
	}
	return out
}

// RedactedString returns the URI re-serialized with any embedded pin-value
// masked, so a URI that carries a plaintext PIN can be logged or dumped safely.
func (u *PKCS11URI) RedactedString() string {
	if u.PinValue == "" {
		return u.String()
	}
	cp := *u
	cp.PinValue = "***redacted***"
	return cp.String()
}

// --- percent-encoding helpers (RFC 7512 §2.3, RFC 3986) ---------------------

// pctDecode reverses percent-encoding. Unlike form decoding it does NOT treat
// "+" as a space (RFC 7512 URIs use literal "+"). It errors on a truncated or
// non-hex escape rather than passing malformed input through.
func pctDecode(s string) ([]byte, error) {
	if !strings.Contains(s, "%") {
		return []byte(s), nil
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(s) {
			return nil, fmt.Errorf("truncated percent-encoding %q", s[i:])
		}
		hi, ok1 := fromHexDigit(s[i+1])
		lo, ok2 := fromHexDigit(s[i+2])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("invalid percent-encoding %q", s[i:i+3])
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, nil
}

func fromHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// isUnreserved reports whether b is an RFC 3986 unreserved character, always safe
// to emit un-encoded.
func isUnreserved(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-' || b == '.' || b == '_' || b == '~':
		return true
	default:
		return false
	}
}

// pathExtra / queryExtra are the sub-delims RFC 7512 permits un-encoded inside a
// path (pk11-pchar) and query (pk11-qchar) attribute value respectively, minus
// the "=" / ";" / "&" / "?" characters this serializer always encodes to keep the
// output unambiguously re-parseable.
const (
	pathExtra  = ":[]@!$'()*+,"
	queryExtra = ":[]@!$'()*+,/|"
)

func encodePath(s string) string  { return pctEncode([]byte(s), pathExtra) }
func encodeQuery(s string) string { return pctEncode([]byte(s), queryExtra) }
func encodePathBytes(b []byte) string {
	// CKA_ID bytes are usually binary; encode everything not unreserved.
	return pctEncode(b, "")
}

func pctEncode(b []byte, extra string) string {
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		if isUnreserved(c) || strings.IndexByte(extra, c) >= 0 {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hexdigits[c>>4])
		sb.WriteByte(hexdigits[c&0x0f])
	}
	return sb.String()
}

func validObjectType(s string) bool {
	switch s {
	case PKCS11TypePublic, PKCS11TypePrivate, PKCS11TypeCert, PKCS11TypeSecretKey, PKCS11TypeData:
		return true
	default:
		return false
	}
}

// validLibraryVersion checks the RFC 7512 "1*DIGIT ['.' 1*DIGIT]" shape.
func validLibraryVersion(s string) bool {
	if s == "" {
		return false
	}
	major, minor, hasDot := strings.Cut(s, ".")
	if !allDigits(major) {
		return false
	}
	if hasDot && !allDigits(minor) {
		return false
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// sortedKeys returns the map keys in a deterministic order without pulling in the
// sort package for such a small set.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// insertion sort — the map is tiny (vendor attributes are rare).
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
