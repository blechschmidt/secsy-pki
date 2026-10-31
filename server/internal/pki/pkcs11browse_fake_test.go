package pki

// The inspector against a fake module.
//
// The SoftHSM/YubiHSM tests prove it reads a real token correctly. This file
// proves what those cannot: what it does when the module misbehaves — a slot
// that refuses C_GetSlotInfo, a token that refuses C_GetTokenInfo, a mechanism
// whose C_GetMechanismInfo fails, a C_FindObjects that pages, an object that
// will not say what class it is. Those branches are most of the error handling
// in pkcs11browse.go, they are the ones that matter when a module is the
// problem, and a healthy token never produces any of them.
//
// It also runs in the HSM-free suite, which is where the coverage gate looks.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// fakeModule is a scripted cryptoki implementation. Every call is answered from
// a field, so a test states exactly the module behaviour it is about.
type fakeModule struct {
	info      pkcs11.Info
	infoErr   error
	slots     []uint
	slotsErr  error
	slotInfo  map[uint]pkcs11.SlotInfo
	slotErr   map[uint]error
	tokenInfo map[uint]pkcs11.TokenInfo
	tokenErr  map[uint]error
	mechs     map[uint][]uint
	mechsErr  error
	mechInfo  map[uint]pkcs11.MechanismInfo
	mechInfoE map[uint]error

	// objects maps a handle to its attribute values; a type absent from the
	// map is refused with attrErr (default CKR_ATTRIBUTE_TYPE_INVALID).
	objects   map[pkcs11.ObjectHandle]map[uint][]byte
	order     []pkcs11.ObjectHandle
	findErr   error
	findInitE error
	sizes     map[pkcs11.ObjectHandle]uint
	sizeErr   error
	// pageSize makes C_FindObjects answer in pages, as a module with many
	// objects does.
	pageSize int

	cursor     int
	attrCalls  int
	findCalls  int
	finalCalls int
}

func (f *fakeModule) GetInfo() (pkcs11.Info, error) { return f.info, f.infoErr }

func (f *fakeModule) GetSlotList(bool) ([]uint, error) { return f.slots, f.slotsErr }

func (f *fakeModule) GetSlotInfo(slot uint) (pkcs11.SlotInfo, error) {
	if err := f.slotErr[slot]; err != nil {
		return pkcs11.SlotInfo{}, err
	}
	return f.slotInfo[slot], nil
}

func (f *fakeModule) GetTokenInfo(slot uint) (pkcs11.TokenInfo, error) {
	if err := f.tokenErr[slot]; err != nil {
		return pkcs11.TokenInfo{}, err
	}
	ti, ok := f.tokenInfo[slot]
	if !ok {
		return pkcs11.TokenInfo{}, pkcs11.Error(pkcs11.CKR_TOKEN_NOT_PRESENT)
	}
	return ti, nil
}

func (f *fakeModule) GetMechanismList(slot uint) ([]*pkcs11.Mechanism, error) {
	if f.mechsErr != nil {
		return nil, f.mechsErr
	}
	out := make([]*pkcs11.Mechanism, 0, len(f.mechs[slot]))
	for _, m := range f.mechs[slot] {
		out = append(out, pkcs11.NewMechanism(m, nil))
	}
	return out, nil
}

func (f *fakeModule) GetMechanismInfo(_ uint, m []*pkcs11.Mechanism) (pkcs11.MechanismInfo, error) {
	if len(m) != 1 {
		return pkcs11.MechanismInfo{}, fmt.Errorf("want exactly one mechanism, got %d", len(m))
	}
	if err := f.mechInfoE[m[0].Mechanism]; err != nil {
		return pkcs11.MechanismInfo{}, err
	}
	return f.mechInfo[m[0].Mechanism], nil
}

func (f *fakeModule) FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
	f.cursor = 0
	return f.findInitE
}

func (f *fakeModule) FindObjects(_ pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	f.findCalls++
	if f.findErr != nil {
		return nil, false, f.findErr
	}
	n := max
	if f.pageSize > 0 && f.pageSize < n {
		n = f.pageSize
	}
	if f.cursor >= len(f.order) {
		return nil, false, nil
	}
	end := f.cursor + n
	if end > len(f.order) {
		end = len(f.order)
	}
	batch := f.order[f.cursor:end]
	f.cursor = end
	return batch, f.cursor < len(f.order), nil
}

func (f *fakeModule) FindObjectsFinal(pkcs11.SessionHandle) error {
	f.finalCalls++
	return nil
}

func (f *fakeModule) GetAttributeValue(_ pkcs11.SessionHandle, h pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	f.attrCalls++
	obj, ok := f.objects[h]
	if !ok {
		return nil, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}
	out := make([]*pkcs11.Attribute, 0, len(a))
	for _, want := range a {
		v, present := obj[want.Type]
		if !present {
			// The module refuses the whole batch, which is what the real one
			// does and what the subdivision in readAttributes exists for.
			return nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)
		}
		out = append(out, pkcs11.NewAttribute(want.Type, v))
	}
	return out, nil
}

func (f *fakeModule) GetObjectSize(_ pkcs11.SessionHandle, h pkcs11.ObjectHandle) (uint, error) {
	if f.sizeErr != nil {
		return 0, f.sizeErr
	}
	s, ok := f.sizes[h]
	if !ok {
		return 0, pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
	}
	return s, nil
}

var _ cryptoki = (*fakeModule)(nil)

// ulongBytes encodes a CK_ULONG the way an LP64 module writes one.
func ulongBytes(v uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

// twoSlotModule is a module presenting one slot with a token this deployment
// uses and one empty slot — the shape that makes a token selector matter.
func twoSlotModule() *fakeModule {
	return &fakeModule{
		info: pkcs11.Info{
			CryptokiVersion:    pkcs11.Version{Major: 2, Minor: 40},
			ManufacturerID:     "Test Vendor     ",
			LibraryDescription: "Test PKCS#11 Library            ",
			LibraryVersion:     pkcs11.Version{Major: 1, Minor: 2},
			Flags:              pkcs11.CKF_OS_LOCKING_OK,
		},
		slots: []uint{1, 2},
		slotInfo: map[uint]pkcs11.SlotInfo{
			1: {SlotDescription: "slot one    ", ManufacturerID: "Test Vendor ",
				Flags:           pkcs11.CKF_TOKEN_PRESENT | pkcs11.CKF_HW_SLOT,
				HardwareVersion: pkcs11.Version{Major: 3, Minor: 1},
				FirmwareVersion: pkcs11.Version{Major: 4, Minor: 2}},
			2: {SlotDescription: "slot two    ", Flags: 0},
		},
		tokenInfo: map[uint]pkcs11.TokenInfo{
			1: {
				Label: "prod-token   ", Model: "Test HSM ", ManufacturerID: "Test Vendor ",
				SerialNumber:    "000123456789",
				Flags:           pkcs11.CKF_RNG | pkcs11.CKF_LOGIN_REQUIRED | pkcs11.CKF_TOKEN_INITIALIZED,
				MaxSessionCount: pkcs11.CK_EFFECTIVELY_INFINITE,
				SessionCount:    3,
				MaxPinLen:       64, MinPinLen: 8,
				TotalPublicMemory: pkcs11.CK_UNAVAILABLE_INFORMATION,
				FreePublicMemory:  pkcs11.CK_UNAVAILABLE_INFORMATION,
				HardwareVersion:   pkcs11.Version{Major: 2, Minor: 4},
				FirmwareVersion:   pkcs11.Version{Major: 2, Minor: 4},
				UTCTime:           "20261031000000",
			},
		},
		mechs: map[uint][]uint{1: {pkcs11.CKM_ECDSA, pkcs11.CKM_RSA_PKCS}},
		mechInfo: map[uint]pkcs11.MechanismInfo{
			pkcs11.CKM_ECDSA: {MinKeySize: 256, MaxKeySize: 521, Flags: pkcs11.CKF_SIGN | pkcs11.CKF_VERIFY},
		},
		mechInfoE: map[uint]error{pkcs11.CKM_RSA_PKCS: pkcs11.Error(pkcs11.CKR_MECHANISM_INVALID)},
	}
}

func TestModuleViewOverAFakeModule(t *testing.T) {
	f := twoSlotModule()
	selected := uint(1)
	mod, err := moduleInfoOnCtx(f, "/opt/test/module.so", &selected, InspectOptions{})
	if err != nil {
		t.Fatalf("moduleInfoOnCtx: %v", err)
	}
	if mod.ModulePath != "/opt/test/module.so" || mod.CryptokiVersion != "2.40" || mod.LibraryVersion != "1.2" {
		t.Errorf("module header = %+v", mod)
	}
	// The fixed-width character fields are blank-padded by the standard; the
	// padding must not reach the output.
	if mod.ManufacturerID != "Test Vendor" || mod.LibraryDescription != "Test PKCS#11 Library" {
		t.Errorf("padding was not trimmed: %q / %q", mod.ManufacturerID, mod.LibraryDescription)
	}
	if len(mod.Flags.Names) != 1 || mod.Flags.Names[0] != "CKF_OS_LOCKING_OK" {
		t.Errorf("library flags = %v", mod.Flags.Names)
	}
	if len(mod.Slots) != 2 {
		t.Fatalf("got %d slots", len(mod.Slots))
	}

	s1 := mod.Slots[0]
	if !s1.Selected || !s1.TokenPresent || s1.Token == nil {
		t.Fatalf("slot 1 = %+v", s1)
	}
	if s1.HardwareVersion != "3.1" || s1.FirmwareVersion != "4.2" {
		t.Errorf("slot versions = %s / %s", s1.HardwareVersion, s1.FirmwareVersion)
	}
	if s1.Token.Label != "prod-token" || s1.Token.SerialNumber != "000123456789" {
		t.Errorf("token = %+v", s1.Token)
	}
	// The CK_ULONG sentinels are named rather than printed as ~0 or 0.
	if s1.Token.MaxSessionCount != "effectively infinite" || s1.Token.SessionCount != "3" {
		t.Errorf("session counts = %q / %q", s1.Token.MaxSessionCount, s1.Token.SessionCount)
	}
	if s1.Token.TotalPublicMemory != "unavailable" {
		t.Errorf("memory = %q", s1.Token.TotalPublicMemory)
	}

	// An empty slot is reported, not skipped: it is the answer to "why does my
	// token selector match nothing".
	s2 := mod.Slots[1]
	if s2.TokenPresent || s2.Token != nil || s2.Selected {
		t.Errorf("slot 2 = %+v", s2)
	}

	// Mechanisms: one with info, one whose C_GetMechanismInfo fails — and the
	// failing one is still listed, because the module offering it is the datum.
	if len(s1.Mechanisms) != 2 {
		t.Fatalf("got %d mechanism(s)", len(s1.Mechanisms))
	}
	if s1.Mechanisms[0].Name != "CKM_ECDSA" || s1.Mechanisms[0].MaxKeySize != 521 {
		t.Errorf("mechanism 0 = %+v", s1.Mechanisms[0])
	}
	if !strings.Contains(s1.Mechanisms[1].Error, "CKR_MECHANISM_INVALID") {
		t.Errorf("a failing C_GetMechanismInfo was not reported: %+v", s1.Mechanisms[1])
	}

	// SkipMechanisms drops the bulk of the payload.
	lean, err := moduleInfoOnCtx(f, "/opt/test/module.so", nil, InspectOptions{SkipMechanisms: true})
	if err != nil {
		t.Fatalf("moduleInfoOnCtx(skip): %v", err)
	}
	for _, s := range lean.Slots {
		if len(s.Mechanisms) != 0 {
			t.Errorf("slot %d kept %d mechanism(s) despite SkipMechanisms", s.SlotID, len(s.Mechanisms))
		}
		if s.Selected {
			t.Errorf("slot %d is marked selected with no selection", s.SlotID)
		}
	}
}

// One bad slot must not cost the view of the others, and a token that refuses
// C_GetTokenInfo must say so rather than look absent.
func TestModuleViewSurvivesABadSlot(t *testing.T) {
	f := twoSlotModule()
	f.slotErr = map[uint]error{2: pkcs11.Error(pkcs11.CKR_SLOT_ID_INVALID)}
	f.tokenErr = map[uint]error{1: pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)}

	mod, err := moduleInfoOnCtx(f, "m.so", nil, InspectOptions{SkipMechanisms: true})
	if err != nil {
		t.Fatalf("moduleInfoOnCtx: %v", err)
	}
	if len(mod.Slots) != 2 {
		t.Fatalf("got %d slots", len(mod.Slots))
	}
	if !strings.Contains(mod.Slots[0].Error, "CKR_DEVICE_ERROR") || mod.Slots[0].Token != nil {
		t.Errorf("slot 1 = %+v", mod.Slots[0])
	}
	if !strings.Contains(mod.Slots[1].Error, "CKR_SLOT_ID_INVALID") {
		t.Errorf("slot 2 = %+v", mod.Slots[1])
	}

	// C_GetInfo failing IS fatal: there is no view without it.
	f2 := twoSlotModule()
	f2.infoErr = pkcs11.Error(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	if _, err := moduleInfoOnCtx(f2, "m.so", nil, InspectOptions{}); err == nil {
		t.Error("a failed C_GetInfo produced a view")
	}
	// So is C_GetSlotList.
	f3 := twoSlotModule()
	f3.slotsErr = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	if _, err := moduleInfoOnCtx(f3, "m.so", nil, InspectOptions{}); err == nil {
		t.Error("a failed C_GetSlotList produced a view")
	}
	// A module whose C_GetMechanismList fails still yields a slot, carrying the
	// error in place of the list.
	f4 := twoSlotModule()
	f4.mechsErr = pkcs11.Error(pkcs11.CKR_FUNCTION_NOT_SUPPORTED)
	mod4, err := moduleInfoOnCtx(f4, "m.so", nil, InspectOptions{})
	if err != nil {
		t.Fatalf("moduleInfoOnCtx: %v", err)
	}
	if len(mod4.Slots[0].Mechanisms) != 1 || mod4.Slots[0].Mechanisms[0].Error == "" {
		t.Errorf("a failed C_GetMechanismList = %+v", mod4.Slots[0].Mechanisms)
	}
}

// ecPrivateKeyObject is a plausible CA private key as a module would answer for
// it: class, the storage attributes, and the policy flags that matter.
func ecPrivateKeyObject(label string) map[uint][]byte {
	return map[uint][]byte{
		pkcs11.CKA_CLASS:       ulongBytes(pkcs11.CKO_PRIVATE_KEY),
		pkcs11.CKA_TOKEN:       {1},
		pkcs11.CKA_PRIVATE:     {1},
		pkcs11.CKA_LABEL:       []byte(label),
		pkcs11.CKA_ID:          {0x0a, 0x0b},
		pkcs11.CKA_KEY_TYPE:    ulongBytes(pkcs11.CKK_EC),
		pkcs11.CKA_SENSITIVE:   {1},
		pkcs11.CKA_EXTRACTABLE: {0},
		pkcs11.CKA_SIGN:        {1},
		pkcs11.CKA_EC_PARAMS:   {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	}
}

func TestObjectEnumerationOverAFakeModule(t *testing.T) {
	f := twoSlotModule()
	f.order = []pkcs11.ObjectHandle{1, 2, 3}
	f.pageSize = 2 // force C_FindObjects to page
	f.objects = map[pkcs11.ObjectHandle]map[uint][]byte{
		1: ecPrivateKeyObject("ca-root"),
		2: {
			pkcs11.CKA_CLASS:    ulongBytes(pkcs11.CKO_PUBLIC_KEY),
			pkcs11.CKA_LABEL:    []byte("ca-root"),
			pkcs11.CKA_KEY_TYPE: ulongBytes(pkcs11.CKK_EC),
			pkcs11.CKA_VERIFY:   {1},
		},
		// An object that will not say what class it is: still enumerated, with
		// the storage attributes asked of it.
		3: {pkcs11.CKA_LABEL: []byte("mystery"), pkcs11.CKA_TOKEN: {1}},
	}
	f.sizes = map[pkcs11.ObjectHandle]uint{1: 96}

	set, err := objectsOnSession(f, 7, 1, InspectOptions{})
	if err != nil {
		t.Fatalf("objectsOnSession: %v", err)
	}
	if len(set.Objects) != 3 {
		t.Fatalf("got %d object(s)", len(set.Objects))
	}
	if set.Truncated {
		t.Error("an uncapped enumeration reported itself truncated")
	}
	if set.TokenLabel != "prod-token" || set.TokenSerial != "000123456789" {
		t.Errorf("the object set does not name its token: %+v", set)
	}
	if set.Counts["CKO_PRIVATE_KEY"] != 1 || set.Counts["CKO_PUBLIC_KEY"] != 1 || set.Counts["unknown"] != 1 {
		t.Errorf("class counts = %v", set.Counts)
	}
	if f.finalCalls != 1 {
		t.Errorf("C_FindObjectsFinal called %d time(s); a leaked search blocks the next one", f.finalCalls)
	}

	priv := set.Objects[0]
	if priv.Handle != 1 || priv.HandleHex != "0x1" || priv.ClassName != "CKO_PRIVATE_KEY" {
		t.Errorf("object 1 = %+v", priv)
	}
	if priv.Label != "ca-root" || priv.ID != "0a0b" {
		t.Errorf("identity attributes were not promoted: label=%q id=%q", priv.Label, priv.ID)
	}
	if priv.KeyType != "CKK_EC (0x3)" {
		t.Errorf("key type = %q", priv.KeyType)
	}
	if priv.Size != "96" {
		t.Errorf("C_GetObjectSize = %q", priv.Size)
	}
	byName := map[string]ObjectAttribute{}
	for _, a := range priv.Attributes {
		byName[a.Name] = a
	}
	if got := byName["CKA_EXTRACTABLE"]; got.Value != "false" {
		t.Errorf("CKA_EXTRACTABLE = %+v", got)
	}
	if got := byName["CKA_EC_PARAMS"]; !strings.Contains(got.Value, "P-256") {
		t.Errorf("CKA_EC_PARAMS = %+v", got)
	}
	// The key-material rows are present as withheld, and carry nothing.
	if got := byName["CKA_PRIVATE_EXPONENT"]; got.Status != AttrStatusWithheld || got.Raw != "" {
		t.Errorf("CKA_PRIVATE_EXPONENT = %+v", got)
	}
	// The array attributes are present as not-read.
	if got := byName["CKA_UNWRAP_TEMPLATE"]; got.Status != AttrStatusNotRead {
		t.Errorf("CKA_UNWRAP_TEMPLATE = %+v", got)
	}
	// The default view drops "this object has no such attribute" rows.
	for _, a := range priv.Attributes {
		if a.Status == AttrStatusUnavailable && a.Reason == "CKR_ATTRIBUTE_TYPE_INVALID" {
			t.Errorf("the default view kept an unsupported row: %s", a.Name)
		}
	}
	// Attributes come back in catalogue order, which is the standard's order —
	// not the order the refusals happened to resolve in.
	order := map[uint]int{}
	for i, a := range pkcs11Attributes {
		order[a.typ] = i
	}
	for i := 1; i < len(priv.Attributes); i++ {
		if order[priv.Attributes[i-1].Type] > order[priv.Attributes[i].Type] {
			t.Errorf("attribute %s precedes %s, which the catalogue orders first",
				priv.Attributes[i-1].Name, priv.Attributes[i].Name)
			break
		}
	}

	// The unclassed object is still inspected, and only for storage attributes.
	mystery := set.Objects[2]
	if mystery.ClassName != "unknown" || mystery.Label != "mystery" {
		t.Errorf("unclassed object = %+v", mystery)
	}
	for _, a := range mystery.Attributes {
		if a.Name == "CKA_MODULUS" {
			t.Error("a class-specific attribute was asked of an unclassed object")
		}
	}
}

func TestObjectEnumerationCapAndFailures(t *testing.T) {
	f := twoSlotModule()
	f.order = []pkcs11.ObjectHandle{1, 2, 3, 4, 5}
	f.objects = map[pkcs11.ObjectHandle]map[uint][]byte{}
	for _, h := range f.order {
		f.objects[h] = ecPrivateKeyObject(fmt.Sprintf("key-%d", h))
	}

	set, err := objectsOnSession(f, 1, 1, InspectOptions{MaxObjects: 2})
	if err != nil {
		t.Fatalf("objectsOnSession: %v", err)
	}
	if len(set.Objects) != 2 || !set.Truncated {
		t.Errorf("cap 2 over 5 objects: %d returned, truncated=%v", len(set.Objects), set.Truncated)
	}

	// A failed search is a failed request: a partial object list would read as
	// "this is what is on the token".
	f.findErr = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	if _, err := objectsOnSession(f, 1, 1, InspectOptions{}); err == nil {
		t.Error("a failed C_FindObjects produced an object set")
	}
	f.findErr = nil
	f.findInitE = pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)
	if _, err := objectsOnSession(f, 1, 1, InspectOptions{}); err == nil {
		t.Error("a failed C_FindObjectsInit produced an object set")
	}
}

// AllAttributes bypasses the class scoping — and must not bypass the
// withholding policy. Asserted here because the fake can be asked for anything.
func TestAllAttributesKeepsTheWithholdingPolicy(t *testing.T) {
	f := twoSlotModule()
	f.order = []pkcs11.ObjectHandle{1}
	f.objects = map[pkcs11.ObjectHandle]map[uint][]byte{1: ecPrivateKeyObject("ca-root")}
	// A module that WOULD hand over the private scalar if asked — which is the
	// case the policy exists for.
	f.objects[1][pkcs11.CKA_VALUE] = []byte("this is the private key, do not export")
	f.objects[1][pkcs11.CKA_PRIVATE_EXPONENT] = []byte{0xde, 0xad, 0xbe, 0xef}

	for _, opts := range []InspectOptions{{}, {AllAttributes: true}} {
		set, err := objectsOnSession(f, 1, 1, opts)
		if err != nil {
			t.Fatalf("objectsOnSession: %v", err)
		}
		for _, a := range set.Objects[0].Attributes {
			if a.Type != pkcs11.CKA_VALUE && a.Type != pkcs11.CKA_PRIVATE_EXPONENT {
				continue
			}
			if a.Status != AttrStatusWithheld {
				t.Errorf("all=%v: %s has status %q — the module was asked for key material",
					opts.AllAttributes, a.Name, a.Status)
			}
			if a.Raw != "" || a.Value != "" || a.Length != 0 {
				t.Errorf("all=%v: %s carries data", opts.AllAttributes, a.Name)
			}
		}
	}

	// With the whole catalogue, the unsupported rows are kept — that is what
	// distinguishes "the token does not have it" from "it was not asked for".
	wide, err := objectsOnSession(f, 1, 1, InspectOptions{AllAttributes: true})
	if err != nil {
		t.Fatalf("objectsOnSession: %v", err)
	}
	narrow, err := objectsOnSession(f, 1, 1, InspectOptions{})
	if err != nil {
		t.Fatalf("objectsOnSession: %v", err)
	}
	if len(wide.Objects[0].Attributes) <= len(narrow.Objects[0].Attributes) {
		t.Errorf("the whole catalogue produced %d rows, the class-scoped view %d",
			len(wide.Objects[0].Attributes), len(narrow.Objects[0].Attributes))
	}
}

// An object whose handle has gone stale (the session was reset under us) is one
// error row rather than a failed enumeration.
func TestObjectWithAnInvalidHandle(t *testing.T) {
	f := twoSlotModule()
	f.order = []pkcs11.ObjectHandle{9}
	f.objects = map[pkcs11.ObjectHandle]map[uint][]byte{} // handle 9 resolves to nothing

	set, err := objectsOnSession(f, 1, 1, InspectOptions{})
	if err != nil {
		t.Fatalf("objectsOnSession: %v", err)
	}
	if len(set.Objects) != 1 {
		t.Fatalf("got %d object(s)", len(set.Objects))
	}
	o := set.Objects[0]
	if o.ClassName != "unknown" || o.Label != "" {
		t.Errorf("object = %+v", o)
	}
	var refused int
	for _, a := range o.Attributes {
		if a.Status == AttrStatusUnavailable && strings.Contains(a.Reason, "CKR_OBJECT_HANDLE_INVALID") {
			refused++
		}
	}
	if refused == 0 {
		t.Error("the stale handle's refusals were not reported with their CKR name")
	}
}
