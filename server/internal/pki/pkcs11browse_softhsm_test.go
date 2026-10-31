package pki

// The raw PKCS#11 inspector against a real token (SoftHSM).
//
// Three things can only be established against a module:
//
//   - that the enumeration works at all — an empty C_FindObjects template, the
//     attribute catalogue, the class-driven scoping — and reports the key this
//     test just generated with the attributes it was generated with;
//   - that no private key material comes back, on a token that would hand it
//     over if asked: SoftHSM enforces CKA_SENSITIVE, so the proof that matters
//     is that the inspector does not ask;
//   - that inspecting does not disturb the serving key provider. The inspector
//     runs in the same process as a live session pool, and this package's
//     history (Task 208) is that a day-2 read path logged the server out of its
//     own token. The assertions here are the same ones
//     sharedmodule_softhsm_test.go makes: after the inspection, the serving
//     pool must still resolve its key and still sign.
//
// Gated on the SECSY_* variables scripts/setup-softhsm.sh --export-env emits,
// via the shared sharedModuleCfg helper, so it skips with no token present.

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// findObject returns the first object of a class with a label, failing the test
// when the inspection did not see it.
func findObject(t *testing.T, set *ObjectSet, class uint, label string) Object {
	t.Helper()
	for _, o := range set.Objects {
		if o.Class == class && o.Label == label {
			return o
		}
	}
	t.Fatalf("the inspection found no %s labelled %q (it saw %d object(s): %v)",
		ckoNames[class], label, len(set.Objects), objectSummaries(set))
	return Object{}
}

func objectSummaries(set *ObjectSet) []string {
	out := make([]string, 0, len(set.Objects))
	for _, o := range set.Objects {
		out = append(out, o.ClassName+":"+o.Label)
	}
	return out
}

// attr returns one attribute row of an object.
func attr(t *testing.T, o Object, typ uint) ObjectAttribute {
	t.Helper()
	for _, a := range o.Attributes {
		if a.Type == typ {
			return a
		}
	}
	t.Fatalf("object %s has no %s row", o.HandleHex, attributeName(typ))
	return ObjectAttribute{}
}

// A full inspection through a live session pool: the module view, the token the
// configuration resolved to, and the objects with their attributes.
func TestInspectThroughSessionPool(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)
	requireServing(t, pool, label, "baseline")

	insp, err := pool.Inspect(context.Background(), InspectOptions{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	// --- the module ---------------------------------------------------------
	mod := insp.Module
	if mod == nil {
		t.Fatal("no module view")
	}
	if mod.ModulePath != cfg.ModulePath {
		t.Errorf("module path = %q, want %q", mod.ModulePath, cfg.ModulePath)
	}
	if mod.CryptokiVersion == "" || mod.LibraryDescription == "" || mod.ManufacturerID == "" {
		t.Errorf("C_GetInfo came back empty: %+v", mod)
	}
	if len(mod.Slots) == 0 {
		t.Fatal("no slots reported")
	}

	// Exactly one slot is the one this deployment signs on, and it is the one
	// holding the configured token — the distinction that matters on a module
	// presenting several.
	var selected *SlotInfo
	for i := range mod.Slots {
		if mod.Slots[i].Selected {
			if selected != nil {
				t.Error("more than one slot is marked as this deployment's")
			}
			selected = &mod.Slots[i]
		}
	}
	if selected == nil {
		t.Fatal("no slot marked as this deployment's token")
	}
	if selected.Token == nil {
		t.Fatal("the selected slot reports no token")
	}
	if selected.Token.Label != cfg.TokenLabel {
		t.Errorf("selected token label = %q, want %q", selected.Token.Label, cfg.TokenLabel)
	}
	if selected.Token.SerialNumber == "" {
		t.Error("the token reports no serial number")
	}
	// SoftHSM requires a login and has an RNG; both are flags, and decoding
	// them is the point of reporting flags by name.
	flags := strings.Join(selected.Token.Flags.Names, " ")
	for _, want := range []string{"CKF_LOGIN_REQUIRED", "CKF_TOKEN_INITIALIZED", "CKF_USER_PIN_INITIALIZED"} {
		if !strings.Contains(flags, want) {
			t.Errorf("token flags %q do not include %s", flags, want)
		}
	}

	// --- mechanisms ---------------------------------------------------------
	var foundECDSA, named bool
	for _, m := range selected.Mechanisms {
		if m.Name == "CKM_ECDSA" {
			foundECDSA = true
			if m.Flags.Value&pkcs11.CKF_SIGN == 0 {
				t.Errorf("CKM_ECDSA does not report CKF_SIGN: flags %s", m.Flags.Hex)
			}
			if m.MaxKeySize == 0 {
				t.Error("CKM_ECDSA reports no key-size range")
			}
		}
		if strings.HasPrefix(m.Name, "CKM_") && !strings.Contains(m.Name, "0x") {
			named = true
		}
	}
	if !foundECDSA {
		t.Error("the mechanism list does not include CKM_ECDSA")
	}
	if !named {
		t.Error("no mechanism resolved to a CKM_ name")
	}

	// --- objects ------------------------------------------------------------
	set := insp.Objects
	if set == nil {
		t.Fatal("no object set")
	}
	if set.SlotID != selected.SlotID {
		t.Errorf("objects came from slot %d, the selected slot is %d", set.SlotID, selected.SlotID)
	}
	if set.Counts["CKO_PRIVATE_KEY"] == 0 || set.Counts["CKO_PUBLIC_KEY"] == 0 {
		t.Errorf("class counts %v hold neither a private nor a public key", set.Counts)
	}

	// The key servingPool generated, as the token describes it.
	priv := findObject(t, set, pkcs11.CKO_PRIVATE_KEY, label)
	if priv.HandleHex == "" || priv.Handle == 0 {
		t.Error("the private key has no object handle")
	}
	if got := attr(t, priv, pkcs11.CKA_CLASS).Value; !strings.HasPrefix(got, "CKO_PRIVATE_KEY") {
		t.Errorf("CKA_CLASS = %q", got)
	}
	if got := attr(t, priv, pkcs11.CKA_SENSITIVE).Value; got != "true" {
		t.Errorf("CKA_SENSITIVE = %q, want true for a generated CA key", got)
	}
	if got := attr(t, priv, pkcs11.CKA_EXTRACTABLE).Value; got != "false" {
		t.Errorf("CKA_EXTRACTABLE = %q, want false for a generated CA key", got)
	}
	if got := attr(t, priv, pkcs11.CKA_SIGN).Value; got != "true" {
		t.Errorf("CKA_SIGN = %q", got)
	}
	if got := attr(t, priv, pkcs11.CKA_KEY_TYPE).Value; !strings.HasPrefix(got, "CKK_EC") {
		t.Errorf("CKA_KEY_TYPE = %q, want CKK_EC for the generated P-256 key", got)
	}
	// The curve, decoded: this is what makes the raw view readable.
	if got := attr(t, priv, pkcs11.CKA_EC_PARAMS).Value; !strings.Contains(got, "P-256") {
		t.Errorf("CKA_EC_PARAMS = %q, want the decoded curve", got)
	}
	// An attribute the token refuses is reported as the refusal, not as blank.
	if a := attr(t, priv, pkcs11.CKA_LABEL); a.Status != AttrStatusPresent || a.Value != label {
		t.Errorf("CKA_LABEL row = %+v", a)
	}

	pub := findObject(t, set, pkcs11.CKO_PUBLIC_KEY, label)
	if got := attr(t, pub, pkcs11.CKA_EC_POINT); got.Status != AttrStatusPresent || got.Raw == "" {
		t.Errorf("the public key's CKA_EC_POINT row = %+v", got)
	}
	if got := attr(t, pub, pkcs11.CKA_VERIFY).Value; got != "true" {
		t.Errorf("public key CKA_VERIFY = %q", got)
	}

	// --- the inspection must not have disturbed the server ------------------
	requireServing(t, pool, label, "after a full PKCS#11 inspection")
}

// The invariant this whole feature is constrained by: no private key material
// leaves the token through the inspector. Every attribute that could carry it
// is reported as withheld, with no bytes, on a token that WOULD answer some of
// them if asked.
func TestInspectNeverReturnsPrivateKeyMaterial(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)

	// AllAttributes is the hostile case: it bypasses the class scoping, so the
	// catalogue's withholding is the only thing left standing between the
	// request and the key material.
	insp, err := pool.Inspect(context.Background(), InspectOptions{AllAttributes: true})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	material := map[uint]bool{
		pkcs11.CKA_PRIVATE_EXPONENT: true, pkcs11.CKA_PRIME_1: true, pkcs11.CKA_PRIME_2: true,
		pkcs11.CKA_EXPONENT_1: true, pkcs11.CKA_EXPONENT_2: true, pkcs11.CKA_COEFFICIENT: true,
	}
	var checked int
	for _, o := range insp.Objects.Objects {
		isKey := o.Class == pkcs11.CKO_PRIVATE_KEY || o.Class == pkcs11.CKO_SECRET_KEY
		for _, a := range o.Attributes {
			secret := material[a.Type] || (a.Type == pkcs11.CKA_VALUE && isKey)
			if !secret {
				continue
			}
			checked++
			if a.Status != AttrStatusWithheld {
				t.Errorf("object %s (%s): %s has status %q, want %q",
					o.HandleHex, o.ClassName, a.Name, a.Status, AttrStatusWithheld)
			}
			if a.Raw != "" || a.Value != "" || a.Length != 0 {
				t.Errorf("object %s: %s carries data (len=%d value=%q raw=%q)",
					o.HandleHex, a.Name, a.Length, a.Value, a.Raw)
			}
			if a.Reason == "" {
				t.Errorf("object %s: %s is withheld without saying why", o.HandleHex, a.Name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no key-material attribute rows were examined — the policy is untested")
	}
	requireServing(t, pool, label, "after a whole-catalogue inspection")
}

// AllAttributes is also what surfaces the attributes the token reports as
// unsupported; the default view drops them as noise. Both behaviours are
// asserted together, because the difference is what the flag means.
func TestInspectAllAttributesSurfacesUnsupportedRows(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)

	narrow, err := pool.Inspect(context.Background(), InspectOptions{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	wide, err := pool.Inspect(context.Background(), InspectOptions{AllAttributes: true})
	if err != nil {
		t.Fatalf("Inspect(all): %v", err)
	}

	narrowPriv := findObject(t, narrow.Objects, pkcs11.CKO_PRIVATE_KEY, label)
	widePriv := findObject(t, wide.Objects, pkcs11.CKO_PRIVATE_KEY, label)
	if len(widePriv.Attributes) <= len(narrowPriv.Attributes) {
		t.Errorf("the whole catalogue produced %d rows, the class-scoped view %d — AllAttributes added nothing",
			len(widePriv.Attributes), len(narrowPriv.Attributes))
	}
	// The default view must not be padded with "the object does not have it".
	for _, a := range narrowPriv.Attributes {
		if a.Status == AttrStatusUnavailable && a.Reason == "CKR_ATTRIBUTE_TYPE_INVALID" {
			t.Errorf("the default view kept an unsupported row: %s", a.Name)
		}
	}
	var unsupported int
	for _, a := range widePriv.Attributes {
		if a.Status == AttrStatusUnavailable {
			unsupported++
		}
	}
	if unsupported == 0 {
		t.Error("the whole-catalogue view reported no refused attribute at all")
	}
}

// The module view on its own opens no session and needs no login, so it works
// for an operator who only wants to know which slot is which — and it still
// must not disturb a serving pool.
func TestInspectModuleNeedsNoSession(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)

	mod, err := InspectModule(cfg, InspectOptions{SkipMechanisms: true})
	if err != nil {
		t.Fatalf("InspectModule: %v", err)
	}
	if len(mod.Slots) == 0 {
		t.Fatal("no slots")
	}
	for _, s := range mod.Slots {
		if len(s.Mechanisms) != 0 {
			t.Errorf("slot %d returned mechanisms despite SkipMechanisms", s.SlotID)
		}
	}
	// A wrong PIN is irrelevant to the module view: nothing logs in.
	bad := cfg
	bad.Pin = "definitely-not-the-pin"
	if _, err := InspectModule(bad, InspectOptions{SkipMechanisms: true}); err != nil {
		t.Errorf("InspectModule with a wrong PIN failed (%v) — it must not be logging in", err)
	}
	requireServing(t, pool, label, "after two module-view reads")
}

// The one-shot path (the CLI's) logs in itself, through the same refcounted
// module/login helper the rest of the package uses. Running it against a token
// a live pool is already logged in to is the day-2 hazard, so it is asserted
// here rather than assumed.
func TestInspectOneShotAlongsideServingPool(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, label := servingPool(t, cfg)
	requireServing(t, pool, label, "baseline")

	insp, err := Inspect(cfg, InspectOptions{SkipMechanisms: true})
	if err != nil {
		t.Fatalf("Inspect (one-shot): %v", err)
	}
	if insp.Objects == nil || len(insp.Objects.Objects) == 0 {
		t.Fatal("the one-shot inspection found no objects")
	}
	// A private object is only visible to an authenticated session, so finding
	// the generated private key also proves the one-shot path logged in.
	findObject(t, insp.Objects, pkcs11.CKO_PRIVATE_KEY, label)

	requireServing(t, pool, label, "after a one-shot inspection")
}

// The object cap is a bound on memory and on how much a browser is asked to
// render, and it has to report itself: a silently truncated inventory is how an
// operator concludes an object is absent.
func TestInspectObjectCapIsReported(t *testing.T) {
	cfg := sharedModuleCfg(t)
	pool, _ := servingPool(t, cfg)

	insp, err := pool.Inspect(context.Background(), InspectOptions{MaxObjects: 1, SkipMechanisms: true})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(insp.Objects.Objects) != 1 {
		t.Fatalf("object cap 1 returned %d objects", len(insp.Objects.Objects))
	}
	if !insp.Objects.Truncated {
		t.Error("a capped enumeration did not report itself as truncated")
	}
}
