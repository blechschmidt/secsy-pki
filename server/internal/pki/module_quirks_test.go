package pki

// The module-quirk decision, tested without a module.
//
// The decision it encodes is a claim about specific released software, so the
// cases are the actual libraryVersion values those releases report rather than
// invented ones: 2.6.0 is what Debian bookworm-backports ships, 2.7.1 is the
// last affected release, 2.7.2 is the fix, 2.8.0 is what the `-yubihsm` image
// builds. Getting the boundary wrong in either direction is a real failure — too
// strict and every YubiHSM deployment quietly loses an attribute it should be
// asserting, too loose and RSA import breaks on the module Debian ships.

import (
	"testing"

	"github.com/miekg/pkcs11"
)

func TestCanAssertUnwrapFalse(t *testing.T) {
	const yubi = "YubiHSM PKCS#11 Library"

	cases := []struct {
		name string
		desc string
		ver  pkcs11.Version
		want bool
	}{
		// Yubico's module, by release. minor = VERSION_MINOR*10 + VERSION_PATCH.
		{"yubihsm-2.6.0-debian-backports", yubi, pkcs11.Version{Major: 2, Minor: 60}, false},
		{"yubihsm-2.7.0", yubi, pkcs11.Version{Major: 2, Minor: 70}, false},
		{"yubihsm-2.7.1-last-affected", yubi, pkcs11.Version{Major: 2, Minor: 71}, false},
		{"yubihsm-2.7.2-the-fix", yubi, pkcs11.Version{Major: 2, Minor: 72}, true},
		{"yubihsm-2.7.3", yubi, pkcs11.Version{Major: 2, Minor: 73}, true},
		{"yubihsm-2.8.0-shipped-in-the-image", yubi, pkcs11.Version{Major: 2, Minor: 80}, true},
		// A future major must not be read as older than 2.72.
		{"yubihsm-3.0.0", yubi, pkcs11.Version{Major: 3, Minor: 0}, true},
		// An older major is affected: there is no such release, but reading
		// {1, 99} as "newer than 2.72" would be a comparison bug.
		{"yubihsm-1.99.9", yubi, pkcs11.Version{Major: 1, Minor: 99}, false},
		// The field is space-padded in CK_INFO; a module that leaves the padding
		// in must still be recognized.
		{"yubihsm-padded-description", "  " + yubi + "      ", pkcs11.Version{Major: 2, Minor: 60}, false},
		// Everything else keeps the assertion, including a version that would be
		// "affected" if the description had matched.
		{"softhsm", "Implementation of PKCS11", pkcs11.Version{Major: 2, Minor: 60}, true},
		{"unknown-vendor", "Acme HSM PKCS#11", pkcs11.Version{Major: 0, Minor: 1}, true},
		{"empty-description", "", pkcs11.Version{Major: 2, Minor: 60}, true},
		// Yubico's *other* PKCS#11 module (YubiKey) is a different library and is
		// not affected, so it must not be matched by description.
		{"yubikey-piv", "YubiKey PKCS#11 Library", pkcs11.Version{Major: 2, Minor: 40}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canAssertUnwrapFalse(pkcs11.Info{
				ManufacturerID:     "Yubico (www.yubico.com)",
				LibraryDescription: tc.desc,
				LibraryVersion:     tc.ver,
			})
			if got != tc.want {
				t.Errorf("canAssertUnwrapFalse(%q %d.%d) = %t, want %t",
					tc.desc, tc.ver.Major, tc.ver.Minor, got, tc.want)
			}
		})
	}
}

// TestUnwrapFalseAttrOnNoModule pins the fallback. A nil module cannot be asked
// what it is, and the answer has to be the safe one: assert the attribute. The
// paths that build templates always have a real module, so this is about the
// function being honest at its boundary rather than about a reachable case.
func TestUnwrapFalseAttrOnNoModule(t *testing.T) {
	attrs := unwrapFalseAttr(nil)
	if len(attrs) != 1 {
		t.Fatalf("unwrapFalseAttr(nil) returned %d attributes, want 1", len(attrs))
	}
	if attrs[0].Type != pkcs11.CKA_UNWRAP {
		t.Errorf("attribute type = %d, want CKA_UNWRAP (%d)", attrs[0].Type, pkcs11.CKA_UNWRAP)
	}
	// A PKCS#11 CK_BBOOL false is a single zero byte. Asserting on the encoding
	// matters: a one-byte 0x01 here would assert the opposite of the intent.
	if len(attrs[0].Value) != 1 || attrs[0].Value[0] != 0 {
		t.Errorf("attribute value = %v, want a single zero byte (CK_FALSE)", attrs[0].Value)
	}
}

// TestImportTemplateAssertsUnwrapFalseOnAGoodModule checks the wiring, not the
// predicate: a signing import built against no module (the correct-module
// fallback) carries CKA_UNWRAP=false, and a decrypt import does not — a KEK is
// created without the attribute on every module, which is why kek.go never met
// this bug.
func TestImportTemplateAssertsUnwrapFalseOnAGoodModule(t *testing.T) {
	key := sharedRSAKey(t)

	for _, tc := range []struct {
		usage ImportKeyUsage
		want  bool
	}{
		{ImportUsageSign, true},
		{ImportUsageDecrypt, false},
	} {
		privAttrs, _, err := importTemplates(nil, key, "unwrap-template", nil, tc.usage)
		if err != nil {
			t.Fatalf("importTemplates(%s): %v", tc.usage, err)
		}
		found := false
		for _, a := range privAttrs {
			if a.Type == pkcs11.CKA_UNWRAP {
				found = true
			}
		}
		if found != tc.want {
			t.Errorf("a %s import template has CKA_UNWRAP=%t, want %t", tc.usage, found, tc.want)
		}
	}
}
