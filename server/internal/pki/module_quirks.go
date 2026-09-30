package pki

// Working around what a PKCS#11 module gets wrong (Task 201).
//
// One quirk lives here, and it is worth the file because of what it costs to
// meet in the field. Yubico's module before 2.7.2 tests the *presence* of
// CKA_UNWRAP in a key template rather than its value:
//
//	// pkcs11/yubihsm_pkcs11.c, yubihsm-shell 2.6.0
//	typedef enum { ATTRIBUTE_NOT_SET = 0, ATTRIBUTE_FALSE, ATTRIBUTE_TRUE }
//	  yubihsm_pkcs11_attribute;
//	...
//	if (template.unwrap) { // This is a wrap key
//
// ATTRIBUTE_FALSE is 1, so it is truthy, and `CKA_UNWRAP = FALSE` — an
// assertion that the key must *not* unwrap — makes the module create a device
// **wrap-key** instead of an asymmetric key. That branch sits inside the RSA
// arm, which is why it takes RSA and leaves EC alone, and it is on both the
// import path (C_CreateObject) and the generate path (C_GenerateKeyPair).
// Upstream fixed all three call sites in 2.7.2 ("Fix a bug where generating an
// RSA key pair can potentially result in the wrong type of object being
// created"); 2.7.0 and 2.7.1 still have it.
//
// A wrap-key is not exposed as CKO_PRIVATE_KEY, so nothing is silently
// corrupted: the read-back in importKeyOnSession cannot resolve the key it just
// created and the operation fails. But it fails as "the token exposes no public
// key object", which says nothing about the actual cause, after an operator has
// already pointed a CA at that label — see TestSecretEnvelopeRoundTrip in
// internal/yubihsmtest for the same failure met from the KEK side.
//
// So the template adapts. It is not enough to simply stop asserting
// CKA_UNWRAP=false everywhere: PKCS#11 leaves the default for a private key
// token-specific, and SoftHSM's default is CK_TRUE, so dropping it would hand
// every software-token deployment an unwrap-capable CA key. The attribute is
// therefore omitted only for the modules that cannot read it, and those modules
// are the ones on which omitting it costs nothing — a YubiHSM derives the
// object's capability set from the template, so an absent CKA_UNWRAP means no
// unwrap capability at all, which is exactly what the explicit FALSE was asking
// for. On every other module the assertion stays.
//
// The `-yubihsm` container image builds 2.8.0 from Yubico's signed release, so
// the affected versions are not reachable through it. They are reachable the
// way docs/deployment/container.md tells operators to run in production —
// mounting the host's vendor module into the image — because Debian ships 2.6.0
// in bookworm-backports and bookworm proper ships nothing.

import (
	"strings"

	"github.com/miekg/pkcs11"
)

// yubihsmLibraryDescription is how Yubico's module fills in
// CK_INFO.libraryDescription (YUBIHSM_PKCS11_LIBDESC). Matching on this rather
// than on manufacturerID keeps YubiKey's PKCS#11 module — same manufacturer,
// different library, unaffected — out of the quirk.
const yubihsmLibraryDescription = "YubiHSM PKCS#11 Library"

// yubihsmUnwrapFixedIn is the first Yubico release whose RSA templates read
// CKA_UNWRAP by value, in the module's own libraryVersion encoding:
//
//	libraryVersion = {VERSION_MAJOR, VERSION_MINOR*10 + VERSION_PATCH}
//
// so 2.6.0 reports {2, 60}, 2.7.2 reports {2, 72} and 2.8.0 reports {2, 80}.
var yubihsmUnwrapFixedIn = pkcs11.Version{Major: 2, Minor: 72}

// canAssertUnwrapFalse reports whether an explicit CKA_UNWRAP=false may be put
// in a private-key template for the module that returned info.
//
// True for everything except the affected Yubico releases, so an unrecognized
// module keeps the least-privilege assertion: a module is presumed to implement
// PKCS#11 correctly until it is known not to.
func canAssertUnwrapFalse(info pkcs11.Info) bool {
	if !strings.HasPrefix(strings.TrimSpace(info.LibraryDescription), yubihsmLibraryDescription) {
		return true
	}
	return !versionOlderThan(info.LibraryVersion, yubihsmUnwrapFixedIn)
}

// versionOlderThan orders two CK_VERSIONs.
func versionOlderThan(v, than pkcs11.Version) bool {
	if v.Major != than.Major {
		return v.Major < than.Major
	}
	return v.Minor < than.Minor
}

// unwrapFalseAttr returns the CKA_UNWRAP=false attribute as a zero- or
// one-element slice, so a template can append it unconditionally:
//
//	privAttrs = append(privAttrs, unwrapFalseAttr(ctx)...)
//
// A module that cannot be asked (C_GetInfo failed) is treated as correct, for
// the same reason an unrecognized one is: the attribute is the safe default, and
// a module whose C_GetInfo does not work has larger problems that the very next
// call will surface.
func unwrapFalseAttr(ctx *pkcs11.Ctx) []*pkcs11.Attribute {
	if ctx != nil {
		if info, err := ctx.GetInfo(); err == nil && !canAssertUnwrapFalse(info) {
			return nil
		}
	}
	return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false)}
}
