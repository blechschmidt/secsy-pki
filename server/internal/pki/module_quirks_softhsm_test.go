package pki

// The other half of module_quirks_test.go: on a module that reads CKA_UNWRAP
// correctly, the attribute must actually reach the token and stick.
//
// module_quirks_test.go checks the decision and the template in isolation, which
// cannot catch the failure that matters here. SoftHSM defaults CKA_UNWRAP to
// CK_TRUE for a private key created without it — verified, not assumed; that
// default is why the attribute is gated rather than dropped — so a refactor that
// stopped appending it on *every* module would leave every software-token CA key
// unwrap-capable, and nothing else in the suite would notice. These tests read
// the bit back off the token for both ways a key gets there.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/miekg/pkcs11"
)

// softHSMPool builds a session pool from the SECSY_* variables
// scripts/setup-softhsm.sh --export-env emits, skipping when there is no token,
// so `go test ./...` on a machine with no HSM stays green.
func softHSMPool(t *testing.T) *SessionPool {
	t.Helper()
	module, token := os.Getenv("SECSY_PKCS11_MODULE"), os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE and SECSY_TOKEN_LABEL " +
			"(run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := NewSessionPool(PKCS11Config{ModulePath: module, Pin: pin, TokenLabel: token}, 1)
	if err != nil {
		t.Fatalf("opening a SoftHSM session pool: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// quirkLabel keeps each run's objects apart on a persistent token.
func quirkLabel(t *testing.T, base string) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "t201-" + base + "-" + hex.EncodeToString(b[:])
}

// readUnwrap reports the CKA_UNWRAP bit of the private key stored under label.
func readUnwrap(t *testing.T, p *SessionPool, label string) bool {
	t.Helper()
	s, release, err := p.borrow(context.Background())
	if err != nil {
		t.Fatalf("borrowing a session: %v", err)
	}
	defer release()
	ko, err := findKeyObjects(p.ctx, s.handle, LabelLocator(label))
	if err != nil {
		t.Fatalf("resolving %q on the token: %v", label, err)
	}
	attrs, err := p.ctx.GetAttributeValue(s.handle, ko.priv, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, nil),
	})
	if err != nil {
		t.Fatalf("reading CKA_UNWRAP of %q: %v", label, err)
	}
	if len(attrs) != 1 || len(attrs[0].Value) != 1 {
		t.Fatalf("CKA_UNWRAP of %q came back as %v, want one CK_BBOOL", label, attrs)
	}
	return attrs[0].Value[0] != 0
}

// destroyKey removes both halves of a test key so a persistent token does not
// accumulate them across runs and later lookups by label stay unambiguous.
func destroyKey(t *testing.T, p *SessionPool, label string) {
	t.Helper()
	s, release, err := p.borrow(context.Background())
	if err != nil {
		return
	}
	defer release()
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		tmpl := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		}
		if err := p.ctx.FindObjectsInit(s.handle, tmpl); err != nil {
			continue
		}
		handles, _, _ := p.ctx.FindObjects(s.handle, 8)
		_ = p.ctx.FindObjectsFinal(s.handle)
		for _, h := range handles {
			_ = p.ctx.DestroyObject(s.handle, h)
		}
	}
}

// TestGeneratedKeyIsNotUnwrapCapableOnSoftHSM covers the generation path, across
// key types: the CKA_UNWRAP append happens once after the type switch, so a
// mistake there would affect every type at once — and an EC key is the case that
// would still have worked even on the broken Yubico module, which makes it the
// one most likely to be left out of a fix.
func TestGeneratedKeyIsNotUnwrapCapableOnSoftHSM(t *testing.T) {
	p := softHSMPool(t)
	for _, keyType := range []string{"ecdsa-sha2-nistp256", "rsa-2048"} {
		t.Run(keyType, func(t *testing.T) {
			label := quirkLabel(t, "gen")
			t.Cleanup(func() { destroyKey(t, p, label) })
			if _, err := p.GenerateSignKey(context.Background(), label, keyType); err != nil {
				t.Fatalf("generating a %s key: %v", keyType, err)
			}
			if readUnwrap(t, p, label) {
				t.Error("the generated signing key is unwrap-capable; the least-privilege template did not reach the token")
			}
		})
	}
}

// TestImportedKeyIsNotUnwrapCapableOnSoftHSM is the same claim for the path this
// task is about. An imported CA key has to be no more privileged than a
// generated one — that equivalence is the promise internal/pki/importkey.go
// opens with.
func TestImportedKeyIsNotUnwrapCapableOnSoftHSM(t *testing.T) {
	p := softHSMPool(t)
	key := sharedRSAKey(t)

	label := quirkLabel(t, "imp")
	t.Cleanup(func() { destroyKey(t, p, label) })
	if _, err := p.ImportKey(context.Background(), label, nil, key, ImportUsageSign); err != nil {
		t.Fatalf("importing an RSA key: %v", err)
	}
	if readUnwrap(t, p, label) {
		t.Error("the imported signing key is unwrap-capable; the least-privilege template did not reach the token")
	}
}

// TestSoftHSMDefaultsUnwrapTrue records the token behaviour the gate is built
// on. If a future SoftHSM changed this default, the reasoning in
// module_quirks.go would still hold for other tokens but this repository's
// stated justification would be stale — better to be told by a failing test than
// to have the comment quietly become wrong.
func TestSoftHSMDefaultsUnwrapTrue(t *testing.T) {
	p := softHSMPool(t)
	key := sharedRSAKey(t)

	label := quirkLabel(t, "dflt")
	t.Cleanup(func() { destroyKey(t, p, label) })

	// The import template minus the one attribute, created directly so the test
	// states exactly what it is asking the token.
	privAttrs, _, err := importTemplates(nil, key, label, nil, ImportUsageSign)
	if err != nil {
		t.Fatalf("building the import template: %v", err)
	}
	withoutUnwrap := make([]*pkcs11.Attribute, 0, len(privAttrs))
	for _, a := range privAttrs {
		if a.Type != pkcs11.CKA_UNWRAP {
			withoutUnwrap = append(withoutUnwrap, a)
		}
	}
	if len(withoutUnwrap) != len(privAttrs)-1 {
		t.Fatalf("the sign import template has no CKA_UNWRAP to remove (%d attributes)", len(privAttrs))
	}

	s, release, err := p.borrow(context.Background())
	if err != nil {
		t.Fatalf("borrowing a session: %v", err)
	}
	_, err = p.ctx.CreateObject(s.handle, withoutUnwrap)
	release()
	if err != nil {
		t.Fatalf("creating a key without CKA_UNWRAP: %v", err)
	}

	if !readUnwrap(t, p, label) {
		t.Error("SoftHSM now defaults CKA_UNWRAP to CK_FALSE for a private key. " +
			"Nothing is broken, but the reason module_quirks.go gates the attribute instead of " +
			"dropping it no longer holds for this token — recheck the other tokens and simplify " +
			"unwrapFalseAttr if none of them default it to CK_TRUE either.")
	}
}
