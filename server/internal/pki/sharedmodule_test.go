package pki

import (
	"bytes"
	"testing"
)

// The login refcount is what stops one holder of a PKCS#11 module from logging
// the whole process out from under the others. Its arithmetic needs no token,
// so it is tested here rather than in the SoftHSM-gated file: the decision
// "issue the real C_Logout now" is the single bit that, if it flips early,
// empties the serving key provider's key list.

func newTestModule() *sharedModule {
	return &sharedModule{logins: map[uint]int{}, pinFP: map[uint][]byte{}}
}

func TestSharedModuleLoginRefcount(t *testing.T) {
	m := newTestModule()
	fp := pinFingerprint("1234")

	// Three holders on one slot: only the third release logs out.
	m.takeLogin(0, fp)
	m.takeLogin(0, fp)
	m.takeLogin(0, fp)
	for i := 1; i <= 2; i++ {
		if m.dropLogin(0) {
			t.Fatalf("release %d of 3 reported the last logout; the remaining holders would be deauthenticated", i)
		}
	}
	if !m.dropLogin(0) {
		t.Fatal("the last release did not report a logout; the token would stay logged in for the life of the process")
	}
	if _, ok := m.logins[0]; ok {
		t.Errorf("slot 0 still tracked after the last release: %v", m.logins)
	}
}

func TestSharedModuleLoginRefcountIsPerSlot(t *testing.T) {
	m := newTestModule()
	m.takeLogin(0, pinFingerprint("1234"))
	m.takeLogin(7, pinFingerprint("5678"))

	// Slot 7's holder must not keep slot 0 logged in, nor the reverse: the
	// refcount is per token, because so is the login state.
	if !m.dropLogin(0) {
		t.Error("releasing the only slot-0 holder did not report a logout")
	}
	if !m.dropLogin(7) {
		t.Error("releasing the only slot-7 holder did not report a logout")
	}
	if len(m.logins) != 0 {
		t.Errorf("logins not empty after releasing both slots: %v", m.logins)
	}
}

func TestSharedModuleDropLoginWithoutTakeDoesNotLogOut(t *testing.T) {
	m := newTestModule()
	fp := pinFingerprint("1234")

	// An unbalanced release must not go negative, and must not report a logout:
	// a double-Close on one holder would otherwise deauthenticate a healthy one.
	if m.dropLogin(0) {
		t.Fatal("dropLogin on an untracked slot reported a logout")
	}
	m.takeLogin(0, fp)
	if !m.dropLogin(0) {
		t.Fatal("the sole holder's release did not report a logout")
	}
	if m.dropLogin(0) {
		t.Fatal("a second (unbalanced) release reported another logout")
	}
}

// The PIN fingerprint is what lets a second holder be told its PIN is wrong,
// on a token that answers the second C_Login with CKR_USER_ALREADY_LOGGED_IN
// without ever looking at the credential.
func TestSharedModuleRemembersTheEstablishingPIN(t *testing.T) {
	m := newTestModule()
	right, wrong := pinFingerprint("1234"), pinFingerprint("999999")
	if bytes.Equal(right, wrong) {
		t.Fatal("distinct PINs produced the same fingerprint")
	}

	// The first holder's PIN is the one on record; a later holder's is not,
	// because that one was never checked by the token.
	m.takeLogin(0, right)
	m.takeLogin(0, right)
	if got := m.pinFP[0]; !bytes.Equal(got, right) {
		t.Fatalf("slot 0 fingerprint = %x, want the establishing PIN's %x", got, right)
	}

	// Releasing down to the real logout clears it: the next login validates a
	// PIN again, so a stale fingerprint must not outlive the login it describes.
	if m.dropLogin(0) {
		t.Fatal("the first of two releases reported a logout")
	}
	if !m.dropLogin(0) {
		t.Fatal("the last release did not report a logout")
	}
	if _, ok := m.pinFP[0]; ok {
		t.Error("the PIN fingerprint outlived the login it described")
	}
}

// The fingerprint must not be derivable from the PIN alone outside this
// process: it is salted per process, so the same PIN digests differently in a
// different image. (Within one process it must of course be stable.)
func TestSharedModulePINFingerprintIsStableAndSalted(t *testing.T) {
	if !bytes.Equal(pinFingerprint("1234"), pinFingerprint("1234")) {
		t.Error("the same PIN fingerprinted differently twice in one process")
	}
	if bytes.Equal(pinFingerprint("1234"), []byte("1234")) {
		t.Error("the fingerprint is the PIN itself")
	}
	if len(pinSalt) != 32 {
		t.Errorf("pin salt is %d bytes, want 32", len(pinSalt))
	}
}
