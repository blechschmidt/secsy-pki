package keyprovider

import (
	"path/filepath"
	"strings"
	"testing"
)

// The PIN is resolved lazily, at the first HSM login. For a credential that
// lives in Vault or a cloud secrets manager that is right: a server must not
// refuse to boot because a secrets service was briefly slow.
//
// A PIN *file* is not like that. Its permissions will be exactly the same at the
// first signature as they are at startup, and until this preflight existed a
// deployment with a group-readable one started, bound its listener and answered
// /healthz with 200 while every single signature failed with HTTP 500 —
//
//	{"error":"signing: resolving signing key …: keyprovider: pin_source file
//	 /run/secrets/hsm.pin has insecure permissions 0644 …"}
//
// which is the worst shape a misconfiguration can take: automation that verifies
// a rollout by polling /healthz, which is most of it, saw a healthy CA.

func TestPreflightRejectsAGroupReadablePinFile(t *testing.T) {
	// 0640 root:<group> rather than 0644: it is what `chown root:secsy` plus a
	// default umask produces, and it is the form that looks deliberate.
	path := writePinFile(t, "0001password", 0o640)
	err := PreflightPinSources(PKCS11Settings{
		PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: path}},
	})
	if err == nil {
		t.Fatal("startup accepted a PIN file that group can read")
	}
	if !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("the error does not name the problem: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("the error does not name the path, which is the whole point of checking early: %v", err)
	}
}

func TestPreflightAcceptsAPrivatePinFile(t *testing.T) {
	path := writePinFile(t, "0001password", 0o600)
	if err := PreflightPinSources(PKCS11Settings{
		PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: path}},
	}); err != nil {
		t.Fatalf("a 0600 PIN file was rejected: %v", err)
	}
}

// A path that does not exist fails signing just as surely, so it fails startup
// too.
func TestPreflightRejectsAMissingPinFile(t *testing.T) {
	if err := PreflightPinSources(PKCS11Settings{
		PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{
			Path: filepath.Join(t.TempDir(), "absent.pin"),
		}},
	}); err == nil {
		t.Fatal("startup accepted a pin_source file that does not exist")
	}
}

// The override is still an override: a deployment that enforces the file's
// access some other way says so and is believed.
func TestPreflightHonoursTheInsecureOverride(t *testing.T) {
	path := writePinFile(t, "0001password", 0o644)
	if err := PreflightPinSources(PKCS11Settings{
		PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{
			Path: path, AllowInsecurePerms: true,
		}},
	}); err != nil {
		t.Fatalf("allow_insecure_perms was not honoured at startup: %v", err)
	}
}

// Sources that resolve over a network are not probed here: a boot that depends
// on a secrets service being up is a worse failure mode than the one being
// fixed, and `secsy-ca doctor` resolves them on demand instead.
func TestPreflightSkipsSourcesItCannotDecideLocally(t *testing.T) {
	for _, s := range []PKCS11Settings{
		{Pin: "0001password"},
		{PinSource: PinSourceSettings{Type: "env", Env: EnvPinSourceSettings{Var: "SECSY_PIN_NOT_SET_209"}}},
		{PinSource: PinSourceSettings{Type: "vault", Vault: VaultPinSourceSettings{
			VaultSettings: VaultSettings{Address: "https://vault.invalid:8200", Token: "t"}, Path: "hsm/prod",
		}}},
	} {
		if err := PreflightPinSources(s); err != nil {
			t.Fatalf("startup probed a source it cannot decide locally (%s): %v", s.PinSource.Type, err)
		}
	}
}

// A high-availability token set names the token whose PIN file is wrong, because
// "which of the four" is the question an operator asks next.
func TestPreflightNamesTheOffendingTokenInAnHASet(t *testing.T) {
	good := writePinFile(t, "0001password", 0o600)
	bad := writePinFile(t, "0001password", 0o644)
	err := PreflightPinSources(PKCS11Settings{
		Tokens: []TokenSettings{
			{Name: "primary", PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: good}}},
			{Name: "standby", PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: bad}}},
		},
	})
	if err == nil {
		t.Fatal("startup accepted an HA set with a group-readable PIN file")
	}
	if !strings.Contains(err.Error(), "standby") {
		t.Fatalf("the error does not name the token at fault: %v", err)
	}
}
