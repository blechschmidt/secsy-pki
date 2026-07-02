package pki

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// Probe verifies connectivity to the configured PKCS#11 token without requiring
// any particular key to exist. It loads the module, initializes Cryptoki, finds
// the configured token, opens a session, and logs in with the user PIN — the
// same steps every signing operation performs, minus the key lookup. It returns
// nil when the token is reachable and the PIN is accepted, and a descriptive
// error otherwise. All resources it opens are released before returning.
//
// This is intended for readiness probes: a healthy result means the HSM can
// service signing requests right now.
func Probe(cfg PKCS11Config) (err error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return fmt.Errorf("failed to load PKCS#11 module: %s", cfg.ModulePath)
	}
	if initErr := ctx.Initialize(); initErr != nil {
		if e, ok := initErr.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			ctx.Destroy()
			return fmt.Errorf("initializing PKCS#11: %w", initErr)
		}
	}

	var (
		session  pkcs11.SessionHandle
		haveSess bool
		loggedIn bool
	)
	defer func() {
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
		return fmt.Errorf("getting slots: %w", err)
	}

	slotID, err := findToken(ctx, slots, cfg)
	if err != nil {
		return err
	}

	session, err = ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return fmt.Errorf("opening session: %w", err)
	}
	haveSess = true

	// A login round-trip confirms the PIN is valid, not just that the module
	// loads — so a rotated/incorrect PIN surfaces as unready rather than at the
	// first signing attempt.
	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.Pin); err != nil {
		return fmt.Errorf("logging in: %w", err)
	}
	loggedIn = true

	return nil
}
