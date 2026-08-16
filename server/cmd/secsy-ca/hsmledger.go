package main

import (
	"context"
	"log"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// Signature-ledger recording for the CLI (Task 167).
//
// secsy-ca signs from the same HSM the server does — init-root, issue, gen-crl,
// rotate, ssh, sign and the rest all reach a key provider. Every one of those
// signatures appears in the device audit log, so every one of them needs a
// ledger row too; a CLI-issued certificate that the ledger does not know about
// is indistinguishable, on the device log, from an abused key.
//
// The recorder is a package-level hook rather than a parameter threaded through
// buildProvider because buildProvider is called from three dozen dispatch arms
// and has no access to the store. Installing it once, immediately after the
// database is opened, covers all of them.

var signatureRecorder keyprovider.SignatureRecorder

// installSignatureRecorder turns on ledger recording when the attached device
// has been provisioned for audited operation.
//
// A failure to determine that is reported and treated as "off". The alternative
// — refusing to run any CLI command because the audit state could not be read —
// would make a database hiccup lock an operator out of the CA, and the device
// log still bounds what the HSM did regardless.
func installSignatureRecorder(db *database.DB) {
	rec, err := hsmaudit.EnableRecording(context.Background(), db)
	if err != nil {
		log.Printf("WARNING: could not determine HSM audit state, signature ledger recording is off: %v", err)
		return
	}
	signatureRecorder = rec
}

// recordSignatures wraps p so its signatures reach the ledger, when recording
// is enabled. It is a no-op otherwise, so an unprovisioned deployment behaves
// exactly as before.
func recordSignatures(p keyprovider.Provider) keyprovider.Provider {
	if signatureRecorder == nil {
		return p
	}
	return keyprovider.Record(p, signatureRecorder)
}
