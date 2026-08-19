package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmattest"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// `secsy-ca hsm-attest` drives YubiHSM key attestation (Task 168).
//
// The subcommands split along the same trust boundary as `hsm-audit`: key/ca/
// audit run on the CA host and touch the device, while verify runs anywhere and
// is dispatched in main before the database or key provider is opened, so a
// third party can check an attestation they were handed without any access to
// the CA.

func hsmAttestUsage() {
	fmt.Fprint(os.Stderr, `Usage: secsy-ca hsm-attest <subcommand> [flags]

Ask the YubiHSM to attest a key it holds, and check what the device says about
it — in particular whether the private key can ever leave the device. Or attest
the device itself, and check what Yubico says about it.

Subcommands:
  key <label>           Attest one key by its HSM label
  ca <ca-id>            Attest the key behind a CA, bound to that CA's
                        certificate so the attestation is tied to the key the
                        CA actually signs with
  audit                 Attest every asymmetric key on the device and report
                        which ones fail policy
  device                Attest the device itself: verify against Yubico's
                        published attestation CA that the attached hardware is a
                        genuine YubiHSM, and print its verified serial number
  verify -file FILE     Verify an attestation offline (no database, no HSM).
                        FILE is either the JSON emitted by -out, or a PEM
                        attestation certificate. A device attestation written by
                        "device -out" is recognised and verified as one.

Flags (device):
  -challenge STRING     Nonce the device must answer. Defaults to a fresh random
                        one; supply your own to check a device on someone else's
                        behalf. Answering it makes the device generate, attest
                        and delete a throwaway key in a reserved slot, which
                        costs three device audit-log entries.
  -no-challenge         Only read and check the device certificate. Read-only,
                        and a strictly weaker claim: it shows that a genuine
                        YubiHSM with this serial exists, not that the device
                        examined is that one.
  -object-id ID         Reserved slot for the challenge key (default 0xfa00).
  -expect-serial SERIAL Serial the device must turn out to have.
  -roots FILE           PEM trust anchors. Defaults to Yubico's published
                        attestation roots, embedded in this binary.

Flags (key, ca, audit, device):
  -out FILE             Write the attestation as JSON for later verification
                        or for handing to a third party
  -pem FILE             Write the attestation certificate chain as PEM
  -json                 Emit the full machine-readable verdict

Flags (verify):
  -file FILE            Attestation to verify (JSON or PEM). Required.
  -device-cert FILE     Device attestation certificate, when FILE is a bare PEM
                        certificate that does not carry one. Without it the
                        attestation's signature cannot be checked.
  -roots FILE           PEM trust anchors. Defaults to Yubico's published
                        attestation roots, embedded in this binary.
  -expect-key FILE      Certificate or public key the attested key must equal.
                        This is what ties an attestation to a specific CA;
                        without it the result only says that some key on the
                        device has these properties.
  -expect-label LABEL   Key label the attestation must assert.
  -expect-serial SERIAL Device serial the attestation must assert.
  -expect-challenge C   For a device attestation: the challenge it must answer.
                        Set it to the nonce you chose, or the bundle only proves
                        possession at some unknown time.
  -require-anchor       Fail unless the device certificate chains to a trusted
                        root, i.e. the attesting device is provably a genuine
                        YubiHSM. On by default; Yubico publishes both the root
                        and the issuing sub-CA and both ship embedded, so stock
                        hardware anchors with no configuration. Pass
                        -require-anchor=false for a device whose factory
                        attestation key was replaced with an owner-generated
                        one, where no Yubico chain exists to anchor to.
  -allow-exportable     Report rather than fail when the key can be exported.
  -allow-imported       Report rather than fail when the key was imported
                        instead of generated inside the HSM.
  -allow-no-challenge   Accept a device attestation that answers no challenge,
                        i.e. one that authenticates a certificate rather than a
                        device.
  -json                 Emit the full machine-readable verdict.

Exit status is 0 when the attestation satisfies the policy and 1 when it does
not, so this is usable as a compliance check in a pipeline.
`)
}

func cmdHSMAttest(db *database.DB, cfg *config.Config, args []string) error {
	if len(args) == 0 {
		hsmAttestUsage()
		return fmt.Errorf("hsm-attest: no subcommand given")
	}
	sub, rest := args[0], args[1:]

	hsmCfg := hsm.Config{
		ConnectorURL: cfg.YubiHSM.ConnectorURL,
		AuthKeyID:    cfg.YubiHSM.AuthKeyID,
		Password:     cfg.YubiHSM.Password,
	}
	ctx := context.Background()

	switch sub {
	case "key":
		return cmdHSMAttestKey(ctx, hsmCfg, cfg, rest)
	case "ca":
		return cmdHSMAttestCA(ctx, hsmCfg, cfg, db, rest)
	case "audit":
		return cmdHSMAttestAudit(ctx, hsmCfg, cfg, rest)
	case "device":
		return cmdHSMAttestDevice(ctx, hsmCfg, cfg, rest)
	case "help", "-h", "--help":
		hsmAttestUsage()
		return nil
	default:
		hsmAttestUsage()
		return fmt.Errorf("hsm-attest: unknown subcommand %q", sub)
	}
}

// attestFlags are the output flags shared by the device-touching subcommands.
type attestFlags struct {
	out    *string
	pemOut *string
	asJSON *bool
}

func registerAttestFlags(fs *flag.FlagSet) attestFlags {
	return attestFlags{
		out:    fs.String("out", "", "write the attestation as JSON to this file"),
		pemOut: fs.String("pem", "", "write the attestation certificate chain as PEM to this file"),
		asJSON: fs.Bool("json", false, "emit JSON"),
	}
}

func cmdHSMAttestKey(ctx context.Context, hsmCfg hsm.Config, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("hsm-attest key", flag.ContinueOnError)
	f := registerAttestFlags(fs)
	label, rest := splitIDAndFlags(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if label == "" {
		label = fs.Arg(0)
	}
	if label == "" {
		hsmAttestUsage()
		return fmt.Errorf("hsm-attest key: key label is required")
	}

	pol, err := cfg.YubiHSM.AttestationPolicy()
	if err != nil {
		return err
	}
	att, err := hsmattest.NewDeviceAttester(hsmCfg).AttestKey(ctx, label)
	if err != nil {
		return err
	}
	return reportAttestation(att, hsmattest.Verify(att, pol), f)
}

func cmdHSMAttestCA(ctx context.Context, hsmCfg hsm.Config, cfg *config.Config, db *database.DB, args []string) error {
	fs := flag.NewFlagSet("hsm-attest ca", flag.ContinueOnError)
	f := registerAttestFlags(fs)
	caID, rest := splitIDAndFlags(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if caID == "" {
		caID = fs.Arg(0)
	}
	if caID == "" {
		hsmAttestUsage()
		return fmt.Errorf("hsm-attest ca: CA id is required")
	}

	caRec, err := db.GetCA(caID)
	if err != nil {
		return fmt.Errorf("CA lookup failed: %w", err)
	}
	if caRec == nil {
		return fmt.Errorf("CA %q not found", caID)
	}
	label := pki.ExtractKeyLabel(caRec.PKCS11URI)
	if label == "" {
		return fmt.Errorf("CA %q has no resolvable HSM key label (pkcs11_uri=%q); only HSM-backed CAs can be attested",
			caID, caRec.PKCS11URI)
	}

	pol, err := cfg.YubiHSM.AttestationPolicy()
	if err != nil {
		return err
	}
	pol.ExpectedLabel = label
	// Binding the attestation to the CA certificate's key is what makes it a
	// statement about this CA rather than about some object on the device.
	if pub, err := caCertPublicKey(caRec.Certificate, caRec.PublicKey); err == nil && pub != nil {
		pol.ExpectedPublicKey = pub
	} else {
		fmt.Fprintf(os.Stderr,
			"warning: CA %q has no usable public key on record; the attestation cannot be bound to it\n", caID)
	}

	att, err := hsmattest.NewDeviceAttester(hsmCfg).AttestKey(ctx, label)
	if err != nil {
		return err
	}
	return reportAttestation(att, hsmattest.Verify(att, pol), f)
}

// cmdHSMAttestAudit attests every asymmetric key on the device.
//
// This is the posture check an operator actually wants: not "is this one key
// safe" but "is anything on this device exportable". A key that should never
// have been created with exportable-under-wrap is invisible until something
// enumerates them.
func cmdHSMAttestAudit(ctx context.Context, hsmCfg hsm.Config, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("hsm-attest audit", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	out := fs.String("out", "", "write all attestations as JSON to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := cfg.YubiHSM.AttestationPolicy()
	if err != nil {
		return err
	}
	objs, err := hsm.ListObjects(ctx, hsmCfg)
	if err != nil {
		return err
	}
	attester := hsmattest.NewDeviceAttester(hsmCfg)

	type row struct {
		Attestation  *hsmattest.Attestation `json:"attestation,omitempty"`
		Verification *hsmattest.Result      `json:"verification,omitempty"`
		ObjectID     uint16                 `json:"object_id"`
		Label        string                 `json:"label"`
		Error        string                 `json:"error,omitempty"`
	}
	var rows []row
	var failures int

	for _, o := range objs {
		if o.Type != "asymmetric-key" {
			continue
		}
		att, err := attester.AttestObject(ctx, o.ID)
		if err != nil {
			rows = append(rows, row{ObjectID: o.ID, Label: o.Label, Error: err.Error()})
			failures++
			continue
		}
		// Each key is judged on the device's own assertions; no per-key expected
		// label or key is imposed here because this pass is an inventory.
		res := hsmattest.Verify(att, pol)
		if !res.Verified {
			failures++
		}
		rows = append(rows, row{Attestation: att, Verification: res, ObjectID: o.ID, Label: o.Label})
	}

	if *out != "" {
		data, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, data, 0o600); err != nil {
			return err
		}
	}
	if *asJSON {
		return emitJSON(rows)
	}

	if len(rows) == 0 {
		fmt.Println("No asymmetric keys on the device.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "OBJECT\tLABEL\tEXPORTABLE\tORIGIN\tCAPABILITIES\tVERDICT")
	for _, r := range rows {
		if r.Error != "" {
			fmt.Fprintf(tw, "0x%04x\t%s\t?\t?\t?\tERROR: %s\n", r.ObjectID, r.Label, r.Error)
			continue
		}
		v := r.Verification
		verdict := "ok"
		if !v.Verified {
			verdict = "FAIL: " + v.Problems[0]
		}
		fmt.Fprintf(tw, "0x%04x\t%s\t%s\t%s\t%s\t%s\n",
			r.ObjectID, r.Label, yesNo(!v.NonExportable), v.Origin,
			strings.Join(v.Capabilities, ","), verdict)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d attested key(s) did not satisfy policy", failures, len(rows))
	}
	fmt.Printf("\nAll %d key(s) satisfy the attestation policy.\n", len(rows))
	return nil
}

// cmdHSMAttestDevice attests the device rather than a key on it.
//
// The other subcommands take the device for granted: they establish what an
// object on it is, on the strength of a signature by an attestation key nobody
// checked belonged to real hardware. This one closes that, and it is the
// prerequisite for reading any of the others as evidence rather than as claims.
func cmdHSMAttestDevice(ctx context.Context, hsmCfg hsm.Config, cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("hsm-attest device", flag.ContinueOnError)
	f := registerAttestFlags(fs)
	challenge := fs.String("challenge", "", "nonce the device must answer (default: a fresh random one)")
	noChallenge := fs.Bool("no-challenge", false, "only read and check the device certificate; do not make the device answer a challenge")
	objectID := fs.Uint("object-id", uint(hsmattest.DefaultDeviceChallengeKeyID), "reserved object id for the throwaway challenge key")
	expectSerial := fs.String("expect-serial", "", "serial the device must turn out to have")
	roots := fs.String("roots", "", "PEM trust anchors (default: embedded Yubico attestation roots)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *noChallenge && *challenge != "" {
		return fmt.Errorf("hsm-attest device: -challenge and -no-challenge are mutually exclusive")
	}
	if *objectID > 0xffff {
		return fmt.Errorf("hsm-attest device: -object-id 0x%x is not a YubiHSM object handle", *objectID)
	}

	pol, err := cfg.YubiHSM.DeviceAttestationPolicy()
	if err != nil {
		return err
	}
	pol.ExpectedSerial = *expectSerial
	if *roots != "" {
		r, inter, err := hsmattest.LoadRoots([]string{*roots})
		if err != nil {
			return err
		}
		pol.Roots, pol.Intermediates = r, inter
	}

	// A challenge is the difference between authenticating the device and
	// authenticating a certificate, so it is what happens unless the operator
	// asks for the read-only form.
	nonce := *challenge
	switch {
	case *noChallenge:
		nonce = ""
		pol.RequireProofOfPossession = false
	case nonce == "":
		if nonce, err = hsmattest.NewChallenge(); err != nil {
			return err
		}
	}
	pol.ExpectedChallenge = nonce

	auth := hsmattest.NewDeviceAuthenticator(hsmCfg)
	auth.ChallengeObjectID = uint16(*objectID)
	att, err := auth.Attest(ctx, nonce)
	// Answering a challenge writes three force-audited entries to the device's
	// 62-entry log ring, so this command owes the ledger a drain on the way out
	// exactly as a signing command does — including when it failed partway, which
	// is when unaccounted entries matter most.
	if nonce != "" {
		hsmUsed.Store(true)
	}
	if err != nil {
		return err
	}
	return reportDeviceAttestation(att, hsmattest.VerifyDevice(att, pol), f)
}

// cmdHSMAttestVerify is the offline verifier. It reads no config, opens no
// database and touches no device, so it is dispatched before any of them exist.
func cmdHSMAttestVerify(args []string) error {
	fs := flag.NewFlagSet("hsm-attest verify", flag.ContinueOnError)
	file := fs.String("file", "", "attestation to verify (JSON or PEM)")
	deviceCert := fs.String("device-cert", "", "device attestation certificate (PEM)")
	roots := fs.String("roots", "", "PEM trust anchors (default: embedded Yubico root)")
	expectKey := fs.String("expect-key", "", "certificate or public key the attested key must equal")
	expectLabel := fs.String("expect-label", "", "key label the attestation must assert")
	expectSerial := fs.String("expect-serial", "", "device serial the attestation must assert")
	expectChallenge := fs.String("expect-challenge", "", "challenge a device attestation must answer")
	requireAnchor := fs.Bool("require-anchor", true, "fail unless the device certificate chains to a trusted root; -require-anchor=false to opt out")
	allowExportable := fs.Bool("allow-exportable", false, "report rather than fail when the key is exportable")
	allowImported := fs.Bool("allow-imported", false, "report rather than fail when the key was imported")
	allowNoChallenge := fs.Bool("allow-no-challenge", false, "accept a device attestation that answers no challenge")
	asJSON := fs.Bool("json", false, "emit JSON")
	path, rest := splitIDAndFlags(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *file != "" {
		path = *file
	}
	if path == "" {
		hsmAttestUsage()
		return fmt.Errorf("hsm-attest verify: -file is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading attestation: %w", err)
	}
	// A device attestation says what it is, so it is verified as what it is
	// rather than misread as a key attestation with most of its fields missing.
	if dev, ok := deviceAttestationFrom(data); ok {
		return verifyDeviceAttestation(dev, deviceVerifyFlags{
			roots:            *roots,
			expectSerial:     *expectSerial,
			expectChallenge:  *expectChallenge,
			requireAnchor:    *requireAnchor,
			allowNoChallenge: *allowNoChallenge,
			asJSON:           *asJSON,
		})
	}

	att, err := loadAttestation(data, *deviceCert)
	if err != nil {
		return err
	}

	pol := hsmattest.DefaultPolicy()
	pol.RequireNonExportable = !*allowExportable
	pol.RequireGeneratedOnDevice = !*allowImported
	pol.RequireAnchoredChain = *requireAnchor
	pol.ExpectedLabel = *expectLabel
	pol.ExpectedSerial = *expectSerial
	if *roots != "" {
		r, inter, err := hsmattest.LoadRoots([]string{*roots})
		if err != nil {
			return err
		}
		pol.Roots, pol.Intermediates = r, inter
	}
	if *expectKey != "" {
		data, err := os.ReadFile(*expectKey)
		if err != nil {
			return fmt.Errorf("reading -expect-key: %w", err)
		}
		pub, err := publicKeyFromPEM(data)
		if err != nil {
			return fmt.Errorf("-expect-key: %w", err)
		}
		pol.ExpectedPublicKey = pub
	}

	res := hsmattest.Verify(att, pol)
	if *asJSON {
		if err := emitJSON(res); err != nil {
			return err
		}
	} else {
		printAttestationResult(res)
	}
	if !res.Verified {
		return attestationFailed(res)
	}
	return nil
}

// reportAttestation writes the requested outputs and returns a non-nil error
// when the attestation failed policy, so the command's exit status is usable.
func reportAttestation(att *hsmattest.Attestation, res *hsmattest.Result, f attestFlags) error {
	if *f.out != "" {
		data, err := json.MarshalIndent(att, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*f.out, data, 0o600); err != nil {
			return err
		}
	}
	if *f.pemOut != "" {
		chain := att.CertificatePEM
		if att.DeviceCertificatePEM != "" {
			chain = strings.TrimRight(chain, "\n") + "\n" + att.DeviceCertificatePEM
		}
		if err := os.WriteFile(*f.pemOut, []byte(chain), 0o644); err != nil { //nolint:gosec // public certificates
			return err
		}
	}
	if *f.asJSON {
		if err := emitJSON(map[string]any{"attestation": att, "verification": res}); err != nil {
			return err
		}
	} else {
		printAttestationResult(res)
		if *f.out != "" {
			fmt.Fprintf(os.Stderr, "\nAttestation written to %s — verify it anywhere with:\n  secsy-ca hsm-attest verify -file %s\n", *f.out, *f.out)
		}
	}
	if !res.Verified {
		return attestationFailed(res)
	}
	return nil
}

// reportDeviceAttestation writes the requested outputs for a device attestation
// and returns a non-nil error when it failed policy.
func reportDeviceAttestation(att *hsmattest.DeviceAttestation, res *hsmattest.DeviceResult, f attestFlags) error {
	if *f.out != "" {
		data, err := json.MarshalIndent(att, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*f.out, data, 0o600); err != nil {
			return err
		}
	}
	if *f.pemOut != "" {
		chain := att.DeviceCertificatePEM
		if att.ChallengeCertificatePEM != "" {
			chain = strings.TrimRight(att.ChallengeCertificatePEM, "\n") + "\n" + chain
		}
		if err := os.WriteFile(*f.pemOut, []byte(chain), 0o644); err != nil { //nolint:gosec // public certificates
			return err
		}
	}
	if *f.asJSON {
		if err := emitJSON(map[string]any{"attestation": att, "verification": res}); err != nil {
			return err
		}
	} else {
		printDeviceResult(res)
		if *f.out != "" {
			fmt.Fprintf(os.Stderr, "\nDevice attestation written to %s — verify it anywhere with:\n  secsy-ca hsm-attest verify -file %s -expect-challenge %s\n",
				*f.out, *f.out, att.Challenge)
		}
	}
	if !res.Verified {
		return fmt.Errorf("device attestation did not satisfy policy: %s", res.Problems[0])
	}
	return nil
}

// deviceVerifyFlags carries the offline verifier's device-related options.
type deviceVerifyFlags struct {
	roots            string
	expectSerial     string
	expectChallenge  string
	requireAnchor    bool
	allowNoChallenge bool
	asJSON           bool
}

// verifyDeviceAttestation is the offline half: it checks a bundle a device
// produced elsewhere, with no device, database or config of its own.
func verifyDeviceAttestation(att *hsmattest.DeviceAttestation, f deviceVerifyFlags) error {
	pol := hsmattest.DefaultDevicePolicy()
	pol.RequireAnchoredChain = f.requireAnchor
	pol.RequireProofOfPossession = !f.allowNoChallenge
	pol.ExpectedSerial = f.expectSerial
	pol.ExpectedChallenge = f.expectChallenge
	if f.roots != "" {
		r, inter, err := hsmattest.LoadRoots([]string{f.roots})
		if err != nil {
			return err
		}
		pol.Roots, pol.Intermediates = r, inter
	}

	res := hsmattest.VerifyDevice(att, pol)
	if f.asJSON {
		if err := emitJSON(res); err != nil {
			return err
		}
	} else {
		printDeviceResult(res)
	}
	if !res.Verified {
		return fmt.Errorf("device attestation did not satisfy policy: %s", res.Problems[0])
	}
	return nil
}

// deviceAttestationFrom recognises a device attestation bundle by the kind it
// declares, so that `verify` routes on what the file says it is rather than on
// which fields happen to be populated.
func deviceAttestationFrom(data []byte) (*hsmattest.DeviceAttestation, bool) {
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		return nil, false
	}
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &probe); err != nil || probe.Kind != hsmattest.DeviceAttestationKind {
		return nil, false
	}
	att := &hsmattest.DeviceAttestation{}
	if err := json.Unmarshal(data, att); err != nil {
		return nil, false
	}
	return att, true
}

// printDeviceResult renders a device verdict for a human. The serial comes
// first: "which device is this, and is it real" is the entire question.
func printDeviceResult(res *hsmattest.DeviceResult) {
	fmt.Printf("Device serial:    %s\n", orDash(res.Serial))
	// Only an answered challenge reports the firmware the device is running; the
	// certificate's own value is what it shipped with, and saying so is better
	// than either a dash or a number that a firmware update has made wrong.
	switch {
	case res.FirmwareVersion != "":
		fmt.Printf("Firmware:         %s\n", res.FirmwareVersion)
	case res.FactoryFirmwareVersion != "":
		fmt.Printf("Firmware:         %s at manufacture (only a challenge reports the running version)\n",
			res.FactoryFirmwareVersion)
	default:
		fmt.Printf("Firmware:         -\n")
	}
	fmt.Printf("Certificate:      %s\n", orDash(res.SubjectCommonName))
	fmt.Printf("Issuing CA:       %s\n", orDash(res.IssuingCA))
	fmt.Printf("Trust anchor:     %s\n", orDash(res.TrustAnchor))
	fmt.Println()
	fmt.Printf("Yubico-certified: %s\n", yesNo(res.ChainAnchored))
	pop := "no"
	if res.ProofOfPossession {
		pop = fmt.Sprintf("yes (challenge %s, object 0x%04x)", res.Challenge, res.ChallengeObjectID)
	}
	fmt.Printf("Answered challenge: %s\n", pop)
	if res.ReportedSerialMatched != nil {
		agreement := "differs from its certificate"
		if *res.ReportedSerialMatched {
			agreement = "agrees with its certificate"
		}
		fmt.Printf("Device reports:   %s (%s)\n", res.ReportedSerial, agreement)
	}

	if len(res.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range res.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}
	if len(res.Problems) > 0 {
		fmt.Println("\nProblems:")
		for _, p := range res.Problems {
			fmt.Printf("  - %s\n", p)
		}
	}
	fmt.Printf("\n%s\n", res.Summary)
}

// printAttestationResult renders a verdict for a human.
func printAttestationResult(res *hsmattest.Result) {
	fmt.Printf("Key label:        %s\n", orDash(res.KeyLabel))
	fmt.Printf("Object ID:        0x%04x\n", res.ObjectID)
	fmt.Printf("Device serial:    %s (firmware %s)\n", orDash(res.DeviceSerial), orDash(res.FirmwareVersion))
	fmt.Printf("Key:              %s %s\n", orDash(res.PublicKeyAlgorithm), res.PublicKeyDetail)
	fmt.Printf("SPKI fingerprint: %s\n", orDash(res.SPKIFingerprint))
	fmt.Println()
	fmt.Printf("Non-exportable:   %s\n", yesNo(res.NonExportable))
	fmt.Printf("Generated in HSM: %s  (origin: %s)\n", yesNo(res.GeneratedOnDevice), orDash(res.Origin))
	fmt.Printf("Can sign:         %s\n", yesNo(res.CanSign))
	fmt.Printf("Capabilities:     %s\n", orDash(strings.Join(res.Capabilities, ", ")))
	if len(res.Domains) > 0 {
		fmt.Printf("Domains:          %v\n", res.Domains)
	}
	fmt.Println()
	fmt.Printf("Device-signed:    %s\n", yesNo(res.DeviceBound))
	anchor := "no"
	if res.ChainAnchored {
		anchor = "yes (" + res.TrustAnchor + ")"
	}
	fmt.Printf("Chain anchored:   %s\n", anchor)
	if res.KeyMatched != nil {
		fmt.Printf("Matches expected: %s\n", yesNo(*res.KeyMatched))
	}

	if len(res.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range res.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}
	if len(res.Problems) > 0 {
		fmt.Println("\nProblems:")
		for _, p := range res.Problems {
			fmt.Printf("  - %s\n", p)
		}
	}
	fmt.Printf("\n%s\n", res.Summary)
}

// loadAttestation reads an attestation from either the JSON form this command
// emits or a bare PEM certificate, so an operator can verify whatever they were
// handed without converting it first.
func loadAttestation(data []byte, deviceCertPath string) (*hsmattest.Attestation, error) {
	att := &hsmattest.Attestation{}
	if trimmed := strings.TrimSpace(string(data)); strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, att); err != nil {
			return nil, fmt.Errorf("parsing attestation JSON: %w", err)
		}
		// Tolerate the {"attestation":…} envelope the REST API returns, so a
		// response saved straight from curl verifies without editing.
		if att.CertificatePEM == "" {
			var wrapper struct {
				Attestation *hsmattest.Attestation `json:"attestation"`
			}
			if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Attestation != nil {
				att = wrapper.Attestation
			}
		}
		if att.CertificatePEM == "" {
			return nil, fmt.Errorf("attestation JSON carries no certificate_pem")
		}
	} else {
		att.CertificatePEM = string(data)
	}

	if deviceCertPath != "" {
		dc, err := os.ReadFile(deviceCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading -device-cert: %w", err)
		}
		att.DeviceCertificatePEM = string(dc)
	}
	return att, nil
}

// attestationFailed turns a negative verdict into a non-zero exit status. The
// full report has already been printed, so this only needs to name the reason.
func attestationFailed(res *hsmattest.Result) error {
	return fmt.Errorf("attestation did not satisfy policy: %s", res.Problems[0])
}

// caCertPublicKey recovers a CA's public key, preferring its X.509 certificate
// and falling back to the stored public-key column (an SSH-only CA has no
// certificate).
func caCertPublicKey(certPEM, pubPEM string) (crypto.PublicKey, error) {
	if s := strings.TrimSpace(certPEM); s != "" {
		return publicKeyFromPEM([]byte(s))
	}
	if s := strings.TrimSpace(pubPEM); s != "" {
		return publicKeyFromPEM([]byte(s))
	}
	return nil, fmt.Errorf("no certificate or public key on record")
}

// publicKeyFromPEM accepts either a PUBLIC KEY or a CERTIFICATE block, so an
// operator can point -expect-key at the CA certificate directly.
func publicKeyFromPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not valid PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	default:
		return nil, fmt.Errorf("PEM type %q; want PUBLIC KEY or CERTIFICATE", block.Type)
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
