package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// operatorActor derives the audit actor for a CLI-driven escrow/recovery
// operation. An explicit -operator flag wins; otherwise the OS user is used,
// prefixed so it is unambiguous in the audit trail that this came from the CLI.
func operatorActor(explicit string) string {
	if explicit != "" {
		return "operator:" + explicit
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "operator:" + u.Username
	}
	return "operator:secsy-secret"
}

// openAuditDB opens the configured database so escrow and recovery operations
// can be appended to the tamper-evident audit log. It returns a clear error if
// no database is configured, since escrow/recovery must be auditable.
func openAuditDB(cfg *config.Config) (*database.DB, error) {
	if cfg.Database.Driver == "" || cfg.Database.DSN == "" {
		return nil, fmt.Errorf("escrow operations require an audit database: set database.driver and database.dsn in the config")
	}
	db, err := database.New(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("opening audit database: %w", err)
	}
	return db, nil
}

// recordEscrowEvent appends one escrow/recovery event to the hash-chained audit
// log. Failing to record is treated as a hard error for recovery ceremonies:
// an unauditable break-glass operation must not silently succeed.
func recordEscrowEvent(db *database.DB, actor, action, target, result, detail string) error {
	return db.AppendEvent(&audit.Event{
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Target:    target,
		Result:    result,
		Detail:    detail,
	})
}

// escrowPolicyFromConfig builds a validated M-of-N escrow policy from the
// secret.escrow configuration, resolving each recovery agent's public key from
// the key provider or an inline/file PEM.
func escrowPolicyFromConfig(ctx context.Context, cfg *config.Config, provider keyprovider.Provider) (*secret.EscrowPolicy, error) {
	ec := cfg.Secret.Escrow
	if !ec.Enabled {
		return nil, fmt.Errorf("key escrow is not enabled: set secret.escrow.enabled and configure recovery agents")
	}
	specs := make([]secret.AgentSpec, 0, len(ec.Agents))
	for _, a := range ec.Agents {
		spec := secret.AgentSpec{ID: a.ID, KeyLabel: a.KeyLabel, PublicKeyPEM: a.PublicKey}
		if spec.PublicKeyPEM == "" && a.PublicKeyFile != "" {
			pem, err := os.ReadFile(a.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("reading public_key_file for agent %q: %w", a.ID, err)
			}
			spec.PublicKeyPEM = string(pem)
		}
		specs = append(specs, spec)
	}
	return secret.NewEscrowPolicy(ctx, provider, ec.Threshold, specs)
}

// cmdEscrowConfig inspects and validates the configured escrow policy. Without
// -verify it prints the configuration; with -verify it resolves every agent key
// (and self-tests unwrap for provider-held keys) so operators can confirm the
// escrow is usable before relying on it for recovery.
func cmdEscrowConfig(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("escrow-config", flag.ContinueOnError)
	verify := fs.Bool("verify", false, "resolve every recovery-agent key and validate the policy end-to-end")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ec := cfg.Secret.Escrow
	if !ec.Enabled {
		fmt.Println("Key escrow: DISABLED (set secret.escrow.enabled: true to enable)")
		return nil
	}
	fmt.Printf("Key escrow: ENABLED\n")
	fmt.Printf("  Quorum (threshold): %d of %d recovery agent(s)\n", ec.Threshold, len(ec.Agents))
	fmt.Printf("  Recovery agents:\n")
	for _, a := range ec.Agents {
		src := "provider key label"
		switch {
		case a.PublicKey != "":
			src = "inline PEM public key"
		case a.PublicKeyFile != "":
			src = "PEM file: " + a.PublicKeyFile
		}
		fmt.Printf("    - %-20s key_label=%-20s (%s)\n", a.ID, a.KeyLabel, src)
	}

	if !*verify {
		fmt.Println("\nRun with -verify to resolve every agent key and confirm the policy is usable.")
		return nil
	}

	policy, err := escrowPolicyFromConfig(context.Background(), cfg, provider)
	if err != nil {
		return fmt.Errorf("escrow policy is INVALID: %w", err)
	}
	fmt.Printf("\nVerification: OK — %d agent key(s) resolved, %d-of-%d quorum enforced.\n",
		len(policy.Agents()), policy.Threshold(), len(policy.Agents()))
	for _, ag := range policy.Agents() {
		bits := ag.Pub.N.BitLen()
		recoverable := "recoverable via provider"
		if ag.KeyLabel == "" {
			recoverable = "wrap-only (private key held externally)"
		}
		fmt.Printf("    - %-20s RSA-%d  %s\n", ag.ID, bits, recoverable)
	}
	return nil
}

// cmdEscrowInitAgent generates an RSA recovery-agent key on the configured
// provider, mirroring init-kek but for an escrow agent. The generated key is a
// decryption key (least-privilege) so it can unwrap its share during recovery.
func cmdEscrowInitAgent(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("escrow-init-agent", flag.ContinueOnError)
	label := fs.String("label", "", "key label for the new recovery-agent key (required)")
	keyType := fs.String("key-type", "rsa-4096", "RSA key type (rsa-2048 or rsa-4096)")
	pubOut := fs.String("pub-out", "", "also write the agent's PEM public key to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		return fmt.Errorf("-label is required")
	}
	info, err := provider.GenerateKey(context.Background(), keyprovider.KeySpec{
		Label:   *label,
		KeyType: *keyType,
		Usage:   keyprovider.KeyUsageDecrypt,
	})
	if err != nil {
		return fmt.Errorf("generating recovery-agent key: %w", err)
	}
	fmt.Printf("Recovery-agent key created:\n")
	fmt.Printf("  Label:    %s\n", info.Label)
	fmt.Printf("  Key type: %s\n", info.KeyType)
	if info.URI != "" {
		fmt.Printf("  URI:      %s\n", info.URI)
	}
	if *pubOut != "" {
		der, err := x509.MarshalPKIXPublicKey(info.PublicKey)
		if err != nil {
			return fmt.Errorf("encoding public key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		if err := os.WriteFile(*pubOut, pemBytes, 0o644); err != nil {
			return fmt.Errorf("writing -pub-out: %w", err)
		}
		fmt.Printf("  Public key written to %s\n", *pubOut)
	}
	fmt.Fprintf(os.Stderr, "\nAdd this agent to your config:\n  secret:\n    escrow:\n      agents:\n        - id: %q\n          key_label: %q\n", *label, *label)
	return nil
}

// cmdRecover runs an escrow recovery ceremony: a quorum of recovery agents each
// unwrap their share (on the HSM), the shares reconstruct the data key, and the
// envelope is decrypted. Every recovery is logged to the tamper-evident audit
// log, including denials when the quorum is not met.
func cmdRecover(cfg *config.Config, provider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	in := fs.String("in", "-", "input envelope file, or '-' for stdin")
	out := fs.String("out", "-", "output plaintext file, or '-' for stdout")
	context_ := fs.String("context", "", "encryption context that was bound at encryption time")
	operator := fs.String("operator", "", "operator identity recorded in the audit log (default: OS user)")
	var agents multiFlag
	fs.Var(&agents, "agent", "recovery-agent id contributing to the quorum (repeat for each agent)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(agents) == 0 {
		return fmt.Errorf("at least one -agent is required; a recovery needs a quorum of recovery agents")
	}

	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	actor := operatorActor(*operator)

	blob, err := readInput(*in)
	if err != nil {
		return fmt.Errorf("reading envelope: %w", err)
	}
	env, err := secret.Unmarshal(blob)
	if err != nil {
		return err
	}
	if env.Escrow == nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretRecover, env.KEKLabel, audit.ResultError, "envelope has no key escrow")
		return fmt.Errorf("this envelope has no key escrow; recovery is not possible")
	}

	target := env.KEKLabel
	agentList := strings.Join([]string(agents), ",")
	detail := fmt.Sprintf("threshold=%d agents=[%s] escrowed_to=[%s]",
		env.Escrow.Threshold, agentList, strings.Join(env.Escrow.AgentIDs(), ","))

	// Enforce the quorum before any HSM work so a sub-quorum attempt is denied and
	// audited rather than partially executed.
	if len(agents) < env.Escrow.Threshold {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretRecover, target, audit.ResultDenied,
			"quorum not met: "+detail)
		return fmt.Errorf("recovery quorum not met: %d agent(s) supplied but %d required (dual control)",
			len(agents), env.Escrow.Threshold)
	}

	rs, err := secret.NewRecoveryService(provider)
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretRecover, target, audit.ResultError, err.Error())
		return err
	}
	plaintext, err := rs.Recover(context.Background(), env, []string(agents), []byte(*context_))
	if err != nil {
		_ = recordEscrowEvent(db, actor, audit.ActionSecretRecover, target, audit.ResultError, detail+" error="+err.Error())
		return err
	}
	defer zero(plaintext)

	if err := recordEscrowEvent(db, actor, audit.ActionSecretRecover, target, audit.ResultSuccess, detail); err != nil {
		return fmt.Errorf("recovery succeeded but recording the audit event failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Recovery OK: %d-of-%d quorum met by agents [%s]; result logged to the audit chain.\n",
		env.Escrow.Threshold, len(env.Escrow.Shares), agentList)
	return writeOutput(*out, plaintext)
}

// cmdSecretAudit shows escrow and recovery events from the tamper-evident audit
// log and can verify the hash chain end-to-end.
func cmdSecretAudit(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	verify := fs.Bool("verify", false, "verify the audit hash chain end-to-end")
	limit := fs.Int("limit", 50, "maximum number of events to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openAuditDB(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	if *verify {
		res, err := db.VerifyEventChain()
		if err != nil {
			return fmt.Errorf("verifying audit chain: %w", err)
		}
		if res.Valid {
			fmt.Printf("audit chain OK: %d event(s) verified, hash chain intact.\n", res.Count)
			return nil
		}
		fmt.Printf("audit chain BROKEN at seq %d: %s\n", res.BrokenAtSeq, res.Reason)
		return fmt.Errorf("audit chain verification failed at seq %d", res.BrokenAtSeq)
	}

	var events []audit.Event
	for _, action := range []string{audit.ActionSecretEscrow, audit.ActionSecretRecover} {
		evs, _, err := db.ListEvents(action, "", "", *limit, 0)
		if err != nil {
			return fmt.Errorf("listing %s events: %w", action, err)
		}
		events = append(events, evs...)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Seq > events[j].Seq })
	if len(events) > *limit {
		events = events[:*limit]
	}
	if len(events) == 0 {
		fmt.Println("No escrow or recovery events recorded yet.")
		return nil
	}
	fmt.Printf("%-6s %-20s %-16s %-9s %-16s %s\n", "SEQ", "TIMESTAMP", "ACTION", "RESULT", "ACTOR", "DETAIL")
	for _, e := range events {
		fmt.Printf("%-6d %-20s %-16s %-9s %-16s %s\n",
			e.Seq, e.Timestamp.Format(time.RFC3339), e.Action, e.Result, e.Actor, e.Detail)
	}
	return nil
}

// multiFlag collects a repeated string flag (e.g. -agent a -agent b).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
