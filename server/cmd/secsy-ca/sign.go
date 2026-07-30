package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/signing"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// cmdSigningKey provisions an artifact code-signing credential (Task 60): it
// generates (or reuses) a dedicated key on the signing-role provider and issues
// its certificate through the CA manager under the lint-gated "code-signing"
// profile (EKU id-kp-codeSigning, KU digitalSignature). Unlike tsa-key, which
// hand-crafts its certificate, the signing certificate takes the ordinary
// issuance path: pre-issuance lint (and any profile gates) run, and the
// certificate is recorded for renewal/revocation like any other leaf.
//
// The emitted PEM (leaf, plus the issuer chain with -chain) is what the server
// references via signing.signers[].certificate_file; the key label via
// signing.signers[].key_label.
func cmdSigningKey(db *database.DB, mgr *ca.Manager, signingProvider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("signing-key", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	label := fs.String("label", "codesign", "provider key label for the signing key")
	keyType := fs.String("key-type", "ecdsa-p256", "signing key type (ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096)")
	cn := fs.String("cn", "", "certificate subject common name (default: the key label)")
	org := fs.String("o", "", "certificate subject organization")
	validityDays := fs.Int("validity-days", 0, "certificate validity in days (0 = profile default)")
	profile := fs.String("profile", "code-signing", "issuance profile (must carry the codeSigning EKU)")
	out := fs.String("out", "", "write the certificate PEM here (default: stdout)")
	chain := fs.Bool("chain", false, "append the issuing CA chain to the output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caRef == "" {
		fs.Usage()
		return fmt.Errorf("-ca is required")
	}

	kt, err := keyprovider.NormalizeKeyType(*keyType)
	if err != nil {
		return err
	}
	switch kt {
	case keyprovider.KeyTypeECDSAP256, keyprovider.KeyTypeECDSAP384,
		keyprovider.KeyTypeRSA2048, keyprovider.KeyTypeRSA4096:
	default:
		return fmt.Errorf("signing key must be ECDSA or RSA (got %q); the CMS signer supports those families", kt)
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}

	subjectCN := *cn
	if subjectCN == "" {
		subjectCN = *label
	}

	ctx := context.Background()
	pub, err := signingPublicKey(ctx, signingProvider, *label, kt)
	if err != nil {
		return err
	}

	// Issue through the ordinary CA path so the code-signing profile shapes the
	// certificate and the fail-closed pre-issuance lint gate runs on it.
	res, err := mgr.IssueCertificateFromTemplate(ctx, ca.TemplateIssueSpec{
		CAID:        caID,
		Subject:     pkix.Name{CommonName: subjectCN, Organization: orgSlice(*org)},
		PublicKey:   pub,
		Profile:     *profile,
		Validity:    time.Duration(*validityDays) * 24 * time.Hour,
		RequestedBy: "secsy-ca signing-key",
	})
	if err != nil {
		return fmt.Errorf("issuing signing certificate: %w", err)
	}

	// Fail loudly if the chosen profile did not produce a usable code-signing
	// certificate — the same check the server and CLI signers apply.
	if err := signing.CheckCodeSigningCert(res.Certificate); err != nil {
		return fmt.Errorf("issued certificate is not usable for code signing (profile %q): %w", *profile, err)
	}

	outPEM := append([]byte(nil), res.PEM...)
	if *chain {
		issuers, err := tsaIssuerChain(db, caID)
		if err != nil {
			return err
		}
		for _, c := range issuers {
			outPEM = append(outPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
	}

	fmt.Fprintf(os.Stderr, "Provisioned code-signing certificate: serial=%s key=%s profile=%s not_after=%s\n",
		res.Serial, *label, res.Profile, res.Certificate.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "Reference it in config under signing.signers: key_label=%q, certificate_file=<the written PEM>.\n", *label)
	return writeOutput(*out, outPEM)
}

// signingPublicKey returns the public key for the signing key label, reusing an
// existing key (idempotent certificate reissue without key rotation) or
// generating a new one on the signing-role backend.
func signingPublicKey(ctx context.Context, provider keyprovider.Provider, label, keyType string) (crypto.PublicKey, error) {
	info, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: label})
	if err == nil {
		fmt.Fprintf(os.Stderr, "Reusing existing signing key %q.\n", label)
		return info.PublicKey, nil
	}
	gen, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyType, Usage: keyprovider.KeyUsageSign})
	if err != nil {
		return nil, fmt.Errorf("generating signing key %q: %w", label, err)
	}
	return gen.PublicKey, nil
}

// cmdSign produces a CMS/PKCS#7 detached signature over a file (or a
// precomputed digest) with a signer configured under signing.signers,
// optionally embedding an RFC 3161 countersignature from the locally
// configured TSA. The signing key is used on its provider; nothing is sent to
// the server — this is the offline/pipeline counterpart of POST /api/sign.
func cmdSign(db *database.DB, cfg *config.Config, mgr *ca.Manager, signingProvider, tsaProvider keyprovider.Provider, args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	signerName := fs.String("signer", "", "configured signer name from signing.signers (required)")
	in := fs.String("in", "", "artifact file to sign")
	digestHex := fs.String("digest", "", "precomputed artifact digest (hex, in the signer's digest algorithm) instead of -in")
	out := fs.String("out", "", "signature output path (default: <in>.p7s; required with -digest unless writing to stdout with -out -)")
	format := fs.String("format", "der", "signature output format: der or pem")
	level := fs.String("level", "", "CAdES baseline level: b (signed attrs), t (+timestamp), lt (+long-term-validation material). Empty uses the signer default")
	timestamp := fs.String("timestamp", "auto", "embed an RFC 3161 countersignature: auto (signer default), yes, or no. Ignored when -level is set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *signerName == "" {
		fs.Usage()
		return fmt.Errorf("-signer is required")
	}
	if (*in == "") == (*digestHex == "") {
		return fmt.Errorf("exactly one of -in or -digest is required")
	}
	if *format != "der" && *format != "pem" {
		return fmt.Errorf("-format must be der or pem")
	}
	reqLevel, err := signing.ParseLevel(*level)
	if err != nil {
		return err
	}

	sc, err := signerFromConfig(db, cfg, *signerName)
	if err != nil {
		return err
	}

	// Resolve the effective level up front. This invocation signs exactly one
	// artifact, so — unlike the server, which must be ready for any request — the
	// TSA and revocation source are wired only when this signature needs them.
	effectiveLevel := reqLevel
	if effectiveLevel == "" {
		effectiveLevel = sc.DefaultLevel
	}
	if effectiveLevel == "" {
		// Legacy -timestamp path: derive B/T from the timestamp decision.
		needTSA := sc.TimestampByDefault
		switch *timestamp {
		case "auto":
			// Signer default applies.
		case "yes", "true":
			needTSA = true
		case "no", "false":
			needTSA = false
		default:
			return fmt.Errorf("-timestamp must be auto, yes, or no")
		}
		if needTSA {
			effectiveLevel = signing.LevelT
		} else {
			effectiveLevel = signing.LevelB
		}
	}
	req := signing.SignRequest{Signer: sc.Name, Level: effectiveLevel}

	var authority *tsa.Authority
	if effectiveLevel == signing.LevelT || effectiveLevel == signing.LevelLT {
		authority, err = buildCLITSAAuthority(db, cfg, tsaProvider)
		if err != nil {
			return fmt.Errorf("%s requires a timestamp, but the TSA is unusable: %w", effectiveLevel, err)
		}
	}

	svc, err := signing.NewService(signingProvider, authority, []signing.SignerConfig{*sc})
	if err != nil {
		return err
	}
	// CAdES-LT embeds long-term-validation material: the CA manager (over the CA
	// key provider) produces the OCSP responses / CRLs for the signer chain.
	if effectiveLevel == signing.LevelLT {
		svc.SetRevocationSource(mgr)
	}

	outPath := *out
	if *in != "" {
		content, err := os.ReadFile(*in)
		if err != nil {
			return fmt.Errorf("reading artifact: %w", err)
		}
		req.Content = content
		if outPath == "" {
			outPath = *in + ".p7s"
		}
	} else {
		digest, err := hex.DecodeString(strings.TrimSpace(*digestHex))
		if err != nil {
			return fmt.Errorf("-digest is not valid hex: %w", err)
		}
		req.Digest = digest
		if outPath == "" {
			return fmt.Errorf("-out is required with -digest")
		}
	}

	res, err := svc.Sign(context.Background(), req)
	if err != nil {
		return err
	}

	sig := res.Signature
	if *format == "pem" {
		sig = pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: sig})
	}

	fmt.Fprintf(os.Stderr, "Signed with %q (cert serial %s): level=%s digest=%s:%s\n",
		res.Signer.Name, res.Signer.Certificate.SerialNumber, res.Level, hashFlagName(res.DigestAlgorithm), hex.EncodeToString(res.ArtifactDigest))
	if res.Timestamped {
		fmt.Fprintf(os.Stderr, "RFC 3161 signature-timestamp embedded: genTime=%s serial=%s\n",
			res.TimestampGenTime.UTC().Format(time.RFC3339), res.TimestampSerial)
	}
	if res.EmbeddedCRLs > 0 || res.EmbeddedOCSPs > 0 {
		fmt.Fprintf(os.Stderr, "Long-term-validation material embedded: %d CRL(s), %d OCSP response(s)\n",
			res.EmbeddedCRLs, res.EmbeddedOCSPs)
	}
	if outPath == "-" {
		_, err := os.Stdout.Write(sig)
		return err
	}
	if err := os.WriteFile(outPath, sig, 0o644); err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s signature to %s\n", strings.ToUpper(*format), outPath)
	return nil
}

// cmdVerifySignature verifies a CMS detached signature against an artifact
// file (or its digest) and prints the verdict. Trust anchors come from -ca-file
// (offline), a single -ca (id/label) from the store, or every X.509 CA in the
// store. No key provider is needed — verification is public-key only.
func cmdVerifySignature(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("verify-signature", flag.ContinueOnError)
	sigPath := fs.String("sig", "", "signature file (DER or PEM PKCS#7) (required)")
	in := fs.String("in", "", "artifact file the signature covers")
	digestHex := fs.String("digest", "", "precomputed artifact digest (hex, in the signature's digest algorithm) instead of -in")
	caRef := fs.String("ca", "", "trust only this CA (id or label) from the store")
	caFile := fs.String("ca-file", "", "trust the CA certificate(s) in this PEM file instead of the store")
	requireTimestamp := fs.Bool("require-timestamp", false, "fail unless a valid RFC 3161 countersignature is embedded")
	requireLevel := fs.String("require-level", "", "fail unless the signature achieves at least this CAdES level (b|t|lt)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sigPath == "" {
		fs.Usage()
		return fmt.Errorf("-sig is required")
	}
	if (*in == "") == (*digestHex == "") {
		return fmt.Errorf("exactly one of -in or -digest is required")
	}
	reqLevel, err := signing.ParseLevel(*requireLevel)
	if err != nil {
		return err
	}

	sigRaw, err := os.ReadFile(*sigPath)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}
	sigDER := sigRaw
	if block, _ := pem.Decode(sigRaw); block != nil {
		sigDER = block.Bytes
	}

	roots, err := verifyTrustAnchors(db, *caRef, *caFile)
	if err != nil {
		return err
	}
	if len(roots) == 0 {
		return fmt.Errorf("no trust anchors: pass -ca/-ca-file or store a CA first")
	}

	req := signing.VerifyRequest{Signature: sigDER, Roots: roots, RequireTimestamp: *requireTimestamp, RequireLevel: reqLevel}
	if *in != "" {
		content, err := os.ReadFile(*in)
		if err != nil {
			return fmt.Errorf("reading artifact: %w", err)
		}
		req.Content = content
	} else {
		digest, err := hex.DecodeString(strings.TrimSpace(*digestHex))
		if err != nil {
			return fmt.Errorf("-digest is not valid hex: %w", err)
		}
		req.Digest = digest
	}

	res, err := signing.Verify(req)
	if err != nil {
		fmt.Printf("INVALID: %v\n", err)
		return fmt.Errorf("signature verification failed")
	}

	fmt.Printf("Verification: OK\n")
	fmt.Printf("  Signer:    %s (serial %s)\n", res.SignerCertificate.Subject, res.SignerCertificate.SerialNumber)
	fmt.Printf("  CAdES:     %s\n", res.Level)
	fmt.Printf("  Digest:    %s:%s\n", hashFlagName(res.DigestAlgorithm), hex.EncodeToString(res.ArtifactDigest))
	fmt.Printf("  Chain:     %d certificate(s) to trusted root %q\n", len(res.Chain), res.Chain[len(res.Chain)-1].Subject.CommonName)
	if res.Timestamped {
		fmt.Printf("  Timestamp: %s (token serial %s, TSA %q)\n",
			res.TimestampGenTime.UTC().Format(time.RFC3339), res.TimestampSerial, res.TSACertificate.Subject.CommonName)
	} else {
		fmt.Printf("  Timestamp: none\n")
	}
	if res.RevocationCRLs > 0 || res.RevocationOCSPs > 0 {
		fmt.Printf("  Revocation material: %d CRL(s), %d OCSP response(s)\n", res.RevocationCRLs, res.RevocationOCSPs)
	}
	fmt.Printf("  Validity evaluated at: %s\n", res.VerifiedAt.UTC().Format(time.RFC3339))
	return nil
}

// signerFromConfig materializes a signing.SignerConfig from the signing.signers
// entry with the given name: the certificate (and inline chain) is loaded from
// its PEM file and completed from the store when only the leaf is present.
func signerFromConfig(db *database.DB, cfg *config.Config, name string) (*signing.SignerConfig, error) {
	var entry *config.SigningSignerConfig
	for i := range cfg.Signing.Signers {
		if cfg.Signing.Signers[i].Name == name {
			entry = &cfg.Signing.Signers[i]
			break
		}
	}
	if entry == nil {
		names := make([]string, 0, len(cfg.Signing.Signers))
		for _, s := range cfg.Signing.Signers {
			names = append(names, s.Name)
		}
		return nil, fmt.Errorf("signer %q is not configured under signing.signers (configured: %v)", name, names)
	}

	chain, err := readCertChainFile(entry.CertificateFile)
	if err != nil {
		return nil, fmt.Errorf("signer %q: %w", name, err)
	}
	if len(chain) == 1 && (entry.CAID != "" || entry.CALabel != "") {
		ref := entry.CAID
		if ref == "" {
			ref = entry.CALabel
		}
		caID, err := resolveCA(db, ref)
		if err != nil {
			return nil, fmt.Errorf("signer %q: %w", name, err)
		}
		issuers, err := tsaIssuerChain(db, caID)
		if err != nil {
			return nil, fmt.Errorf("signer %q: %w", name, err)
		}
		chain = append(chain, issuers...)
	}

	return &signing.SignerConfig{
		Name:               entry.Name,
		KeyLabel:           entry.KeyLabel,
		Certificate:        chain[0],
		Chain:              chain,
		Digest:             hashFromFlagName(entry.Digest),
		TimestampByDefault: entry.Timestamp,
		TenantID:           entry.Tenant,
	}, nil
}

// buildCLITSAAuthority assembles the in-process RFC 3161 authority from the
// tsa: config block, mirroring the server's wiring (certificate file + chain
// completion, policy OID, accuracy, signature digest). It works regardless of
// tsa.enabled — that flag only controls the public /tsa HTTP endpoint.
func buildCLITSAAuthority(db *database.DB, cfg *config.Config, provider keyprovider.Provider) (*tsa.Authority, error) {
	if cfg.TSA.KeyLabel == "" || cfg.TSA.CertificateFile == "" {
		return nil, fmt.Errorf("configure tsa.key_label and tsa.certificate_file (provision with `secsy-ca tsa-key`)")
	}
	chain, err := readCertChainFile(cfg.TSA.CertificateFile)
	if err != nil {
		return nil, err
	}
	if len(chain) == 1 && (cfg.TSA.CAID != "" || cfg.TSA.CALabel != "") {
		ref := cfg.TSA.CAID
		if ref == "" {
			ref = cfg.TSA.CALabel
		}
		caID, err := resolveCA(db, ref)
		if err != nil {
			return nil, err
		}
		issuers, err := tsaIssuerChain(db, caID)
		if err != nil {
			return nil, err
		}
		chain = append(chain, issuers...)
	}
	tc := tsa.Config{
		KeyLabel:        cfg.TSA.KeyLabel,
		Certificate:     chain[0],
		Chain:           chain,
		Accuracy:        tsa.Accuracy{Seconds: cfg.TSA.AccuracySeconds, Millis: cfg.TSA.AccuracyMillis, Micros: cfg.TSA.AccuracyMicros},
		Ordering:        cfg.TSA.Ordering,
		SignatureDigest: hashFromFlagName(cfg.TSA.SignatureDigest),
		IncludeTSAName:  cfg.TSA.IncludeTSAName,
	}
	if cfg.TSA.PolicyOID != "" {
		oid, err := parseDottedOIDString(cfg.TSA.PolicyOID)
		if err != nil {
			return nil, fmt.Errorf("tsa.policy_oid: %w", err)
		}
		tc.PolicyOID = oid
	}
	return tsa.New(db, provider, tc)
}

// verifyTrustAnchors loads the verification roots: the PEM file when given,
// one named CA, or every X.509 CA in the store.
func verifyTrustAnchors(db *database.DB, caRef, caFile string) ([]*x509.Certificate, error) {
	if caFile != "" {
		return readCertChainFile(caFile)
	}
	if caRef != "" {
		caID, err := resolveCA(db, caRef)
		if err != nil {
			return nil, err
		}
		return tsaIssuerChain(db, caID)
	}
	cas, err := db.ListCAs()
	if err != nil {
		return nil, err
	}
	var roots []*x509.Certificate
	for _, m := range cas {
		if m.Certificate == "" {
			continue
		}
		cert, err := pki.ParseCertificatePEM([]byte(m.Certificate))
		if err != nil {
			continue
		}
		roots = append(roots, cert)
	}
	return roots, nil
}

// readCertChainFile parses one or more concatenated PEM CERTIFICATE blocks.
func readCertChainFile(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate in %q: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%q contains no certificates", path)
	}
	return certs, nil
}

// hashFromFlagName maps a config/flag digest name to a crypto.Hash (empty =
// SHA-256, matching the signing service default).
func hashFromFlagName(name string) crypto.Hash {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	case "sha1":
		return crypto.SHA1
	default:
		return 0
	}
}

// hashFlagName is the inverse of hashFromFlagName for display.
func hashFlagName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	case crypto.SHA1:
		return "sha1"
	default:
		return h.String()
	}
}

// parseDottedOIDString parses a dotted-decimal OID like "1.3.6.1.4.1.99999.1.1".
func parseDottedOIDString(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID %q must have at least two arcs", s)
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("OID %q has an invalid arc %q", s, p)
		}
		oid = append(oid, n)
	}
	return oid, nil
}
