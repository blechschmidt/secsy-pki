package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
)

// cmdGRPC is a gRPC client for the PKIService (Task 56). It demonstrates the
// gRPC API surface end-to-end and mirrors the REST issue/renew/revoke/status
// operations over gRPC, authenticating with the same credentials the server
// accepts (Bearer OIDC token, Basic root credentials, or a mutual-TLS client
// certificate). The default operation, "demo", generates a fresh key + CSR,
// issues a certificate, reads back its status, then revokes it — a full
// round-trip over gRPC against a running server.
func cmdGRPC(args []string) error {
	fs := flag.NewFlagSet("grpc", flag.ContinueOnError)
	addr := fs.String("addr", "localhost:9443", "gRPC server address host:port")
	operation := fs.String("operation", "demo", "operation: demo|issue|renew|revoke|suspend|release|get|status|list|crl-metadata|ocsp-metadata|stream-events")
	caID := fs.String("ca", "", "issuing CA id (required for most operations)")
	profile := fs.String("profile", "", "certificate profile (issue/renew)")
	cn := fs.String("cn", "grpc-demo.example.com", "subject common name for the generated CSR (issue/demo)")
	dns := fs.String("dns", "", "comma-separated DNS SANs for the generated CSR")
	serial := fs.String("serial", "", "certificate serial (renew/revoke/get/status)")
	reason := fs.String("reason", "unspecified", "revocation reason name (revoke/demo)")
	validityDays := fs.Int("validity-days", 0, "requested validity in days (0 = profile default)")
	csrFile := fs.String("csr", "", "path to a PEM CSR to issue/renew (default: generate one)")
	certOut := fs.String("cert-out", "", "write the issued certificate PEM to this file")

	// stream-events options (live audit/lifecycle event subscription).
	action := fs.String("action", "", "stream-events: narrow to a single audit action (e.g. cert.issue)")
	tenant := fs.String("tenant", "", "stream-events: tenant selector (platform operator narrowing / multi-tenant principal choice)")
	resumeFrom := fs.Int64("resume-from", 0, "stream-events: replay the durable event log from sequence numbers greater than this before the live tail (0 = live only)")
	heartbeat := fs.Int("heartbeat", 0, "stream-events: heartbeat interval in seconds on an idle stream (0 = server default)")
	streamJSON := fs.Bool("json", false, "stream-events: emit each frame as a single JSON line (NDJSON) instead of human-readable text")
	duration := fs.Duration("duration", 0, "stream-events: stop after this long (0 = until interrupted)")

	// Authentication (mutually exclusive; pick the one the server is configured for).
	token := fs.String("token", "", "Bearer OIDC token for authorization")
	basic := fs.String("basic", "", "Basic auth credentials as user:password (root)")
	clientCert := fs.String("client-cert", "", "PEM client certificate for mutual-TLS auth")
	clientKey := fs.String("client-key", "", "PEM client key for mutual-TLS auth")

	// Transport.
	plaintext := fs.Bool("plaintext", false, "connect over plaintext h2c (no TLS)")
	insecureTLS := fs.Bool("insecure", false, "skip TLS certificate verification (testing only)")
	caCert := fs.String("cacert", "", "PEM CA bundle to verify the server certificate")
	serverName := fs.String("servername", "", "override the TLS server name (SNI)")
	timeout := fs.Duration("timeout", 30*time.Second, "per-call timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	conn, err := dialGRPC(grpcDialOptions{
		addr:        *addr,
		plaintext:   *plaintext,
		insecureTLS: *insecureTLS,
		caCert:      *caCert,
		serverName:  *serverName,
		clientCert:  *clientCert,
		clientKey:   *clientKey,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	client := pkiv1.NewPKIServiceClient(conn)

	// appendAuth attaches the authorization metadata (Bearer/Basic) to a context.
	// It is factored out so the long-lived streaming operation can carry the same
	// credentials without a per-call deadline.
	appendAuth := func(ctx context.Context) context.Context {
		if *token != "" {
			return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+*token)
		}
		if *basic != "" {
			enc := base64.StdEncoding.EncodeToString([]byte(*basic))
			return metadata.AppendToOutgoingContext(ctx, "authorization", "Basic "+enc)
		}
		return ctx
	}
	// Build the per-call context for unary RPCs: authorization metadata + deadline.
	authCtx := func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		return appendAuth(ctx), cancel
	}

	switch strings.ToLower(*operation) {
	case "issue":
		if *caID == "" {
			return fmt.Errorf("grpc issue: -ca is required")
		}
		csrPEM, _, err := loadOrGenerateCSR(*csrFile, *cn, splitCSV(*dns))
		if err != nil {
			return err
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{
			CaId: *caID, CsrPem: csrPEM, Profile: *profile, ValidityDays: int32(*validityDays),
		})
		if err != nil {
			return fmt.Errorf("IssueCertificate: %w", err)
		}
		printIssued(resp)
		return writeCertOut(*certOut, resp.GetCertificatePem())

	case "renew":
		if *caID == "" || *serial == "" {
			return fmt.Errorf("grpc renew: -ca and -serial are required")
		}
		var csrPEM string
		if *csrFile != "" {
			b, err := os.ReadFile(*csrFile)
			if err != nil {
				return fmt.Errorf("reading -csr: %w", err)
			}
			csrPEM = string(b)
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.RenewCertificate(ctx, &pkiv1.RenewCertificateRequest{
			CaId: *caID, Serial: *serial, CsrPem: csrPEM, ValidityDays: int32(*validityDays),
		})
		if err != nil {
			return fmt.Errorf("RenewCertificate: %w", err)
		}
		printIssued(resp)
		return writeCertOut(*certOut, resp.GetCertificatePem())

	case "revoke":
		if *caID == "" || *serial == "" {
			return fmt.Errorf("grpc revoke: -ca and -serial are required")
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.RevokeCertificate(ctx, &pkiv1.RevokeCertificateRequest{
			CaId: *caID, Serial: *serial, Reason: *reason,
		})
		if err != nil {
			return fmt.Errorf("RevokeCertificate: %w", err)
		}
		fmt.Printf("Revocation: serial=%s status=%s\n", resp.GetSerial(), resp.GetStatus())
		return nil

	case "suspend":
		if *caID == "" || *serial == "" {
			return fmt.Errorf("grpc suspend: -ca and -serial are required")
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.SuspendCertificate(ctx, &pkiv1.SuspendCertificateRequest{CaId: *caID, Serial: *serial})
		if err != nil {
			return fmt.Errorf("SuspendCertificate: %w", err)
		}
		fmt.Printf("Suspend: serial=%s status=%s\n", resp.GetSerial(), resp.GetStatus())
		return nil

	case "release":
		if *caID == "" || *serial == "" {
			return fmt.Errorf("grpc release: -ca and -serial are required")
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.ReleaseCertificate(ctx, &pkiv1.ReleaseCertificateRequest{CaId: *caID, Serial: *serial})
		if err != nil {
			return fmt.Errorf("ReleaseCertificate: %w", err)
		}
		fmt.Printf("Release: serial=%s status=%s\n", resp.GetSerial(), resp.GetStatus())
		return nil

	case "get":
		if *caID == "" || *serial == "" {
			return fmt.Errorf("grpc get: -ca and -serial are required")
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.GetCertificate(ctx, &pkiv1.GetCertificateRequest{CaId: *caID, Serial: *serial})
		if err != nil {
			return fmt.Errorf("GetCertificate: %w", err)
		}
		printCertInfo(resp.GetCertificate())
		return nil

	case "status":
		if *caID == "" || *serial == "" {
			return fmt.Errorf("grpc status: -ca and -serial are required")
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.GetCertificateStatus(ctx, &pkiv1.GetCertificateStatusRequest{CaId: *caID, Serial: *serial})
		if err != nil {
			return fmt.Errorf("GetCertificateStatus: %w", err)
		}
		fmt.Printf("Status: %s\n", statusName(resp.GetStatus()))
		if resp.GetRevokedAt() != nil {
			fmt.Printf("  Revoked: %s (reason %d)\n", resp.GetRevokedAt().AsTime().UTC().Format(time.RFC3339), resp.GetRevocationReason())
		}
		return nil

	case "list":
		if *caID == "" {
			return fmt.Errorf("grpc list: -ca is required")
		}
		// Auto-follow the keyset pages (Task 83) so the client prints the full
		// inventory while each RPC returns a bounded page. -profile narrows the
		// listing, mirroring the REST/CLI filter surface.
		shown, cursor := 0, ""
		var total int32
		for {
			ctx, cancel := authCtx()
			resp, err := client.ListCertificates(ctx, &pkiv1.ListCertificatesRequest{
				CaId:    *caID,
				Cursor:  cursor,
				Profile: *profile,
			})
			cancel()
			if err != nil {
				return fmt.Errorf("ListCertificates: %w", err)
			}
			total = resp.GetTotal()
			for _, c := range resp.GetCertificates() {
				fmt.Printf("  serial=%s cn=%q status=%s expires=%s\n",
					c.GetSerial(), c.GetCommonName(), statusName(c.GetStatus()), c.GetNotAfter().AsTime().UTC().Format(time.RFC3339))
				shown++
			}
			if !resp.GetHasMore() {
				break
			}
			cursor = resp.GetNextCursor()
		}
		fmt.Printf("%d of %d certificate(s).\n", shown, total)
		return nil

	case "crl-metadata":
		if *caID == "" {
			return fmt.Errorf("grpc crl-metadata: -ca is required")
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.GetCRLMetadata(ctx, &pkiv1.GetCRLMetadataRequest{CaId: *caID})
		if err != nil {
			return fmt.Errorf("GetCRLMetadata: %w", err)
		}
		fmt.Printf("CRL scope=%s number=%d thisUpdate=%s nextUpdate=%s\n",
			resp.GetScope(), resp.GetCrlNumber(),
			resp.GetThisUpdate().AsTime().UTC().Format(time.RFC3339),
			resp.GetNextUpdate().AsTime().UTC().Format(time.RFC3339))
		fmt.Printf("  url=%s delta=%s shards=%d deltaAvailable=%v\n",
			resp.GetCrlUrl(), resp.GetDeltaCrlUrl(), resp.GetShardCount(), resp.GetDeltaAvailable())
		return nil

	case "ocsp-metadata":
		if *caID == "" {
			return fmt.Errorf("grpc ocsp-metadata: -ca is required")
		}
		ctx, cancel := authCtx()
		defer cancel()
		resp, err := client.GetOCSPMetadata(ctx, &pkiv1.GetOCSPMetadataRequest{CaId: *caID})
		if err != nil {
			return fmt.Errorf("GetOCSPMetadata: %w", err)
		}
		fmt.Printf("OCSP urls=%v nonce=%v delegated=%v\n", resp.GetOcspUrls(), resp.GetNonceSupported(), resp.GetDelegatedResponder())
		return nil

	case "demo":
		return grpcDemo(client, authCtx, *caID, *profile, *cn, splitCSV(*dns), int32(*validityDays), *reason)

	case "stream-events", "watch-events", "events":
		return grpcStreamEvents(client, appendAuth, streamEventsOptions{
			action:     *action,
			tenant:     *tenant,
			resumeFrom: *resumeFrom,
			heartbeat:  int32(*heartbeat),
			asJSON:     *streamJSON,
			duration:   *duration,
		})

	default:
		return fmt.Errorf("grpc: unknown -operation %q", *operation)
	}
}

type streamEventsOptions struct {
	action     string
	tenant     string
	resumeFrom int64
	heartbeat  int32
	asJSON     bool
	duration   time.Duration
}

// grpcStreamEvents subscribes to the live audit/lifecycle event feed over the
// StreamEvents server-streaming RPC — the gRPC peer of the REST SSE endpoint —
// and prints each frame (event, heartbeat, or lag) until the deadline elapses,
// the caller interrupts (Ctrl-C), or the server closes the stream. With
// -resume-from it first replays the durable log from that sequence cursor.
func grpcStreamEvents(client pkiv1.PKIServiceClient, appendAuth func(context.Context) context.Context, o streamEventsOptions) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if o.duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.duration)
		defer cancel()
	}
	// Cancel cleanly on Ctrl-C / SIGTERM so the stream tears down and the server
	// unsubscribes promptly rather than leaking the subscription until timeout.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		select {
		case <-sig:
			cancel()
		case <-ctx.Done():
		}
	}()

	stream, err := client.StreamEvents(appendAuth(ctx), &pkiv1.StreamEventsRequest{
		Action:           o.action,
		Tenant:           o.tenant,
		ResumeFromSeq:    o.resumeFrom,
		HeartbeatSeconds: o.heartbeat,
	})
	if err != nil {
		return fmt.Errorf("StreamEvents: %w", err)
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			// A clean end: server closed the stream (EOF) or we cancelled locally
			// (deadline reached or interrupted).
			if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("stream recv: %w", err)
		}
		printEventFrame(msg, o.asJSON)
	}
}

// printEventFrame renders one stream frame. In JSON mode it emits the canonical
// protojson of the frame (one object per line, NDJSON); otherwise it prints a
// compact human-readable line per event, heartbeat, or lag notice.
func printEventFrame(msg *pkiv1.StreamEventsResponse, asJSON bool) {
	if asJSON {
		if b, err := protojson.Marshal(msg); err == nil {
			fmt.Println(string(b))
		}
		return
	}
	switch p := msg.GetPayload().(type) {
	case *pkiv1.StreamEventsResponse_Event:
		e := p.Event
		fmt.Printf("[%s] #%d %s actor=%s tenant=%s target=%s result=%s%s\n",
			e.GetTimestamp().AsTime().UTC().Format(time.RFC3339), e.GetSeq(), e.GetAction(),
			e.GetActor(), orDash(e.GetTenant()), orDash(e.GetTarget()), e.GetResult(), detailSuffix(e.GetDetail()))
	case *pkiv1.StreamEventsResponse_Heartbeat:
		fmt.Printf(": heartbeat last_seq=%d\n", p.Heartbeat.GetLastSeq())
	case *pkiv1.StreamEventsResponse_Lag:
		fmt.Printf("! %s\n", p.Lag.GetMessage())
	}
}

func detailSuffix(detail string) string {
	if detail == "" {
		return ""
	}
	return " detail=" + detail
}

// grpcDemo runs a full issue -> status -> revoke -> status round-trip over gRPC.
func grpcDemo(client pkiv1.PKIServiceClient, authCtx func() (context.Context, context.CancelFunc), caID, profile, cn string, dns []string, validityDays int32, reason string) error {
	if caID == "" {
		return fmt.Errorf("grpc demo: -ca is required")
	}
	csrPEM, _, err := loadOrGenerateCSR("", cn, dns)
	if err != nil {
		return err
	}

	fmt.Printf("1. Issuing certificate for CN=%q under CA %s...\n", cn, caID)
	ctx1, cancel1 := authCtx()
	defer cancel1()
	issued, err := client.IssueCertificate(ctx1, &pkiv1.IssueCertificateRequest{
		CaId: caID, CsrPem: csrPEM, Profile: profile, ValidityDays: validityDays,
	})
	if err != nil {
		return fmt.Errorf("IssueCertificate: %w", err)
	}
	printIssued(issued)
	serial := issued.GetSerial()

	fmt.Printf("\n2. Reading status of serial %s...\n", serial)
	ctx2, cancel2 := authCtx()
	defer cancel2()
	st, err := client.GetCertificateStatus(ctx2, &pkiv1.GetCertificateStatusRequest{CaId: caID, Serial: serial})
	if err != nil {
		return fmt.Errorf("GetCertificateStatus: %w", err)
	}
	fmt.Printf("   status=%s\n", statusName(st.GetStatus()))

	fmt.Printf("\n3. Revoking serial %s (reason=%s)...\n", serial, reason)
	ctx3, cancel3 := authCtx()
	defer cancel3()
	rev, err := client.RevokeCertificate(ctx3, &pkiv1.RevokeCertificateRequest{CaId: caID, Serial: serial, Reason: reason})
	if err != nil {
		return fmt.Errorf("RevokeCertificate: %w", err)
	}
	fmt.Printf("   status=%s\n", rev.GetStatus())

	fmt.Printf("\n4. Re-reading status of serial %s...\n", serial)
	ctx4, cancel4 := authCtx()
	defer cancel4()
	st2, err := client.GetCertificateStatus(ctx4, &pkiv1.GetCertificateStatusRequest{CaId: caID, Serial: serial})
	if err != nil {
		return fmt.Errorf("GetCertificateStatus: %w", err)
	}
	fmt.Printf("   status=%s\n", statusName(st2.GetStatus()))
	if st2.GetStatus() != pkiv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED {
		return fmt.Errorf("demo: expected status REVOKED after revocation, got %s", statusName(st2.GetStatus()))
	}
	fmt.Printf("\nEnd-to-end gRPC issue+revoke succeeded.\n")
	return nil
}

type grpcDialOptions struct {
	addr        string
	plaintext   bool
	insecureTLS bool
	caCert      string
	serverName  string
	clientCert  string
	clientKey   string
}

// dialGRPC establishes a client connection with the requested transport
// security. It supports plaintext h2c, server-only TLS (with an optional custom
// CA bundle or verification skip), and mutual-TLS with a client certificate.
func dialGRPC(o grpcDialOptions) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if o.plaintext {
		creds = insecure.NewCredentials()
	} else {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.serverName}
		if o.insecureTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		if o.caCert != "" {
			pemBytes, err := os.ReadFile(o.caCert)
			if err != nil {
				return nil, fmt.Errorf("reading -cacert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("-cacert %q contained no certificates", o.caCert)
			}
			tlsCfg.RootCAs = pool
		}
		if o.clientCert != "" && o.clientKey != "" {
			cert, err := tls.LoadX509KeyPair(o.clientCert, o.clientKey)
			if err != nil {
				return nil, fmt.Errorf("loading client key pair: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		creds = credentials.NewTLS(tlsCfg)
	}
	conn, err := grpc.NewClient(o.addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", o.addr, err)
	}
	return conn, nil
}

// loadOrGenerateCSR returns a PEM CSR: either read from csrFile, or freshly
// generated with an ephemeral EC key for the given subject and SANs. The
// generated private key is returned so a caller may persist it, but the demo
// discards it (the certificate is revoked immediately).
func loadOrGenerateCSR(csrFile, cn string, dns []string) (csrPEM string, key *ecdsa.PrivateKey, err error) { //nolint:unparam // key is returned for API completeness so a caller can persist it; the demo callers discard it (see doc comment).
	if csrFile != "" {
		b, rerr := os.ReadFile(csrFile)
		if rerr != nil {
			return "", nil, fmt.Errorf("reading -csr: %w", rerr)
		}
		return string(b), nil, nil
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generating key: %w", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", nil, fmt.Errorf("creating CSR: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return string(pemBytes), key, nil
}

func printIssued(resp *pkiv1.CertificateResponse) {
	fmt.Printf("Issued certificate:\n")
	fmt.Printf("  Serial:  %s\n", resp.GetSerial())
	fmt.Printf("  Profile: %s\n", resp.GetProfile())
	if resp.GetNotBefore() != nil {
		fmt.Printf("  Valid:   %s .. %s\n",
			resp.GetNotBefore().AsTime().UTC().Format(time.RFC3339),
			resp.GetNotAfter().AsTime().UTC().Format(time.RFC3339))
	}
	if ct := resp.GetCt(); ct != nil && ct.GetEnabled() {
		fmt.Printf("  CT:      embedded=%v scts=%d status=%s\n", ct.GetEmbedded(), ct.GetSctCount(), ct.GetStatus())
	}
}

func printCertInfo(c *pkiv1.CertificateInfo) {
	if c == nil {
		fmt.Println("(no certificate)")
		return
	}
	fmt.Printf("Certificate:\n")
	fmt.Printf("  Serial:   %s\n", c.GetSerial())
	fmt.Printf("  Subject:  %s\n", c.GetSubject())
	fmt.Printf("  Profile:  %s\n", c.GetProfile())
	fmt.Printf("  Status:   %s\n", statusName(c.GetStatus()))
	fmt.Printf("  Valid:    %s .. %s\n",
		c.GetNotBefore().AsTime().UTC().Format(time.RFC3339),
		c.GetNotAfter().AsTime().UTC().Format(time.RFC3339))
	if c.GetCertificatePem() != "" {
		fmt.Printf("\n%s", c.GetCertificatePem())
	}
}

func writeCertOut(path, certPEM string) error {
	if path == "" {
		fmt.Printf("\n%s", certPEM)
		return nil
	}
	if err := os.WriteFile(path, []byte(certPEM), 0o644); err != nil {
		return fmt.Errorf("writing certificate: %w", err)
	}
	fmt.Printf("  Wrote certificate to %s\n", path)
	return nil
}

func statusName(s pkiv1.CertificateStatus) string {
	switch s {
	case pkiv1.CertificateStatus_CERTIFICATE_STATUS_VALID:
		return "valid"
	case pkiv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED:
		return "revoked"
	case pkiv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED:
		return "expired"
	case pkiv1.CertificateStatus_CERTIFICATE_STATUS_UNKNOWN:
		return "unknown"
	default:
		return "unspecified"
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
