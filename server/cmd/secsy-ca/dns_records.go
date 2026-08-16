package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/cliout"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/dnsrecords"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// cmdDNSRecords generates DANE TLSA (RFC 6698) and SSHFP (RFC 4255) DNS pinning
// records for material this PKI issues, in zone-file presentation format. It is
// read-only public-key material — no HSM/key provider is required — so an
// operator can mint records during an HSM outage.
func cmdDNSRecords(db *database.DB, args []string) error {
	if len(args) == 0 {
		dnsRecordsUsage()
		return fmt.Errorf("dns-records: no subcommand given")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "tlsa":
		return cmdDNSRecordsTLSA(db, rest)
	case "sshfp":
		return cmdDNSRecordsSSHFP(db, rest)
	case "help", "-h", "--help":
		dnsRecordsUsage()
		return nil
	default:
		dnsRecordsUsage()
		return fmt.Errorf("dns-records: unknown subcommand %q", sub)
	}
}

func dnsRecordsUsage() {
	fmt.Fprint(os.Stderr, `Usage: secsy-ca dns-records <tlsa|sshfp> [flags]

Generate DNS pinning records in zone-file presentation format.

  tlsa   DANE TLSA records (RFC 6698) for a TLS service:
           - the leaf certificate     (usage DANE-EE 3), when -serial is given
           - the issuing CA            (usages PKIX-CA 0 and DANE-TA 2)
         across selector 0/1 (full cert / SubjectPublicKeyInfo) and matching
         type 1 (SHA-256) and 0 (verbatim).

           secsy-ca dns-records tlsa -ca <id|label> -host host.example.com [-port 443] [-serial <leaf>]

  sshfp  SSHFP records (RFC 4255) for an SSH host key or an sshca-signed host
         certificate, covering fingerprint types 1 (SHA-1) and 2 (SHA-256).

           secsy-ca dns-records sshfp -host host.example.com -key /etc/ssh/ssh_host_ed25519_key.pub
           secsy-ca dns-records sshfp -ssh-ca <id|label> -serial <n> [-host host.example.com]

Add -json to any subcommand to emit the structured records plus the zone text.
`)
}

// cmdDNSRecordsTLSA emits DANE TLSA records for a CA (and optionally a leaf it
// issued) served at a host:port.
func cmdDNSRecordsTLSA(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("dns-records tlsa", flag.ContinueOnError)
	caRef := fs.String("ca", "", "issuing CA id or label (required)")
	serial := fs.String("serial", "", "leaf certificate serial issued by -ca (optional; adds DANE-EE records)")
	host := fs.String("host", "", "service hostname the records are published under (required)")
	port := fs.Int("port", 443, "TLS service port")
	protocol := fs.String("protocol", "tcp", "transport protocol (tcp|udp)")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}
	if *caRef == "" || *host == "" {
		fs.Usage()
		return fmt.Errorf("-ca and -host are required")
	}
	if *port <= 0 || *port > 65535 {
		return fmt.Errorf("invalid -port %d", *port)
	}

	caID, err := resolveCA(db, *caRef)
	if err != nil {
		return err
	}
	caModel, err := db.GetCA(caID)
	if err != nil {
		return fmt.Errorf("looking up CA: %w", err)
	}
	if caModel == nil || strings.TrimSpace(caModel.Certificate) == "" {
		return fmt.Errorf("CA %q has no certificate on record", *caRef)
	}
	caCert, err := pki.ParseCertificatePEM([]byte(caModel.Certificate))
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	owner := dnsrecords.TLSAOwnerName(*host, *port, *protocol)

	var tlsa []dnsrecords.TLSARecord
	if *serial != "" {
		leafModel, err := db.GetIssuedCertificate(caID, *serial)
		if err != nil {
			return fmt.Errorf("looking up leaf certificate: %w", err)
		}
		if leafModel == nil {
			return fmt.Errorf("no certificate with serial %s issued by CA %q", *serial, *caRef)
		}
		leafCert, err := pki.ParseCertificatePEM([]byte(leafModel.Certificate))
		if err != nil {
			return fmt.Errorf("parsing leaf certificate: %w", err)
		}
		leafRecs, err := dnsrecords.LeafTLSARecords(owner, leafCert)
		if err != nil {
			return err
		}
		tlsa = append(tlsa, leafRecs...)
	}
	issuerRecs, err := dnsrecords.IssuerTLSARecords(owner, caCert)
	if err != nil {
		return err
	}
	tlsa = append(tlsa, issuerRecs...)

	return emitDNSRecords(dnsrecords.NewBundle(tlsa, nil), asJSON)
}

// cmdDNSRecordsSSHFP emits SSHFP records for a raw SSH host key or an
// sshca-signed host certificate.
func cmdDNSRecordsSSHFP(db *database.DB, args []string) error {
	fs := flag.NewFlagSet("dns-records sshfp", flag.ContinueOnError)
	host := fs.String("host", "", "hostname the records are published under (defaults to the cert's first principal)")
	keyPath := fs.String("key", "", "path to an SSH public key or certificate in authorized_keys format ('-' for stdin)")
	caRef := fs.String("ssh-ca", "", "SSH CA id or label holding the stored host certificate (with -serial)")
	serial := fs.String("serial", "", "serial of the stored SSH host certificate (with -ssh-ca)")
	out := cliout.Register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	asJSON, err := out.JSON()
	if err != nil {
		return err
	}

	usingKey := *keyPath != ""
	usingStored := *caRef != "" || *serial != ""
	switch {
	case usingKey && usingStored:
		return fmt.Errorf("give either -key or (-ssh-ca and -serial), not both")
	case usingStored && (*caRef == "" || *serial == ""):
		return fmt.Errorf("-ssh-ca and -serial must be given together")
	case !usingKey && !usingStored:
		fs.Usage()
		return fmt.Errorf("one of -key or (-ssh-ca and -serial) is required")
	}

	hostName := strings.TrimSpace(*host)
	var authorizedKey []byte
	if usingKey {
		data, err := readInput(*keyPath)
		if err != nil {
			return fmt.Errorf("reading SSH public key: %w", err)
		}
		authorizedKey = data
	} else {
		caID, err := resolveCA(db, *caRef)
		if err != nil {
			return err
		}
		certModel, err := db.GetSSHCertificate(caID, *serial)
		if err != nil {
			return fmt.Errorf("looking up SSH certificate: %w", err)
		}
		if certModel == nil {
			return fmt.Errorf("no SSH certificate with serial %s under CA %q", *serial, *caRef)
		}
		if certModel.CertType != "host" {
			return fmt.Errorf("SSH certificate %s is a %s certificate; SSHFP records apply to host keys", *serial, certModel.CertType)
		}
		authorizedKey = []byte(certModel.Certificate)
		if hostName == "" && len(certModel.Principals) > 0 {
			hostName = certModel.Principals[0]
		}
	}

	if hostName == "" {
		return fmt.Errorf("-host is required (the stored certificate carried no principal to default from)")
	}

	key, err := dnsrecords.ParseSSHPublicKey(authorizedKey)
	if err != nil {
		return err
	}
	sshfp, err := dnsrecords.SSHFPRecords(hostName, key)
	if err != nil {
		return err
	}

	return emitDNSRecords(dnsrecords.NewBundle(nil, sshfp), asJSON)
}

// emitDNSRecords writes a bundle either as the plain zone-file block (default) or
// as indented JSON through the shared encoder.
func emitDNSRecords(bundle dnsrecords.Bundle, asJSON bool) error {
	if asJSON {
		return cliout.Emit(bundle)
	}
	if bundle.Zone != "" {
		fmt.Println(bundle.Zone)
	}
	return nil
}
