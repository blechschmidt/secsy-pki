//go:build sqlite

package scep

import (
	"crypto/x509"
	"testing"
)

// TestSCEP_SMIMEEnroll proves the SCEP enrollment path honors an S/MIME
// profile (Task 66): a PKCSReq whose CSR carries an rfc822Name SAN enrolls
// under the smime profile with the address normalized and the emailProtection
// EKU, while a mailbox-less request is blocked by the pre-issuance lint gate
// (a SCEP failure CertRep, nothing issued).
func TestSCEP_SMIMEEnroll(t *testing.T) {
	_, ts, caCert := newTestServer(t, Config{
		Profile:          "smime",
		RequireChallenge: true,
		Grants:           []Grant{{Name: "mail-fleet", Challenge: "s3cr3t", Profile: "smime"}},
	})

	client := newSCEPClient(t, ts, caCert, "smime-device")
	issued, status, err := client.enroll("Mail Device", "s3cr3t", "device@MAIL.Example.COM")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if status != pkiStatusSuccess {
		t.Fatalf("pkiStatus = %q, want success", status)
	}
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
	if len(issued.EmailAddresses) != 1 || issued.EmailAddresses[0] != "device@mail.example.com" {
		t.Fatalf("SAN = %v, want the normalized [device@mail.example.com]", issued.EmailAddresses)
	}
	if len(issued.ExtKeyUsage) != 1 || issued.ExtKeyUsage[0] != x509.ExtKeyUsageEmailProtection {
		t.Fatalf("EKU = %v, want exactly emailProtection", issued.ExtKeyUsage)
	}

	// A mailbox-less CSR under the smime profile must fail the lint gate; SCEP
	// reports that as a failure CertRep rather than an issued certificate.
	failClient := newSCEPClient(t, ts, caCert, "smime-device-2")
	cert, status, err := failClient.enroll("No Mailbox", "s3cr3t")
	if err != nil {
		t.Fatalf("enroll transport failed: %v", err)
	}
	if cert != nil || status == pkiStatusSuccess {
		t.Fatalf("mailbox-less enrollment should fail, got status=%q cert=%v", status, cert != nil)
	}
}
