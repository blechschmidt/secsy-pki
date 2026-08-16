package hsmattest

// Test fixtures captured from a real YubiHSM 2, serial 31650425, firmware
// 2.4.0, attached over USB. They are real device output rather than synthesized
// DER on purpose: the encoding of the Yubico attestation extensions is not
// specified anywhere this code could be checked against, so the only meaningful
// regression test is against bytes the hardware actually produced.
//
// The attested key is an ECP256 signing key at object 0x7e57 labelled
// "hsmaudit-test", generated on-device with capability sign-ecdsa only — so it
// is non-exportable and generated-on-device, and its capability mask is
// 0x0000000000000080.

// realAttestationPEM is the per-key attestation certificate for object 0x7e57.
const realAttestationPEM = `-----BEGIN CERTIFICATE-----
MIICuDCCAaCgAwIBAgIQAQfJA3sSkvv9gYuzpDEwrTANBgkqhkiG9w0BAQsFADAp
MScwJQYDVQQDDB5ZdWJpSFNNIEF0dGVzdGF0aW9uICgzMTY1MDQyNSkwIBcNMTcw
MTAxMDAwMDAwWhgPMjA3MTEwMDUwMDAwMDBaMCgxJjAkBgNVBAMMHVl1YmlIU00g
QXR0ZXN0YXRpb24gaWQ6MHg3ZTU3MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
9h5qab8Bq5iEUVC8zncnCz9g33ctB9baF7ICxl+KEUMp4QB2ra95bSRf2lwAE473
Ug705nI8OEl/DCKGFGQpHqOBpTCBojATBgorBgEEAYLECgQBBAUEAwIEADAUBgor
BgEEAYLECgQCBAYCBAHi8nkwEgYKKwYBBAGCxAoEAwQEAwIAATATBgorBgEEAYLE
CgQEBAUDAwAAATAZBgorBgEEAYLECgQFBAsDCQAAAAAAAAAAgDASBgorBgEEAYLE
CgQGBAQCAn5XMB0GCisGAQQBgsQKBAkEDwwNaHNtYXVkaXQtdGVzdDANBgkqhkiG
9w0BAQsFAAOCAQEAmfpUhnBfe5sU/X8QXcCHowQmUfeQynq2iMRLFfDMJug1Yj46
4Yh1HKJsksuJr8vEvJMmIrCzEXI2EXCCKUee8ZCqK81m4z6dJBllI3qMx7BBNikx
z3JvVg/QaebxRPYinY0A/G7CyEDdOK0uFFya9aIXe+n1E+sZ3DTjmHTK5VKuqEGR
S4FZdDc6KnepxS2N/ojyHGRLxDMjMAGl6osXxKrFge+ZZE3jGELmQRdq0f7dFR8/
d0J39hj4/2v4P9VMFTmKtgQefYmnOnD/wYC+tfRFnj/Ys94Wc+WvcclodKNziPnR
f0WKW1HTSE9MPKNkmhnTvO/NH6/mUT6fnL7DpA==
-----END CERTIFICATE-----
`

// realDeviceCertPEM is the device attestation certificate read from opaque
// object 0x0000 on the same device. It issues realAttestationPEM.
const realDeviceCertPEM = `-----BEGIN CERTIFICATE-----
MIIDWDCCAkCgAwIBAgIJAMe6avTqzrZvMA0GCSqGSIb3DQEBCwUAMCgxJjAkBgNV
BAMMHVl1YmljbyBZdWJpSFNNIDY3NDIwMzYgU3ViLUNBMCAXDTE3MDEwMTAwMDAw
MFoYDzIwNzExMDA1MDAwMDAwWjApMScwJQYDVQQDDB5ZdWJpSFNNIEF0dGVzdGF0
aW9uICgzMTY1MDQyNSkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDk
gZAmFVlK3T7USxTc07lVC1iL3gUmZccAZopsQVMcS60wgI8+Gg4Lwnh9XTrjTVwr
gVJmvy811QhzFrZyHyG04xzIkI1rbZ8vLo9vGCanxoMD3+KZ0aYR8MuDeH1Ft6eW
6U6cCoGrJr2ie+A648Eoa3PTAtyvgFZbxgdBTC92nE207ICgq0pYeD6dLqJn2Vvc
WGS+Wdg26opY3pijqrw3FQAs9kmK+eLXVGQx8DhYiC6F/Nu3DwST/utE66QG9wMI
dM/mx6XWYwdA0ltxfK7D5llK64rI1uuWNsdp30sqRfVUJba5+c6O6LsDsfUU0kSQ
tIYsItvj8IIxnyDZQTb5AgMBAAGjgYEwfzATBgorBgEEAYLECgQBBAUEAwIEADAU
BgorBgEEAYLECgQCBAYCBAHi8nkwHQYDVR0OBBYEFNyOCJsY8QprJUfDOdhENgUK
LuAeMB8GA1UdIwQYMBaAFORdpfNhsJGzDY8sb6BA22/vV5GOMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggEBABrmUlQTL7qVCrCYV+P7JcQ+O58Y
mseAwPXnA9LvK5ma4HWh+FvPmqT1MCBQ5Ni4d/gW3n8ptqa0KUsQRgdyjOdnICkp
SFnF2FN8sWdSRqoXJI/0pVB0XZlpmvO76w1TOPdf2IGtO0T/p9b+1hEnyg50LbeQ
Rkl9JyGEgHp09Un06fUIAXhPMpqmm8rxnZOUwf95zZNdjTO/+5/duYB0oNkAzzWY
2n5GH/RC4vHui2d1YbJXxIMTca59ap23tNLaWBG82Y8YNzXcxvOFh1M1JXFVpxW7
oFXZ1Az2XqxvooBIxeXhRWNKhuu/T6E7b8loHWZed4nc8HVHzrjKYQT1KGo=
-----END CERTIFICATE-----
`
