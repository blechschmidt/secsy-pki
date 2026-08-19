// Package yubihsmtest is the YubiHSM 2 hardware conformance suite.
//
// Every other HSM test in this repository runs against SoftHSM, which is a
// software token: it implements the PKCS#11 API but shares none of the real
// device's constraints. It has no USB transport, no SCP03 secure channel, no
// 62-slot append-only audit log, no attestation certificates, and no
// irreversible device options. Those are exactly the properties the enterprise
// claims in this codebase rest on, so they can only be validated on hardware.
//
// This package is that validation, top to bottom in one place:
//
//	driver_test.go       transport framing and the SCP03 secure channel
//	keys_test.go         on-device key lifecycle across the algorithm matrix
//	attestation_test.go  per-key attestation and its trust chain
//	device_test.go       the device itself, against Yubico's published CA
//	audit_test.go        the append-only device audit log and its digest chain
//	genesis_test.go      what a factory reset writes, and what the anchor is worth
//	pkcs11_test.go       the keyprovider/PKCS#11 layer the product signs through
//	pki_test.go          the product itself: CA, CRL, OCSP, SSH CA, TSA, secrets
//
// The tiers are deliberately ordered bottom-up: a failure in driver_test.go
// explains failures in every tier above it, so the first failing tier names the
// layer at fault.
//
// # Enabling the suite
//
// The suite is off unless SECSY_YUBIHSM_TESTS is set to 1. Without it every
// test skips, so `go test ./...` stays green on a machine with no device and
// this package costs CI nothing but a compile. It is an environment variable
// rather than a build tag so that the suite is compiled — and therefore
// type-checked and linted — on every ordinary build, which is where test rot
// is actually caught. The per-package hardware tests that predate this suite
// (internal/hsm, internal/hsmattest, internal/hsmaudit, internal/pki) stay
// behind the `yubihsm` build tag because each declares a TestMain that would
// otherwise hijack that package's SoftHSM tests.
//
// Run it with scripts/yubihsm-test.sh, or by hand:
//
//	SECSY_YUBIHSM_TESTS=1 go test -tags sqlite -p 1 -count=1 ./internal/yubihsmtest/ -v
//
// See docs/hsm/hardware-test-suite.md for the full operator guide.
//
// # What the suite will and will not do to a device
//
// It creates and deletes scratch objects in the 0x7f00–0x7f1f handle range and
// signs with them, plus the reserved device-challenge slot 0xfa00, whose range
// is fixed by the production code rather than by this suite. It does not touch
// objects outside those and does not write device options.
//
// It does, however, consume device audit-log entries. On a device with forced
// audit the log is 62 slots deep and, once full, the device refuses every
// audited operation until entries are acknowledged. A full run generates well
// over 62 audited operations, so the suite drains the log as it goes and says
// so in the test output. Acknowledged entries are gone from the device, which
// is exactly what a deployment's audit collector needs to see — so do not point
// this suite at a device whose audit log a running deployment is collecting.
// See docs/hsm/hardware-test-suite.md.
//
// Provisioning forced audit is gated on SECSY_YUBIHSM_DESTRUCTIVE=1, because a
// YubiHSM that has had force-audit set to "fixed" cannot be returned to its
// previous state without a factory reset that destroys every key on it.
//
// The genesis tier factory-resets the device several times, which is strictly
// more than that and also undoes what the audit tier just established, so it
// needs SECSY_YUBIHSM_RESET=1 on top. After a genesis run the device is at
// factory defaults.
package yubihsmtest
