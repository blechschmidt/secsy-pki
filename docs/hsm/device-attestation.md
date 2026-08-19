# YubiHSM device attestation

Proving that the hardware in the slot is a genuine YubiHSM with the serial
number it claims — and getting that serial number from Yubico rather than from
the operator.

This is the foundation the other two YubiHSM guarantees stand on, and until you
have checked it they are assumptions:

| | Question | Rests on |
|---|---|---|
| [Device attestation](device-attestation.md) | *Is this a real YubiHSM, and which one?* | Yubico's published attestation CA |
| [Key attestation](key-attestation.md) | What is the key? | The device's assertions — trustworthy only if the device is |
| [Audit log](audit-log.md) | What did the device do? | The same |

```console
$ secsy-ca hsm-attest device
Device serial:    31650425
Firmware:         2.4.0
Certificate:      YubiHSM Attestation (31650425)
Issuing CA:       Yubico YubiHSM 6742036 Sub-CA
Trust anchor:     Yubico YubiHSM Root CA

Yubico-certified: yes
Answered challenge: yes (challenge 7b1c9f0a…, object 0xfa00)
Device reports:   31650425 (agrees with its certificate)

verified: this is YubiHSM serial 31650425 — its attestation key answered the
challenge and its certificate chains to "Yubico YubiHSM Root CA"
```

Exit status is 0 when the device authenticates and 1 when it does not, so this
works as a commissioning gate or a periodic check in a pipeline.

## What is actually being proven

A YubiHSM ships with an attestation key whose certificate sits in opaque object
`0x0000`. That certificate is signed by a Yubico sub-CA, chains to Yubico's
published root, and carries the device's serial number in a Yubico-signed
extension (`1.3.6.1.4.1.41482.4.2`). Reading it and verifying the chain proves
that **a** genuine YubiHSM with that serial exists.

It does not prove that the thing answering is that device. The certificate is
public: it is handed out on request and it accompanies every attestation the
device has ever produced. Anything that can replay bytes can serve a copy. Chain
verification alone therefore authenticates a *certificate*, which is the same
reason a TLS server has to prove possession of its private key instead of merely
presenting one.

So the command is a challenge-response. It picks a nonce, makes the device sign
something covering that nonce with the attestation key, and checks the result
against the device certificate. Only a device holding that private key can
answer, and a recorded answer to one nonce is worthless against the next.

### Getting a nonce into an attestation signature

The YubiHSM will not sign a caller-supplied blob with its attestation key: the
factory key holds `sign-attestation-certificate` and nothing else. The only
channel from host to attestation signature is the **label** of an attested
object, which is host-supplied at key generation.

Answering a challenge therefore means:

1. generate a throwaway ECP256 key, with **no capabilities at all**, in the
   reserved slot `0xfa00`, labelled `da1:` + a base64url digest of the challenge;
2. attest it with the factory attestation key;
3. read the device attestation certificate;
4. delete the throwaway key.

All four share one session, so nothing can be swapped between them. The
resulting certificate says *YubiHSM serial N attested an object labelled H*,
signed by a key that has never left genuine Yubico hardware — and H is a value
the device could not have predicted.

This is the same primitive the [audit log](audit-log.md) uses to bind a log head
to a device serial, read in the other direction: there the label is the payload
and the serial is the evidence; here the nonce is the evidence and the serial is
the payload.

**It costs three force-audited device-log entries** (generate, attest, delete)
out of the 62-entry ring, and the command drains the log on its way out like any
other CLI command that reaches the HSM.

## Checking a device on someone else's behalf

The nonce is what makes the result transferable. An auditor who supplies their
own challenge gets a statement that could not have been prepared in advance:

```console
# the auditor picks a nonce and sends it
$ CHALLENGE=$(openssl rand -hex 16)

# the operator runs, on the machine holding the device
$ secsy-ca hsm-attest device -challenge "$CHALLENGE" -out device.json

# the auditor verifies, with no device, no database and no config
$ secsy-ca hsm-attest verify -file device.json -expect-challenge "$CHALLENGE"
```

`verify` recognises a device attestation by the `kind` field the bundle carries
and checks it as one. Without `-expect-challenge` a bundle still proves
possession — but at some unspecified time, which is exactly the gap the nonce
closes.

The bundle contains certificates rather than conclusions, so every claim in the
report is re-derived by the verifier instead of being taken from the producer.

## Options

| Flag | Effect |
|---|---|
| `-challenge STRING` | Nonce the device must answer. Default: a fresh random 128-bit one. |
| `-no-challenge` | Read and check the device certificate only. Read-only, and a strictly weaker claim. |
| `-expect-serial SERIAL` | Fail unless the device turns out to be this one. |
| `-object-id ID` | Reserved slot for the challenge key (default `0xfa00`, range `0xfa00`–`0xfaff`). |
| `-roots FILE` | PEM trust anchors. Default: Yubico's published roots, embedded. |
| `-out FILE` | Write the bundle as JSON for offline or third-party verification. |
| `-pem FILE` | Write the certificates as PEM. |
| `-json` | Emit the full machine-readable verdict. |

### `-no-challenge`

The passive form writes nothing to the device — no key generation, no deletion,
no audit-log entries — which is the right choice when the device must not be
touched. It is honest about establishing less:

```
verified with findings: a genuine YubiHSM with serial 31650425 was certified by
"Yubico YubiHSM Root CA", but no challenge was answered, so this does not
establish that the device examined is that one
```

Verifying such a bundle needs `-allow-no-challenge`, so accepting the weaker
claim is a decision on both sides rather than a default nobody noticed.

## What verification checks

1. **The certificate parses and names a device** — the Yubico serial extension
   is present and decodes. A certificate that names no device cannot
   authenticate one.
2. **Its two halves agree** — the subject (`YubiHSM Attestation (31650425)`) and
   the signed serial extension name the same device. They cannot disagree on
   genuine hardware; that shape is what a hand-edited certificate has.
3. **Yubico certified it** — the device certificate chains to a trusted
   attestation root. Without this anyone can mint a certificate asserting
   whatever serial they like *and answer challenges with it*, so it is required
   by default.
4. **The device answered the challenge** — the challenge certificate's signature
   verifies against the device certificate, and the label it attests is the
   digest of this challenge.
5. **One device, not two** — the serial the challenge certificate asserts equals
   the serial the device certificate is issued to.
6. **The device agrees about itself** — the serial read over the authenticated
   SCP03 session equals the certified one. A difference means the certificate in
   opaque object 0 was not issued to the device serving it.
7. **It is the expected device** — when `-expect-serial` is given.

Two findings are reported without failing the verdict, because both have
legitimate causes:

- **Firmware disagreement.** The device certificate's firmware extension records
  what was running when the certificate was issued *at the factory*; the
  challenge certificate reports what is running *now*. A firmware update makes
  them differ. The report shows both, and calls the running one the firmware.
- **An irregular challenge key** — one created outside the reserved range or
  holding capabilities. The proof of possession still holds; what suffers is the
  attributability of the device-log entries it left behind.

## Trust anchors

secsy-pki embeds both of Yubico's attestation PKIs, so stock hardware
authenticates with no configuration:

| PKI | Root | Covers |
| --- | --- | --- |
| YubiHSM 2 device attestation | `Yubico YubiHSM Root CA` | A YubiHSM 2's pre-loaded certificate in opaque object 0 |
| Unified Yubico device attestation | `Yubico Attestation Root 1` | The YubiKey family, plus a `YubiHSM Attestation B2 1` branch |

Yubico publishes each YubiHSM 2 sub-CA individually, named after its subject key
identifier in uppercase hex, and a device certificate names its issuer by exactly
that value — so a device whose sub-CA postdates your binary is a one-file fix
and the error says which file:

```
device attestation certificate "YubiHSM Attestation (…)" does not chain to a
trusted attestation root …; if this is genuine hardware its issuing sub-CA
"Yubico YubiHSM <n> Sub-CA" is published at
https://developers.yubico.com/YubiHSM2/Concepts/<AKI>.pem — fetch it and pass it
with -roots
```

Fetching it over the network is safe: it is signed by an embedded root, so a
hostile server can serve a bad file but not one that verifies. Configuration is
shared with key attestation — `yubihsm.attestation_root_files` and
`yubihsm.attestation_require_anchored_chain` — because the two answer different
questions about the same PKI.

Turn anchoring off only for a device whose factory attestation key has been
replaced with an owner-generated one, where no Yubico chain exists by
construction. Such a device can still prove possession; it just cannot prove it
is a YubiHSM.

## Testing

The verification logic is covered by hermetic unit tests over a synthetic
attestation PKI (`internal/hsmattest/device_test.go`), which is where the
adversarial cases live: a replayed answer, an answer signed by another key, an
impostor's self-signed device certificate, a bundle whose two halves name
different devices. Two of those tests run against the device certificate captured
from real hardware and the *actual* embedded Yubico roots, so a mistake in which
certificates are trusted fails without a device attached.

Hardware validation is [tier 3b of the YubiHSM suite](hardware-test-suite.md):

```console
$ SECSY_YUBIHSM_TESTS=1 go test -tags sqlite -p 1 -count=1 ./internal/yubihsmtest/ -run Device -v
```

It authenticates the attached device against Yubico's published CA, checks that
two challenges produce two different answers and that neither satisfies the
other, and asserts that the throwaway key is gone when the command returns.

---

↩ Back to [HSM & key management](README.md) · [documentation map](../README.md)
