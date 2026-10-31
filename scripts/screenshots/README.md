# Regenerating the documentation screenshots

```bash
make screenshots          # or: ./scripts/screenshots/capture.sh
```

Writes `docs/screenshots/*.png`, which
[the console walkthrough](../../docs/operations/console-walkthrough.md) embeds.
Takes a couple of minutes, most of it the `go build`. To retake only some of
them — every image retaken is a binary diff — name them:

```bash
CAPTURE_ONLY=07-certificates.png,17-audit.png ./scripts/screenshots/capture.sh
```

## Why this exists rather than a folder of images

The images are published, and this is a PKI: a screenshot of a working
deployment puts that deployment's certificate subjects, serial numbers, CA
labels, operator names and audit trail into the documentation. "I remembered to
blur the private ones first" is a promise every future regeneration has to keep
independently, and a serial number is not obviously sensitive until someone
correlates it with a CT log.

So the screenshots are taken of a PKI built for the purpose and destroyed
afterwards: an invented company (*Northwind Logistics GmbH*) under `.example`
names, a **SoftHSM token of its own** in a directory of its own with a
`SOFTHSM2_CONF` of its own — so a developer's real token is neither read nor
written — its own SQLite database, its own port, and a break-glass password that
exists for the length of one capture run. None of that depends on care taken at
the time; it is how the thing is wired.

What the images show is not staged either. Every certificate in them was signed
by a key generated inside that token, through the shipped `secsy-ca` CLI: the
serials are the CA's, the revocation reasons went onto a real CRL, the expiry
bands in the monitor are real remaining validity, and the audit log is a real
hash chain with a real RFC 3161 anchor over its head. The HSM key inventory
reports non-extractability because PKCS#11 was asked.

## The pieces

| File | What it is |
| --- | --- |
| `capture.sh` | the entry point: PKI up, photograph, PKI down |
| `demo-pki.sh` | builds and seeds the throwaway PKI (`up` / `down`) |
| `capture.js` | drives headless Chromium over CDP; one entry per shot |

Seeding is almost all `secsy-ca`/`secsy-secret` against the database, before the
server starts. **`seed_restrictions` is the exception** and runs *after*
`serve()`: restriction sets have no CLI, so the only way to create one is the
REST API, which needs a listener. Anything else that is console-and-API-only
has to go in the same place.

## Requirements

Chromium or Chrome, `node`, `softhsm2`, `openssl`, `ssh-keygen` and a Go
toolchain. `CHROME=/path/to/chrome` overrides the browser search.

Not wired into CI on purpose: screenshots that regenerate on every push are a
binary diff on every push.

## Adding or changing a shot

Add an entry to `SHOTS` in `capture.js`. A shot names the file, the JS that puts
the page into the state worth photographing, a predicate that has to be true
before the shutter, and what to frame.

The console is a vanilla-JS SPA whose view switcher and loaders are plain
globals, so a shot's `setup` drives them directly — `switchView('certs')`,
`loadCerts()`. Four helpers are injected for the rest: `shotSet` fills a field
and fires the events the SPA's live validation listens for, `shotPick` selects
an `<option>` by visible text, `shotClick` presses a button, and `shotPanel`
finds one of the console's many unnamed panels by its heading.

Keep the PKI up while you work on a shot:

```bash
KEEP_DEMO=1 ./scripts/screenshots/capture.sh   # leaves it running at :9443
./scripts/screenshots/demo-pki.sh down         # when you are done
```

Prefer `clipTo` over `maxHeight` when there is a natural boundary: `clipTo` cuts
where a named element begins, so the crop still lands between the same two
panels after somebody adds a field to the one above it.

Then update the prose.
[`docs/operations/console-walkthrough.md`](../../docs/operations/console-walkthrough.md)
describes these images in its alt text, and alt text that no longer matches the
picture is worse than none — it is the version screen readers get.
