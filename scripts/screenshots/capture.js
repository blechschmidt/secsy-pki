// capture.js — photograph the secsy-pki operator console for the documentation.
//
// Drives real headless Chromium over CDP against the throwaway PKI that
// demo-pki.sh puts up. A real browser rather than a DOM shim because the output
// is an image: layout, fonts, the status pills and the panel borders all have to
// be the ones an operator sees, and a shim has none of them.
//
//   node capture.js <chrome-binary> <base-url> <output-dir> <demo-home>
//
// <demo-home> is the demo PKI's directory. Some shots need material to paste
// into a form — a CSR for the pre-issuance dry run, a leaf for chain validation
// — and taking it from the demo tree means the screenshot shows the product
// acting on a real certificate this PKI really issued.
//
// Each shot is declared once, below, in SHOTS. A shot says how to get the page
// into the state worth photographing (`setup`), what to wait for (`settle`), and
// what to frame (`clip`). Adding one is adding an entry.
//
// Two decisions worth knowing about:
//
//   * deviceScaleFactor 2. The images are read on high-density displays and
//     downscaled by the site's CSS anyway; capturing at 1x and letting the
//     browser upscale is the one way to make a screenshot of text look worse
//     than the text.
//   * Element clipping, not full-page. A console view is several stacked panels
//     — the Authorities view is the CA table plus six provisioning forms — and
//     a capture of the whole thing becomes an unreadable thumbnail inline in a
//     page. Framing the panel under discussion keeps the subject roughly the
//     size it is on screen.
'use strict';

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CHROME = process.argv[2];
const BASE = process.argv[3];
const OUTDIR = process.argv[4];
const DEMO = process.argv[5];

if (!CHROME || !BASE || !OUTDIR || !DEMO) {
  console.error('usage: node capture.js <chrome-binary> <base-url> <output-dir> <demo-home>');
  process.exit(2);
}

const WIDTH = 1500;
const HEIGHT = 1000;
const SCALE = 2;

// The console's break-glass operator. demo-pki.sh puts the same value in the
// demo config; it lives as long as one capture run.
const USER = 'root';
const PASS = process.env.SHOT_ROOT_PASSWORD || 'demo-console-password';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// read returns a file from the demo tree, or '' when the seeding did not get
// that far — a shot that needs it fails on its own rather than taking the whole
// run down.
function read(rel) {
  try { return fs.readFileSync(path.join(DEMO, rel), 'utf8'); } catch (_) { return ''; }
}

const PREVIEW_CSR = read('work/preview-request.csr');
const LEAF_CERT = read('work/wms.northwind.example.crt');

// js turns a value into a JS literal safe to interpolate into page source.
const js = v => JSON.stringify(v);

// ── a minimal CDP client ────────────────────────────────────────────────────

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id === undefined) return;
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      msg.error ? p.reject(new Error(msg.error.message)) : p.resolve(msg.result);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {resolve, reject});
      this.ws.send(JSON.stringify({id, method, params: params || {}}));
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 30000);
    });
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr, awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error('eval failed: ' + JSON.stringify(
        r.exceptionDetails.exception || r.exceptionDetails));
    }
    return r.result.value;
  }
  // waitFor polls a JS predicate until it is true, or throws.
  async waitFor(expr, what, timeoutMs = 20000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (await this.eval(`!!(${expr})`)) return;
      if (Date.now() > deadline) throw new Error('timed out waiting for ' + what);
      await sleep(150);
    }
  }
}

// ── page helpers, installed into the console ────────────────────────────────
//
// The console is a vanilla-JS SPA whose view switcher and loaders are plain
// globals, so a shot's setup can drive it directly. These three fill the gaps:
// a selector form for the panels that carry no id, a select-by-visible-text,
// and a field setter that fires the events the SPA's handlers listen for.

const HELPERS = `
// shotPanel finds a .panel (or .card) by its own heading text. Most of the
// console's panels have no id, and a heading is a far more stable handle than
// an nth-child path through a layout that gets fields added to it.
window.shotPanel = (text) => {
  const t = text.toLowerCase();
  for (const el of document.querySelectorAll('.view.active .panel, .view.active .card')) {
    const h = el.querySelector(':scope > h2, :scope > h3');
    if (h && h.textContent.trim().toLowerCase().startsWith(t)) return el;
  }
  return null;
};
// shotPick selects an <option> by value or visible text and notifies the SPA.
// Exact matches win over substrings, and that is not a nicety: the profile list
// is alphabetical, so a substring search for "server" finds "hybrid-server"
// first and the shot quietly photographs the wrong profile.
window.shotPick = (id, text) => {
  const sel = document.getElementById(id);
  if (!sel) return false;
  const t = String(text).toLowerCase();
  const choose = (o) => {
    sel.value = o.value;
    sel.dispatchEvent(new Event('change', {bubbles: true}));
    return true;
  };
  for (const o of sel.options) {
    if (o.value === text || o.textContent.trim().toLowerCase() === t) return choose(o);
  }
  for (const o of sel.options) {
    if (o.textContent.trim().toLowerCase().includes(t)) return choose(o);
  }
  return false;
};
// shotSet fills an input/textarea and fires input+change, which is what the
// console's live validation and policy summaries react to.
window.shotSet = (id, value) => {
  const el = document.getElementById(id);
  if (!el) return false;
  if (el.type === 'checkbox') { el.checked = !!value; }
  else { el.value = value; }
  el.dispatchEvent(new Event('input', {bubbles: true}));
  el.dispatchEvent(new Event('change', {bubbles: true}));
  return true;
};
// shotHeadingAbove returns the h2/h3 that introduces an element — its own
// previous sibling, or the previous sibling of the row that wraps it. The
// console puts side-by-side panels in a .row and the section heading before the
// row, so a frame boundary taken at the panel cuts the heading in half.
window.shotHeadingAbove = (el) => {
  let node = el;
  for (let i = 0; i < 3 && node; i++) {
    const prev = node.previousElementSibling;
    if (prev) return /^H[23]$/.test(prev.tagName) ? prev : null;
    node = node.parentElement;   // first child: the heading may be a level up
  }
  return null;
};
window.shotClick = (id) => {
  const el = document.getElementById(id);
  if (!el) return false;
  el.click();
  return true;
};
`;

// ── the shots ───────────────────────────────────────────────────────────────
//
// `setup` runs in the page and leaves it in the state to photograph. `settle` is
// a predicate that has to become true before the shutter. `clip` names what to
// frame: a CSS selector, or `panel:<heading>` for one of the console's unnamed
// panels; absent means the viewport.
//
// Two ways to shorten a frame too tall to read inline. `clipTo` cuts it where a
// named element begins — a boundary that moves with the layout, so the crop
// still lands between the same two panels after somebody adds a field to the
// one above it. `maxHeight` is the blunt one, in CSS pixels, for tables with no
// natural end.

const SHOTS = [
  {
    file: '01-sign-in.png',
    what: 'the sign-in card — what the console authenticates',
    // Shot before the login step, so this one runs against the overlay.
    preLogin: true,
    setup: `shotSet('loginUser', ${js(USER)}); shotSet('loginPass', ${js(PASS)})`,
    settle: `!document.getElementById('login').classList.contains('hidden')`,
    clip: '#login .card',
  },
  {
    file: '02-authorities.png',
    what: 'the Authorities view — the CA hierarchy',
    setup: `switchView('cas'); loadAuthorities()`,
    settle: `document.querySelectorAll('#casRows tr').length >= 4`,
    clip: '#view-cas',
    // The table and its toolbar, stopping where the provisioning forms begin.
    clipTo: `panel:Create root CA`,
  },
  {
    file: '03-create-ca.png',
    what: 'the root and intermediate creation forms, filled in',
    setup: `
      switchView('cas');
      shotSet('rootLabel', 'northwind-root-r2');
      shotSet('rootCN', 'Northwind Logistics Root CA R2');
      shotSet('rootO', 'Northwind Logistics GmbH');
      shotSet('rootDays', '7300');
      shotPick('rootKeyType', 'ecdsa-p384');
      shotSet('interLabel', 'northwind-issuing-tls-g3');
      shotSet('interCN', 'Northwind Logistics TLS Issuing CA G3');
      shotSet('interO', 'Northwind Logistics GmbH');
      shotSet('interDays', '1825');
      shotPick('interParent', 'northwind-root');
    `,
    settle: `document.getElementById('rootCN').value.length > 0`,
    clip: `panel:Create root CA`,
    // Both forms sit in one flex row; frame the row so the pair reads together.
    expandToRow: true,
  },
  {
    file: '04-hsm-key-inventory.png',
    what: 'the HSM key inventory — the non-extractability verdict',
    setup: `switchView('cas'); if (typeof loadKeyInventory === 'function') loadKeyInventory()`,
    settle: `(() => { const p = shotPanel('HSM key inventory');
             return p && p.querySelectorAll('tbody tr').length >= 3; })()`,
    clip: `panel:HSM key inventory`,
    maxHeight: 900,
  },
  {
    file: '05-issue.png',
    what: 'the Issue view — a CSR, a profile, and the profile policy summary',
    setup: `
      switchView('issue');
      shotPick('issueCA', 'northwind-issuing-tls');
      shotPick('issueProfile', 'server');
      shotSet('issueCSR', ${js(PREVIEW_CSR)});
    `,
    settle: `document.getElementById('issueProfileInfo').textContent.trim().length > 0 &&
             document.getElementById('issueCSR').value.includes('CERTIFICATE REQUEST')`,
    clip: '#view-issue > .panel',
    maxHeight: 1250,
  },
  {
    file: '06-issue-preview.png',
    what: 'the pre-issuance dry run — every gate\'s verdict, nothing signed',
    setup: `
      switchView('issue');
      shotPick('issueCA', 'northwind-issuing-tls');
      shotPick('issueProfile', 'server');
      shotSet('issueCSR', ${js(PREVIEW_CSR)});
      await new Promise(r => setTimeout(r, 300));
      shotClick('issuePreviewBtn');
    `,
    settle: `(() => {
      const box = document.getElementById('issuePreviewResult');
      if (!box || box.classList.contains('hidden')) return false;
      if (box.textContent.includes('Previewing')) return false;
      return box.querySelectorAll('table, .verdict, .notice').length > 0 ||
             box.textContent.trim().length > 80;
    })()`,
    clip: '#issuePreviewResult',
    maxHeight: 1100,
  },
  {
    file: '07-certificates.png',
    what: 'the Certificates view — the issued estate, filters and CRL freshness',
    setup: `switchView('certs'); shotPick('certCA', 'northwind-issuing-tls'); loadCerts()`,
    settle: `document.querySelectorAll('#certRows tr').length >= 8`,
    clip: '#view-certs',
    clipTo: `panel:Bulk revocation`,
    maxHeight: 1250,
  },
  {
    file: '08-bulk-revocation.png',
    what: 'bulk revocation — the dry-run preview and the typed confirmation',
    // The device CA, not the TLS one: the *.fleet names this selection is about
    // are issued there, and a dry run that matches nothing shows the mechanism
    // without showing it working.
    setup: `
      switchView('certs');
      shotPick('certCA', 'northwind-issuing-device');
      await new Promise(r => setTimeout(r, 600));
      shotSet('bulkPattern', '*.fleet.northwind.example');
      shotPick('bulkReason', 'keyCompromise');
      await new Promise(r => setTimeout(r, 200));
      shotClick('bulkPreview');
    `,
    settle: `(() => {
      const box = document.getElementById('bulkPlanBox');
      if (box.classList.contains('hidden')) return false;
      return document.querySelectorAll('#bulkSampleRows tr').length >= 2;
    })()`,
    clip: `panel:Bulk revocation`,
    maxHeight: 1150,
  },
  {
    file: '09-expiry-monitor.png',
    what: 'the Expiry Monitor — what breaks next, and when',
    setup: `switchView('monitor'); loadMonitor()`,
    settle: `document.querySelectorAll('#view-monitor tbody tr').length >= 4`,
    clip: '#view-monitor',
    maxHeight: 1100,
  },
  {
    file: '10-inventory.png',
    what: 'the cross-CA inventory and the key-compromise search',
    setup: `switchView('inventory'); loadInventory()`,
    settle: `document.querySelectorAll('#view-inventory tbody tr').length >= 8`,
    clip: '#view-inventory',
    maxHeight: 1200,
  },
  {
    file: '11-validate.png',
    what: 'chain validation — a structured verdict, nothing signed',
    setup: `
      switchView('validate');
      shotPick('validateCA', 'northwind-issuing-tls');
      shotSet('validateCert', ${js(LEAF_CERT)});
      await new Promise(r => setTimeout(r, 200));
      shotClick('validateBtn');
    `,
    settle: `document.getElementById('validateResult').textContent.trim().length > 40`,
    clip: '#view-validate',
    maxHeight: 1250,
  },
  {
    file: '12-trust-bundle.png',
    what: 'the trust bundle — what a relying party needs, and the SVID minters',
    setup: `switchView('bundle'); shotPick('bundleCA', 'northwind-issuing-tls'); loadBundle()`,
    settle: `document.querySelector('#view-bundle textarea, #view-bundle pre') !== null`,
    clip: '#view-bundle',
    clipTo: `panel:Mint an X.509-SVID`,
    maxHeight: 1100,
  },
  {
    file: '13-ssh-ca.png',
    what: 'the SSH CA — signing OpenSSH certificates from the same HSM, under a CA-level lifetime ceiling',
    setup: `switchView('ssh'); loadSSH()`,
    // The ceiling panel reads the selected CA, so wait for it to resolve too —
    // otherwise the shot can catch it on "Select an SSH CA…".
    settle: `document.querySelectorAll('#view-ssh tbody tr').length >= 2 &&
             document.getElementById('sshMaxValidityState').textContent.includes('12h')`,
    clip: '#view-ssh',
    maxHeight: 1150,
  },
  {
    file: '14-signing.png',
    what: 'artifact signing — CAdES levels and the countersigning TSA',
    setup: `switchView('signing'); loadSigning()`,
    settle: `(() => { const p = shotPanel('Configured signers');
             return p && p.textContent.includes('release-signing'); })()`,
    clip: '#view-signing',
    clipTo: `panel:Provision a code-signing credential`,
    maxHeight: 1100,
  },
  {
    file: '15-secrets.png',
    what: 'the secret layer — envelope encryption under the HSM-held KEK',
    setup: `
      switchView('secrets');
      if (typeof loadSecretsPage === 'function') loadSecretsPage();
      shotSet('encInput', 'warehouse-db password for the Rotterdam depot');
    `,
    settle: `document.getElementById('view-secrets').classList.contains('active')`,
    clip: '#view-secrets',
    clipTo: `panel:Signing keys`,
    maxHeight: 1400,
  },
  {
    file: '16-stored-secrets.png',
    what: 'the stored-secret registry — versions, rollback, rotation reminders',
    setup: `
      switchView('secrets');
      if (typeof loadStoredSecrets === 'function') loadStoredSecrets();
      if (typeof loadSecretLifecycle === 'function') loadSecretLifecycle();
    `,
    settle: `document.querySelectorAll('#storeRows tr').length >= 3`,
    clip: '#storeRows',
    clipFromPanel: true,
    withHeading: true,
    maxHeight: 1100,
  },
  {
    file: '17-audit.png',
    what: 'the audit log — hash-chain verification and the SIEM exports',
    setup: `switchView('audit'); loadAudit(); await new Promise(r => setTimeout(r, 400));
            shotClick('auditVerifyBtn')`,
    settle: `document.querySelectorAll('#auditRows tr').length >= 6 &&
             document.getElementById('auditVerify').textContent.trim().length > 10`,
    clip: '#view-audit',
    maxHeight: 1250,
  },
  {
    file: '18-access.png',
    what: 'per-CA delegation — one group administering exactly one sub-CA',
    // Pick the sub-CA the demo actually delegated. On the root — the default
    // selection — the grants table correctly reads "no grants", which is the
    // least informative thing this page can say.
    setup: `
      switchView('access');
      await new Promise(r => setTimeout(r, 600));
      shotPick('accessResource', 'northwind-issuing-device');
      if (typeof loadAccess === 'function') loadAccess();
    `,
    settle: `(() => {
      const rows = document.querySelectorAll('#accessRows tr');
      return rows.length >= 1 && !rows[0].textContent.includes('No grants');
    })()`,
    clip: '#view-access',
    clipTo: `panel:Role catalog`,
    maxHeight: 1000,
  },
  {
    file: '19-api-tokens.png',
    what: 'scoped API tokens — how automation authenticates',
    setup: `switchView('tokens'); loadTokens()`,
    settle: `document.querySelectorAll('#view-tokens tbody tr').length >= 2`,
    clip: '#view-tokens',
    maxHeight: 1000,
  },
  {
    file: '20-compliance.png',
    what: 'the compliance view — lint split, blocked issuance, audit-chain state',
    setup: `switchView('compliance'); loadCompliance()`,
    settle: `document.getElementById('view-compliance').classList.contains('active') &&
             document.querySelectorAll('#view-compliance tbody tr').length >= 3`,
    clip: '#view-compliance',
    clipTo: `panel:Lint a certificate`,
    maxHeight: 1400,
  },
  // Last by habit, not by necessity any more. loadOps() calls GET /api/doctor,
  // which builds a second PKCS#11 provider for the sweep and closes it; that
  // teardown used to log out and finalize the module for the whole process, so
  // every shot taken after this one photographed an HSM that looked empty
  // (/api/inventory/keys returned nothing, the secret KEK failed with
  // CKR_OBJECT_HANDLE_INVALID). The module and the login are now refcounted
  // across holders in pki/pool.go, so the sweep is harmless — keep the order
  // anyway: it costs nothing, and it keeps the heaviest page off the critical
  // path of the others.
  {
    file: '21-operations.png',
    what: 'the Operations view — diagnostics, DR manifest, restore drill, publishing',
    setup: `switchView('ops'); loadOps()`,
    settle: `(() => { const p = shotPanel('Preflight diagnostics');
             return p && p.querySelectorAll('tbody tr').length >= 10; })()`,
    clip: `panel:Preflight diagnostics`,
    maxHeight: 950,
  },
];

// CAPTURE_ONLY=07-certificates.png,17-audit.png retakes just those. Every image
// retaken is a binary diff, so a change to one panel should cost one image
// rather than all of them.
const ONLY = [...new Set((process.env.CAPTURE_ONLY || '').split(',').map(s => s.trim()).filter(Boolean))];
const shots = ONLY.length ? SHOTS.filter(s => ONLY.includes(s.file)) : SHOTS;
if (shots.length !== (ONLY.length || SHOTS.length)) {
  console.error('CAPTURE_ONLY names a shot that does not exist; the shots are: ' +
                SHOTS.map(s => s.file).join(', '));
  process.exit(2);
}

// ── driving it ──────────────────────────────────────────────────────────────

async function main() {
  fs.mkdirSync(OUTDIR, {recursive: true});
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'secsy-shot-'));

  const chrome = spawn(CHROME, [
    '--headless=new',
    '--remote-debugging-port=0',
    '--user-data-dir=' + profile,
    '--no-sandbox',
    '--disable-gpu',
    '--hide-scrollbars',
    // The demo server's listener certificate is issued by the demo PKI's own
    // root, which this throwaway browser profile has no reason to trust. The
    // alternative is installing a root into the profile to photograph a padlock
    // that is not in any of the frames.
    '--ignore-certificate-errors',
    '--force-device-scale-factor=' + SCALE,
    '--window-size=' + WIDTH + ',' + HEIGHT,
    // Deterministic type across machines: without this the images re-render with
    // whatever fonts the host happens to have and every regeneration is a diff.
    '--font-render-hinting=none',
    'about:blank',
  ], {stdio: ['ignore', 'ignore', 'pipe']});

  let wsURL = '';
  chrome.stderr.on('data', d => {
    const m = /ws:\/\/[^\s]+/.exec(d.toString());
    if (m && !wsURL) wsURL = m[0];
  });

  for (let i = 0; i < 200 && !wsURL; i++) await sleep(50);
  if (!wsURL) throw new Error('chrome did not report a debugging endpoint');

  const ws = new WebSocket(wsURL);
  await new Promise((res, rej) => {
    ws.addEventListener('open', res);
    ws.addEventListener('error', () => rej(new Error('cannot attach to chrome')));
  });
  const browser = new CDP(ws);

  const {targetId} = await browser.send('Target.createTarget', {url: 'about:blank'});
  const {sessionId} = await browser.send('Target.attachToTarget', {targetId, flatten: true});

  // A flat session multiplexes over the browser socket; wrap so every call
  // carries the sessionId.
  const page = new CDP(ws);
  page.send = (method, params) => {
    const id = ++browser.id;
    return new Promise((resolve, reject) => {
      browser.pending.set(id, {resolve, reject});
      ws.send(JSON.stringify({id, sessionId, method, params: params || {}}));
      setTimeout(() => {
        if (browser.pending.delete(id)) reject(new Error(method + ' timed out'));
      }, 30000);
    });
  };

  await page.send('Page.enable');
  await page.send('Runtime.enable');
  await page.send('Security.setIgnoreCertificateErrors', {ignore: true}).catch(() => {});
  await page.send('Emulation.setDeviceMetricsOverride', {
    width: WIDTH, height: HEIGHT, deviceScaleFactor: SCALE, mobile: false,
  });

  await page.send('Page.navigate', {url: BASE + '/console/'});
  await page.waitFor(`document.readyState === 'complete'`, 'document load', 30000);
  await page.waitFor(`typeof window.switchView === 'function'`, 'the console bundle', 30000);
  await page.eval(HELPERS);
  await page.waitFor(`!document.getElementById('login').classList.contains('hidden') ||
                      !document.getElementById('app').classList.contains('hidden')`,
                     'the console to decide whether it is signed in', 30000);
  await sleep(600);

  const taken = [];
  let loggedIn = false;

  const logIn = async () => {
    await page.eval(`(() => {
      shotSet('loginUser', ${js(USER)});
      shotSet('loginPass', ${js(PASS)});
      document.getElementById('loginForm')
        .dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
    })()`);
    await page.waitFor(`!document.getElementById('app').classList.contains('hidden')`,
                       'the console to sign in', 30000);
    // loadCAs() populates every CA picker in the app; a shot that selects one
    // before it has run would select from an empty list.
    await page.waitFor(`document.getElementById('certCA').options.length > 0`,
                       'the CA pickers to populate', 30000);
    await page.eval(HELPERS);
    await sleep(1200);
    loggedIn = true;
  };

  for (const shot of shots) {
    if (!shot.preLogin && !loggedIn) await logIn();
    process.stdout.write('  ' + shot.file + ' … ');
    try {
      await page.eval(`(async () => { ${shot.setup} })()`);
      if (shot.settle) await page.waitFor(shot.settle, shot.file);
      await sleep(900);   // transitions, late-arriving fetches
      await page.eval(`window.scrollTo(0, 0)`);

      const params = {format: 'png', captureBeyondViewport: true};
      if (shot.clip) {
        const box = await page.eval(`(() => {
          const resolve = (sel) => sel.startsWith('panel:')
            ? shotPanel(sel.slice(6))
            : document.querySelector(sel);
          let el = resolve(${js(shot.clip)});
          if (!el) return null;
          // Some panels take their heading from the section above them, so they
          // cannot be found by heading; name an element inside one instead.
          if (${shot.clipFromPanel ? 'true' : 'false'}) {
            const p = el.closest('.panel') || el.closest('.card');
            if (p) el = p;
          }
          // ...and for those, the heading is a preceding sibling. Without this
          // the frame's top padding catches the bottom half of it, which reads
          // as a mistake rather than as a crop.
          let top = el;
          if (${shot.withHeading ? 'true' : 'false'}) {
            const h = shotHeadingAbove(el);
            if (h) top = h;
          }
          // A pair of forms side by side reads as a pair; frame the flex row
          // they share rather than one of them.
          if (${shot.expandToRow ? 'true' : 'false'} &&
              el.parentElement && el.parentElement.classList.contains('row')) {
            el = el.parentElement;
          }
          const r = el.getBoundingClientRect();
          const tr = top.getBoundingClientRect();
          const box = {x: r.x + window.scrollX, y: tr.y + window.scrollY,
                       width: r.width,
                       height: r.height + (r.y - tr.y)};
          const stopSel = ${js(shot.clipTo || '')};
          if (stopSel) {
            let stop = resolve(stopSel);
            if (stop) {
              // Cut above the stop panel's section heading when it has one, for
              // the same reason withHeading exists: a frame ending halfway
              // through "Digital signatures" reads as a rendering fault.
              const h = shotHeadingAbove(stop);
              if (h) stop = h;
              const sr = stop.getBoundingClientRect();
              const cut = sr.y + window.scrollY - box.y;
              if (cut > 40 && cut < box.height) { box.height = cut; box.cut = true; }
            }
          }
          return box;
        })()`);
        if (!box || box.width < 10 || box.height < 10) {
          throw new Error('clip target ' + shot.clip + ' is not on screen');
        }
        // Pad above and below so the panel's own border and shadow stay inside
        // the frame — except at a clipTo boundary, where padding past the cut is
        // what puts the first line of the next section back into the shot the
        // cut existed to remove.
        const pad = 14;
        let height = box.cut ? box.height + pad - 16 : box.height + pad * 2;
        if (shot.maxHeight && height > shot.maxHeight) height = shot.maxHeight;
        params.clip = {
          x: Math.max(0, box.x - pad),
          y: Math.max(0, box.y - pad),
          width: box.width + pad * 2,
          height,
          scale: 1,
        };
      }

      const {data} = await page.send('Page.captureScreenshot', params);
      fs.writeFileSync(path.join(OUTDIR, shot.file), Buffer.from(data, 'base64'));
      taken.push(shot.file);
      console.log('ok');
    } catch (err) {
      console.log('FAILED: ' + err.message);
    }
  }

  chrome.kill('SIGKILL');
  fs.rmSync(profile, {recursive: true, force: true});

  console.log('\ncaptured ' + taken.length + '/' + shots.length + ' into ' + OUTDIR);
  if (taken.length !== shots.length) process.exit(1);
}

main().catch(err => { console.error(err); process.exit(1); });
