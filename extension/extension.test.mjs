// End-to-end verification of the extension, in a real browser, against a real server.
//
// This file lives here rather than in tests/ because tests/ is owned by other work in
// flight. It uses the project's own harnesses (tests/lib/harness.mjs, tests/lib/cdp.mjs)
// and follows the pattern in tests/browser.test.mjs. Run it with:
//
//     node extension/extension.test.mjs
//
// WHAT IT IS ALLOWED TO CONCLUDE
//
// Only what it drives. Nothing here asserts against the live deployment: the server is a
// process started from this tree on loopback, and the extension is pointed at it. The
// claims it makes are, in order:
//
//   1. Chromium loads the package with no manifest error, and the background service
//      worker starts. Proved by a chrome-extension:// target existing at all: a manifest
//      Chromium refuses produces no target and this file cannot get past step one.
//   2. The gate document opens FROM THE PACKAGE, and every subresource it uses came from
//      the package. This is the whole product claim, so it is measured with the browser's
//      own resource timeline rather than reasoned about: any entry whose URL is not
//      chrome-extension:// and not an /api/ call is a failure.
//   3. The client reaches the signalling API on a different origin. This is not obvious:
//      server/signal.js refuses a cross-site POST, and an extension page is on another
//      origin. See the report and the assertions below for what the server actually sees.
//   4. A gate really opens: the room exists in the server's map afterwards, asked of the
//      server directly rather than read out of the page that claims to have created it.
//   5. The shareable link names the SIGNALLING origin's web client, not the extension.
//      Captured off the real copy button, not recomputed, because the value that matters
//      is the one app.js hands to the clipboard.
//
// WHAT IT DOES NOT COVER, said out loud: no second peer, so no WebRTC handshake, no
// transfer and no chat. tests/browser.test.mjs already drives all of that against the web
// client, and the extension changes nothing about the code paths involved. Wiring a second
// extension tab into a full pairing run is the obvious next step and is listed in the
// README as unfinished rather than implied as done.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, summary, startServer, request, makeJoinProof } from '../tests/lib/harness.mjs';
import { launchBrowser, findBrowser } from '../tests/lib/cdp.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// The package under test. Overridable so the checks in this file can be run against a
// deliberately broken copy and shown to FAIL: a check that has never failed is not
// evidence. See extension/README.md for the negative control that was run.
const EXT = process.env.WG_EXT_TEST_DIR ?? HERE;
const PORT = Number(process.env.WG_EXT_TEST_PORT ?? 3801);
const CDP_PORT = Number(process.env.WG_EXT_TEST_CDP ?? 9821);
const ORIGIN = `http://127.0.0.1:${PORT}`;

if (!findBrowser()) {
  // A missing browser is a FAILURE by default, not a skip: an environment that quietly
  // lost its Chromium would otherwise read as a pass forever. The opt-out is explicit,
  // for machines that knowingly cannot run a browser.
  if (process.env.WG_EXT_TEST_ALLOW_SKIP === '1') {
    process.stdout.write('SKIP extension.test.mjs: no Chromium-based browser on PATH (WG_EXT_TEST_ALLOW_SKIP=1)\n');
    process.exit(0);
  }
  process.stdout.write('FAIL extension.test.mjs: no Chromium-based browser on PATH. '
    + 'Set WG_EXT_TEST_ALLOW_SKIP=1 to skip knowingly.\n');
  process.exit(1);
}

/**
 * Is a room id present in the server's map?
 *
 * Asked the same way tests/browser.test.mjs asks it: a create for an id that is already
 * held is refused with room_exists. There is no endpoint that reports occupancy, on
 * purpose, so this is the only honest probe. It matters that this question is put to the
 * SERVER: the page saying it created a gate is the claim under test, not the evidence.
 */
async function roomHeld(roomId) {
  const r = await request(PORT, 'POST', '/api/create', {
    roomId, sessionMinutes: 10, joinProofHash: makeJoinProof().hash,
  });
  return r.status === 409 && r.json?.error === 'room_exists';
}

const server = await startServer({
  WG_HTTP_PORT: String(PORT),
  WG_HTTP_HOST: '127.0.0.1',
  WG_STUN_ENABLED: '0',
});

const browser = await launchBrowser({
  port: CDP_PORT,
  // Both flags, not just --load-extension. Without --disable-extensions-except a profile
  // carrying anything else would run alongside this package and a failure could come from
  // code this test never installed.
  extraArgs: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
});

// A `finally` does not run on SIGTERM: the process is killed without unwinding, and the
// browser this file started is left holding its debugging port. The next run then refuses
// to attach to it, correctly, and the refusal reads as a new bug rather than as litter from
// a run somebody cancelled. Observed exactly that during development after a `timeout 300`.
let reaping = false;
const reap = () => {
  if (reaping) return;
  reaping = true;
  // Synchronous kill: an async close has nothing to await on the way out of a signal.
  try { process.kill(browser.pid, 'SIGKILL'); } catch (err) { void err; }
  try { server.child.kill('SIGKILL'); } catch (err) { void err; }
};
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => { reap(); process.exit(1); });
}

let ok = false;
try {
  // ---------------------------------------------------------------- 1. it loads
  //
  // The id is not knowable in advance: Chromium derives it from the package path for an
  // unpacked load, so it changes with the checkout directory. Read it off whatever
  // chrome-extension:// target the browser has, which for this manifest is the background
  // service worker declared in manifest.json.
  let extId = null;
  const deadline = Date.now() + 15000;
  while (!extId && Date.now() < deadline) {
    const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`, { signal: AbortSignal.timeout(5000) });
    const list = await res.json();
    for (const target of list) {
      const m = /^chrome-extension:\/\/([a-p]{32})\//.exec(target.url ?? '');
      if (m) { extId = m[1]; break; }
    }
    if (!extId) await new Promise((r) => { setTimeout(r, 200).unref?.(); });
  }
  check('the browser loaded the extension and started its background worker',
    Boolean(extId), 'no chrome-extension:// target ever appeared, which is what a rejected manifest looks like');
  if (!extId) throw new Error('cannot continue without an extension id');

  const base = `chrome-extension://${extId}`;

  // ---------------------------------------------------------------- 2. its own page opens
  const about = await browser.newTab(`${base}/index.html`);
  const manifest = JSON.parse(await about.eval('return JSON.stringify(chrome.runtime.getManifest());'));
  check('the loaded manifest is manifest v3', manifest.manifest_version === 3, JSON.stringify(manifest.manifest_version));
  check('the extension page states what it does NOT protect against',
    (await about.eval("return document.body.textContent.includes('does not fix');")) === true);
  check('the extension page names the metadata the signalling server still sees',
    (await about.eval("return document.body.textContent.includes('per-seat token');")) === true);

  // Point the extension at the local server. Written straight to localStorage rather than
  // through the Save button because chrome.permissions.request needs a real user gesture
  // and http://127.0.0.1 is already in host_permissions, so the button would only be
  // testing the prompt. The storage key is the one endpoint.js reads; if that ever
  // diverges this assertion fails rather than the whole run silently using the default.
  await about.eval(`localStorage.setItem('wg.signalOrigin', ${JSON.stringify(ORIGIN)}); return true;`);
  // Reload before asserting, because endpoint.js pins the origin at module evaluation and
  // this page already evaluated it (options.js imports it) with the default in force. That
  // pinning is a deliberate property, not an accident: see ACTIVE_ORIGIN in endpoint.js. The
  // first version of this test asserted without the reload, got the default back, and the
  // failure was the design working.
  await about.send('Page.reload', {});
  await about.waitFor("document.readyState !== 'loading' && !!document.getElementById('origin-input')",
    { label: 'the extension page to reload' });
  const readBack = await about.eval(
    "const m = await import('/js/endpoint.js'); return m.signalOrigin() + ' ' + m.gateLink('WARP-X');",
  );
  check('endpoint.js reads the configured origin back', readBack.startsWith(ORIGIN), readBack);
  check('the gate link names the signalling origin\'s web client, not the extension',
    readBack.endsWith(`${ORIGIN}/app#WARP-X`) && !readBack.includes('chrome-extension'), readBack);

  const badOrigin = await about.eval(
    "const m = await import('/js/endpoint.js');"
    + " return JSON.stringify([m.parseOrigin('http://example.com'), m.parseOrigin('https://x.test/path'),"
    + " m.parseOrigin('javascript:alert(1)'), m.parseOrigin('https://x.test'),"
    + " m.matchPatternFor('https://gate.example:8443'), m.parseOrigin('http://[::1]:3095')]);",
  );
  const parsed = JSON.parse(badOrigin);
  check('plain http on a real host is refused', parsed[0].ok === false, badOrigin);
  check('an origin with a path is refused', parsed[1].ok === false, badOrigin);
  check('a javascript: URL is refused', parsed[2].ok === false, badOrigin);
  check('a bare https origin is accepted', parsed[3].ok === true && parsed[3].origin === 'https://x.test', badOrigin);
  // Chrome rejects a match pattern whose host carries a port, so a self-hoster on a
  // non-standard port would hit a permissions.request() that throws rather than prompts.
  check('a permission match pattern drops the port', parsed[4] === 'https://gate.example/*', badOrigin);
  // [::1] is refused up front: it is in neither host_permissions nor the CSP connect-src,
  // and optional_host_permissions is https-only, so accepting it would only defer the
  // failure to a permission error at Save.
  check('http://[::1] is refused as an origin', parsed[5].ok === false, badOrigin);

  // The options page's Save button, driven for real.
  //
  // This is the one interactive path in code written for the extension rather than copied,
  // and it has a trap in it: chrome.permissions.request() must be called while the user
  // activation from the click is still live, so an `await` placed before it turns Save into
  // a button that silently does nothing. Runtime.evaluate with userGesture supplies a real
  // activation, which is the only way to exercise that from a harness.
  //
  // The origin used is http://localhost:9999, which is already covered by the manifest's
  // host_permissions, so request() resolves without a prompt a headless browser could not
  // answer. That exercises validation, the permission call, the storage write and the
  // reporting; the only untested branch is a user declining a prompt.
  const savePath = await about.send('Runtime.evaluate', {
    expression: `(async () => {
      document.getElementById('origin-input').value = 'http://localhost:9999';
      document.getElementById('origin-save').click();
      await new Promise((r) => setTimeout(r, 600));
      return JSON.stringify({
        status: document.getElementById('origin-status').textContent,
        stored: localStorage.getItem('wg.signalOrigin'),
      });
    })()`,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  });
  const saved = JSON.parse(savePath.result.value);
  check('the Save button stores a valid origin and says so',
    saved.stored === 'http://localhost:9999' && /Saved\./.test(saved.status), JSON.stringify(saved));

  const rejected = await about.send('Runtime.evaluate', {
    expression: `(async () => {
      document.getElementById('origin-input').value = 'https://example.test/with/a/path';
      document.getElementById('origin-save').click();
      await new Promise((r) => setTimeout(r, 400));
      return JSON.stringify({
        status: document.getElementById('origin-status').textContent,
        stored: localStorage.getItem('wg.signalOrigin'),
      });
    })()`,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  });
  const rej = JSON.parse(rejected.result.value);
  check('a bad origin is refused and does NOT overwrite the stored one',
    rej.stored === 'http://localhost:9999' && /not a usable signalling origin/.test(rej.status),
    JSON.stringify(rej));

  // Put the local server back, and reload so the gate page opened below pins it.
  await about.eval(`localStorage.setItem('wg.signalOrigin', ${JSON.stringify(ORIGIN)}); return true;`);

  // ---------------------------------------------------------------- 3. the gate opens
  //
  // Opened at about:blank and navigated by hand so that the CDP Network domain is enabled
  // BEFORE the document starts loading. Attaching afterwards would miss every request the
  // page made on its way up, which is precisely the set under test.
  const tab = await browser.newTab('about:blank');
  /** Every URL this page asks the network stack for, in order. */
  const requested = [];
  tab.ws.addEventListener('message', (event) => {
    // A second listener on the same socket. The Tab class ignores any method it does not
    // recognise, so this neither competes with it nor changes its behaviour.
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (err) {
      // A frame this test cannot parse is a harness fault worth seeing, not worth hiding.
      process.stderr.write(`could not parse a CDP frame: ${err.message}\n`);
      return;
    }
    if (msg.method === 'Network.requestWillBeSent') requested.push(msg.params.request.url);
  });
  await tab.send('Network.enable');
  // Record Content-Security-Policy violations from inside the page.
  //
  // The first version of this read the console lines the Tab class collects and looked for
  // "Refused to". That check could never fail: CSP violations are written to the browser's
  // log, not raised through the console API, so Runtime.consoleAPICalled never sees them
  // and the check reported green whether or not anything had been blocked. The
  // `securitypolicyviolation` DOM event is the page's own account of the same thing, and it
  // is installed with addScriptToEvaluateOnNewDocument so the listener exists before the
  // first byte of the document rather than after everything has already been blocked.
  await tab.send('Page.addScriptToEvaluateOnNewDocument', {
    source: "globalThis.__cspViolations = [];"
      + "document.addEventListener('securitypolicyviolation',"
      + " (e) => { globalThis.__cspViolations.push(e.effectiveDirective + ' ' + e.blockedURI); });",
  });
  await tab.send('Page.navigate', { url: `${base}/app.html` });
  // Wait for the ONBOARDING SCREEN, not merely for the checkbox to exist in the DOM.
  //
  // The markup ships every screen hidden and boot() un-hides one at the very end, after an
  // await on /api/config. The checkbox is in the parsed document long before boot has
  // wired its change handler, so a test that waits on the element ticks a box nobody is
  // listening to, finds the continue button still disabled, and times out somewhere else
  // entirely. Waiting on the screen waits on boot having finished.
  await tab.waitFor("!document.getElementById('screen-onboarding').hidden",
    { timeout: 30000, label: 'boot() to finish and show the onboarding screen' });
  check('the gate document is served from the extension package',
    (await tab.eval('return location.protocol;')) === 'chrome-extension:');

  // The claim, measured, and measured in a way that can FAIL.
  //
  // Two independent instruments, because the obvious one is silently blind. Resource
  // Timing was tried first and rejected: `performance.getEntriesByType('resource')` reports
  // nothing at all for chrome-extension:// subresources, so a check written on it sees an
  // empty list and passes "no foreign resources" while having measured no resource of any
  // kind. That is the exact shape of a check that reports green because it looked at
  // nothing, so both instruments below carry a positive control.
  //
  // Instrument one: the browser's own network stack, recorded from before the first byte.
  const own = requested.filter((u) => u.startsWith('chrome-extension:'));
  const apiCalls = requested.filter((u) => u.startsWith(`${ORIGIN}/api/`));
  const foreign = requested.filter((u) => !u.startsWith('chrome-extension:') && !u.startsWith(`${ORIGIN}/api/`));
  check('the network stack really recorded this page loading from the package',
    own.length > 3, `only ${own.length} package requests were seen, so the next check measured nothing`);
  check('every script, style and asset the gate loaded came from the extension package',
    foreign.length === 0, `from outside the package: ${foreign.join(', ')}`);
  check('the only requests leaving the package are signalling API calls to the configured origin',
    apiCalls.length > 0 && apiCalls.every((u) => u.startsWith(`${ORIGIN}/api/`)), JSON.stringify(apiCalls));
  check('the gate document itself was loaded from the package',
    own.some((u) => u.endsWith('/app.html')), own.slice(0, 5).join(', '));
  check('the client module graph was loaded from the package',
    own.some((u) => u.endsWith('/js/app.js')), own.slice(0, 5).join(', '));

  // Instrument two: what the document ended up with, independent of how it got there. A
  // stylesheet whose rules parsed is a stylesheet that arrived; a stylesheet pointing at
  // the network is caught by the href. The rule count is the positive control: zero rules
  // would mean the sheet never loaded and the href assertion was about a link that did
  // nothing.
  const sheets = JSON.parse(await tab.eval(`
    const out = [];
    for (const sheet of document.styleSheets) {
      let rules = -1;
      try { rules = sheet.cssRules.length; } catch (err) { rules = 'blocked: ' + err.message; }
      out.push({ href: sheet.href, rules });
    }
    const scripts = [...document.querySelectorAll('script[src]')].map((el) => el.src);
    return JSON.stringify({ sheets: out, scripts });
  `));
  check('every stylesheet in the document is a package URL and actually parsed',
    sheets.sheets.length > 0
      && sheets.sheets.every((s2) => String(s2.href).startsWith('chrome-extension:') && s2.rules > 0),
    JSON.stringify(sheets.sheets));
  check('every script element in the document is a package URL',
    sheets.scripts.length > 0 && sheets.scripts.every((u) => u.startsWith('chrome-extension:')),
    JSON.stringify(sheets.scripts));

  // Onboarding is a clickwrap gate and has to be answered before anything else exists.
  const gated = await tab.eval("return document.getElementById('onboarding-done').disabled;");
  check('the continue button is disabled until the terms are accepted', gated === true);
  await tab.eval(`
    const c = document.getElementById('agree-check');
    c.checked = true;
    c.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  `);
  await tab.eval("document.getElementById('onboarding-done').click(); return true;");
  try {
    await tab.waitFor("!document.getElementById('screen-home').hidden", { label: 'the home screen' });
  } catch (err) {
    // Never let a timeout hide the reason. The page's own console and exception list are
    // the only place an afterAgreement() throw is recorded, and without printing them a
    // real product bug reads as "the harness is flaky".
    process.stdout.write(`page errors: ${JSON.stringify(tab.pageErrors)}\n`);
    process.stdout.write(`console: ${JSON.stringify(tab.consoleLines)}\n`);
    throw err;
  }

  // The instance disclosure has to be telling the extension's story, not the website's.
  // Upstream this block reads location.hostname, which here is the extension id, and would
  // print "you are on hgkl...jej, which is not the official instance" over the one delivery
  // path that does not have that problem.
  const disclosure = await tab.eval("return document.getElementById('instance-disc').textContent;");
  check('the instance disclosure does not call the extension id an untrusted host',
    !disclosure.includes(extId), disclosure.slice(0, 200));
  check('the instance disclosure names the configured signalling origin',
    disclosure.includes(ORIGIN), disclosure.slice(0, 400));

  // /api/config is fetched on the boot path, so reaching the home screen with iceServers
  // resolved is already evidence the cross-origin GET worked. Assert it directly anyway:
  // a page that failed that fetch can still render, and "it looked fine" is not a check.
  const configReach = await tab.eval(
    `const r = await fetch('${ORIGIN}/api/config', { signal: AbortSignal.timeout(5000) });`
    + ' return r.status + " " + ((await r.json()).maxParticipants ?? "?");',
  );
  check('the extension page can read a cross-origin GET /api/config',
    configReach.startsWith('200 '), configReach);

  // ---------------------------------------------------------------- 4. a real room
  //
  // Capture the link off the real copy button rather than recomputing it. The value under
  // test is the one app.js hands to the clipboard, and a test that recalculates it would
  // pass even if the patched call site had been reverted.
  await tab.eval(`
    globalThis.__copied = null;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: async (t) => { globalThis.__copied = t; } },
    });
    return true;
  `);
  await tab.send('Page.bringToFront', {});
  await tab.eval("document.getElementById('create-btn').click(); return true;");
  // Pressing Create raises the IP exposure notice first; nothing opens behind it.
  await tab.waitFor("!document.getElementById('net-modal').hidden", { timeout: 20000, label: 'the IP exposure notice' });
  await tab.eval("document.getElementById('net-continue').click(); return true;");
  await tab.waitFor("!document.getElementById('screen-waiting').hidden", { timeout: 30000, label: 'the waiting screen' });
  check('an extension page can create a gate on a cross-origin signalling server', true);

  await tab.eval("document.getElementById('reveal-share').click(); return true;");
  await tab.waitFor("document.getElementById('share-shown').hidden === false", { label: 'the share panel' });
  const code = await tab.eval("return document.getElementById('room-code').textContent.trim();");
  check('a gate code was minted', /^WARP-/.test(code), code);

  await tab.eval("document.getElementById('copy-link').click(); return true;");
  await tab.waitFor('globalThis.__copied !== null', { label: 'the copy button to produce a link' });
  const copied = await tab.eval('return globalThis.__copied;');
  check('the copied link points at the signalling origin, not at the extension',
    copied.startsWith(`${ORIGIN}/app#`), copied);
  check('the copied link carries the gate code in the fragment', copied.endsWith(`#${code}`), copied);
  check('the secret is not in the address bar',
    !(await tab.eval('return location.href;')).includes('WARP-'));

  // The server's own answer, not the page's.
  const { deriveSecret, deriveRoomId } = await import('../public/js/crypto.js');
  const roomId = await deriveRoomId(await deriveSecret(code));
  check('the server is really holding a room for that code', await roomHeld(roomId), roomId);

  // ---------------------------------------------------------------- 5. nothing broke
  const violations = JSON.parse(await tab.eval('return JSON.stringify(globalThis.__cspViolations ?? null);'));
  check('the CSP violation recorder was actually installed',
    Array.isArray(violations), 'the listener never ran, so the next check measured nothing');
  check('the extension page CSP blocked nothing, because nothing tried to load remotely',
    Array.isArray(violations) && violations.length === 0, JSON.stringify(violations));
  // The service worker refusal is EXPECTED on an extension page and is not a page error;
  // anything else here is.
  const errors = tab.pageErrors.filter((e) => !/ServiceWorker|Service Worker/i.test(e));
  check('the gate page raised no uncaught errors', errors.length === 0, errors.join(' | '));

  // The streaming-download predicate must say no here. It is a capability gate consulted
  // before a large file is accepted, and Chromium refuses a page service worker on an
  // extension origin, so a true here would accept a transfer that cannot be delivered.
  const streamable = await tab.eval(
    "const m = await import('/js/download.js'); return m.supportsStreamDownload();",
  );
  check('the streaming-download capability reports FALSE on an extension page',
    streamable === false, String(streamable));

  ok = summary('extension');
} finally {
  await browser.close();
  await server.stop();
  // Left deliberately: a temp file this test wrote would be cleaned here. It writes none.
  void fs;
}

process.exit(ok ? 0 : 1);
