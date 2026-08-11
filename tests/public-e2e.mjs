// End-to-end test against a live deployment, over the real network path.
//
//   node tests/public-e2e.mjs https://warpgate.fysh.site
//
// Unlike browser.test.mjs this does not start a local server: it drives two tabs
// against a deployed instance, so it exercises Cloudflare, the tunnel, TLS and the
// real signalling path. The room link never leaves the harness.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { check, summary } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';

const ORIGIN = (process.argv[2] || 'https://warpgate.fysh.site').replace(/\/$/, '');

if (!findBrowser()) {
  process.stdout.write('BAD  no Chromium-based browser available\n');
  process.exit(1);
}

// Resolve the host over DNS-over-HTTPS and pin it for the browser.
//
// This is not papering over a deployment problem: the record is live globally, but
// this network's own resolver serves a stale negative answer for it, so a headless
// browser using system DNS cannot reach a site the rest of the world can. Pinning
// keeps the test measuring the deployment rather than the local resolver.
const host = new URL(ORIGIN).hostname;
// The gate is its own document. ORIGIN is the landing, which carries none of it.
const APP = `${ORIGIN}/app`;
let pin = [];

// Pinning is a workaround for this network's resolver, not part of what is being
// tested, so it is best effort: try two providers, and if both are unreachable carry
// on unpinned. The assertion that matters is whether the app is actually served.
const dohProviders = [
  `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`,
  `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
];
for (const url of dohProviders) {
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(8000),
    });
    const dns = await res.json();
    const ip = (dns.Answer || []).filter((a) => a.type === 1).map((a) => a.data)[0];
    if (ip) {
      pin = [`--host-resolver-rules=MAP ${host} ${ip}`];
      break;
    }
  } catch (err) {
    void err;
  }
}

// Emitted on BOTH paths, deliberately.
//
// This check used to live inside the `if (ip)` above, so a run where neither DoH provider
// answered simply did not emit it: the suite printed 17 checks instead of 18, exited 0,
// and nothing said which run had measured what. Observed on 2026-08-10, one run of 17
// between two runs of 18. A check that silently does not run is the same failure as a
// check that cannot fail, and it is harder to spot, because the evidence is a number in a
// summary line nobody diffs.
//
// Falling back to system DNS is a legitimate outcome and not a failure, so this does not
// go red for it. What it does is make the choice VISIBLE and the count STABLE.
check(pin.length
  ? `resolved ${host} over DNS-over-HTTPS and pinned it for the browser`
  : `no DoH answer for ${host}: falling back to system DNS, which this network answers stale`,
  pin.length === 0 || /^--host-resolver-rules=MAP \S+ (\d{1,3}\.){3}\d{1,3}$/.test(pin[0]),
  pin[0] || '(unpinned)');

// Wait for the deployment to actually be serving before judging it. Running straight
// after a container restart otherwise fails on a cold start rather than a defect.
for (let i = 0; i < 30; i += 1) {
  try {
    const r = await fetch(`${ORIGIN}/api/health`, { signal: AbortSignal.timeout(4000) });
    if (r.ok) break;
  } catch (err) { void err; }
  await new Promise((r) => { setTimeout(r, 1000); });
}

// Which BUILD is being measured. Every probe below exercises behaviour that has been
// correct for months, so all 18 pass just as happily against last week's container: a
// green run says the deployment works, not that the deployment is this tree. That is the
// 2026-08-10 gateway failure exactly, where the checks were sound and the bytes were old.
//
// There is no version endpoint to ask, and there should not be: /api/health returns
// liveness only because a richer payload is a usage side channel. So compare the bytes
// instead. app.js is the whole transfer path, so any change to this tree moves it.
const localApp = createHash('sha256')
  .update(readFileSync(new URL('../public/js/app.js', import.meta.url)))
  .digest('hex').slice(0, 16);
let liveApp = '(unreachable)';
try {
  const r = await fetch(`${ORIGIN}/js/app.js`, { signal: AbortSignal.timeout(15000) });
  liveApp = r.ok
    ? createHash('sha256').update(Buffer.from(await r.arrayBuffer())).digest('hex').slice(0, 16)
    : `(http ${r.status})`;
} catch (err) {
  liveApp = `(fetch failed: ${err.message})`;
}
check('the deployment is serving THIS tree, so the probes below judge this build',
  liveApp === localApp, `tree=${localApp} live=${liveApp}`);
if (liveApp !== localApp) {
  process.stdout.write('BAD  refusing to run: 18 green probes against a stale build read as a pass\n');
  process.stdout.write('     deploy this tree first, then re-run\n');
  summary(`public end-to-end (${ORIGIN})`);
  process.exit(1);
}

const browser = await launchBrowser({ port: 9763, extraArgs: pin });
check('the harness is driving the browser it started itself',
  Number.isInteger(browser.pid) && browser.debugPort === 9763, `pid ${browser.pid} on ${browser.debugPort}`);
let ok = false;

try {
  const a = await browser.newTab(APP);
  await a.waitFor("document.readyState === 'complete' && !!document.getElementById('screen-home')",
    { timeout: 30000, label: 'app loaded from the public origin' });
  // What is served has to be Warp Gate and not a tunnel error page or a parked domain,
  // both of which also load to readyState complete.
  const identity = await a.eval(`
    return JSON.stringify({
      origin: location.origin,
      title: document.title,
      screens: [...document.querySelectorAll('section.screen')].map((s) => s.id),
    });
  `);
  const id = JSON.parse(identity);
  check(`the gate is served from ${APP}`,
    id.origin === ORIGIN && id.screens.includes('screen-home') && id.screens.includes('screen-connected'),
    identity);

  check('page is a secure context, so WebCrypto is available',
    await a.eval('return window.isSecureContext === true && !!window.crypto.subtle;'));

  const cfg = await a.eval("const r = await fetch('/api/config'); return JSON.stringify(await r.json());");
  check('config endpoint answers through the tunnel', /sessionMinutes/.test(cfg), cfg.slice(0, 120));

  // Dismiss onboarding if shown, then create.
  await a.eval(`
    if (!document.getElementById('screen-onboarding').hidden) {
      const c = document.getElementById('agree-check');
      c.checked = true;
      c.dispatchEvent(new Event('change', { bubbles: true }));
      document.getElementById('onboarding-done').click();
    }
    return true;
  `);
  await a.waitFor("!document.getElementById('screen-home').hidden", { label: 'home screen' });
  await a.eval("document.getElementById('create-btn').click(); return true;");
  // The pre-flight network notice stands in front of both create and join. Clicking
  // through it is what a person does, so the test does the same rather than
  // pre-dismissing it in sessionStorage and skipping the path a real visitor takes.
  await a.waitFor("!document.getElementById('net-modal').hidden",
    { timeout: 20000, label: 'network notice shown before a gate is created' });
  await a.eval("document.getElementById('net-continue').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { timeout: 25000, label: 'gate created through Cloudflare' });
  const created = await a.eval(`
    return JSON.stringify({
      screens: [...document.querySelectorAll('section.screen')].filter((s) => !s.hidden).map((s) => s.id),
      error: (document.getElementById('home-error') || {}).textContent || '',
      slots: Object.keys(sessionStorage).filter((k) => k.startsWith('wg.slot.')),
    });
  `);
  const cr = JSON.parse(created);
  check('a gate can be created over the public path',
    cr.screens.length === 1 && cr.screens[0] === 'screen-waiting' && cr.error === '' && cr.slots.length === 1,
    created);

  // The secret is deliberately not left in the address bar, so reveal it to get the
  // link. It stays inside the harness and is never printed.
  const barUrl = await a.eval('return location.href;');
  check('the secret is not left in the address bar', !barUrl.includes('WARP-'), barUrl);
  await a.eval("document.getElementById('reveal-share').click(); return true;");
  await a.waitFor("document.getElementById('share-shown').hidden === false", { label: 'share revealed' });
  const code = await a.eval("return document.getElementById('room-code').textContent.trim();");
  const link = APP + '#' + code;
  check('a gate code is produced', /^WARP-/.test(code));

  const b = await browser.newTab(link);
  // A joiner arriving on a link meets the same notice, and until it is answered the
  // gate shows no screen at all, so this has to come before any screen assertion.
  await b.waitFor("!document.getElementById('net-modal').hidden",
    { timeout: 20000, label: 'network notice shown to the joiner' });
  await b.eval("document.getElementById('net-continue').click(); return true;");
  await a.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 45000, label: 'creator reached connected over the public path' });
  await b.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 45000, label: 'joiner reached connected over the public path' });
  const paired = await Promise.all([a, b].map((tab) => tab.eval(`
    return JSON.stringify({
      screens: [...document.querySelectorAll('section.screen')].filter((s) => !s.hidden).map((s) => s.id),
      secure: window.isSecureContext === true,
    });
  `)));
  const pa = JSON.parse(paired[0]);
  const pb = JSON.parse(paired[1]);
  check('two peers complete the handshake over the real deployment',
    pa.screens.join() === 'screen-connected' && pb.screens.join() === 'screen-connected'
    && pa.secure && pb.secure, paired.join(' | '));

  const sasA = await a.eval("return document.getElementById('sas').textContent;");
  const sasB = await b.eval("return document.getElementById('sas').textContent;");
  check('both sides derive the same verification code', sasA === sasB && /^\d{5}$/.test(sasA), `${sasA} vs ${sasB}`);

  // The badge ships pre-filled with the word "connecting", so `length > 0` was true
  // before the page had resolved anything at all and could not fail. What has to be
  // asserted is the transition off that placeholder, and then the value it settled on.
  const badgeAtLoad = await b.eval("return document.getElementById('route-badge').textContent;");
  const settled = "(t => t && t !== 'connecting')(document.getElementById('route-badge').textContent)";
  await a.waitFor(settled, { timeout: 20000, label: 'route badge left its placeholder' });
  const route = await a.eval("return document.getElementById('route-badge').textContent;");
  check('the route badge ships with a placeholder, so its content alone proves nothing',
    /connecting/i.test(badgeAtLoad) || /DIRECT P2P|RELAYED|CONNECTED/.test(badgeAtLoad), badgeAtLoad);
  check('the data path the user is shown resolves to a real answer',
    /^DIRECT P2P \(.+\)$|^RELAYED \(still encrypted\)$|^CONNECTED$/.test(route), route);

  const msg = `public path check ${Date.now()}`;
  await a.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(msg)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(msg)})`,
    { timeout: 20000, label: 'message arrived at the peer' });
  const copies = await b.eval(`
    return document.getElementById('messages').textContent.split(${JSON.stringify(msg)}).length - 1;
  `);
  check('an encrypted message crosses between the two peers exactly once',
    copies === 1, `rendered ${copies} times`);

  check('no uncaught page errors on either side',
    a.pageErrors.length === 0 && b.pageErrors.length === 0,
    [...a.pageErrors, ...b.pageErrors].join(' | '));

  // Positive control for the two clearing checks below. getItem of a key that was never
  // written is also null, so "cleared" and "never there" are the same reading: without
  // this, both checks pass on a build that stopped storing the secret at all.
  const held = await Promise.all([a, b].map((tab) => tab.eval(`
    return JSON.stringify({ secret: sessionStorage.getItem('wg.secret') });
  `)));
  check('CONTROL: both devices are holding a room secret before anything is severed',
    JSON.parse(held[0]).secret !== null && JSON.parse(held[1]).secret !== null,
    held.join(' | '));

  await a.eval("document.getElementById('sever').click(); return true;");
  await a.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 20000, label: 'gate severed' });
  await b.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 20000, label: 'peer told of severing' });
  // "Clears both sides" is about state, not screens: the gate has ended, so the room
  // secret goes with it on the device that pressed Sever AND on the device that was
  // merely told. Only the local button used to do that.
  const cleared = await Promise.all([a, b].map((tab) => tab.eval(`
    return JSON.stringify({
      secret: sessionStorage.getItem('wg.secret'),
      slots: Object.keys(sessionStorage).filter((k) => k.startsWith('wg.slot.')),
    });
  `)));
  const ca = JSON.parse(cleared[0]);
  const cb = JSON.parse(cleared[1]);
  check('severing clears the room secret on the device that ended it',
    ca.secret === null && ca.slots.length === 0, cleared[0]);
  check('severing clears the room secret on the device that was told',
    cb.secret === null && cb.slots.length === 0, cleared[1]);
  check('the fragment is stripped from the URL on sever',
    (await a.eval('return location.hash;')) === '');

  ok = true;
} finally {
  await browser.close();
}

check('the public deployment completed a full lifecycle', ok);
process.exit(summary(`public end-to-end (${ORIGIN})`) ? 0 : 1);
