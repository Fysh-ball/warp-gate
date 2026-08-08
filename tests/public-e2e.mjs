// End-to-end test against a live deployment, over the real network path.
//
//   node tests/public-e2e.mjs https://wg.fysh.site
//
// Unlike browser.test.mjs this does not start a local server: it drives two tabs
// against a deployed instance, so it exercises Cloudflare, the tunnel, TLS and the
// real signalling path. The room link never leaves the harness.

import { check, summary } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';

const ORIGIN = (process.argv[2] || 'https://wg.fysh.site').replace(/\/$/, '');

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
let pin = [];
try {
  const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
    signal: AbortSignal.timeout(8000),
  });
  const dns = await res.json();
  const ip = (dns.Answer || []).filter((a) => a.type === 1).map((a) => a.data)[0];
  if (ip) {
    pin = [`--host-resolver-rules=MAP ${host} ${ip}`];
    check(`resolved ${host} via DNS-over-HTTPS and pinned it for the browser`, true);
  } else {
    check(`${host} has no A record via DoH`, false, JSON.stringify(dns).slice(0, 160));
  }
} catch (err) {
  check('DoH lookup succeeded', false, err.message);
}

const browser = await launchBrowser({ port: 9344, extraArgs: pin });
let ok = false;

try {
  const a = await browser.newTab(ORIGIN);
  await a.waitFor("document.readyState === 'complete' && !!document.getElementById('screen-home')",
    { timeout: 30000, label: 'app loaded from the public origin' });
  check(`app is served from ${ORIGIN}`, true);

  check('page is a secure context, so WebCrypto is available',
    await a.eval('return window.isSecureContext === true && !!window.crypto.subtle;'));

  const cfg = await a.eval("const r = await fetch('/api/config'); return JSON.stringify(await r.json());");
  check('config endpoint answers through the tunnel', /sessionMinutes/.test(cfg), cfg.slice(0, 120));

  // Dismiss onboarding if shown, then create.
  await a.eval("const b=document.getElementById('onboarding-done'); if(b && !document.getElementById('screen-onboarding').hidden) b.click(); return true;");
  await a.waitFor("!document.getElementById('screen-home').hidden", { label: 'home screen' });
  await a.eval("document.getElementById('create-btn').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { timeout: 25000, label: 'gate created through Cloudflare' });
  check('a gate can be created over the public path', true);

  // The link stays inside the harness and is never printed.
  const link = await a.eval('return location.href;');
  check('the secret is carried in the URL fragment', link.includes('#WARP-'));

  const b = await browser.newTab(link);
  await a.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 45000, label: 'creator reached connected over the public path' });
  await b.waitFor("!document.getElementById('screen-connected').hidden",
    { timeout: 45000, label: 'joiner reached connected over the public path' });
  check('two peers complete the handshake over the real deployment', true);

  const sasA = await a.eval("return document.getElementById('sas').textContent;");
  const sasB = await b.eval("return document.getElementById('sas').textContent;");
  check('both sides derive the same verification code', sasA === sasB && /^\d{5}$/.test(sasA), `${sasA} vs ${sasB}`);

  const route = await a.eval("return document.getElementById('route-badge').textContent;");
  check('the data path is reported to the user', route.length > 0, route);

  const msg = `public path check ${Date.now()}`;
  await a.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(msg)};
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { cancelable: true }));
    return true;
  `);
  await b.waitFor(`document.getElementById('messages').textContent.includes(${JSON.stringify(msg)})`,
    { timeout: 20000, label: 'message arrived at the peer' });
  check('an encrypted message crosses between the two peers', true);

  check('no uncaught page errors on either side',
    a.pageErrors.length === 0 && b.pageErrors.length === 0,
    [...a.pageErrors, ...b.pageErrors].join(' | '));

  await a.eval("document.getElementById('sever').click(); return true;");
  await a.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 20000, label: 'gate severed' });
  await b.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 20000, label: 'peer told of severing' });
  check('severing propagates and clears both sides', true);
  check('the fragment is stripped from the URL on sever',
    (await a.eval('return location.hash;')) === '');

  ok = true;
} finally {
  await browser.close();
}

check('the public deployment completed a full lifecycle', ok);
process.exit(summary(`public end-to-end (${ORIGIN})`) ? 0 : 1);
