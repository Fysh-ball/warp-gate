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
      check(`resolved ${host} over DNS-over-HTTPS and pinned it for the browser`, true);
      break;
    }
  } catch (err) {
    void err;
  }
}
if (!pin.length) {
  process.stdout.write(`note  DoH lookup unavailable; falling back to system DNS for ${host}\n`);
}

// Wait for the deployment to actually be serving before judging it. Running straight
// after a container restart otherwise fails on a cold start rather than a defect.
for (let i = 0; i < 30; i += 1) {
  try {
    const r = await fetch(`${ORIGIN}/api/health`, { signal: AbortSignal.timeout(4000) });
    if (r.ok) break;
  } catch (err) { void err; }
  await new Promise((r) => { setTimeout(r, 1000); });
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
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { timeout: 25000, label: 'gate created through Cloudflare' });
  check('a gate can be created over the public path', true);

  // The secret is deliberately not left in the address bar, so reveal it to get the
  // link. It stays inside the harness and is never printed.
  const barUrl = await a.eval('return location.href;');
  check('the secret is not left in the address bar', !barUrl.includes('WARP-'), barUrl);
  await a.eval("document.getElementById('reveal-share').click(); return true;");
  await a.waitFor("document.getElementById('share-shown').hidden === false", { label: 'share revealed' });
  const code = await a.eval("return document.getElementById('room-code').textContent.trim();");
  const link = ORIGIN + '/#' + code;
  check('a gate code is produced', /^WARP-/.test(code));

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
