// Does the CDN inject script into the gate, and does the CSP stop it?
//
//   node tests/cdn-injection.test.mjs https://warpgate.fysh.site
//
// Not part of run-all.sh: it needs the network and a live deployment, the same reason
// tests/public-e2e.mjs is run by hand. It exists because a deploy on 2026-08-10 measured
// the served /app document 938 bytes LARGER than the file on disk, and the difference was
// Cloudflare's JS Detections bootstrap appended before </body>.
//
// That is worth a permanent check rather than a note, because it is the exact scenario
// README.md warns about in "whoever serves the page controls the code": a third party
// modifying the document that holds the decryption keys, silently, in transit. Here it is
// benign bot detection. The mechanism is not benign, and the only thing standing between
// the two is `script-src 'self'` with no nonce and no 'unsafe-inline'.
//
// So this measures the defence, not the injection. The injection may stop or start with a
// dashboard toggle nobody here controls; the CSP must hold either way.

import { check, summary } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';

const ORIGIN = (process.argv[2] || 'https://warpgate.fysh.site').replace(/\/$/, '');

if (!findBrowser()) {
  process.stdout.write('BAD  no Chromium-based browser available\n');
  process.exit(1);
}

let browser;
try {
  browser = await launchBrowser({ port: 9791 });

  // ---------------------------------------------------------------- what is served

  const res = await fetch(`${ORIGIN}/app`, { signal: AbortSignal.timeout(20000) });
  const served = await res.text();
  const injected = /__CF\$cv\$params|challenge-platform/.test(served);

  check('the gate document was fetched over the real path', res.status === 200, `http ${res.status}`);

  // Deliberately NOT asserting that injection is present. If Cloudflare turns JS
  // Detections off tomorrow this file must keep passing, because nothing about Warp Gate
  // got worse. What must never pass is an injected script that RUNS.
  process.stdout.write(`     note: CDN script injection ${injected ? 'IS' : 'is NOT'} present in /app right now\n`);

  const csp = res.headers.get('content-security-policy') || '';
  check('the CSP survived the CDN and still restricts script to this origin',
    /(^|;)\s*script-src\s+'self'\s*(;|$)/.test(csp), csp || '(no CSP header)');
  check('and it grants no blanket inline allowance, which is what would let an injection run',
    !/'unsafe-inline'/.test(csp) && !/'unsafe-eval'/.test(csp), csp || '(no CSP header)');
  check('and no nonce, so an injected tag cannot carry one that happens to match',
    !/'nonce-/.test(csp), csp || '(no CSP header)');

  // ---------------------------------------------------------------- what actually runs
  //
  // The header check above is necessary and not sufficient: it proves the policy is
  // stated, not that the browser enforced it on this document. Load the page for real and
  // ask the document what happened.

  const tab = await browser.newTab(`${ORIGIN}/app`);

  // The bootstrap runs from a DOMContentLoaded handler, so give it every chance to have
  // run before asking. Note that tab.eval wraps what it is given in an async function
  // BODY, so every expression here needs an explicit `return`: without one it evaluates
  // to undefined and every field read off it throws, which reads like a page failure
  // rather than a harness mistake.
  await new Promise((r) => { setTimeout(r, 2000); });

  const violations = await tab.eval(`return ({
    cfGlobal: typeof window.__CF$cv$params,
    injectedIframes: document.querySelectorAll('iframe').length,
  })`);

  // The tell that the inline bootstrap never executed: it sets window.__CF$cv$params
  // inside an iframe it appends, and appends that iframe unconditionally as its first act.
  // If it had run, there would be an iframe. app.html contains none of its own.
  check('the page defines no window.__CF$cv$params, so the injected bootstrap never ran',
    violations.cfGlobal === 'undefined', `typeof = ${violations.cfGlobal}`);
  check('and the iframe that bootstrap appends as its first act is not in the document',
    violations.injectedIframes === 0, `${violations.injectedIframes} iframe(s)`);

  // CONTROL. Everything above passes just as well on a blank page, on a 404, or if the
  // browser never loaded anything at all. Prove the tab is holding the real gate.
  const real = await tab.eval(`return ({
    hasGateScript: !!document.querySelector('script[src*="app.js"]'),
    title: document.title,
    origin: location.origin,
  })`);
  check('CONTROL: the tab is holding the real gate document, not a blank or error page',
    real.hasGateScript && real.origin === ORIGIN, JSON.stringify(real));

  // CONTROL. Prove the "did it run" probe can report the other answer. Execute the same
  // shape of code the injection uses, from a context CSP does allow (the debugger), and
  // confirm the probe sees it. If this does not flip, the probe above is a constant.
  await tab.eval(`
    const f = document.createElement('iframe');
    f.setAttribute('data-control', '1');
    document.body.appendChild(f);
    window.__CF$cv$params = { control: true };
    return true;
  `);
  const after = await tab.eval(`return ({
    cfGlobal: typeof window.__CF$cv$params,
    iframes: document.querySelectorAll('iframe').length,
  })`);
  check('CONTROL: the same probe DOES report a global and an iframe once one exists',
    after.cfGlobal === 'object' && after.iframes === 1, JSON.stringify(after));
} finally {
  if (browser) await browser.close();
}

process.exit(summary(`cdn injection (${ORIGIN})`) ? 0 : 1);
