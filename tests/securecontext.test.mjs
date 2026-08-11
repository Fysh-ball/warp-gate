// What the gate does when the browser has NOT given the page the Web Crypto API.
//
// WHY THIS EXISTS
//
// crypto.subtle is exposed in a secure context only: TLS, or one of the loopback
// addresses. A self-hosted copy reached at http://192.168.x.x therefore serves a
// byte-identical /app whose cryptography is missing. Measured against the quickstart
// container on 2026-08-10, one process and two origins:
//
//   http://127.0.0.1:3095    isSecureContext true   crypto.subtle object
//   http://172.16.34.2:3095  isSecureContext false  crypto.subtle undefined
//
// Both served the same document with the same title. The page renders, the primitive the
// whole product rests on is gone, and before requireSecureContext() the symptom was an
// uncaught TypeError partway through opening a gate. qrscan.js and download.js already
// test isSecureContext and vanish quietly, which made it read as a reduced page rather
// than a broken one.
//
// HOW THE INSECURE CASE IS REPRODUCED
//
// Not by binding a LAN address, which would make this suite depend on the machine having
// one and on which address it got. The condition the code actually reads is
// `globalThis.crypto?.subtle`, so that is what is removed, in a page-init script that runs
// before any module: `subtle` is an accessor on Crypto.prototype and `isSecureContext` one
// on Window.prototype, both configurable, so both are redefined to the values a real
// insecure origin reports. Check 5 asserts the removal actually took, because every
// assertion after it is satisfied by an injection that silently did nothing.
//
// PROVING THESE CAN FAIL
//
// The two runs are each other's control, against the same probe code:
//   - checks 2-4 (banner hidden, buttons live) are asserted on the secure run and their
//     opposites on the insecure run, so neither outcome is what the probe always says;
//   - check 9, "no uncaught TypeError", is the one assertion no second run covers, because
//     it passes trivially in a page that threw nothing at all. So it plants one, by
//     reaching the exact call the pre-fix build reached, and requires the probe to catch
//     it. An empty pageErrors list is also what a listener that was never wired reports.
import { check, summary, startServer, delay, freePort } from './lib/harness.mjs';
import { launchBrowser } from './lib/cdp.mjs';

const PORT = Number(process.env.WG_SECURE_PORT || 0) || await freePort(3793);
const CDP_PORT = Number(process.env.WG_SECURE_CDP || 0) || await freePort(9793);
const ORIGIN = `http://127.0.0.1:${PORT}`;

// The onboarding gate stands in front of every screen. Accepted up front so that what is
// measured below is the home screen and not the agreement overlay.
const AGREE = `try {
  localStorage.setItem('wg.agreed.v1', JSON.stringify({ version: 1, acceptedAt: '2026-01-01T00:00:00.000Z' }));
} catch (err) { void err; }`;

// Exactly what a non-secure origin reports, and nothing else: the goal is a page that
// differs from the run above it in one respect only.
const STRIP_SUBTLE = `
  Object.defineProperty(Crypto.prototype, 'subtle', {
    configurable: true, enumerable: true, get() { return undefined; },
  });
  // On globalThis, not on Window.prototype. Chrome defines isSecureContext as an own
  // property of the global object, so a prototype getter is shadowed and never consulted:
  // the first run of this file redefined the prototype, read back true, and check 5 caught
  // it. That is the whole reason check 5 exists.
  Object.defineProperty(globalThis, 'isSecureContext', {
    configurable: true, enumerable: true, get() { return false; },
  });
`;

const server = await startServer({ WG_HTTP_PORT: String(PORT) });
const browser = await launchBrowser({ port: CDP_PORT });

/** Open /app with the agreement already accepted, optionally with the crypto API removed. */
async function openApp({ strip }) {
  const tab = await browser.newTab('about:blank');
  await tab.send('Page.enable', {});
  await tab.send('Runtime.enable', {});
  // Both scripts run before the document's own modules, which is the only ordering in
  // which removing subtle reproduces the real thing: a page that had it and lost it later
  // is not the failure being tested.
  await tab.send('Page.addScriptToEvaluateOnNewDocument', {
    source: strip ? `${AGREE}\n${STRIP_SUBTLE}` : AGREE,
  });
  await tab.send('Page.navigate', { url: `${ORIGIN}/app` });
  await tab.waitFor("document.readyState === 'complete'", { timeout: 30000, label: '/app loaded' });
  // boot() is async and the banner is written inside it, so readyState is not the signal.
  await delay(900);
  return tab;
}

const READ = `
  const banner = document.getElementById('insecure-warning');
  const create = document.getElementById('create-btn');
  const join = document.getElementById('join-btn');
  return {
    title: document.title,
    hasSubtle: Boolean(globalThis.crypto && globalThis.crypto.subtle),
    secure: globalThis.isSecureContext,
    bannerPresent: Boolean(banner),
    bannerHidden: banner ? banner.hidden : null,
    bannerText: banner ? banner.textContent.replace(/\\s+/g, ' ').trim() : '',
    createDisabled: create ? create.disabled : null,
    joinDisabled: join ? join.disabled : null,
    logText: (document.getElementById('log') || {}).textContent || '',
  };
`;

// ------------------------------------------------------------------ run A, secure origin
const secureTab = await openApp({ strip: false });
const A = await secureTab.eval(READ);

// Guards every "the banner stayed hidden" claim below: an empty or wrong document would
// satisfy them all by having nothing to show.
check('the probe loaded the real gate document', A.title.includes('Warp Gate'), `title ${JSON.stringify(A.title)}`);
check('the insecure-context banner exists in the markup at all', A.bannerPresent === true,
  'no #insecure-warning element, so every assertion about it is vacuous');
check('127.0.0.1 is a secure context and has crypto.subtle',
  A.hasSubtle === true && A.secure === true, `subtle ${A.hasSubtle}, isSecureContext ${A.secure}`);
check('on a secure origin the banner stays hidden', A.bannerHidden === true, `hidden=${A.bannerHidden}`);
check('on a secure origin create and join stay live',
  A.createDisabled === false && A.joinDisabled === false,
  `create disabled=${A.createDisabled}, join disabled=${A.joinDisabled}`);

// ---------------------------------------------------------------- run B, insecure origin
const insecureTab = await openApp({ strip: true });
const B = await insecureTab.eval(READ);

check('the injection actually removed crypto.subtle',
  B.hasSubtle === false && B.secure === false,
  `subtle ${B.hasSubtle}, isSecureContext ${B.secure}: without this every check below is measuring a secure page`);
check('without crypto.subtle the banner is shown', B.bannerHidden === false, `hidden=${B.bannerHidden}`);
check('the banner names the address that caused it', B.bannerText.includes(ORIGIN),
  `banner text did not contain ${ORIGIN}: ${B.bannerText.slice(0, 160)}`);
check('the banner says what the page cannot do',
  /cannot encrypt/i.test(B.bannerText), B.bannerText.slice(0, 160));
check('without crypto.subtle create and join are disabled',
  B.createDisabled === true && B.joinDisabled === true,
  `create disabled=${B.createDisabled}, join disabled=${B.joinDisabled}`);
check('the status log states the cause too',
  /not a secure context/i.test(B.logText), B.logText.slice(-200));

// The regression itself: the pre-fix build reached crypto.js and threw.
const boots = insecureTab.pageErrors.filter((e) => /TypeError/.test(e));
check('the insecure page threw nothing uncaught',
  boots.length === 0, boots.join(' | '));

// CONTROL for the check immediately above. It passes in a page that threw nothing for any
// reason, including a probe that never receives exceptions. So reach the call the old
// build reached, asynchronously (a Runtime.evaluate throw returns to the caller and is
// never reported as an uncaught exception), and require it to be seen.
await insecureTab.eval(`
  setTimeout(() => { globalThis.crypto.subtle.importKey('raw', new Uint8Array(1), 'HKDF', false, ['deriveBits']); }, 0);
  return true;
`);
await delay(500);
const planted = insecureTab.pageErrors.filter((e) => /TypeError/.test(e));
check('CONTROL: the probe does report an uncaught TypeError when one happens',
  planted.length > 0,
  'a planted throw was not captured, so the check above proves nothing about the real boot');

await browser.close();
await server.stop();
process.exit(summary('secure context') ? 0 : 1);
