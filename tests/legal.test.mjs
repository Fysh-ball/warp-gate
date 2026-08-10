// The desktop layout of the policy pages, measured in a real browser.
//
// WHY THIS IS A SEPARATE FILE
//
// tests/browser.test.mjs already checks that these four pages carry the product's type
// language, rule their sections, keep prose to a measure and meet WCAG AA in both
// palettes. What it does not check is the thing that was actually wrong: at 1900px the
// document was a 583px column of prose with 631px of empty background on its left and
// 650px on its right, which is 68% of the window painting nothing. Every one of those
// existing checks passed while that was true, because none of them looks at what the
// window is doing outside the column.
//
// So the assertions here are about the WINDOW, not about the column: how much of it the
// page uses, where the rail is relative to the prose, and whether the rail stays put when
// the page moves. And the one that matters most is the opposite claim: that none of it
// reaches a phone.
//
// PROVING THESE CAN FAIL
//
// Run against a copy of the tree with this change backed out, seventeen of the twenty-four
// checks below report BAD and the file exits 1. That is the evidence that they assert the
// fix rather than describing whatever the page happens to do.
//
// The seven that pass in both states are not evidence of anything on their own, so none of
// them is left to stand alone:
//   - the first check exists only to prove the probe measured four real pages, because
//     every "every page" assertion below is satisfied by an empty list;
//   - the phone geometry guard describes the state the pages were ALREADY in, so it plants
//     a deliberate breakage and requires itself to catch it;
//   - the CSP check plants a style attribute, which the policy refuses, and requires the
//     listener to see it. An empty violation list is also what a listener that was never
//     wired up reports.
import { check, summary, startServer } from './lib/harness.mjs';
import { launchBrowser } from './lib/cdp.mjs';

// Its own ports. These used to be 3788/9764, and 9764 is also motion.test.mjs's DevTools
// port: the runner is sequential so the two never overlapped by design, but an aborted run
// leaves its browser listening, and the next suite on the same port then refuses to attach
// with an error that describes a collision it did not cause. One suite, one port.
const PORT = Number(process.env.WG_LEGAL_PORT || 3789);
const CDP_PORT = Number(process.env.WG_LEGAL_CDP || 9765);
const ORIGIN = `http://127.0.0.1:${PORT}`;
const PAGES = ['privacy', 'terms', 'acceptable-use', 'faq'];

// The window the owner reported the defect from, and a phone.
const DESKTOP = { width: 1900, height: 1000, mobile: false };
const PHONE = { width: 390, height: 844, mobile: true };

// The reading column, in pixels of rendered text.
//
// The floor is above the 583px the page had before, so a tree that never widened the
// measure cannot pass. The ceiling is the same 800px tests/browser.test.mjs already
// enforces, restated here rather than referenced: line length is what makes prose
// readable, and "make the page use the window" must never be allowed to buy width by
// spending it on longer lines.
// The fewest headings a policy page can have and still be a document rather than an empty
// shell. Used where a count is compared against another count, so that zero matching zero
// cannot pass for agreement.
const MIN_SECTIONS = 3;
const PROSE_MIN = 640;
const PROSE_MAX = 800;

// How much of the window either margin may be. Measured before the change: 33.5% and
// 34.5%. This is deliberately NOT the 8% the app screens are held to in
// tests/browser.test.mjs: a policy is a reading page, and prose that ran the width of a
// 1900px window would be unreadable whatever it did to this number. The bar is that the
// page uses a majority of the window it was given.
const DEAD_MAX = 0.26;

// The pre-fix phone rendering, measured at 390x844 before anything here changed, in
// device pixels. Nothing about the desktop layout is allowed to move any of them.
const PHONE_MAIN_WIDTH = 390;
const PHONE_PROSE_WIDTH = 364;
const PHONE_PROSE_LEFT = 13;
const PHONE_PROSE_FONT = '15.5px';

// Registered before the first navigation, so a violation raised while the document is
// still parsing is recorded rather than reported to a document that no longer exists.
const CSP_PROBE = `
  window.__csp = [];
  document.addEventListener('securitypolicyviolation', (e) => {
    window.__csp.push((e.violatedDirective || '?') + ' <- ' + (e.blockedURI || 'inline'));
  });
`;

// Everything the assertions below read, gathered in one pass so that no two checks can
// disagree about what the page looked like at the moment they ran.
const GEOMETRY = `
  const main = document.querySelector('main.legal');
  const nav = document.querySelector('.legal-toc');
  const navShown = Boolean(nav) && getComputedStyle(nav).display !== 'none';
  const nr = navShown ? nav.getBoundingClientRect() : null;
  const win = document.documentElement.clientWidth;

  let prose = 0, proseLeft = Infinity, proseRight = 0, proseTop = Infinity, proseBottom = 0;
  // The font of BODY prose specifically, taken from the first paragraph under the first
  // section heading. Not "the font of the widest p": the mono 12px .doc-meta line is
  // exactly as wide as the column, so widest-wins reports a policy page as being set in
  // 12px and a font regression in the actual prose would never be seen.
  const firstBody = main.querySelector('h2 + p');
  const proseFont = firstBody ? getComputedStyle(firstBody).fontSize : '0px';
  for (const el of main.querySelectorAll('p, li')) {
    if (el.closest('.legal-toc')) continue;
    if (el.classList.contains('eyebrow') || el.classList.contains('doc-foot')) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 2) continue;
    prose = Math.max(prose, r.width);
    proseLeft = Math.min(proseLeft, r.left);
    proseRight = Math.max(proseRight, r.right);
    proseTop = Math.min(proseTop, r.top);
    proseBottom = Math.max(proseBottom, r.bottom);
  }
  if (!isFinite(proseLeft)) { proseLeft = 0; proseTop = 0; }

  const heads = [...main.querySelectorAll('h2')].filter((h) => !h.closest('.legal-toc'));
  const ids = heads.map((h) => h.id);
  const links = [...(nav ? nav.querySelectorAll('.legal-toc-link') : [])];

  const left = nr ? Math.min(nr.left, proseLeft) : proseLeft;
  const right = nr ? Math.max(nr.right, proseRight) : proseRight;

  return JSON.stringify({
    win,
    mainWidth: Math.round(main.getBoundingClientRect().width * 100) / 100,
    prose: Math.round(prose * 100) / 100,
    proseLeft: Math.round(proseLeft * 100) / 100,
    proseTop: Math.round(proseTop * 100) / 100,
    proseBottom: Math.round(proseBottom * 100) / 100,
    proseFont,
    navShown,
    navPresent: Boolean(nav),
    navWidth: nr ? Math.round(nr.width * 100) / 100 : 0,
    navRight: nr ? Math.round(nr.right * 100) / 100 : 0,
    navTop: nr ? Math.round(nr.top * 100) / 100 : 0,
    navBottom: nr ? Math.round(nr.bottom * 100) / 100 : 0,
    navPosition: nav ? getComputedStyle(nav).position : 'absent',
    headCount: heads.length,
    idCount: ids.filter(Boolean).length,
    uniqueIds: new Set(ids.filter(Boolean)).size,
    linkCount: links.length,
    // A link in the rail that points at nothing is worse than no rail: it looks like
    // navigation and does nothing when clicked.
    deadLinks: links.filter((a) => !document.getElementById(decodeURIComponent(a.hash.slice(1)))).length,
    // Reading order: the rail must be reachable before the policy it indexes.
    navBeforeBody: Boolean(nav) && Boolean(main.querySelector('.legal-body'))
      && (nav.compareDocumentPosition(main.querySelector('.legal-body')) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0,
    deadLeft: Math.round(left * 100) / 100,
    deadRight: Math.round((win - right) * 100) / 100,
    csp: window.__csp || [],
  });
`;

const delay = (ms) => new Promise((r) => { setTimeout(r, ms).unref?.(); });

const srv = await startServer({ WG_HTTP_PORT: String(PORT) });
const browser = await launchBrowser({ port: CDP_PORT });

async function open(page, viewport, { scripts = true } = {}) {
  const tab = await browser.newTab('about:blank');
  await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: CSP_PROBE });
  await tab.send('Emulation.setDeviceMetricsOverride', { ...viewport, deviceScaleFactor: 1 });
  if (!scripts) await tab.send('Emulation.setScriptExecutionDisabled', { value: true });
  await tab.send('Page.navigate', { url: `${ORIGIN}/${page}.html` });
  await tab.waitFor("document.readyState === 'complete'", { timeout: 30000, label: `${page} loaded` });
  return tab;
}

const read = async (tab) => JSON.parse(await tab.eval(GEOMETRY));

try {
  // ------------------------------------------------------------------ desktop, 1900x1000
  const desktop = {};
  for (const page of PAGES) {
    const tab = await open(page, DESKTOP);
    desktop[page] = await read(tab);
    desktop[page].tab = tab;
  }

  // The suite has to have measured something. Every "every page" assertion below is
  // satisfied by an empty list, and an empty list is what a broken probe produces.
  check('the desktop pass measured all four policy pages',
    PAGES.every((p) => desktop[p] && desktop[p].win > 1000 && desktop[p].headCount >= 4),
    PAGES.map((p) => `${p}:${desktop[p] && desktop[p].headCount}`).join(' '));

  check('every h2 on every policy page carries a unique id',
    PAGES.every((p) => desktop[p].idCount === desktop[p].headCount
      && desktop[p].uniqueIds === desktop[p].headCount),
    PAGES.map((p) => `${p} ${desktop[p].idCount}/${desktop[p].headCount} ids, ${desktop[p].uniqueIds} unique`).join(' | '));

  check('every page has a sticky rail with one working link per section',
    PAGES.every((p) => desktop[p].navShown
      && desktop[p].navPosition === 'sticky'
      && desktop[p].linkCount === desktop[p].headCount
      && desktop[p].deadLinks === 0),
    PAGES.map((p) => `${p} ${desktop[p].linkCount}/${desktop[p].headCount} links, ${desktop[p].deadLinks} dead, ${desktop[p].navPosition}`).join(' | '));

  check('the rail comes before the policy in the DOM, so it is reachable first',
    PAGES.every((p) => desktop[p].navBeforeBody),
    PAGES.map((p) => `${p}:${desktop[p].navBeforeBody}`).join(' '));

  check(`at 1900x1000 the prose column is between ${PROSE_MIN}px and ${PROSE_MAX}px`,
    PAGES.every((p) => desktop[p].prose >= PROSE_MIN && desktop[p].prose <= PROSE_MAX),
    PAGES.map((p) => `${p} ${desktop[p].prose}px`).join(' | '));

  check(`at 1900x1000 neither margin is more than ${Math.round(DEAD_MAX * 100)}% of the window`,
    PAGES.every((p) => desktop[p].deadLeft <= DEAD_MAX * desktop[p].win
      && desktop[p].deadRight <= DEAD_MAX * desktop[p].win),
    PAGES.map((p) => `${p} ${desktop[p].deadLeft}/${desktop[p].deadRight} of ${desktop[p].win}`).join(' | '));

  // Beside, not above. A rail that has dropped to its own row still satisfies every width
  // measurement above while looking exactly like the phone layout being complained about.
  check('the rail sits beside the prose rather than above it',
    PAGES.every((p) => desktop[p].navShown
      && desktop[p].navRight <= desktop[p].proseLeft
      && desktop[p].navTop < desktop[p].proseBottom
      && desktop[p].proseTop < desktop[p].navBottom),
    PAGES.map((p) => `${p} nav right ${desktop[p].navRight} vs prose left ${desktop[p].proseLeft}`).join(' | '));

  for (const page of PAGES) desktop[page].tab.close();

  // Sticky and current-section, measured after actually moving the page. A rail that is
  // declared sticky but has no room to travel scrolls away with the text, and only a
  // scroll can tell the two apart.
  //
  // Its own tab, brought to the front. getBoundingClientRect forces layout on demand and
  // works in any tab, but an IntersectionObserver callback needs a RENDERING update, and
  // a browser does not render a backgrounded tab. Measured here first: with the other
  // three policy pages still open behind it, the observer never ran, no link was ever
  // marked, and the failure read exactly like a broken highlight rather than like a tab
  // nobody was looking at.
  {
    const tab = await open('privacy', DESKTOP);
    await tab.send('Page.bringToFront', {});
    const scrolled = JSON.parse(await tab.eval(`
      window.scrollTo(0, 1400);
      return JSON.stringify({ y: window.scrollY });
    `));
    await delay(300);
    // Every read below is guarded on the rail existing. A tree without one is exactly the
    // tree these checks are meant to reject, and a probe that throws there aborts the
    // whole file: the six checks after this point would never run and never report, which
    // is indistinguishable from them having passed.
    const after = JSON.parse(await tab.eval(`
      const nav = document.querySelector('.legal-toc');
      const bar = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--bar-h')) || 46;
      const current = document.querySelector('.legal-toc-link[aria-current]');
      const target = current ? document.getElementById(decodeURIComponent(current.hash.slice(1))) : null;
      return JSON.stringify({
        navTop: nav ? Math.round(nav.getBoundingClientRect().top * 100) / 100 : null,
        bar,
        currentText: current ? current.textContent : null,
        // The marked section must be one the reader has actually reached: its heading is
        // at or above the line under the masthead, and the next one is not.
        targetTop: target ? Math.round(target.getBoundingClientRect().top) : null,
      });
    `));
    check('the rail stays under the masthead when the page is scrolled 1400px',
      scrolled.y > 1000 && after.navTop !== null
      && after.navTop >= after.bar && after.navTop <= after.bar + 40,
      `scrolled to ${scrolled.y}, nav top ${after.navTop}, bar ${after.bar}`);
    check('and the rail marks the section actually being read',
      Boolean(after.currentText) && after.targetTop !== null && after.targetTop <= after.bar + 30,
      `current "${after.currentText}" whose heading is at ${after.targetTop}`);
    tab.close();
  }

  // ------------------------------------------------------------------ phone, 390x844
  //
  // The no-change guard. These are the numbers the pages rendered before any of this
  // existed; the desktop layout is not allowed to have moved one of them.
  const phone = {};
  for (const page of PAGES) {
    const tab = await open(page, PHONE);
    phone[page] = await read(tab);
    tab.close();
  }
  check('at 390x844 nothing of the rail is on screen and the column is exactly what it was',
    PAGES.every((p) => phone[p].navPresent && !phone[p].navShown
      && phone[p].mainWidth === PHONE_MAIN_WIDTH
      && phone[p].prose === PHONE_PROSE_WIDTH
      && phone[p].proseLeft === PHONE_PROSE_LEFT
      && phone[p].proseFont === PHONE_PROSE_FONT),
    PAGES.map((p) => `${p} main ${phone[p].mainWidth} prose ${phone[p].prose}@${phone[p].proseLeft} ${phone[p].proseFont} rail shown ${phone[p].navShown}`).join(' | '));

  // That check is a guard, not a proof: it describes the state the pages were already in,
  // so the pre-fix tree passes it too. It makes two separate claims, so plant two separate
  // breakages and require each to be caught on its own. Both plants are CSSOM property
  // writes, which CSP does not police; a style ATTRIBUTE would be refused outright and the
  // plant would silently never happen, which is the failure mode this whole block exists
  // to rule out.
  {
    const tab = await open('privacy', PHONE);

    // Claim one: the column geometry is untouched.
    await tab.eval(`document.documentElement.style.setProperty('--legal-pad', '40px'); return true;`);
    const widened = await read(tab);
    check('and the phone geometry guard catches a padding change planted at phone width',
      widened.prose !== PHONE_PROSE_WIDTH || widened.proseLeft !== PHONE_PROSE_LEFT,
      `prose ${widened.prose}@${widened.proseLeft}, was ${PHONE_PROSE_WIDTH}@${PHONE_PROSE_LEFT}`);
    await tab.eval(`document.documentElement.style.removeProperty('--legal-pad'); return true;`);

    // Claim two: the rail is not on screen. A separate plant, because a check that only
    // ever looked at widths would pass this arm while a rail sat on the phone.
    // Guarded, and the guard is reported rather than swallowed: on a tree with no rail
    // there is nothing to force visible, and "the plant did not happen" must read as a
    // failure to demonstrate the check, not as the check having been demonstrated.
    const planted = await tab.eval(`
      const nav = document.querySelector('.legal-toc');
      if (nav) nav.style.display = 'block';
      return Boolean(nav);
    `);
    const shown = await read(tab);
    check('and the phone rail guard catches a rail forced visible at phone width',
      planted === true && shown.navShown === true,
      `plant ${planted ? 'applied' : 'IMPOSSIBLE: no rail in this tree'}, rail shown ${shown.navShown}`);
    tab.close();
  }

  // ------------------------------------------------------------------ no JavaScript
  //
  // The pages carried no script at all until this change. With the script blocked they
  // must still be the complete, centred, readable document they were.
  {
    const tab = await open('privacy', DESKTOP, { scripts: false });
    const g = await read(tab);
    check('with JavaScript disabled the policy is complete, centred and has no rail',
      // The section count is compared with the count from the scripted pass rather than
      // with a literal. A literal 12 was here first and it went stale the moment the
      // policy gained a section, which is a check failing on correct content: the claim
      // is "the same document, without the script", not "twelve headings forever".
      // MIN_SECTIONS keeps a page that somehow rendered nothing from satisfying it by
      // matching zero against zero.
      !g.navPresent
      && g.headCount === desktop.privacy.headCount && g.headCount >= MIN_SECTIONS
      && g.idCount === g.headCount
      && g.prose >= PROSE_MIN && g.prose <= PROSE_MAX
      && Math.abs(g.deadLeft - g.deadRight) <= 2,
      `rail ${g.navPresent}, ${g.idCount}/${g.headCount} ids `
      + `(scripted ${desktop.privacy.headCount}), prose ${g.prose}, `
      + `margins ${g.deadLeft}/${g.deadRight}`);
    tab.close();
  }

  // ------------------------------------------------------------------ the width ladder
  //
  // One width is one width. The defect being fixed here was a layout that was correct at
  // the width somebody looked at and wrong everywhere else, so the rail has to be checked
  // for appearing when it should, staying beside the prose when it does, and never
  // pushing the page wider than the window.
  //
  // The breakpoint is asserted against the DEVICE width, not the measured client width.
  // Measured here: a 1100px window reports document.documentElement.clientWidth as 1085,
  // because the classic scrollbar is 15px of it, and the rail is on. So `min-width: 1100px`
  // is evaluated against the 1100, and "nothing changes below 1100px" is a claim about the
  // window rather than about the scrollport. Asserting it against clientWidth instead
  // moves the expected breakpoint 15px and fails on a correct layout.
  {
    const tab = await open('privacy', DESKTOP);
    const ladder = [];
    for (const w of [390, 700, 900, 1099, 1100, 1280, 1440, 1600, 1920, 2560]) {
      await tab.send('Emulation.setDeviceMetricsOverride',
        { width: w, height: 1000, deviceScaleFactor: 1, mobile: w < 700 });
      const g = await read(tab);
      const over = await tab.eval('return document.documentElement.scrollWidth - document.documentElement.clientWidth;');
      ladder.push({ w, ...g, over });
    }
    tab.close();
    const row = (r) => `${r.w}(${r.win}) prose ${r.prose} rail ${r.navShown ? r.navWidth : 'off'} over ${r.over}`;

    check('the width ladder measured ten widths from 390 to 2560',
      ladder.length === 10 && ladder.every((r) => r.prose > 100 && r.win > 100),
      ladder.map(row).join(' | '));
    check('no policy page scrolls sideways at any width from 390 to 2560',
      ladder.every((r) => r.over <= 0),
      ladder.filter((r) => r.over > 0).map(row).join(' | ') || 'none');
    check('the rail is on screen exactly when the window is 1100px or wider, and beside the prose whenever it is',
      ladder.every((r) => (r.w >= 1100) === r.navShown)
      && ladder.filter((r) => r.navShown).every((r) => r.navRight <= r.proseLeft),
      ladder.map((r) => `${r.w}(${r.win}):${r.navShown ? 'on' : 'off'}`).join(' '));
    check(`and the reading measure never exceeds ${PROSE_MAX}px at any of them`,
      ladder.every((r) => r.prose <= PROSE_MAX),
      ladder.map((r) => `${r.win}:${r.prose}`).join(' '));
  }

  // ------------------------------------------------ the marked link, in both palettes
  //
  // tests/browser.test.mjs sweeps these pages for contrast in both themes, but it does it
  // at scroll position zero, where no section is current and the marked colour is never
  // painted. So the one state its sweep cannot reach is asserted here: scrolled, marked,
  // and measured against the background actually composited behind it.
  const RATIO = `
    const num = (c) => (c.match(/[0-9.]+/g) || []).map(Number);
    const blend = (fg, bg, a) => fg.map((v, i) => v * a + bg[i] * (1 - a));
    const lum = (rgb) => { const [r, g, b] = rgb.map((v) => {
      const x = v / 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
    }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
    function bgOf(el) {
      const layers = [];
      for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
        const p = num(getComputedStyle(n).backgroundColor);
        const a = p.length > 3 ? p[3] : 1;
        if (p.length >= 3 && a > 0) { layers.push({ rgb: p.slice(0, 3), a }); if (a >= 1) break; }
      }
      if (!layers.length) return [255, 255, 255];
      let out = layers[layers.length - 1].rgb;
      for (let i = layers.length - 2; i >= 0; i -= 1) out = blend(layers[i].rgb, out, layers[i].a);
      return out;
    }
    function ratioOf(el) {
      const p = num(getComputedStyle(el).color);
      const bg = bgOf(el);
      const fg = (p.length > 3 ? p[3] : 1) >= 1 ? p.slice(0, 3) : blend(p.slice(0, 3), bg, p[3]);
      const hi = Math.max(lum(fg), lum(bg));
      const lo = Math.min(lum(fg), lum(bg));
      return Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100;
    }
  `;
  for (const theme of ['dark', 'light']) {
    const tab = await browser.newTab('about:blank');
    await tab.send('Emulation.setDeviceMetricsOverride', { ...DESKTOP, deviceScaleFactor: 1 });
    await tab.send('Emulation.setEmulatedMedia', {
      features: [{ name: 'prefers-color-scheme', value: theme }],
    });
    await tab.send('Page.navigate', { url: `${ORIGIN}/privacy.html` });
    await tab.waitFor("document.readyState === 'complete'", { timeout: 30000, label: `privacy ${theme}` });
    await tab.send('Page.bringToFront', {});
    await tab.eval('window.scrollTo(0, 1400); return true;');
    await delay(300);
    const seen = JSON.parse(await tab.eval(`${RATIO}
      const marked = document.querySelector('.legal-toc-link[aria-current]');
      const plain = document.querySelector('.legal-toc-link:not([aria-current])');
      const title = document.querySelector('.legal-toc-title');
      // Prove the ratio function can report a bad pair, in this palette, on this element:
      // a contrast assertion that has only ever seen readable text is not a check.
      //
      // The wait is not padding. The marked link carries a 0.15s colour transition, and
      // getComputedStyle during a running transition returns the INTERPOLATED value, so
      // reading straight after the write returns the old colour and the planted pair
      // measures as perfectly readable. That is a canary that always reports clean, which
      // is the worst possible outcome for a check whose whole job is to fail.
      const before = marked ? ratioOf(marked) : null;
      if (marked) marked.style.color = getComputedStyle(document.body).backgroundColor;
      await new Promise((r) => setTimeout(r, 260));
      const canary = marked ? ratioOf(marked) : null;
      if (marked) marked.style.color = '';
      return JSON.stringify({
        marked: before,
        plain: plain ? ratioOf(plain) : null,
        title: title ? ratioOf(title) : null,
        canary,
      });
    `));
    tab.close();
    // 13px text, so AA is 4.5:1. No large-text exemption applies anywhere in the rail.
    check(`every state of the rail meets WCAG AA in the ${theme} theme`,
      seen.marked >= 4.5 && seen.plain >= 4.5 && seen.title >= 4.5,
      `current ${seen.marked}, plain ${seen.plain}, title ${seen.title}`);
    check(`and that ${theme} ratio really can report a bad pair`,
      seen.canary !== null && seen.canary < 1.2, `planted pair measured ${seen.canary}`);
  }

  // ------------------------------------------------------------------ reduced motion
  {
    const tab = await browser.newTab('about:blank');
    await tab.send('Emulation.setDeviceMetricsOverride', { ...DESKTOP, deviceScaleFactor: 1 });
    await tab.send('Page.navigate', { url: `${ORIGIN}/privacy.html` });
    await tab.waitFor("document.readyState === 'complete'", { timeout: 30000, label: 'privacy for motion' });
    const durations = async () => JSON.parse(await tab.eval(`
      const link = document.querySelector('.legal-toc-link');
      return JSON.stringify(link ? getComputedStyle(link).transitionDuration : null);
    `));
    const normal = await durations();
    await tab.send('Emulation.setEmulatedMedia', {
      features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
    });
    const reduced = await durations();
    tab.close();
    check('the rail honours prefers-reduced-motion, and had motion to give up',
      typeof normal === 'string' && /0\.1/.test(normal)
      && typeof reduced === 'string' && /^0s(, 0s)*$/.test(reduced),
      `normal ${normal}, reduced ${reduced}`);
  }

  // ------------------------------------------------------------------ CSP
  {
    const violations = [];
    for (const page of PAGES) {
      const tab = await open(page, DESKTOP);
      await delay(150);
      const g = await read(tab);
      if (g.csp.length) violations.push(`${page}: ${g.csp.join(', ')}`);
      tab.close();
    }
    check('the rail raises no Content-Security-Policy violation on any page',
      violations.length === 0, violations.join(' | '));

    // Same problem as the phone guard: an empty violation list is what a listener that
    // was never wired up also reports. Set a style attribute, which style-src 'self'
    // refuses, and require the listener to see it.
    const tab = await open('privacy', DESKTOP);
    const caught = JSON.parse(await tab.eval(`
      document.querySelector('main.legal').setAttribute('style', 'color: red');
      await new Promise((resolve) => setTimeout(resolve, 200));
      return JSON.stringify(window.__csp);
    `));
    check('and that CSP listener catches a planted inline style attribute',
      caught.length === 1 && /style-src/.test(caught[0]), JSON.stringify(caught));
    tab.close();
  }
} finally {
  await browser.close();
  await srv.stop();
}

process.exit(summary('legal pages') ? 0 : 1);
