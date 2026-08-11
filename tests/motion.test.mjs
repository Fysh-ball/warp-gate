// Motion, asserted rather than eyeballed.
//
// Everything here runs against the real server and a real headless browser, and every
// claim is read out of the live document: computed custom properties, live Animation
// objects from document.getAnimations(), and the CSS text the server actually served.
//
// THE TRAP THIS FILE IS BUILT AROUND. document.getAnimations() returns [] both when
// nothing is animating AND when the stylesheet 404'd, failed to parse, or was refused by
// the CSP. Those two states are indistinguishable from inside the page, and every
// "nothing is moving here" assertion below is therefore worthless on its own: a broken
// stylesheet would report the whole suite green. Every such check calls pageAnimates()
// FIRST, which requires the document as a whole to be animating something, and only then
// asks whether one particular element is still.

import { check, summary, startServer, request, delay } from './lib/harness.mjs';
import { launchBrowser, findBrowser } from './lib/cdp.mjs';

const PORT = 3787;
const STUN = 3788;
const CDP_PORT = 9764;
const ORIGIN = `http://127.0.0.1:${PORT}`;
// The gate is a separate document from the landing. Anything about screens, messages or
// the SAS has to be pointed here; anything about the hero, the reveal or the pause
// control has to be pointed at ORIGIN.
const APP = `${ORIGIN}/app`;

if (!findBrowser()) {
  process.stdout.write('BAD  no Chromium-based browser available for motion testing\n');
  process.exit(1);
}

// ---------------------------------------------------------------- page-side helpers
//
// Injected as source into each eval rather than imported, because they run inside the
// browser. Kept in one string so a change lands in every check at once.

/**
 * Everything document.getAnimations() knows, flattened into plain JSON.
 *
 * `effect.getKeyframes()` is where the compositor-only audit gets its property list: the
 * keys of a computed keyframe are the properties the animation will actually write, minus
 * the four bookkeeping fields the API adds to every one of them.
 */
const ANIM_FNS = `
  const BOOKKEEPING = new Set(['offset', 'computedOffset', 'easing', 'composite']);
  function describe(a) {
    const t = a.effect ? a.effect.getTiming() : {};
    let props = [];
    try {
      for (const frame of a.effect.getKeyframes()) {
        for (const key of Object.keys(frame)) if (!BOOKKEEPING.has(key)) props.push(key);
      }
    } catch (err) { props = ['<unreadable: ' + err.message + '>']; }
    return {
      name: a.animationName || (a.transitionProperty ? 'transition:' + a.transitionProperty : '?'),
      playState: a.playState,
      duration: typeof t.duration === 'number' ? t.duration : String(t.duration),
      iterations: t.iterations === Infinity ? 'Infinity' : t.iterations,
      props,
      target: a.effect && a.effect.target
        ? (a.effect.target.id || a.effect.target.className || a.effect.target.tagName)
        : null,
    };
  }
  function allAnimations() { return document.getAnimations().map(describe); }
  /** The guard. Nothing may conclude "still" from a page that animates nothing at all. */
  function pageAnimates() { return document.getAnimations().length; }
  function animationsOn(sel) {
    const el = document.querySelector(sel);
    if (!el) return null;
    return el.getAnimations({ subtree: false }).map(describe);
  }
  /** Is anything from this element up to body currently RUNNING an animation? */
  function ancestorsMoving(sel) {
    const el = document.querySelector(sel);
    if (!el) return null;
    const moving = [];
    for (let n = el; n && n !== document.documentElement; n = n.parentElement) {
      for (const a of n.getAnimations({ subtree: false })) {
        if (a.playState === 'running') {
          moving.push((n.id || n.className || n.tagName) + ':' + (a.animationName || a.transitionProperty));
        }
      }
    }
    return moving;
  }
`;

/** Walk every same-origin stylesheet rule and hand back the ones matching a predicate. */
const SHEET_FNS = `
  function eachRule(visit) {
    for (const sheet of document.styleSheets) {
      let rules;
      // A cross-origin sheet throws on .cssRules. There are none here, and if one ever
      // appears this must say so rather than silently measuring a smaller set.
      try { rules = sheet.cssRules; } catch (err) { visit({ selectorText: '<unreadable>', cssText: err.message }); continue; }
      const walk = (list) => {
        for (const rule of list) {
          visit(rule);
          if (rule.cssRules) walk(rule.cssRules);
        }
      };
      walk(rules);
    }
  }
`;

const agreeInPage = `
  localStorage.setItem('wg.agreed.v1', JSON.stringify({ version: 1, acceptedAt: new Date().toISOString() }));
  sessionStorage.setItem('wg.dismissed.v1:net-modal', '1');
  return true;
`;

const server = await startServer({
  WG_HTTP_PORT: String(PORT),
  WG_STUN_PORT: String(STUN),
  WG_STUN_URL: `stun:127.0.0.1:${STUN}`,
  WG_CREATE_PER_WINDOW: '200',
  WG_JOIN_PER_WINDOW: '200',
  WG_REJECT_PER_WINDOW: '500',
  WG_PUBLIC_GET_PER_WINDOW: '500',
});

const browser = await launchBrowser({ port: CDP_PORT });
check('headless browser launched', Boolean(browser.version), browser.version);

async function openTab(url, { reduce = false, width = 1440, height = 900 } = {}) {
  const tab = await browser.newTab('about:blank');
  await tab.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  if (reduce) {
    await tab.send('Emulation.setEmulatedMedia', {
      features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
    });
  }
  await tab.send('Page.navigate', { url });
  await tab.waitFor("document.readyState === 'complete'", { timeout: 30000, label: `loaded ${url}` });
  // A tab in the background does not advance CSS animations in Chromium, so every timing
  // and playState assertion below would be measuring the browser's occlusion policy
  // rather than the page.
  await tab.send('Page.bringToFront', {});
  return tab;
}

try {
  // ============================================================== 1. the tokens exist
  const land = await openTab(ORIGIN);

  const tokens = JSON.parse(await land.eval(`
    const cs = getComputedStyle(document.documentElement);
    const read = (n) => cs.getPropertyValue(n).trim();
    return JSON.stringify({
      micro: read('--motion-micro'), small: read('--motion-small'),
      medium: read('--motion-medium'), large: read('--motion-large'),
      enter: read('--ease-enter'), exit: read('--ease-exit'), standard: read('--ease-standard'),
      rise: read('--reveal-rise'), press: read('--press-scale'), fold: read('--fold-scale'),
    });
  `));
  check('the motion scale resolves: four durations from the M3 tokens',
    tokens.micro === '100ms' && tokens.small === '150ms'
    && tokens.medium === '250ms' && tokens.large === '300ms', JSON.stringify(tokens));
  check('and three easing curves, none of them empty',
    tokens.enter.startsWith('cubic-bezier') && tokens.exit.startsWith('cubic-bezier')
    && tokens.standard.startsWith('cubic-bezier'), JSON.stringify(tokens));
  check('the three tokens the reduced-motion branch rewrites are at their full values',
    tokens.rise === '8px' && tokens.press === '0.985' && tokens.fold === '0.94',
    `${tokens.rise} / ${tokens.press} / ${tokens.fold}`);

  // ============================================================== 4. the no-JS safety net
  //
  // Over the CSS the SERVER SERVES, not over the file on disk and not over the CSSOM: the
  // question is what a browser with a dead script receives. `html.js-reveal` is what makes
  // .u-reveal invisible, and landing.js adds that class only after the observer exists. An
  // unscoped rule would leave every section at opacity 0 forever the moment the script
  // failed for any reason at all.
  const cssText = (await request(PORT, 'GET', '/css/style.css')).text;
  const scoped = (cssText.match(/html\.js-reveal\s+\.u-reveal\s*\{\s*opacity:\s*0/g) ?? []).length;
  const bare = (cssText.match(/^\s*\.u-reveal\s*\{\s*opacity:\s*0/gm) ?? []).length;
  check('the reveal start state is scoped to html.js-reveal, exactly once',
    scoped === 1, `${scoped} scoped occurrences`);
  check('and .u-reveal is never given opacity 0 unscoped, so a dead script shows everything',
    bare === 0, `${bare} bare occurrences`);
  // The regexes have to be able to find something, or "0 bare occurrences" is equally
  // consistent with a regex that matches nothing anywhere.
  check('CONTROL: the bare-rule regex does match an unscoped rule when there is one',
    /^\s*\.u-reveal\s*\{\s*opacity:\s*0/gm.test('.u-reveal { opacity: 0; }'));
  check('CONTROL: the served stylesheet is a real stylesheet, not an error page',
    cssText.length > 20000 && cssText.includes('@keyframes wg-rise'), `${cssText.length} bytes`);

  // ============================================================== 5. the hero is exempt
  const heroExempt = JSON.parse(await land.eval(`
    return JSON.stringify({
      h1: document.querySelector('.lp-h1').closest('.u-reveal') === null,
      preview: document.querySelector('.lp-preview').closest('.u-reveal') === null,
      forLine: document.querySelector('.lp-for-line').closest('.u-reveal') === null,
      enrolled: document.querySelectorAll('.u-reveal').length,
    });
  `));
  check('nothing in the hero is enrolled in the reveal: the LCP element is not faded in',
    heroExempt.h1 && heroExempt.preview && heroExempt.forLine, JSON.stringify(heroExempt));
  check('but the reveal did enrol something, so the exemption means something',
    heroExempt.enrolled > 10, `${heroExempt.enrolled} elements enrolled`);

  // ============================================================== 2. a section reveals
  const revealed = JSON.parse(await land.eval(ANIM_FNS + `
    const el = document.getElementById('how-it-works');
    el.scrollIntoView({ block: 'center' });
    // Two frames, which is what an IntersectionObserver needs to deliver and the class to
    // take effect. No layout is read here to force it: the observer is the clock.
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    return JSON.stringify({ anims: animationsOn('#how-it-works'), total: pageAnimates() });
  `));
  check('scrolling a section into view starts a wg-rise animation on it',
    revealed.anims.some((a) => a.name === 'wg-rise'), JSON.stringify(revealed.anims));
  check('and it is 250ms of the medium token, not some other number',
    revealed.anims.some((a) => a.name === 'wg-rise' && a.duration === 250),
    JSON.stringify(revealed.anims));

  // ============================================================== 10. compositor-only audit
  //
  // The standing regression guard. Every property any live animation will write, checked
  // against the set that does not cost a layout. Sampled here, while the reveal is in
  // flight, because that is when the page has the most animations running at once.
  const SAFE = ['transform', 'opacity', 'color', 'backgroundColor', 'borderColor', 'filter'];
  // ONE named exemption, and it is named rather than folded into SAFE so that a second
  // animation reaching for the same property still fails this check. The header sweep
  // slides a gradient along a 1px strip: background-position costs a paint and no layout,
  // it is landing-only, and it is behind the pause control. Widening SAFE instead would
  // have quietly permitted it everywhere.
  const PAINT_EXEMPT = ['backgroundPositionX', 'backgroundPositionY'];
  // The set with the teeth. Nothing may ever animate a property that forces layout, and
  // no exemption applies to any of these.
  const NEVER = ['height', 'width', 'top', 'left', 'right', 'bottom', 'margin', 'marginTop',
    'padding', 'paddingTop', 'flexBasis', 'boxShadow', 'inset', 'fontSize', 'lineHeight'];
  const audit = JSON.parse(await land.eval(ANIM_FNS + `
    const sc = document.querySelector('.page') || document.scrollingElement;
    sc.scrollTop = sc.scrollHeight;
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const anims = allAnimations();
    const props = new Set();
    for (const a of anims) for (const p of a.props) props.add(p);
    return JSON.stringify({ count: anims.length, props: [...props] });
  `));
  check('the compositor-only audit had animations to look at',
    audit.count > 0, `${audit.count} animations`);
  check('every property any live animation writes is compositor-safe, bar one named exemption',
    audit.count > 0 && audit.props.every((p) => SAFE.includes(p) || PAINT_EXEMPT.includes(p)),
    JSON.stringify(audit.props));
  check('and nothing anywhere animates a property that forces layout',
    audit.count > 0 && audit.props.every((p) => !NEVER.includes(p)),
    JSON.stringify(audit.props.filter((p) => NEVER.includes(p))));
  check('CONTROL: the layout-property guard does reject one when it sees it',
    ['transform', 'height'].some((p) => NEVER.includes(p)) === true);

  // The same audit over the stylesheet's @keyframes, which is where a `height` would be
  // introduced. This one does not depend on an animation happening to be running.
  const kf = JSON.parse(await land.eval(SHEET_FNS + `
    const found = {};
    eachRule((rule) => {
      if (!rule.name || !rule.cssRules || rule.type !== CSSRule.KEYFRAMES_RULE) return;
      const props = new Set();
      for (const frame of rule.cssRules) {
        for (const p of frame.style) props.add(p);
      }
      found[rule.name] = [...props];
    });
    return JSON.stringify(found);
  `));
  // Same rule, same one exemption, spelled in CSS property names because that is what a
  // CSSKeyframeRule reports. `sweep` is the only block allowed to name background-position.
  const KF_SAFE = ['transform', 'opacity'];
  const KF_EXEMPT = { sweep: ['background-position-x', 'background-position-y'] };
  const kfBad = Object.entries(kf).filter(([name, props]) =>
    props.some((p) => !KF_SAFE.includes(p) && !(KF_EXEMPT[name] ?? []).includes(p)));
  check('every @keyframes in the stylesheet animates a compositor-safe property',
    kfBad.length === 0, JSON.stringify(kfBad));
  check('CONTROL: the @keyframes audit rejects a planted height frame',
    [['bogus', ['height']]].filter(([name, props]) =>
      props.some((p) => !KF_SAFE.includes(p) && !(KF_EXEMPT[name] ?? []).includes(p))).length === 1);
  check('CONTROL: the @keyframes walk found the blocks it is auditing',
    Object.keys(kf).length >= 4 && 'wg-rise' in kf, JSON.stringify(Object.keys(kf)));

  // ============================================================== 3. the reveal settles
  const settled = JSON.parse(await land.eval(`
    await new Promise((r) => setTimeout(r, 1600));
    const el = document.getElementById('how-it-works');
    return JSON.stringify({
      opacity: getComputedStyle(el).opacity,
      stillMarked: el.classList.contains('u-reveal') || el.classList.contains('is-in'),
      delay: el.style.animationDelay,
      leftOver: document.querySelectorAll('.u-reveal').length,
    });
  `));
  check('a revealed section ends at opacity 1 with its reveal classes taken back off',
    settled.opacity === '1' && settled.stillMarked === false && settled.delay === '',
    JSON.stringify(settled));

  // ============================================================== 11. exactly one will-change
  const wills = JSON.parse(await land.eval(SHEET_FNS + `
    const out = [];
    eachRule((rule) => {
      if (!rule.style) return;
      if (rule.style.getPropertyValue('will-change')) out.push(rule.selectorText);
    });
    return JSON.stringify(out);
  `));
  check('the stylesheet declares exactly one will-change, and it is on .lp-flip-box',
    wills.length === 1 && wills[0] === '.lp-flip-box', JSON.stringify(wills));

  // ============================================================== 15. SC 2.2.2
  //
  // The direct machine reading of Pause, Stop, Hide: after using the control, no animation
  // that repeats forever may still be running. This expression reported BAD against the
  // pre-change tree, where the header sweep and the bridge flow were ungated.
  const beforeToggle = JSON.parse(await land.eval(ANIM_FNS + `
    return JSON.stringify(allAnimations().filter((a) => a.iterations === 'Infinity'));
  `));
  check('the landing does have a perpetual animation to stop, before it is stopped',
    beforeToggle.length > 0, JSON.stringify(beforeToggle));

  const afterToggle = JSON.parse(await land.eval(ANIM_FNS + `
    document.getElementById('motion-toggle').click();
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const running = document.getAnimations()
      .filter((a) => a.playState === 'running' && a.effect.getTiming().iterations === Infinity);
    return JSON.stringify({
      motion: document.documentElement.dataset.motion,
      pressed: document.getElementById('motion-toggle').getAttribute('aria-pressed'),
      label: document.getElementById('motion-toggle').textContent,
      running: running.length,
      total: pageAnimates(),
    });
  `));
  check('the pause control sets data-motion=off and reports its own state',
    afterToggle.motion === 'off' && afterToggle.pressed === 'true'
    && /resume/i.test(afterToggle.label), JSON.stringify(afterToggle));
  check('and no animation repeating forever is still running: SC 2.2.2 satisfied',
    afterToggle.running === 0, JSON.stringify(afterToggle));

  // The flipper is driven by a timer, not by CSS, so the check above cannot see it. This
  // one does: with motion paused the word must not change.
  const wordBefore = await land.eval("return document.querySelector('.lp-flip-face').textContent;");
  await delay(5200);
  const wordAfter = await land.eval("return document.querySelector('.lp-flip-face').textContent;");
  check('the timer-driven hero word does not change while motion is paused',
    wordBefore === wordAfter && wordBefore.length > 0, `${wordBefore} -> ${wordAfter}`);

  const resumed = JSON.parse(await land.eval(`
    document.getElementById('motion-toggle').click();
    return JSON.stringify({
      motion: document.documentElement.dataset.motion ?? null,
      pressed: document.getElementById('motion-toggle').getAttribute('aria-pressed'),
      stored: (() => { try { return localStorage.getItem('wg.motion.v1'); } catch (err) { return 'threw: ' + err.message; } })(),
    });
  `));
  check('and the control is a toggle, not a one-way switch, and it persists',
    resumed.motion === null && resumed.pressed === 'false' && resumed.stored === 'on',
    JSON.stringify(resumed));

  // ============================================================== 17c. the donation address
  // Click, then WAIT ON THE MODAL, then settle. The 600ms below used to do both jobs, and
  // it stopped being able to: support.js fetches the QR encoder on first use now, so
  // opening the lightbox spans a module load. Locally that lands in a few milliseconds and
  // the suite passed alone; under the full run it did not, and the failure read as "the
  // lightbox did not open" rather than "the test looked too early". The sleep is kept
  // because it is doing the other job, letting the open transition finish before anything
  // asks what is still animating, but it is no longer what decides the modal is up.
  await land.eval(`document.querySelector('[data-qr="xmr"]').click(); return true;`);
  await land.waitFor("!document.getElementById('qr-modal').hidden",
    { timeout: 15000, label: 'the donation lightbox opened' });
  const addrStill = JSON.parse(await land.eval(ANIM_FNS + `
    await new Promise((r) => setTimeout(r, 600));
    return JSON.stringify({
      total: pageAnimates(),
      addr: animationsOn('.qr-modal-addr'),
      canvas: animationsOn('.qr-modal-paper canvas'),
      pixelated: getComputedStyle(document.querySelector('.qr-modal-paper canvas')).imageRendering,
      shown: !document.getElementById('qr-modal').hidden,
    });
  `));
  check('the QR lightbox opened, so this is measuring something that is on screen',
    addrStill.shown === true && addrStill.total > 0, JSON.stringify(addrStill).slice(0, 200));
  check('a crypto address is never animated: no reveal, no stagger, no typewriter',
    Array.isArray(addrStill.addr) && addrStill.addr.length === 0, JSON.stringify(addrStill.addr));
  check('and the QR canvas is neither transformed nor faded, and stays pixelated',
    Array.isArray(addrStill.canvas) && addrStill.canvas.length === 0
    && addrStill.pixelated === 'pixelated', JSON.stringify(addrStill));

  land.close();

  // ============================================================== 12/13/14. reduced motion
  //
  // The pair that implementations get wrong in opposite directions. This block fails if
  // reduced motion REMOVES too much; check 15 above fails if the default case removes too
  // little. Both have to hold at once.
  const quiet = await openTab(ORIGIN, { reduce: true });

  const quietTokens = JSON.parse(await quiet.eval(`
    const cs = getComputedStyle(document.documentElement);
    return JSON.stringify({
      rise: cs.getPropertyValue('--reveal-rise').trim(),
      press: cs.getPropertyValue('--press-scale').trim(),
      fold: cs.getPropertyValue('--fold-scale').trim(),
      medium: cs.getPropertyValue('--motion-medium').trim(),
    });
  `));
  check('under reduce, the three travel tokens collapse and the durations do not',
    quietTokens.rise === '0px' && quietTokens.press === '1' && quietTokens.fold === '1'
    && quietTokens.medium === '250ms',
    JSON.stringify(quietTokens));

  const quietReveal = JSON.parse(await quiet.eval(ANIM_FNS + `
    const el = document.getElementById('how-it-works');
    el.scrollIntoView({ block: 'center' });
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const during = animationsOn('#how-it-works');
    await new Promise((r) => setTimeout(r, 1600));
    return JSON.stringify({ during, opacity: getComputedStyle(el).opacity });
  `));
  check('REDUCED MEANS REDUCED: the reveal animation still exists under reduce',
    quietReveal.during.some((a) => a.name === 'wg-rise'), JSON.stringify(quietReveal.during));
  check('it is a fade with the travel taken out, not a removal',
    quietReveal.during.some((a) => a.name === 'wg-rise' && a.props.includes('opacity')),
    JSON.stringify(quietReveal.during));
  check('and the section still ends visible, which a blanket animation:none would break',
    quietReveal.opacity === '1', quietReveal.opacity);

  const quietFlip = JSON.parse(await quiet.eval(ANIM_FNS + `
    const first = document.querySelector('.lp-flip-face').textContent;
    const anims = animationsOn('#flipbox');
    await new Promise((r) => setTimeout(r, 6000));
    return JSON.stringify({
      anims,
      running: (animationsOn('#flipbox') || []).filter((a) => a.playState === 'running').length,
      first,
      second: document.querySelector('.lp-flip-face').textContent,
    });
  `));
  check('under reduce the hero word is pinned: no running animation on the flip box',
    quietFlip.running === 0, JSON.stringify(quietFlip.anims));
  check('and it is the SAME word six seconds later, not a perpetual crossfade',
    quietFlip.first === quietFlip.second && quietFlip.first.length > 0,
    `${quietFlip.first} -> ${quietFlip.second}`);

  const quietPress = JSON.parse(await quiet.eval(SHEET_FNS + `
    const found = [];
    eachRule((rule) => {
      if (!rule.selectorText || !rule.style) return;
      if (!/button:active/.test(rule.selectorText)) return;
      if (rule.style.getPropertyValue('filter')) found.push(rule.selectorText + ' -> ' + rule.style.getPropertyValue('filter'));
    });
    return JSON.stringify(found);
  `));
  check('with the press scale collapsed, the press says it in luminance instead',
    quietPress.length === 1 && /brightness/.test(quietPress[0]), JSON.stringify(quietPress));

  quiet.close();

  // ============================================================== the gate document
  const app = await openTab(APP);
  await app.eval(agreeInPage);
  await app.send('Page.reload', {});
  await app.waitFor("document.readyState === 'complete'", { timeout: 30000, label: 'gate reloaded' });
  await app.send('Page.bringToFront', {});
  await app.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'home screen' });

  // ============================================================== 16. no perpetual loop here
  //
  // The gate is where somebody reads the SAS words aloud and compares them with another
  // human. Nothing on it may loop forever in peripheral vision, and #extras (which holds
  // the bridge illustration) is on screen on this very screen, so this is measuring it.
  const gateLoops = JSON.parse(await app.eval(ANIM_FNS + `
    return JSON.stringify({
      extrasShown: !document.getElementById('extras').hidden,
      infinite: allAnimations().filter((a) => a.iterations === 'Infinity'),
    });
  `));
  check('the gate shows the extras block, so the bridge is in scope for this check',
    gateLoops.extrasShown === true, JSON.stringify(gateLoops).slice(0, 160));
  check('and the gate at rest runs no animation that repeats forever',
    gateLoops.infinite.length === 0, JSON.stringify(gateLoops.infinite));

  // ============================================================== 18. progress is untouched
  const prog = await app.eval(`
    const p = document.createElement('progress');
    p.max = 100; p.value = 40;
    document.getElementById('screen-home').appendChild(p);
    const d = getComputedStyle(p).transitionDuration;
    p.remove();
    return d;
  `);
  check('a <progress> bar carries no transition, so it never reports a stale number',
    prog === '0s', String(prog));

  // ============================================================== 19. one copy of the number
  const appSrc = (await request(PORT, 'GET', '/js/app.js')).text;
  check('the gate script no longer holds its own copy of the fade duration',
    !appSrc.includes('DONATE_FADE_MS'), 'DONATE_FADE_MS is back');
  check('it reads the fade out of the --motion-small token instead',
    /FADE_MS\s*=\s*parseFloat\([\s\S]{0,200}--motion-small/.test(appSrc));
  const jsFade = await app.eval(`
    return parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--motion-small'));
  `);
  check('and that token is the 150ms the modal transition uses',
    jsFade === 150, String(jsFade));
  check('CONTROL: the DONATE_FADE_MS probe does fire on the old form',
    'const DONATE_FADE_MS = 180;'.includes('DONATE_FADE_MS'));

  // ============================================================== 6. screen entrance
  //
  // Driven through the real button, not by poking show(): what is being asserted is that
  // the app's own screen change animates, and calling an internal would assert something
  // else. localStorage was cleared above so onboarding is shown again.
  await app.eval("localStorage.removeItem('wg.agreed.v1'); return true;");
  await app.send('Page.reload', {});
  await app.waitFor("!document.getElementById('screen-onboarding').hidden",
    { timeout: 30000, label: 'onboarding back' });
  await app.send('Page.bringToFront', {});
  const entrance = JSON.parse(await app.eval(ANIM_FNS + `
    const c = document.getElementById('agree-check');
    c.checked = true;
    c.dispatchEvent(new Event('change', { bubbles: true }));
    document.getElementById('onboarding-done').click();
    return JSON.stringify({ anims: animationsOn('#screen-home'), total: pageAnimates() });
  `));
  check('pressing Continue gives the home screen an entrance',
    entrance.anims.some((a) => a.name === 'wg-rise-sm'), JSON.stringify(entrance.anims));
  check('and it runs for the 300ms large token, the tier a whole screen gets',
    entrance.anims.some((a) => a.name === 'wg-rise-sm' && a.duration === 300),
    JSON.stringify(entrance.anims));

  // ============================================================== 7. the screens with no entrance
  //
  // Source side: the set itself. A live check cannot reach #screen-failed without a real
  // connection failure, so the membership is asserted where it is decided, and the regex
  // is proved against a deliberately broken copy of the same line.
  const enteringLine = (/const ENTERING = new Set\(\[[^\]]*\]\)/.exec(appSrc) ?? [''])[0];
  check('CONTROL: the ENTERING set was found in the served script',
    enteringLine.length > 0, appSrc.slice(0, 0) || 'not found');
  const notEntering = ['failed', 'severed', 'password'];
  check('no screen reporting a bad outcome, and no screen holding up an action, gets an entrance',
    notEntering.every((n) => !enteringLine.includes(`'${n}'`)), enteringLine);
  const brokenLine = enteringLine.replace("'connected'", "'connected', 'failed'");
  check('CONTROL: the same test reports BAD when failed is added to the set',
    notEntering.some((n) => brokenLine.includes(`'${n}'`)) === true, brokenLine);

  // ============================================================== 7b. the gate's drawers
  //
  // Connection details and Games are the only disclosures on this site that get opened and
  // shut repeatedly, and they were the only motion on the connected screen that was still a
  // snap in one direction: a 150ms fade in, nothing at all on the way out. Both halves are
  // measured here, and the closing half is the one with a mechanism behind it. A <details>
  // shuts natively between two frames, so app.js preventDefaults the summary click, marks
  // the panel and lets wg-fold run before setting `open = false`. What must be true is that
  // the panel is STILL OPEN while that runs, and that it ends closed anyway.
  const drawer = JSON.parse(await app.eval(`
    for (const s of document.querySelectorAll('section.screen')) s.hidden = s.id !== 'screen-connected';
    const disc = document.getElementById('games-disc');
    const body = disc.querySelector('.disc-body');
    const summary = disc.querySelector('summary');
    const mine = () => (document.getAnimations ? document.getAnimations() : [])
      .filter((a) => a.effect && a.effect.target === body);
    const frame = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const settle = async () => {
      await Promise.all(mine().map((a) => a.finished.catch((err) => { void err; })));
      await frame();
    };

    disc.open = false;
    await frame();

    summary.click();
    await frame();
    const opening = { open: disc.open, marked: disc.classList.contains('is-opening'), running: mine().length };
    await settle();

    summary.click();
    await frame();
    const closing = { open: disc.open, marked: disc.classList.contains('is-closing'), running: mine().length };
    await settle();
    // Past the 500ms backstop as well, so "it closed" cannot be the timer rescuing a
    // listener that never fired without that being visible in the numbers above.
    await new Promise((r) => setTimeout(r, 600));
    const shut = { open: disc.open, marked: disc.classList.contains('is-closing') };
    return JSON.stringify({ opening, closing, shut });
  `));
  check('a gate drawer opens with an animation rather than a snap',
    drawer.opening.open === true && drawer.opening.marked === true && drawer.opening.running >= 1,
    JSON.stringify(drawer.opening));
  check('and it is held open while it folds shut, instead of disappearing in one frame',
    drawer.closing.open === true && drawer.closing.marked === true && drawer.closing.running >= 1,
    JSON.stringify(drawer.closing));
  check('and it does end closed, with nothing left marked on it',
    drawer.shut.open === false && drawer.shut.marked === false, JSON.stringify(drawer.shut));

  // An invitation is the one thing in that drawer that arrives without being asked for,
  // and it may arrive into a panel that just opened itself. It gets the same 4px rise a
  // message landing in the transcript gets, ONCE: a re-render for an unrelated notice
  // replaying it would make the motion mean nothing.
  const inviteArrival = JSON.parse(await app.eval(`
    const [play, ui] = await Promise.all([import('/js/gameplay.js'), import('/js/gameui.js')]);
    const area = document.getElementById('game-area');
    const games = new play.GameSession({ send: async () => true });
    const gameUi = new ui.GameUI({
      root: area,
      games,
      partners: () => [{ peer: 'peer-them', label: 'Their Device' }],
      onNotice: () => {},
    });
    area.replaceChildren();
    gameUi.render();
    await games.receive('peer-them', { t: 'invite', mid: 'aaaa000000000002', game: 'chess', seat: 'w' });
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const row = () => area.querySelector('.game-row.game-status');
    const running = (el) => (document.getAnimations ? document.getAnimations() : [])
      .filter((a) => a.effect && a.effect.target === el).length;
    const first = { found: Boolean(row()), marked: row() ? row().classList.contains('is-arriving') : null,
                    running: row() ? running(row()) : 0 };
    gameUi.render();
    const second = { found: Boolean(row()), marked: row() ? row().classList.contains('is-arriving') : null };
    return JSON.stringify({ first, second });
  `));
  check('an invitation arriving in the Games drawer is animated in',
    inviteArrival.first.found === true && inviteArrival.first.marked === true
    && inviteArrival.first.running >= 1, JSON.stringify(inviteArrival.first));
  check('and a re-render of the same invitation does not replay the arrival',
    inviteArrival.second.found === true && inviteArrival.second.marked === false,
    JSON.stringify(inviteArrival.second));

  app.close();

  // ============================================================== 8, 9, 17. a live gate
  //
  // Two tabs, a real WebRTC connection, a real message. Everything below needs an actual
  // data channel: a message arriving is the one cue that a message arrived, and the SAS
  // words only exist once two devices have derived them.
  const a = await openTab(APP);
  await a.eval(agreeInPage);
  await a.send('Page.reload', {});
  await a.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'tab A home' });
  await a.send('Page.bringToFront', {});
  await a.eval("document.getElementById('create-btn').click(); return true;");
  await a.waitFor("!document.getElementById('screen-waiting').hidden", { timeout: 30000, label: 'tab A waiting' });
  await a.eval("document.getElementById('reveal-share').click(); return true;");
  await a.waitFor("document.getElementById('share-shown').hidden === false", { timeout: 20000, label: 'share panel' });
  const code = await a.eval("return document.getElementById('room-code').textContent.trim();");
  check('a gate was opened and its code read off the page',
    /^WARP(-[A-Z]{4,7}){8}$/.test(code), code);

  // Straight to the invite link. The onboarding flag is in localStorage, which tab A
  // already set and which the whole profile shares, so this joins from the link. The IP
  // exposure notice is per TAB (sessionStorage) and stands in front of a link-join too,
  // so it is answered through its own button rather than pre-dismissed: navigating this
  // tab a second time to set storage would be a fragment-only change, which does not
  // reload the document at all.
  const b = await openTab(`${APP}#${code}`);
  await b.waitFor("!document.getElementById('net-modal').hidden",
    { timeout: 25000, label: 'the exposure notice on the link-join' });
  await b.eval("document.getElementById('net-continue').click(); return true;");
  await a.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 40000, label: 'tab A connected' });
  await b.waitFor("!document.getElementById('screen-connected').hidden", { timeout: 40000, label: 'tab B connected' });
  await a.send('Page.bringToFront', {});

  // -------------------------------------------------- 8. a message arrives, visibly
  //
  // Observed with a MutationObserver installed BEFORE the send, so the animation is read
  // off the node as it is added. Polling afterwards would sample a 150ms animation at an
  // arbitrary point and report absence as often as presence.
  const arrival = JSON.parse(await a.eval(ANIM_FNS + `
    const list = document.getElementById('messages');
    const seen = new Promise((resolve) => {
      const mo = new MutationObserver((records) => {
        for (const rec of records) {
          for (const node of rec.addedNodes) {
            if (!(node instanceof HTMLElement) || !node.classList.contains('msg')) continue;
            mo.disconnect();
            resolve({ classes: node.className, anims: node.getAnimations({ subtree: false }).map(describe) });
            return;
          }
        }
      });
      mo.observe(list, { childList: true });
      setTimeout(() => { mo.disconnect(); resolve({ classes: '<timed out>', anims: [] }); }, 8000);
    });
    document.getElementById('chat-input').value = 'motion probe';
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    const got = await seen;
    return JSON.stringify(got);
  `));
  check('a message arriving in the list is marked as new',
    /\bis-new\b/.test(arrival.classes), arrival.classes);
  check('and it fades in over the 150ms small token, rising 4px rather than 8',
    arrival.anims.some((x) => x.name === 'wg-rise-sm' && x.duration === 150),
    JSON.stringify(arrival.anims));

  // -------------------------------------------------- 9. the burst guard, for real
  // Sending is asynchronous (the row is appended after the frame has been encrypted and
  // handed to the data channel), so counting straight after the loop counts nothing. The
  // observer records each row AS IT IS INSERTED, which is the only moment the arrival
  // class is guaranteed to still be on it, and the insertion times come back too so a
  // "3 of 10" result cannot be mistaken for three separate 200ms windows.
  //
  // The quiet wait below is load bearing and was added after a flake: 10 added, 5 marked,
  // span 104ms. The guard's window is anchored to the PREVIOUS arrival, not to the burst,
  // so a burst well inside 200ms can still straddle a boundary and get two allowances.
  // Waiting out a full window first makes the burst's own first row reset it, which is the
  // only way "3 of 10" is a fact about the guard rather than about scheduling.
  const guarded = JSON.parse(await a.eval(`
    await new Promise((r) => setTimeout(r, 400));
    const form = document.getElementById('chat-form');
    const input = document.getElementById('chat-input');
    const list = document.getElementById('messages');
    const rows = [];
    const mo = new MutationObserver((records) => {
      for (const rec of records) {
        for (const node of rec.addedNodes) {
          if (node instanceof HTMLElement && node.classList.contains('msg')) {
            rows.push({ marked: node.classList.contains('is-new'), at: performance.now() });
          }
        }
      }
    });
    mo.observe(list, { childList: true });
    for (let i = 0; i < 10; i += 1) {
      input.value = 'burst ' + i;
      form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    }
    await new Promise((r) => setTimeout(r, 2500));
    mo.disconnect();
    const times = rows.map((r) => r.at);
    return JSON.stringify({
      added: rows.length,
      marked: rows.filter((r) => r.marked).length,
      spanMs: times.length ? Math.round(Math.max(...times) - Math.min(...times)) : 0,
    });
  `));
  check('ten rows in one burst all land in the list',
    guarded.added === 10, JSON.stringify(guarded));
  check('and they land inside one burst window, so the count below is measuring the guard',
    guarded.spanMs < 200, JSON.stringify(guarded));
  check('but exactly three of them are animated: a burst is not information',
    guarded.marked === 3, JSON.stringify(guarded));

  // -------------------------------------------------- 17. the security surfaces stand still
  //
  // The SAS words and the gate code are read aloud and compared between two humans, or
  // typed into a second device. Any fade, slide, scale or reflow while one is being read
  // raises the question "did that just change?", and the security model cannot answer it.
  //
  // Sampled WHILE something else on the page is animating, deliberately. Waiting for the
  // page to go quiet and then reporting "the SAS is still" would be true of a page whose
  // stylesheet never loaded, and the guard below would pass on it. A message is sent so
  // that there is live motion in the document at the instant the SAS is measured.
  const still = JSON.parse(await a.eval(ANIM_FNS + `
    document.getElementById('chat-input').value = 'still probe';
    document.getElementById('chat-form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    // Poll for the arrival rather than sleeping a guessed interval: the sample has to land
    // inside the 150ms the row is animating for.
    for (let i = 0; i < 200 && document.getAnimations().length === 0; i += 1) {
      await new Promise((r) => requestAnimationFrame(r));
    }
    const out = { total: pageAnimates(), sasText: (document.getElementById('sas') || {}).textContent || '' };
    for (const sel of ['#sas', '.sas-box', '#room-code', '.code']) {
      out[sel] = { own: animationsOn(sel), ancestors: ancestorsMoving(sel) };
    }
    return JSON.stringify(out);
  `));
  check('CONTROL: the page is animating something, so "still" is a measurement',
    still.total > 0, `${still.total} animations on the page`);
  check('and the SAS is actually showing, so this is not measuring an empty element',
    still.sasText.trim().length > 2 && still.sasText !== '-----', still.sasText);
  for (const sel of ['#sas', '.sas-box', '#room-code', '.code']) {
    const entry = still[sel];
    check(`${sel} carries no animation of its own`,
      entry && Array.isArray(entry.own) && entry.own.length === 0, JSON.stringify(entry?.own));
    check(`and nothing from ${sel} up to the root is moving under it`,
      entry && Array.isArray(entry.ancestors) && entry.ancestors.length === 0,
      JSON.stringify(entry?.ancestors));
  }

  // -------------------------------------------------- 7 live. a screen with no entrance
  //
  // Burning the gate goes through the same show() the home screen went through, so this
  // is the real code path deciding that 'severed' gets no entrance.
  await a.eval("document.getElementById('sever').click(); return true;");
  await a.waitFor("!document.getElementById('screen-severed').hidden", { timeout: 20000, label: 'severed screen' });
  const severed = JSON.parse(await a.eval(ANIM_FNS + `
    return JSON.stringify({
      anims: animationsOn('#screen-severed'),
      dataEnter: document.getElementById('screen-severed').hasAttribute('data-enter'),
      total: pageAnimates(),
    });
  `));
  check('the burned-gate screen arrives with no entrance at all',
    severed.anims.length === 0 && severed.dataEnter === false, JSON.stringify(severed));
  // The control for it: the rule exists and would have fired had the set said so.
  const wouldHave = JSON.parse(await a.eval(ANIM_FNS + `
    const el = document.getElementById('screen-severed');
    el.dataset.enter = '';
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const anims = animationsOn('#screen-severed');
    delete el.dataset.enter;
    return JSON.stringify(anims);
  `));
  check('CONTROL: adding data-enter to that same screen DOES animate it, so the absence means something',
    wouldHave.some((x) => x.name === 'wg-rise-sm'), JSON.stringify(wouldHave));

  // -------------------------------------------------- 20. nothing delays input
  //
  // #create-btn is the gate's "open a gate". The INP budget is 200ms; the guard is that no
  // animation on the press path has been allowed to become input delay.
  const inp = await openTab(APP);
  await inp.eval(agreeInPage);
  await inp.send('Page.reload', {});
  await inp.waitFor("!document.getElementById('screen-home').hidden", { timeout: 30000, label: 'INP tab home' });
  await inp.send('Page.bringToFront', {});
  const inpResult = JSON.parse(await inp.eval(`
    const seen = [];
    const po = new PerformanceObserver((list) => {
      for (const e of list.getEntries()) seen.push({ name: e.name, duration: e.duration });
    });
    po.observe({ type: 'event', durationThreshold: 16, buffered: true });
    document.getElementById('create-btn').click();
    await new Promise((r) => setTimeout(r, 1200));
    po.disconnect();
    const worst = seen.reduce((m, e) => Math.max(m, e.duration), 0);
    return JSON.stringify({ worst, count: seen.length, seen: seen.slice(0, 6) });
  `));
  check('pressing the gate button costs well under the 200ms INP budget',
    inpResult.worst < 200, JSON.stringify(inpResult));
  inp.close();
  a.close();
  b.close();
} finally {
  await browser.close();
  await server.stop();
}

process.exit(summary('motion') ? 0 : 1);
