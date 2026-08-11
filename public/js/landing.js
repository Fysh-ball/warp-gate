/**
 * Landing page behaviour. This is the ONLY script the landing document loads.
 *
 * The landing and the gate are separate documents (index.html and app.html) and this
 * file is the boundary. It knows nothing about rooms, keys or peers, it imports only
 * ./support.js and ./qr.js through it, and it must stay that way: the landing is the
 * document that may one day carry a sponsor slot, and the whole point of the split is
 * that such a document never shares a script context with the one holding a key.
 *
 * If any of it fails the landing is still readable and every link still works.
 */

// Two imports rather than one since 2026-08-10: the donation panel is the landing's alone
// (app.html has no cards and no modal markup), while the source link is a licence obligation
// both documents carry. Splitting them is what took the panel off the gate's load path.
import { wireSupport } from './support.js';
import { applySourceLink, instanceKind } from './common.js';

// Links minted before the split were `/#WARP-...`, and they are printed on QR codes
// and pasted into chats that nobody can go back and edit. The fragment never reaches
// the server, so this hands it to the gate document client-side and leaves no entry
// in history to go back to. location.replace, not assignment: Back must return to
// wherever the link was followed from, not bounce off this page forever.
//
// Matched against the shape generateGateCode() actually mints, NOT against "there is a
// fragment". This page has its own anchors, and faq.html links to `/#support`: a
// blanket redirect threw anyone following that link into the gate. Recognising the
// prefix here rather than importing parseSecret keeps landing.js free of crypto.js;
// a fragment this rejects is simply left alone, and an anchor is the safe direction
// to be wrong in.
if (/^#WARP-/i.test(location.hash)) {
  location.replace(`/app${location.hash}`);
}

// The hero's eyebrow is static copy written for the canonical host, so a self-hosted
// copy served it verbatim and told every visitor it was "the only official instance".
// Same classification the gate document uses for its instance disclosure, from common.js.
{
  const brow = document.querySelector('.lp-hero-brow');
  const kind = instanceKind();
  if (brow && kind !== 'official') {
    brow.textContent = kind === 'local'
      ? `${location.hostname}\u00a0/\u00a0your own copy`
      : `${location.hostname}\u00a0/\u00a0not the official instance`;
  }
}

const WORDS = [
  'Friends', 'Sysadmins', 'Regular people', 'Family', 'Photographers',
  'Yourself', 'Roommates', 'Freelancers', 'Journalists', 'Students',
  'Small teams', 'Your other laptop', 'Musicians', 'Whoever',
];

const FLIP_MS = 2400;

// The word was drawn by walking WORDS in order, so every visit recited the same list from
// the same place: the first four were the only ones most people ever saw, and the last few
// needed half a minute of staring to reach. Draw from a shuffled bag instead. Every word
// comes up once before any of them comes up twice, which pure random does not give you,
// and the order is different on each load.
let bag = [];
function nextWord(previous) {
  if (!bag.length) {
    bag = WORDS.slice();
    for (let i = bag.length - 1; i > 0; i -= 1) {
      const j = Math.floor(Math.random() * (i + 1));
      [bag[i], bag[j]] = [bag[j], bag[i]];
    }
    // A bag refills without knowing what the old one ended on, and that seam is the one
    // place the same word can still land twice running. Push it to the back of the queue.
    if (bag.length > 1 && bag[bag.length - 1] === previous) {
      [bag[bag.length - 1], bag[0]] = [bag[0], bag[bag.length - 1]];
    }
  }
  return bag.pop();
}

// ------------------------------------------------------- the pause control (SC 2.2.2)
//
// WCAG SC 2.2.2, Pause Stop Hide, is LEVEL A, and this page had two failures of it. The
// flipper is "moving information lasting more than five seconds" (four words, 2.4s each,
// forever). The hero preview is "auto-updating information", which has no five-second
// grace at all. Both loops already returned early on a hidden tab, which is a good
// instinct and is NOT a 2.2.2 mechanism: it is not reachable by the user and it does
// nothing while the tab is on screen.
//
// One button, one attribute on <html>, covering both loops and the header sweep. The CSS
// side is `html[data-motion="off"]`; the JS side is loopsOff(), because no stylesheet can
// stop a setInterval from rewriting a transform.
const MOTION_KEY = 'wg.motion.v1';
const motionMq = window.matchMedia('(prefers-reduced-motion: reduce)');

/**
 * Is the OS asking for less motion, RIGHT NOW?
 *
 * A function rather than a boolean, and this is the whole point. Two places in this file
 * used to read `.matches` once at module load and close over the result, so somebody who
 * turned the setting on mid-visit kept the hero tumbling until they reloaded the page.
 */
const motionReduced = () => motionMq.matches;

/** Should a perpetual loop sit this beat out? Read live, on every tick, never cached. */
const loopsOff = () => document.documentElement.dataset.motion === 'off' || motionReduced();

function armMotionToggle() {
  const btn = document.getElementById('motion-toggle');
  if (!btn) return;

  let stored = null;
  try {
    stored = localStorage.getItem(MOTION_KEY);
  } catch (err) {
    // Private mode throws on the read as well as on the write. A preference that cannot
    // be persisted must still be settable for this visit, so this is a warning and not a
    // reason to leave the control unwired.
    console.warn(`[warp gate] could not read the motion preference: ${err.message}`);
  }

  const apply = (off) => {
    if (off) document.documentElement.dataset.motion = 'off';
    else delete document.documentElement.dataset.motion;
    btn.setAttribute('aria-pressed', off ? 'true' : 'false');
    btn.textContent = off ? 'Resume motion' : 'Pause motion';
  };

  apply(stored === 'off');

  btn.addEventListener('click', () => {
    const off = document.documentElement.dataset.motion !== 'off';
    apply(off);
    try {
      localStorage.setItem(MOTION_KEY, off ? 'off' : 'on');
    } catch (err) {
      console.warn(`[warp gate] could not save the motion preference: ${err.message}`);
    }
  });
}

armMotionToggle();

const shell = document.getElementById('flipper');
const box = document.getElementById('flipbox');

// Nothing to do on the legal pages, which share this stylesheet but not the hero.
if (shell && box && box.children.length === 4) {
  const faces = Array.prototype.slice.call(box.children);

  // Which quarter turn the cube is on, and half its height. Both live out here because
  // size() and the flip timer each need to write the box transform and neither may drop
  // the other's half of it. Declared before size() runs: `let` in the same block is in
  // its temporal dead zone until this line executes, so a reference from size() called
  // above would throw rather than read a stale zero.
  let step = 0;
  let depth = 0;

  /**
   * The box transform, written in one place.
   *
   * `translateZ(-depth)` is not decoration and it is the reason the word stopped being
   * clipped on its left edge. The faces sit on the surface of a cube of half-height
   * `depth`, each pushed out by `translateZ(depth)`. With the box itself at z=0 the front
   * face therefore sat `depth` px NEARER the viewer than the perspective origin, and a
   * 800px perspective magnifies that by 800/(800-depth): about 3.2% at hero size. The
   * clip box is not magnified, so the face grew out of it symmetrically, roughly 5px past
   * each edge, and clip-path ate the first glyph. Pushing the box back by the same depth
   * puts the front face exactly at z=0, where the scale factor is 1.
   */
  function setAngle() {
    box.style.transform = `translateZ(${-depth}px) rotateX(${step * 90}deg)`;
  }

  /**
   * Give the box one fixed height and one fixed width, so neither the headline
   * nor the line below it moves when the word changes.
   *
   * The height comes from the FONT SIZE, not from offsetHeight. offsetHeight
   * inherits the body's 1.55 line-height, which sized the box to the line box
   * and left the word floating high inside it. The faces are then centred by
   * setting line-height equal to that height, so the height IS the line box.
   *
   * The width is measured against the widest word in the list rather than the
   * word currently on show, for the same reason: a box that resizes per word
   * drags the rest of the line with it every 2.4 seconds.
   */
  function size() {
    const cs = window.getComputedStyle(faces[0]);
    const fontPx = parseFloat(cs.fontSize) || 24;

    const probe = document.createElement('span');
    // CSSOM, not a style attribute: the CSP forbids the latter, not this.
    // Padding 0, matching .lp-flip-face. If these two ever disagree the box is measured
    // against a width the word does not have, and the flipper's overflow:hidden clips
    // the last glyph of the longest word.
    probe.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;padding:0;left:-9999px;top:0';
    probe.style.fontFamily = cs.fontFamily;
    probe.style.fontSize = cs.fontSize;
    probe.style.fontWeight = cs.fontWeight;
    probe.style.letterSpacing = cs.letterSpacing;
    // `normal`, so the probe reports the height the FONT wants for a line rather than the
    // height this page happens to have asked for. That number is what the clip box has to
    // clear, and it is not derivable from the font size: for the stack in use here it came
    // out at 50px against a 36.5px font, a ratio of 1.371.
    probe.style.lineHeight = 'normal';
    document.body.appendChild(probe);

    let w = 0;
    let natural = 0;
    try {
      for (const word of WORDS) {
        probe.textContent = word;
        const r = probe.getBoundingClientRect();
        w = Math.max(w, Math.ceil(r.width));
        natural = Math.max(natural, Math.ceil(r.height));
      }
    } finally {
      probe.remove();
    }

    // WHY THIS IS NOT `fontPx * 1.34` ANY MORE. It was, and it cut the descender off the
    // "y" in "Sysadmins". 1.34em is below what the font itself reserves for a line, so the
    // glyph box overhung the clip box by half a pixel at each end and clip-path took it.
    // The measured line box is the floor; +2 is slack for the fractional rect. The old
    // constant stays as a lower bound so a browser that reports a mean `normal` height
    // cannot shrink the box below what it used to be.
    const h = Math.max(Math.round(fontPx * 1.34), natural + 2);

    // +4, not +12: the old slack covered the frame's padding and border, which are gone.
    // Some slack has to stay, because getBoundingClientRect returns a fractional width
    // and overflow:hidden clips on the rounded-down integer.
    shell.style.width = `${w + 4}px`;
    shell.style.height = `${h}px`;
    // The strut in ::before shares this line height, which is what lines the rotating
    // word up with the "For" beside it: the faces sit in a line box of exactly h at the
    // top of the shell, so the strut's baseline and theirs are the same line.
    shell.style.lineHeight = `${h}px`;
    box.style.height = `${h}px`;
    box.style.width = '100%';
    // The depth is layout, not motion, so it is written with the transition off: at load
    // the box would otherwise interpolate from `none` to `translateZ(-h/2)`, which is a
    // 3% zoom-out over 620ms that nobody asked for, and a resize would replay it. The
    // reflow read in between is what makes `none` apply to this write rather than to the
    // whole pair. Only the quarter turns the timer writes are meant to be seen moving.
    const keep = box.style.transition;
    box.style.transition = 'none';
    depth = h / 2;
    setAngle();
    void box.offsetHeight;
    box.style.transition = keep;
    for (let i = 0; i < faces.length; i += 1) {
      const face = faces[i];
      face.style.width = '100%';
      face.style.height = `${h}px`;
      face.style.lineHeight = `${h}px`;
      face.style.transform = `rotateX(${i * -90}deg) translateZ(${h / 2}px)`;
    }
  }

  size();

  // Coalesce to one measurement per frame. size() does fourteen text measurements
  // through a real DOM node, and a drag-resize fires this far faster than it paints.
  let queued = 0;
  window.addEventListener('resize', () => {
    if (queued) return;
    queued = requestAnimationFrame(() => { queued = 0; size(); });
  });

  for (let i = 0; i < faces.length; i += 1) faces[i].textContent = nextWord(null);

  const flipTimer = setInterval(() => {
    // Reduced motion is a standing preference, not a pause, so the timer goes away for
    // good and the word already on show is the word that stays. What used to happen was
    // worse than nothing: the stylesheet swapped the tumble for a 300ms crossfade and
    // this loop kept swapping the text every 2.4 seconds forever, so a reduced-motion
    // visitor got a perpetual loop with the amplitude turned down rather than a stop.
    // #lp-preview below has always done the right thing here; this now matches it.
    if (motionReduced()) { clearInterval(flipTimer); return; }
    // The button, by contrast, is reversible: skip the beat and keep the timer, so
    // pressing it again picks the tumble back up where it left off.
    if (loopsOff()) return;
    // No point tumbling a box on a screen nobody is looking at.
    if (document.visibilityState !== 'visible') return;

    step += 1;
    setAngle();
    // Re-label the face that is currently behind the box, one quarter turn ahead
    // of where it will be needed, so the swap is never visible.
    const incoming = (step + 1) % faces.length;
    faces[incoming].textContent = nextWord(faces[step % faces.length].textContent);
  }, FLIP_MS);
}

// ----------------------------------------------------- hero gate preview
//
// The panel in the hero is a picture of a gate in use, and a still one was doing that
// badly: every number in it was frozen at a value nobody could have arrived at, which
// reads as a screenshot of a mockup rather than as a thing that runs. This drives the
// same panel through one short session on a loop: the gate is opened, the other device
// joins, three messages land, a file goes across, and a fresh gate replaces it.
//
// It is decorative, and it is deliberately cheap. ONE timer at 200ms drives all of it,
// it returns immediately on a tab nobody is looking at, and the per-tick work is one
// transform plus at most three short strings, each skipped when its value has not
// changed. The bar moves by transform: scaleX and never by width, so a bar advancing
// is a composite rather than a relayout of everything under it.
//
// Nothing here is required for the page to make sense. The markup in index.html is one
// coherent frame of this loop, so with this file dead, or with reduced motion asked
// for, the panel is still a picture of a gate rather than an empty box.

const gate = document.getElementById('lp-preview');

if (gate) {
  const el = {
    badge: document.getElementById('lp-badge'),
    code: document.getElementById('lp-code'),
    chat: document.getElementById('lp-chat'),
    typing: document.getElementById('lp-typing'),
    wait: document.getElementById('lp-wait'),
    pct: document.getElementById('lp-pct'),
    fill: document.getElementById('lp-fill'),
    state: document.getElementById('lp-state'),
    clock: document.getElementById('lp-clock'),
    meter: gate.querySelector('.lp-preview-meter'),
  };
  const msgs = el.chat
    ? Array.prototype.slice.call(el.chat.querySelectorAll('.lp-msg:not(.lp-msg-typing)'))
    : [];
  const dots = el.typing
    ? Array.prototype.slice.call(el.typing.querySelectorAll('.lp-dot'))
    : [];

  // Every id and both counts, or nothing runs. A loop that half-finds its own markup
  // would leave the panel in a state no frame of the script describes, which is worse
  // than the still picture it started as.
  const complete = Object.values(el).every(Boolean) && msgs.length === 3 && dots.length === 3;
  // Read once HERE on purpose: this decides which of two shapes the panel takes, a loop
  // or the settled final frame, and that is a construction-time choice. Every LATER read
  // goes through loopsOff() inside the tick, so the setting changing mid-visit stops the
  // loop rather than waiting for a reload.
  const noMotion = motionReduced();

  // One cycle, as milliseconds from the top of it. Named rather than inlined because
  // three of them are read by the renderer as well as by the script below.
  const TICK_MS = 200;
  const CYCLE_MS = 17600;
  const PAIRED_AT = 2400;
  const TRANSFER_FROM = 5800;
  const TRANSFER_TO = 13200;
  // The seam. Timing the fade to land exactly on the wrap was tried and traced, and it
  // does not hold: setInterval jitters, so the content was swapping at half opacity in
  // full view. The fade is given a clear 600ms of slack instead, and the badge goes back
  // to Connecting as it starts. The frames in the middle are then an empty panel labelled
  // "GATE / CONNECTING", which is not a broken half-state at all: it is exactly what a
  // gate looks like in the seconds after you press "Open a gate".
  const STACK_FADE_MS = 400;
  const FADE_AT = CYCLE_MS - 1000;

  // Where the countdown starts before anyone has joined. Five minutes is what an
  // unclaimed gate actually gets (server/config.js, ttl.unclaimedMs), and this is the
  // only clock on the panel that counts DOWN: it measures how long the invitation
  // stays open, not how long the conversation is allowed to last.
  const INVITE_OPEN_S = 4 * 60 + 58;

  // Two codes, alternating, so the restart reads as a second gate rather than as the
  // first one stuttering.
  const CODES = [
    'WARP-DRIFT-MEAD-PLUNK-SIXTH-TOTE-VIVID-WHALE-ZONAL',
    'WARP-AMBER-CRISP-MAPLE-KETTLE-MARBLE-VELVET-WALNUT-WIDGET',
  ];

  if (complete && !noMotion) {
    // The three blocks that fade out together at the end of a cycle. The head row is
    // left alone: the label and the badge belong to the panel, not to the session
    // inside it, and a panel that empties completely reads as a page still loading.
    const stack = [el.code, el.chat, el.meter];

    el.chat.style.position = 'relative';
    el.typing.style.position = 'absolute';
    el.typing.style.left = '0';
    el.typing.style.opacity = '0';
    // Hidden in the markup so a dead script leaves no dots behind; from here the
    // indicator is driven by opacity alone, which costs no layout.
    el.typing.hidden = false;
    // Centred over the whole conversation block rather than given a row: the block's
    // height is three messages and must stay three messages whatever is on show.
    el.wait.style.position = 'absolute';
    el.wait.style.left = '0';
    el.wait.style.right = '0';
    el.wait.style.top = '50%';
    el.wait.style.transform = 'translateY(-50%)';
    el.wait.style.opacity = '0';
    el.wait.hidden = false;
    // The width and the origin used to be set here, undoing a `width: 62%` the stylesheet
    // had just applied: two mechanisms disagreeing about who owns the bar, with the
    // script always winning the argument one frame later. The stylesheet states scaleX
    // now, so there is nothing left to take back and this loop only moves the number.
    for (const node of stack) node.style.transition = `opacity ${STACK_FADE_MS}ms ease`;

    let elapsed = 0;
    // -1 so the FIRST reset re-prints the code that is already in the markup. Starting at
    // 0 made the loop's opening move a visible swap to the other code, at full opacity,
    // in the first 200ms of the page: the one frame a visitor is guaranteed to be looking
    // at. Traced, not guessed.
    let cycle = -1;
    // 1, not 0: reset() is called directly below, so the beat at 0 has already run. Left
    // at 0 the first tick ran it a second time and swapped the code again.
    let step = 1;
    let lastClock = '';
    let lastPct = '';
    let lastLit = -1;
    let typing = false;

    function setStack(value) {
      for (const node of stack) node.style.opacity = value;
    }

    /**
     * Put motion back on the pieces reset() froze.
     *
     * Called on a beat of its own, a second before anything uses it, and never at the
     * bottom of reset(). A transition installed in the same frame as the value
     * it is meant to animate simply does not run: there is no earlier computed style
     * for the element to move away from. Separating them in time is the fix that does
     * not require reading layout back to force a reflow.
     */
    function armMotion() {
      el.fill.style.transition = `transform ${TICK_MS}ms linear`;
      el.typing.style.transition = 'opacity 200ms ease';
      el.wait.style.transition = 'opacity 340ms ease';
      for (const msg of msgs) msg.style.transition = 'opacity 340ms ease, transform 340ms ease';
    }

    function hideTyping() {
      el.typing.style.opacity = '0';
      typing = false;
    }

    function reset() {
      cycle += 1;
      el.code.textContent = CODES[cycle % CODES.length];
      el.badge.className = 'badge badge-work';
      el.badge.textContent = 'Connecting';
      el.state.textContent = 'invite open';
      el.pct.textContent = 'waiting';
      lastPct = 'waiting';
      lastClock = '';

      // Everything goes back to the top of the session with motion switched OFF. This
      // runs while the stack is still faded out, and the two things a viewer must never
      // catch are a progress bar rewinding and the previous conversation fading away
      // underneath the new gate fading in.
      el.fill.style.transition = 'none';
      el.fill.style.transform = 'scaleX(0)';
      for (const msg of msgs) {
        msg.style.transition = 'none';
        msg.style.opacity = '0';
        msg.style.transform = 'translateY(4px)';
      }
      el.typing.style.transition = 'none';
      el.wait.style.transition = 'none';
      el.wait.style.opacity = '1';
      hideTyping();
      setStack('1');
    }

    function pair() {
      el.badge.className = 'badge badge-direct';
      el.badge.textContent = 'Direct P2P';
      el.state.textContent = 'connected';
      el.pct.textContent = 'queued';
      lastPct = 'queued';
      // The gate has a second device in it now, so the line that said it was waiting for
      // one is the first thing that stops being true.
      el.wait.style.opacity = '0';
    }

    /**
     * Park the typing indicator over the slot the next message is about to fill.
     *
     * Not appended to the end of the list, because every message is already in the
     * flow: an indicator that took a row of its own would either sit in the wrong
     * place or change the height of the panel, and the panel's height is the one
     * thing in the hero that must not move. offsetTop is read here, twice a cycle,
     * and never from inside the tick.
     */
    function typeInto(index) {
      el.typing.style.top = `${msgs[index].offsetTop}px`;
      el.typing.style.opacity = '1';
      typing = true;
      lastLit = -1;
    }

    function land(index) {
      hideTyping();
      msgs[index].style.opacity = '1';
      msgs[index].style.transform = 'none';
    }

    // The end of the loop. The badge moves first so that the frames where the body is
    // gone are labelled with a state that explains them.
    function closeGate() {
      el.badge.className = 'badge badge-work';
      el.badge.textContent = 'Connecting';
      setStack('0');
    }

    function beginTransfer() {
      el.pct.textContent = '0%';
      lastPct = '0%';
    }

    function endTransfer() {
      el.fill.style.transform = 'scaleX(1)';
      el.pct.textContent = 'sent';
      lastPct = 'sent';
    }

    // A real transfer is not a straight line: it ramps, holds a rate, loses it for a
    // moment, and then finishes. Constant speed is the clearest tell that a progress
    // bar is decoration, so this one is drawn through keypoints instead.
    const CURVE = [[0, 0], [0.10, 0.09], [0.42, 0.41], [0.53, 0.44], [0.86, 0.87], [1, 1]];

    function progressAt(ms) {
      const t = (ms - TRANSFER_FROM) / (TRANSFER_TO - TRANSFER_FROM);
      if (t <= 0) return 0;
      if (t >= 1) return 1;
      for (let i = 1; i < CURVE.length; i += 1) {
        if (t > CURVE[i][0]) continue;
        const [x0, y0] = CURVE[i - 1];
        const [x1, y1] = CURVE[i];
        return y0 + ((t - x0) / (x1 - x0)) * (y1 - y0);
      }
      return 1;
    }

    function mmss(seconds) {
      return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
    }

    // The script. One list of beats, read in order, so the shape of the session is
    // legible in one place rather than spread across a pile of nested timeouts that
    // would each have to be cancelled on a hidden tab.
    const BEATS = [
      { at: 0, run: reset },
      // Its own beat, a full second before anything uses it, for the reason armMotion
      // explains: a transition and the value it animates cannot land in one frame.
      { at: 1400, run: armMotion },
      { at: PAIRED_AT, run: pair },
      { at: 2800, run: () => typeInto(0) },
      { at: 4000, run: () => land(0) },
      { at: 5400, run: () => land(1) },
      { at: TRANSFER_FROM, run: beginTransfer },
      { at: 8800, run: () => typeInto(2) },
      { at: 9900, run: () => land(2) },
      { at: TRANSFER_TO, run: endTransfer },
      { at: FADE_AT, run: closeGate },
    ];

    function render() {
      // Down to the moment the other device arrives, up from there. Counting UP after
      // pairing is the honest direction: once the two browsers are talking directly
      // there is no clock running the conversation out, and a number falling towards
      // zero would say there is.
      const clock = elapsed < PAIRED_AT
        ? mmss(INVITE_OPEN_S - Math.floor(elapsed / 1000))
        : mmss(Math.floor((elapsed - PAIRED_AT) / 1000));
      if (clock !== lastClock) {
        el.clock.textContent = clock;
        lastClock = clock;
      }

      if (elapsed >= TRANSFER_FROM && elapsed < TRANSFER_TO) {
        const done = progressAt(elapsed);
        const pct = `${Math.round(done * 100)}%`;
        if (pct !== lastPct) {
          el.pct.textContent = pct;
          lastPct = pct;
        }
        el.fill.style.transform = `scaleX(${done.toFixed(4)})`;
      }

      if (typing) {
        const lit = Math.floor(elapsed / 220) % dots.length;
        if (lit !== lastLit) {
          for (let i = 0; i < dots.length; i += 1) dots[i].style.opacity = i === lit ? '1' : '0.3';
          lastLit = lit;
        }
      }
    }

    reset();
    render();

    setInterval(() => {
      // The pause control, and the live reduced-motion read. Freezing mid-cycle is a
      // correct resting state for this panel: every frame of the loop is a picture of a
      // gate in some stage of use, which is what the markup is on its own.
      if (loopsOff()) return;
      // Same rule the flipper follows: nothing moves on a screen nobody is looking at.
      if (document.visibilityState !== 'visible') return;

      // Advanced by the tick rather than read off the wall clock. A tab that spent a
      // minute in the background comes back exactly where it was left instead of
      // jumping into the middle of a transfer nobody watched start.
      elapsed += TICK_MS;
      if (elapsed >= CYCLE_MS) {
        elapsed = 0;
        step = 0;
      }
      while (step < BEATS.length && BEATS[step].at <= elapsed) {
        BEATS[step].run();
        step += 1;
      }
      render();
    }, TICK_MS);
  } else if (complete) {
    // Reduced motion was asked for, so the panel settles into the frame the loop would
    // have ended on and no timer is ever created. The messages and the badge are
    // already right in the markup; only the meter has a mid-transfer value to finish.
    el.pct.textContent = 'sent';
    // The stylesheet already owns the width, the origin and a starting scaleX(0.62), and
    // sets `transition: none` on this element under reduced motion, so the bar arrives at
    // its final length in one frame rather than growing into it.
    el.fill.style.transform = 'scaleX(1)';
    el.state.textContent = 'connected';
    el.clock.textContent = 'live';
  }
}

// ------------------------------------------------------------- scroll reveal
//
// Sections rise 8px and fade in as they come into view, once each, and then the machinery
// takes itself apart.
//
// The failure model is the important part. `html.js-reveal` is what makes .u-reveal
// invisible, this is the only place that class is ever added, and it is added LAST, after
// the observer exists and every target has been enrolled. A dead script, a module the CSP
// refused, a parse error above this line, or a browser with no IntersectionObserver all
// leave the page fully painted. The failure mode is "no reveal", never "no content",
// which is the only acceptable direction for a decoration that starts at opacity 0.
//
// Nothing in the hero is enrolled. It is above the fold, and fading the LCP element in
// delays the LCP paint by the length of the fade and buys nothing at all.
// `.support-card`, not `a.support-card`: that row is two anchors and two coin panels that
// are divs, and revealing only the anchors would stagger half a row in and leave the
// other half standing there. Hover colour is still anchors-only, which is correct,
// because the divs are not links.
const REVEAL_SELECTOR = '.lp-section, .lp-step, .lp-card, .lp-slot, .support-card';
const STAGGER_MS = 40;
// Nine cards at 40ms apart would put 360ms between the first and the last, by which point
// the stagger has stopped reading as a group arriving and started reading as a queue.
const STAGGER_MAX = 5;
// A reveal that gets halfway leaves content at opacity 0 permanently, which is far worse
// than no reveal at all. animationend is the normal path; this is the one that runs when
// there was no animation to end.
const REVEAL_FAILSAFE_MS = 1500;

function armReveal() {
  if (typeof IntersectionObserver !== 'function') return;

  const targets = Array.prototype.slice.call(document.querySelectorAll(REVEAL_SELECTOR))
    .filter((el) => !el.closest('.lp-hero'));
  if (!targets.length) return;

  // Position among SAME-PARENT siblings, so a row of cards staggers across itself and
  // the sections do not inherit a delay from how many cards happen to precede them.
  // Computed here rather than in the callback: this reads the DOM tree, which is cheap,
  // but doing it up front keeps the observer callback to a class swap and a timer.
  const delayOf = new Map();
  for (const el of targets) {
    const siblings = el.parentElement ? el.parentElement.children : [el];
    const index = Math.min(Array.prototype.indexOf.call(siblings, el), STAGGER_MAX);
    delayOf.set(el, index * STAGGER_MS);
  }

  const settle = (el) => {
    el.classList.remove('is-in');
    el.classList.remove('u-reveal');
    el.style.animationDelay = '';
  };

  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      const el = entry.target;
      // Immediately, and before anything else: once revealed, never again. An element
      // scrolled back past must not replay.
      observer.unobserve(el);
      // CSSOM, not a style attribute: the CSP forbids the latter, not this.
      el.style.animationDelay = `${delayOf.get(el) ?? 0}ms`;
      el.classList.add('is-in');
      el.addEventListener('animationend', () => settle(el), { once: true });
      setTimeout(() => settle(el), REVEAL_FAILSAFE_MS + (delayOf.get(el) ?? 0));
    }
  }, {
    // A section counts as arrived slightly before its top edge reaches the bottom of the
    // window, so the fade is already running by the time it is properly in view rather
    // than starting at the moment somebody looks at it.
    rootMargin: '0px 0px -6% 0px',
  });

  for (const el of targets) {
    el.classList.add('u-reveal');
    observer.observe(el);
  }
  // LAST. Everything above can fail without hiding anything; from this line on, .u-reveal
  // is invisible until the observer says otherwise, so the observer has to exist first.
  document.documentElement.classList.add('js-reveal');
}

armReveal();

// ------------------------------------------------------------- hero CTAs
//
// There is no scripted CTA left. "Open a gate" and "Join one" are ANCHORS to /app, which
// is what makes them work with middle-click, with "open in new tab", and with this file
// dead. Nothing on the landing needs JavaScript to get you into a gate.

// ------------------------------------------------------------- support + source
//
// Copy buttons and QR codes for the donation addresses, and the AGPL section 13 link.
// Failures are reported to the console: this document has no status log, and a landing
// page is not the place to invent one. The buttons already say when a copy did not land.
wireSupport((message) => console.warn(`[warp gate] ${message}`));

// ----------------------------------------------------------------- the suggestion box

// Matches WG_SUGGESTIONS_MAX_CHARS's default and the textarea's maxlength. Three copies of
// one number is two too many, but the server is the only one that can be authoritative and
// it does not publish it; the two client-side copies are both advisory, and a mismatch
// costs a refusal with a clear message rather than lost text.
const SUGGEST_MAX = 600;
// WG_SUGGESTIONS_MAX_TEXT_BYTES's default: the server refuses a line over this many
// bytes with the same 400 as the character cap, and only this copy can say which one
// the writer actually hit.
const SUGGEST_MAX_BYTES = 1200;

function armSuggestions() {
  const section = document.getElementById('suggest-section');
  const form = document.getElementById('suggest-form');
  const text = document.getElementById('suggest-text');
  const count = document.getElementById('suggest-count');
  const said = document.getElementById('suggest-said');
  const send = document.getElementById('suggest-send');
  if (!section || !form || !text) return;

  section.hidden = false;

  const tally = () => {
    const left = SUGGEST_MAX - [...text.value].length;
    // Silent until it starts to matter. A counter that is always on screen is a counter
    // that tells everybody their idea is too long before they have written it.
    count.textContent = left <= 100 ? `${left} characters left` : '';
  };
  text.addEventListener('input', tally);
  tally();

  form.addEventListener('submit', async (event) => {
    // The CSP sets form-action 'none', so a real submission would be blocked rather than
    // navigating: this is what makes the form work at all, not a nicety.
    event.preventDefault();
    const body = text.value.trim();
    if (!body) { said.textContent = 'Write something first.'; return; }
    // The server also caps the LINE at 1200 bytes, so 401-600 CJK or emoji characters
    // pass every character count here and are still refused. Checked before the send,
    // and named as the byte limit it is, because "over 600 characters" was false for
    // exactly the text that hit it.
    if (new TextEncoder().encode(body).length > SUGGEST_MAX_BYTES) {
      said.textContent = 'That is over the size limit: characters beyond plain letters '
        + 'count for more than one. Trim it down a little.';
      return;
    }

    send.disabled = true;
    said.textContent = 'Sending...';
    try {
      const res = await fetch('/api/suggest', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: body }),
        signal: AbortSignal.timeout(8000),
      });
      if (res.status === 204) {
        // Cleared on success only. A failed send that wiped the box would lose what
        // somebody just wrote, and there is no draft anywhere to get it back from.
        text.value = '';
        tally();
        said.textContent = 'Sent. Thank you: it is in the file, with no name on it.';
        return;
      }
      // One sentence per cause, for the same reason as everywhere else in this codebase.
      said.textContent = {
        429: 'That is a few in quick succession. Try again in a minute.',
        507: 'The box is full at the moment. Try again later.',
        404: 'This copy of Warp Gate does not collect suggestions.',
        400: 'That was refused: it may be empty or too long.',
      }[res.status] ?? `That did not send (http ${res.status}). Try again in a moment.`;
    } catch (err) {
      // Never a bare catch: an aborted timeout and a dead network read differently to
      // whoever is looking at the console.
      said.textContent = err.name === 'TimeoutError'
        ? 'The server took too long to answer. Try again in a moment.'
        : 'That did not send. Check the connection and try again.';
      console.warn(`[warp gate] suggestion failed: ${err.message}`);
    } finally {
      send.disabled = false;
    }
  });
}

// Fetched here rather than through signal.js: that module knows how to open and join
// rooms, and the landing has no business importing it. One same-origin GET, with the
// timeout every external fetch in this codebase carries.
fetch('/api/config', { signal: AbortSignal.timeout(8000) })
  .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`http ${res.status}`))))
  .then((config) => {
    applySourceLink(config?.sourceUrl);
    // Only revealed if this deployment actually accepts suggestions. A box that posts into
    // a 404 collects nothing and says nothing, which is a worse answer than not asking.
    if (config?.suggestions === true) armSuggestions();
  })
  // The link stays hidden rather than pointing somewhere wrong. Section 13 is satisfied
  // by the gate document, which is where the interaction actually happens.
  .catch((err) => console.warn(`[warp gate] could not read /api/config: ${err.message}`));
