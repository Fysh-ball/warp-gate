/**
 * Landing page behaviour: the flipping word in the hero, and nothing else.
 *
 * Deliberately independent of app.js. It binds to two ids that app.js does not
 * know about, touches no application state, and if any of it fails the page is
 * still a working gate with a word that does not rotate. Loaded as a module so
 * the strict CSP (`script-src 'self'`) is satisfied without an inline script.
 */

const WORDS = [
  'Friends', 'Sysadmins', 'Regular people', 'Family', 'Photographers',
  'Yourself', 'Roommates', 'Freelancers', 'Journalists', 'Students',
  'Small teams', 'Your other laptop', 'Musicians', 'Whoever',
];

const FLIP_MS = 2400;
const FADE_MS = 300;

const shell = document.getElementById('flipper');
const box = document.getElementById('flipbox');
const home = document.getElementById('screen-home');

/*
 * Expand the create card's optional settings once there is room for them.
 *
 * Expiry and room password both have working defaults, and expanded they cost about
 * 185px: enough to push "Join gate" behind the fixed log panel on a 390x844 phone,
 * which is where the gate controls have to be reachable without scrolling. The markup
 * ships closed and this widens it, rather than the reverse, so the state that changes
 * on load is the one that grows downward on a desktop, never the one that yanks the
 * Create button up the screen on a phone.
 *
 * It reads and writes one attribute on one element and touches no application state,
 * so app.js neither knows nor cares. A closed <details> still resolves by id, still
 * takes a value, and still submits: only its pixels are gone.
 */
const options = document.getElementById('create-options');
if (options) {
  const wide = window.matchMedia('(min-width: 900px)');
  const sync = () => { options.open = wide.matches; };
  sync();
  wide.addEventListener('change', sync);
}

// Nothing to do on the legal pages, which share this stylesheet but not the hero.
if (shell && box && box.children.length === 4) {
  const faces = Array.prototype.slice.call(box.children);
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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
    const h = Math.round(fontPx * 1.34);

    const probe = document.createElement('span');
    // CSSOM, not a style attribute: the CSP forbids the latter, not this.
    probe.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;padding:0 .14em;left:-9999px;top:0';
    probe.style.fontFamily = cs.fontFamily;
    probe.style.fontSize = cs.fontSize;
    probe.style.fontWeight = cs.fontWeight;
    probe.style.letterSpacing = cs.letterSpacing;
    document.body.appendChild(probe);

    let w = 0;
    try {
      for (const word of WORDS) {
        probe.textContent = word;
        w = Math.max(w, Math.ceil(probe.getBoundingClientRect().width));
      }
    } finally {
      probe.remove();
    }

    shell.style.width = `${w + 12}px`;
    shell.style.height = `${h}px`;
    box.style.height = `${h}px`;
    box.style.width = '100%';
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

  // The home screen starts hidden behind onboarding, and a display:none subtree
  // has no laid-out width to measure against. Re-measure the moment app.js
  // reveals it. Watching the attribute keeps this one-way: landing.js reads the
  // screen state and never sets it.
  if (home) {
    new MutationObserver(() => { if (!home.hidden) size(); })
      .observe(home, { attributes: true, attributeFilter: ['hidden'] });
  }

  for (let i = 0; i < faces.length; i += 1) faces[i].textContent = WORDS[i];

  let step = 0;
  setInterval(() => {
    // No point tumbling a box on a screen nobody is looking at.
    if (document.visibilityState !== 'visible') return;
    if (home && home.hidden) return;

    step += 1;
    if (reduced) {
      // Someone asked not to be given a 3D tumble, so they get a crossfade: the
      // stylesheet swaps the transition to opacity and only the text changes.
      box.style.opacity = '0';
      setTimeout(() => {
        faces[0].textContent = WORDS[step % WORDS.length];
        for (let i = 1; i < faces.length; i += 1) faces[i].style.display = 'none';
        box.style.opacity = '1';
      }, FADE_MS);
      return;
    }

    box.style.transform = `rotateX(${step * 90}deg)`;
    // Re-label the face that is currently behind the box, one quarter turn ahead
    // of where it will be needed, so the swap is never visible.
    const incoming = (step + 1) % faces.length;
    faces[incoming].textContent = WORDS[(step + 1) % WORDS.length];
  }, FLIP_MS);
}

// ------------------------------------------------------------- hero CTAs
//
// The hero shows a picture of a gate rather than the working form, so the primary
// action has to carry the user to the form and put the cursor in it. Scrolling alone
// would leave a keyboard user exactly where they started.
{
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

  const goTo = (targetId, focusId) => {
    const target = document.getElementById(targetId);
    if (!target) return;
    target.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
    if (!focusId) return;
    const el = document.getElementById(focusId);
    if (!el) return;
    // preventScroll, or focusing fights the smooth scroll and lands somewhere else.
    // A reduced-motion jump is instant, so it needs no settle time.
    if (reduced) el.focus({ preventScroll: true });
    else setTimeout(() => el.focus({ preventScroll: true }), 420);
  };

  document.getElementById('cta-open')
    ?.addEventListener('click', () => goTo('gate-controls', 'create-btn'));
  document.getElementById('cta-how')
    ?.addEventListener('click', () => goTo('how-it-works', null));
}
