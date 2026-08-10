// The table of contents on the policy pages.
//
// WHAT THIS FILE IS ALLOWED TO BE
//
// These four documents are the only pages on the site that carried no JavaScript at all,
// and that was a feature rather than an oversight: a privacy policy that cannot be read
// without running code is a bad look for a tool whose whole claim is that it runs as
// little code as possible. So this script is additive and nothing else. It reads headings
// that are already in the HTML, builds a nav out of them, and sets one class. If it never
// loads, never runs, or is blocked outright, the page is the same complete, readable,
// centred document it was before: the `.has-toc` class is what switches the two-column
// layout on, and CSS cannot invent it.
//
// It also does not mint the ids. Every h2 in the four HTML files carries its own
// `id="sec-..."`, written into the markup, so /privacy.html#sec-retention resolves with
// JavaScript disabled. The slug function here exists only so that a heading someone adds
// later without an id still gets one, and gets the SAME one this file would have written
// into the HTML.
//
// CSP: this origin serves `default-src 'none'; script-src 'self'; style-src 'self'`.
// Nothing below writes a style attribute, an inline handler or a stylesheet. Geometry is
// entirely in style.css and the only thing this file changes about presentation is which
// classes and which aria-current attribute are present.

/* A policy with two sections is a page you can already see the whole of. Below this a
   rail is furniture, not navigation. */
const MIN_SECTIONS = 3;

/**
 * The id a heading gets when the markup did not give it one.
 *
 * Kept identical to the rule that generated the ids now in the HTML, including the
 * `sec-` prefix and the cut at a word boundary near 60 characters, so that adding an
 * unlabelled h2 produces the id you would have written by hand rather than a second
 * naming scheme living in the same document.
 *
 * The prefix is not decoration. Ids like "1-agreement" are legal HTML but are not valid
 * CSS identifiers, so anything that later reaches for one with querySelector throws
 * instead of missing. Every id here starts with a letter.
 */
export function slugFor(text) {
  return `sec-${text
    .toLowerCase()
    .replace(/^\s*\d+[.)]\s*/, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/^(.{0,60}[a-z0-9])(-.*)?$/, '$1')}`;
}

/** Give every heading an id, without ever silently reusing one already on the page. */
function ensureIds(headings, doc) {
  for (const h of headings) {
    if (h.id) continue;
    const base = slugFor((h.textContent || '').replace(/\s+/g, ' ').trim()) || 'sec';
    let id = base;
    // getElementById, not a Set of what this loop has minted: the collision that matters
    // is with anything else in the document, including ids from the markup.
    for (let n = 2; doc.getElementById(id); n += 1) id = `${base}-${n}`;
    h.id = id;
  }
}

/** The nav element, fully built, or null if this page does not warrant one. */
function buildNav(doc, headings) {
  const nav = doc.createElement('nav');
  nav.className = 'legal-toc';
  // Named by its own visible title rather than by a duplicate aria-label, so the two
  // cannot drift apart.
  nav.setAttribute('aria-labelledby', 'legal-toc-title');

  const title = doc.createElement('div');
  title.className = 'legal-toc-title';
  title.id = 'legal-toc-title';
  title.textContent = 'On this page';
  nav.appendChild(title);

  // An ordered list: the sections of a policy are read in order and several of them are
  // numbered in their own text. A screen reader announcing "list of 12 items" is telling
  // the truth about the document.
  const list = doc.createElement('ol');
  list.className = 'legal-toc-list';
  for (const h of headings) {
    const li = doc.createElement('li');
    const a = doc.createElement('a');
    a.className = 'legal-toc-link';
    a.href = `#${h.id}`;
    // textContent, never innerHTML. The headings are ours, but the rule that keeps this
    // file unable to inject markup is worth more than the two words of formatting it
    // would buy.
    a.textContent = (h.textContent || '').replace(/\s+/g, ' ').trim();
    li.appendChild(a);
    list.appendChild(li);
  }
  nav.appendChild(list);
  return nav;
}

/**
 * Keep the rail pointing at the section being read.
 *
 * IntersectionObserver is the TRIGGER, not the answer. Using it alone means trusting a
 * strip of viewport to contain exactly one heading, which is false whenever two headings
 * are close together and false again right after a fragment jump moves several at once.
 * So the observer fires only when some heading crosses the line under the masthead, and
 * the callback then reads the actual positions and picks the last heading at or above
 * that line. That is the definition of "the section you are in", stated directly.
 *
 * Cost: one O(n) pass over at most eighteen headings, only when one of them crosses.
 * There is deliberately no scroll listener.
 */
function trackCurrent(win, headings, links) {
  if (typeof win.IntersectionObserver !== 'function') return null;

  // Read the masthead height from the same token the CSS uses, so the line the rail
  // follows and the line a scroll anchor lands on cannot disagree. A missing or
  // unparseable token falls back to the measured height rather than to zero: zero would
  // put the line at the very top of the viewport, where it silently marks the previous
  // section for the first 46 pixels of every scroll.
  const raw = win.getComputedStyle(win.document.documentElement).getPropertyValue('--bar-h');
  const barH = Number.parseFloat(raw);
  const line = (Number.isFinite(barH) ? barH : 46) + 24;

  let marked = null;
  const mark = (heading) => {
    if (heading === marked) return;
    marked = heading;
    for (const [target, link] of links) {
      // Removed rather than set to "false": `[aria-current]` matches any value, so an
      // explicit false would leave every link in the rail looking current.
      if (target === heading) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    }
  };

  const update = () => {
    let current = null;
    for (const h of headings) {
      if (h.getBoundingClientRect().top - line > 1) break;
      current = h;
    }
    mark(current);
  };

  const io = new win.IntersectionObserver(update, {
    // Pull the top of the root down to the line under the masthead and leave the other
    // three edges alone. Every heading crossing that line, in either direction, is a
    // callback. Deliberately NOT a one-pixel band written as a negative bottom margin in
    // viewport pixels: that number is wrong the moment the window is resized, a
    // rootMargin cannot be changed after construction, and the fix would be a resize
    // listener that tears the observer down and builds another. This margin has no
    // viewport height in it, so there is nothing for a resize to invalidate. It costs a
    // few extra callbacks as headings appear from the bottom, which is at most one per
    // section for a whole page of scrolling.
    rootMargin: `-${line}px 0px 0px 0px`,
    threshold: 0,
  });
  for (const h of headings) io.observe(h);

  // The observer reports its initial state on the next frame, but a page opened at a
  // fragment is already scrolled by the time this runs, so settle it now rather than
  // showing an unmarked rail until something moves.
  update();

  return io;
}

/** Build the rail. Exported so a test can run it against a document it controls. */
export function buildToc(doc, win) {
  const main = doc.querySelector('main.legal');
  if (!main) return null;
  // The wrapper is what makes two grid items possible. Without it there is nothing to put
  // in the second column, so there is nothing to build.
  const body = main.querySelector('.legal-body');
  if (!body) return null;
  if (main.querySelector('.legal-toc')) return null;

  const headings = Array.prototype.slice.call(body.querySelectorAll('h2'));
  if (headings.length < MIN_SECTIONS) return null;

  ensureIds(headings, doc);
  const nav = buildNav(doc, headings);
  // First child, matching the first grid column, so the rail is also the first thing a
  // keyboard or a screen reader reaches inside the page.
  main.insertBefore(nav, main.firstChild);

  const links = new Map();
  const anchors = nav.querySelectorAll('.legal-toc-link');
  for (let i = 0; i < headings.length; i += 1) links.set(headings[i], anchors[i]);

  // Last, and only once the nav is genuinely in the document: this class is the single
  // switch for the two-column layout, and setting it before the rail exists would give
  // the page one frame of prose indented past an empty column.
  main.classList.add('has-toc');

  trackCurrent(win, headings, links);
  return nav;
}

// A module is deferred, so the document is parsed by the time this runs. Guarded anyway:
// this file is also imported directly by tests/legal.test.mjs, where there is no document
// at all and the import must not throw.
if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  buildToc(document, window);
}
