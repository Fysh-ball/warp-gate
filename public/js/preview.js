// Everything a finished file row grows once the bytes are actually here: the inline
// image, the inline video and audio players, and the Open button.
//
// WHY THIS IS A SEPARATE MODULE, fetched with await import() rather than sitting in
// app.js. Nothing in here can be reached until a peer has sent a file and this side has
// finished receiving it, which is a decision nobody has made when a gate opens. That is
// the same rule tests/size.test.mjs states at its head and the same rule batchui.js and
// dirsink.js already follow, and it is not bookkeeping: the gate's eager graph is
// budgeted, and preview code is the largest thing here that a gate used for chat alone
// never touches. app.js keeps the parts that must exist without this file: the Save
// button, so a failed fetch still leaves the file recoverable, and the release
// bookkeeping, so severing can revoke every URL synchronously.
//
// The MIME string on every meta here is CHOSEN BY THE PEER. It is not evidence of
// anything. Every use of it below is a lookup in a fixed table, never a prefix test and
// never a value passed through to anything that acts on it.

// type/subtype, RFC 6838 restricted-name characters only. Anything else is not a MIME.
const MIME_PATTERN = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;

/** Reduce a peer-supplied MIME string to one that is safe to act on, or '' if it is not. */
export function safeMime(mime) {
  const value = typeof mime === 'string' ? mime.trim().toLowerCase() : '';
  return MIME_PATTERN.test(value) ? value : '';
}

// Only these render inline. The MIME string is chosen by the peer, so a prefix test on
// "image/" also matched image/svg+xml, which browsers render as a document.
export const INLINE_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif']);

// The container formats a browser will actually decode in a <video>/<audio> element.
// Deliberately short, and deliberately not "video/*": a prefix test would admit
// video/x-anything, and the point of a table is that a type nobody listed gets no
// element. A file whose real content does not match its declared container fails to
// decode and is handled by the error path below, which is why the list can afford to be
// about containers rather than codecs.
export const INLINE_VIDEO_TYPES = new Set(['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime']);
export const INLINE_AUDIO_TYPES = new Set([
  'audio/mpeg', 'audio/mp4', 'audio/aac', 'audio/ogg', 'audio/opus',
  'audio/wav', 'audio/x-wav', 'audio/webm', 'audio/flac',
]);

/**
 * The types Open is offered for, and the type each one is FORCED to on the way out.
 *
 * THIS IS THE SECURITY BOUNDARY OF THIS FILE. A blob: URL is same-origin with the
 * document that created it, so a top-level navigation to a blob whose type is text/html
 * runs the peer's markup inside the gate's own origin, with the room key in the heap next
 * door. There is no sandbox on a blob: document and no header that can be attached to one.
 *
 * So two rules, and both are needed:
 *
 *   1. DEFAULT DENY. A type that is not a key of this map gets no Open button at all. Not
 *      a disabled one, not one that downloads instead: absent. A missing button is a
 *      correct answer.
 *   2. THE TYPE IS FORCED. The URL is built from `new Blob([bytes], { type: <the VALUE
 *      here> })`, never from meta.mime. The peer's string only ever selects a row of this
 *      table; it never reaches the Blob. Without this, a peer could declare image/png,
 *      pass the allowlist, and have their HTML served under a type the browser sniffs or
 *      under a type this code copied verbatim.
 *
 * Why each entry is safe to navigate to same-origin:
 *   - the five raster image types: a browser renders these in an image document. There is
 *     no scripting model in PNG, JPEG, GIF, WebP or AVIF. image/svg+xml is absent for the
 *     opposite reason: SVG is a document format with <script> in it.
 *   - the video and audio containers: rendered by a media element in a media document.
 *     Same reasoning. No container here carries executable content that a browser runs;
 *     the historical exceptions are formats like SMIL and ASX, which are not on the list.
 *   - text/plain, forced to charset=utf-8: a plain-text document executes nothing. The
 *     charset is pinned rather than left to the browser because the one historical way to
 *     get script out of a text document was charset confusion (UTF-7), and an explicit
 *     charset removes the question rather than arguing about which browsers still sniff.
 *
 * Deliberately NOT here, each because it is an active document format: text/html,
 * application/xhtml+xml, image/svg+xml, text/xml and application/xml (XSLT can carry
 * script), and application/pdf. PDF is the one a user will miss, and it is left out on
 * purpose: it is a scripting format, its viewer is the largest piece of attack surface a
 * browser exposes for a file type, and the pay-off would be convenience rather than
 * capability, since Save already puts the file where the system PDF reader can open it.
 */
export const OPEN_TYPES = new Map([
  ['image/png', 'image/png'],
  ['image/jpeg', 'image/jpeg'],
  ['image/gif', 'image/gif'],
  ['image/webp', 'image/webp'],
  ['image/avif', 'image/avif'],
  ['video/mp4', 'video/mp4'],
  ['video/webm', 'video/webm'],
  ['video/ogg', 'video/ogg'],
  ['video/quicktime', 'video/quicktime'],
  ['audio/mpeg', 'audio/mpeg'],
  ['audio/mp4', 'audio/mp4'],
  ['audio/aac', 'audio/aac'],
  ['audio/ogg', 'audio/ogg'],
  ['audio/opus', 'audio/ogg'],
  ['audio/wav', 'audio/wav'],
  ['audio/x-wav', 'audio/wav'],
  ['audio/webm', 'audio/webm'],
  ['audio/flac', 'audio/flac'],
  ['text/plain', 'text/plain; charset=utf-8'],
]);

/** The type Open would force for this peer-declared MIME, or '' if Open is not offered. */
export function openableAs(mime) {
  return OPEN_TYPES.get(safeMime(mime)) ?? '';
}

// Where the caution below points. The upload page rather than the home page, because the
// recommendation is "check this file" and landing somewhere that asks the user to find the
// right box is how advice stops being followed.
const VIRUSTOTAL_URL = 'https://www.virustotal.com/gui/home/upload';

/**
 * The scan caution, on a file this device RECEIVED and never on one it sent.
 *
 * ASKED FOR VERBATIM: "We should also show a 'If you recieved a file within this session we
 * recommend running it through virus total first before opening it'". The recommendation is
 * right and the obvious wording of it is not, so the caveat is in the same sentence rather
 * than in a disclosure underneath it:
 *
 *   UPLOADING A FILE TO VIRUSTOTAL PUBLISHES IT. Samples are shared with security vendors
 *   and are downloadable by paying subscribers. This product's entire premise is that
 *   nothing leaves the two browsers, so "run it through VirusTotal" on its own is advice
 *   that undoes the thing the user came here for, and a user who follows it on a private
 *   document has handed that document to third parties. It is the right move for something
 *   you were sent and did not expect, and the wrong move for anything private, and a user
 *   cannot make that call from a sentence that does not tell them the difference.
 *
 * NO HASH LOOKUP, which would have been the privacy-preserving version. `fingerprintFile`
 * in transfer.js hashes only the first FINGERPRINT_PREFIX_BYTES of the file, so it is not a
 * whole-file SHA-256 and VirusTotal cannot be searched with it. Building a lookup URL out of
 * it would return "not found" for every file ever sent, which a user reads as "clean": a
 * check that cannot fail, pointed at the user. WebCrypto has no streaming digest either, so
 * a real hash means re-reading the whole file, which for a disk-sink file is a second full
 * read and for a 3 GB file is not cheap. If that is ever offered it has to be an explicit
 * action that says it is computing a hash, not a link that quietly claims to be one.
 *
 * On the ROW rather than as a page-level banner, deliberately: the standing "Files over
 * 500 MB" notice was already reported as taking over a phone screen, and a second permanent
 * banner makes the same complaint worse. This sits where the decision is made, next to Save
 * and Open, at the moment the user is about to open something.
 */
function appendScanCaution(row) {
  const el = document.createElement('div');
  el.className = 'muted small scan-caution';
  el.appendChild(document.createTextNode('Did not expect this file? Scan it with '));
  const link = document.createElement('a');
  link.href = VIRUSTOTAL_URL;
  link.target = '_blank';
  // Both halves, as attributes rather than window.open flags, for the reason openBytes gives
  // below: noopener so the new document gets no window.opener back into a page holding a room
  // key, and noreferrer so the request does not carry this gate's URL to a third party.
  link.rel = 'noopener noreferrer';
  link.textContent = 'VirusTotal';
  el.appendChild(link);
  el.appendChild(document.createTextNode(' before opening. That uploads a copy to a third '
    + 'party who shares it with security vendors, so never do it with something private.'));
  row.appendChild(el);
}

/** Append a muted one-line note to a row. Every failure path below ends in one of these. */
function note(row, text) {
  const el = document.createElement('div');
  el.className = 'muted small';
  el.textContent = text;
  row.appendChild(el);
}

/**
 * Open bytes in a new tab under a type this code chose.
 *
 * `getBytes` is a function rather than a blob because the disk route has to read the file
 * back at click time: the bytes were streamed straight to the user's chosen file and this
 * page never held them. It is awaited INSIDE the click handler, so the navigation still
 * happens inside the browser's transient activation window and is not treated as a popup.
 *
 * The anchor, rather than window.open: window.open with 'noopener' returns null by
 * specification, so its result cannot distinguish "blocked" from "opened", and an anchor
 * carries rel="noopener noreferrer" as an ordinary attribute the browser honours. The new
 * document therefore gets no window.opener back into the gate.
 */
async function openBytes(row, getBytes, forced, ctx) {
  let bytes;
  try {
    bytes = await getBytes();
  } catch (err) {
    // Reading a file back through a FileSystemFileHandle is the path that fails in
    // practice: the grant can lapse, and the file can have been moved or deleted since it
    // was written. Say which, rather than doing nothing on a click.
    note(row, `This could not be opened: ${err.message}. The file itself is unchanged.`);
    ctx.scrollMessages();
    return;
  }
  // FORCED TYPE. See OPEN_TYPES above: meta.mime never reaches this constructor.
  const url = URL.createObjectURL(new Blob([bytes], { type: forced }));
  ctx.objectUrls.add(url);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.target = '_blank';
  anchor.rel = 'noopener noreferrer';
  document.body.appendChild(anchor);
  try {
    anchor.click();
  } finally {
    // The anchor goes even if click() throws: a detached-but-attached node would keep the
    // blob referenced for the life of the page.
    anchor.remove();
  }
  // Long enough for the new document to have fetched the URL, and tracked in objectUrls so
  // that severing does not have to wait this timer out. Matches saveBlob's 60 seconds.
  setTimeout(() => {
    if (ctx.objectUrls.delete(url)) URL.revokeObjectURL(url);
  }, 60_000);
}

/**
 * Build the inline element for a received blob, or null if this type does not get one.
 *
 * Images keep the class name they have always had, because the stylesheet and the
 * end-to-end tests both name it. Every inline element additionally carries `msg-media`,
 * which is the one selector app.js releases on: adding a fourth kind later means adding
 * the class, not editing the release path, and a release path that misses a kind leaks an
 * object URL that pins the whole file in memory for the life of the gate.
 */
function inlineElementFor(mime) {
  const type = safeMime(mime);
  if (INLINE_IMAGE_TYPES.has(type)) {
    const img = document.createElement('img');
    img.className = 'msg-image msg-media';
    return img;
  }
  const kind = INLINE_VIDEO_TYPES.has(type) ? 'video' : (INLINE_AUDIO_TYPES.has(type) ? 'audio' : '');
  if (!kind) return null;
  const el = document.createElement(kind);
  el.className = 'msg-media';
  // controls, and nothing else. No autoplay, no loop, and not muted: a file that arrives
  // in a chat must not make noise, must not start a download of its whole body, and must
  // not repeat. preload="metadata" is the smallest thing that still lets the element
  // report a duration and a poster frame, and it is also what makes the error path below
  // fire promptly for a file that is not really this type: with preload="none" nothing is
  // decoded until a play, so a broken file would sit there looking fine.
  el.controls = true;
  el.preload = 'metadata';
  el.autoplay = false;
  el.loop = false;
  el.muted = false;
  return el;
}

/**
 * Give a finished, received file row everything that needs the bytes.
 *
 * `ctx` carries app.js's release bookkeeping rather than this module importing it: the
 * lists have to be reachable from severing, which is synchronous and cannot await an
 * import, so they live there and this module is handed them.
 *
 * Returns nothing. Every failure inside is reported into the row, because the caller
 * discards the promise and a silent failure here is a row that quietly loses a feature.
 */
export function decorateFileRow(row, meta, ctx) {
  const name = ctx.sanitizeFilename(meta.name);
  const save = row.querySelector('button.save-btn');
  // Where content goes in. A received row's first action is Save and the preview belongs
  // above it; a SENT row has no Save and ends in a "Sent." line, and a thumbnail printed
  // underneath a line that says the send already finished reads as a second event. Null on
  // the disk row, which has neither, and appends instead.
  const anchor = save ?? row.querySelector('.sent-note');

  // FIRST, before every early return below, so a file that gets no inline preview and no
  // Open button still gets the caution: the Open button is withheld for types this page
  // will not navigate to, and those are exactly the ones a user opens from their own file
  // manager instead, where nothing here can say anything at all.
  //
  // `meta.sent` is the one exemption, and it is a statement about provenance rather than a
  // rendering flag. Telling somebody to upload their OWN outgoing file to a third party
  // that publishes it would be advice to leak the thing they just chose to send privately,
  // which is the exact harm the caution's own wording warns about. Until sender previews
  // existed this was enforced by the caller: app.js's finishFileRow returned at "Sent."
  // and there was no route here at all. There is one now, so the rule is enforced where it
  // is stated. tests/batchui.test.mjs pins the caller side; the caution count is pinned in
  // tests/browser.test.mjs.
  if (!meta.sent) appendScanCaution(row);

  // ------------------------------------------------------------------ inline preview
  if (meta.blob) {
    const el = inlineElementFor(meta.mime);
    if (el) {
      const url = URL.createObjectURL(meta.blob);
      ctx.objectUrls.add(url);
      if (el.tagName === 'IMG') el.alt = name;
      else el.setAttribute('aria-label', name);

      // Counted on LOAD, not on insert: a peer sending three files that merely claim to be
      // playable used to evict three genuine previews with rows that never decoded.
      // loadedmetadata is the media element's equivalent of an image's load: it is the
      // first point at which the browser has committed to being able to render this.
      const arrived = () => {
        // Each preview pins a decoded frame or a demuxed header plus the blob behind an
        // object URL, and nothing else releases either while the gate is live. Files under
        // the auto-accept threshold arrive with no prompt at all, so an unbounded run of
        // them is the peer's choice and not the user's.
        ctx.inlinePreviews.push(row);
        while (ctx.inlinePreviews.length > ctx.MAX_INLINE_PREVIEWS) {
          ctx.releasePreview(ctx.inlinePreviews.shift());
        }
        ctx.scrollMessages();
      };
      const failed = () => {
        // A media element that has already been torn down can still deliver one last error
        // as it lets go of its source, and appending "this did not open" to a row that was
        // merely EVICTED would be a false statement about the file. The element leaving the
        // document is the signal that some other path already handled it.
        if (!el.isConnected) return;
        // Declared as something playable and is not: a ZIP named .mp4, or text sent as
        // audio/wav. Leaving the element in place renders a dead player with no
        // explanation, which is exactly what the broken <img> used to do.
        if (typeof el.pause === 'function') {
          // A detached media element can keep playing in Chromium, so it is stopped and
          // its source cleared BEFORE it leaves the DOM. Removing it is not enough.
          el.pause();
          el.removeAttribute('src');
          el.load();
        }
        el.remove();
        if (ctx.objectUrls.delete(url)) URL.revokeObjectURL(url);
        const noun = el.tagName === 'IMG' ? 'an image' : 'playable media';
        note(row, `This did not open as ${noun}. Use Save to keep the file as it was sent.`);
        ctx.scrollMessages();
      };
      el.addEventListener(el.tagName === 'IMG' ? 'load' : 'loadedmetadata', arrived, { once: true });
      el.addEventListener('error', failed, { once: true });
      el.src = url;
      // Before the buttons, so the row reads as content-then-actions.
      if (anchor) row.insertBefore(el, anchor);
      else row.appendChild(el);
    }
  }

  // ------------------------------------------------------------------------ Open
  //
  // Two sources, one rule. In memory the bytes are already here. On disk they are not:
  // the file was streamed to the location the user picked and this page kept only the
  // handle, so the bytes are read back at click time. Both go through openBytes, which is
  // where the forced type is applied, so there is exactly one place that constructs the
  // Blob that gets navigated to.
  const forced = openableAs(meta.mime);
  if (!forced) return;
  let getBytes = null;
  if (meta.blob) getBytes = () => meta.blob;
  else if (meta.handle && typeof meta.handle.getFile === 'function') getBytes = () => meta.handle.getFile();
  if (!getBytes) return;

  const open = document.createElement('button');
  open.className = 'secondary open-btn';
  open.textContent = 'Open';
  open.title = `Open ${name} in a new tab`;
  open.addEventListener('click', () => { void openBytes(row, getBytes, forced, ctx); });
  if (save) save.after(open);
  else if (anchor) anchor.before(open);
  else row.appendChild(open);
}
