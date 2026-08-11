// Compare a deployed origin against what this working tree actually serves.
//
//   node tools/verify-deploy.mjs https://warpgate.fysh.site
//
// The reference side is a server started from THIS TREE on a private port, so every
// expectation comes from the code rather than from a value typed here that drifts the
// moment somebody edits a header. Exit 0 when everything matches AND every probe's
// needle is still alive in this tree, 1 otherwise: a probe whose needle has left the
// reference side compares absent against absent forever, and that is reported as
// VACUOUS rather than counted as a match.
//
// How to use it, and the part that makes it evidence rather than decoration:
//
//   1. Run it BEFORE deploying. Every probe covering something you changed must report
//      BAD. A probe that is OK before the deploy is measuring nothing, and it will still
//      be OK afterwards whether or not the deploy worked.
//   2. Deploy.
//   3. Run it again. The same probes must now report OK.
//
// Step 1 is not optional. It is the negative control, and skipping it turns the whole
// run into a check that has never been seen fail. Nothing here enforces that, because
// only the person deploying knows what they changed: read the before-run and confirm the
// probes you care about are red in it.
//
// The probe list below is a snapshot of what a given release changed, so expect to edit
// it. That is the intended use, not a defect: it is cheaper to write four lines that
// compare two origins than to reason about whether a restart picked up a file.

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TARGET = process.argv[2] || 'https://warpgate.fysh.site';
const PORT = 3891;
const REF = `http://127.0.0.1:${PORT}`;

const srv = spawn(process.execPath, [path.join(ROOT, 'server', 'index.js')], {
  cwd: ROOT,
  env: {
    ...process.env,
    WG_HTTP_HOST: '127.0.0.1',
    WG_HTTP_PORT: String(PORT),
    WG_SOURCE_URL: 'https://github.com/Fysh-ball/warp-gate',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let boot = '';
srv.stdout.on('data', (b) => { boot += b; });
srv.stderr.on('data', (b) => { boot += b; });

async function up() {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(`${REF}/api/health`, { signal: AbortSignal.timeout(2000) });
      if (r.ok) return true;
    } catch { /* not listening yet */ }
    await sleep(100);
  }
  return false;
}

let pass = 0, fail = 0, vacuous = 0;

// The two boolean fields whose healthy value on the reference side is false: both assert
// the ABSENCE of something (the blanket reduced-motion nuke, the FAQ sentence denying the
// extension exists). Every other boolean is a presence needle and must be true against
// this tree, every status must be 2xx, and no string may be the '(absent)' sentinel:
// otherwise the needle has died in the tree, both sides agree on nothing, and the probe
// is measuring nothing. A new negated field must be named here or it reads as dead.
const EXPECT_FALSE = new Set(['nuke', 'deniedItExists']);

function deadNeedles(v, key = '', path = '', out = []) {
  if (typeof v === 'boolean') {
    if (v === EXPECT_FALSE.has(key)) out.push(path);
  } else if (typeof v === 'string') {
    if (v === '(absent)') out.push(path);
  } else if (typeof v === 'number') {
    if (/status$/i.test(key) && !(v >= 200 && v < 300)) out.push(path);
  } else if (v && typeof v === 'object') {
    for (const [k, val] of Object.entries(v)) deadNeedles(val, k, path ? `${path}.${k}` : k, out);
  }
  return out;
}

function report(name, refVal, tgtVal) {
  const same = JSON.stringify(refVal) === JSON.stringify(tgtVal);
  const dead = typeof refVal === 'string' && refVal.startsWith('REF-ERROR')
    ? [] // already loud: the error string cannot equal the target side
    : deadNeedles(refVal, name);
  const line = `${name}\n     tree=${JSON.stringify(refVal)}\n     live=${JSON.stringify(tgtVal)}`;
  if (dead.length) {
    vacuous++;
    console.log(`VACUOUS ${line}\n     dead in this tree: ${dead.join(', ') || name}`);
  } else if (same) { pass++; console.log('OK   ' + line); }
  else { fail++; console.log('BAD  ' + line); }
  return same;
}

async function get(base, path) {
  const r = await fetch(base + path, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
  return { status: r.status, headers: r.headers, text: await r.text() };
}

if (!(await up())) {
  console.log('BAD  reference server did not start\n' + boot);
  process.exit(1);
}
console.log(`reference: this working tree on ${REF}`);
console.log(`target:    ${TARGET}\n`);

const probes = [
  {
    name: '1. /app grants the camera to itself, so the QR scanner can open it',
    async run(base) {
      const r = await get(base, '/app');
      const p = r.headers.get('permissions-policy') || '';
      return (p.match(/camera=\([^)]*\)/) || ['(absent)'])[0];
    },
  },
  {
    // Not "the landing CSP differs from the gate CSP": with WG_AD_ORIGINS unset,
    // LANDING_CSP is deliberately the same string as CSP, so that check is identical on
    // both sides and measures nothing. This measures served BYTES instead, which is what
    // the work order actually asks for: the gate document and its two largest eager
    // modules, gzipped by the server, byte for byte.
    //
    // Compared after decoding, by length and hash. Not by content-length: Cloudflare
    // re-compresses and answers chunked, so that header is absent on the live side and
    // present on the reference side no matter what the bytes are. A check that can only
    // ever be red is worse than one that is vacuous, because it looks like a finding.
    name: '2. the served bytes of the gate and its heaviest modules match this tree',
    async run(base) {
      const out = {};
      for (const p of ['/app', '/js/app.js', '/js/words.js']) {
        const r = await fetch(base + p, { signal: AbortSignal.timeout(15000) });
        let body = await r.text();
        // Cloudflare appends its JS Detections bootstrap to HTML before </body>. Those
        // bytes are not ours and never will be, so comparing them makes this check
        // permanently red and therefore useless. Strip exactly that element and compare
        // what the server actually sent. See tests/cdn-injection.test.mjs, which is where
        // the injection itself is measured and where the CSP that neuters it is proven.
        const injected = /<script>\(function\(\)\{[^]*?__CF\$cv\$params[^]*?<\/script>/.exec(body);
        if (injected) {
          body = body.replace(injected[0], '');
          // Reported, never compared: the reference side has none and the live side does,
          // so including it in the comparison would guarantee a mismatch forever.
          console.log(`     note: stripped ${injected[0].length} bytes of CDN-injected script from ${base}${p}`);
        }
        const buf = Buffer.from(body, 'utf8');
        out[p] = {
          status: r.status,
          bytes: buf.length,
          sha: createHash('sha256').update(buf).digest('hex').slice(0, 16),
        };
      }
      return out;
    },
  },
  {
    name: '3. /api/config advertises the suggestion box as a field',
    async run(base) {
      const r = await get(base, '/api/config');
      const j = JSON.parse(r.text);
      return { hasSuggestions: 'suggestions' in j, fields: Object.keys(j).length };
    },
  },
  {
    name: '4. the games stylesheet is served and is the pastel one',
    async run(base) {
      const r = await get(base, '/css/games.css');
      // Comments stripped before looking for the blanket reduced-motion rule, because
      // this file deliberately QUOTES that rule inside a comment explaining why it is
      // not there. Searching the raw text finds the counter-example and reports the
      // defect as present. A scanner must not match the thing it is documenting.
      const code = r.text.replace(/\/\*[\s\S]*?\*\//g, '');
      return { status: r.status, pastel: r.text.includes('--g-rose'), nuke: /animation-duration:\s*0\.01ms/.test(code) };
    },
  },
  {
    name: '5. the camera scanner module is served and reports its last error',
    async run(base) {
      const r = await get(base, '/js/qrscan.js');
      return { status: r.status, lastScanError: r.text.includes('lastScanError') };
    },
  },
  {
    name: '6. the link layer does commit-then-reveal on the public key',
    async run(base) {
      const r = await get(base, '/js/link.js');
      return { status: r.status, pkc: r.text.includes("'pkc'"), reveal: r.text.includes('armRevealTimer') };
    },
  },
  {
    name: '7. the client checks the relayed sender against the server attestation',
    async run(base) {
      const r = await get(base, '/js/signal.js');
      return { status: r.status, sfrom: r.text.includes('sfrom'), checker: r.text.includes('checkSender') };
    },
  },
  {
    name: '8. the crypto module exposes the key commitment',
    async run(base) {
      const r = await get(base, '/js/crypto.js');
      return { status: r.status, commit: r.text.includes('commitPublicKey') };
    },
  },
  {
    // The stylesheet carries this deploy's two visible changes: the status log became a
    // collapsible dock, and the landing caps at its reading measure instead of stretching
    // across a 2560px display. Probe 2 hashes the gate document and the two heaviest
    // modules and would not have noticed either, so without this the deploy's own change
    // would have gone out with nothing measuring whether it landed.
    name: '9. the stylesheet is the one with the log dock and the landing measure cap',
    async run(base) {
      const r = await get(base, '/css/style.css');
      return {
        status: r.status,
        bytes: Buffer.byteLength(r.text, 'utf8'),
        sha: createHash('sha256').update(Buffer.from(r.text, 'utf8')).digest('hex').slice(0, 16),
        dock: r.text.includes('.log-dock'),
        collapsed: r.text.includes('.log-dock:not([data-open]) .log'),
        landingCap: r.text.includes('min(1320px, 90vw)'),
      };
    },
  },
  {
    // Three modules that did not exist in the last deployment. On a stale target these are
    // 404s, which is the loudest possible BAD, and it is the right check for them: the
    // page weight budget passes by moving code behind a lazy import, and a lazy import
    // that 404s in production fails at the moment the user presses the button rather than
    // at load, so "the file is there" is exactly the claim worth verifying.
    name: '10. the modules split out for the page weight budget are actually served',
    async run(base) {
      const out = {};
      for (const p of ['/js/chunkwire.js', '/js/streamable.js', '/js/share.js']) {
        const r = await get(base, p);
        out[p] = {
          status: r.status,
          bytes: Buffer.byteLength(r.text, 'utf8'),
          sha: createHash('sha256').update(Buffer.from(r.text, 'utf8')).digest('hex').slice(0, 16),
        };
      }
      return out;
    },
  },
  {
    // The ONLY probe in this file that can tell whether the container was restarted.
    // Every other one reads a file out of `public/`, and `public/` is an rsync target:
    // static bytes go live without touching the process. This deploy also changes
    // `server/index.js`, and a served header is the one thing a stale process cannot fake.
    //
    // Without `media-src`, CSP falls back to `default-src 'none'` and every previewed
    // <video>/<audio> is blocked. That failure is invisible from the outside: the file
    // downloads, the element appears, and nothing plays. So the header is the evidence.
    name: "11. the gate's CSP allows a blob media preview, which only a restarted container serves",
    async run(base) {
      const r = await get(base, '/app');
      const csp = r.headers.get('content-security-policy') || '(absent)';
      const media = (csp.match(/media-src [^;]*/) || ['(absent)'])[0];
      return {
        media,
        // Reported alongside, because "media-src is present" and "media-src is present and
        // did not quietly widen" are different claims and only the second one is safe.
        noData: !/media-src[^;]*data:/.test(csp),
        noWildcard: !/media-src[^;]*\*/.test(csp),
      };
    },
  },
  {
    // Five modules that did not exist in the last deployment, for the same reason probe 10
    // exists: each is behind an `import()` that only runs after a decision the user makes
    // minutes into a session, so a 404 here does not fail at load. It fails when a receiver
    // presses Accept all, or Open, or picks a folder, and it fails as a broken feature
    // rather than as a missing file.
    name: '12. the modules added by the batch accept, the preview and the sink split are served',
    async run(base) {
      const out = {};
      // scanui.js joined this list on 2026-08-10 for exactly the reason the comment above
      // gives: the camera panel moved off the boot path, so a 404 on it now shows up only
      // when somebody presses "scan the code with the camera", which is minutes after the
      // deploy looked fine.
      for (const p of ['/js/batchui.js', '/js/dirsink.js', '/js/preview.js', '/js/filesink.js',
        '/js/common.js', '/js/scanui.js']) {
        const r = await get(base, p);
        out[p] = {
          status: r.status,
          // A 404 from this server answers with JSON, and a module served as JSON is refused
          // by the browser at `import()` time even though the bytes arrived. Status alone
          // would not separate those two, so the type is part of the claim.
          ctype: /javascript/.test(r.headers.get('content-type') || ''),
          bytes: Buffer.byteLength(r.text, 'utf8'),
          sha: createHash('sha256').update(Buffer.from(r.text, 'utf8')).digest('hex').slice(0, 16),
        };
      }
      return out;
    },
  },
  {
    // The two changes in this deploy that a user would actually notice and that no hash
    // above pins to its cause. Probe 9 hashes the whole stylesheet, so it goes red for any
    // edit at all and never says which one; probe 6 reads link.js for the key exchange and
    // would pass with the transfer half years out of date.
    //
    // `parked` is the resume fix: a resume that lands while a send is still running used to
    // be answered `file-resume-ok` and then dropped on the streaming latch, so the promise
    // was made and never kept and a 434 MB transfer died on the receiver's timer. That is
    // the one line here whose absence is data loss rather than cosmetics.
    name: '13. the compact verification panel and the resume-parking fix are the served ones',
    async run(base) {
      const css = await get(base, '/css/style.css');
      const link = await get(base, '/js/link.js');
      return {
        sasBox: css.text.includes('.sas-box'),
        sasLine: css.text.includes('.sas-line'),
        parked: link.text.includes('out.parked'),
        batchGrant: link.text.includes('batchGrant'),
        coverage: link.text.includes('newCoverage'),
      };
    },
  },
  {
    // The preview panel now points a receiver at VirusTotal for a file that arrived from
    // someone else. It is advice, so nothing breaks when it is missing: the panel renders,
    // the file opens, and the only thing absent is the sentence telling the user to check
    // it first. That is precisely the class of change no hash above would attribute, and
    // that a stale `preview.js` would carry away silently.
    //
    // Matched on the full upload URL rather than on the word VirusTotal, because the word
    // is one edit away from appearing in a comment while the link still points nowhere.
    name: '14. the preview panel serves the VirusTotal upload link',
    async run(base) {
      const r = await get(base, '/js/preview.js');
      return {
        status: r.status,
        url: r.text.includes('https://www.virustotal.com/gui/home/upload'),
        constName: r.text.includes('VIRUSTOTAL_URL'),
      };
    },
  },
  {
    // The batch panel gained a per-file state model, so a receiver who accepts 7 files sees
    // 7 rows and a tally instead of one download and six invisible files. Probed by the
    // words the model renders and by the table that holds them: a state without a label in
    // STATE_TEXT draws as nothing at all, so the table is the feature.
    //
    // Deliberately not matched on 'queued' or 'done' alone. Those are ordinary words that
    // could plausibly sit in the previous release's bytes, and a probe that matches the
    // release it is supposed to detect the absence of is a probe that measures nothing.
    name: '15. the batch panel serves the per-file state model and its tally',
    async run(base) {
      const r = await get(base, '/js/batchui.js');
      return {
        status: r.status,
        table: r.text.includes('STATE_TEXT'),
        offeredText: r.text.includes('waiting for you to accept'),
        queuedText: r.text.includes('waiting its turn'),
        // The tally line, which is the "rather than one download" half of the change.
        tally: r.text.includes('Files arrive one at a time.'),
        strangers: r.text.includes('did not match what you were offered'),
      };
    },
  },
  {
    // A transfer that dies because the other tab closed used to end in a bare error code.
    // Both halves of the replacement are checked, because they are two separate claims: the
    // first says what happened, the second says what to do about it, and a partial deploy
    // that carried one without the other would read as an accusation with no way forward.
    name: '16. link.js serves the plain-language message for a peer that disconnected',
    async run(base) {
      const r = await get(base, '/js/link.js');
      return {
        status: r.status,
        cause: r.text.includes('severed, whether by accident or on purpose'),
        remedy: r.text.includes('establish a new connection and send it again'),
      };
    },
  },
  {
    // The sender's side of an offer. Before this, a file waiting on the other device's
    // Accept showed the SENDER nothing at all, so a receiver who walked away looked
    // identical to a transfer that had not started. `offeredRowId` is the identifier that
    // holds that row, and it is unique to this change: probe 2 hashes app.js and would go
    // red for any edit whatsoever without ever naming this one.
    name: '17. app.js serves the sender-side row for a file awaiting acceptance',
    async run(base) {
      const r = await get(base, '/js/app.js');
      return {
        status: r.status,
        marker: r.text.includes('offeredRowId'),
        // More than the declaration: the assignment and the lookup are what make the row
        // appear, and a file carrying only `let offeredRowId = null` would be a half deploy.
        uses: (r.text.match(/offeredRowId/g) || []).length >= 3,
      };
    },
  },
  {
    // Opening the games drawer on a phone used to leave the invitation below the fold, so
    // the invite existed and the user never saw it. The fix is two files that only work
    // together: gameui.js scrolls the status line into view, and style.css keeps the sticky
    // bar from covering the thing it just scrolled to. Deploying one without the other
    // scrolls the invitation exactly under the bar, so both are one probe.
    name: '18. the game invitation scrolls into view, and clears the bar when it does',
    async run(base) {
      const js = await get(base, '/js/gameui.js');
      const css = await get(base, '/css/style.css');
      return {
        jsStatus: js.status,
        cssStatus: css.status,
        scrolls: js.text.includes('scrollIntoView'),
        nearest: /scrollIntoView\(\{\s*block:\s*'nearest'/.test(js.text),
        // The whole rule, selector included: `scroll-margin-top` on its own already appears
        // elsewhere in this stylesheet, so matching the property would be green before the
        // deploy and would stay green if the rule landed on the wrong selector.
        // Selector shortened on 2026-08-11: #games-disc is a child of .conn-rail above
        // 1024px now, so the old `#screen-connected > #games-disc` descendant combinator
        // stopped matching it on a desktop and the rule silently applied on phones only.
        // The leading newline matters. Without it this string is a SUBSTRING of the old
        // rule, so the probe would have been green against the pre-deploy stylesheet and
        // would have measured nothing, which is the exact failure the paragraph above is
        // about. Anchored to the start of the line, it is BAD until the new file is served.
        scrollMargin: css.text.includes("\n#games-disc .game-status { scroll-margin-top: calc(var(--bar-h) + 12px); }"),
      };
    },
  },
  {
    // The FAQ said "there is no app, no extension and no account, and there never will be"
    // while the repository shipped an MV3 extension, and the extension shipped that very
    // page inside itself. Both halves are checked: the front page has to advertise the
    // extension with a link somebody can follow, and the FAQ answer has to have stopped
    // denying it exists. The old sentence is matched too, because a stale faq.html would
    // otherwise pass on the new one being merely absent from a file that never loaded.
    name: '19. the extension is advertised on the front page, and the FAQ no longer denies it',
    async run(base) {
      const index = await get(base, '/index.html');
      const faq = await get(base, '/faq.html');
      // The release download, not the source folder it used to point at: "clone the repo"
      // is a developer instruction. /releases/latest rather than a pinned tag so the link
      // does not have to be edited, and this probe does not have to be edited, every time
      // a version ships.
      const LINK = 'https://github.com/Fysh-ball/warp-gate/releases/latest';
      return {
        indexStatus: index.status,
        faqStatus: faq.status,
        onFrontPage: index.text.includes('A browser extension, if you want one'),
        frontPageLink: index.text.includes(LINK),
        faqLink: faq.text.includes(LINK),
        deniedItExists: faq.text.includes('no app, no extension and no account'),
      };
    },
  },
  {
    // The transfer that died when a phone locked its screen. Both halves are one probe
    // because either one alone still leaves a stall: resume.js has to stop refusing an
    // offset that is merely behind what landed here, and peer.js has to stop counting its
    // drain deadline on a clock that ran while the page did not.
    name: '20. the served gate tolerates a resume behind it and counts drain time while awake',
    async run(base) {
      const resume = await get(base, '/js/resume.js');
      const peer = await get(base, '/js/peer.js');
      return {
        resumeStatus: resume.status,
        peerStatus: peer.status,
        // The new comparison, and the ABSENCE of the old one. Presence alone would pass on
        // a file that somehow carried both.
        tolerates: resume.text.includes('offset < 0 || offset > at'),
        strictGone: !resume.text.includes('offset !== at'),
        // A `let` deadline is the tell: the wall-clock version could not be reassigned.
        // The clock became performance.now() on 2026-08-11; the needle follows the tree.
        deadlineMoves: peer.text.includes('let deadline = performance.now() + DRAIN_TIMEOUT_MS'),
        handsBackOvershoot: peer.text.includes('if (late > 0) deadline += late;'),
      };
    },
  },
  {
    // 61 KB of wordlist that every visitor used to fetch before the page knew whether they
    // were creating a gate, joining one, or reading the screen. Three readings, because a
    // half-deployed version of this is a page that cannot mint a code at all: crypto.js has
    // to expose the accessor, it must NOT still name words.js in a static import, and
    // app.js has to be the copy that awaits it.
    name: '21. the wordlist is served on demand, not on the boot path',
    async run(base) {
      const crypto = await get(base, '/js/crypto.js');
      const app = await get(base, '/js/app.js');
      const words = await get(base, '/js/words.js');
      return {
        cryptoStatus: crypto.status,
        appStatus: app.status,
        // Still reachable. A lazy module that 404s is worse than an eager one.
        wordsStatus: words.status,
        accessor: crypto.text.includes('export function loadGateCode()'),
        lazy: crypto.text.includes("import('./words.js')"),
        noStaticImport: !/^import .*from '\.\/words\.js';$/m.test(crypto.text),
        appAwaits: (app.text.match(/await loadGateCode\(\)/g) || []).length >= 3,
      };
    },
  },
];

for (const p of probes) {
  let refVal, tgtVal;
  try { refVal = await p.run(REF); } catch (e) { refVal = 'REF-ERROR: ' + e.message; }
  try { tgtVal = await p.run(TARGET); } catch (e) { tgtVal = 'TARGET-ERROR: ' + e.message; }
  report(p.name, refVal, tgtVal);
}

console.log(`\n${pass} match, ${fail} differ, ${vacuous} vacuous`);
if (vacuous > 0) {
  console.log('VACUOUS probes have lost their needle in this tree: they can no longer fail,');
  console.log('so they prove nothing about the deployment. Repair or retire them.');
}
srv.kill('SIGTERM');
await sleep(300);
srv.kill('SIGKILL');
process.exit(fail === 0 && vacuous === 0 ? 0 : 1);
