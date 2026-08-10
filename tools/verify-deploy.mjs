// Compare a deployed origin against what this working tree actually serves.
//
//   node tools/verify-deploy.mjs https://warpgate.fysh.site
//
// The reference side is a server started from THIS TREE on a private port, so every
// expectation comes from the code rather than from a value typed here that drifts the
// moment somebody edits a header. Exit 0 when everything matches, 1 otherwise.
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
function report(name, refVal, tgtVal) {
  const same = JSON.stringify(refVal) === JSON.stringify(tgtVal);
  const line = `${name}\n     tree=${JSON.stringify(refVal)}\n     live=${JSON.stringify(tgtVal)}`;
  if (same) { pass++; console.log('OK   ' + line); }
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
      for (const p of ['/js/batchui.js', '/js/dirsink.js', '/js/preview.js', '/js/filesink.js', '/js/common.js']) {
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
];

for (const p of probes) {
  let refVal, tgtVal;
  try { refVal = await p.run(REF); } catch (e) { refVal = 'REF-ERROR: ' + e.message; }
  try { tgtVal = await p.run(TARGET); } catch (e) { tgtVal = 'TARGET-ERROR: ' + e.message; }
  report(p.name, refVal, tgtVal);
}

console.log(`\n${pass} match, ${fail} differ`);
srv.kill('SIGTERM');
await sleep(300);
srv.kill('SIGKILL');
process.exit(fail === 0 ? 0 : 1);
