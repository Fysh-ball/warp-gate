// What each page actually costs to open, and what is NOT in that cost.
//
// Two different questions, and only one of them is about speed:
//
//   1. How many bytes does a browser fetch before the gate is usable? A ceiling that
//      fails the build is the only thing that stops this drifting upward one honest
//      addition at a time.
//   2. Is any of that code off the security path? The gate's whole job is a key
//      exchange and two words a human reads aloud. A chess move generator and a
//      Reed-Solomon decoder loading ahead of that screen is not a performance
//      complaint, it is a surface-area complaint: an auditor reading the load path
//      should find nothing in it that a gate could run without.
//
// The graph is walked from the static `import` statements only, which is exactly what
// the browser fetches eagerly. `import(...)` calls are deliberately NOT followed: they
// are the mechanism under test.
//
// Run: node tests/size.test.mjs

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { check, summary } from './lib/harness.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const JS = path.join(ROOT, 'public', 'js');

/**
 * Every static import specifier in a module.
 *
 * Matches the four spellings that actually fetch on load: `import x from 's'`,
 * `import 's'`, `export ... from 's'`, and `import x, {y} from 's'`. A dynamic
 * `import('s')` has a paren where these have whitespace or a quote, so it cannot match:
 * that distinction is the entire point of this file, and check "the matcher can tell
 * the two apart" below proves it rather than asserting it.
 *
 * The class excludes quotes and parens but NOT newlines, and that is load bearing. It
 * used to exclude `\n` as well, which meant a perfectly ordinary wrapped import
 *
 *     import {
 *       one, two,
 *     } from './x.js';
 *
 * matched nothing at all, so './x.js' and everything it pulls in vanished from the
 * measured graph and every ceiling below passed while measuring less than the browser
 * fetches. That is the worst failure a budget can have: it FAILS OPEN, reporting green
 * precisely when the page got heavier. Found when a wrapped import in session.js silently
 * dropped link.js, the single largest module in the gate, out of the graph.
 *
 * Excluding parens still separates a static import from a dynamic one, because `import(`
 * puts a paren exactly where a static import has whitespace or a quote. The two checks
 * below prove both halves: that a wrapped import IS seen, and that a dynamic one is NOT.
 */
function staticImports(source) {
  const out = [];
  const re = /(?:^|\n)\s*(?:import|export)\b[^'"()]*?['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(source)) !== null) out.push(m[1]);
  return out;
}

function dynamicImports(source) {
  const out = [];
  const re = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  let m;
  while ((m = re.exec(source)) !== null) out.push(m[1]);
  return out;
}

/**
 * Walk the eager graph from an entry module and return every file in it.
 *
 * Returns a Map so a diamond (two modules importing the same third) is counted once,
 * which is what the browser does too.
 */
function eagerGraph(entry) {
  const seen = new Map();
  const queue = [path.join(JS, entry)];
  while (queue.length) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    const source = fs.readFileSync(file, 'utf8');
    seen.set(file, source);
    for (const spec of staticImports(source)) {
      if (!spec.startsWith('.')) continue; // no bare specifiers in this codebase
      queue.push(path.resolve(path.dirname(file), spec));
    }
  }
  return seen;
}

const rel = (file) => path.relative(JS, file);
const bytes = (graph) => [...graph.values()].reduce((n, src) => n + Buffer.byteLength(src), 0);
const packed = (graph) => [...graph.values()]
  .reduce((n, src) => n + zlib.gzipSync(Buffer.from(src), { level: 9 }).length, 0);

// ---------------------------------------------------------------- the matcher itself
//
// A size test that cannot tell a static import from a dynamic one would report the lazy
// split as working the moment it was written and would go on reporting it after somebody
// undid it. Prove the discrimination before trusting anything measured with it.
{
  const sample = [
    "import { a } from './a.js';",
    "import './b.js';",
    "export { c } from './c.js';",
    "import d, { e } from './d.js';",
    "const x = await import('./lazy.js');",
    "  return import('./also-lazy.js').then(f);",
  ].join('\n');

  const stat = staticImports(sample);
  const dyn = dynamicImports(sample);
  check('the matcher finds every static import',
    ['./a.js', './b.js', './c.js', './d.js'].every((s) => stat.includes(s)) && stat.length === 4,
    stat.join(' '));
  check('CONTROL: and counts neither dynamic import as static',
    !stat.includes('./lazy.js') && !stat.includes('./also-lazy.js'), stat.join(' '));
  check('CONTROL: while the dynamic matcher finds exactly those two',
    dyn.length === 2 && dyn.includes('./lazy.js') && dyn.includes('./also-lazy.js'),
    dyn.join(' '));
}

// ---------------------------------------------- the instrument, before the measurements
//
// Every ceiling below is only as good as the walker that feeds it, and a walker that
// misses an import understates the weight instead of failing. So prove the instrument
// first, on fixtures, where the right answer is known independently of the codebase.
{
  const WRAPPED = "import {\n  one,\n  two,\n} from './wrapped.js';\n";
  check('the walker sees an import wrapped across lines',
    staticImports(WRAPPED).includes('./wrapped.js'), JSON.stringify(staticImports(WRAPPED)));

  const ONE_LINE = "import { one } from './flat.js';\n";
  check('the walker sees an ordinary single-line import',
    staticImports(ONE_LINE).includes('./flat.js'), JSON.stringify(staticImports(ONE_LINE)));

  const SIDE_EFFECT = "import './side-effect.js';\n";
  check('the walker sees a bare side-effect import',
    staticImports(SIDE_EFFECT).includes('./side-effect.js'), JSON.stringify(staticImports(SIDE_EFFECT)));

  const REEXPORT = "export { a } from './reexport.js';\n";
  check('the walker sees a re-export, which fetches exactly like an import',
    staticImports(REEXPORT).includes('./reexport.js'), JSON.stringify(staticImports(REEXPORT)));

  // The other half. If this ever matched, every lazy module below would look eager and
  // the exclusion checks would fail loudly, which is the safe direction: it is the miss
  // above that is dangerous, not a false hit here.
  const DYNAMIC = "const mod = await import('./lazy.js');\n";
  check('CONTROL: the walker does NOT see a dynamic import, which is the thing under test',
    !staticImports(DYNAMIC).includes('./lazy.js'), JSON.stringify(staticImports(DYNAMIC)));

  const DYNAMIC_AT_START = "import('./lazy-at-line-start.js');\n";
  check('CONTROL: nor one sitting at the start of its own line',
    !staticImports(DYNAMIC_AT_START).includes('./lazy-at-line-start.js'),
    JSON.stringify(staticImports(DYNAMIC_AT_START)));

  // And that the fixtures are not all quietly returning nothing, which would satisfy
  // every negative check above while measuring nothing at all.
  check('CONTROL: the fixtures do resolve to specifiers, so the checks above are not vacuous',
    staticImports(WRAPPED).length === 1 && staticImports(REEXPORT).length === 1,
    `${staticImports(WRAPPED).length} ${staticImports(REEXPORT).length}`);
}

// ---------------------------------------------------------------- the gate
{
  const graph = eagerGraph('app.js');
  const raw = bytes(graph);
  const gz = packed(graph);

  // Ceilings, not measurements. Set roughly 10% above today so an honest addition fits
  // and a careless one does not, and stated in gzipped bytes as well as raw because
  // gzipped is what the server sends and therefore what a phone on mobile data waits for.
  //
  // words.js is 30 KB gzipped of that and is NOT excludable: crypto.js needs it to turn a
  // typed gate code into the room secret, which is the first thing a joining device does,
  // and to render one the instant somebody presses Create. Deferring it was considered and
  // rejected on 2026-08-10 for that second reason: a lazy import behind Create moves the
  // same fetch behind the primary action instead of removing it. It is on the critical
  // path by definition.
  //
  // ---- why the gzipped ceiling moved from 176 KB to 192 KB on 2026-08-10 ----
  //
  // A red-team review found the SAS could be forced to match: nothing committed to a
  // public key before both were exchanged, so a relay attacker holding the gate code could
  // grind a birthday collision in the 5-digit SAS with about 640 curve operations and make
  // two people read identical codes while each talked to the attacker. Fixing it added
  // commit-then-reveal to the handshake, sender attestation on every relayed envelope, and
  // a receive-side gate on key confirmation. Measured cost: the eager graph went from under
  // 180,224 B to 185,285 B gzipped, so at least 5,061 B of the increase is that fix.
  //
  // None of it can be lazy. It runs during the key exchange, which is the one thing the
  // gate exists to do, so the surface-area argument this file makes everywhere else says
  // the opposite here: this code belongs in front of the verification screen.
  //
  // The ceiling is therefore raised deliberately, once, with the number and the cause
  // written down. That is not the same as a ceiling that drifts: the next increase needs
  // its own reason of this kind, and "the tests went red" is not one. If this comment ever
  // grows a second entry that says "made room for a feature", the budget has stopped
  // working and should be lowered back.
  //
  // Both figures are the SUM of each file gzipped separately, not the graph gzipped as one
  // blob, because the server compresses per response. Measured together it is 177,655 B,
  // which is the more flattering number and the wrong one.
  const RAW_CEILING = 520 * 1024;
  const GZ_CEILING = 192 * 1024;

  check('the gate is under its raw byte ceiling',
    raw <= RAW_CEILING, `${raw} B eager across ${graph.size} modules, ceiling ${RAW_CEILING}`);
  check('the gate is under its gzipped ceiling',
    gz <= GZ_CEILING, `${gz} B gzipped, ceiling ${GZ_CEILING}`);

  // The named exclusions. Each is code that only runs after a decision the user has not
  // made when the gate opens, so none of it may be on the eager graph.
  const OFF_PATH = [
    ['the games match layer', 'gameplay.js'],
    ['the board renderer', 'gameui.js'],
    ['the chess engine', path.join('games', 'chess.js')],
    ['the battleships engine', path.join('games', 'battleships.js')],
    ['the QR decoder', 'qrdecode.js'],
    ['the camera scanner', 'qrscan.js'],
    ['the SAS word derivation', 'saswords.js'],
    // Split off the eager graph on 2026-08-10, when this session's work took the gate
    // 15,310 B over the raw ceiling. Each of these is the large half of a module whose
    // small half had been holding it on the boot path, and each obeys the same rule as
    // everything above: it cannot be reached until a decision nobody has made at load.
    ['the QR encoder', 'qr.js'],
    ['the share target', 'share.js'],
    ['the resume negotiation', 'resume.js'],
    ['the streaming download', 'download.js'],
  ];
  const eager = new Set([...graph.keys()].map(rel));
  for (const [what, file] of OFF_PATH) {
    check(`${what} is not fetched to open a gate`, !eager.has(file), file);
  }

  // The exclusion list is only meaningful if those files exist. A renamed module would
  // otherwise satisfy every check above by being absent from the whole repository.
  for (const [what, file] of OFF_PATH) {
    check(`CONTROL: ${what} exists, so its absence from the graph means something`,
      fs.existsSync(path.join(JS, file)), file);
  }

  // And the positive: the things that MUST be eager, because a gate cannot open without
  // them. If the split ever goes too far, this is what says so.
  for (const must of ['crypto.js', 'session.js', 'link.js', 'peer.js', 'transfer.js',
    // The small halves of the four splits above. If one of these ever fell off the graph
    // too, the module it was split out of would have taken its call sites with it and the
    // exclusions above would be passing because the FEATURE was deleted.
    'chunkwire.js', 'streamable.js']) {
    check(`CONTROL: ${must} IS on the eager graph, so the walk is really walking`,
      eager.has(must), [...eager].sort().join(' '));
  }

  // The lazy edge is present rather than merely the eager one being absent. Deleting the
  // import() entirely would pass every check above and ship a gate with no games at all.
  const appSrc = fs.readFileSync(path.join(JS, 'app.js'), 'utf8');
  const lazy = dynamicImports(appSrc);
  check('the gate still reaches the games, dynamically',
    lazy.includes('./gameplay.js') && lazy.includes('./gameui.js'), lazy.join(' '));

  // Same argument, one per split. An exclusion above says only that a file is absent from
  // the eager graph, and deleting its import() entirely satisfies that perfectly while
  // shipping a gate that cannot draw a QR, receive a shared file, resume a transfer or
  // stream a download. The edge has to be present, in the file that owns the call site.
  const REACHED = [
    ['the QR encoder', 'app.js', './qr.js'],
    ['the share target', 'app.js', './share.js'],
    ['the QR encoder from the donation modal', 'support.js', './qr.js'],
    ['the resume negotiation', 'link.js', './resume.js'],
    ['the streaming download', 'transfer.js', './download.js'],
  ];
  for (const [what, from, spec] of REACHED) {
    const edges = dynamicImports(fs.readFileSync(path.join(JS, from), 'utf8'));
    check(`the gate still reaches ${what}, dynamically`, edges.includes(spec),
      `${from} has no import(${spec}): ${edges.join(' ') || '(no dynamic imports at all)'}`);
  }
}

// ---------------------------------------------------------------- the landing
{
  const graph = eagerGraph('landing.js');
  const raw = bytes(graph);
  const gz = packed(graph);
  const RAW_CEILING = 130 * 1024;
  const GZ_CEILING = 40 * 1024;

  check('the landing is under its raw byte ceiling',
    raw <= RAW_CEILING, `${raw} B eager across ${graph.size} modules, ceiling ${RAW_CEILING}`);
  check('the landing is under its gzipped ceiling',
    gz <= GZ_CEILING, `${gz} B gzipped, ceiling ${GZ_CEILING}`);

  // A page whose only job is to explain the product and hand out a link has no business
  // holding the key exchange, the transfer machinery or a game.
  const eager = new Set([...graph.keys()].map(rel));
  for (const off of ['crypto.js', 'link.js', 'transfer.js', 'gameplay.js', 'qrdecode.js']) {
    check(`the landing does not pull in ${off}`, !eager.has(off), [...eager].sort().join(' '));
  }
}

// ---------------------------------------------------------------- a ceiling that bites
//
// Every ceiling above passes today, so none of them has ever been observed to fail, and
// an untriggered limit is a limit nobody has checked the arithmetic of. Run the same
// comparison against a ceiling below the measured size: it must report over.
{
  const graph = eagerGraph('app.js');
  const raw = bytes(graph);
  check('CONTROL: a ceiling below the measured size reports over',
    !(raw <= Math.floor(raw / 2)), `${raw} B vs a deliberately impossible ${Math.floor(raw / 2)}`);
  check('CONTROL: the walk found more than one module',
    graph.size > 1, `${graph.size} modules`);
}

// Exit code, not just a printed tally. A bare summary() call returns the verdict and
// throws it away, so the process exits 0 whatever happened and run-all.sh prints SUITE OK
// over a suite that failed. That is not a cosmetic bug: a budget nobody can fail is not a
// budget. tests/suggest.test.mjs had exactly this and reported green while broken.
process.exit(summary('page weight') ? 0 : 1);
