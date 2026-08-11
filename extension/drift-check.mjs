// Does the extension's copy of the client still match public/?
//
// WHY THIS EXISTS
//
// extension/ carries a copy of the web client, because the web client addresses the server
// that served it and this one has to be told where the server is (see js/endpoint.js). A
// copy is a fork, and a fork of 14,000 lines of security-relevant JavaScript will drift the
// first time somebody fixes a bug in public/ and forgets this directory. Drift here is not
// cosmetic: the extension exists to be the trustworthy delivery path, and a trustworthy
// delivery path serving a client six months behind the audited one is worse than useless.
//
// So the fork is made LOUD. Every file is compared against its public/ counterpart. A file
// the recipe does not patch must be byte-identical. A file the recipe DOES patch must be
// byte-identical to a FRESH application of sync-from-public.mjs's recipe to today's
// public/, so its content is pinned exactly: an edit to public/, to the shipped copy, or
// to the recipe itself all read as drift until the sync is rerun. The earlier version of
// this check asserted only "differs from public and carries the patch marker", which is
// permanently true of a patched file and therefore could not fail: a patched copy could
// rot arbitrarily and the gate stayed green. Judging whether a patch is the RIGHT change
// is still the part a human is for; that it is the change that shipped is machine-checked.
//
// Run with:  node extension/drift-check.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
// The recipe itself: the list of patched files and the function that applies their
// patches. One source of truth, shared with the tool that writes the files.
// extension/README.md explains WHY each file is patched.
import { PATCHES, PATCHED_FILES, patchedText } from './sync-from-public.mjs';
import { DEFAULT_ORIGIN, matchPatternFor } from './js/endpoint.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.resolve(HERE, '..', 'public');

/**
 * Files that exist only in the extension. Listed rather than inferred, so that a stray file
 * dropped into this directory is reported instead of quietly shipping inside the package.
 */
const EXTENSION_ONLY = new Set([
  'manifest.json',
  'index.html',
  'js/endpoint.js',
  'js/options.js',
  'js/background.js',
  'README.md',
  'drift-check.mjs',
  'sync-from-public.mjs',
  'extension.test.mjs',
]);

/**
 * Files in public/ this package deliberately does not ship, and why.
 *
 * Stated rather than left as an absence: "it is not there" and "we decided not to ship it"
 * look identical on disk, and only one of them is a decision.
 */
const NOT_SHIPPED = new Map([
  ['index.html', "the site landing page: a marketing document with no gate machinery in it. "
    + "The extension's own index.html of the same name replaces it, which is why the "
    + 'comparison below skips this name entirely.'],
  ['js/landing.js', 'only the site landing page loads it.'],
  ['sw.js', 'Chromium refuses to let an extension PAGE register a service worker, so the '
    + 'streaming download it provides cannot run here at all. See js/streamable.js.'],
  ['manifest.webmanifest', 'a web app manifest names a start_url and a scope on a server. '
    + 'There is no server here.'],
]);

let problems = 0;
const fail = (msg) => { problems += 1; process.stdout.write(`BAD  ${msg}\n`); };
const pass = (msg) => process.stdout.write(`OK   ${msg}\n`);

/** Every file under a directory, as paths relative to it. */
function walk(dir, base = dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full, base));
    else out.push(path.relative(base, full));
  }
  return out;
}

const publicFiles = new Set(walk(PUBLIC));
const extFiles = new Set(walk(HERE));

// 1. Nothing in public/ has gone missing from the copy without a stated reason.
for (const rel of publicFiles) {
  if (extFiles.has(rel)) continue;
  if (NOT_SHIPPED.has(rel)) continue;
  fail(`public/${rel} is not in the extension and is not on the deliberately-not-shipped list. `
    + 'A file added to the client after this copy was made will simply be absent here, and the '
    + 'first symptom is a module that fails to import at runtime.');
}

// 2. Nothing is in the extension that is neither a copy nor a declared original.
for (const rel of extFiles) {
  if (publicFiles.has(rel) || EXTENSION_ONLY.has(rel)) continue;
  fail(`extension/${rel} is neither a copy of a public/ file nor on the extension-only list. `
    + 'Everything in this directory ships inside the package, so an unaccounted file is an '
    + 'unaccounted shipped file.');
}

// 3. Every unpatched shared file is byte-identical; every patched one matches a fresh
// application of the recipe to today's public/.
let identical = 0;
let patched = 0;
for (const rel of publicFiles) {
  if (!extFiles.has(rel)) continue;
  // A name that exists in both trees but is not a copy: extension/index.html REPLACES the
  // site landing page rather than copying it, so comparing them is meaningless. Skipped by
  // name rather than by heuristic, because "these two files happen to share a name" and
  // "this file drifted" must never be the same report.
  if (EXTENSION_ONLY.has(rel)) continue;
  const a = fs.readFileSync(path.join(PUBLIC, rel));
  const b = fs.readFileSync(path.join(HERE, rel));
  if (!PATCHED_FILES.has(rel)) {
    if (a.equals(b)) { identical += 1; continue; }
    fail(`extension/${rel} differs from public/${rel} and is NOT on the patched list. `
      + 'This is either drift between the two copies or an undocumented change.');
    continue;
  }
  let expected;
  try {
    expected = patchedText(rel, a.toString('utf8'));
  } catch (err) {
    fail(`the recipe for extension/${rel} no longer applies to public/${rel}: ${err.message}`);
    continue;
  }
  if (b.toString('utf8') === expected) { patched += 1; continue; }
  if (a.equals(b)) {
    fail(`extension/${rel} is byte-identical to public/${rel}, but it is on the patched list. `
      + 'Either the patch was lost, or the list is stale. Both are wrong.');
    continue;
  }
  fail(`extension/${rel} does not match a fresh application of the recipe to public/${rel}. `
    + 'Either public/ moved, the shipped copy was edited, or the recipe changed. '
    + 'Run node extension/sync-from-public.mjs and read the resulting diff.');
}

// 4. The default origin lives in three places with three different owners: js/endpoint.js
// (the value the client signals to), manifest.json host_permissions (what a fresh install
// is allowed to contact), and the recipe's app.html disclosure (what the page tells the
// user). If one moves and another lags, a fresh install signals to an origin it has no
// permission for and every request fails opaquely, because only a user-gesture Save can
// prompt for more. Assert agreement instead of hoping.
const manifest = JSON.parse(fs.readFileSync(path.join(HERE, 'manifest.json'), 'utf8'));
const pattern = matchPatternFor(DEFAULT_ORIGIN);
if (!(manifest.host_permissions ?? []).includes(pattern)) {
  fail(`manifest.json host_permissions ${JSON.stringify(manifest.host_permissions ?? [])} is missing `
    + `${pattern}, the match pattern for js/endpoint.js DEFAULT_ORIGIN ${DEFAULT_ORIGIN}. `
    + 'A fresh install would have no permission to reach its own default origin.');
} else {
  pass(`manifest host_permissions covers DEFAULT_ORIGIN ${DEFAULT_ORIGIN}`);
}
const disclosure = (PATCHES.get('app.html') ?? []).map(([, to]) => to).join('\n');
if (!disclosure.includes(`<span id="instance-origin">${DEFAULT_ORIGIN}</span>`)) {
  fail('the sync-from-public.mjs app.html disclosure does not name js/endpoint.js '
    + `DEFAULT_ORIGIN ${DEFAULT_ORIGIN}, so the page would tell the user it signals `
    + 'somewhere it does not.');
} else {
  pass('the app.html disclosure names the same DEFAULT_ORIGIN');
}

// The positive control. Every count above can be zero, and zero problems with zero files
// compared is what a broken path looks like: PUBLIC resolving somewhere empty would report
// a clean run. Refuse to call that a pass.
if (identical + patched === 0) {
  fail(`nothing was compared at all. public/ resolved to ${PUBLIC}; this check measured nothing `
    + 'and a green result here would be meaningless.');
} else {
  pass(`${identical} files byte-identical to public/, ${patched} deliberately patched`);
}

process.stdout.write(problems === 0
  ? '\ndrift-check: the extension copy is in step with public/\n'
  : `\ndrift-check: ${problems} problem(s)\n`);
process.exit(problems === 0 ? 0 : 1);
