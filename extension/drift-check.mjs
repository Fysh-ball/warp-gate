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
// So the fork is made LOUD. Every file is compared against its public/ counterpart, and
// exactly two outcomes are acceptable: byte-identical, or on the list of files this
// directory deliberately patches, with the patch still present. Anything else fails.
//
// This does NOT verify the CONTENT of a patch is still correct, only that the set of
// patched files has not grown or shrunk and that the copies are otherwise in step. That is
// the part a human forgets; judging a patch is the part a human is for.
//
// Run with:  node extension/drift-check.mjs

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.resolve(HERE, '..', 'public');

/**
 * Files copied from public/ that this directory deliberately changes, and the marker each
 * change carries. Keep this list and extension/README.md in step: the README explains WHY
 * each one is patched and this decides whether it still IS.
 */
const PATCHED = new Map([
  ['js/signal.js', 'EXTENSION PATCH'],
  ['js/session.js', 'EXTENSION PATCH'],
  ['js/app.js', 'EXTENSION PATCH'],
  // Was js/download.js until the predicate moved upstream into js/streamable.js. The entry
  // moved with the function, not with the filename: leaving it on download.js would have
  // failed loudly here (a file on the patched list that is byte-identical), which is the
  // behaviour this list is for.
  ['js/streamable.js', 'EXTENSION PATCH'],
  ['app.html', 'EXTENSION PATCH'],
  // The legal pages differ by one mechanical rewrite: href="/" is the site's landing
  // document, which this package does not ship, so it points at index.html instead.
  ['faq.html', 'href="/index.html"'],
  ['privacy.html', 'href="/index.html"'],
  ['terms.html', 'href="/index.html"'],
  ['acceptable-use.html', 'href="/index.html"'],
]);

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

// 3. Every shared file is either identical or a declared patch that still carries its marker.
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
  const same = a.equals(b);
  const marker = PATCHED.get(rel);
  if (same && marker) {
    fail(`extension/${rel} is byte-identical to public/${rel}, but it is on the patched list. `
      + 'Either the patch was lost, or the list is stale. Both are wrong.');
    continue;
  }
  if (same) { identical += 1; continue; }
  if (!marker) {
    fail(`extension/${rel} differs from public/${rel} and is NOT on the patched list. `
      + 'This is either drift between the two copies or an undocumented change.');
    continue;
  }
  if (!b.toString('utf8').includes(marker)) {
    fail(`extension/${rel} differs from public/${rel} but does not carry its "${marker}" marker, `
      + 'so the difference is not the documented one.');
    continue;
  }
  patched += 1;
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
