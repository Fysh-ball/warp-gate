// Build the loadable .zip of the extension.
//
// "Clone the repo and load unpacked" is a developer instruction, not something you can
// hand to a person, so the shipped artifact is a zip attached to a release. There is no
// `zip` binary on the build box and this repository has no dependencies, so the archive is
// written here: deflate plus the three ZIP records, with a fixed timestamp so the same
// tree always produces the same bytes and a release can be compared against a rebuild.
//
// The file list is an ALLOWLIST BY STRUCTURE (manifest.json, the three asset directories,
// the top-level pages) and never a list of names to exclude. A denylist rots in the
// dangerous direction: the day someone adds another dev script beside sync-from-public.mjs
// it ships to users, and nothing says so. This way a new dev file is excluded by default
// and a new REQUIRED file is caught by verify() below rather than shipped missing.

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';

const HERE = path.dirname(new URL(import.meta.url).pathname);

// Dev tooling that must never reach a user, asserted explicitly at the end. This is a
// belt on top of the allowlist, not the mechanism: if the allowlist ever grows a hole,
// this is the thing that says so out loud instead of quietly widening the package.
const NEVER_SHIP = ['pack.mjs', 'sync-from-public.mjs', 'drift-check.mjs', 'extension.test.mjs', 'README.md'];

const ASSET_DIRS = ['css', 'icons', 'js'];

/** Every file the package ships, relative to the extension root, sorted. */
export function fileList(root) {
  const out = ['manifest.json'];
  for (const name of fs.readdirSync(root)) {
    if (name.endsWith('.html')) out.push(name);
  }
  for (const dir of ASSET_DIRS) {
    const abs = path.join(root, dir);
    if (!fs.existsSync(abs)) continue;
    const walk = (rel) => {
      for (const name of fs.readdirSync(path.join(root, rel)).sort()) {
        const child = `${rel}/${name}`;
        if (fs.statSync(path.join(root, child)).isDirectory()) walk(child);
        else out.push(child);
      }
    };
    walk(dir);
  }
  return out.sort();
}

/**
 * Refuse to build a package that is missing something it references.
 *
 * The allowlist decides what goes IN; this decides whether that was enough. Without it a
 * renamed icon or a new stylesheet would produce a perfectly valid zip that fails to load,
 * and the only signal would be a user's error message.
 */
export function verify(root, list) {
  const have = new Set(list);
  const missing = [];
  const seen = [];

  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  const fromManifest = [
    ...Object.values(manifest.icons ?? {}),
    ...Object.values(manifest.action?.default_icon ?? {}),
    manifest.background?.service_worker,
    ...(manifest.background?.scripts ?? []),
    manifest.options_ui?.page,
  ].filter((v) => typeof v === 'string');
  for (const ref of fromManifest) {
    seen.push(`manifest.json -> ${ref}`);
    if (!have.has(ref)) missing.push(`manifest.json references ${ref}, which is not in the package`);
  }

  for (const rel of list.filter((f) => f.endsWith('.html'))) {
    const html = fs.readFileSync(path.join(root, rel), 'utf8');
    for (const m of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
      // A leading slash is package-relative here, not host-relative: sync-from-public.mjs
      // rewrites these pages precisely so root links resolve against the extension root.
      // Treating them as "not our business", which is right for a website, skipped every
      // real reference in the package and left this check with six.
      const ref = m[1].split('#')[0].split('?')[0].replace(/^\.\//, '').replace(/^\//, '');
      if (ref === '' || /^[a-z]+:/i.test(m[1])) continue;
      const resolved = m[1].startsWith('/')
        ? ref
        : path.posix.normalize(path.posix.join(path.posix.dirname(rel), ref));
      seen.push(`${rel} -> ${resolved}`);
      if (!have.has(resolved)) missing.push(`${rel} references ${ref}, which is not in the package`);
    }
  }

  // An empty reference set would make this check pass while measuring nothing, which is
  // exactly how a verifier reports green on a package it never looked at.
  if (seen.length < 10) {
    throw new Error(`only ${seen.length} references were found to check, which means this check is broken, not that the package is clean`);
  }

  const shipped = NEVER_SHIP.filter((f) => have.has(f));
  if (shipped.length) missing.push(`dev files would be shipped to users: ${shipped.join(', ')}`);

  return { missing, checked: seen.length };
}

// ---- the archive itself

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

// 1980-01-01 00:00:00 in DOS format. Fixed rather than the file's own mtime so that
// rebuilding an unchanged tree produces byte-identical output: a release asset that cannot
// be reproduced cannot be checked against its source, which is most of the point of
// shipping the client in a package at all.
const DOS_DATE = (1 << 5) | 1;
const DOS_TIME = 0;

export function buildZip(root, list) {
  const locals = [];
  const central = [];
  let offset = 0;

  for (const rel of list) {
    const raw = fs.readFileSync(path.join(root, rel));
    const packed = zlib.deflateRawSync(raw, { level: 9 });
    const name = Buffer.from(rel, 'utf8');
    const crc = crc32(raw);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, packed);

    const dir = Buffer.alloc(46);
    dir.writeUInt32LE(0x02014b50, 0);
    dir.writeUInt16LE(20, 4);
    dir.writeUInt16LE(20, 6);
    dir.writeUInt16LE(0, 8);
    dir.writeUInt16LE(8, 10);
    dir.writeUInt16LE(DOS_TIME, 12);
    dir.writeUInt16LE(DOS_DATE, 14);
    dir.writeUInt32LE(crc, 16);
    dir.writeUInt32LE(packed.length, 20);
    dir.writeUInt32LE(raw.length, 24);
    dir.writeUInt16LE(name.length, 28);
    // Multiplied, not shifted: JS bitwise operators are 32-bit SIGNED, so `0o100644 << 16`
    // is negative and writeUInt32LE refuses it. The mode has to survive into the archive
    // because a zip whose entries unpack without a read bit is a zip that will not load.
    dir.writeUInt32LE(0o100644 * 65536, 38);
    dir.writeUInt32LE(offset, 42);
    central.push(dir, name);

    offset += local.length + name.length + packed.length;
  }

  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(list.length, 8);
  end.writeUInt16LE(list.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, cd, end]);
}

// ---- run

if (process.argv[1] && process.argv[1].endsWith('pack.mjs')) {
  const root = process.argv[2] ? path.resolve(process.argv[2]) : HERE;
  const outDir = process.argv[3] ? path.resolve(process.argv[3]) : path.join(HERE, '..', 'dist');

  const list = fileList(root);
  const { missing, checked } = verify(root, list);
  if (missing.length) {
    process.stdout.write('BAD  the package is incomplete, so nothing was written:\n');
    for (const m of missing) process.stdout.write(`     ${m}\n`);
    process.exit(1);
  }
  process.stdout.write(`OK   ${checked} references all resolve inside the package\n`);

  const version = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8')).version;
  fs.mkdirSync(outDir, { recursive: true });
  const out = path.join(outDir, `warp-gate-extension-${version}.zip`);
  const zip = buildZip(root, list);
  fs.writeFileSync(out, zip);
  process.stdout.write(`OK   wrote ${out} (${list.length} files, ${(zip.length / 1024).toFixed(0)} KiB)\n`);

  // Written by hand above, so it is read back by something that did not write it. A zip
  // this file both produces and validates would agree with itself about a broken archive.
  try {
    execFileSync('unzip', ['-t', out], { stdio: 'pipe' });
    const listed = execFileSync('unzip', ['-Z1', out], { encoding: 'utf8' }).trim().split('\n');
    if (listed.length !== list.length) throw new Error(`unzip sees ${listed.length} entries, not ${list.length}`);
    process.stdout.write(`OK   unzip reads the archive and agrees on all ${listed.length} entries\n`);
  } catch (err) {
    process.stdout.write(`BAD  unzip refused the archive this script wrote: ${err.message}\n`);
    process.exit(1);
  }
}
