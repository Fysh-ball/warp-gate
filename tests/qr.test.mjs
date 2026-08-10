// QR encoder verification by independent decode.
//
// The encoder is checked by rendering a PNG and reading it back with zbarimg, a
// completely separate implementation. A QR code cannot be decoded unless the mode
// bits, Reed-Solomon blocks, interleaving, data placement, mask and format
// information are all correct, so a successful round trip is strong evidence.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { check, summary } from './lib/harness.mjs';
import { encodeQr, capacityFor } from '../public/js/qr.js';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-qr-'));

// ---------------------------------------------------------------- PNG writer

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** Render a QR matrix to an 8-bit greyscale PNG with a quiet zone. */
function renderPng(qr, scale = 8, quiet = 4) {
  const total = (qr.size + quiet * 2) * scale;
  const raw = Buffer.alloc((total + 1) * total, 0xff);
  for (let y = 0; y < total; y += 1) raw[y * (total + 1)] = 0; // filter byte per scanline
  for (let r = 0; r < qr.size; r += 1) {
    for (let c = 0; c < qr.size; c += 1) {
      if (!qr.modules[r * qr.size + c]) continue;
      for (let dy = 0; dy < scale; dy += 1) {
        const y = (r + quiet) * scale + dy;
        const rowStart = y * (total + 1) + 1;
        raw.fill(0x00, rowStart + (c + quiet) * scale, rowStart + (c + quiet) * scale + scale);
      }
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(total, 0);
  ihdr.writeUInt32BE(total, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // greyscale
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function decode(pngPath) {
  try {
    const out = execFileSync('zbarimg', ['--quiet', '--raw', pngPath], { encoding: 'utf8', timeout: 15000 });
    return out.replace(/\n$/, '');
  } catch (err) {
    return { error: err.message, status: err.status };
  }
}

function roundTrip(name, text) {
  const qr = encodeQr(text);
  const file = path.join(TMP, `${name}.png`);
  fs.writeFileSync(file, renderPng(qr));
  const decoded = decode(file);
  return { qr, decoded, file };
}

// ---------------------------------------------------------------- tooling check
{
  let version = '';
  try {
    version = execFileSync('zbarimg', ['--version'], { encoding: 'utf8', timeout: 5000 }).trim();
  } catch (err) {
    version = `MISSING: ${err.message}`;
  }
  check('zbarimg is available as an independent decoder', !version.startsWith('MISSING'), version);
}

// ---------------------------------------------------------------- negative control
{
  // Prove the decode check can fail. A matrix of noise must NOT decode; if this
  // "passes", the whole suite proves nothing.
  const qr = encodeQr('https://warpgate.fysh.site/#WARP-TEST');
  for (let i = 0; i < qr.modules.length; i += 3) qr.modules[i] ^= 1;
  const file = path.join(TMP, 'corrupt.png');
  fs.writeFileSync(file, renderPng(qr));
  const decoded = decode(file);
  check('a deliberately corrupted matrix fails to decode, so the check is real',
    typeof decoded !== 'string' || decoded === '', typeof decoded === 'string' ? `decoded "${decoded}"` : 'failed as expected');
}

// ---------------------------------------------------------------- real payloads
{
  // The WORST case, not an average one, and it is close to the ceiling: eight seven-letter
  // words is the longest code the wordlist can produce, and qr.js stops at version 6, which
  // holds 106 payload bytes. This URL is 99. That 7-byte headroom is the reason words.js
  // caps its entries at seven letters.
  const url = 'https://warpgate.fysh.site/app#WARP-BALANCE-BEEHIVE-BISCUIT-BICYCLE-BAGPIPE-BALCONY-BANQUET-BAPTISM';
  const { qr, decoded } = roundTrip('warpgate-link', url);
  check('a real Warp Gate link encodes and decodes byte-for-byte',
    decoded === url, typeof decoded === 'string' ? decoded : JSON.stringify(decoded));
  // Was `<= 5` against a 59-byte base32 link. The longest word code needs version 6, which
  // is the last version qr.js implements, so this is now a check on the actual ceiling
  // rather than on comfortable headroom. Stated as bytes as well as version, because
  // "version 6" alone does not say how close 99 is to 106.
  check('the longest possible Warp Gate link still fits the highest version qr.js supports',
    qr.version <= 6, `version ${qr.version}, ${url.length} bytes of a 106-byte capacity`);
  check('and a longer link than the wordlist can produce is refused rather than silently truncated',
    (() => {
      try { roundTrip('too-long', `${url}-OVERFLOW`); return false; } catch (err) { return /capacity|too long|refus/i.test(err.message); }
    })(), 'a payload past version 6 must throw');
  check('module matrix is square and the documented size',
    qr.modules.length === qr.size * qr.size && qr.size === 17 + 4 * qr.version, `size ${qr.size} v${qr.version}`);
}

// ---------------------------------------------------------------- every version
{
  let allOk = true;
  const details = [];
  for (let version = 1; version <= 6; version += 1) {
    // Fill the version exactly to its stated capacity: an off-by-one in the capacity
    // table would show up here as either an overflow error or a decode failure.
    const payload = 'A'.repeat(capacityFor(version));
    const { qr, decoded } = roundTrip(`version-${version}`, payload);
    const ok = decoded === payload && qr.version === version;
    if (!ok) { allOk = false; details.push(`v${version}: got v${qr.version} decoded=${JSON.stringify(decoded).slice(0, 60)}`); }
  }
  check('all six versions encode at exactly their stated capacity and decode back', allOk, details.join(' | '));

  const overflow = (() => {
    try { encodeQr('A'.repeat(capacityFor(6) + 1)); return 'accepted'; } catch (err) { return err.message; }
  })();
  check('exceeding version 6 capacity is refused with a clear error',
    /exceeds/.test(String(overflow)), String(overflow));
}

// ---------------------------------------------------------------- fuzz
{
  let failures = 0;
  const seen = new Set();
  for (let i = 0; i < 25; i += 1) {
    const length = 10 + ((i * 7) % 90);
    // Deterministic pseudo-random payload: reproducible if this ever fails.
    let text = '';
    for (let j = 0; j < length; j += 1) {
      text += 'ABCDEFGHJKMNPQRSTVWXYZ0123456789-:/.#'[(i * 31 + j * 17) % 37];
    }
    const { qr, decoded } = roundTrip(`fuzz-${i}`, text);
    seen.add(qr.version);
    if (decoded !== text) {
      failures += 1;
      process.stdout.write(`     fuzz ${i} (${length} chars, v${qr.version}) decoded ${JSON.stringify(decoded)}\n`);
    }
  }
  check('25 varied payloads of 10 to 99 characters all round-trip', failures === 0, `${failures} failures`);
  check('the fuzz corpus exercised more than one version', seen.size > 1, `versions ${[...seen].sort().join(',')}`);
}

// ---------------------------------------------------------------- donation addresses
{
  // These are read out of the shipped HTML rather than hardcoded, so the test proves
  // that what a donor scans is exactly what the page displays. A QR that differs from
  // the visible address by one character sends money to nobody.
  const html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const found = [...html.matchAll(/id="addr-([a-z]+)"[^>]*>([^<]+)</g)]
    .map((m) => ({ name: m[1], address: m[2].trim() }));

  check('donation addresses were found in the page', found.length >= 2, `found ${found.length}`);

  for (const { name, address } of found) {
    const { qr, decoded } = roundTrip(`donate-${name}`, address);
    check(`${name.toUpperCase()} address survives the QR round trip exactly`,
      decoded === address,
      typeof decoded === 'string' ? `decoded ${decoded.length} chars, expected ${address.length}` : JSON.stringify(decoded));
    check(`${name.toUpperCase()} QR fits the supported version range`, qr.version <= 6, `version ${qr.version}`);
  }
}

fs.rmSync(TMP, { recursive: true, force: true });
process.exit(summary('qr') ? 0 : 1);
