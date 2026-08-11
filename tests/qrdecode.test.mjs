// QR decoder verification by round trip against the encoder.
//
// qr.js is the only producer this decoder has to read, so the strongest test available
// is to encode a payload, paint the matrix into an ImageData-shaped buffer the way a
// camera frame would arrive, and require the exact string back. That path cannot
// succeed unless binarisation, finder location, perspective sampling, format
// information, unmasking, de-interleaving, Reed-Solomon and the bitstream parser are
// all correct at once.
//
// Round trips alone would still pass for a lookup table, so the rest of the suite
// attacks it: different scales, different quiet zones, an off-centre code in a
// non-square frame, all four rotations, salt-and-pepper and gaussian noise, and
// damage deliberately pushed past the error correction budget. The assertion that
// matters most is the last one: past the budget the answer must be null, never
// different text. Silently wrong text would send a scanning phone to the wrong room.

import { check, summary } from './lib/harness.mjs';
import { encodeQr, capacityFor } from '../public/js/qr.js';
import { decodeQr, decodeMatrix, rsDecode, lastDecodeError } from '../public/js/qrdecode.js';

const WORST_CASE = 'https://warpgate.fysh.site/app#WARP-BALANCE-BEEHIVE-BISCUIT-BICYCLE-BAGPIPE-BALCONY-BANQUET-BAPTISM';

// ---------------------------------------------------------------- frame helpers

/** xorshift32. Deterministic so a failure can be reproduced from the seed alone. */
function rng(seed) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13; state >>>= 0;
    state ^= state >> 17;
    state ^= state << 5; state >>>= 0;
    return state / 4294967296;
  };
}

function blankFrame(width, height, value = 255) {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < width * height; i += 1) {
    data[i * 4] = value;
    data[i * 4 + 1] = value;
    data[i * 4 + 2] = value;
    data[i * 4 + 3] = 255;
  }
  return { data, width, height };
}

/** Paint a module matrix into an existing frame at a pixel offset. */
function stamp(frame, qr, { scale = 6, quiet = 4, offsetX = 0, offsetY = 0 } = {}) {
  const light = 255;
  const paint = (x, y, value) => {
    if (x < 0 || x >= frame.width || y < 0 || y >= frame.height) return;
    const o = (y * frame.width + x) * 4;
    frame.data[o] = value;
    frame.data[o + 1] = value;
    frame.data[o + 2] = value;
    frame.data[o + 3] = 255;
  };
  const span = (qr.size + quiet * 2) * scale;
  for (let y = 0; y < span; y += 1) for (let x = 0; x < span; x += 1) paint(offsetX + x, offsetY + y, light);
  for (let r = 0; r < qr.size; r += 1) {
    for (let c = 0; c < qr.size; c += 1) {
      if (!qr.modules[r * qr.size + c]) continue;
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          paint(offsetX + (c + quiet) * scale + dx, offsetY + (r + quiet) * scale + dy, 0);
        }
      }
    }
  }
  return frame;
}

function render(qr, { scale = 6, quiet = 4 } = {}) {
  const span = (qr.size + quiet * 2) * scale;
  return stamp(blankFrame(span, span), qr, { scale, quiet });
}

/** Rotate a frame clockwise by 90 degrees, n times. */
function rotate(frame, quarters) {
  let current = frame;
  for (let n = 0; n < ((quarters % 4) + 4) % 4; n += 1) {
    const { width, height, data } = current;
    const out = new Uint8ClampedArray(data.length);
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        const source = (y * width + x) * 4;
        const target = (x * height + (height - 1 - y)) * 4;
        for (let k = 0; k < 4; k += 1) out[target + k] = data[source + k];
      }
    }
    current = { data: out, width: height, height: width };
  }
  return current;
}

/**
 * Solve the homography taking four (u,v) points to four (x,y) points, by direct linear
 * transform and gaussian elimination. Written out here rather than borrowed from the
 * decoder: a test that generated its input with the decoder's own perspective maths
 * would agree with itself no matter how wrong that maths was.
 */
function homography(pairs) {
  const matrix = [];
  const rhs = [];
  for (const [u, v, x, y] of pairs) {
    matrix.push([u, v, 1, 0, 0, 0, -u * x, -v * x]); rhs.push(x);
    matrix.push([0, 0, 0, u, v, 1, -u * y, -v * y]); rhs.push(y);
  }
  for (let col = 0; col < 8; col += 1) {
    let pivot = col;
    for (let r = col + 1; r < 8; r += 1) {
      if (Math.abs(matrix[r][col]) > Math.abs(matrix[pivot][col])) pivot = r;
    }
    [matrix[col], matrix[pivot]] = [matrix[pivot], matrix[col]];
    [rhs[col], rhs[pivot]] = [rhs[pivot], rhs[col]];
    for (let r = 0; r < 8; r += 1) {
      if (r === col) continue;
      const factor = matrix[r][col] / matrix[col][col];
      for (let c = col; c < 8; c += 1) matrix[r][c] -= factor * matrix[col][c];
      rhs[r] -= factor * rhs[col];
    }
  }
  const h = rhs.map((value, i) => value / matrix[i][i]);
  return (u, v) => {
    const denominator = h[6] * u + h[7] * v + 1;
    return [(h[0] * u + h[1] * v + h[2]) / denominator, (h[3] * u + h[4] * v + h[5]) / denominator];
  };
}

/** Project a frame onto an arbitrary convex quadrilateral: a camera held at an angle. */
function tilt(frame, corners, width, height) {
  const out = blankFrame(width, height);
  // Solved destination to source, so every output pixel has somewhere to read from.
  const toSource = homography([
    [corners[0], corners[1], 0, 0],
    [corners[2], corners[3], frame.width - 1, 0],
    [corners[4], corners[5], frame.width - 1, frame.height - 1],
    [corners[6], corners[7], 0, frame.height - 1],
  ]);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const [sx, sy] = toSource(x, y);
      const ix = Math.round(sx);
      const iy = Math.round(sy);
      if (ix < 0 || ix >= frame.width || iy < 0 || iy >= frame.height) continue;
      const source = (iy * frame.width + ix) * 4;
      const target = (y * width + x) * 4;
      out.data[target] = frame.data[source];
      out.data[target + 1] = frame.data[source + 1];
      out.data[target + 2] = frame.data[source + 2];
    }
  }
  return out;
}

function saltAndPepper(frame, fraction, seed) {
  const random = rng(seed);
  const out = { data: Uint8ClampedArray.from(frame.data), width: frame.width, height: frame.height };
  for (let i = 0; i < frame.width * frame.height; i += 1) {
    if (random() >= fraction) continue;
    const value = random() < 0.5 ? 0 : 255;
    out.data[i * 4] = value;
    out.data[i * 4 + 1] = value;
    out.data[i * 4 + 2] = value;
  }
  return out;
}

/** Box-Muller, so the added noise really is gaussian rather than uniform. */
function gaussianNoise(frame, sigma, seed) {
  const random = rng(seed);
  const out = { data: Uint8ClampedArray.from(frame.data), width: frame.width, height: frame.height };
  for (let i = 0; i < frame.width * frame.height; i += 1) {
    const u = Math.max(1e-9, random());
    const offset = Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * random()) * sigma;
    for (let k = 0; k < 3; k += 1) out.data[i * 4 + k] = out.data[i * 4 + k] + offset;
  }
  return out;
}

function noiseFrame(width, height, seed) {
  const random = rng(seed);
  const data = new Uint8ClampedArray(width * height * 4);
  for (let i = 0; i < width * height; i += 1) {
    const value = Math.floor(random() * 256);
    data[i * 4] = value;
    data[i * 4 + 1] = value;
    data[i * 4 + 2] = value;
    data[i * 4 + 3] = 255;
  }
  return { data, width, height };
}

/** Flip n module bits anywhere in the matrix, function patterns included. */
function damage(qr, flips, seed) {
  const random = rng(seed);
  const copy = { size: qr.size, modules: Uint8Array.from(qr.modules), version: qr.version };
  for (let i = 0; i < flips; i += 1) copy.modules[Math.floor(random() * copy.modules.length)] ^= 1;
  return copy;
}

/**
 * The module positions that carry data and EC codewords, worked out here rather than
 * imported so the test does not inherit the decoder's idea of the layout. Flipping
 * only these isolates error correction: damage to a finder or a timing pattern is a
 * location failure that no amount of Reed-Solomon can undo, so mixing the two in one
 * measurement would say nothing about either.
 */
function dataModules(qr) {
  const size = qr.size;
  const version = qr.version;
  const reserved = new Uint8Array(size * size);
  const mark = (r, c) => {
    if (r >= 0 && r < size && c >= 0 && c < size) reserved[r * size + c] = 1;
  };
  for (let r = 0; r < 8; r += 1) {
    for (let c = 0; c < 8; c += 1) {
      mark(r, c); mark(r, size - 1 - c); mark(size - 1 - r, c);
    }
  }
  for (let i = 8; i < size - 8; i += 1) { mark(6, i); mark(i, 6); }
  if (version >= 2) {
    for (let r = -2; r <= 2; r += 1) for (let c = -2; c <= 2; c += 1) mark(size - 7 + r, size - 7 + c);
  }
  for (let i = 0; i <= 8; i += 1) { mark(8, i); mark(i, 8); }
  for (let i = 0; i < 8; i += 1) { mark(8, size - 1 - i); mark(size - 1 - i, 8); }
  const free = [];
  for (let i = 0; i < reserved.length; i += 1) if (!reserved[i]) free.push(i);
  return free;
}

function damageData(qr, positions, flips, seed) {
  const random = rng(seed);
  const copy = { size: qr.size, modules: Uint8Array.from(qr.modules), version: qr.version };
  const chosen = new Set();
  while (chosen.size < flips) chosen.add(positions[Math.floor(random() * positions.length)]);
  for (const index of chosen) copy.modules[index] ^= 1;
  return copy;
}

// ---------------------------------------------------------------- matrix round trip
{
  const qr = encodeQr(WORST_CASE);
  const decoded = decodeMatrix(qr);
  check('a module matrix decodes straight back to its payload',
    decoded !== null && decoded.text === WORST_CASE, decoded ? `${decoded.text.length} chars` : 'null');
  check('the decoder recovers the version, mask and level the encoder chose',
    decoded !== null && decoded.version === qr.version && decoded.mask === qr.mask && decoded.ecLevel === 'M',
    decoded ? `v${decoded.version} mask ${decoded.mask} level ${decoded.ecLevel}, encoder used v${qr.version} mask ${qr.mask}` : 'null');
}

// ---------------------------------------------------------------- pixel round trip
{
  const qr = encodeQr(WORST_CASE);
  const decoded = decodeQr(render(qr));
  check('the longest possible Warp Gate link survives a pixel round trip byte for byte',
    decoded !== null && decoded.text === WORST_CASE,
    decoded ? JSON.stringify(decoded.text) : 'null');
  check('nothing threw on the way through', lastDecodeError() === null, String(lastDecodeError()));
  // "No error" is only evidence if an error CAN be reported: with the reporter deleted,
  // the line above stays green forever. A frame whose pixel reads throw proves the
  // capture path is alive, and the next decodeQr call resets it, so nothing leaks on.
  {
    const hostile = new Proxy({ length: 40 * 40 * 4 }, {
      get(target, prop) { if (prop === 'length') return target.length; throw new Error('hostile frame'); },
    });
    const got = decodeQr({ width: 40, height: 40, data: hostile });
    check('CONTROL: a frame that breaks the decoder is reported through lastDecodeError, not swallowed',
      got === null && lastDecodeError() !== null, `returned ${got}, error ${String(lastDecodeError())}`);
  }

  const payloads = [
    'WARP',
    'https://warpgate.fysh.site/app#WARP-TEST',
    '0123456789012345678901234567890123456789',
    'punctuation: $%*+-./:?&=@~[]{}<>|\\^`"\'',
    'unicode payload éüß 日本語',
  ];
  let failures = [];
  for (const payload of payloads) {
    const encoded = encodeQr(payload);
    const got = decodeQr(render(encoded, { scale: 5 }));
    if (!got || got.text !== payload || got.version !== encoded.version) {
      failures.push(`${JSON.stringify(payload).slice(0, 24)} -> ${got ? JSON.stringify(got.text).slice(0, 40) : 'null'}`);
    }
  }
  check('five varied payloads including multibyte UTF-8 round trip through pixels',
    failures.length === 0, failures.join(' | '));
}

// ---------------------------------------------------------------- every version
{
  const failures = [];
  const versions = new Set();
  for (let version = 1; version <= 6; version += 1) {
    const payload = 'A'.repeat(capacityFor(version));
    const qr = encodeQr(payload);
    const decoded = decodeQr(render(qr, { scale: 4 }));
    versions.add(qr.version);
    if (!decoded || decoded.text !== payload || decoded.version !== version) {
      failures.push(`v${version}: ${decoded ? `v${decoded.version} ${decoded.text.length} chars` : 'null'}`);
    }
  }
  check('all six supported versions decode at exactly their stated capacity',
    failures.length === 0 && versions.size === 6, failures.join(' | ') || `versions ${[...versions].sort().join(',')}`);
}

// ---------------------------------------------------------------- geometry independence
{
  const qr = encodeQr(WORST_CASE);

  const scaleFailures = [];
  for (const scale of [2, 3, 4, 5, 7, 11]) {
    const decoded = decodeQr(render(qr, { scale }));
    if (!decoded || decoded.text !== WORST_CASE) scaleFailures.push(`${scale}px/module`);
  }
  check('the same code decodes at six different module scales, 2 to 11 pixels',
    scaleFailures.length === 0, scaleFailures.join(', '));

  const quietFailures = [];
  for (const quiet of [1, 2, 4, 8]) {
    const decoded = decodeQr(render(qr, { scale: 5, quiet }));
    if (!decoded || decoded.text !== WORST_CASE) quietFailures.push(`quiet ${quiet}`);
  }
  check('the same code decodes with quiet zones of 1, 2, 4 and 8 modules',
    quietFailures.length === 0, quietFailures.join(', '));

  // A lookup table keyed on the buffer could pass everything above. It cannot pass
  // this: the code sits well off centre in a frame that is not even square.
  const frame = stamp(blankFrame(520, 380), qr, { scale: 5, quiet: 4, offsetX: 250, offsetY: 40 });
  const offset = decodeQr(frame);
  check('a code parked off centre in a 520x380 frame is still located and read',
    offset !== null && offset.text === WORST_CASE, offset ? JSON.stringify(offset.text).slice(0, 40) : 'null');

  const rotationFailures = [];
  for (const quarters of [1, 2, 3]) {
    const decoded = decodeQr(rotate(render(qr, { scale: 5 }), quarters));
    if (!decoded || decoded.text !== WORST_CASE) rotationFailures.push(`${quarters * 90} degrees`);
  }
  check('the code reads at 90, 180 and 270 degrees, so the finder ordering is real',
    rotationFailures.length === 0, rotationFailures.join(', '));
}

// ---------------------------------------------------------------- perspective
{
  // A phone is never square-on to a laptop screen. Under a real projective warp the
  // module grid is no longer evenly spaced, the bottom-right corner is not where the
  // other three finders imply, and only the alignment pattern says where the grid
  // actually goes: this is the check that the four-point transform earns its place.
  const source = render(encodeQr(WORST_CASE), { scale: 8 });
  const tilts = {
    'a mild tilt': [40, 30, 420, 60, 400, 430, 60, 400],
    'a strong tilt': [60, 20, 430, 90, 390, 440, 30, 380],
  };
  const failures = [];
  for (const [name, corners] of Object.entries(tilts)) {
    const decoded = decodeQr(tilt(source, corners, 460, 460));
    if (!decoded || decoded.text !== WORST_CASE) failures.push(`${name}: ${decoded ? 'wrong text' : 'null'}`);
  }
  check('a genuinely perspective-warped code decodes at two viewing angles',
    failures.length === 0, failures.join(' | '));

  // A tilt so extreme the grid cannot be recovered must still fail closed.
  const beyond = decodeQr(tilt(source, [200, 20, 450, 150, 300, 440, 20, 300], 460, 460));
  check('and a tilt past what the geometry can recover returns null rather than other text',
    beyond === null || beyond.text === WORST_CASE, beyond ? JSON.stringify(beyond.text).slice(0, 40) : 'null');
}

// ---------------------------------------------------------------- noise tolerance
{
  const qr = encodeQr(WORST_CASE);
  const clean = render(qr, { scale: 6 });

  // Sweep the damage upwards and record two separate things: where it still reads, and
  // whether it EVER reads as something else. The second one is the real assertion.
  const levels = [0.02, 0.05, 0.10, 0.15, 0.20, 0.30, 0.45, 0.60, 0.80];
  const report = [];
  let wrongText = 0;
  let highestFullyDecoded = 0;
  for (const fraction of levels) {
    let decoded = 0;
    for (let seed = 1; seed <= 6; seed += 1) {
      const got = decodeQr(saltAndPepper(clean, fraction, seed * 7919));
      if (!got) continue;
      if (got.text === WORST_CASE) decoded += 1;
      else wrongText += 1;
    }
    if (decoded === 6) highestFullyDecoded = fraction;
    report.push(`${Math.round(fraction * 100)}%:${decoded}/6`);
  }
  check('salt-and-pepper noise is absorbed up to at least 15 percent of pixels',
    highestFullyDecoded >= 0.15, report.join(' '));
  check('no salt-and-pepper level anywhere in the sweep produced different text',
    wrongText === 0, `${wrongText} wrong-text decodes across ${levels.length * 6} damaged frames`);
  check('the heaviest salt-and-pepper level destroys the code rather than surviving it',
    decodeQr(saltAndPepper(clean, 0.8, 4242)) === null, 'an 80 percent destroyed frame must read as nothing');

  let gaussianDecoded = 0;
  let gaussianWrong = 0;
  for (let seed = 1; seed <= 6; seed += 1) {
    const got = decodeQr(gaussianNoise(clean, 60, seed * 104729));
    if (got && got.text === WORST_CASE) gaussianDecoded += 1;
    else if (got) gaussianWrong += 1;
  }
  check('gaussian noise at sigma 60 on a 0-to-255 range still decodes every time',
    gaussianDecoded === 6 && gaussianWrong === 0, `${gaussianDecoded}/6 decoded, ${gaussianWrong} wrong`);
}

// ---------------------------------------------------------------- error correction budget
{
  // Version 6 at level M is four blocks of 27 data plus 16 EC codewords, so each block
  // survives 8 corrupt codewords: 32 across a symbol of 172. Codewords are interleaved
  // across the blocks, so 15 scattered module flips land roughly 4 per block, inside
  // the budget, and 60 land roughly 15 per block, well past it. Nothing here touches a
  // finder or a timing pattern, so the only thing being measured is the correction.
  const qr = encodeQr(WORST_CASE);
  const positions = dataModules(qr);
  check('the worst-case payload really is version 6 at level M, which is what the budget below assumes',
    qr.version === 6 && positions.length === 1383, `version ${qr.version}, ${positions.length} data modules`);

  let recovered = 0;
  for (let seed = 1; seed <= 8; seed += 1) {
    const got = decodeQr(render(damageData(qr, positions, 15, seed * 31337), { scale: 6 }));
    if (got && got.text === WORST_CASE) recovered += 1;
  }
  check('15 flipped data modules are corrected by Reed-Solomon, not merely tolerated',
    recovered === 8, `${recovered}/8 recovered`);

  let past = { nulls: 0, wrong: 0, lucky: 0 };
  for (let seed = 1; seed <= 12; seed += 1) {
    const got = decodeQr(render(damageData(qr, positions, 60, seed * 2654435761), { scale: 6 }));
    if (!got) past.nulls += 1;
    else if (got.text === WORST_CASE) past.lucky += 1;
    else past.wrong += 1;
  }
  check('damage past the correction budget returns null, never different text',
    past.wrong === 0, `${past.nulls} null, ${past.lucky} still correct, ${past.wrong} WRONG`);
  check('and that level of damage really does defeat the decoder rather than being harmless',
    past.nulls === 12, `${past.nulls} of 12 frames failed to read`);

  // Damage aimed at the finder patterns instead: not a correction problem, a location
  // problem, and the required answer is still null rather than something else.
  let finderWrong = 0;
  for (let seed = 1; seed <= 8; seed += 1) {
    const got = decodeQr(render(damage(qr, 400, seed * 99991), { scale: 6 }));
    if (got && got.text !== WORST_CASE) finderWrong += 1;
  }
  check('heavy damage across the whole symbol, finder patterns included, never yields other text',
    finderWrong === 0, `${finderWrong} wrong-text decodes out of 8`);
}

// ---------------------------------------------------------------- Reed-Solomon directly
{
  // An independent RS encoder, so this exercises rsDecode against a codeword the
  // decoder did not produce. Same field and same generator roots as ISO/IEC 18004.
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x; LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
  const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

  function encodeBlock(data, ecLength) {
    let generator = [1];
    for (let i = 0; i < ecLength; i += 1) {
      const next = new Array(generator.length + 1).fill(0);
      for (let j = 0; j < generator.length; j += 1) {
        next[j] ^= generator[j];
        next[j + 1] ^= mul(generator[j], EXP[i]);
      }
      generator = next;
    }
    const remainder = new Uint8Array(ecLength);
    for (const byte of data) {
      const factor = byte ^ remainder[0];
      remainder.copyWithin(0, 1);
      remainder[ecLength - 1] = 0;
      if (factor !== 0) for (let i = 0; i < ecLength; i += 1) remainder[i] ^= mul(generator[i + 1], factor);
    }
    return Uint8Array.from([...data, ...remainder]);
  }

  const ecLength = 16;
  const source = Uint8Array.from({ length: 27 }, (_, i) => (i * 37 + 11) & 0xff);
  const codeword = encodeBlock(source, ecLength);

  check('an undamaged block comes back unchanged',
    String(rsDecode(codeword, ecLength)) === String(source), 'clean block');

  const random = rng(7);
  let corrected = 0;
  let mistakes = 0;
  for (let trial = 0; trial < 60; trial += 1) {
    const damaged = Uint8Array.from(codeword);
    const hit = new Set();
    while (hit.size < ecLength / 2) hit.add(Math.floor(random() * damaged.length));
    for (const i of hit) damaged[i] ^= 1 + Math.floor(random() * 255);
    const result = rsDecode(damaged, ecLength);
    if (result && String(result) === String(source)) corrected += 1;
    else if (result) mistakes += 1;
  }
  check('Reed-Solomon corrects the full 8 errors its 16 check symbols allow, 60 times running',
    corrected === 60 && mistakes === 0, `${corrected}/60 corrected, ${mistakes} wrong`);

  let beyondWrong = 0;
  let beyondRefused = 0;
  for (let trial = 0; trial < 60; trial += 1) {
    const damaged = Uint8Array.from(codeword);
    const hit = new Set();
    while (hit.size < ecLength / 2 + 3) hit.add(Math.floor(random() * damaged.length));
    for (const i of hit) damaged[i] ^= 1 + Math.floor(random() * 255);
    const result = rsDecode(damaged, ecLength);
    if (!result) beyondRefused += 1;
    else if (String(result) !== String(source)) beyondWrong += 1;
  }
  check('past 8 errors it refuses rather than miscorrecting',
    beyondWrong === 0 && beyondRefused > 0, `${beyondRefused}/60 refused, ${beyondWrong} miscorrected`);
}

// ---------------------------------------------------------------- negative controls
{
  const qr = encodeQr(WORST_CASE);

  // Control 1: a blank frame. Proved able to fail by stamping a code into a frame from
  // the same builder at the same size: if decodeQr could not tell them apart, the
  // second half of this pair would be the failure.
  const blank = blankFrame(400, 400);
  const blankWithCode = stamp(blankFrame(400, 400), qr, { scale: 6, quiet: 4, offsetX: 40, offsetY: 40 });
  check('a blank white frame returns null', decodeQr(blank) === null, JSON.stringify(decodeQr(blank)));
  check('a blank black frame returns null', decodeQr(blankFrame(400, 400, 0)) === null, 'all dark');
  check('...and the blank-frame control can fail: the same frame with a code in it decodes',
    (decodeQr(blankWithCode) || {}).text === WORST_CASE, 'identical builder, identical size');

  // Control 2: pure noise. Same pairing: noise with a code composited over it must read.
  let noiseNulls = 0;
  let noiseText = [];
  for (let seed = 1; seed <= 12; seed += 1) {
    const got = decodeQr(noiseFrame(360, 300, seed * 40503));
    if (got === null) noiseNulls += 1;
    else noiseText.push(JSON.stringify(got.text).slice(0, 30));
  }
  check('twelve frames of pure uniform noise all return null',
    noiseNulls === 12, noiseText.join(' '));
  const noiseWithCode = stamp(noiseFrame(360, 300, 40503), qr, { scale: 5, quiet: 4, offsetX: 20, offsetY: 20 });
  check('...and the noise control can fail: the same noise frame with a code stamped on it decodes',
    (decodeQr(noiseWithCode) || {}).text === WORST_CASE, 'same builder, same seed, same size');

  // Control 3: a corrupted code. Proved able to fail by asserting the pristine frame
  // decodes first, so "null" here is the corruption and not a broken helper.
  const pristine = render(qr, { scale: 6 });
  check('...and the corruption control can fail: the code decodes before it is corrupted',
    (decodeQr(pristine) || {}).text === WORST_CASE, 'pre-corruption baseline');
  const shredded = decodeQr(render(damage(qr, 600, 555), { scale: 6 }));
  check('a corrupted code returns null rather than garbage',
    shredded === null, shredded ? JSON.stringify(shredded.text).slice(0, 40) : 'null');

  // Control 4: a frame with the finder patterns present but nothing valid behind them.
  // This is the frame most likely to produce confident nonsense, because location
  // succeeds and only the payload is meaningless.
  const finderOnly = blankFrame(400, 400);
  const decoy = { size: qr.size, modules: new Uint8Array(qr.size * qr.size) };
  for (const [row, col] of [[0, 0], [0, qr.size - 7], [qr.size - 7, 0]]) {
    for (let r = 0; r < 7; r += 1) {
      for (let c = 0; c < 7; c += 1) {
        const ring = r === 0 || r === 6 || c === 0 || c === 6;
        const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        decoy.modules[(row + r) * qr.size + (col + c)] = ring || core ? 1 : 0;
      }
    }
  }
  stamp(finderOnly, decoy, { scale: 6, quiet: 4, offsetX: 30, offsetY: 30 });
  const decoyResult = decodeQr(finderOnly);
  check('three finder patterns with an empty symbol behind them return null, not nonsense',
    decoyResult === null, decoyResult ? JSON.stringify(decoyResult.text).slice(0, 40) : 'null');
}

// ---------------------------------------------------------------- hostile input
{
  const hostile = [
    ['null', null],
    ['undefined', undefined],
    ['a number', 42],
    ['a string', 'not a frame'],
    ['an empty object', {}],
    ['no data', { width: 100, height: 100 }],
    ['data too short for the stated size', { data: new Uint8ClampedArray(16), width: 100, height: 100 }],
    ['fractional dimensions', { data: new Uint8ClampedArray(4000), width: 10.5, height: 10.5 }],
    ['negative dimensions', { data: new Uint8ClampedArray(4000), width: -100, height: -100 }],
    ['NaN dimensions', { data: new Uint8ClampedArray(4000), width: NaN, height: NaN }],
    ['a one pixel frame', { data: new Uint8ClampedArray(4), width: 1, height: 1 }],
    ['dimensions past the pixel ceiling', { data: new Uint8ClampedArray(4), width: 100000, height: 100000 }],
    ['a data array of the wrong type', { data: 'string', width: 100, height: 100 }],
  ];
  const threw = [];
  const notNull = [];
  for (const [label, input] of hostile) {
    let result;
    try {
      result = decodeQr(input);
    } catch (err) {
      threw.push(`${label}: ${err.message}`);
      continue;
    }
    if (result !== null) notNull.push(label);
  }
  check('thirteen malformed inputs all return null', notNull.length === 0, notNull.join(', '));
  check('and none of them throws', threw.length === 0, threw.join(' | '));

  // A frame of structured junk rather than uniform noise: stripes and blocks are what
  // actually sits behind a phone in a room, and they are far better at producing false
  // finder patterns than white noise is.
  const random = rng(2024);
  const junk = blankFrame(320, 320);
  for (let y = 0; y < 320; y += 1) {
    for (let x = 0; x < 320; x += 1) {
      const value = ((x >> 3) + (y >> 3)) % 3 === 0 || random() < 0.2 ? 0 : 255;
      const o = (y * 320 + x) * 4;
      junk.data[o] = value; junk.data[o + 1] = value; junk.data[o + 2] = value;
    }
  }
  const junkResult = decodeQr(junk);
  check('a frame of structured junk returns null rather than inventing a payload',
    junkResult === null, junkResult ? JSON.stringify(junkResult.text).slice(0, 40) : 'null');
}

// ---------------------------------------------------------------- cost per frame
{
  // Not a benchmark, a guard: this runs on every video frame, so the failure mode to
  // catch is an unbounded search, which would blow past this by orders of magnitude
  // rather than by a few milliseconds. The bound is loose on purpose since a loaded
  // build box is not a stable clock.
  const qr = encodeQr(WORST_CASE);
  const frames = [render(qr, { scale: 6 }), noiseFrame(320, 320, 11), blankFrame(320, 320)];
  for (const frame of frames) decodeQr(frame); // warm the JIT so this measures the code, not the compile

  const started = Date.now();
  for (let i = 0; i < 10; i += 1) for (const frame of frames) decodeQr(frame);
  const perFrame = (Date.now() - started) / 30;
  check('a frame costs well under a tenth of a second, code present or not',
    perFrame < 100, `${perFrame.toFixed(1)} ms per frame averaged over clean, noise and blank`);
}

process.exit(summary('qr decode') ? 0 : 1);
