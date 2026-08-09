// A small QR encoder: byte mode, error correction level M, versions 1 to 6.
//
// Scope is deliberately narrow. A Warp Gate link is about 60 characters, and version 6
// holds 106 bytes, so nothing larger is needed. Stopping at version 6 also means the
// version information block (only present from version 7) never has to be encoded.
//
// This is not cryptography and inventing none of it: it is ISO/IEC 18004 implemented
// directly. It is verified in tests by decoding the rendered output with zbarimg, an
// independent decoder, which cannot succeed unless the Reed-Solomon blocks, masking
// and format information are all correct.

const EC_LEVEL_M = 0b00;

// [version]: { totalCodewords, ecPerBlock, blocks }. All uniform-size blocks at level M
// for versions 1 to 6, which is why no second block group is needed.
const VERSIONS = {
  1: { total: 26, ecPerBlock: 10, blocks: 1 },
  2: { total: 44, ecPerBlock: 16, blocks: 1 },
  3: { total: 70, ecPerBlock: 26, blocks: 1 },
  4: { total: 100, ecPerBlock: 18, blocks: 2 },
  5: { total: 134, ecPerBlock: 24, blocks: 2 },
  6: { total: 172, ecPerBlock: 16, blocks: 4 },
};

const sizeFor = (version) => 17 + 4 * version;
const dataCodewords = (v) => VERSIONS[v].total - VERSIONS[v].ecPerBlock * VERSIONS[v].blocks;
/** Byte-mode payload capacity: 4 mode bits + 8 count bits of overhead. */
export const capacityFor = (version) => dataCodewords(version) - 2;

// ---------------------------------------------------------------- GF(256)

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d; // primitive polynomial for QR
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
})();

const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

function generatorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= gfMul(poly[j], 1);
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function reedSolomon(data, ecLength) {
  const gen = generatorPoly(ecLength);
  const result = new Uint8Array(ecLength);
  for (const byte of data) {
    const factor = byte ^ result[0];
    result.copyWithin(0, 1);
    result[ecLength - 1] = 0;
    if (factor !== 0) {
      for (let i = 0; i < ecLength; i += 1) result[i] ^= gfMul(gen[i + 1], factor);
    }
  }
  return result;
}

// ---------------------------------------------------------------- bit stream

function buildCodewords(bytes, version) {
  const capacity = dataCodewords(version);
  // Two codewords go to the mode indicator and the length byte. Overflowing simply
  // dropped the tail, and this encodes donation addresses: silent data loss there is a
  // scannable code that pays the wrong person. encodeQr picks the version so this cannot
  // happen today, but a truncating primitive should not be left lying around.
  if (bytes.length > capacity - 2) {
    throw new Error(
      `payload of ${bytes.length} bytes does not fit QR version ${version} (capacity ${capacity - 2} bytes)`,
    );
  }
  const bits = [];
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push((value >>> i) & 1);
  };

  push(0b0100, 4); // byte mode
  push(bytes.length, 8); // count is 8 bits for versions 1 to 9
  for (const b of bytes) push(b, 8);

  const totalBits = capacity * 8;
  for (let i = 0; i < 4 && bits.length < totalBits; i += 1) bits.push(0); // terminator
  while (bits.length % 8 !== 0) bits.push(0);

  const words = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | bits[i + j];
    words.push(byte);
  }
  const PAD = [0xec, 0x11];
  while (words.length < capacity) words.push(PAD[(words.length - Math.ceil(bits.length / 8)) % 2]);

  // Split into equal blocks, compute EC per block, then interleave both halves.
  const { blocks, ecPerBlock } = VERSIONS[version];
  const perBlock = capacity / blocks;
  const dataBlocks = [];
  const ecBlocks = [];
  for (let i = 0; i < blocks; i += 1) {
    const slice = words.slice(i * perBlock, (i + 1) * perBlock);
    dataBlocks.push(slice);
    ecBlocks.push(reedSolomon(slice, ecPerBlock));
  }

  const out = [];
  for (let i = 0; i < perBlock; i += 1) for (const block of dataBlocks) out.push(block[i]);
  for (let i = 0; i < ecPerBlock; i += 1) for (const block of ecBlocks) out.push(block[i]);
  return out;
}

// ---------------------------------------------------------------- matrix

class Matrix {
  constructor(size) {
    this.size = size;
    this.modules = new Uint8Array(size * size);
    this.reserved = new Uint8Array(size * size);
  }

  get(r, c) { return this.modules[r * this.size + c]; }
  set(r, c, value) { this.modules[r * this.size + c] = value ? 1 : 0; }
  isReserved(r, c) { return this.reserved[r * this.size + c] === 1; }
  reserve(r, c) { this.reserved[r * this.size + c] = 1; }

  place(r, c, value) {
    this.set(r, c, value);
    this.reserve(r, c);
  }
}

function drawFinder(m, row, col) {
  for (let r = -1; r <= 7; r += 1) {
    for (let c = -1; c <= 7; c += 1) {
      const rr = row + r;
      const cc = col + c;
      if (rr < 0 || rr >= m.size || cc < 0 || cc >= m.size) continue;
      const inRing = (r >= 0 && r <= 6 && (c === 0 || c === 6)) || (c >= 0 && c <= 6 && (r === 0 || r === 6));
      const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      m.place(rr, cc, inRing || inCore);
    }
  }
}

function drawAlignment(m, row, col) {
  for (let r = -2; r <= 2; r += 1) {
    for (let c = -2; c <= 2; c += 1) {
      const outer = Math.max(Math.abs(r), Math.abs(c));
      m.place(row + r, col + c, outer !== 1);
    }
  }
}

function drawFunctionPatterns(m, version) {
  const size = m.size;
  drawFinder(m, 0, 0);
  drawFinder(m, 0, size - 7);
  drawFinder(m, size - 7, 0);

  // Timing patterns.
  for (let i = 8; i < size - 8; i += 1) {
    m.place(6, i, i % 2 === 0);
    m.place(i, 6, i % 2 === 0);
  }

  // Versions 2 to 6 have exactly one alignment pattern, at the bottom right; the
  // other three combinations would collide with the finder patterns.
  if (version >= 2) drawAlignment(m, size - 7, size - 7);

  // The always-dark module.
  m.place(4 * version + 9, 8, true);

  // Reserve the format information areas so data placement skips them.
  for (let i = 0; i <= 8; i += 1) {
    if (i !== 6) { m.reserve(8, i); m.reserve(i, 8); }
  }
  for (let i = 0; i < 8; i += 1) {
    m.reserve(8, size - 1 - i);
    m.reserve(size - 1 - i, 8);
  }
}

function placeData(m, codewords) {
  const size = m.size;
  let bitIndex = 0;
  const nextBit = () => {
    const byte = codewords[bitIndex >>> 3];
    const bit = byte === undefined ? 0 : (byte >>> (7 - (bitIndex & 7))) & 1;
    bitIndex += 1;
    return bit;
  };

  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col -= 1; // the vertical timing pattern occupies column 6
    for (let i = 0; i < size; i += 1) {
      const row = upward ? size - 1 - i : i;
      for (let c = 0; c < 2; c += 1) {
        const cc = col - c;
        if (!m.isReserved(row, cc)) m.set(row, cc, nextBit());
      }
    }
    upward = !upward;
  }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function penalty(m) {
  const size = m.size;
  let score = 0;

  // Rule 1: runs of five or more identical modules.
  for (let axis = 0; axis < 2; axis += 1) {
    for (let a = 0; a < size; a += 1) {
      let run = 1;
      let prev = axis === 0 ? m.get(a, 0) : m.get(0, a);
      for (let b = 1; b < size; b += 1) {
        const value = axis === 0 ? m.get(a, b) : m.get(b, a);
        if (value === prev) {
          run += 1;
        } else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
          prev = value;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
    }
  }

  // Rule 2: 2x2 blocks of one colour.
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const v = m.get(r, c);
      if (v === m.get(r, c + 1) && v === m.get(r + 1, c) && v === m.get(r + 1, c + 1)) score += 3;
    }
  }

  // Rule 3: finder-like patterns.
  const A = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const B = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  const matches = (get, a, start, pattern) => {
    for (let i = 0; i < 11; i += 1) if (get(a, start + i) !== pattern[i]) return false;
    return true;
  };
  for (let a = 0; a < size; a += 1) {
    for (let start = 0; start + 11 <= size; start += 1) {
      const row = (x, y) => m.get(x, y);
      const col = (x, y) => m.get(y, x);
      if (matches(row, a, start, A) || matches(row, a, start, B)) score += 40;
      if (matches(col, a, start, A) || matches(col, a, start, B)) score += 40;
    }
  }

  // Rule 4: deviation from an even balance of dark and light.
  let dark = 0;
  for (let i = 0; i < m.modules.length; i += 1) dark += m.modules[i];
  const percent = (dark * 100) / m.modules.length;
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

function formatBits(mask) {
  const data = (EC_LEVEL_M << 3) | mask;
  let value = data << 10;
  for (let i = 14; i >= 10; i -= 1) {
    if ((value >>> i) & 1) value ^= 0b10100110111 << (i - 10);
  }
  return ((data << 10) | value) ^ 0b101010000010010;
}

function drawFormat(m, mask) {
  const bits = formatBits(mask);
  const size = m.size;
  const bit = (i) => (bits >>> i) & 1;

  for (let i = 0; i < 6; i += 1) m.place(8, i, bit(14 - i));
  m.place(8, 7, bit(8));
  m.place(8, 8, bit(7));
  m.place(7, 8, bit(6));
  for (let i = 0; i < 6; i += 1) m.place(5 - i, 8, bit(5 - i));

  for (let i = 0; i < 7; i += 1) m.place(size - 1 - i, 8, bit(14 - i));
  for (let i = 0; i < 8; i += 1) m.place(8, size - 8 + i, bit(7 - i));
}

/**
 * Encode text as a QR matrix.
 * Returns { size, modules } where modules is a size*size Uint8Array of 0 or 1,
 * or throws if the text is too long for version 6.
 */
export function encodeQr(text) {
  const bytes = new TextEncoder().encode(text);
  const version = Object.keys(VERSIONS)
    .map(Number)
    .sort((a, b) => a - b)
    .find((v) => bytes.length <= capacityFor(v));
  if (!version) {
    throw new Error(`${bytes.length} bytes exceeds the ${capacityFor(6)} byte capacity of version 6`);
  }

  const codewords = buildCodewords(bytes, version);

  let best = null;
  for (let mask = 0; mask < 8; mask += 1) {
    const m = new Matrix(sizeFor(version));
    drawFunctionPatterns(m, version);
    placeData(m, codewords);
    // Masking applies only to data modules, never to function patterns.
    for (let r = 0; r < m.size; r += 1) {
      for (let c = 0; c < m.size; c += 1) {
        if (!m.isReserved(r, c) && MASKS[mask](r, c)) m.set(r, c, m.get(r, c) ^ 1);
      }
    }
    drawFormat(m, mask);
    const score = penalty(m);
    if (!best || score < best.score) best = { score, matrix: m, mask };
  }

  return { size: best.matrix.size, modules: best.matrix.modules, version, mask: best.mask };
}

/** Render a matrix into a canvas element, with the quiet zone the spec requires. */
export function drawQr(canvas, qr, { quiet = 4, dark = '#000000', light = '#ffffff' } = {}) {
  const total = qr.size + quiet * 2;
  // The scale comes from the size the page authored, not from canvas.width, because this
  // function then overwrites canvas.width: rendering into the same canvas twice used to
  // shrink the code a little more each time (320 -> 287 -> 270 -> 246...). The authored
  // width is stashed on first render so a re-render measures the same basis.
  const authored = Number(canvas.dataset?.qrBaseWidth) || canvas.width;
  if (canvas.dataset) canvas.dataset.qrBaseWidth = String(authored);
  const scale = Math.floor(authored / total);
  if (!(scale >= 1)) {
    // A canvas with no width attribute used to clamp to one pixel per module and produce
    // an unscannable image that looked like a rendering rather than a mistake.
    throw new Error(
      `canvas is ${authored || 0}px wide, too small for a ${total}-module QR code (needs at least ${total}px)`,
    );
  }
  const ctx = canvas.getContext('2d');
  const pixels = total * scale;
  canvas.width = pixels;
  canvas.height = pixels;
  ctx.fillStyle = light;
  ctx.fillRect(0, 0, pixels, pixels);
  ctx.fillStyle = dark;
  for (let r = 0; r < qr.size; r += 1) {
    for (let c = 0; c < qr.size; c += 1) {
      if (qr.modules[r * qr.size + c]) {
        ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
      }
    }
  }
  return { pixels, scale };
}
