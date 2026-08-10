// A small QR decoder: the reading half of qr.js, scoped to what this app produces.
//
// WHAT IT DECODES
//   - Versions 1 to 6 (21x21 to 41x41 modules). That is exactly the range qr.js
//     encodes, and it is the range where no version information block exists, so the
//     symbol size can be measured from the finder patterns alone and never has to be
//     read back out of the code.
//   - All four error correction levels. qr.js only ever writes M, but the level is
//     carried in the format information whether we want it or not, and the block
//     layouts for L, Q and H are three more rows of a table we already need. Refusing
//     them would cost code rather than save it.
//   - Byte, numeric and alphanumeric segments, including several segments in one
//     symbol. Byte data is read as UTF-8, which is what qr.js writes via TextEncoder,
//     and falls back to ISO-8859-1, which is what an unlabelled byte segment means in
//     the spec.
//   - Real Reed-Solomon correction: syndromes, Berlekamp-Massey, Chien search and
//     Forney. A camera never hands over a perfect image, so a decoder that only reads
//     clean pixels would be decoration.
//
// WHAT IT DELIBERATELY DOES NOT DECODE
//   - Versions 7 to 40. Those carry a BCH-coded version block and up to 46 alignment
//     patterns, neither of which this app can ever produce.
//   - Micro QR, Kanji mode, ECI segments and structured append (a payload split over
//     several symbols). Unsupported modes return null rather than a guess.
//   - Mirrored symbols (a code seen in a mirror). A phone pointed at a laptop screen
//     never sees one.
//   - More than one code per frame: the first symbol that decodes wins.
//
// The whole module is pure computation: pixels in, text out. No DOM, no camera, no
// network, no timers, so a Node test can drive it with no browser at all.

const MAX_IMAGE_PIXELS = 40000000;
// Roughly a 1200x830 frame. Anything larger is box-downsampled to about this before
// the locate passes run, which is what keeps a 4K frame from costing seconds.
const MAX_WORKING_PIXELS = 1000000;
const MIN_VERSION = 1;
const MAX_VERSION = 6;
// Every geometry candidate costs a full sample-and-decode pass, so the search is
// capped: a frame of pure noise must cost roughly one pass, not hundreds.
const MAX_FINDER_CANDIDATES = 12;
const MAX_TRIPLES = 6;

// A decode that fails returns null rather than throwing, because it runs per video
// frame and a hostile frame must not take the page down. The message is kept here so
// a failure is still diagnosable instead of silently swallowed.
let lastError = null;
export const lastDecodeError = () => lastError;

// [version][level] = [ecPerBlock, blocksA, dataPerBlockA, blocksB, dataPerBlockB].
// Group B blocks, where present, hold one more data codeword than group A.
const EC_BLOCKS = {
  1: { L: [7, 1, 19, 0, 0], M: [10, 1, 16, 0, 0], Q: [13, 1, 13, 0, 0], H: [17, 1, 9, 0, 0] },
  2: { L: [10, 1, 34, 0, 0], M: [16, 1, 28, 0, 0], Q: [22, 1, 22, 0, 0], H: [28, 1, 16, 0, 0] },
  3: { L: [15, 1, 55, 0, 0], M: [26, 1, 44, 0, 0], Q: [18, 2, 17, 0, 0], H: [22, 2, 13, 0, 0] },
  4: { L: [20, 1, 80, 0, 0], M: [18, 2, 32, 0, 0], Q: [26, 2, 24, 0, 0], H: [16, 4, 9, 0, 0] },
  5: { L: [26, 1, 108, 0, 0], M: [24, 2, 43, 0, 0], Q: [18, 2, 15, 2, 16], H: [22, 2, 11, 2, 12] },
  6: { L: [18, 2, 68, 0, 0], M: [16, 4, 27, 0, 0], Q: [24, 4, 19, 0, 0], H: [28, 4, 15, 0, 0] },
};

// Format information codes the level as L=01, M=00, Q=11, H=10, which is not the
// order anybody would guess, so it is spelled out rather than computed.
const EC_LEVELS = ['M', 'L', 'H', 'Q'];

// Identical to the encoder's table. The decoder cannot import it (qr.js keeps it
// private) and should not: an independent copy means a mask bug shows up as a failed
// round trip instead of cancelling itself out.
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

const ALPHANUMERIC = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

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
const gfDiv = (a, b) => (a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255]);

function polyEval(poly, x) {
  let out = 0;
  for (let i = poly.length - 1; i >= 0; i -= 1) out = gfMul(out, x) ^ poly[i];
  return out;
}

// ---------------------------------------------------------------- Reed-Solomon

/**
 * Correct one block of data+EC codewords in place-free fashion.
 * Returns the corrected data codewords, or null when the damage is past the budget.
 * Everything here indexes poly[i] as the coefficient of x^i, the reverse of the wire
 * order, because that is the only convention under which Forney reads cleanly.
 */
export function rsDecode(block, ecLength) {
  const n = block.length;
  if (ecLength <= 0 || n <= ecLength || n > 255) return null;

  // Syndromes: the received word evaluated at alpha^0 .. alpha^(ecLength-1), matching
  // the generator qr.js builds from those same roots.
  const syndromes = new Uint8Array(ecLength);
  let clean = true;
  for (let i = 0; i < ecLength; i += 1) {
    let s = 0;
    for (let j = 0; j < n; j += 1) s = gfMul(s, EXP[i]) ^ block[j];
    syndromes[i] = s;
    if (s !== 0) clean = false;
  }
  const data = block.slice(0, n - ecLength);
  if (clean) return data;

  // Berlekamp-Massey.
  let lambda = [1];
  let previous = [1];
  let previousDelta = 1;
  let errors = 0;
  let shift = 1;
  for (let r = 0; r < ecLength; r += 1) {
    let delta = syndromes[r];
    for (let i = 1; i <= errors; i += 1) delta ^= gfMul(lambda[i] || 0, syndromes[r - i]);
    if (delta === 0) {
      shift += 1;
      continue;
    }
    const scale = gfDiv(delta, previousDelta);
    const adjusted = new Array(Math.max(lambda.length, previous.length + shift)).fill(0);
    for (let i = 0; i < lambda.length; i += 1) adjusted[i] = lambda[i];
    for (let i = 0; i < previous.length; i += 1) adjusted[i + shift] ^= gfMul(previous[i], scale);
    if (2 * errors <= r) {
      const wasLambda = lambda;
      lambda = adjusted;
      previous = wasLambda;
      previousDelta = delta;
      errors = r + 1 - errors;
      shift = 1;
    } else {
      lambda = adjusted;
      shift += 1;
    }
  }
  if (errors === 0 || errors > ecLength / 2 || lambda.length - 1 !== errors) return null;

  // Chien search: a root at alpha^-i means the codeword byte at index n-1-i is wrong.
  const positions = [];
  for (let i = 0; i < n; i += 1) {
    if (polyEval(lambda, EXP[(255 - (i % 255)) % 255]) === 0) positions.push(i);
  }
  // A locator whose root count does not match its degree found roots outside the
  // field positions we can act on: that is a miscorrection, not a correction.
  if (positions.length !== errors) return null;

  // Omega = S * Lambda mod x^ecLength.
  const omega = new Array(ecLength).fill(0);
  for (let i = 0; i < ecLength; i += 1) {
    for (let j = 0; j < lambda.length && i + j < ecLength; j += 1) {
      omega[i + j] ^= gfMul(syndromes[i], lambda[j]);
    }
  }
  // Formal derivative over GF(2): the even-power terms vanish.
  const derivative = [];
  for (let i = 1; i < lambda.length; i += 2) derivative[(i - 1) / 2] = lambda[i];
  for (let i = 0; i < derivative.length; i += 1) if (derivative[i] === undefined) derivative[i] = 0;

  const corrected = Uint8Array.from(block);
  for (const i of positions) {
    const index = n - 1 - i;
    if (index < 0 || index >= n) return null;
    const locator = EXP[i % 255];
    const inverse = EXP[(255 - (i % 255)) % 255];
    const denominator = polyEval(derivative, gfMul(inverse, inverse));
    if (denominator === 0) return null;
    corrected[index] ^= gfMul(locator, gfDiv(polyEval(omega, inverse), denominator));
  }

  // The check that makes silent miscorrection unlikely rather than merely rare: if the
  // corrected word is a real codeword, every syndrome is zero again.
  for (let i = 0; i < ecLength; i += 1) {
    let s = 0;
    for (let j = 0; j < n; j += 1) s = gfMul(s, EXP[i]) ^ corrected[j];
    if (s !== 0) return null;
  }
  return corrected.slice(0, n - ecLength);
}

// ---------------------------------------------------------------- binarisation

/**
 * Convert a frame to a single luma plane, box-downsampled if it is large.
 * Everything downstream is linear in the pixel count and runs up to three times, so
 * without a working ceiling a 4K frame costs seconds. Only the text comes back out,
 * never coordinates, so nothing has to be mapped to the original scale afterwards.
 */
function toLuma(imageData) {
  if (!imageData || typeof imageData !== 'object') return null;
  const { data, width, height } = imageData;
  if (!Number.isInteger(width) || !Number.isInteger(height)) return null;
  // A version 1 symbol with its quiet zone is 29 modules; below that there is nothing
  // to find, and bailing here keeps every later loop bounded by a sane frame.
  if (width < 29 || height < 29) return null;
  if (width * height > MAX_IMAGE_PIXELS) return null;
  if (!data || typeof data.length !== 'number') return null;

  const source = width * height;
  const channels = data.length >= source * 4 ? 4 : (data.length >= source ? 1 : 0);
  // Single channel input is not what a canvas hands over, but it is what a test or a
  // pre-converted frame naturally has, and refusing it would buy nothing.
  if (channels === 0) return null;

  const step = Math.max(1, Math.ceil(Math.sqrt(source / MAX_WORKING_PIXELS)));
  const outWidth = Math.floor(width / step);
  const outHeight = Math.floor(height / step);
  if (outWidth < 29 || outHeight < 29) return null;

  const luma = new Uint8Array(outWidth * outHeight);
  // The common case is a frame small enough to use as it stands, and the box filter
  // below costs several times as much as this even when its box is one pixel wide.
  if (step === 1) {
    if (channels === 1) {
      for (let i = 0; i < source; i += 1) luma[i] = data[i];
    } else {
      for (let i = 0; i < source; i += 1) {
        const o = i * 4;
        luma[i] = (data[o] * 299 + data[o + 1] * 587 + data[o + 2] * 114) / 1000;
      }
    }
    return { luma, width, height };
  }

  const cells = step * step;
  for (let y = 0; y < outHeight; y += 1) {
    for (let x = 0; x < outWidth; x += 1) {
      let total = 0;
      for (let dy = 0; dy < step; dy += 1) {
        const row = (y * step + dy) * width + x * step;
        for (let dx = 0; dx < step; dx += 1) {
          const o = (row + dx) * channels;
          total += channels === 4
            ? (data[o] * 299 + data[o + 1] * 587 + data[o + 2] * 114) / 1000
            : data[o];
        }
      }
      luma[y * outWidth + x] = total / cells;
    }
  }
  return { luma, width: outWidth, height: outHeight };
}

const BLOCK = 8;
const clamp = (v, lo, hi) => (v < lo ? lo : v > hi ? hi : v);

/** Otsu, used as a fallback and for frames too small to block up. */
function globalBinarise(luma, width, height) {
  const histogram = new Int32Array(256);
  for (let i = 0; i < luma.length; i += 1) histogram[luma[i]] += 1;
  const total = luma.length;
  let sum = 0;
  for (let i = 0; i < 256; i += 1) sum += i * histogram[i];
  let sumBackground = 0;
  let weightBackground = 0;
  let best = 0;
  let threshold = 127;
  for (let t = 0; t < 256; t += 1) {
    weightBackground += histogram[t];
    if (weightBackground === 0) continue;
    const weightForeground = total - weightBackground;
    if (weightForeground === 0) break;
    sumBackground += t * histogram[t];
    const meanBackground = sumBackground / weightBackground;
    const meanForeground = (sum - sumBackground) / weightForeground;
    const between = weightBackground * weightForeground * (meanBackground - meanForeground) ** 2;
    if (between > best) {
      best = between;
      threshold = t;
    }
  }
  const bits = new Uint8Array(width * height);
  for (let i = 0; i < bits.length; i += 1) bits[i] = luma[i] <= threshold ? 1 : 0;
  return bits;
}

/**
 * Local thresholding on an 8x8 grid, smoothed over a 5x5 neighbourhood of blocks.
 * A global threshold is fine for a rendered PNG and useless against a phone camera
 * pointed at a laptop screen, where one corner of the frame is reliably brighter
 * than the other.
 */
function hybridBinarise(luma, width, height) {
  if (width < BLOCK * 5 || height < BLOCK * 5) return globalBinarise(luma, width, height);
  const subW = (width >> 3) + ((width & 7) === 0 ? 0 : 1);
  const subH = (height >> 3) + ((height & 7) === 0 ? 0 : 1);
  const blackPoint = new Int32Array(subW * subH);

  for (let by = 0; by < subH; by += 1) {
    let yOffset = by << 3;
    if (yOffset + BLOCK > height) yOffset = height - BLOCK;
    for (let bx = 0; bx < subW; bx += 1) {
      let xOffset = bx << 3;
      if (xOffset + BLOCK > width) xOffset = width - BLOCK;
      let sum = 0;
      let min = 255;
      let max = 0;
      for (let y = 0; y < BLOCK; y += 1) {
        const row = (yOffset + y) * width + xOffset;
        for (let x = 0; x < BLOCK; x += 1) {
          const p = luma[row + x];
          sum += p;
          if (p < min) min = p;
          if (p > max) max = p;
        }
      }
      let average;
      if (max - min > 24) {
        average = sum >> 6;
      } else {
        // A flat block is either all paper or all ink. Half the minimum keeps flat
        // white white; the neighbours decide when the block is inside a dark run.
        average = min >> 1;
        if (by > 0 && bx > 0) {
          const neighbours = (blackPoint[(by - 1) * subW + bx]
            + 2 * blackPoint[by * subW + bx - 1]
            + blackPoint[(by - 1) * subW + bx - 1]) >> 2;
          if (min < neighbours) average = neighbours;
        }
      }
      blackPoint[by * subW + bx] = average;
    }
  }

  const bits = new Uint8Array(width * height);
  for (let by = 0; by < subH; by += 1) {
    let yOffset = by << 3;
    if (yOffset + BLOCK > height) yOffset = height - BLOCK;
    const centreY = clamp(by, 2, subH - 3);
    for (let bx = 0; bx < subW; bx += 1) {
      let xOffset = bx << 3;
      if (xOffset + BLOCK > width) xOffset = width - BLOCK;
      const centreX = clamp(bx, 2, subW - 3);
      let sum = 0;
      for (let dy = -2; dy <= 2; dy += 1) {
        const row = (centreY + dy) * subW;
        for (let dx = -2; dx <= 2; dx += 1) sum += blackPoint[row + centreX + dx];
      }
      const threshold = sum / 25;
      for (let y = 0; y < BLOCK; y += 1) {
        const row = (yOffset + y) * width;
        for (let x = 0; x < BLOCK; x += 1) {
          bits[row + xOffset + x] = luma[row + xOffset + x] <= threshold ? 1 : 0;
        }
      }
    }
  }
  return bits;
}

/**
 * 3x3 majority filter. Salt-and-pepper noise breaks the run-length checks that find
 * the finder patterns, which is a locate failure rather than a bit error, so error
 * correction never gets the chance to absorb it. Removing isolated pixels first is
 * what turns that into a decodable frame.
 */
function despeckle(bits, width, height) {
  const out = Uint8Array.from(bits);
  for (let y = 1; y < height - 1; y += 1) {
    for (let x = 1; x < width - 1; x += 1) {
      const i = y * width + x;
      const sum = bits[i - width - 1] + bits[i - width] + bits[i - width + 1]
        + bits[i - 1] + bits[i] + bits[i + 1]
        + bits[i + width - 1] + bits[i + width] + bits[i + width + 1];
      out[i] = sum >= 5 ? 1 : 0;
    }
  }
  return out;
}

function sameBits(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

// ---------------------------------------------------------------- finder patterns

const patternTotal = (counts) => counts[0] + counts[1] + counts[2] + counts[3] + counts[4];

/** The 1:1:3:1:1 dark-light-dark-light-dark signature of a finder pattern. */
function isFinderRatio(counts) {
  const total = patternTotal(counts);
  if (total < 7) return false;
  const module = total / 7;
  const variance = module / 2;
  return Math.abs(module - counts[0]) < variance
    && Math.abs(module - counts[1]) < variance
    && Math.abs(3 * module - counts[2]) < 3 * variance
    && Math.abs(module - counts[3]) < variance
    && Math.abs(module - counts[4]) < variance;
}

const centreFromEnd = (counts, end) => end - counts[4] - counts[3] - counts[2] / 2;

function crossCheckVertical(bits, width, height, centreX, startY, maxCount, originalTotal) {
  const counts = [0, 0, 0, 0, 0];
  const get = (x, y) => bits[y * width + x];
  let y = startY;
  while (y >= 0 && get(centreX, y)) { counts[2] += 1; y -= 1; }
  if (y < 0) return null;
  while (y >= 0 && !get(centreX, y) && counts[1] <= maxCount) { counts[1] += 1; y -= 1; }
  if (y < 0 || counts[1] > maxCount) return null;
  while (y >= 0 && get(centreX, y) && counts[0] <= maxCount) { counts[0] += 1; y -= 1; }
  if (counts[0] > maxCount) return null;

  y = startY + 1;
  while (y < height && get(centreX, y)) { counts[2] += 1; y += 1; }
  if (y === height) return null;
  while (y < height && !get(centreX, y) && counts[3] < maxCount) { counts[3] += 1; y += 1; }
  if (y === height || counts[3] >= maxCount) return null;
  while (y < height && get(centreX, y) && counts[4] < maxCount) { counts[4] += 1; y += 1; }
  if (counts[4] >= maxCount) return null;

  const total = patternTotal(counts);
  if (5 * Math.abs(total - originalTotal) >= 2 * originalTotal) return null;
  return isFinderRatio(counts) ? centreFromEnd(counts, y) : null;
}

function crossCheckHorizontal(bits, width, height, startX, centreY, maxCount, originalTotal) {
  const counts = [0, 0, 0, 0, 0];
  const get = (x, y) => bits[y * width + x];
  let x = startX;
  while (x >= 0 && get(x, centreY)) { counts[2] += 1; x -= 1; }
  if (x < 0) return null;
  while (x >= 0 && !get(x, centreY) && counts[1] <= maxCount) { counts[1] += 1; x -= 1; }
  if (x < 0 || counts[1] > maxCount) return null;
  while (x >= 0 && get(x, centreY) && counts[0] <= maxCount) { counts[0] += 1; x -= 1; }
  if (counts[0] > maxCount) return null;

  x = startX + 1;
  while (x < width && get(x, centreY)) { counts[2] += 1; x += 1; }
  if (x === width) return null;
  while (x < width && !get(x, centreY) && counts[3] < maxCount) { counts[3] += 1; x += 1; }
  if (x === width || counts[3] >= maxCount) return null;
  while (x < width && get(x, centreY) && counts[4] < maxCount) { counts[4] += 1; x += 1; }
  if (counts[4] >= maxCount) return null;

  const total = patternTotal(counts);
  if (5 * Math.abs(total - originalTotal) >= originalTotal) return null;
  return isFinderRatio(counts) ? centreFromEnd(counts, x) : null;
}

/**
 * The diagonal pass is what keeps noise out. A random frame throws up plenty of rows
 * and columns that happen to read 1:1:3:1:1; very few of them do it on the diagonal
 * as well, and every one that survives here costs a full decode attempt.
 *
 * It is run on three parallel diagonals rather than one. A diagonal is a single pixel
 * wide, and every row that confirms a given finder proposes the same centre, so one
 * speckle sitting on that one line used to reject the finder from every row at once:
 * a real pattern with hundreds of confirmations would vanish over a single pixel.
 */
function crossCheckDiagonal(bits, width, height, centreX, centreY) {
  for (const [dx, dy] of [[0, 0], [1, -1], [-1, 1]]) {
    const x = centreX + dx;
    const y = centreY + dy;
    if (x < 0 || x >= width || y < 0 || y >= height) continue;
    if (checkOneDiagonal(bits, width, height, x, y)) return true;
  }
  return false;
}

function checkOneDiagonal(bits, width, height, centreX, centreY) {
  const counts = [0, 0, 0, 0, 0];
  const get = (x, y) => bits[y * width + x];
  let i = 0;
  while (centreX >= i && centreY >= i && get(centreX - i, centreY - i)) { counts[2] += 1; i += 1; }
  if (counts[2] === 0) return false;
  while (centreX >= i && centreY >= i && !get(centreX - i, centreY - i)) { counts[1] += 1; i += 1; }
  if (counts[1] === 0) return false;
  while (centreX >= i && centreY >= i && get(centreX - i, centreY - i)) { counts[0] += 1; i += 1; }
  if (counts[0] === 0) return false;

  i = 1;
  while (centreX + i < width && centreY + i < height && get(centreX + i, centreY + i)) { counts[2] += 1; i += 1; }
  while (centreX + i < width && centreY + i < height && !get(centreX + i, centreY + i)) { counts[3] += 1; i += 1; }
  if (counts[3] === 0) return false;
  while (centreX + i < width && centreY + i < height && get(centreX + i, centreY + i)) { counts[4] += 1; i += 1; }
  if (counts[4] === 0) return false;
  return isFinderRatio(counts);
}

function addCandidate(list, x, y, moduleSize) {
  for (const found of list) {
    if (Math.abs(found.x - x) <= found.moduleSize && Math.abs(found.y - y) <= found.moduleSize) {
      const n = found.count + 1;
      found.x = (found.x * found.count + x) / n;
      found.y = (found.y * found.count + y) / n;
      found.moduleSize = (found.moduleSize * found.count + moduleSize) / n;
      found.count = n;
      return;
    }
  }
  if (list.length < 64) list.push({ x, y, moduleSize, count: 1 });
}

/** Locate finder-pattern centres, most-confirmed first. */
function findFinderPatterns(bits, width, height) {
  const candidates = [];
  const counts = [0, 0, 0, 0, 0];

  for (let y = 0; y < height; y += 1) {
    counts[0] = 0; counts[1] = 0; counts[2] = 0; counts[3] = 0; counts[4] = 0;
    let state = 0;
    for (let x = 0; x <= width; x += 1) {
      // One index past the row is treated as light, so a pattern that runs to the edge
      // still gets its closing transition.
      const dark = x < width && bits[y * width + x] === 1;
      if (dark) {
        if ((state & 1) === 1) state += 1;
        counts[state] += 1;
      } else if ((state & 1) === 0) {
        if (state === 4) {
          if (isFinderRatio(counts)) {
            const total = patternTotal(counts);
            const maxCount = counts[2];
            const rawX = centreFromEnd(counts, x);
            const centreX = Math.floor(rawX);
            if (centreX >= 0 && centreX < width) {
              const centreY = crossCheckVertical(bits, width, height, centreX, y, maxCount, total);
              if (centreY !== null) {
                const roundedY = Math.floor(centreY);
                const refinedX = crossCheckHorizontal(bits, width, height, centreX, roundedY, maxCount, total);
                if (refinedX !== null
                  && crossCheckDiagonal(bits, width, height, Math.floor(refinedX), roundedY)) {
                  addCandidate(candidates, refinedX, centreY, total / 7);
                }
              }
            }
          }
          counts[0] = counts[2];
          counts[1] = counts[3];
          counts[2] = counts[4];
          counts[3] = 1;
          counts[4] = 0;
          state = 3;
        } else {
          state += 1;
          counts[state] += 1;
        }
      } else {
        counts[state] += 1;
      }
    }
  }

  candidates.sort((a, b) => b.count - a.count);
  return candidates.slice(0, MAX_FINDER_CANDIDATES);
}

// ---------------------------------------------------------------- alignment pattern

/**
 * Locate an alignment pattern inside a window around an estimated position.
 * The signature looked for is light-dark-light with all three runs one module wide.
 * A row through the centre of the pattern reads dark-light-dark-light-dark, and the
 * only one of those triples whose middle run is the centre module is the light-dark-
 * light one: reading it as dark-light-dark instead lands a whole module off.
 */
function findAlignment(bits, width, height, estimateX, estimateY, moduleSize, allowance) {
  const left = Math.max(0, Math.floor(estimateX - allowance));
  const right = Math.min(width - 1, Math.ceil(estimateX + allowance));
  const top = Math.max(0, Math.floor(estimateY - allowance));
  const bottom = Math.min(height - 1, Math.ceil(estimateY + allowance));
  if (right - left < moduleSize * 3 || bottom - top < moduleSize * 3) return null;

  const variance = moduleSize / 2;
  const fits = (length) => Math.abs(length - moduleSize) < variance;
  let best = null;

  for (let y = top; y <= bottom; y += 1) {
    const row = y * width;
    // Rolling window of the last three runs: value, start and length.
    const value = [0, 0, 0];
    const start = [0, 0, 0];
    const length = [0, 0, 0];
    let runValue = bits[row + left];
    let runStart = left;
    for (let x = left + 1; x <= right + 1; x += 1) {
      const here = x <= right ? bits[row + x] : runValue ^ 1;
      if (here === runValue) continue;
      value[0] = value[1]; value[1] = value[2]; value[2] = runValue;
      start[0] = start[1]; start[1] = start[2]; start[2] = runStart;
      length[0] = length[1]; length[1] = length[2]; length[2] = x - runStart;
      runValue = here;
      runStart = x;
      if (value[0] !== 0 || value[1] !== 1 || value[2] !== 0) continue;
      if (!fits(length[0]) || !fits(length[1]) || !fits(length[2])) continue;
      const centreX = start[1] + length[1] / 2;
      const centreY = verifyAlignmentColumn(bits, width, height, Math.round(centreX), y, moduleSize);
      if (centreY === null) continue;
      const distance = (centreX - estimateX) ** 2 + (centreY - estimateY) ** 2;
      if (!best || distance < best.distance) best = { x: centreX, y: centreY, distance };
    }
  }
  return best;
}

function verifyAlignmentColumn(bits, width, height, centreX, startY, moduleSize) {
  if (centreX < 0 || centreX >= width) return null;
  const get = (x, y) => bits[y * width + x];
  const limit = Math.ceil(moduleSize * 2) + 2;
  const counts = [0, 0, 0];
  let y = startY;
  while (y >= 0 && get(centreX, y) && counts[1] <= limit) { counts[1] += 1; y -= 1; }
  if (y < 0 || counts[1] > limit) return null;
  while (y >= 0 && !get(centreX, y) && counts[0] <= limit) { counts[0] += 1; y -= 1; }
  if (counts[0] === 0 || counts[0] > limit) return null;

  y = startY + 1;
  while (y < height && get(centreX, y) && counts[1] <= limit) { counts[1] += 1; y += 1; }
  if (y === height || counts[1] > limit) return null;
  while (y < height && !get(centreX, y) && counts[2] <= limit) { counts[2] += 1; y += 1; }
  if (counts[2] === 0 || counts[2] > limit) return null;

  const variance = moduleSize / 2;
  if (Math.abs(counts[0] - moduleSize) >= variance) return null;
  if (Math.abs(counts[1] - moduleSize) >= variance) return null;
  if (Math.abs(counts[2] - moduleSize) >= variance) return null;
  return y - counts[2] - counts[1] / 2;
}

// ---------------------------------------------------------------- perspective

/** Maps the unit square (0,0),(1,0),(1,1),(0,1) onto four points. */
function squareToQuad(x0, y0, x1, y1, x2, y2, x3, y3) {
  const dx3 = x0 - x1 + x2 - x3;
  const dy3 = y0 - y1 + y2 - y3;
  if (dx3 === 0 && dy3 === 0) {
    return [x1 - x0, x2 - x1, x0, y1 - y0, y2 - y1, y0, 0, 0, 1];
  }
  const dx1 = x1 - x2;
  const dx2 = x3 - x2;
  const dy1 = y1 - y2;
  const dy2 = y3 - y2;
  const denominator = dx1 * dy2 - dx2 * dy1;
  if (denominator === 0) return null;
  const a13 = (dx3 * dy2 - dx2 * dy3) / denominator;
  const a23 = (dx1 * dy3 - dx3 * dy1) / denominator;
  return [
    x1 - x0 + a13 * x1, x3 - x0 + a23 * x3, x0,
    y1 - y0 + a13 * y1, y3 - y0 + a23 * y3, y0,
    a13, a23, 1,
  ];
}

const adjoint = (m) => [
  m[4] * m[8] - m[7] * m[5], m[7] * m[2] - m[1] * m[8], m[1] * m[5] - m[4] * m[2],
  m[6] * m[5] - m[3] * m[8], m[0] * m[8] - m[6] * m[2], m[3] * m[2] - m[0] * m[5],
  m[3] * m[7] - m[6] * m[4], m[6] * m[1] - m[0] * m[7], m[0] * m[4] - m[3] * m[1],
];

const multiply = (a, b) => [
  a[0] * b[0] + a[1] * b[3] + a[2] * b[6], a[0] * b[1] + a[1] * b[4] + a[2] * b[7], a[0] * b[2] + a[1] * b[5] + a[2] * b[8],
  a[3] * b[0] + a[4] * b[3] + a[5] * b[6], a[3] * b[1] + a[4] * b[4] + a[5] * b[7], a[3] * b[2] + a[4] * b[5] + a[5] * b[8],
  a[6] * b[0] + a[7] * b[3] + a[8] * b[6], a[6] * b[1] + a[7] * b[4] + a[8] * b[7], a[6] * b[2] + a[7] * b[5] + a[8] * b[8],
];

/** Transform mapping the four source points onto the four destination points. */
function quadToQuad(source, destination) {
  const toSource = squareToQuad(...source);
  const toDestination = squareToQuad(...destination);
  if (!toSource || !toDestination) return null;
  return multiply(toDestination, adjoint(toSource));
}

function project(transform, x, y) {
  const denominator = transform[6] * x + transform[7] * y + transform[8];
  if (denominator === 0 || !Number.isFinite(denominator)) return null;
  return [
    (transform[0] * x + transform[1] * y + transform[2]) / denominator,
    (transform[3] * x + transform[4] * y + transform[5]) / denominator,
  ];
}

/**
 * Sample one module per grid cell. Each cell is read as the majority of five points,
 * not one, because a single stray pixel at a module centre is otherwise a bit error
 * that has to be paid for out of the error correction budget.
 */
function sampleGrid(bits, width, height, dimension, transform, moduleSize) {
  const modules = new Uint8Array(dimension * dimension);
  // Below four pixels per module the neighbours are closer than the module is wide, so
  // a spread-out vote reads the module next door instead of this one: at that size the
  // centre pixel on its own is the honest answer.
  const spread = Math.floor(moduleSize / 4);
  const reach = spread >= 1 ? 1 : 0;
  for (let row = 0; row < dimension; row += 1) {
    for (let col = 0; col < dimension; col += 1) {
      const point = project(transform, col + 0.5, row + 0.5);
      if (!point) return null;
      let dark = 0;
      let votes = 0;
      for (let dy = -reach; dy <= reach; dy += 1) {
        for (let dx = -reach; dx <= reach; dx += 1) {
          const x = Math.round(point[0] + dx * spread);
          const y = Math.round(point[1] + dy * spread);
          // Any sample outside the frame means the geometry is wrong, and guessing at
          // the edge is exactly how a decoder invents text.
          if (x < 0 || x >= width || y < 0 || y >= height) return null;
          dark += bits[y * width + x];
          votes += 1;
        }
      }
      modules[row * dimension + col] = dark * 2 > votes ? 1 : 0;
    }
  }
  return modules;
}

// ---------------------------------------------------------------- format info

const FORMAT_MASK = 0b101010000010010;

const VALID_FORMATS = (() => {
  const all = [];
  for (let data = 0; data < 32; data += 1) {
    let value = data << 10;
    for (let i = 14; i >= 10; i -= 1) {
      if ((value >>> i) & 1) value ^= 0b10100110111 << (i - 10);
    }
    all.push({ data, bits: (((data << 10) | value) ^ FORMAT_MASK) >>> 0 });
  }
  return all;
})();

const popcount = (v) => {
  let n = v;
  let bits = 0;
  while (n) { bits += n & 1; n >>>= 1; }
  return bits;
};

/** Nearest valid format word, or null when no word is within the BCH budget of 3. */
function correctFormat(raw) {
  let best = null;
  for (const candidate of VALID_FORMATS) {
    const distance = popcount((raw ^ candidate.bits) & 0x7fff);
    if (!best || distance < best.distance) best = { distance, data: candidate.data };
  }
  if (!best || best.distance > 3) return null;
  return { ecLevel: EC_LEVELS[(best.data >> 3) & 3], mask: best.data & 7, distance: best.distance };
}

function readFormat(modules, size) {
  const at = (r, c) => modules[r * size + c];
  let first = 0;
  for (let i = 0; i < 6; i += 1) first |= at(8, i) << (14 - i);
  first |= at(8, 7) << 8;
  first |= at(8, 8) << 7;
  first |= at(7, 8) << 6;
  for (let i = 0; i < 6; i += 1) first |= at(5 - i, 8) << (5 - i);

  let second = 0;
  for (let i = 0; i < 7; i += 1) second |= at(size - 1 - i, 8) << (14 - i);
  for (let i = 0; i < 8; i += 1) second |= at(8, size - 8 + i) << (7 - i);

  // Both copies get corrected and the more confident one wins. The spec puts two
  // copies there precisely so a smudge over one corner is survivable.
  const a = correctFormat(first);
  const b = correctFormat(second);
  if (!a) return b;
  if (!b) return a;
  return a.distance <= b.distance ? a : b;
}

// ---------------------------------------------------------------- module layout

/** The modules the encoder reserves: function patterns plus the format areas. */
function functionMask(version) {
  const size = 17 + 4 * version;
  const reserved = new Uint8Array(size * size);
  const mark = (r, c) => {
    if (r >= 0 && r < size && c >= 0 && c < size) reserved[r * size + c] = 1;
  };
  for (let r = 0; r < 8; r += 1) {
    for (let c = 0; c < 8; c += 1) {
      mark(r, c);
      mark(r, size - 1 - c);
      mark(size - 1 - r, c);
    }
  }
  for (let i = 8; i < size - 8; i += 1) {
    mark(6, i);
    mark(i, 6);
  }
  if (version >= 2) {
    for (let r = -2; r <= 2; r += 1) for (let c = -2; c <= 2; c += 1) mark(size - 7 + r, size - 7 + c);
  }
  mark(4 * version + 9, 8);
  for (let i = 0; i <= 8; i += 1) {
    mark(8, i);
    mark(i, 8);
  }
  for (let i = 0; i < 8; i += 1) {
    mark(8, size - 1 - i);
    mark(size - 1 - i, 8);
  }
  return reserved;
}

/** Walk the zigzag in the same order the encoder wrote it, unmasking as we go. */
function readCodewords(modules, size, version, mask) {
  const reserved = functionMask(version);
  const isMasked = MASKS[mask];
  const bits = [];
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col -= 1; // the vertical timing pattern occupies column 6
    for (let i = 0; i < size; i += 1) {
      const row = upward ? size - 1 - i : i;
      for (let c = 0; c < 2; c += 1) {
        const cc = col - c;
        if (reserved[row * size + cc]) continue;
        const value = modules[row * size + cc] ^ (isMasked(row, cc) ? 1 : 0);
        bits.push(value);
      }
    }
    upward = !upward;
  }
  const codewords = new Uint8Array(bits.length >> 3);
  for (let i = 0; i < codewords.length; i += 1) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | bits[i * 8 + j];
    codewords[i] = byte;
  }
  return codewords;
}

function deinterleave(codewords, version, ecLevel) {
  const spec = EC_BLOCKS[version]?.[ecLevel];
  if (!spec) return null;
  const [ecPerBlock, countA, dataA, countB, dataB] = spec;
  const blocks = [];
  for (let i = 0; i < countA; i += 1) blocks.push(new Uint8Array(dataA + ecPerBlock));
  for (let i = 0; i < countB; i += 1) blocks.push(new Uint8Array(dataB + ecPerBlock));
  const lengths = blocks.map((b) => b.length - ecPerBlock);
  const total = blocks.reduce((sum, b) => sum + b.length, 0);
  if (codewords.length < total) return null;

  const longest = Math.max(...lengths);
  let position = 0;
  for (let i = 0; i < longest; i += 1) {
    for (let b = 0; b < blocks.length; b += 1) {
      if (i < lengths[b]) blocks[b][i] = codewords[position++];
    }
  }
  for (let i = 0; i < ecPerBlock; i += 1) {
    for (let b = 0; b < blocks.length; b += 1) blocks[b][lengths[b] + i] = codewords[position++];
  }
  if (position !== total) return null;
  return { blocks, ecPerBlock };
}

// ---------------------------------------------------------------- bitstream

function parseSegments(data, version) {
  let position = 0;
  const totalBits = data.length * 8;
  const read = (count) => {
    if (position + count > totalBits) return null;
    let value = 0;
    for (let i = 0; i < count; i += 1) {
      const bit = (data[(position + i) >> 3] >> (7 - ((position + i) & 7))) & 1;
      value = (value << 1) | bit;
    }
    position += count;
    return value;
  };

  const bytes = [];
  let text = '';
  const flushBytes = () => {
    if (!bytes.length) return true;
    const buffer = Uint8Array.from(bytes);
    bytes.length = 0;
    try {
      text += new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    } catch (err) {
      // Not UTF-8. The spec's default for an unlabelled byte segment is ISO-8859-1,
      // which always decodes, so this cannot fail a second time.
      void err;
      let latin = '';
      for (const b of buffer) latin += String.fromCharCode(b);
      text += latin;
    }
    return true;
  };

  // Every segment consumes bits, so the loop is bounded by the bitstream length. The
  // extra counter is belt and braces against a mode that somehow reads zero bits.
  let guard = 0;
  while (position + 4 <= totalBits && guard < 4096) {
    guard += 1;
    const mode = read(4);
    if (mode === null || mode === 0) break; // terminator
    if (mode === 0b0001) {
      const count = read(version <= 9 ? 10 : 12);
      if (count === null) return null;
      flushBytes();
      let digits = '';
      for (let i = 0; i + 3 <= count; i += 3) {
        const triple = read(10);
        if (triple === null || triple > 999) return null;
        digits += String(triple).padStart(3, '0');
      }
      const remainder = count % 3;
      if (remainder === 2) {
        const pair = read(7);
        if (pair === null || pair > 99) return null;
        digits += String(pair).padStart(2, '0');
      } else if (remainder === 1) {
        const single = read(4);
        if (single === null || single > 9) return null;
        digits += String(single);
      }
      text += digits;
    } else if (mode === 0b0010) {
      const count = read(version <= 9 ? 9 : 11);
      if (count === null) return null;
      flushBytes();
      let out = '';
      for (let i = 0; i + 2 <= count; i += 2) {
        const pair = read(11);
        if (pair === null || pair >= 45 * 45) return null;
        out += ALPHANUMERIC[Math.floor(pair / 45)] + ALPHANUMERIC[pair % 45];
      }
      if (count % 2 === 1) {
        const single = read(6);
        if (single === null || single >= 45) return null;
        out += ALPHANUMERIC[single];
      }
      text += out;
    } else if (mode === 0b0100) {
      const count = read(version <= 9 ? 8 : 16);
      if (count === null) return null;
      for (let i = 0; i < count; i += 1) {
        const byte = read(8);
        if (byte === null) return null;
        bytes.push(byte);
      }
    } else {
      // Kanji, ECI, structured append, FNC1: out of scope, and guessing at an
      // unsupported mode is how a decoder returns confident nonsense.
      return null;
    }
  }
  flushBytes();
  return text;
}

// ---------------------------------------------------------------- matrix decode

/**
 * Decode a sampled module matrix. Takes the same { size, modules } shape encodeQr
 * returns, so the matrix path can be tested without going near pixels.
 */
export function decodeMatrix(matrix) {
  if (!matrix) return null;
  const { size, modules } = matrix;
  if (!Number.isInteger(size) || !modules || modules.length !== size * size) return null;
  if ((size - 17) % 4 !== 0) return null;
  const version = (size - 17) / 4;
  if (version < MIN_VERSION || version > MAX_VERSION) return null;

  const format = readFormat(modules, size);
  if (!format) return null;

  const codewords = readCodewords(modules, size, version, format.mask);
  const split = deinterleave(codewords, version, format.ecLevel);
  if (!split) return null;

  const data = [];
  for (const block of split.blocks) {
    const corrected = rsDecode(block, split.ecPerBlock);
    if (!corrected) return null;
    for (const byte of corrected) data.push(byte);
  }

  const text = parseSegments(Uint8Array.from(data), version);
  if (text === null) return null;
  return { text, version, mask: format.mask, ecLevel: format.ecLevel };
}

// ---------------------------------------------------------------- geometry

const distance = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

/** Order three finder centres as top-left, top-right, bottom-left. */
function orderFinders(a, b, c) {
  const points = [a, b, c];
  const sides = [distance(b, c), distance(a, c), distance(a, b)];
  let corner = 0;
  for (let i = 1; i < 3; i += 1) if (sides[i] > sides[corner]) corner = i;
  const topLeft = points[corner];
  const rest = points.filter((_, i) => i !== corner);
  const [first, second] = rest;
  // Screen coordinates run downwards, so the clockwise pair has a positive cross
  // product. That is what says which of the two remaining corners is the top right.
  const cross = (first.x - topLeft.x) * (second.y - topLeft.y)
    - (first.y - topLeft.y) * (second.x - topLeft.x);
  const topRight = cross > 0 ? first : second;
  const bottomLeft = cross > 0 ? second : first;

  const legA = distance(topLeft, topRight);
  const legB = distance(topLeft, bottomLeft);
  const hypotenuse = sides[corner];
  if (legA === 0 || legB === 0) return null;
  const squareness = Math.abs(hypotenuse - Math.hypot(legA, legB)) / hypotenuse;
  const balance = Math.abs(legA - legB) / Math.max(legA, legB);
  return { topLeft, topRight, bottomLeft, legA, legB, error: squareness + balance };
}

function estimateDimension(order) {
  const moduleSize = (order.topLeft.moduleSize + order.topRight.moduleSize + order.bottomLeft.moduleSize) / 3;
  if (!(moduleSize > 0.5)) return null;
  const raw = (order.legA / moduleSize + order.legB / moduleSize) / 2 + 7;
  let dimension = Math.round(raw);
  // Valid dimensions are 4v+17, so they are all 1 modulo 4. Anything more than one
  // step away is not a rounding wobble, it is the wrong geometry.
  const offset = ((dimension % 4) + 4) % 4;
  if (offset === 0) dimension += 1;
  else if (offset === 2) dimension -= 1;
  else if (offset === 3) return null;
  if (dimension < 21 || dimension > 41) return null;
  if (Math.abs(dimension - raw) > 2) return null;
  return { dimension, moduleSize };
}

function tryGeometry(bits, width, height, order) {
  const estimate = estimateDimension(order);
  if (!estimate) return null;
  const { dimension, moduleSize } = estimate;
  const version = (dimension - 17) / 4;
  const { topLeft, topRight, bottomLeft } = order;

  // Where the fourth corner would be if the symbol were perfectly flat.
  const flatX = topRight.x - topLeft.x + bottomLeft.x;
  const flatY = topRight.y - topLeft.y + bottomLeft.y;

  const attempts = [];
  if (version >= 2) {
    const modulesBetween = dimension - 7;
    const correction = 1 - 3 / modulesBetween;
    const estimateX = topLeft.x + correction * (flatX - topLeft.x);
    const estimateY = topLeft.y + correction * (flatY - topLeft.y);
    for (const factor of [4, 8, 16]) {
      const found = findAlignment(bits, width, height, estimateX, estimateY, moduleSize, moduleSize * factor);
      if (found) {
        attempts.push({
          source: [3.5, 3.5, dimension - 3.5, 3.5, dimension - 6.5, dimension - 6.5, 3.5, dimension - 3.5],
          destination: [topLeft.x, topLeft.y, topRight.x, topRight.y, found.x, found.y, bottomLeft.x, bottomLeft.y],
        });
        break;
      }
    }
  }
  // Always keep the three-point fallback: a damaged or missing alignment pattern must
  // not cost the whole decode when error correction could have covered it.
  attempts.push({
    source: [3.5, 3.5, dimension - 3.5, 3.5, dimension - 3.5, dimension - 3.5, 3.5, dimension - 3.5],
    destination: [topLeft.x, topLeft.y, topRight.x, topRight.y, flatX, flatY, bottomLeft.x, bottomLeft.y],
  });

  for (const attempt of attempts) {
    const transform = quadToQuad(attempt.source, attempt.destination);
    if (!transform) continue;
    const modules = sampleGrid(bits, width, height, dimension, transform, moduleSize);
    if (!modules) continue;
    const decoded = decodeMatrix({ size: dimension, modules });
    if (decoded) return decoded;
  }
  return null;
}

function decodeFromBits(bits, width, height) {
  const candidates = findFinderPatterns(bits, width, height);
  if (candidates.length < 3) return null;

  const orders = [];
  for (let i = 0; i < candidates.length; i += 1) {
    for (let j = i + 1; j < candidates.length; j += 1) {
      for (let k = j + 1; k < candidates.length; k += 1) {
        const order = orderFinders(candidates[i], candidates[j], candidates[k]);
        if (!order) continue;
        const sizes = [candidates[i].moduleSize, candidates[j].moduleSize, candidates[k].moduleSize];
        const spread = (Math.max(...sizes) - Math.min(...sizes)) / Math.min(...sizes);
        // Three finders of a real symbol are the same size and sit on a right angle.
        // Anything far off either is noise and is not worth a decode pass.
        if (order.error > 0.5 || spread > 0.7) continue;
        orders.push({ order, score: order.error + spread });
      }
    }
  }
  orders.sort((a, b) => a.score - b.score);

  for (const entry of orders.slice(0, MAX_TRIPLES)) {
    const decoded = tryGeometry(bits, width, height, entry.order);
    if (decoded) return decoded;
  }
  return null;
}

// ---------------------------------------------------------------- entry point

/**
 * Find and decode a QR code in an ImageData-shaped frame.
 * Returns { text, version, mask, ecLevel } or null. Never throws.
 */
export function decodeQr(imageData) {
  lastError = null;
  try {
    const frame = toLuma(imageData);
    if (!frame) return null;
    const { luma, width, height } = frame;

    // Three attempts at most, cheapest first. Locating is the expensive half, so a
    // binarisation identical to one already tried is dropped rather than searched
    // again: that is what keeps a blank frame down to a single locate pass.
    const hybrid = hybridBinarise(luma, width, height);
    const attempted = [];
    for (const build of [
      () => hybrid,
      () => despeckle(hybrid, width, height),
      () => despeckle(globalBinarise(luma, width, height), width, height),
    ]) {
      const bits = build();
      if (attempted.some((previous) => sameBits(previous, bits))) continue;
      attempted.push(bits);
      const decoded = decodeFromBits(bits, width, height);
      if (decoded) return decoded;
    }
    return null;
  } catch (err) {
    // A camera frame is arbitrary data. Nothing above is allowed to take the page
    // down, but the reason is kept rather than discarded: see lastDecodeError.
    lastError = err instanceof Error ? err.message : String(err);
    return null;
  }
}
