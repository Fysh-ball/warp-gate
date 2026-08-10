// Icon generator for the installable app.
//
// There is no image library here and there is not going to be one: this repo has no
// dependencies and no build step. So the PNG bytes are written by hand. A PNG is a
// signature, an IHDR chunk, one zlib-compressed IDAT and an IEND, and node:zlib already
// ships the only hard part. Everything else is a CRC and a loop.
//
// The colours are READ from public/css/style.css rather than typed in again. An icon is
// part of the palette, and a second copy of "#0b0d10" in a second file is a copy that
// goes stale the day the palette moves.
//
// Run: node tools/make-icons.mjs

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CSS = path.join(ROOT, 'public', 'css', 'style.css');
const OUT = path.join(ROOT, 'public', 'icons');

/**
 * Pull one custom property out of the FIRST :root block in style.css.
 *
 * First, deliberately: that block is the dark palette, and the light one further down
 * is a media-query override. An icon has one set of bytes and cannot follow a media
 * query, so it takes the base values.
 */
export function readPaletteColour(css, name) {
  const root = css.slice(css.indexOf(':root'));
  const m = new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{3,8})`).exec(root);
  if (!m) throw new Error(`style.css has no --${name}; the icons cannot invent one`);
  return m[1];
}

export function hexToRgb(hex) {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ];
}

// ---------------------------------------------------------------- PNG container

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

/**
 * Encode 8-bit truecolour RGB. No alpha channel on purpose: every icon here is
 * full-bleed, and a maskable icon with transparent corners gets those corners filled
 * with whatever the launcher feels like.
 */
export function encodePng(width, height, rgb) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 2;   // colour type 2: truecolour
  ihdr[10] = 0;  // deflate
  ihdr[11] = 0;  // adaptive filtering
  ihdr[12] = 0;  // no interlace

  // One filter byte per scanline. Filter 0 (None) keeps this readable; the images are
  // flat colour over a flat background, so deflate finds the redundancy anyway.
  const stride = width * 3;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y += 1) {
    raw[y * (stride + 1)] = 0;
    rgb.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------- the mark

// Distance from a point to a line segment. A thick stroke with round caps is just
// "every point within half the stroke width of the segment", which is the cheapest way
// to draw a chevron without a path rasteriser.
function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const l2 = (dx * dx) + (dy * dy);
  let t = l2 === 0 ? 0 : (((px - ax) * dx) + ((py - ay) * dy)) / l2;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (ax + (t * dx)), py - (ay + (t * dy)));
}

/**
 * The mark: an open ring with two chevrons travelling through it.
 *
 * `scale` shrinks the glyph without shrinking the background. A maskable icon is
 * cropped to the inner 80% of its width by the launcher, so the drawing has to stay
 * inside a circle of radius 0.4 * size or the platform eats the edge of the ring.
 *
 * Supersampled rather than antialiased analytically: 4x4 per pixel is 16 boolean tests
 * and produces a clean edge at 192px, which is the size that actually has to survive.
 */
function render(size, scale, bg, fg) {
  const SS = 4;
  const c = size / 2;
  const rOuter = 0.400 * size * scale;
  const rInner = 0.325 * size * scale;
  const arm = 0.075 * size * scale;
  const stroke = 0.045 * size * scale;
  const chevrons = [-0.130, 0.060].map((dx) => dx * size * scale);

  const out = Buffer.alloc(size * size * 3);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let hits = 0;
      for (let sy = 0; sy < SS; sy += 1) {
        for (let sx = 0; sx < SS; sx += 1) {
          const px = x + ((sx + 0.5) / SS);
          const py = y + ((sy + 0.5) / SS);
          const d = Math.hypot(px - c, py - c);
          let on = d <= rOuter && d >= rInner;
          if (!on) {
            for (const dx of chevrons) {
              const apexX = c + dx + arm;
              const backX = c + dx - arm;
              if (distToSegment(px, py, backX, c - arm, apexX, c) <= stroke / 2
                || distToSegment(px, py, backX, c + arm, apexX, c) <= stroke / 2) {
                on = true;
                break;
              }
            }
          }
          if (on) hits += 1;
        }
      }
      const a = hits / (SS * SS);
      const i = ((y * size) + x) * 3;
      for (let k = 0; k < 3; k += 1) {
        out[i + k] = Math.round((bg[k] * (1 - a)) + (fg[k] * a));
      }
    }
  }
  return out;
}

/** The same mark as vector, for platforms that would rather scale than sample. */
function renderSvg(size, scale, bgHex, fgHex) {
  const c = size / 2;
  const rMid = 0.3625 * size * scale;
  const ring = 0.075 * size * scale;
  const arm = 0.075 * size * scale;
  const stroke = 0.045 * size * scale;
  const paths = [-0.130, 0.060].map((dx) => {
    const ax = c + (dx * size * scale) + arm;
    const bx = c + (dx * size * scale) - arm;
    return `<path d="M${bx.toFixed(2)} ${(c - arm).toFixed(2)} L${ax.toFixed(2)} ${c.toFixed(2)} `
      + `L${bx.toFixed(2)} ${(c + arm).toFixed(2)}"/>`;
  }).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">`
    + `<rect width="${size}" height="${size}" fill="${bgHex}"/>`
    + `<circle cx="${c}" cy="${c}" r="${rMid.toFixed(2)}" fill="none" stroke="${fgHex}" `
    + `stroke-width="${ring.toFixed(2)}"/>`
    + `<g fill="none" stroke="${fgHex}" stroke-width="${stroke.toFixed(2)}" stroke-linecap="round" `
    + `stroke-linejoin="round">${paths}</g></svg>\n`;
}

// ---------------------------------------------------------------- write them out

function main() {
  const css = fs.readFileSync(CSS, 'utf8');
  const bgHex = readPaletteColour(css, 'bg');
  const fgHex = readPaletteColour(css, 'accent');
  const bg = hexToRgb(bgHex);
  const fg = hexToRgb(fgHex);

  fs.mkdirSync(OUT, { recursive: true });

  // 1.0 for the plain icons, 0.78 for maskable: the launcher crops a maskable icon to
  // the inner 80% of its width, so the ring has to sit well inside that circle.
  const jobs = [
    ['icon-192.png', 192, 1.0],
    ['icon-512.png', 512, 1.0],
    ['icon-maskable-192.png', 192, 0.78],
    ['icon-maskable-512.png', 512, 0.78],
  ];
  for (const [name, size, scale] of jobs) {
    const png = encodePng(size, size, render(size, scale, bg, fg));
    fs.writeFileSync(path.join(OUT, name), png);
    process.stdout.write(`wrote icons/${name}  ${size}x${size}  ${png.length} bytes\n`);
  }

  const svg = renderSvg(512, 1.0, bgHex, fgHex);
  fs.writeFileSync(path.join(OUT, 'icon.svg'), svg);
  process.stdout.write(`wrote icons/icon.svg  ${svg.length} bytes\n`);
  process.stdout.write(`palette: background ${bgHex}, mark ${fgHex} (both read from css/style.css)\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
