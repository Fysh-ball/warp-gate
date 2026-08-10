// Image path: formats, the inline allowlist, lying MIME types, many at once,
// paste-from-clipboard and a multi-file drag-and-drop.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
// Fixed command strings only; nothing here is interpolated from input.
import { execSync } from 'node:child_process';
import { check, summary } from '../lib/harness.mjs';
import { openPair, rows, digestReceived, chainHashFile, logText } from './lib/pair.mjs';

const PORT = 3982;
const STUN = 3983;
const CDP = 9782;
const DIR = '/home/user/.cache/wg-stress/images';
const ASSETS = '/home/user/.cache/wg-stress/assets';
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });

const w = (name, buf) => { const p = path.join(DIR, name); fs.writeFileSync(p, buf); return p; };

// Real encoders, so WebP/AVIF/GIF are genuine files rather than something hand-rolled.
if (!fs.existsSync(path.join(ASSETS, 'tiny.avif'))) {
  fs.mkdirSync(ASSETS, { recursive: true });
  const sh = (cmd) => execSync(cmd, { cwd: ASSETS, stdio: 'pipe' });
  sh('magick -size 4x4 xc:red png:tiny.png');
  sh('magick -size 8x8 xc:blue webp:tiny.webp');
  sh('magick -size 8x8 xc:green png:g.png');
  sh('avifenc -q 60 g.png tiny.avif');
  sh('magick -delay 10 -size 8x8 xc:red xc:blue -loop 0 anim.gif');
}

// 1x1 PNG, the smallest real image there is.
const onePx = w('1x1.png', Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64',
));
const png = w('real.png', fs.readFileSync(path.join(ASSETS, 'tiny.png')));
const gif = w('anim.gif', fs.readFileSync(path.join(ASSETS, 'anim.gif')));
const webp = w('pic.webp', fs.readFileSync(path.join(ASSETS, 'tiny.webp')));
const avif = w('pic.avif', fs.readFileSync(path.join(ASSETS, 'tiny.avif')));
const svg = w('vector.svg', Buffer.from(
  '<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40">'
  + '<script>window.__WG_SVG_RAN = 1;</script><rect width="40" height="40" fill="red"/></svg>',
));
// A ZIP wearing a .jpg extension: the browser will label it image/jpeg from the name.
const zipBytes = Buffer.concat([
  Buffer.from('PK', 'binary'),
  crypto.randomBytes(2048),
  Buffer.from('PK'), Buffer.alloc(18),
]);
const fakeJpeg = w('archive.jpg', zipBytes);
const fakePng = w('not-really.png', Buffer.from('this is plain text pretending to be a PNG, repeatedly. '.repeat(40)));

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

const waitRow = (tab, name, ms = 60000) => tab.waitFor(
  `__wgRows().some(r => r.title.includes(${JSON.stringify(name)}) && (r.buttons.includes('Save') || /Written to|failed|refuse/i.test(r.text)))`,
  { timeout: ms, label: `${name} settled on the receiver` },
);

const rowFor = async (tab, name) => (await rows(tab)).find((r) => r.title.includes(name));

try {
  // ---------------------------------------------------------------- formats, one by one
  for (const [file, label] of [[onePx, '1x1.png'], [png, 'real.png'], [gif, 'anim.gif'],
    [webp, 'pic.webp'], [avif, 'pic.avif']]) {
    await a.setFileInput('#file-input', [file]);
    await waitRow(b, label);
    const row = await rowFor(b, label);
    const got = await digestReceived(b, row.id);
    check(`${label}: content matches the source exactly`, got === chainHashFile(file), `want ${chainHashFile(file)} got ${got}`);
    check(`${label}: rendered inline and decoded`,
      Boolean(row.img) && row.img.complete && row.img.w > 0, JSON.stringify(row.img));
  }

  // ---------------------------------------------------------------- SVG must NOT inline
  await a.setFileInput('#file-input', [svg]);
  await waitRow(b, 'vector.svg');
  const svgRow = await rowFor(b, 'vector.svg');
  check('SVG is NOT rendered inline', svgRow.img === null, JSON.stringify(svgRow.img));
  check('SVG is still offered as a save', svgRow.buttons.includes('Save'), JSON.stringify(svgRow.buttons));
  check('nothing inside the SVG executed',
    (await b.eval('return !window.__WG_SVG_RAN;')) === true);
  check('SVG content survives intact',
    (await digestReceived(b, svgRow.id)) === chainHashFile(svg));

  // ---------------------------------------------------------------- lying MIME types
  await a.setFileInput('#file-input', [fakeJpeg]);
  await waitRow(b, 'archive.jpg');
  const zipRow = await rowFor(b, 'archive.jpg');
  check('a ZIP named .jpg still arrives byte-exact',
    (await digestReceived(b, zipRow.id)) === chainHashFile(fakeJpeg));
  check('a ZIP named .jpg does not produce a decoded image',
    zipRow.img === null || zipRow.img.w === 0, JSON.stringify(zipRow.img));
  check('a ZIP named .jpg does not leave an undecodable <img> in the transcript',
    zipRow.img === null,
    `an <img> element was inserted for undecodable content: ${JSON.stringify(zipRow.img)}`);

  await a.setFileInput('#file-input', [fakePng]);
  await waitRow(b, 'not-really.png');
  const notPng = await rowFor(b, 'not-really.png');
  check('text claiming image/png arrives byte-exact',
    (await digestReceived(b, notPng.id)) === chainHashFile(fakePng));
  check('text claiming image/png does not leave an undecodable <img> in the transcript',
    notPng.img === null,
    `an <img> element was inserted for undecodable content: ${JSON.stringify(notPng.img)}`);

  // ---------------------------------------------------------------- many at once
  const many = [];
  for (let i = 0; i < 6; i += 1) {
    // Distinct bytes per file so a mix-up cannot pass.
    const bytes = fs.readFileSync(png);
    many.push(w(`batch-${i}.png`, Buffer.concat([bytes, Buffer.from(`\n<!--${i}-->`)])));
  }
  await a.setFileInput('#file-input', many);
  await b.waitFor("__wgRows().filter(r => /batch-\\d\\.png/.test(r.title) && r.buttons.includes('Save')).length === 6",
    { timeout: 90000, label: 'all six batched images received' });
  let allMatched = true;
  const detail = [];
  for (let i = 0; i < 6; i += 1) {
    const row = await rowFor(b, `batch-${i}.png`);
    const got = await digestReceived(b, row.id);
    const want = chainHashFile(many[i]);
    if (got !== want) { allMatched = false; detail.push(`batch-${i}: want ${want} got ${got}`); }
  }
  check('six images selected at once each arrive with their own content', allMatched, detail.join(' | '));

  const previewState = await b.eval(`
    const rs = __wgRows().filter(r => /batch-\\d\\.png/.test(r.title));
    return JSON.stringify({
      withImg: rs.filter(r => r.img).length,
      released: rs.filter(r => /Preview released/.test(r.text)).length,
      total: rs.length,
    });
  `);
  const ps = JSON.parse(previewState);
  check('only the newest few previews stay rendered', ps.withImg <= 3, previewState);
  check('older previews say they were released rather than vanishing',
    ps.released === ps.total - ps.withImg, previewState);

  // ---------------------------------------------------------------- paste from clipboard
  const pasteBytes = fs.readFileSync(png).toString('base64');
  await a.eval(`
    const bin = Uint8Array.from(atob(${JSON.stringify(pasteBytes)}), c => c.charCodeAt(0));
    const file = new File([bin], 'pasted.png', { type: 'image/png' });
    const dt = new DataTransfer();
    dt.items.add(file);
    const ev = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true });
    document.getElementById('chat-input').dispatchEvent(ev);
    return true;
  `);
  await waitRow(b, 'pasted.png');
  const pasted = await rowFor(b, 'pasted.png');
  check('a pasted image is sent and rendered inline', Boolean(pasted.img) && pasted.img.w > 0, JSON.stringify(pasted.img));
  check('a pasted image arrives byte-exact',
    (await digestReceived(b, pasted.id)) === chainHashFile(png));

  // ---------------------------------------------------------------- drag and drop, many
  const dropB64 = [0, 1, 2].map((i) => fs.readFileSync(many[i]).toString('base64'));
  await a.eval(`
    const b64 = ${JSON.stringify(dropB64)};
    const dt = new DataTransfer();
    b64.forEach((s, i) => {
      const bin = Uint8Array.from(atob(s), c => c.charCodeAt(0));
      dt.items.add(new File([bin], 'dropped-' + i + '.png', { type: 'image/png' }));
    });
    window.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true }));
    const veilUp = !document.getElementById('drop-veil').hidden;
    window.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
    return veilUp;
  `);
  await b.waitFor("__wgRows().filter(r => /dropped-\\d\\.png/.test(r.title) && r.buttons.includes('Save')).length === 3",
    { timeout: 90000, label: 'all three dropped images received' });
  let dropOk = true;
  const dropDetail = [];
  for (let i = 0; i < 3; i += 1) {
    const row = await rowFor(b, `dropped-${i}.png`);
    const got = await digestReceived(b, row.id);
    const want = chainHashFile(many[i]);
    if (got !== want) { dropOk = false; dropDetail.push(`dropped-${i}: want ${want} got ${got}`); }
  }
  check('a three-file drag-and-drop delivers all three, each byte-exact', dropOk, dropDetail.join(' | '));
  check('the drop veil is put away again',
    (await a.eval("return document.getElementById('drop-veil').hidden;")) === true);

  const senderLog = await logText(a);
  const receiverLog = await logText(b);
  check('no frame was rejected anywhere in the image run',
    !/frame rejected/.test(senderLog) && !/frame rejected/.test(receiverLog),
    `${senderLog.slice(-200)} || ${receiverLog.slice(-200)}`);
  check('no page error was thrown', a.pageErrors.length === 0 && b.pageErrors.length === 0,
    [...a.pageErrors, ...b.pageErrors].join(' | '));
} finally {
  await pair.close();
}

process.exit(summary('stress/images') ? 0 : 1);
