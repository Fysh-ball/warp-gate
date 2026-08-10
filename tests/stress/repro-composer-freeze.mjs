// SMALLEST REPRODUCTION of the composer freeze.
//
// app.js:1414 wires every 'input' event on #chat-input to autoGrow (app.js:1058), which
// sets height to 'auto' and then reads scrollHeight. That read forces a synchronous
// layout, and laying out a single unbroken run of characters is what costs: the browser
// has to measure a token with no break opportunities.
//
// A long unbroken token is the normal case for this product: a key, a JWT, a base64
// blob, a password, a URL. This runs the same byte count twice, once as one token and
// once with newlines every 79 characters, so the variable is the SHAPE and nothing else.

import { check, summary } from '../lib/harness.mjs';
import { openPair } from './lib/pair.mjs';

const pair = await openPair({ port: 3964, stunPort: 3965, cdpPort: 9765 });
const { a } = pair;

const measure = (chars, shape) => a.eval(`
  const input = document.getElementById('chat-input');
  input.value = '';
  input.dispatchEvent(new Event('input', { bubbles: true }));
  const unit = ${JSON.stringify(shape)} === 'one-token' ? 'C' : 'C'.repeat(79) + '\\n';
  const text = unit.repeat(Math.ceil(${chars} / unit.length));
  input.value = text;
  const t0 = performance.now();
  // Exactly what a paste or a keystroke does.
  input.dispatchEvent(new Event('input', { bubbles: true }));
  const ms = performance.now() - t0;
  input.value = '';
  input.dispatchEvent(new Event('input', { bubbles: true }));
  return Math.round(ms);
`);

try {
  const onScreen = await a.eval("return !document.getElementById('screen-connected').hidden && Boolean(document.getElementById('chat-input').offsetParent);");
  check('the composer is visible, so its layout is really being computed', onScreen === true, String(onScreen));

  const rows = [];
  for (const chars of [1024, 8192, 16384, 32768, 65536]) {
    const oneToken = await measure(chars, 'one-token');
    const wrapped = await measure(chars, 'wrapped');
    rows.push({ chars, oneToken, wrapped });
    process.stdout.write(`     ${chars} chars: one unbroken token ${oneToken} ms, same size wrapped ${wrapped} ms\n`);
  }

  const worst = rows[rows.length - 1];
  check('a 64 KiB unbroken paste does not block the page for more than 200 ms',
    worst.oneToken < 200,
    `one 'input' event cost ${worst.oneToken} ms (the same 65536 bytes with newlines cost ${worst.wrapped} ms). `
    + 'app.js:1058 autoGrow reads scrollHeight after setting height:auto, forcing a synchronous layout, '
    + 'and app.js:1414 does it on every input event.');

  // This assertion originally proved the BUG (unbroken text cost many times more than
  // wrapped text at the same size). Now that the composer wraps, shape must no longer
  // matter, so it is inverted: it guards the fix instead of the defect. Left inverted
  // rather than deleted, because a regression in style.css would make the two diverge
  // again and this is what would catch it.
  check('shape no longer changes the cost: an unbroken paste is as cheap as a wrapped one',
    worst.oneToken <= Math.max(50, worst.wrapped * 5),
    `unbroken ${worst.oneToken} ms vs wrapped ${worst.wrapped} ms at the same byte count`);
} finally {
  await pair.close();
}

process.exit(summary('stress/repro-composer-freeze') ? 0 : 1);
