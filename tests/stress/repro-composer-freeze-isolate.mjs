// Which half of autoGrow costs the time?
//
//   autoGrow (app.js:1058):  el.style.height = 'auto';  el.style.height = el.scrollHeight + 'px'
//
// Setting height to 'auto' first is what makes the scrollHeight read expensive: it throws
// away the fixed height and asks the engine to lay the whole unbroken token out from
// scratch. This measures the same textarea three ways with the same 64 KiB value.

import { check, summary } from '../lib/harness.mjs';
import { openPair } from './lib/pair.mjs';

const pair = await openPair({ port: 3962, stunPort: 3963, cdpPort: 9763 });
const { a } = pair;

try {
  const r = JSON.parse(await a.eval(`
    const input = document.getElementById('chat-input');
    const text = 'C'.repeat(65536);
    const reset = () => { input.value = ''; input.style.height = ''; void document.body.offsetHeight; };

    // 1. value only, no read of scrollHeight at all
    reset();
    let t = performance.now();
    input.value = text;
    void document.body.offsetHeight;
    const valueOnly = Math.round(performance.now() - t);

    // 2. read scrollHeight WITHOUT resetting height to auto first
    reset();
    input.value = text;
    void document.body.offsetHeight;
    t = performance.now();
    const h1 = input.scrollHeight;
    const plainRead = Math.round(performance.now() - t);

    // 3. exactly what autoGrow does
    reset();
    input.value = text;
    void document.body.offsetHeight;
    t = performance.now();
    input.style.height = 'auto';
    const h2 = input.scrollHeight;
    input.style.height = Math.min(h2, 220) + 'px';
    const autoGrowPattern = Math.round(performance.now() - t);

    reset();
    return JSON.stringify({ valueOnly, plainRead, autoGrowPattern, h1, h2 });
  `));
  process.stdout.write(`     ${JSON.stringify(r)}\n`);

  check('setting the value alone is cheap', r.valueOnly < 200, `${r.valueOnly} ms`);
  check('the cost is in the scrollHeight read that autoGrow forces, not in the assignment',
    r.autoGrowPattern > r.valueOnly * 5,
    `value only ${r.valueOnly} ms, plain scrollHeight ${r.plainRead} ms, autoGrow pattern ${r.autoGrowPattern} ms`);
} finally {
  await pair.close();
}

process.exit(summary('stress/repro-composer-freeze-isolate') ? 0 : 1);
