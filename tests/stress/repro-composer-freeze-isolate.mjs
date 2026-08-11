// Which half of autoGrow costs the time?
//
//   autoGrow (app.js:1058):  el.style.height = 'auto';  el.style.height = el.scrollHeight + 'px'
//
// The answer, measured, is NEITHER. The cost is laying a 64 KiB value out at all, which
// happens on assignment whether or not autoGrow ever runs. Measured here: 12497 ms to
// assign and lay out, 14200 ms with a plain scrollHeight read on top, 17533 ms for the
// whole autoGrow pattern. autoGrow adds about 40 per cent, which is a real cost and not
// the cause of a freeze: it cannot make a fast operation slow, only a slow one slower.
// Throwing the height away first does not force a second layout of the TEXT, which is why
// it is not a multiple: the engine has the content laid out and is being asked to
// re-measure the box around it, and `h1 === h2` is that fact showing through.
//
// This file used to assert the opposite, on the theory that height:auto is what makes the
// scrollHeight read expensive. It never caught that it was wrong because its checks had
// NEVER EXECUTED: every one of its runs aborted on the harness's hardcoded 30s CDP ceiling
// and the suite counted the abort as a single failing entry, so no check reported either
// way. The measurement it made once given time refutes its own premise.
//
// The old method could not have answered the question it asked. It started the clock AFTER
// `input.value = text; void document.body.offsetHeight` in two of its three cases, so the
// expensive layout sat outside the timed region for exactly the two cases that were meant
// to look expensive. Every case below times the assignment too, which is the only way the
// three numbers are comparable.

import { check, summary } from '../lib/harness.mjs';
import { openPair } from './lib/pair.mjs';

const pair = await openPair({ port: 3962, stunPort: 3963, cdpPort: 9763 });
const { a } = pair;

try {
  const r = JSON.parse(await a.eval(`
    const input = document.getElementById('chat-input');
    const text = 'C'.repeat(65536);
    const reset = () => { input.value = ''; input.style.height = ''; void document.body.offsetHeight; };

    // Warm-up. The first layout of this text also pays one-time font shaping, and charging
    // that to whichever case happens to run first is how a measurement invents a winner.
    reset();
    input.value = text;
    void input.scrollHeight;
    reset();

    // 1. assign and lay out, and never read scrollHeight at all
    let t = performance.now();
    input.value = text;
    void document.body.offsetHeight;
    const assignOnly = Math.round(performance.now() - t);
    reset();

    // 2. the same, plus a plain scrollHeight read with the height left alone
    t = performance.now();
    input.value = text;
    const h1 = input.scrollHeight;
    const assignAndRead = Math.round(performance.now() - t);
    reset();

    // 3. the same, plus exactly what autoGrow does
    t = performance.now();
    input.value = text;
    input.style.height = 'auto';
    const h2 = input.scrollHeight;
    input.style.height = Math.min(h2, 220) + 'px';
    void document.body.offsetHeight;
    const assignAndAutoGrow = Math.round(performance.now() - t);

    reset();
    return JSON.stringify({ assignOnly, assignAndRead, assignAndAutoGrow, h1, h2 });
  // Three full layouts of a 64 KiB value is the thing being measured, and on a loaded box
  // that is minutes rather than seconds. The harness default of 30s is what aborted every
  // previous run of this file.
  `, { timeoutMs: 300000 }));
  process.stdout.write(`     ${JSON.stringify(r)}\n`);

  // Without this the two checks below could both pass on a textarea that laid nothing out:
  // a hidden or empty composer measures 0 ms three times and every ratio holds trivially.
  check('the composer really laid the 64 KiB value out, so there is something to compare',
    r.h1 > 1000,
    `scrollHeight ${r.h1} px`);

  check('reading scrollHeight is not what costs: it adds little to the assignment that precedes it',
    r.assignAndRead < Math.max(r.assignOnly * 3, r.assignOnly + 250),
    `assign only ${r.assignOnly} ms, assign + read ${r.assignAndRead} ms`);

  check('nor is the height:auto reset: the full autoGrow pattern is not a multiple of the assignment',
    r.assignAndAutoGrow < Math.max(r.assignOnly * 3, r.assignOnly + 250),
    `assign only ${r.assignOnly} ms, assign + autoGrow ${r.assignAndAutoGrow} ms`);

  // The mechanical reason the reset is free, and the thing that would change first if a
  // future style rule made autoGrow expensive again.
  check('height:auto does not change what scrollHeight reports, so it forces no new layout of the text',
    r.h1 === r.h2,
    `without the reset ${r.h1} px, with it ${r.h2} px`);
} finally {
  await pair.close();
}

process.exit(summary('stress/repro-composer-freeze-isolate') ? 0 : 1);
