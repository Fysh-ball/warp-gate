// Why does a long message make the tab stop answering?
//
// Measured INSIDE a CONNECTED page, so the composer and the transcript are actually
// visible and therefore actually laid out. (A hidden element skips layout entirely, so
// measuring this on the home screen answers nothing.)
//
// Each step is the one a real paste performs: value assignment, the 'input' event that
// app.js:1414 wires to autoGrow, and autoGrow's scrollHeight read, which forces a
// synchronous layout of the whole textarea.

import { check, summary } from '../lib/harness.mjs';
import { openPair } from './lib/pair.mjs';

const pair = await openPair({ port: 3966, stunPort: 3967, cdpPort: 9767 });
const { a } = pair;

try {
  const visible = await a.eval(`
    const el = document.getElementById('chat-input');
    return JSON.stringify({
      screenVisible: !document.getElementById('screen-connected').hidden,
      offsetParent: Boolean(el.offsetParent),
    });
  `);
  check('the composer really is on screen, so these numbers are of a laid-out element',
    JSON.parse(visible).screenVisible === true && JSON.parse(visible).offsetParent === true, visible);

  const results = [];
  for (const kb of [1, 16, 64, 200, 400]) {
    for (const shape of ['one-line', 'wrapped']) {
      const src = `
        const input = document.getElementById('chat-input');
        input.value = '';
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const unit = 'SHAPE' === 'one-line' ? 'C' : 'C'.repeat(79) + '\\n';
        const text = unit.repeat(Math.ceil(KB * 1024 / unit.length));
        const t0 = performance.now();
        input.value = text;
        const t1 = performance.now();
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const t2 = performance.now();
        void document.body.offsetHeight;
        const t3 = performance.now();
        // Deliberately NOT requestAnimationFrame: a backgrounded headless tab may never
        // run one, and a wait that can hang forever cannot measure anything.
        await new Promise((r) => { setTimeout(r, 0); });
        const t4 = performance.now();
        // Steady state: what the composer costs to lay out ONCE IT HOLDS what it will
        // actually hold. The measurement above includes the browser digesting a 400 KiB
        // value that only exists because this script assigns .value directly; maxlength
        // stops a real paste from ever creating it, so that intermediate cost is not on
        // any user's path. This second layout is.
        void document.body.offsetHeight;
        const t5 = performance.now();
        void document.body.offsetHeight;
        const t6 = performance.now();
        const clamped = input.value.length;
        input.value = '';
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return JSON.stringify({
          kb: KB, shape: 'SHAPE', chars: text.length, clamped,
          setValue: Math.round(t1 - t0),
          inputEventAutoGrow: Math.round(t2 - t1),
          forcedLayout: Math.round(t3 - t2),
          twoFrames: Math.round(t4 - t3),
          steadyLayout: Math.round(t6 - t5),
        });
      `.replace(/KB/g, String(kb)).replace(/SHAPE/g, shape);
      const started = Date.now();
      let r;
      try {
        r = JSON.parse(await a.eval(src));
      } catch (err) {
        r = { kb, shape, evalFailed: err.message };
      }
      // Node-side wall time catches anything that happens AFTER the expression returns
      // but before the renderer can answer, which is where paint lives.
      r.wallMs = Date.now() - started;
      results.push(r);
      process.stdout.write(`     ${JSON.stringify(r)}\n`);
    }
  }

  const worstOneLine = results.filter((r) => r.shape === 'one-line').at(-1);
  const worstWrapped = results.filter((r) => r.shape === 'wrapped').at(-1);
  const cost = (r) => r.wallMs;
  // Steady state is the assertion that matters, for both shapes. The one-off cost above
  // includes the browser swallowing a 400 KiB value that ONLY a script can create:
  // maxlength clamps a real paste in the UA before the value is ever that long. Testing
  // the unreachable path harder would not make any user's tab faster.
  check('once clamped, a huge single-line paste leaves the composer cheap to lay out',
    worstOneLine.steadyLayout < 500,
    `steady layout ${worstOneLine.steadyLayout} ms: ${JSON.stringify(worstOneLine)}`);
  check('once clamped, a huge wrapped paste leaves the composer cheap to lay out',
    worstWrapped.steadyLayout < 500,
    `steady layout ${worstWrapped.steadyLayout} ms: ${JSON.stringify(worstWrapped)}`);
  check('a wrapped 400 KiB paste never stalls the page at all',
    cost(worstWrapped) < 2000,
    `${cost(worstWrapped)} ms total: ${JSON.stringify(worstWrapped)}`);

  // The composer now refuses to hold more than one data channel message can carry.
  // That is the real fix for the stall: 400 KiB was never sendable, so laying it out
  // only bought a frozen tab followed by a failure. Both shapes must clamp, because
  // maxlength does not apply to a value assigned by script.
  const MAX = 16000;
  for (const r of [worstOneLine, worstWrapped]) {
    check(`a ${r.kb} KiB ${r.shape} paste is clamped to the message limit, not laid out whole`,
      r.clamped === MAX,
      `held ${r.clamped} characters after the input event, expected ${MAX} (source was ${r.chars})`);
  }

  // A message that fits must be left completely alone: a limit that also truncates
  // ordinary messages would be a worse bug than the one it fixes.
  const small = results.find((r) => r.kb === 1 && r.shape === 'one-line');
  check('a 1 KiB message is not clamped at all',
    small.clamped === small.chars, JSON.stringify(small));
} finally {
  await pair.close();
}

process.exit(summary('stress/composer-cost') ? 0 : 1);
