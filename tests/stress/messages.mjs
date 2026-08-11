// The message path: length, volume, whitespace, control characters, bidi overrides,
// astral emoji, and content that looks like markup.

import { check, summary } from '../lib/harness.mjs';
import { openPair, sendChat, logText, msgText } from './lib/pair.mjs';

const PORT = 3988;
const STUN = 3989;
const CDP = 9788;

const pair = await openPair({ port: PORT, stunPort: STUN, cdpPort: CDP });
const { a, b } = pair;

/** The exact text of the last bubble on a tab, read out of the DOM. */
const lastText = (tab) => tab.eval(`
  const rows = [...document.querySelectorAll('#messages .msg')];
  const last = rows[rows.length - 1];
  if (!last) return null;
  const body = last.querySelector('.msg-text');
  return body ? body.textContent : null;
`);

const countRows = (tab) => tab.eval("return document.querySelectorAll('#messages .msg').length;");

/** Send from A and wait until B's bubble count grows, then return B's last text. */
async function roundTrip(text, label) {
  const before = await countRows(b);
  await sendChat(a, text);
  await b.waitFor(`document.querySelectorAll('#messages .msg').length > ${before}`,
    { timeout: 30000, label });
  return lastText(b);
}

try {
  // ---------------------------------------------------------------- markup stays text
  const markup = '<img src=x onerror="window.__WG_XSS=1"><script>window.__WG_XSS2=1</script>';
  const gotMarkup = await roundTrip(markup, 'markup message arrived');
  check('markup arrives as the exact text that was typed', gotMarkup === markup, JSON.stringify(gotMarkup));
  const injected = await b.eval(`
    return JSON.stringify({
      xss: Boolean(window.__WG_XSS || window.__WG_XSS2),
      imgs: document.querySelectorAll('#messages img:not(.msg-image)').length,
      scripts: document.querySelectorAll('#messages script').length,
    });
  `);
  check('markup never becomes markup', injected === '{"xss":false,"imgs":0,"scripts":0}', injected);

  // ---------------------------------------------------------------- astral emoji
  const astral = 'family \u{1F468}‍\u{1F469}‍\u{1F467}‍\u{1F466} flag \u{1F1EC}\u{1F1E7} math \u{1D538}\u{1D539}';
  const gotAstral = await roundTrip(astral, 'astral emoji arrived');
  check('4-byte astral characters survive exactly',
    gotAstral === astral, `${JSON.stringify(gotAstral)} vs ${JSON.stringify(astral)}`);

  // ---------------------------------------------------------------- control chars + bidi
  const control = `bell: esc: nul:\u0000 del: rtl:‮abc‬ lrm:‎`;
  const gotControl = await roundTrip(control, 'control characters arrived');
  check('control characters and bidi overrides round-trip byte for byte',
    gotControl === control, JSON.stringify(gotControl));
  check('the transcript keeps a bidi override rather than neutralising it (recorded, not asserted safe)',
    typeof gotControl === 'string', JSON.stringify(gotControl));

  // ---------------------------------------------------------------- lone surrogate
  const lone = `lone\uD800surrogate`;
  const gotLone = await roundTrip(lone, 'lone surrogate arrived');
  check('a lone surrogate is replaced rather than corrupting the frame',
    gotLone === 'lone�surrogate' || gotLone === lone,
    JSON.stringify(gotLone));

  // ---------------------------------------------------------------- pure whitespace
  const beforeWs = await countRows(b);
  const beforeWsA = await countRows(a);
  await sendChat(a, '   \t\n  ');
  await new Promise((r) => { setTimeout(r, 2500); });
  const afterWs = await countRows(b);
  const afterWsA = await countRows(a);
  check('a message of pure whitespace is not sent at all',
    afterWs === beforeWs && afterWsA === beforeWsA, `b ${beforeWs}->${afterWs}, a ${beforeWsA}->${afterWsA}`);

  // ---------------------------------------------------------------- long messages
  //
  // The composer is the product's own boundary: maxlength catches typing and pasting,
  // and the input listener (app.js MAX_MESSAGE_CHARS) catches anything that sets the
  // value directly, clamping to 16,000 characters with a trim notice. Assert the clamp
  // BEHAVIOUR, so this fails if the clamp silently stops working, then that a message
  // at the cap still arrives whole.
  const maxMsg = await a.eval('return __wg.pcs.map(p => p.sctp && p.sctp.maxMessageSize).filter(Boolean)[0] || null;');
  process.stdout.write(`     note: SCTP maxMessageSize reported as ${maxMsg}\n`);

  const clamp = JSON.parse(await a.eval(`
    const input = document.getElementById('chat-input');
    input.value = 'A'.repeat(20000);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    const trim = document.getElementById('compose-trim');
    const r = { length: input.value.length, noticeHidden: trim ? trim.hidden : null,
      notice: trim ? trim.textContent : '' };
    input.value = '';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return JSON.stringify(r);
  `));
  check('a paste over the cap is clamped to exactly 16,000 characters',
    clamp.length === 16000, `composer holds ${clamp.length} chars`);
  check('and the trim notice tells the user what happened',
    clamp.noticeHidden === false && /Trimmed to 16,000 characters/.test(clamp.notice),
    JSON.stringify({ hidden: clamp.noticeHidden, notice: clamp.notice }));

  const maxText = 'A'.repeat(16000);
  const gotMax = await roundTrip(maxText, 'a message at the cap arrived').catch((e) => `TIMEOUT:${e.message}`);
  check('a message at the 16,000 character cap arrives whole', gotMax === maxText,
    typeof gotMax === 'string' ? `${gotMax.length} chars, ${gotMax.slice(0, 40)}` : String(gotMax));

  // Over the SCTP ceiling. Whatever happens, the gate must still work afterwards.
  const huge = 'B'.repeat(400 * 1024);
  const beforeHuge = await countRows(b);
  const hugeErr = await a.eval(`
    document.getElementById('chat-input').value = ${JSON.stringify(huge)};
    document.getElementById('chat-form').requestSubmit();
    return true;
  `);
  void hugeErr;
  await new Promise((r) => { setTimeout(r, 4000); });
  const hugeArrived = (await countRows(b)) > beforeHuge;
  const composerAfterFailure = JSON.parse(await a.eval(`
    return JSON.stringify({
      inputLength: document.getElementById('chat-input').value.length,
      ownRows: document.querySelectorAll('#messages .msg').length,
    });
  `));
  check('a message that could not be sent is still recoverable by the user',
    composerAfterFailure.inputLength > 0,
    `the composer holds ${composerAfterFailure.inputLength} chars after the send failed; `
    + 'app.js:1433 clears the input before awaiting sendChat, so the typed text is gone');
  const senderLogAfterHuge = await logText(a);
  process.stdout.write(`     note: 400 KiB message arrived=${hugeArrived}; sender log tail: ${JSON.stringify(senderLogAfterHuge.slice(-220))}\n`);
  check('a message over the SCTP message ceiling is reported to the sender rather than failing silently',
    hugeArrived || /could not send/.test(senderLogAfterHuge),
    senderLogAfterHuge.slice(-300));

  // The gate must survive the oversize attempt.
  const survived = await roundTrip('still alive', 'gate survived the oversize message')
    .catch((e) => `TIMEOUT:${e.message}`);
  check('the gate still carries messages after an oversize one was attempted',
    survived === 'still alive', String(survived));

  // ---------------------------------------------------------------- thousands, rapidly
  const N = 2000;
  await a.eval(`
    const form = document.getElementById('chat-form');
    const input = document.getElementById('chat-input');
    for (let i = 0; i < ${N}; i += 1) {
      input.value = 'seq-' + i;
      form.requestSubmit();
    }
    return true;
  // 2000 synchronous submits, each one a row, an autoGrow relayout, an encrypt and a send.
  // That is the load being applied and it does not fit in the harness default of 30s, so
  // this call aborted the whole file before the assertions below could run even once. The
  // waitFor that follows already allowed 180s; only the half doing the work did not.
  `, { timeoutMs: 300000 });
  const tail = await b.waitFor(`(() => {
    const rows = [...document.querySelectorAll('#messages .msg-text')].map(x => x.textContent);
    return rows.includes('seq-${N - 1}') ? JSON.stringify(rows.filter(t => t.startsWith('seq-'))) : '';
  })()`, { timeout: 180000, label: 'the last of 2000 rapid messages arrived' }).catch((e) => `TIMEOUT:${e.message}`);

  if (String(tail).startsWith('TIMEOUT')) {
    check(`all ${N} rapid messages are delivered`, false, String(tail));
  } else {
    const seen = JSON.parse(tail);
    const nums = seen.map((t) => Number(t.slice(4)));
    const contiguous = nums.every((n, i) => i === 0 || n === nums[i - 1] + 1);
    check('rapid messages arrive strictly in order', contiguous, `${nums[0]}..${nums[nums.length - 1]}`);
    check('the last rapid message arrived', nums[nums.length - 1] === N - 1, String(nums[nums.length - 1]));
    check('the transcript is capped rather than growing without bound',
      (await countRows(b)) <= 200, String(await countRows(b)));
  }

  const bLog = await logText(b);
  check('no frame was rejected across the whole message run',
    !/frame rejected/.test(bLog) && !/frame rejected/.test(await logText(a)),
    bLog.slice(-300));
  check('no page error was thrown', a.pageErrors.length === 0 && b.pageErrors.length === 0,
    [...a.pageErrors, ...b.pageErrors].join(' | '));

  const finalText = await msgText(b);
  check('the receiving transcript is still rendering after all of that',
    finalText.includes('seq-') || finalText.length > 0, String(finalText.length));
} finally {
  await pair.close();
}

process.exit(summary('stress/messages') ? 0 : 1);
