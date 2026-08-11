// The suggestion box: the store, and the route in front of it.
//
// Two properties matter more than anything else here and both get controls:
//
//   1. It is OFF unless an operator turned it on. A store that quietly starts collecting
//      because a default pointed somewhere writable is the opposite of what this site
//      promises, so the off case is tested first and tested harder than the on case.
//   2. It records the text and the hour, and nothing else. There is no assertion that can
//      prove a negative about every future field, so the test asserts the exact key set
//      instead: adding a field breaks it, which is the point.
//
// Run: node tests/suggest.test.mjs

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { check, summary, startServer, request, delay, freePort } from './lib/harness.mjs';

const PORT = await freePort(3782);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-suggest-'));
const STORE = path.join(tmp, 'suggestions.jsonl');

// The operator's reader, run the way an operator runs it: a separate process, over the
// wire of argv and stderr, not by importing its internals. Its exit code is part of what
// is under test, and an import cannot observe one.
const READER = new URL('../deploy/read-suggestions.mjs', import.meta.url).pathname;

function runReader(file, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [READER, file], {
      env: { ...process.env, WG_SUGGESTIONS_PATH: file, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { err += c; });
    child.on('error', (e) => resolve({ code: -1, out, err: `${err}spawn failed: ${e.message}` }));
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

// ---------------------------------------------------------------- off by default
{
  const srv = await startServer({ WG_HTTP_PORT: String(PORT), WG_STUN_ENABLED: '0' });

  const res = await request(PORT, 'POST', '/api/suggest', { text: 'hello' });
  check('with no path configured the route does not exist',
    res.status === 404, `http ${res.status}`);

  const cfg = await request(PORT, 'GET', '/api/config');
  check('and the page is told the box is off',
    cfg.json.suggestions === false, JSON.stringify(cfg.json.suggestions));

  // The whole off case rests on the server having actually started, so prove it answers
  // something else. Otherwise a server that failed to boot passes both checks above.
  check('CONTROL: the server is up, so the 404 means "no such route"',
    cfg.status === 200 && Array.isArray(cfg.json.sessionMinutes), `http ${cfg.status}`);

  await srv.stop();
}

// ---------------------------------------------------------------- on, end to end
{
  const srv = await startServer({
    WG_HTTP_PORT: String(PORT),
    WG_STUN_ENABLED: '0',
    WG_SUGGESTIONS_PATH: STORE,
    WG_SUGGESTIONS_MAX_CHARS: '40',
    WG_SUGGESTIONS_PER_WINDOW: '5',
    WG_SUGGESTIONS_MAX_BYTES: '400',
  });

  const cfg = await request(PORT, 'GET', '/api/config');
  check('with a path configured the page is told the box is on',
    cfg.json.suggestions === true, JSON.stringify(cfg.json.suggestions));

  const ok = await request(PORT, 'POST', '/api/suggest', { text: 'a dark theme please' });
  check('a suggestion is accepted', ok.status === 204, `http ${ok.status}`);
  check('and the answer carries no body to probe with',
    (ok.text ?? '') === '', JSON.stringify(ok.text));

  const lines = fs.readFileSync(STORE, 'utf8').trim().split('\n');
  check('it reached the store', lines.length === 1, `${lines.length} line(s)`);

  const row = JSON.parse(lines[0]);
  check('the text is stored as sent', row.text === 'a dark theme please', row.text);

  // The exact key set. This is the privacy assertion: it fails the moment anything else
  // is recorded alongside, whatever that something is.
  check('and NOTHING else is recorded beside it',
    JSON.stringify(Object.keys(row).sort()) === JSON.stringify(['at', 'text']),
    Object.keys(row).join(','));

  check('the timestamp is rounded to the hour',
    /T\d\d:00:00\.000Z$/.test(row.at), row.at);

  // Empty and whitespace-only are refused rather than stored as blank rows.
  const blank = await request(PORT, 'POST', '/api/suggest', { text: '   \n  ' });
  check('a blank suggestion is refused', blank.status === 400, `http ${blank.status}`);

  const long = await request(PORT, 'POST', '/api/suggest', { text: 'x'.repeat(41) });
  check('one over the character cap is refused', long.status === 400, `http ${long.status}`);
  const atCap = await request(PORT, 'POST', '/api/suggest', { text: 'y'.repeat(40) });
  check('CONTROL: exactly at the cap is accepted, so the cap is a cap and not an off-by-one',
    atCap.status === 204, `http ${atCap.status}`);

  // Control characters never reach the file: the operator reads this with `cat`.
  const nasty = await request(PORT, 'POST', '/api/suggest', {
    text: 'bell \u0007 and escape \u001B[2J clear',
  });
  check('a suggestion containing terminal escapes is accepted', nasty.status === 204,
    `http ${nasty.status}`);
  const stored = fs.readFileSync(STORE, 'utf8');
  check('but the escapes are not in the file',
    !new RegExp('[\\u0000-\\u0008\\u000B-\\u001F\\u007F-\\u009F]').test(stored),
    'raw control byte found in the store');
  check('CONTROL: the surrounding words did survive, so it stripped rather than dropped',
    /bell {2}and escape \[2J clear/.test(stored), stored.slice(-120));

  // Rate limit. Five per window was configured and four have been accepted, so the sixth
  // acceptance must be refused.
  const more = [];
  for (let i = 0; i < 4; i += 1) {
    more.push((await request(PORT, 'POST', '/api/suggest', { text: `idea ${i}` })).status);
  }
  check('the box is rate limited', more.includes(429), more.join(','));

  await srv.stop();
}

// ---------------------------------------------------------------- the store fills up
{
  const full = path.join(tmp, 'full.jsonl');
  // Written just under the cap, so the next append cannot fit.
  fs.writeFileSync(full, `${'#'.repeat(300)}\n`);
  const srv = await startServer({
    WG_HTTP_PORT: String(PORT),
    WG_STUN_ENABLED: '0',
    WG_SUGGESTIONS_PATH: full,
    WG_SUGGESTIONS_MAX_BYTES: '320',
  });

  const before = fs.statSync(full).size;
  const res = await request(PORT, 'POST', '/api/suggest', { text: 'this will not fit' });
  check('a full store refuses rather than rotating',
    fs.statSync(full).size === before, `${before} -> ${fs.statSync(full).size}`);

  // The fill level must NOT be readable from outside. A 507 against a 204 was a gauge
  // anyone could poll to watch the box approach its cap, which is the same class of usage
  // side channel the live room count was taken off /api/health for (THREAT-MODEL.md).
  check('and a full store answers exactly what an accepted one answers',
    res.status === 204, `http ${res.status}`);

  // ...which is only acceptable because the OPERATOR still finds out. The signal moved to
  // stderr, where a stranger cannot read it and the person running the box can.
  await delay(120);
  const log = srv.stderr();
  check('the operator is told on stderr that the store is full',
    /\[suggest\] store full at \d+ of \d+ bytes/.test(log), JSON.stringify(log.slice(-300)));
  check('and the message says submissions are being discarded, not merely that it is full',
    /DISCARDED/.test(log), JSON.stringify(log.slice(-300)));

  // Rate limited, or a script hitting a full store turns this into the request log this
  // server deliberately does not keep.
  for (let i = 0; i < 5; i += 1) {
    await request(PORT, 'POST', '/api/suggest', { text: `also will not fit ${i}` });
  }
  await delay(120);
  const occurrences = (srv.stderr().match(/store full at/g) ?? []).length;
  check('the full-store warning is rate limited, not one line per request',
    occurrences === 1, `${occurrences} occurrence(s) after 6 refused submissions`);

  await srv.stop();
}

// -------------------------------------------------- the two caps measure the same thing
{
  // The character cap counts CODE POINTS and the file cap counts BYTES. With only the
  // first, 600 emoji was 2,444 bytes on one line against a 644-byte ASCII line, so the
  // store filled after 429 submissions rather than the ~1,700 the file cap was reasoned
  // about with. Measured, before the byte cap existed.
  const bytes = path.join(tmp, 'bytes.jsonl');
  const srv = await startServer({
    WG_HTTP_PORT: String(PORT),
    WG_STUN_ENABLED: '0',
    WG_SUGGESTIONS_PATH: bytes,
    WG_SUGGESTIONS_MAX_CHARS: '600',
    WG_SUGGESTIONS_MAX_TEXT_BYTES: '400',
    WG_SUGGESTIONS_PER_WINDOW: '50',
  });

  // 200 astral code points: inside the character cap, 800 bytes, past the byte cap. The
  // figures are deliberately kept under maxSmallBodyBytes, or the 413 on the body would
  // answer first and this would assert the wrong refusal.
  const emoji = '\u{1F600}'.repeat(200);
  check('CONTROL: the payload really is inside the character cap and outside the byte cap',
    [...emoji].length === 200 && Buffer.byteLength(emoji) === 800,
    `${[...emoji].length} code points, ${Buffer.byteLength(emoji)} bytes`);
  const fat = await request(PORT, 'POST', '/api/suggest', { text: emoji });
  check('a submission inside the character cap but past the byte cap is refused',
    fat.status === 400 && fat.json?.error === 'too_long', `http ${fat.status} ${fat.text}`);

  // The positive arm, and it is what stops the byte cap being a blanket refusal: the
  // ordinary case the character cap was chosen for still fits.
  const ascii = await request(PORT, 'POST', '/api/suggest', { text: 'x'.repeat(400) });
  check('CONTROL: 400 characters of ASCII still fit, so the byte cap did not replace the other one',
    ascii.status === 204, `http ${ascii.status}`);

  // And an emoji suggestion a person would actually write is unaffected.
  const human = await request(PORT, 'POST', '/api/suggest', { text: `dark theme please \u{1F311}` });
  check('CONTROL: an ordinary suggestion with an emoji in it is still accepted',
    human.status === 204, `http ${human.status}`);

  const stored = fs.readFileSync(bytes, 'utf8').trim().split('\n');
  check('only the two accepted submissions reached the store',
    stored.length === 2, `${stored.length} line(s)`);

  await srv.stop();
}

// ---------------------------------------------------------------- reading it back
{
  const mixed = path.join(tmp, 'mixed.jsonl');
  fs.writeFileSync(mixed, [
    JSON.stringify({ at: '2026-08-10T09:00:00.000Z', text: 'one' }),
    'this line is not json',
    JSON.stringify({ at: '2026-08-10T10:00:00.000Z', text: 'two' }),
    '',
  ].join('\n'));

  const { read } = await import('../server/suggestions.js');
  const out = read(mixed);
  check('every readable entry comes back', out.entries.length === 2,
    out.entries.map((e) => e.text).join(','));
  check('and a corrupt line is REPORTED, not silently skipped',
    out.malformed === 1, String(out.malformed));
  check('CONTROL: a clean file reports zero malformed, so the counter is not always 1',
    read(STORE).malformed === 0, String(read(STORE).malformed));

  const missing = read(path.join(tmp, 'no-such-file.jsonl'));
  check('a store that does not exist yet reads as empty, not as an error',
    missing.entries.length === 0 && missing.malformed === 0, JSON.stringify(missing));
}

// ------------------------------------------------- the reader sanitises what the writer does
// The reader had its own regex, stripping C0 and C1 only, so RLO, ZWSP, LRI and BOM went
// straight through the one script whose stated job is re-checking a hand-edited file. And
// `at` was printed through no filter at all: a line edited by hand could put a raw ANSI CSI
// in the timestamp and repaint the operator's terminal.
//
// Every hostile character below is built with String.fromCharCode. A literal control byte
// written into a source file makes grep treat the file as binary and silently return
// nothing, which is a worse outcome than the bug.
{
  const ch = (n) => String.fromCharCode(n);
  const ESC = ch(0x1B);
  const HOSTILE = {
    'RLO (bidi override)': ch(0x202E),
    'ZWSP (zero width space)': ch(0x200B),
    'BOM': ch(0xFEFF),
    'LRI (isolate)': ch(0x2066),
    'ESC (terminal escape)': ESC,
    'BEL': ch(0x07),
  };

  const nasty = path.join(tmp, 'nasty.jsonl');
  fs.writeFileSync(nasty, `${JSON.stringify({
    // A CSI erase-display and a bell, in the field that was printed unfiltered.
    at: `2026-08-10T09:00:00.000Z${ESC}[2J${ch(0x07)}`,
    text: `keep${ch(0x202E)}this${ch(0x200B)}visible${ch(0xFEFF)}${ch(0x2066)}${ESC}[31m`,
  })}\n`);

  const survives = (haystack) => Object.entries(HOSTILE)
    .filter(([, c]) => haystack.includes(c))
    .map(([name]) => name);

  // THE NEGATIVE CONTROL, run before the check it validates. The detector is pointed at the
  // known-bad state, which is the PARSED row rather than the file: JSON.stringify escapes
  // ESC and BEL on the way to disk, so the bytes on disk are harmless and it is the parse
  // that makes them real again. Printing these two fields straight out is exactly what the
  // pre-fix reader did. If the detector cannot find these characters here it cannot find
  // them anywhere, and its silence on the reader's output below would mean nothing at all.
  const parsed = JSON.parse(fs.readFileSync(nasty, 'utf8').trim());
  const unfiltered = survives(`${parsed.at}${parsed.text}`);
  check('CONTROL: the detector finds every hostile character in the unfiltered row',
    unfiltered.length === Object.keys(HOSTILE).length,
    `only found ${unfiltered.length} of ${Object.keys(HOSTILE).length}: ${unfiltered.join(', ')}`);

  const shown = await runReader(nasty);
  check('CONTROL: the reader ran and printed the entry', shown.code === 0 && shown.out.includes('1 suggestion(s)'),
    `exit ${shown.code}, stderr ${JSON.stringify(shown.err)}`);

  const leaked = survives(shown.out);
  check('nothing hostile survives the reader, in either field',
    leaked.length === 0, `leaked: ${leaked.join(', ')}`);
  check('and the readable part of both fields is still there, so this is filtering and not blanking',
    shown.out.includes('keepthisvisible') && shown.out.includes('2026-08-10T09:00:00.000Z[2J'),
    JSON.stringify(shown.out));
}

// ------------------------------------------------------- the reader will not eat the box
// read() took an operator-supplied path from argv and pulled the whole thing into one
// string. A store far past the writer's own cap is either not this server's file or the
// result of something appending without the cap, and either way it should be refused by
// name rather than met with an out-of-memory kill.
{
  const huge = path.join(tmp, 'huge.jsonl');
  const line = `${JSON.stringify({ at: '2026-08-10T09:00:00.000Z', text: 'x'.repeat(500) })}\n`;
  fs.writeFileSync(huge, line.repeat(60)); // about 34 KB
  const size = fs.statSync(huge).size;
  check('CONTROL: the oversized file really is past 4x the cap used below',
    size > 2048 * 4, `${size} bytes against a cap of ${2048 * 4}`);

  const refused = await runReader(huge, { WG_SUGGESTIONS_MAX_BYTES: '2048' });
  check('a store far past the writer\'s cap is refused rather than read into memory',
    refused.code === 2 && /Refusing to read it into memory/.test(refused.err),
    `exit ${refused.code}, stderr ${JSON.stringify(refused.err)}`);
  check('and the refusal names the size and the knob, so it can be acted on',
    refused.err.includes(String(size)) && refused.err.includes('WG_SUGGESTIONS_MAX_BYTES'),
    JSON.stringify(refused.err));

  // THE CONTROL. The same file, the same reader, one env value different. Without this the
  // refusal above could be the reader failing for any reason at all.
  const allowed = await runReader(huge, { WG_SUGGESTIONS_MAX_BYTES: '1048576' });
  check('CONTROL: the same file under a cap it fits inside reads normally',
    allowed.code === 0 && allowed.out.includes('60 suggestion(s)'),
    `exit ${allowed.code}, stderr ${JSON.stringify(allowed.err)}`);
}

// ------------------------------------------------ the request path does not block the loop
// statSync and appendFileSync ran on every submission, on the same event loop that is
// holding every live SSE stream in the process. A stat on a cold or contended filesystem
// stalls all of them, and the stat ran even when the store was full.
{
  const mod = await import('../server/suggestions.js');
  const returned = mod.append('a suggestion from the async check');
  check('append() hands back a promise rather than doing the work inline',
    returned instanceof Promise, typeof returned);
  const settled = await returned;
  check('CONTROL: and it still resolves to the same result shape',
    typeof settled === 'object' && typeof settled.ok === 'boolean', JSON.stringify(settled));

  // THE NEGATIVE CONTROL for the predicate itself: the pre-fix shape, which returned the
  // result object directly. If `instanceof Promise` cannot refuse this, it is not evidence.
  const preFixShaped = () => ({ ok: true });
  check('CONTROL: the same predicate refuses a synchronous append',
    !(preFixShaped() instanceof Promise), 'the predicate accepts a plain object');

  // And the syscalls themselves, because a function can be async and still block: awaiting
  // is not what makes it non-blocking, not calling the Sync variants is. Scoped to append()
  // alone: read() is the operator's CLI, off the request path, and stays synchronous.
  const src = fs.readFileSync(new URL('../server/suggestions.js', import.meta.url), 'utf8');
  const from = src.indexOf('export async function append');
  const to = src.indexOf('\nexport ', from + 1);
  check('CONTROL: the append() body was actually located in the source',
    from > 0 && to > from, `from ${from} to ${to}`);
  const body = src.slice(from, to);
  const syncCalls = body.match(/\b\w+Sync\(/g) ?? [];
  check('and it reaches the filesystem without a single blocking call',
    syncCalls.length === 0, syncCalls.join(', '));
  check('CONTROL: the same scan does find the deliberate synchronous calls in read()',
    (src.slice(src.indexOf('export function read')).match(/\b\w+Sync\(/g) ?? []).length > 0,
    'the scan finds nothing anywhere, so its silence above means nothing');
}

// ---------------------------------------------------- the size cap survived going async
// statSync followed by appendFileSync was indivisible: nothing else in the process could
// run between the two. Two awaits are not, so without serialising the writes every request
// in flight together stats the same under-cap size and then appends past it, and the file
// cap is exceeded by as much as the concurrency allows. This is the bug the fix for
// finding 7 would have introduced.
{
  const raced = path.join(tmp, 'raced.jsonl');
  const MAX = 900;
  const srv = await startServer({
    WG_HTTP_PORT: String(PORT),
    WG_STUN_ENABLED: '0',
    WG_SUGGESTIONS_PATH: raced,
    WG_SUGGESTIONS_MAX_BYTES: String(MAX),
    WG_SUGGESTIONS_PER_WINDOW: '200',
  });

  // Twenty-four at once, each about 250 bytes on the line, against a 900 byte cap: three fit.
  const text = 'x'.repeat(200);
  const results = await Promise.all(
    Array.from({ length: 24 }, () => request(PORT, 'POST', '/api/suggest', { text })),
  );
  check('CONTROL: all twenty-four submissions were accepted at the wire, so the race had something to race',
    results.every((r) => r.status === 204), results.map((r) => r.status).join(','));

  const size = fs.statSync(raced).size;
  check('concurrent submissions cannot walk the store past its byte cap',
    size <= MAX, `${size} bytes against a cap of ${MAX}`);
  check('CONTROL: and they did fill it, so the cap was actually reached rather than never approached',
    size > MAX / 2, `${size} bytes: the payloads were too small to test anything`);

  await srv.stop();
}

// ---------------------------------------------------------------- the store it cannot write
//
// Found in production on 2026-08-10, not by a test. The box was on, the landing rendered
// it, and every submission came back 400 `store_unwritable` because the container drops
// ALL capabilities and its uid did not own the bind directory. The only trace was one
// line per attempt in a container log. From outside, a store that refuses every write and
// a store nobody has written to are the same empty file.
//
// So the thing under test is not "the write fails", which was already true and already
// silent. It is that the process SAYS SO at boot, once, where an operator will see it.
{
  const PORT = await freePort(3783);
  const walled = path.join(tmp, 'no-entry');
  fs.mkdirSync(walled, { recursive: true });
  // 0o500: readable and traversable, not writable. The same shape as the production
  // failure, reached without needing a container or a second uid.
  fs.chmodSync(walled, 0o500);

  const srv = await startServer({
    WG_HTTP_PORT: String(PORT),
    WG_STUN_ENABLED: '0',
    WG_SUGGESTIONS_PATH: path.join(walled, 'suggestions.jsonl'),
  });

  const banner = srv.stdout();
  check('a suggestion box whose store cannot be written says so at boot',
    /WARNING: the suggestion box is ON but its store is unusable/.test(banner),
    banner.split('\n').filter((l) => /suggestion/i.test(l)).join(' | ') || '(nothing said)');
  check('and it names the directory, so the operator knows which path to fix',
    banner.includes(walled), '(the warning does not name the path)');
  check('but it starts anyway: one broken feature must not take the whole gate down',
    (await request(PORT, 'GET', '/api/health')).status === 200);

  // The warning must be earned, not printed unconditionally. Same server, writable store.
  const okDir = path.join(tmp, 'can-write');
  fs.mkdirSync(okDir, { recursive: true });
  const P2 = await freePort(PORT + 1);
  const srv2 = await startServer({
    WG_HTTP_PORT: String(P2),
    WG_STUN_ENABLED: '0',
    WG_SUGGESTIONS_PATH: path.join(okDir, 'suggestions.jsonl'),
  });
  check('CONTROL: a writable store produces no such warning, so the warning is a measurement',
    !/store is unusable/.test(srv2.stdout()), srv2.stdout());

  // And the box genuinely works there, so "no warning" means usable rather than unchecked.
  const posted = await request(P2, 'POST', '/api/suggest', { text: 'this one lands' });
  check('CONTROL: and a submission to the unwarned store actually reaches disk',
    posted.status === 204 && fs.readFileSync(path.join(okDir, 'suggestions.jsonl'), 'utf8').includes('this one lands'),
    `http ${posted.status}`);

  await srv.stop();
  await srv2.stop();
  // Restore the mode or the rmSync below cannot remove it.
  fs.chmodSync(walled, 0o700);
}

fs.rmSync(tmp, { recursive: true, force: true });
// A suite that returns green on failure is worse than no suite: this exits non-zero so the
// runner can tell.
process.exit(summary('suggestion box') ? 0 : 1);
