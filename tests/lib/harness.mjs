// Test harness: spawns a real server process and speaks to it over the wire.
// Nothing here imports the server's own modules, so a test failure means the
// deployed behaviour is wrong, not just an internal function.

import { spawn } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

let passed = 0;
let failed = 0;
const failures = [];

export function check(name, condition, detail = '') {
  if (condition) {
    passed += 1;
    process.stdout.write(`OK   ${name}\n`);
  } else {
    failed += 1;
    failures.push(name);
    process.stdout.write(`BAD  ${name}${detail ? `  <- ${detail}` : ''}\n`);
  }
}

export function summary(label) {
  process.stdout.write(`\n${label}: ${passed} passed, ${failed} failed\n`);
  if (failures.length) process.stdout.write(`failed: ${failures.join(', ')}\n`);
  return failed === 0;
}

export function resetCounters() {
  passed = 0;
  failed = 0;
  failures.length = 0;
}

// Every spawned server is tracked so that a crashing test cannot leave a process
// holding a port. Without this, one failure poisons every subsequent run.
const children = new Set();
const reap = () => {
  for (const child of children) {
    try { child.kill('SIGKILL'); } catch (err) { void err; }
  }
  children.clear();
};
process.on('exit', reap);
for (const signal of ['SIGINT', 'SIGTERM', 'uncaughtException', 'unhandledRejection']) {
  process.on(signal, (err) => {
    reap();
    if (err instanceof Error) process.stderr.write(`\nharness aborted: ${err.stack}\n`);
    process.exit(1);
  });
}

/** Start a server process and wait until it reports listening. */
export function startServer(env = {}) {
  const child = spawn(process.execPath, [path.join(ROOT, 'server', 'index.js')], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.add(child);
  child.on('exit', () => children.delete(child));
  let out = '';
  let err = '';
  child.stdout.on('data', (d) => { out += d.toString(); });
  child.stderr.on('data', (d) => { err += d.toString(); });

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start: ${out}${err}`)), 8000);
    const tick = setInterval(() => {
      if (out.includes('warp-gate http')) {
        clearTimeout(timer);
        clearInterval(tick);
        resolve({
          child,
          stdout: () => out,
          stderr: () => err,
          stop: () => new Promise((done) => {
            child.once('exit', done);
            child.kill('SIGTERM');
            setTimeout(() => { child.kill('SIGKILL'); done(); }, 2500).unref();
          }),
        });
      }
      if (child.exitCode !== null) {
        clearTimeout(timer);
        clearInterval(tick);
        reject(new Error(`server exited ${child.exitCode}: ${out}${err}`));
      }
    }, 25);
    tick.unref?.();
  });
}

export function request(port, method, pathname, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: '127.0.0.1', port, method, path: pathname, headers: {
        ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}),
        ...headers,
      } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = JSON.parse(text); } catch (err) { json = null; void err; }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      },
    );
    req.on('error', reject);
    req.setTimeout(6000, () => req.destroy(new Error('request timeout')));
    if (payload) req.write(payload);
    req.end();
  });
}

/** Minimal SSE client. Collects events and lets a test await a specific one. */
export function openStream(port, roomId, token) {
  const events = [];
  const waiters = [];
  let buffer = '';
  let req = null;
  let res = null;

  const emit = (event, data) => {
    const record = { event, data };
    events.push(record);
    for (let i = waiters.length - 1; i >= 0; i -= 1) {
      if (waiters[i].event === event) {
        waiters[i].resolve(record);
        waiters.splice(i, 1);
      }
    }
  };

  const ready = new Promise((resolve, reject) => {
    req = http.get(
      { host: '127.0.0.1', port, path: `/api/events?room=${encodeURIComponent(roomId)}&token=${encodeURIComponent(token)}` },
      (response) => {
        res = response;
        if (response.statusCode !== 200) {
          const chunks = [];
          response.on('data', (c) => chunks.push(c));
          response.on('end', () => reject(new Error(`stream status ${response.statusCode}: ${Buffer.concat(chunks)}`)));
          return;
        }
        resolve(response);
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          buffer += chunk;
          let idx;
          while ((idx = buffer.indexOf('\n\n')) !== -1) {
            const block = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            if (block.startsWith(':')) { emit('__heartbeat', null); continue; }
            let event = 'message';
            let data = '';
            for (const line of block.split('\n')) {
              if (line.startsWith('event: ')) event = line.slice(7);
              else if (line.startsWith('data: ')) data += line.slice(6);
            }
            let parsed = null;
            try { parsed = data ? JSON.parse(data) : null; } catch (err) { parsed = data; void err; }
            emit(event, parsed);
          }
        });
        response.on('end', () => emit('__end', null));
      },
    );
    req.on('error', reject);
  });

  return {
    ready,
    events,
    seen: (event) => events.some((e) => e.event === event),
    /** Wait for the next occurrence of an event, or for one already received. */
    wait(event, ms = 4000) {
      const existing = events.find((e) => e.event === event);
      if (existing) return Promise.resolve(existing);
      return new Promise((resolve, reject) => {
        const entry = { event, resolve };
        waiters.push(entry);
        setTimeout(() => {
          const i = waiters.indexOf(entry);
          if (i !== -1) waiters.splice(i, 1);
          reject(new Error(`timed out waiting for SSE event "${event}" after ${ms}ms`));
        }, ms).unref?.();
      });
    },
    close() {
      try { req?.destroy(); } catch (err) { void err; }
      try { res?.destroy(); } catch (err) { void err; }
    },
  };
}

/** A promise-based delay. Tests need to observe timers expiring; this is not padding. */
export const delay = (ms) => new Promise((r) => { setTimeout(r, ms).unref?.(); });

export async function expectThrows(fn) {
  try {
    await fn();
    return null;
  } catch (err) {
    return err;
  }
}
