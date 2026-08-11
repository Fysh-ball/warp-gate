// Test harness: spawns a real server process and speaks to it over the wire.
// Nothing here imports the server's own modules, so a test failure means the
// deployed behaviour is wrong, not just an internal function.

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
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

// The environment variable is WG_HTTP_PORT, not WG_PORT. Getting it wrong does not
// fail: the server silently binds its default 3095, the test measures a port nobody is
// serving, and every count comes back zero, which reads exactly like a pass. Reject the
// wrong spelling at the door rather than letting it produce a false clean result.
const PORT_ALIASES = ['WG_PORT', 'WG_HTTPPORT', 'PORT', 'WG_HTTP_PORT_NUMBER'];
const HOST_ALIASES = ['WG_HOST', 'WG_HTTPHOST', 'HOST'];

/**
 * A usable port, preferring the one asked for.
 *
 * Every suite used to hard-code its port, so a second session on the same box turned
 * EADDRINUSE into an aborted run. The preferred port keeps runs reproducible when it is
 * free; when something else holds it, the kernel picks a free one instead. The port is
 * released again before the server binds it, so a racing process can still steal it in
 * the gap: startServer's banner comparison catches that case loudly rather than letting
 * a measurement land on the wrong process.
 */
export function freePort(preferred) {
  const probe = (port) => new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.once('error', reject);
    srv.listen({ port, host: '127.0.0.1' }, () => {
      const got = srv.address().port;
      srv.close(() => resolve(got));
    });
  });
  return probe(preferred).catch((err) => {
    if (err.code !== 'EADDRINUSE' && err.code !== 'EACCES') throw err;
    return probe(0);
  });
}

/** Start a server process, wait until it reports listening, then prove it answers. */
export function startServer(env = {}) {
  // Case-insensitively, because the guard previously compared exact names and a
  // lowercase `port` sailed through: it became a meaningless env var, the server bound
  // the default 3095, the page under test never loaded, and the failure looked like a
  // broken feature rather than a mis-called helper.
  const aliases = new Set([...PORT_ALIASES, ...HOST_ALIASES].map((a) => a.toLowerCase()));
  for (const given of Object.keys(env)) {
    if (aliases.has(given.toLowerCase())) {
      throw new Error(`startServer was given ${given}; the server reads WG_HTTP_PORT and WG_HTTP_HOST. `
        + 'The wrong name binds the default 3095 and every measurement returns zero, which looks like a pass.');
    }
  }
  const wantPort = env.WG_HTTP_PORT === undefined ? null : Number(env.WG_HTTP_PORT);
  if (env.WG_HTTP_PORT !== undefined && !Number.isInteger(wantPort)) {
    throw new Error(`WG_HTTP_PORT must be an integer, got ${JSON.stringify(env.WG_HTTP_PORT)}`);
  }

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

  const handle = {
    child,
    port: wantPort,
    stdout: () => out,
    stderr: () => err,
    stop: () => new Promise((done) => {
      child.once('exit', done);
      child.kill('SIGTERM');
      setTimeout(() => { child.kill('SIGKILL'); done(); }, 2500).unref();
    }),
  };

  const listening = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server did not start: ${out}${err}`)), 8000);
    const tick = setInterval(() => {
      const banner = /warp-gate http (\S+):(\d+)/.exec(out);
      if (banner) {
        clearTimeout(timer);
        clearInterval(tick);
        // The process prints the port it actually bound. If that is not the port the
        // test asked for, every later measurement is against the wrong process.
        if (wantPort !== null && Number(banner[2]) !== wantPort) {
          reject(new Error(`server bound ${banner[1]}:${banner[2]} but the test asked for ${wantPort}. `
            + 'Measuring the wrong port returns zeros that read as a pass.'));
          return;
        }
        resolve(handle);
      }
      if (child.exitCode !== null) {
        clearTimeout(timer);
        clearInterval(tick);
        reject(new Error(`server exited ${child.exitCode}: ${out}${err}`));
      }
    }, 25);
    tick.unref?.();
  });

  // Liveness gate. Nothing may be measured against a server that did not answer: an
  // unanswered port produces empty results, and empty results are indistinguishable
  // from a clean run.
  return listening.then(async (srv) => {
    if (wantPort === null) return srv;
    const deadline = Date.now() + 5000;
    let last = 'never answered';
    for (;;) {
      try {
        const health = await request(wantPort, 'GET', '/api/health');
        if (health.json?.ok === true) return srv;
        last = `http ${health.status} ${health.text}`;
      } catch (probeErr) {
        last = probeErr.message;
      }
      if (Date.now() > deadline) {
        await srv.stop();
        throw new Error(`server on ${wantPort} never reported {"ok":true} from /api/health (${last}); aborting `
          + 'rather than measuring against a server that is not there');
      }
      await new Promise((r) => { setTimeout(r, 50).unref?.(); });
    }
  });
}

/**
 * A join proof pair.
 *
 * The creator registers H = SHA-256(J) and the joiner presents J. In the browser both
 * come from the room secret; a test only needs a matching pair, so this generates one
 * directly rather than duplicating the HKDF the app already has its own tests for.
 */
/**
 * Are these two slot tokens both present and genuinely different?
 *
 * Exported rather than inlined so the assertion in the test and the proof that the
 * assertion can fail run the same code, instead of two similar-looking copies.
 */
export function distinctTokens(a, b) {
  if (typeof a !== 'string' || a.length === 0) return false;
  if (typeof b !== 'string' || b.length === 0) return false;
  return a !== b;
}

export function makeJoinProof() {
  const proof = crypto.randomBytes(16).toString('base64url');
  const hash = crypto.createHash('sha256').update(Buffer.from(proof, 'base64url')).digest('base64url');
  return { proof, hash };
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
export function openStream(port, roomId, token, { readyTimeoutMs = 8000 } = {}) {
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
    // A server that accepts the connection and then says nothing used to hang the whole
    // suite: there was no deadline anywhere on this path, so one wedged process meant an
    // indefinite stall with no output rather than a failure.
    const deadline = setTimeout(() => {
      try { req?.destroy(); } catch (destroyErr) { void destroyErr; }
      reject(new Error(`SSE stream to room ${roomId} did not open within ${readyTimeoutMs}ms`));
    }, readyTimeoutMs);
    deadline.unref?.();
    const settle = (fn) => (value) => { clearTimeout(deadline); fn(value); };
    resolve = settle(resolve);
    reject = settle(reject);

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
    /**
     * Wait out a window and report whether the event arrived during it.
     *
     * Reading `events` immediately after the request that might leak proves nothing: the
     * leaked frame is still in flight, so the list is empty either way and the assertion
     * prints OK against a server that does leak. This holds the window open instead, and
     * settles early the moment the event does show up so a leak is reported fast.
     */
    arrivedWithin(event, ms) {
      if (events.some((e) => e.event === event)) return Promise.resolve(true);
      return new Promise((resolve) => {
        const entry = { event, resolve: () => { clearTimeout(timer); resolve(true); } };
        waiters.push(entry);
        // Deliberately NOT unref'd. An unref'd timer lets the process exit while this
        // window is still open, which would report "did not arrive" without ever having
        // waited: the same green output whether the check ran or not.
        const timer = setTimeout(() => {
          const i = waiters.indexOf(entry);
          if (i !== -1) waiters.splice(i, 1);
          resolve(false);
        }, ms);
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
