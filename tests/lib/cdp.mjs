// A tiny Chrome DevTools Protocol client, built on Node's global WebSocket.
// No dependencies: npm is not available here.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const CHROMIUM_CANDIDATES = ['brave', 'chromium', 'google-chrome-stable', 'google-chrome'];

export function findBrowser() {
  for (const name of CHROMIUM_CANDIDATES) {
    for (const dir of (process.env.PATH ?? '').split(':')) {
      const full = path.join(dir, name);
      try {
        fs.accessSync(full, fs.constants.X_OK);
        return full;
      } catch (err) { void err; }
    }
  }
  return null;
}

class Tab {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.consoleLines = [];
    this.pageErrors = [];

    ws.addEventListener('message', (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message} (${msg.error.code})`));
        else resolve(msg.result);
        return;
      }
      if (msg.method === 'Runtime.consoleAPICalled') {
        const text = (msg.params.args ?? []).map((a) => a.value ?? a.description ?? a.type).join(' ');
        this.consoleLines.push(`${msg.params.type}: ${text}`);
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params.exceptionDetails;
        this.pageErrors.push(d.exception?.description ?? d.text ?? 'unknown page error');
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP ${method} timed out`));
        }
      }, 30000).unref?.();
    });
  }

  /**
   * Run an expression inside the headless browser page and return its value.
   *
   * This is the DevTools Protocol's Runtime.evaluate command, not JavaScript's eval().
   * It is how a browser is driven over CDP, it exists only in this test harness, it is
   * never shipped to users, and the expressions come from the test files beside it,
   * never from input. Nothing in public/ or server/ uses eval in any form.
   */
  async eval(expression, attempt = 0) {
    let result;
    try {
      result = await this.send('Runtime.evaluate', {
        expression: `(async () => { ${expression} })()`,
        awaitPromise: true,
        returnByValue: true,
      });
    } catch (err) {
      // The page navigated out from under us and the execution context was torn down.
      // This is a race, not a failure: retry against the new context rather than
      // letting the whole suite abort intermittently.
      if (/execution context|Execution context was destroyed/i.test(err.message) && attempt < 10) {
        await new Promise((r) => { setTimeout(r, 150).unref?.(); });
        return this.eval(expression, attempt + 1);
      }
      throw err;
    }
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
    }
    return result.result?.value;
  }

  /** Poll an expression until it is truthy, then return it. */
  async waitFor(expression, { timeout = 20000, interval = 120, label = expression } = {}) {
    const deadline = Date.now() + timeout;
    let last;
    for (;;) {
      try {
        last = await this.eval(`return (${expression});`);
      } catch (err) {
        // A predicate that throws means "not ready yet", not "fail". Mid-navigation the
        // document is briefly empty, so getElementById returns null and any property
        // read on it throws. Keep polling and report the last error only on timeout.
        last = `threw: ${err.message}`;
        if (Date.now() > deadline) throw new Error(`timed out after ${timeout}ms waiting for: ${label}\n  ${last}`);
        await new Promise((r) => { setTimeout(r, interval).unref?.(); });
        continue;
      }
      if (last) return last;
      if (Date.now() > deadline) {
        throw new Error(`timed out after ${timeout}ms waiting for: ${label}\n  last value: ${JSON.stringify(last)}`
          + (this.pageErrors.length ? `\n  page errors: ${this.pageErrors.join(' | ')}` : ''));
      }
      await new Promise((r) => { setTimeout(r, interval).unref?.(); });
    }
  }

  async setFileInput(selector, filePaths) {
    const { root } = await this.send('DOM.getDocument', { depth: 1 });
    const { nodeId } = await this.send('DOM.querySelector', { nodeId: root.nodeId, selector });
    if (!nodeId) throw new Error(`no element matched ${selector}`);
    await this.send('DOM.setFileInputFiles', { nodeId, files: filePaths });
  }

  /**
   * Close the PAGE, then the socket that was driving it.
   *
   * This used to close the WebSocket alone, which released nothing: the tab kept running,
   * its EventSource kept its connection to /api/events open, and every later tab in the
   * suite competed with it. Two ceilings sit right above where that put the run, and both
   * of them fail silently:
   *
   *   - Chromium allows SIX connections per origin over HTTP/1.1, shared by every tab in
   *     the profile. An SSE stream holds one for the life of the tab, so six live gates
   *     leave nothing for a POST. Measured with four held tabs plus a fresh pair: the
   *     joiner's `fetch('/api/relay')` never got a socket and died on its own 8s
   *     AbortSignal, the handshake never happened, and both screens sat on "gathering"
   *     until they gave up. `ss -tn` counted 6 established and pinned.
   *   - The server allows config.limits.streamsPerKey concurrent event streams per address
   *     (default 4, server/config.js). The fifth is refused with 429, and an EventSource
   *     that receives a non-200 goes to readyState CLOSED and does NOT reconnect. Measured
   *     with the same probe at the default limit: readyState 2 on the creator's stream and
   *     a 90s wait for a screen that could no longer arrive.
   *
   * Neither prints anything, in the page or in the run, so the only symptom either has is
   * a waitFor that times out somewhere further down. That is the shape of the intermittent
   * "password gate: tab B connected" abort this file has produced.
   *
   * Best effort and not awaited by every caller: a page that has already gone (a crashed
   * renderer, a browser being torn down) must not turn a passing run into an error here.
   */
  async close() {
    try { await this.send('Page.close', {}); } catch (err) { void err; }
    try { this.ws.close(); } catch (err) { void err; }
  }
}

/** Does something already answer the DevTools protocol on this port? */
async function devtoolsAlreadyThere(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1200) });
    if (!res.ok) return null;
    const body = await res.json();
    return body?.Browser ?? 'an unidentified DevTools endpoint';
  } catch (err) {
    // Connection refused is the expected, wanted answer: nothing is listening.
    void err;
    return null;
  }
}

export async function launchBrowser({ port = 9333, extraArgs = [] } = {}) {
  const binary = findBrowser();
  if (!binary) throw new Error(`no Chromium-based browser found (looked for: ${CHROMIUM_CANDIDATES.join(', ')})`);

  // Bind to the browser this function starts, and to no other.
  //
  // Previously this spawned a browser and then polled the debugging port until *something*
  // answered. A leaked browser from an earlier aborted run answers that port instantly, so
  // the poll succeeded against a stale process: every tab, every page and every assertion
  // for the whole run could come from a browser holding another run's profile, cookies and
  // storage, and nothing would say so. Two gates close that:
  //   1. refuse to start at all if the port is already serving DevTools, and
  //   2. take the endpoint identity from OUR child's own stderr ("DevTools listening on
  //      ws://127.0.0.1:PORT/devtools/browser/UUID"), then require the endpoint that
  //      answers to report that exact same UUID. The UUID is minted per browser process,
  //      so a stale browser cannot match it.
  const squatter = await devtoolsAlreadyThere(port);
  if (squatter) {
    throw new Error(`a browser is already serving DevTools on 127.0.0.1:${port} (${squatter}). `
      + 'Refusing to attach: it is not the browser this test started, and using it would run the '
      + 'whole suite against another process. Kill that PID (never pkill -f) or pass a different port.');
  }

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-cdp-'));
  const child = spawn(binary, [
    '--headless=new',
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--no-sandbox',
    // Deliberately NOT disabling WebRtcHideLocalIpsWithMdns. Real browsers obfuscate
    // host candidates behind mDNS .local names, and a test that turns that off is
    // testing a browser nobody runs. Set WG_TEST_DISABLE_MDNS=1 to compare.
    ...(process.env.WG_TEST_DISABLE_MDNS === '1' ? ['--disable-features=WebRtcHideLocalIpsWithMdns'] : []),
    ...extraArgs,
    'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });

  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d.toString(); });

  const die = (message) => {
    try { child.kill('SIGKILL'); } catch (err) { void err; }
    // Never let cleanup replace the real reason we are dying.
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (err) { void err; }
    return new Error(message);
  };

  // Wait for OUR child to announce its own endpoint on its own stderr.
  const deadline = Date.now() + 20000;
  let ownEndpoint = null;
  for (;;) {
    const announced = /DevTools listening on (ws:\/\/[^\s]+)/.exec(stderr);
    if (announced) { ownEndpoint = announced[1]; break; }
    if (child.exitCode !== null) {
      throw die(`browser exited ${child.exitCode} before announcing a debugging endpoint: ${stderr.slice(-800)}`);
    }
    if (Date.now() > deadline) {
      throw die('browser never announced a DevTools endpoint on its own stderr, so there is no way to '
        + `tell it apart from any other browser on this machine: ${stderr.slice(-800)}`);
    }
    await new Promise((r) => { setTimeout(r, 100).unref?.(); });
  }
  const ownPort = Number(new URL(ownEndpoint).port);
  if (ownPort !== port) {
    throw die(`the browser this test started is on port ${ownPort}, not the requested ${port}. `
      + `Whatever is on ${port} belongs to someone else and will not be used.`);
  }

  let version = null;
  for (;;) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1500) });
      if (res.ok) { version = await res.json(); break; }
    } catch (err) { void err; }
    if (child.exitCode !== null) throw die(`browser exited ${child.exitCode}: ${stderr.slice(-800)}`);
    if (Date.now() > deadline) throw die(`browser debugging port never answered: ${stderr.slice(-800)}`);
    await new Promise((r) => { setTimeout(r, 200).unref?.(); });
  }
  // The endpoint that answered must be the endpoint our child announced. Anything else
  // is a different browser process and is refused rather than silently driven.
  if (version.webSocketDebuggerUrl !== ownEndpoint) {
    throw die(`127.0.0.1:${port} is serving ${version.webSocketDebuggerUrl}, but the browser this test `
      + `started announced ${ownEndpoint}. That endpoint belongs to another process; refusing to use it.`);
  }

  const tabs = [];

  async function newTab(url) {
    // Unbounded, this hangs the whole suite when the browser accepts the connection and
    // then stops answering: every later timeout is measured from a tab that never opened.
    const res = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`,
      { method: 'PUT', signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`could not open a tab: http ${res.status} ${await res.text()}`);
    const info = await res.json();
    const ws = new WebSocket(info.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', () => reject(new Error('devtools websocket failed')), { once: true });
    });
    const tab = new Tab(ws);
    await tab.send('Runtime.enable');
    await tab.send('Page.enable');
    await tab.send('DOM.enable');
    tabs.push(tab);
    // /json/new answers as soon as the TARGET exists, which is before it has navigated.
    // An eval issued straight afterwards therefore lands in the initial empty document,
    // where isSecureContext is false and a module specifier like '/js/download.js' has no
    // base URL to resolve against. Both were observed as intermittent failures that looked
    // like product bugs. Wait for the document the caller actually asked for.
    if (url && url !== 'about:blank') {
      await tab.waitFor(
        "location.href !== 'about:blank' && document.readyState !== 'loading'",
        { timeout: 30000, label: `tab navigated to ${url}` },
      );
    }
    return tab;
  }

  return {
    version: version.Browser,
    // The PID of the process this call started, and the port it published for itself.
    // A test can assert against these to show it is talking to its own browser.
    pid: child.pid,
    debugPort: ownPort,
    newTab,
    async close() {
      for (const tab of tabs) tab.close();
      child.kill('SIGTERM');
      await new Promise((resolve) => {
        child.once('exit', resolve);
        setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 4000).unref?.();
      });
      // A killed browser keeps flushing its profile for a moment, so a single rmSync races
      // it and throws ENOTEMPTY. That threw out of the suite's finally block and reported a
      // passing run as a failure. Retry, and if it still will not go, say so and carry on:
      // a leftover temp directory is not a test result.
      for (let attempt = 0; ; attempt += 1) {
        try { fs.rmSync(profile, { recursive: true, force: true }); break; } catch (err) {
          if (attempt >= 25) {
            process.stderr.write(`could not remove the browser profile ${profile}: ${err.message}\n`);
            break;
          }
          await new Promise((resolve) => { setTimeout(resolve, 120).unref?.(); });
        }
      }
    },
  };
}
