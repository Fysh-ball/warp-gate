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
      last = await this.eval(`return (${expression});`);
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

  close() {
    try { this.ws.close(); } catch (err) { void err; }
  }
}

export async function launchBrowser({ port = 9333, extraArgs = [] } = {}) {
  const binary = findBrowser();
  if (!binary) throw new Error(`no Chromium-based browser found (looked for: ${CHROMIUM_CANDIDATES.join(', ')})`);

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

  // Wait for the debugging endpoint to answer.
  const deadline = Date.now() + 20000;
  let version = null;
  for (;;) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1500) });
      if (res.ok) { version = await res.json(); break; }
    } catch (err) { void err; }
    if (child.exitCode !== null) throw new Error(`browser exited ${child.exitCode}: ${stderr.slice(-800)}`);
    if (Date.now() > deadline) {
      child.kill('SIGKILL');
      throw new Error(`browser debugging port never opened: ${stderr.slice(-800)}`);
    }
    await new Promise((r) => { setTimeout(r, 200).unref?.(); });
  }

  const tabs = [];

  async function newTab(url) {
    const res = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' });
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
    return tab;
  }

  return {
    version: version.Browser,
    newTab,
    async close() {
      for (const tab of tabs) tab.close();
      child.kill('SIGTERM');
      await new Promise((resolve) => {
        child.once('exit', resolve);
        setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 4000).unref?.();
      });
      fs.rmSync(profile, { recursive: true, force: true });
    },
  };
}
