#!/usr/bin/env node
// Report which ICE candidate types this network can actually gather.
//
//   node tools/ice-check.mjs                          # host candidates only
//   node tools/ice-check.mjs stun:stun.cloudflare.com:3478
//
// This answers the only question that matters for cross-network use: does this
// network yield a server-reflexive (srflx) candidate? Without one, two devices on
// different networks cannot find each other and Warp Gate will correctly report that
// it cannot connect.
//
//   host   a local address. Same LAN or same overlay network only.
//   srflx  the public address a STUN server saw. This is what crosses networks.
//   relay  a TURN relay address. The fallback when NAT is too restrictive.
//
// Run it from the network you actually care about. A result from your LAN says
// nothing about a phone on mobile data.

import { launchBrowser, findBrowser } from '../tests/lib/cdp.mjs';

const servers = process.argv.slice(2);

if (!findBrowser()) {
  process.stdout.write('BAD  no Chromium-based browser found; this needs one to run WebRTC\n');
  process.exit(2);
}

const iceServers = servers.length ? [{ urls: servers }] : [];
process.stdout.write(`ICE servers: ${servers.length ? servers.join(', ') : '(none, host candidates only)'}\n\n`);

const browser = await launchBrowser({ port: 9355 });
try {
  const tab = await browser.newTab('about:blank');
  const result = await tab.eval(`
    const pc = new RTCPeerConnection({ iceServers: ${JSON.stringify(iceServers)} });
    const found = [];
    pc.createDataChannel('probe');
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((resolve) => {
      const done = setTimeout(resolve, 12000);
      pc.addEventListener('icecandidate', (e) => {
        if (!e.candidate) { clearTimeout(done); resolve(); return; }
        const c = e.candidate;
        found.push({ type: c.type, protocol: c.protocol, address: c.address });
      });
    });
    pc.close();
    return JSON.stringify(found);
  `);

  const candidates = JSON.parse(result);
  const types = new Set(candidates.map((c) => c.type).filter(Boolean));

  const counts = {};
  for (const c of candidates) counts[c.type ?? 'unknown'] = (counts[c.type ?? 'unknown'] ?? 0) + 1;
  for (const [type, n] of Object.entries(counts)) {
    process.stdout.write(`  ${type.padEnd(6)} ${n}\n`);
  }
  process.stdout.write('\n');

  // Addresses are deliberately not printed: the srflx one is your public IP.
  if (types.has('relay')) {
    process.stdout.write('OK   relay candidates available: will connect even through restrictive NAT\n');
  }
  if (types.has('srflx')) {
    process.stdout.write('OK   server-reflexive candidate gathered: cross-network connections can work\n');
    process.exit(0);
  }
  if (types.has('host')) {
    process.stdout.write('BAD  host candidates only: this will connect on the same network and nowhere else\n');
    process.stdout.write('     cause: no STUN server configured, or UDP to it is blocked from this network\n');
    process.exit(1);
  }
  process.stdout.write('BAD  no candidates gathered at all\n');
  process.exit(1);
} finally {
  await browser.close();
}
