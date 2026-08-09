#!/usr/bin/env node
// Check whether a STUN server is actually reachable and answering correctly.
//
//   node tools/stun-probe.mjs <host> [port]
//
// Run it from the network you actually care about. Reachability from the LAN proves
// nothing about reachability from a phone on mobile data, which is the case that
// matters. Prints the reflexive address the server saw, which is your public IP.
// Exits 0 on success, 1 on failure.

import { stunBinding } from './stun-client.mjs';

const host = process.argv[2];
const port = Number(process.argv[3] ?? 3479);

if (!host) {
  process.stderr.write('usage: node tools/stun-probe.mjs <host> [port]\n');
  process.exit(2);
}

try {
  const result = await stunBinding(host, port, 3000);
  process.stdout.write(`OK   ${host}:${port} answered a STUN binding request\n`);
  process.stdout.write(`     it sees you as ${result.ip}:${result.port} (${result.family})\n`);
  process.exit(0);
} catch (err) {
  process.stdout.write(`BAD  ${host}:${port} did not answer correctly: ${err.message}\n`);
  process.stdout.write('     causes: no UDP port forward, a firewall, or nothing listening\n');
  process.exit(1);
}
