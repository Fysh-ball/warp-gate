// A minimal RFC 5389 STUN Binding responder.
//
// Why in-process rather than coturn: a Binding transaction is stateless, carries no
// cryptography and is fully specified. Running it here keeps Warp Gate to the single
// process that DESIGN.md section 21 asks for, and avoids depending on a public STUN
// server, which would be a third party IP disclosure on the default path (1.2).
//
// This implements Binding requests only. No TURN allocations, no long-term
// credentials, no ALTERNATE-SERVER. Anything that is not a well-formed Binding
// request is dropped in silence.

import dgram from 'node:dgram';
import { config } from './config.js';
import { keyFor, allow } from './limits.js';

const MAGIC = 0x2112a442;
const BINDING_REQUEST = 0x0001;
const BINDING_SUCCESS = 0x0101;
const XOR_MAPPED_ADDRESS = 0x0020;

function xorMappedAddress(address, port, txid) {
  const isV6 = address.includes(':') && !address.startsWith('::ffff:');
  const ip = address.startsWith('::ffff:') ? address.slice(7) : address;

  if (!isV6) {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
    const value = Buffer.alloc(8);
    value.writeUInt8(0, 0);
    value.writeUInt8(0x01, 1); // family: IPv4
    value.writeUInt16BE(port ^ (MAGIC >>> 16), 2);
    const raw = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    value.writeUInt32BE((raw ^ MAGIC) >>> 0, 4);
    return value;
  }

  // IPv6: XOR against the magic cookie followed by the transaction ID.
  const groups = expandV6(ip);
  if (!groups) return null;
  const value = Buffer.alloc(20);
  value.writeUInt8(0, 0);
  value.writeUInt8(0x02, 1); // family: IPv6
  value.writeUInt16BE(port ^ (MAGIC >>> 16), 2);
  const mask = Buffer.alloc(16);
  mask.writeUInt32BE(MAGIC, 0);
  txid.copy(mask, 4);
  for (let i = 0; i < 16; i += 1) value.writeUInt8(groups[i] ^ mask[i], 4 + i);
  return value;
}

/** Expand an IPv6 literal to 16 bytes. Returns null if it is not parseable. */
function expandV6(ip) {
  // Reject before parsing rather than after. parseInt is not a validator: it read
  // "1zz" as 1, and splitting on "::" silently dropped the third half of "1::2::3",
  // so malformed literals expanded to a plausible-looking address instead of null.
  const parts = ip.split('%')[0].split('::');
  if (parts.length > 2) return null;
  const [head, tail] = parts;
  const parse = (part) => (part ? part.split(':') : []);
  const left = parse(head);
  const right = tail === undefined ? [] : parse(tail);
  if (tail === undefined && left.length !== 8) return null;
  const fill = 8 - left.length - right.length;
  if (fill < 0) return null;
  const groups = [...left, ...Array(tail === undefined ? 0 : fill).fill('0'), ...right];
  if (groups.length !== 8) return null;
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i += 1) {
    if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return null;
    out.writeUInt16BE(Number.parseInt(groups[i], 16), i * 2);
  }
  return out;
}

function buildResponse(txid, address, port) {
  const attrValue = xorMappedAddress(address, port, txid);
  if (!attrValue) return null;
  const msg = Buffer.alloc(20 + 4 + attrValue.length);
  msg.writeUInt16BE(BINDING_SUCCESS, 0);
  msg.writeUInt16BE(4 + attrValue.length, 2);
  msg.writeUInt32BE(MAGIC, 4);
  txid.copy(msg, 8);
  msg.writeUInt16BE(XOR_MAPPED_ADDRESS, 20);
  msg.writeUInt16BE(attrValue.length, 22);
  attrValue.copy(msg, 24);
  return msg;
}

function handle(sock, msg, rinfo) {
  // Drop anything that is not exactly a Binding request. Being strict here keeps the
  // responder from becoming a reflector for arbitrary traffic.
  if (msg.length < 20) return;
  if (msg.readUInt16BE(0) !== BINDING_REQUEST) return;
  if (msg.readUInt32BE(4) !== MAGIC) return;
  const declared = msg.readUInt16BE(2);
  if (20 + declared !== msg.length) return;

  // A UDP source address is forgeable, so the per-source limit below is not a bound on
  // anything: every spoofed source gets a fresh 20/s budget and its own retained bucket
  // entry. The global ceiling is checked first, and is the only one an attacker cannot
  // rotate around. Amplification is not the concern here (a response is ~1.6x a
  // request); the bucket growth behind the untrustworthy key is.
  if (!allow('stun-all', 'global', config.limits.stunPerSecondGlobal, 1000)) return;
  if (!allow('stun', keyFor(rinfo.address), config.limits.stunPerSecondPerIp, 1000)) return;

  const response = buildResponse(msg.subarray(8, 20), rinfo.address, rinfo.port);
  if (!response) return;
  sock.send(response, rinfo.port, rinfo.address, (err) => {
    // Surfaced, like the bind and socket errors below. No address: that would be a
    // request log, which this process deliberately does not keep.
    if (err) process.stderr.write(`stun send failed: ${err.message}\n`);
  });
}

export function startStun() {
  if (!config.stunEnabled) return [];
  const sockets = [];

  for (const type of ['udp4', 'udp6']) {
    const sock = dgram.createSocket({ type, ipv6Only: type === 'udp6', reuseAddr: true });
    sock.on('message', (msg, rinfo) => handle(sock, msg, rinfo));
    sock.on('error', (err) => {
      // A missing IPv6 stack must not take the process down.
      process.stderr.write(`stun ${type} error: ${err.message}\n`);
      try { sock.close(); } catch (closeErr) { void closeErr; }
    });
    try {
      sock.bind(config.stunPort, type === 'udp4' ? config.stunHost : '::');
      sockets.push(sock);
    } catch (err) {
      process.stderr.write(`stun ${type} bind failed: ${err.message}\n`);
    }
  }
  return sockets;
}
