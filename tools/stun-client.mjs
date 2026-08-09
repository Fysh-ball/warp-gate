// An independent RFC 5389 client, written against the RFC rather than against
// server/stun.js, so that agreement between them is evidence rather than tautology.

import dgram from 'node:dgram';
import crypto from 'node:crypto';

const MAGIC = 0x2112a442;

export function stunBinding(host, port, timeoutMs = 2500) {
  return new Promise((resolve, reject) => {
    const txid = crypto.randomBytes(12);
    const req = Buffer.alloc(20);
    req.writeUInt16BE(0x0001, 0);
    req.writeUInt16BE(0, 2);
    req.writeUInt32BE(MAGIC, 4);
    txid.copy(req, 8);

    const sock = dgram.createSocket(host.includes(':') ? 'udp6' : 'udp4');
    const done = (err, value) => {
      clearTimeout(timer);
      try { sock.close(); } catch (closeErr) { void closeErr; }
      if (err) reject(err);
      else resolve(value);
    };
    const timer = setTimeout(() => done(new Error(`no STUN response from ${host}:${port} in ${timeoutMs}ms`)), timeoutMs);
    timer.unref?.();

    sock.on('message', (msg) => {
      if (msg.length < 20) return done(new Error(`short response: ${msg.length} bytes`));
      const type = msg.readUInt16BE(0);
      if (type !== 0x0101) return done(new Error(`not a success response: 0x${type.toString(16)}`));
      if (msg.readUInt32BE(4) !== MAGIC) return done(new Error('magic cookie mismatch'));
      if (!msg.subarray(8, 20).equals(txid)) return done(new Error('transaction id mismatch'));

      let off = 20;
      const end = Math.min(20 + msg.readUInt16BE(2), msg.length);
      while (off + 4 <= end) {
        const atype = msg.readUInt16BE(off);
        const alen = msg.readUInt16BE(off + 2);
        const val = msg.subarray(off + 4, off + 4 + alen);
        if (atype === 0x0020) {
          const family = val.readUInt8(1);
          const mappedPort = val.readUInt16BE(2) ^ (MAGIC >>> 16);
          if (family === 0x01) {
            const raw = val.readUInt32BE(4) ^ MAGIC;
            const ip = [raw >>> 24, (raw >>> 16) & 255, (raw >>> 8) & 255, raw & 255].join('.');
            return done(null, { family: 'IPv4', ip, port: mappedPort });
          }
          if (family === 0x02) {
            const mask = Buffer.alloc(16);
            mask.writeUInt32BE(MAGIC, 0);
            txid.copy(mask, 4);
            const bytes = Buffer.alloc(16);
            for (let i = 0; i < 16; i += 1) bytes[i] = val[4 + i] ^ mask[i];
            const parts = [];
            for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16));
            return done(null, { family: 'IPv6', ip: parts.join(':'), port: mappedPort });
          }
          return done(new Error(`unknown address family 0x${family.toString(16)}`));
        }
        off += 4 + alen + ((4 - (alen % 4)) % 4);
      }
      done(new Error('no XOR-MAPPED-ADDRESS attribute'));
    });

    sock.on('error', (err) => done(err));
    sock.send(req, port, host, (err) => { if (err) done(err); });
  });
}
