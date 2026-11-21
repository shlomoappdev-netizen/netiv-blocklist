// Core of the netiv-blocklist build: parsing, normalising, merging, the Bloom
// filter (NBL1 file format), delta (NBD1) and the safety checks.
// Node 20, no dependencies. The phone (Kotlin) reimplements the Bloom/xxh64
// parts; test-vectors.json keeps the two in step.

import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';

// ---------------------------------------------------------------- normalise

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** Returns a normalised hostname, or null if the token is not a usable host. */
export function normalizeHost(raw) {
  if (typeof raw !== 'string') return null;
  let h = raw.trim().toLowerCase();
  if (!h) return null;
  if (h.startsWith('||')) h = h.slice(2);            // adblock syntax ||host^
  h = h.replace(/\^.*$/, '');
  h = h.replace(/^[a-z]+:\/\//, '');                 // scheme
  h = h.split(/[/?#:]/)[0];                          // path, port
  while (h.startsWith('*.') || h.startsWith('.')) h = h.slice(h.startsWith('*.') ? 2 : 1);
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (h.startsWith('www.')) h = h.slice(4);
  if (h.length < 3 || h.length > 253) return null;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return null;
  const labels = h.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((l) => LABEL.test(l))) return null;
  if (/^[0-9]+$/.test(labels[labels.length - 1])) return null; // IPv4 / numeric TLD
  return h;
}

/** Parses a list file. format: "domains" (one host a line) or "hosts" (0.0.0.0 host). */
export function parseList(text, format) {
  const out = new Set();
  for (let line of text.split('\n')) {
    line = line.replace(/#.*$/, '').trim();
    if (!line || line.startsWith('!')) continue;
    let token;
    if (format === 'hosts') {
      const parts = line.split(/\s+/);
      if (parts.length < 2 || !['0.0.0.0', '127.0.0.1', '::', '::1'].includes(parts[0])) continue;
      token = parts[1];
    } else {
      token = line.split(/\s+/)[0];
    }
    const h = normalizeHost(token);
    if (h) out.add(h);
  }
  return out;
}

/** Parents of a host that still have at least two labels, nearest first. */
export function parentsOf(host) {
  const p = host.split('.');
  const out = [];
  for (let i = 1; i < p.length - 1; i++) out.push(p.slice(i).join('.'));
  return out;
}

/** Drops every entry whose parent is also in the set (the parent already covers it). */
export function collapse(set) {
  const out = [];
  for (const d of set) if (!parentsOf(d).some((p) => set.has(p))) out.push(d);
  return out.sort();
}

// ---------------------------------------------------------------- never-block

/** never-block.txt: one host a line, or a pattern with '*' (e.g. akamai*). */
export function parseNeverBlock(text) {
  const exact = new Set();
  const patterns = [];
  for (let line of text.split('\n')) {
    line = line.replace(/#.*$/, '').trim().toLowerCase();
    if (!line) continue;
    if (line.includes('*')) {
      const re = '^' + line.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[a-z0-9.-]*') + '$';
      patterns.push(new RegExp(re));
    } else {
      const h = normalizeHost(line);
      if (h) exact.add(h);
    }
  }
  return { exact, patterns };
}

/**
 * True if blocking `entry` would block a protected host: the entry is a
 * protected host, a parent of one, or matches a pattern. Subdomains of a
 * protected host stay blockable (an adult x.amazonaws.com is still blocked).
 */
export function hitsNeverBlock(entry, nb) {
  if (nb.exact.has(entry)) return true;
  if (nb.patterns.some((re) => re.test(entry))) return true;
  for (const prot of nb.exact) if (prot.endsWith('.' + entry)) return true;
  return false;
}

// ---------------------------------------------------------------- xxh64

const M64 = (1n << 64n) - 1n;
const P1 = 11400714785074694791n;
const P2 = 14029467366897019727n;
const P3 = 1609587929392839161n;
const P4 = 9650029242287828579n;
const P5 = 2870177450012600261n;
const rotl = (x, r) => ((x << BigInt(r)) | (x >> BigInt(64 - r))) & M64;
const round = (acc, lane) => (rotl((acc + lane * P2) & M64, 31) * P1) & M64;
const merge = (acc, val) => ((((acc ^ round(0n, val)) * P1) & M64) + P4) & M64;

function u64le(b, i) {
  return BigInt(b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)) + (BigInt(b[i + 3]) << 24n) +
    (BigInt(b[i + 4] | (b[i + 5] << 8) | (b[i + 6] << 16)) << 32n) + (BigInt(b[i + 7]) << 56n);
}
function u32le(b, i) {
  return BigInt((b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)) >>> 0) + (BigInt(b[i + 3]) << 24n);
}

/** XXH64 of bytes with a u64 seed, as an unsigned BigInt. */
export function xxh64(bytes, seed = 0n) {
  seed = BigInt(seed) & M64;
  const len = bytes.length;
  let i = 0;
  let h;
  if (len >= 32) {
    let v1 = (seed + P1 + P2) & M64, v2 = (seed + P2) & M64, v3 = seed, v4 = (seed - P1) & M64;
    for (; i + 32 <= len; i += 32) {
      v1 = round(v1, u64le(bytes, i)); v2 = round(v2, u64le(bytes, i + 8));
      v3 = round(v3, u64le(bytes, i + 16)); v4 = round(v4, u64le(bytes, i + 24));
    }
    h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) & M64;
    h = merge(h, v1); h = merge(h, v2); h = merge(h, v3); h = merge(h, v4);
  } else {
    h = (seed + P5) & M64;
  }
  h = (h + BigInt(len)) & M64;
  for (; i + 8 <= len; i += 8) h = (((rotl(h ^ round(0n, u64le(bytes, i)), 27) * P1) & M64) + P4) & M64;
  if (i + 4 <= len) { h = (((rotl(h ^ ((u32le(bytes, i) * P1) & M64), 23) * P2) & M64) + P3) & M64; i += 4; }
  for (; i < len; i++) h = (rotl(h ^ ((BigInt(bytes[i]) * P5) & M64), 11) * P1) & M64;
  h ^= h >> 33n; h = (h * P2) & M64;
  h ^= h >> 29n; h = (h * P3) & M64;
  h ^= h >> 32n;
  return h;
}

// ---------------------------------------------------------------- Bloom / NBL1

export const K = 13;
export const HEADER_LEN = 4 + 4 + 4 + 1 + 8 + 32; // 53
const enc = new TextEncoder();

/** Bits for `capacity` entries at false-positive rate `fp`, rounded up to 64. */
export function bitsFor(capacity, fp) {
  const m = Math.ceil((-capacity * Math.log(fp)) / Math.LN2 ** 2);
  return Math.ceil(m / 64) * 64;
}

/** Bit positions for a host: xxh64(utf8(host), seed=i) mod m, i = 0..k-1. */
export function positions(host, m, k = K) {
  const b = enc.encode(host);
  const mm = BigInt(m);
  const out = new Array(k);
  for (let i = 0; i < k; i++) out[i] = Number(xxh64(b, BigInt(i)) % mm);
  return out;
}

export function buildBloom(domains, m, k = K) {
  const bits = new Uint8Array(m / 8);
  for (const d of domains) for (const p of positions(d, m, k)) bits[p >>> 3] |= 1 << (p & 7);
  return bits;
}

export function bloomHas(bits, m, host, k = K) {
  for (const p of positions(host, m, k)) if (!(bits[p >>> 3] & (1 << (p & 7)))) return false;
  return true;
}

/** Phone semantics: blocked if the host or any parent (>= 2 labels) is "probably in". */
export function bloomBlocks(bits, m, host, k = K) {
  const h = normalizeHost(host);
  if (!h) return null;
  return [h, ...parentsOf(h)].find((x) => bloomHas(bits, m, x, k)) ?? null;
}

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export function encodeFull({ version, count, k = K, m, bits }) {
  const out = Buffer.alloc(HEADER_LEN + bits.length);
  out.write('NBL1', 0, 'ascii');
  out.writeUInt32LE(version, 4);
  out.writeUInt32LE(count, 8);
  out.writeUInt8(k, 12);
  out.writeBigUInt64LE(BigInt(m), 13);
  Buffer.from(sha256(bits), 'hex').copy(out, 21);
  Buffer.from(bits.buffer, bits.byteOffset, bits.length).copy(out, HEADER_LEN);
  return out;
}

export function decodeFull(buf) {
  if (buf.toString('ascii', 0, 4) !== 'NBL1') throw new Error('bad magic');
  const m = Number(buf.readBigUInt64LE(13));
  const bits = new Uint8Array(buf.subarray(HEADER_LEN));
  if (bits.length !== m / 8) throw new Error('bad length');
  const payloadSha = buf.subarray(21, 53).toString('hex');
  if (sha256(bits) !== payloadSha) throw new Error('payload sha256 mismatch');
  return { version: buf.readUInt32LE(4), count: buf.readUInt32LE(8), k: buf.readUInt8(12), m, payloadSha, bits };
}

// ---------------------------------------------------------------- delta / NBD1

const DELTA_HEADER = 4 + 4 + 4 + 8 + 4 + 32; // 56

/** gzip("NBD1" | from u32 | to u32 | m u64 | n u32 | sha256(target payload) | n × (pos u64, value u8)). */
export function encodeDelta(fromVer, toVer, m, oldBits, newBits) {
  if (oldBits.length !== newBits.length) throw new Error('m changed: no delta');
  const changes = [];
  for (let byte = 0; byte < newBits.length; byte++) {
    const x = oldBits[byte] ^ newBits[byte];
    if (!x) continue;
    for (let b = 0; b < 8; b++) if (x & (1 << b)) changes.push([byte * 8 + b, (newBits[byte] >> b) & 1]);
  }
  const out = Buffer.alloc(DELTA_HEADER + changes.length * 9);
  out.write('NBD1', 0, 'ascii');
  out.writeUInt32LE(fromVer, 4);
  out.writeUInt32LE(toVer, 8);
  out.writeBigUInt64LE(BigInt(m), 12);
  out.writeUInt32LE(changes.length, 20);
  Buffer.from(sha256(newBits), 'hex').copy(out, 24);
  let o = DELTA_HEADER;
  for (const [pos, val] of changes) { out.writeBigUInt64LE(BigInt(pos), o); out.writeUInt8(val, o + 8); o += 9; }
  return { gz: gzipSync(out, { level: 9 }), changes: changes.length };
}

export function applyDelta(gz, oldBits, oldVersion) {
  const d = gunzipSync(gz);
  if (d.toString('ascii', 0, 4) !== 'NBD1') throw new Error('bad delta magic');
  if (d.readUInt32LE(4) !== oldVersion) throw new Error('delta is for another base version');
  if (Number(d.readBigUInt64LE(12)) !== oldBits.length * 8) throw new Error('delta m mismatch');
  const n = d.readUInt32LE(20);
  const target = d.subarray(24, 56).toString('hex');
  const bits = new Uint8Array(oldBits);
  for (let i = 0, o = DELTA_HEADER; i < n; i++, o += 9) {
    const pos = Number(d.readBigUInt64LE(o));
    if (d.readUInt8(o + 8)) bits[pos >>> 3] |= 1 << (pos & 7); else bits[pos >>> 3] &= ~(1 << (pos & 7));
  }
  if (sha256(bits) !== target) throw new Error('delta result sha256 mismatch');
  return { version: d.readUInt32LE(8), bits };
}

// ---------------------------------------------------------------- safety

/**
 * Per-source change limits against the previous build. Returns the names of
 * sources that must be frozen at their previous list. No previous count → ok.
 */
export function checkSourceChanges(counts, prevCounts, limits) {
  const frozen = [];
  for (const [name, n] of Object.entries(counts)) {
    const prev = prevCounts?.[name];
    if (!prev) continue;
    const lim = limits[name] ?? { maxDrop: 0.2, maxGrow: 0.5 };
    if (n < prev * (1 - lim.maxDrop) || n > prev * (1 + lim.maxGrow)) frozen.push(name);
  }
  return frozen;
}

export function checkTotalChange(total, prevTotal, max = 0.1) {
  if (!prevTotal) return null;
  const ch = Math.abs(total - prevTotal) / prevTotal;
  return ch > max ? `total changed ${(ch * 100).toFixed(1)}% (${prevTotal} → ${total}), limit ${max * 100}%` : null;
}

/**
 * Sanity: every known adult host is blocked, no clean host is really listed.
 * Clean hosts that only hit by Bloom false positive are returned (they go to
 * the exceptions shipped with latest.json), not treated as failures.
 */
export function sanity({ bits, m, set, adult, clean }) {
  const errors = [];
  const falsePositives = [];
  for (const a of adult) if (!bloomBlocks(bits, m, a)) errors.push(`adult host not blocked: ${a}`);
  for (const c of clean) {
    const h = normalizeHost(c);
    if (!h) continue;
    const real = [h, ...parentsOf(h)].find((x) => set.has(x));
    if (real) { errors.push(`clean host is listed: ${c} (via ${real})`); continue; }
    for (const x of [h, ...parentsOf(h)]) if (bloomHas(bits, m, x)) falsePositives.push(x);
  }
  return { errors, falsePositives: [...new Set(falsePositives)].sort() };
}
