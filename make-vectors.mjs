// Writes test-vectors.json: shared between this repo and the phone (Kotlin).
// Re-run only if the format changes on purpose: node make-vectors.mjs
import fs from 'node:fs';
import { xxh64, positions, buildBloom, encodeFull, bloomBlocks, sha256 } from './lib.mjs';
const enc = new TextEncoder();
const xx = [];
for (const [s, seed] of [['', 0], ['a', 0], ['abc', 0], ['Nobody inspects the spammish repetition', 0],
  ['pornhub.com', 0], ['pornhub.com', 1], ['pornhub.com', 12], ['example.co.il', 7], ['a-very-long-subdomain.of.some.example-domain.com', 3]]) {
  xx.push({ input: s, seed, xxh64: xxh64(enc.encode(s), BigInt(seed)).toString(16).padStart(16, '0') });
}
const M = 23004160;
const pos = ['pornhub.com', 'xvideos.com', 'google.com', 'co.il'].map((h) => ({ host: h, m: M, k: 13, positions: positions(h, M) }));
const mini = { m: 4096, k: 13, version: 7, domains: ['bad.example', 'evil.test', 'xn--80ak6aa92e.com'] };
const bits = buildBloom(mini.domains, mini.m);
const file = encodeFull({ version: mini.version, count: mini.domains.length, m: mini.m, bits });
const queries = ['bad.example', 'www.bad.example', 'cdn.img.evil.test', 'good.example', 'example', 'xn--80ak6aa92e.com']
  .map((q) => ({ host: q, blocked_by: bloomBlocks(bits, mini.m, q) }));
const out = {
  about: 'Shared vectors for NBL1. xxh64 is canonical XXH64 (seed is u64). Bit index = xxh64(utf8(host), seed=i) mod m for i=0..k-1; bit b lives in byte b>>3 at (1 << (b & 7)). Lookups check the normalised host and each parent with >= 2 labels.',
  xxh64: xx,
  positions: pos,
  mini_bloom: { ...mini, full_bin_hex: file.toString('hex'), full_sha256: sha256(file), queries },
};
fs.writeFileSync('test-vectors.json', JSON.stringify(out, null, 2) + '\n');
console.log('ok', file.length, 'bytes mini file');
