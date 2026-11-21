import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  normalizeHost, parseList, collapse, parseNeverBlock, hitsNeverBlock, xxh64, positions, buildBloom,
  bloomHas, bloomBlocks, encodeFull, decodeFull, encodeDelta, applyDelta, bitsFor,
  checkSourceChanges, checkTotalChange, sanity, sha256,
} from '../lib.mjs';

const enc = new TextEncoder();
const V = JSON.parse(fs.readFileSync(new URL('../test-vectors.json', import.meta.url)));

test('normalise', () => {
  assert.equal(normalizeHost('WWW.Example.COM'), 'example.com');
  assert.equal(normalizeHost('*.x.example.com'), 'x.example.com');
  assert.equal(normalizeHost('||ads.example.com^'), 'ads.example.com');
  assert.equal(normalizeHost('https://a.example.com:443/path'), 'a.example.com');
  for (const bad of ['localhost', '10.0.0.1', '0.0.0.0', 'nodot', '-bad.com', 'a_b.com', '', 'www.com'.slice(0, 3)])
    assert.equal(normalizeHost(bad), null, bad);
});

test('parse domains and hosts formats', () => {
  assert.deepEqual([...parseList('# c\nA.com\n!x\n*.b.com\n', 'domains')].sort(), ['a.com', 'b.com']);
  assert.deepEqual([...parseList('0.0.0.0 a.com #c\n127.0.0.1 b.com\n1.2.3.4 c.com\n0.0.0.0 localhost\n', 'hosts')].sort(), ['a.com', 'b.com']);
});

test('collapse drops subdomains of listed parents', () => {
  assert.deepEqual(collapse(new Set(['a.com', 'x.a.com', 'y.x.a.com', 'b.a.org', 'c.org'])), ['a.com', 'b.a.org', 'c.org']);
});

test('never-block: drops protected hosts and their parents, keeps their subdomains', () => {
  const nb = parseNeverBlock('# c\namazonaws.com\nakamai*\nmail.google.com\n');
  assert.ok(hitsNeverBlock('amazonaws.com', nb));
  assert.ok(hitsNeverBlock('akamaihd.net', nb));
  assert.ok(hitsNeverBlock('google.com', nb), 'parent of a protected host');
  assert.ok(!hitsNeverBlock('adult.amazonaws.com', nb));
  assert.ok(!hitsNeverBlock('notakamai.net', nb));
});

test('xxh64 matches canonical and shared vectors', () => {
  for (const v of V.xxh64) assert.equal(xxh64(enc.encode(v.input), BigInt(v.seed)).toString(16).padStart(16, '0'), v.xxh64, v.input);
  assert.equal(V.xxh64[0].xxh64, 'ef46db3751d8e999');
  assert.equal(V.xxh64[3].xxh64, 'fbcea83c8a378bf1');
  for (const p of V.positions) assert.deepEqual(positions(p.host, p.m, p.k), p.positions);
});

test('mini bloom file matches vectors byte for byte', () => {
  const mb = V.mini_bloom;
  const bits = buildBloom(mb.domains, mb.m, mb.k);
  const file = encodeFull({ version: mb.version, count: mb.domains.length, m: mb.m, bits });
  assert.equal(file.toString('hex'), mb.full_bin_hex);
  const d = decodeFull(Buffer.from(mb.full_bin_hex, 'hex'));
  assert.equal(d.version, 7); assert.equal(d.k, 13); assert.equal(d.m, 4096); assert.equal(d.count, 3);
  for (const q of mb.queries) assert.equal(bloomBlocks(d.bits, d.m, q.host), q.blocked_by, q.host);
});

test('bloom: no false negatives, fp rate near target', () => {
  const n = 20000;
  const m = bitsFor(n, 1e-4);
  const doms = Array.from({ length: n }, (_, i) => `site${i}.example`);
  const bits = buildBloom(doms, m);
  assert.ok(doms.every((d) => bloomHas(bits, m, d)));
  let fp = 0;
  for (let i = 0; i < 50000; i++) if (bloomHas(bits, m, `other${i}.test`)) fp++;
  assert.ok(fp <= 25, `fp ${fp}/50000`);
});

test('decodeFull rejects a corrupted payload', () => {
  const bits = buildBloom(['a.com'], 1024);
  const f = encodeFull({ version: 1, count: 1, m: 1024, bits });
  f[f.length - 1] ^= 0xff;
  assert.throws(() => decodeFull(f), /sha256/);
});

test('delta round trip', () => {
  const m = 8192;
  const a = buildBloom(['a.com', 'b.com', 'c.com'], m);
  const b = buildBloom(['a.com', 'c.com', 'd.com', 'e.com'], m);
  const { gz, changes } = encodeDelta(4, 5, m, a, b);
  assert.ok(changes > 0);
  const r = applyDelta(gz, a, 4);
  assert.equal(r.version, 5);
  assert.equal(sha256(r.bits), sha256(b));
  assert.throws(() => applyDelta(gz, a, 3), /base version/);
  assert.throws(() => encodeDelta(1, 2, m, a, new Uint8Array(2048)), /m changed/);
});

test('safety: source change limits', () => {
  const lim = { s: { maxDrop: 0.2, maxGrow: 0.5 } };
  assert.deepEqual(checkSourceChanges({ s: 85 }, { s: 100 }, lim), []);
  assert.deepEqual(checkSourceChanges({ s: 79 }, { s: 100 }, lim), ['s']);
  assert.deepEqual(checkSourceChanges({ s: 151 }, { s: 100 }, lim), ['s']);
  assert.deepEqual(checkSourceChanges({ s: 5 }, null, lim), [], 'first build');
});

test('safety: total change', () => {
  assert.equal(checkTotalChange(109, 100), null);
  assert.match(checkTotalChange(89, 100), /11.0%/);
  assert.equal(checkTotalChange(5, undefined), null);
});

test('safety: sanity', () => {
  const m = 65536;
  const set = new Set(['bad.com']);
  const bits = buildBloom(set, m);
  assert.deepEqual(sanity({ bits, m, set, adult: ['bad.com', 'www.bad.com'], clean: ['good.com'] }).errors, []);
  assert.equal(sanity({ bits, m, set, adult: ['missing.com'], clean: [] }).errors.length, 1);
  assert.equal(sanity({ bits, m, set, adult: [], clean: ['x.bad.com'] }).errors.length, 1);
  // a forced false positive: every bit set
  const all = new Uint8Array(m / 8).fill(255);
  assert.deepEqual(sanity({ bits: all, m, set, adult: [], clean: ['good.co.il'] }).falsePositives, ['co.il', 'good.co.il']);
});
