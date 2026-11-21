#!/usr/bin/env node
// Builds the mandatory adult-site blocklist. Node 20, no dependencies.
//
//   node build.mjs [--out DIR] [--state DIR] [--offline DIR]
//
// --out     repo root to publish into (default: .)
// --state   previous per-source lists (lists.json.gz from the last release);
//           a source that fails a change limit is taken from here
// --offline read <name>.txt from DIR instead of downloading (tests, dev)
//
// Exit codes: 0 built a new version, 3 nothing changed, 1 a safety check
// failed (nothing written; the previous version stays live).

import fs from 'node:fs';
import path from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import {
  parseList, collapse, parseNeverBlock, hitsNeverBlock, normalizeHost, bitsFor, buildBloom,
  encodeFull, decodeFull, encodeDelta, sha256, checkSourceChanges, checkTotalChange, sanity, K,
} from './lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(
  process.argv.slice(2).reduce((a, x, i, all) => (x.startsWith('--') ? [...a, [x.slice(2), all[i + 1]]] : a), []),
);
const OUT = path.resolve(args.out ?? '.');
const STATE = args.state ? path.resolve(args.state) : null;
const OFFLINE = args.offline ? path.resolve(args.offline) : null;
const log = (...a) => console.log(...a);
const readLines = (f) => fs.readFileSync(f, 'utf8').split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean);

async function fetchText(url, tries = 3, timeoutMs = 60_000) {
  let last;
  for (let i = 1; i <= tries; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': 'netiv-blocklist-build' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (e) {
      last = e;
      log(`  ${url}: try ${i} failed (${e.message})`);
      if (i < tries) await new Promise((r) => setTimeout(r, 5000 * i));
    }
  }
  throw last;
}

// Stage 2 hook: additions and exceptions will come from Supabase
// (blocklist_additions / blocklist_exceptions), and open addresses for the
// conflict report. Until then they are read from optional local files.
async function loadOurLists() {
  const f = (n) => path.join(OUT, n);
  return {
    additions: fs.existsSync(f('additions.txt')) ? readLines(f('additions.txt')).map(normalizeHost).filter(Boolean) : [],
    exceptions: fs.existsSync(f('exceptions.txt')) ? readLines(f('exceptions.txt')).map(normalizeHost).filter(Boolean) : [],
    openHosts: [], // stage 2: open rules from Supabase, for conflicts and Bloom false positives
  };
}

async function main() {
  const cfg = JSON.parse(fs.readFileSync(path.join(HERE, 'sources.json'), 'utf8'));
  const latestPath = path.join(OUT, 'latest.json');
  const prev = fs.existsSync(latestPath) ? JSON.parse(fs.readFileSync(latestPath, 'utf8')) : null;
  const prevLists = STATE && fs.existsSync(path.join(STATE, 'lists.json.gz'))
    ? JSON.parse(gunzipSync(fs.readFileSync(path.join(STATE, 'lists.json.gz'))))
    : {};
  const report = { warnings: [], frozen: [], neverBlockDropped: [], falsePositives: [] };

  // 1. Sources
  const lists = {};
  for (const s of cfg.sources) {
    log(`source ${s.name}`);
    try {
      const text = OFFLINE ? fs.readFileSync(path.join(OFFLINE, `${s.name}.txt`), 'utf8') : await fetchText(s.url);
      lists[s.name] = [...parseList(text, s.format)].sort();
      log(`  ${lists[s.name].length.toLocaleString('en')} hosts`);
    } catch (e) {
      if (!prevLists[s.name]) throw new Error(`source ${s.name} failed and there is no previous list: ${e.message}`);
      report.warnings.push(`${s.name}: download failed (${e.message}); using previous list`);
      report.frozen.push(s.name);
      lists[s.name] = prevLists[s.name];
    }
  }

  // 2. Per-source change limits (skipped on the first build)
  const counts = Object.fromEntries(Object.entries(lists).map(([k, v]) => [k, v.length]));
  const limits = Object.fromEntries(cfg.sources.map((s) => [s.name, { maxDrop: s.maxDrop, maxGrow: s.maxGrow }]));
  for (const name of checkSourceChanges(counts, prev?.sources && Object.fromEntries(Object.entries(prev.sources).map(([k, v]) => [k, v.count])), limits)) {
    if (!prevLists[name]) throw new Error(`source ${name} broke its change limit (${prev.sources[name].count} → ${counts[name]}) and there is no previous list to fall back to`);
    report.warnings.push(`${name}: ${prev.sources[name].count} → ${counts[name]} breaks the change limit; using previous list`);
    report.frozen.push(name);
    lists[name] = prevLists[name];
    counts[name] = lists[name].length;
  }

  // 3. Merge, our additions, never-block, exceptions, collapse
  const ours = await loadOurLists();
  const nb = parseNeverBlock(fs.readFileSync(path.join(HERE, 'never-block.txt'), 'utf8'));
  const exceptions = new Set(ours.exceptions);
  const all = new Set();
  for (const s of cfg.sources) if (s.mode !== 'report') for (const d of lists[s.name]) all.add(d);
  for (const d of ours.additions) all.add(d);
  for (const d of [...all]) {
    if (hitsNeverBlock(d, nb)) { all.delete(d); report.neverBlockDropped.push(d); }
    else if (exceptions.has(d)) all.delete(d);
  }
  const domains = collapse(all);
  log(`merged: ${domains.length.toLocaleString('en')} hosts (${report.neverBlockDropped.length} dropped by never-block)`);

  const totalProblem = checkTotalChange(domains.length, prev?.count, cfg.limits.maxTotalChange);
  if (totalProblem) throw new Error(totalProblem);

  // 4. Bloom
  const m = bitsFor(cfg.bloom.capacity, cfg.bloom.fp);
  if (domains.length > cfg.bloom.capacity) report.warnings.push(`count ${domains.length} is over Bloom capacity ${cfg.bloom.capacity}: raise it (next build is full-only)`);
  const t0 = Date.now();
  const bits = buildBloom(domains, m, cfg.bloom.k ?? K);
  log(`bloom: m=${m} bits (${(m / 8 / 1e6).toFixed(2)} MB), ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  // 5. Sanity
  const set = new Set(domains);
  const san = sanity({
    bits, m, set,
    adult: readLines(path.join(HERE, 'sanity/adult.txt')),
    clean: [...readLines(path.join(HERE, 'sanity/clean.txt')), ...ours.openHosts],
  });
  if (san.errors.length) throw new Error('sanity failed:\n  ' + san.errors.join('\n  '));
  report.falsePositives = san.falsePositives;

  // 6. Unchanged?
  const payloadSha = sha256(bits);
  if (prev && prev.payload_sha256 === payloadSha) { log(`no change since v${prev.version}`); return 3; }

  // 7. Write
  const version = (prev?.version ?? 0) + 1;
  const vdir = path.join(OUT, 'v', String(version));
  fs.mkdirSync(vdir, { recursive: true });
  const full = encodeFull({ version, count: domains.length, k: cfg.bloom.k ?? K, m, bits });
  fs.writeFileSync(path.join(vdir, 'full.bin'), full);

  let delta = null;
  if (prev) {
    const prevFull = path.join(OUT, 'v', String(prev.version), 'full.bin');
    if (fs.existsSync(prevFull)) {
      const old = decodeFull(fs.readFileSync(prevFull));
      if (old.m === m) {
        const { gz, changes } = encodeDelta(prev.version, version, m, old.bits, bits);
        if (gz.length <= full.length * 0.3) {
          const name = `delta-from-${prev.version}.bin`;
          fs.writeFileSync(path.join(vdir, name), gz);
          delta = { from: prev.version, file: `v/${version}/${name}`, sha256: sha256(gz), size: gz.length, changed_bits: changes };
        } else report.warnings.push(`delta ${gz.length} B is over 30% of full; full only`);
      } else report.warnings.push(`m changed (${old.m} → ${m}); full only`);
    }
  }

  // Release assets (not committed): plain list and per-source state for the next build.
  const assets = path.join(OUT, 'release-assets');
  fs.mkdirSync(assets, { recursive: true });
  fs.writeFileSync(path.join(assets, 'domains.txt.gz'), gzipSync(domains.join('\n') + '\n', { level: 9 }));
  fs.writeFileSync(path.join(assets, 'lists.json.gz'), gzipSync(JSON.stringify(lists), { level: 9 }));

  const latest = {
    format: 'NBL1',
    version,
    built_at: new Date().toISOString(),
    count: domains.length,
    k: cfg.bloom.k ?? K,
    m,
    capacity: cfg.bloom.capacity,
    fp_rate: cfg.bloom.fp,
    full: { file: `v/${version}/full.bin`, sha256: sha256(full), size: full.length },
    payload_sha256: payloadSha,
    delta,
    // Hosts the Bloom filter says "probably in" that are not really listed.
    // The phone must treat these as not blocked.
    exceptions: [...new Set([...report.falsePositives, ...exceptions])].sort(),
    sources: Object.fromEntries(cfg.sources.map((s) => [s.name, {
      count: counts[s.name], frozen: report.frozen.includes(s.name), mode: s.mode, license: s.license, url: s.url,
    }])),
    report: { warnings: report.warnings, never_block_dropped: report.neverBlockDropped.sort() },
  };
  fs.writeFileSync(latestPath, JSON.stringify(latest, null, 2) + '\n');

  // Keep only this version and the previous one (delta base) in the tree; tags keep the rest.
  for (const v of fs.readdirSync(path.join(OUT, 'v'))) {
    if (Number(v) < version - 1) fs.rmSync(path.join(OUT, 'v', v), { recursive: true, force: true });
  }

  log(`v${version}: ${domains.length} hosts, full.bin ${(full.length / 1e6).toFixed(2)} MB` +
    (delta ? `, delta ${(delta.size / 1e3).toFixed(1)} KB` : '') +
    `, ${latest.exceptions.length} exceptions, ${report.warnings.length} warnings`);
  for (const w of report.warnings) log(`  warning: ${w}`);
  return 0;
}

main().then((code) => process.exit(code), (e) => { console.error(`BUILD STOPPED: ${e.message}`); process.exit(1); });
