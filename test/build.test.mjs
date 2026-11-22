// End-to-end: build twice from fixtures, check files, delta and the stops.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import { decodeFull, applyDelta, bloomBlocks, sha256 } from '../lib.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const FIX = path.join(ROOT, 'test/fixtures');

function sandbox() {
  // A copy of the repo config with tiny Bloom + sanity lists that fit the fixtures.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nbl-'));
  for (const f of ['lib.mjs', 'build.mjs', 'never-block.txt']) fs.copyFileSync(path.join(ROOT, f), path.join(dir, f));
  const cfg = JSON.parse(fs.readFileSync(path.join(ROOT, 'sources.json'), 'utf8'));
  cfg.bloom.capacity = 1000;
  cfg.limits.maxTotalChange = 0.5; // fixtures are tiny
  fs.writeFileSync(path.join(dir, 'sources.json'), JSON.stringify(cfg));
  fs.mkdirSync(path.join(dir, 'sanity'));
  fs.writeFileSync(path.join(dir, 'sanity/adult.txt'), 'bad-one.com\nx.bad-two.com\n');
  fs.writeFileSync(path.join(dir, 'sanity/clean.txt'), 'google.com\nexample.org\n');
  const off = path.join(dir, 'off');
  fs.cpSync(FIX, off, { recursive: true });
  return { dir, off, out: path.join(dir, 'out'), state: path.join(dir, 'state') };
}
const run = (s) => spawnSync(process.execPath, [path.join(s.dir, 'build.mjs'), '--offline', s.off, '--out', s.out, '--state', s.state], { encoding: 'utf8', env: { ...process.env, SUPABASE_URL: '', SUPABASE_SERVICE_ROLE_KEY: '' } });

test('build v1, no-change, v2 with delta, and stops', () => {
  const s = sandbox();
  fs.mkdirSync(s.out);
  let r = run(s);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const l1 = JSON.parse(fs.readFileSync(path.join(s.out, 'latest.json')));
  assert.equal(l1.version, 1);
  const domains = gunzipSync(fs.readFileSync(path.join(s.out, 'release-assets/domains.txt.gz'))).toString().trim().split('\n');
  assert.deepEqual(domains, ['adult.amazonaws.com', 'bad-five.org', 'bad-four.net', 'bad-one.com', 'bad-three.com', 'bad-two.com']);
  assert.deepEqual(l1.report.never_block_dropped, ['akamaihd.net', 'amazonaws.com']);
  const full1 = fs.readFileSync(path.join(s.out, l1.full.file));
  assert.equal(sha256(full1), l1.full.sha256);
  const f1 = decodeFull(full1);
  assert.equal(bloomBlocks(f1.bits, f1.m, 'deep.bad-four.net'), 'bad-four.net');

  // unchanged → exit 3
  assert.equal(run(s).status, 3);

  // our addition → v2 with a delta that rebuilds v2 from v1
  fs.mkdirSync(s.state);
  fs.copyFileSync(path.join(s.out, 'release-assets/lists.json.gz'), path.join(s.state, 'lists.json.gz'));
  fs.writeFileSync(path.join(s.out, 'additions.txt'), 'new-bad.com\n');
  r = run(s);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const l2 = JSON.parse(fs.readFileSync(path.join(s.out, 'latest.json')));
  assert.equal(l2.version, 2);
  assert.equal(l2.delta.from, 1);
  const rebuilt = applyDelta(fs.readFileSync(path.join(s.out, l2.delta.file)), f1.bits, 1);
  const f2 = decodeFull(fs.readFileSync(path.join(s.out, l2.full.file)));
  assert.equal(sha256(rebuilt.bits), f2.payloadSha);

  // a source collapsing → frozen at its previous list (from state), build goes on
  fs.writeFileSync(path.join(s.off, 'blp.txt'), '0.0.0.0 bad-four.net\n');
  fs.writeFileSync(path.join(s.out, 'additions.txt'), 'new-bad.com\nanother-bad.com\n');
  r = run(s);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const l3 = JSON.parse(fs.readFileSync(path.join(s.out, 'latest.json')));
  assert.equal(l3.sources.blp.frozen, true);
  assert.ok(!fs.existsSync(path.join(s.out, 'v/1')), 'old versions pruned');

  // total drop > 10% → stop, nothing written
  fs.writeFileSync(path.join(s.out, 'additions.txt'), '');
  fs.writeFileSync(path.join(s.off, 'hagezi.txt'), 'bad-one.com\n');
  fs.writeFileSync(path.join(s.off, 'stevenblack.txt'), '0.0.0.0 bad-one.com\n');
  fs.rmSync(path.join(s.state, 'lists.json.gz'));
  r = run(s);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /BUILD STOPPED/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.out, 'latest.json'))).version, 3);
});

test('sanity failure stops the build', () => {
  const s = sandbox();
  fs.mkdirSync(s.out);
  fs.writeFileSync(path.join(s.dir, 'sanity/clean.txt'), 'bad-five.org\n');
  const r = run(s);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /clean host is listed: bad-five.org/);
  assert.ok(!fs.existsSync(path.join(s.out, 'latest.json')));
});

test('open hosts: conflicts and false positives stay private', () => {
  const s = sandbox();
  fs.mkdirSync(s.out);
  // x.bad-four.net is really listed (via its parent); cloudfront-like.example is clean.
  fs.writeFileSync(path.join(s.out, 'open-hosts.txt'), 'x.bad-four.net\nclean.example\nbad-one.com\n');
  const r = run(s);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const rep = JSON.parse(fs.readFileSync(path.join(s.out, 'private/report.json')));
  assert.deepEqual(rep.conflicts.map((c) => [c.domain, c.listed_as, c.found_in.join()]).sort(),
    [['bad-one.com', 'bad-one.com', 'hagezi,stevenblack'], ['x.bad-four.net', 'bad-four.net', 'blp']]);
  assert.equal(rep.version, 1);
  assert.match(rep.url, /@v1\/v\/1\/full\.bin$/);
  const pub = fs.readFileSync(path.join(s.out, 'latest.json'), 'utf8') + r.stdout;
  for (const h of ['x.bad-four.net', 'clean.example']) assert.ok(!pub.includes(h), `${h} leaked`);
  // unchanged build still writes the private report (for the panel)
  fs.rmSync(path.join(s.out, 'private'), { recursive: true });
  assert.equal(run(s).status, 3);
  assert.ok(fs.existsSync(path.join(s.out, 'private/report.json')));
});
