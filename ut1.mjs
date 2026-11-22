#!/usr/bin/env node
// UT1 "adult" (Université Toulouse Capitole, CC BY-SA 4.0) for the admin panel only: a warning
// when staff open an address that UT1 lists. Built into private/ut1.bin (NBL1) and uploaded to a
// private Supabase Storage bucket. Never committed, never published, never sent to phones.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseList, collapse, bitsFor, buildBloom, encodeFull } from './lib.mjs';

const URL_UT1 = 'https://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz';
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: KEY } = process.env;
if (!SUPABASE_URL || !KEY) { console.log('ut1: no Supabase secrets, skipped'); process.exit(0); }

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ut1-'));
const res = await fetch(URL_UT1, { signal: AbortSignal.timeout(180_000) });
if (!res.ok) throw new Error(`ut1: HTTP ${res.status}`);
fs.writeFileSync(path.join(tmp, 'adult.tar.gz'), Buffer.from(await res.arrayBuffer()));
execFileSync('tar', ['-xzf', 'adult.tar.gz', 'adult/domains'], { cwd: tmp });
const domains = collapse(parseList(fs.readFileSync(path.join(tmp, 'adult/domains'), 'utf8'), 'domains'));
if (domains.length < 1_000_000) throw new Error(`ut1: only ${domains.length} hosts, not uploading`);
const m = bitsFor(Math.max(domains.length * 1.1, 5_000_000), 1e-4);
const bits = buildBloom(domains, m);
const file = encodeFull({ version: Math.floor(Date.now() / 86400_000), count: domains.length, m, bits });
fs.mkdirSync('private', { recursive: true });
fs.writeFileSync('private/ut1.bin', file);

const base = SUPABASE_URL.replace(/\/$/, '');
const h = { apikey: KEY, authorization: `Bearer ${KEY}` };
await fetch(`${base}/storage/v1/bucket`, { method: 'POST', headers: { ...h, 'content-type': 'application/json' },
  body: JSON.stringify({ id: 'blocklist', name: 'blocklist', public: false }) }); // exists → 400/409, fine
const up = await fetch(`${base}/storage/v1/object/blocklist/ut1.bin`, {
  method: 'POST', headers: { ...h, 'content-type': 'application/octet-stream', 'x-upsert': 'true' }, body: file,
});
if (!up.ok) throw new Error(`ut1 upload: HTTP ${up.status} ${await up.text()}`);
console.log(`ut1: ${domains.length} hosts, ${(file.length / 1e6).toFixed(1)} MB uploaded`);
