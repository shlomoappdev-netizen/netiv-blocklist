#!/usr/bin/env node
// After the tag and release exist: tells Supabase the live version, the conflicts and the
// false positives (private/report.json from build.mjs). Runs on every build, also when nothing
// changed, so the panel always shows the version phones get. Logs counts only.
import fs from 'node:fs';
import { supabaseRpc } from './build.mjs';

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.log('no Supabase secrets: skipped');
  process.exit(0);
}
const r = JSON.parse(fs.readFileSync('private/report.json', 'utf8'));
const out = await supabaseRpc('blocklist_publish', { p: r });
console.log(`supabase: v${out.version}, ${r.conflicts.length} conflicts (${out.new_conflicts} new), ${r.false_positives.length} false positives`);
