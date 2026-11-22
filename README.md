# netiv-blocklist

A merged, daily-updated blocklist of adult sites, packed as a Bloom filter for
on-device checks. Built by `build.mjs` (Node 20, no dependencies) in a GitHub
Action every day at 03:17 UTC. Sources and credits: `CREDITS.md`, `sources.json`.

## Files

| Path | What |
|---|---|
| `latest.json` | current version, counts, sha256s, delta, exceptions |
| `v/<N>/full.bin` | the Bloom filter (NBL1) |
| `v/<N>/delta-from-<N-1>.bin` | bits changed since the previous version (NBD1, gzip) |
| release `v<N>` assets | `domains.txt.gz` (the plain merged list), `lists.json.gz` (per-source state) |

Served through jsDelivr: `https://cdn.jsdelivr.net/gh/shlomoappdev-netizen/netiv-blocklist@v<N>/v/<N>/full.bin`
(fallback: `raw.githubusercontent.com`). Only the current and previous version
stay in the tree; older versions live on in their tags.

## NBL1 (`full.bin`)

All integers little-endian.

```
offset size
0      4    magic "NBL1"
4      4    version u32
8      4    count u32 (hosts in the list)
12     1    k u8 (hash count, 13)
13     8    m u64 (bits; multiple of 64)
21     32   sha256 of the payload
53     m/8  payload: Bloom bits
```

- Bit index i of a host = `XXH64(utf8(host), seed = i) mod m` (unsigned, seed is u64), for i = 0..k-1.
- Bit b is `payload[b >> 3] & (1 << (b & 7))`.
- A host is blocked if the normalised host, or any parent with at least two
  labels, has all k bits set, unless it is in `latest.json` → `exceptions`
  (Bloom false positives on hosts we know are clean).
- Normalising: lower case, strip a leading `*.` and `www.`, trailing dot.
- `latest.json` → `full.sha256` is the sha256 of the whole file (check it after
  download); the header holds the sha256 of the payload only.
- `m` is sized for a fixed capacity (`sources.json` → `bloom`) so deltas work
  across versions; false-positive rate 1/10,000 at capacity.
- `test-vectors.json` has canonical XXH64 values, bit positions and a tiny
  complete file with lookups. Every implementation must pass it.

## NBD1 (delta)

gzip of:

```
"NBD1" | from u32 | to u32 | m u64 | n u32 | sha256 of target payload (32) | n × (bit position u64, value u8)
```

Apply to the `from` payload, then check the sha256. Not published when it
would be over 30% of the full file, or when `m` changed.

## Safety checks (build stops, previous version stays)

- A source that drops > 20% or grows > 50% is taken from the previous build.
- Total changes > 10% → stop.
- An entry that is, or is a parent of, a host in `never-block.txt` is dropped and reported.
- 20 known adult hosts must be blocked; 200+ clean hosts must not be listed.

## Develop

```
node --test
node build.mjs --out /tmp/out            # downloads the sources
node build.mjs --offline DIR --out /tmp/out   # reads DIR/<source>.txt
```

## The admin panel (Supabase)

With the secrets `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`, the build reads
our additions, exceptions and open hosts (`blocklist_build_input`), and after the
release `publish-db.mjs` sends the version, conflicts and Bloom false positives
back (`blocklist_publish`). Anything derived from open hosts stays in
`private/` (git-ignored) and goes only to Supabase; logs show counts only.
Without the secrets, `additions.txt`, `exceptions.txt` and `open-hosts.txt`
(optional, one host a line) are read from the output folder.

Exceptions from the panel are not in `latest.json`; phones get them with their
policy. `latest.json` → `exceptions` holds only Bloom false positives on the
public clean set.
