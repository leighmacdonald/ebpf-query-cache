# a2scache — eBPF A2S query cache for Source / TF2 servers

`a2scache` answers Source engine A2S server queries (`A2S_INFO`,
`A2S_PLAYER`, with the modern challenge flow) **from an eBPF program in
the kernel**, without forwarding the query to the game server. A small
userspace daemon keeps the cache warm by performing the challenge dance
with each backend; on a hit the server sees nothing.

- Entire query path handled in one TC ingress program — no redirect to
another process, no XDP-to-socket hop, no helper daemon on the hot path
- Implements the modern (post-2023) A2S challenge protocol:
unchallenged request → `S2C_CHALLENGE` → challenged request → payload
- Per-`(ip, port)` cache entries (INFO + PLAYER payload + challenge +
timestamps), FE-fragment reassembly, in-skb reply rewrite with
recomputed IP/UDP checksums
- Token-bucket rate limiting per source IP + global, evaluated in the
same program
- Written in Rust: `aya-ebpf` program, `aya` userspace; built hermetically
with a nix flake; targets Linux kernels 6.x and 7.x (Ubuntu 24.04 /
26.04), validated on a 7.0.11 liquorix kernel

## How it works

```
                        host
 client ──UDP──> [veth/iface ingress: TC]
                          │
                     a2scache (BPF, per-packet)
                          │
     ┌────────────────────┼─────────────────────────────┐
     │ non-A2S / unknown key / stale / rate-limited     │
     ▼                    ▼                             ▼
   TC_ACT_OK           TC_ACT_SHOT            A2S request for a
   (pass through)      (drop, counted)        cached (ip, port)
                                                        │
                                            ┌───────────┴───────────┐
                                            │ fresh?                │
                                     yes ┌──┴──┐ no                │
                                         │     └──> pass (counted) │
                                         ▼                        │
                                   synthesize reply:              │
                                   challenge / INFO / PLAYER      │
                                   rewrite skb in place,          │
                                   redirect (mode by topology),   │
                                   count                           │
                                                                  │
 daemon (userspace, one thread per backend) ──> challenge dance ──> game server
   refreshes CacheEntry every interval (< TTL)                    (only this traffic
                                                                  reaches the server)
```

Per-packet decisions (all counters exposed by `a2scache stats`):


| condition                                                                  | verdict                                                                                      |
| -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| not Ethernet/IPv4/UDP or IP fragment                                       | pass (`non_a2s`)                                                                             |
| `(dip, dport)` not a cached key                                            | pass (`unknown_key`)                                                                         |
| per-IP or global token bucket empty                                        | drop (`dropped_rate_*`)                                                                      |
| unchallenged INFO, or PLAYER/INFO with challenge `0xFFFFFFFF`, entry fresh | synthesize `S2C_CHALLENGE` (`sent_challenge_*`)                                              |
| bad challenge value                                                        | pass (`dropped_bad_challenge` — the server will re-challenge)                                |
| challenged INFO/PLAYER, payload age &lt; TTL                               | serve cached payload, rewritten as a reply from the server (`served_info` / `served_player`) |
| entry stale                                                                | pass (`dropped_stale` — the server answers; the daemon re-caches)                            |


Reply rewrite: the program resizes the skb to the cached datagram and
stores a full Ethernet frame — MACs swapped (client ← server), IP
src/dst swapped, UDP ports swapped, IP total length + UDP length set,
IP and UDP checksums recomputed with `bpf_csum_diff` — then delivers it
with a redirect helper chosen by `Config.redirect_mode` (see below).
The returned verdict is the helper's own return value (see *Kernel
compatibility*).

Reply delivery mode (`redirect_mode` in the config map): the mode is
picked by `attach` from the interface's topology and stored in the
config map, so it survives daemon restarts.

- **`peer` (0)** — `bpf_redirect_peer(ifindex_out, 0)`: re-injects the
  frame on the interface's *in-kernel peer* (veth/netkit) receive path.
  Selected when `/sys/class/net/<iface>/iflink` names a device other
  than the interface itself (the peer's ifindex; devices without a peer
  report their own ifindex there).
- **`xmit` (1)** — `bpf_redirect(ifindex_out, 0)`: transmits the frame
  on the same interface's egress, out to the wire. Selected for real
  NICs, bridges, etc. This is required there: `bpf_redirect_peer` on a
  device without `ndo_get_peer_dev` records the target and the kernel
  then silently `kfree()`s the frame in `skb_do_redirect()` (see
  *Troubleshooting*).

## Requirements

- Linux ≥ 5.7 for the helpers used (see *Kernel compatibility*);
validated on 6.8 (Ubuntu 24.04 class) and 7.0.11 (liquorix)
- `CAP_BPF` + `CAP_NET_ADMIN` (root in practice): loading/attaching BPF
and adding the clsact qdisc
- a bpffs mount for pinning (default `/sys/fs/bpf`; `mount -t bpf bpf /sys/fs/bpf`)
- the game server reachable from the daemon host at the configured
`(ip, port)` — **not** at `127.0.0.1`: the Source engine ignores A2S
requests arriving with a `127/8` source address

## Building

Everything is pinned by the nix flake; build artifacts and all caches
live under `./.tmp` (hidden, in-tree).

```
nix build .#a2scache     # hermetic: BPF ELF (bpfel + BTF) + static binary
nix develop              # dev shell: just, nightly rust, bpf-linker, bpftool
```

`just` recipes: `build`, `build-local`, `develop`, `test` (unit),
`test-e2e` (root: netns + fake servers), `test-e2e-real` (root + running
srcds), `lint`, `fmt`, `install`, `clean`.

## Quickstart

```
just install                          # binary + units + /etc/a2scache.toml
# edit /etc/a2scache.toml: [[server]] entries for your backends
systemctl enable --now a2scache-attach@<iface> a2scache-daemon

a2scache status --pin-dir /sys/fs/bpf/a2scache
a2scache stats  --pin-dir /sys/fs/bpf/a2scache -w
a2scache query 192.0.2.10:27015 info     # full challenge dance, for debugging
```

Manual (no systemd):

```
a2scache attach <iface> --ttl-sec 30     # clsact qdisc + load + pin
a2scache serve --config /etc/a2scache.toml
# ...
a2scache clean <iface>                   # detach + remove pins
```

Attach on the interface that **receives** the A2S queries (the one
whose IP the clients/tracker/browser target). The program is attached to
TC ingress only; egress is never touched.

## Configuration (`/etc/a2scache.toml`)

```toml
[bpf]
pin_dir = "/sys/fs/bpf/a2scache"   # must match `attach --pin-dir`

[defaults]
ttl_secs = 30          # BPF serves an entry this long after the daemon
                       # last refreshed it, then passes through
interval_secs = 10     # daemon refresh period per backend; keep < ttl
timeout_ms = 2000      # per-datagram timeout for the daemon's dance
per_ip_capacity = 10000    # token bucket: per source IP (tokens = queries)
per_ip_refill_per_s = 2000
global_capacity = 200000   # token bucket: all sources combined
global_refill_per_s = 50000

# [metrics]
# listen = "127.0.0.1:9103"   # Prometheus /metrics endpoint (off unless set;
                              # `serve --metrics-listen ADDR` wins)

[[server]]
ip = "192.0.2.10"      # the (ip, port) clients query — the BPF cache key
port = 27015
# mac = "aa:bb:cc:dd:ee:ff"   # optional source MAC for synthesized replies
# ttl_secs = 60               # per-instance TTL override (falls back to defaults)
# interval_secs = 5           # per-instance refresh period override
# timeout_ms = 1500           # per-instance dance timeout override
```

Notes:

- **One `[[server]]` per `(ip, port)`**; two servers on one host need one
  entry per port, and duplicate `(ip, port)` entries are rejected. The
  cache map holds at most **4096 instances**
  (`a2s_protocol::CACHE_MAX_ENTRIES`, a compile-time BPF map parameter —
  the daemon refuses a config with more).
- Every per-instance `[[server]]` field is optional and falls back to
  `[defaults]` (enforcing the same validity floors: `ttl_secs >= 1`,
  `interval_secs >= 1`, `timeout_ms >= 100`), so instances can be tuned
  independently — e.g. an often-visited instance gets a longer TTL and a
  faster refresh than a sleepy one. The BPF program reads the TTL
  *per instance* (stored in the cache entry; until an entry's first
  successful refresh, the global TTL applies).
- The client-facing rate limiter (per source IP + one global bucket) is
  *not* per-instance: it bounds what a client/tracker can send, not how a
  given instance behaves. Per-instance "rate" tuning is the refresh
  `interval_secs`.
- `ip` is the address clients use (and therefore the address the daemon
  queries). For a server on the same machine as the cache, use the
  machine's real IP, **not** `127.0.0.1` (Source ignores A2S from
  `127/8`).
- A wildcard-bound (`0.0.0.0`) server sources its *pass-through* replies
  with the egress interface's address. If pass-through replies must
  complete the dance (stale/unknown entries), pick `ip` on the interface
  the reply will leave by.
- `mac`: when set, the first server's MAC becomes the source MAC of all
  synthesized replies; otherwise the MAC recorded at `attach` time is
  used. (BPF holds a single global MAC; per-instance MACs for backends on
  other hosts are not supported yet.)

## Rate limiting

Two independent token buckets (in-BPF, `bpf_ktime_get_ns` based) protect
the pass-through path:

- **per source IP**: default 10k tokens, refill 2k/s — bounds one
client/tracker; cache hits never consume tokens (only packets that
would reach the server do)
- **global**: default 200k / 50k/s — bounds aggregate fan-in (e.g. a
full Steam server-browser sweep)

Only packets that *pass through* consume tokens: a burst entirely
satisfied by cache is free. Dropped packets are counted
(`dropped_rate_ip` / `dropped_rate_global`) and dropped with
`TC_ACT_SHOT`. For a heavily queried public server raise the global
refill; for a small LAN leave the defaults.

## Stats

`a2scache stats` (or `--json`): percpu counters aggregated across CPUs.


| counter                                                                                   | meaning                                                |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `pass_through`                                                                            | request datagrams forwarded to the real server         |
| `served_info` / `served_player`                                                           | cached payloads served                                 |
| `sent_challenge_info` / `sent_challenge_player`                                           | synthesized challenges                                 |
| `dropped_rate_ip` / `dropped_rate_global`                                                 | rate-limit drops                                       |
| `dropped_stale`                                                                           | entry older than TTL → passed through                  |
| `dropped_bad_challenge`                                                                   | wrong challenge value → passed through                 |
| `dropped_too_large`                                                                       | cached payload exceeds map capacity                    |
| `dropped_rewrite` / `dropped_rewrite_guard` / `_tail` / `_hdr` / `_payload` / `_redirect` | reply-rewrite failures (each stage counted)            |
| `non_a2s`                                                                                 | non-Ethernet/IPv4/UDP or IP-fragmented frames (passed) |
| `unknown_key`                                                                             | A2S for a `(dip, dport)` that is not cached (passed)   |


## Status

`a2scache status` renders the config and every cache entry: a count /
capacity header (instances cached vs. the compile-time 4096 limit), each
instance's payload sizes/ages, challenge, effective per-instance TTL, and
the server name parsed from the cached INFO payload.

`a2scache status --json` emits the same list machine-readable (unset
payload ages are `null`):

```json
{"capacity": 4096, "entries": [{"ip": "1.2.3.4", "port": 27015, "name": "Uncletopia | Example", "challenge": 12345, "challenge_age_s": 2, "info_len": 140, "info_age_s": 1, "player_len": 90, "player_age_s": 1, "ttl_s": 30}], "count": 1}
```

## Metrics

The daemon can serve Prometheus metrics at `/metrics`. The endpoint is
**off unless enabled** — set `[metrics] listen` in the config, or pass
`a2scache serve --metrics-listen 127.0.0.1:9103` (the flag wins). Values
are re-read from the pinned BPF maps on *every scrape* (never on a
timer), so an idle daemon does no work; a bind failure logs a warning
and the daemon runs without metrics.

| metric | type | meaning |
| --- | --- | --- |
| `a2scache_bpf_events_total{stat}` | counter | the 18 `stats` verdict counters (`pass_through`, `served_info`, …), per-CPU aggregated; reset to zero when the program is re-attached (the exporter detects the drop and re-baselines) |
| `a2scache_bpf_attached` | gauge | `1` if the pinned maps were readable on the last scrape |
| `a2scache_cache_entries` / `a2scache_cache_capacity` | gauge | instances cached vs. the compile-time 4096 |
| `a2scache_entry_{info,player,challenge}_age_seconds{ip,port}` | gauge | seconds since that half of the entry was last refreshed (`0` = never refreshed, or < 1 s) |
| `a2scache_entry_{info,player}_bytes{ip,port}` | gauge | cached payload sizes (`0` = never refreshed) |
| `a2scache_entry_ttl_seconds{ip,port}` | gauge | effective per-instance freshness window recorded in the entry |
| `a2scache_backend_up{ip,port}` | gauge | `1` if the daemon's last refresh of that backend succeeded |
| `a2scache_backend_refreshes_total{ip,port,result}` | counter | refresh cycles; `result` = `success`\|`failure` |
| `a2scache_backend_last_success_seconds{ip,port}` | gauge | Unix time of the last successful refresh (`0` = never) |
| `a2scache_backend_last_refresh_latency_seconds{ip,port}` | gauge | wall time of the last completed refresh cycle |
| `a2scache_daemon_uptime_seconds` / `a2scache_daemon_backends` | gauge | daemon wall time / configured `[[server]]` count |
| `a2scache_build_info{version}` | gauge | always `1`, labelled with the daemon version |

Sample (excerpt):

```text
a2scache_bpf_events_total{stat="served_info"} 1842
a2scache_bpf_events_total{stat="pass_through"} 7
a2scache_cache_entries 10
a2scache_cache_capacity 4096
a2scache_entry_info_age_seconds{ip="192.0.2.10",port="27015"} 3
a2scache_backend_up{ip="192.0.2.10",port="27015"} 1
a2scache_bpf_attached 1
```

Scrape config and example alerts:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: a2scache
    static_configs:
      - targets: ["game-cache-host:9103"]
```

```yaml
# alerts
groups:
  - name: a2scache
    rules:
      - alert: A2SCacheBackendDown
        # the daemon cannot keep this backend warm
        expr: a2scache_backend_up == 0
        for: 2m
      - alert: A2SCacheEntryStale
        # an entry drifted past its own TTL (refresh slower than TTL)
        expr: a2scache_entry_info_age_seconds > a2scache_entry_ttl_seconds
      - alert: A2SCacheBpfDetached
        # the program fell off the interface (or the pins moved)
        expr: a2scache_bpf_attached == 0
        for: 1m
```

Note: because the BPF stats map is re-created on every `attach`, the
`a2scache_bpf_events_total` series legitimately restart from a low value
after a re-attach; the exporter resets the Prometheus counter at that
point (Prometheus itself handles counter resets for `rate()`/`increase()`).

## Kernel compatibility

- **Minimum kernel 5.7**, set by `bpf_redirect_peer`. Other helpers are
older: `bpf_skb_store_bytes`/`bpf_skb_load_bytes`/`bpf_skb_change_tail`
/ `bpf_ktime_get_ns` (3.0), `bpf_csum_diff` (4.10),
`bpf_get_prandom_u32` (4.4). Maps: array/hash/percpu-array (≤3.18).
Program type TC on clsact (4.10). Ubuntu 24.04 (6.8) and 26.04 (7.x)
both qualify; validated on 7.0.11.
- **TC action enum renumbering (6.x → 7.0)**: `TC_ACT_REDIRECT` was
`0x20000000` on 6.x and became `7` in 7.0's uapi. The program does not
compare against any redirect constant: it returns the redirect
helper's return value verbatim as the verdict, and treats only
`TC_ACT_SHOT` (= 2, stable) as failure. This makes the object load on
both kernel generations.
- **L2 at TC ingress**: `skb->data` is the Ethernet frame (MAC header
first); the kernel pulls L2 after TC. The program therefore reads and
writes full frames (offsets: MAC 0-13, IPv4 14-33, UDP 34-41).
- **`peer` mode re-entry**: with flags 0 `bpf_redirect_peer`
re-enters the receive path on the target (peer) side via `-EAGAIN`
(`another_round`), bypassing the `bpf_redirect` mac_header check —
that is how the synthesized reply is delivered to the client without
going through the host IP stack. Only works on devices with an
in-kernel peer (`ndo_get_peer_dev`: veth, netkit).
- **`xmit` mode on real NICs**: both helpers only *record* the target
in the per-CPU `bpf_redirect_info`; the actual redirect runs in
`skb_do_redirect()` once the program's `TC_ACT_REDIRECT` verdict is
processed, and for the ingress verdict the TC core first pushes
`mac_len` back, so the skb carries the full L2 header. For a device
without a peer, `bpf_redirect_peer` would `kfree()` the frame there
(silent drop). Plain `bpf_redirect(ifindex, 0)` instead transmits on
the same interface's egress (`__bpf_tx_skb` → `dev_queue_xmit`): the
"link layer header is carried" check
(`mac_header < network_header`) holds for driver-built skbs whose
`mac_header` is unset (`HARDHEADER`), and the frame is a complete
Ethernet frame, so it is sent out to the wire to the client.
- **Checksum endianness**: kernel csum helpers (`do_csum`/
`csum_partial` behind `bpf_csum_diff`) sum *native-endian* words and
the result is stored natively (`ip->check = ip_fast_csum(...)`). The
program therefore stores computed checksums in native byte order
(`to_ne_bytes`); a big-endian store double-swaps on x86 and the
receiver's `ip_rcv` checksum test rejects the frame.
- **BPF call arguments ≤ 5 registers**: stack arguments beyond r6-r10
(r11) are only verifier-supported on ~7.1+, so the program keeps BPF
function calls within the 5-register limit (the serve path takes one
pointer argument to a stack struct).
- **Attachment**: classic clsact filter via netlink (`SchedClassifier`),
not TCX — TCX attachments are `bpf_link`s that aya would auto-detach
on process exit and that complicate re-attach; a netlink filter keeps
the program alive after the attaching process exits and pins under
bpffs.

## Testing

- `just test` — unit tests (protocol codec, reassembly, map layouts,
daemon refresh logic, BPF ELF sanity).
- `just test-e2e` — root: builds a veth/netns topology, runs fake TF2
backends (challenge-first dance, FE fragmentation, per-backend query
counters), attaches the program, and checks: cache serving,
per-`(ip, port)` isolation, fragmented responses, stale → pass-through,
backend-A-down with B unaffected, rate-limit bursts, per-instance TTL
divergence (a short-TTL instance goes stale while a long-TTL one stays
fresh), and an 8-instance scale scenario (all cached, isolated, and
served from cache; `status` / `status --json` machine-checked).
- `just test-e2e-real` — root + live srcds: same harness against two real
TF2 dedicated servers; cached replies must be byte-identical to direct
queries. Takes optional `ADDR1 ADDR2` (bare port = the harness veth IP, or
an explicit `ip:port` for a backend bound to another of the host's
addresses).

## Troubleshooting

- **`attach` fails with `EPERM`** — not root / missing `CAP_BPF`,
`CAP_NET_ADMIN`; or unprivileged BPF sysctls:
`kernel.unprivileged_bpf_disabled` is irrelevant for root, but
`bpf_jit_enable = 1` is needed for JITed load (on by default).
- **`serve` retries "cannot open ... CONFIG_MAP"** — the daemon needs
the pins from `attach`; it retries with backoff until they exist.
- **Client sees nothing, `stats` show `pass_through` growing** — the
pass-through reply isn't completing the dance: the server is
wildcard-bound and sources replies with the egress interface's
address; re-aim `[[server]].ip` (see *Configuration* notes).
- **Client sees nothing, `sent_challenge_*` grows, but no drop counter
moves** — the synthesized reply is being kfree'd by the kernel *after*
the program returns: `bpf_redirect_peer` was used on a device without
an in-kernel peer (real NIC/bridge). `attach` picks the mode from the
topology (`iflink` vs `ifindex`); if the interface changed kind
(veth → physical), re-run `attach` so the config map is rewritten.
- **`serve` can't warm a backend, works from another machine** — you
configured `127.0.0.1`; Source ignores A2S from `127/8`.
- **`dropped_stale` high** — `interval_secs` too close to `ttl_secs`, or
the backend is slow; widen the TTL or shorten the interval.
- **`dropped_rate_*` nonzero** — legitimate load is being limited;
raise the corresponding bucket.
- **bpffs missing** — `mount -t bpf bpf /sys/fs/bpf`
(`/etc/fstab`: `bpf /sys/fs/bpf bpffs nodev,noexec,nosuid 0 0`).

## Layout

- `crates/a2s-protocol` — no_std wire codec + `#[repr(C)]` map layouts
(single source of truth for BPF and userspace)
- `crates/a2scache-bpf` — aya-ebpf TC ingress program
- `crates/a2scache` — userspace binary (CLI + refresh daemon), BPF ELF
embedded via `include_bytes!`
- `packaging/` — systemd units (`a2scache-attach@.service`,
`a2scache-daemon.service`)
- `tests/e2e/` — harness (`run.sh`, `real_server.sh`, `client.py`,
`fake_server.py`)

## License

MIT — see `LICENSE.md`.