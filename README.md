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
                                   redirect to peer, count        │
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
IP and UDP checksums recomputed with `bpf_csum_diff` — then
`bpf_redirect_peer(ifindex_out, 0)` re-injects it on the same
interface's peer so the kernel delivers it to the client. The returned
verdict is the helper's own return value (see *Kernel compatibility*).

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

[[server]]
ip = "192.0.2.10"      # the (ip, port) clients query — the BPF cache key
port = 27015
# mac = "aa:bb:cc:dd:ee:ff"   # optional source MAC for synthesized replies
```

Notes:

- **One `[[server]]` per `(ip, port)`**; two servers on one host need one
entry per port.
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
used.

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


## Kernel compatibility

- **Minimum kernel 5.7**, set by `bpf_redirect_peer`. Other helpers are
older: `bpf_skb_store_bytes`/`bpf_skb_load_bytes`/`bpf_skb_change_tail`
/ `bpf_ktime_get_ns` (3.0), `bpf_csum_diff` (4.10),
`bpf_get_prandom_u32` (4.4). Maps: array/hash/percpu-array (≤3.18).
Program type TC on clsact (4.10). Ubuntu 24.04 (6.8) and 26.04 (7.x)
both qualify; validated on 7.0.11.
- **TC action enum renumbering (6.x → 7.0)**: `TC_ACT_REDIRECT` was
`0x20000000` on 6.x and became `7` in 7.0's uapi. The program does not
compare against any redirect constant: it returns `bpf_redirect_peer`'s
return value verbatim as the verdict, and treats only
`TC_ACT_SHOT` (= 2, stable) as failure. This makes the object load on
both kernel generations.
- **L2 at TC ingress**: `skb->data` is the Ethernet frame (MAC header
first); the kernel pulls L2 after TC. The program therefore reads and
writes full frames (offsets: MAC 0-13, IPv4 14-33, UDP 34-41).
- **`bpf_redirect_peer` re-entry**: with flags 0 the redirect re-enters
the receive path on the target (peer) side via `-EAGAIN`
(`another_round`), bypassing the `bpf_redirect` mac_header check —
that is how the synthesized reply is delivered to the client without
going through the host IP stack.
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
- `just test-e2e` — root: builds a veth/netns topology, runs two fake
TF2 backends (challenge-first dance, FE fragmentation, per-backend
query counters), attaches the program, and checks: cache serving,
per-`(ip, port)` isolation, fragmented responses, stale → pass-through,
backend-A-down with B unaffected, rate-limit bursts.
- `just test-e2e-real` — root + live srcds: same harness against two real
TF2 dedicated servers; cached replies must be byte-identical to direct
queries.

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