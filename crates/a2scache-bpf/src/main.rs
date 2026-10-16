//! TC ingress program: serves cached TF2 A2S responses in place.
//!
//! For every UDP datagram whose (dst_ip, dst_port) has a cache entry, the
//! program either synthesizes the reply (challenge, INFO or PLAYER
//! response) by rewriting the skb and redirecting it to egress, or passes
//! the query through (rate limited) so the backend/daemon can refresh.

#![no_std]
#![no_main]

use a2s_protocol::{
    CHALLENGE_RESP_LEN, CacheEntry, Config, INFO_BODY, INFO_REQ_LEN, INFO_REQ_LEN_CHALLENGED,
    MAGIC, MAX_PAYLOAD, NO_CHALLENGE, PLAYER_REQ_LEN, RateEntry, TYPE_CHALLENGE, TYPE_INFO_REQ,
    TYPE_PLAYER_REQ, cache_key, stats,
};
use aya_ebpf::{
    EbpfContext,
    bindings::{__be32, __sk_buff},
    helpers::{
        bpf_csum_diff, bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect_peer,
        bpf_skb_change_tail, bpf_skb_load_bytes, bpf_skb_store_bytes,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, PerCpuArray},
    programs::TcContext,
};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

const ETH_HLEN: u32 = 14;
const IP_HLEN: u32 = 20;
const UDP_HLEN: u32 = 8;
const UDP_OFFSET: u32 = ETH_HLEN + IP_HLEN;
const PAYLOAD_OFFSET: u32 = UDP_OFFSET + UDP_HLEN;

const ETH_IPV4: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const IP_DF: u16 = 0x4000;
const MILLI_TOKEN: u32 = 1000;
const NS_PER_SEC: u64 = 1_000_000_000;

// Maps are unpinned here: the userspace loader pins them (and the program)
// into the pin dir explicitly. `pinned()` (ByName) would make the aya loader
// auto-pin them into /sys/fs/bpf at load time, reusing stale pins across
// runs and ignoring our pin dir.
#[map]
static CONFIG_MAP: Array<Config> = Array::<Config>::with_max_entries(1, 0);

#[map]
static CACHE_MAP: HashMap<u64, CacheEntry> = HashMap::<u64, CacheEntry>::with_max_entries(64, 0);

#[map]
static RATE_IP_MAP: HashMap<u32, RateEntry> = HashMap::<u32, RateEntry>::with_max_entries(65536, 0);

#[map]
static RATE_GLOBAL_MAP: Array<RateEntry> = Array::<RateEntry>::with_max_entries(1, 0);

#[map]
static STATS_MAP: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(stats::COUNT as u32, 0);

#[classifier]
fn a2scache_ingress(ctx: TcContext) -> i32 {
    let cfg = match CONFIG_MAP.get(0) {
        Some(c) => *c,
        None => return TC_ACT_OK,
    };
    if cfg.enabled == 0 {
        return TC_ACT_OK;
    }

    let len = ctx.skb.len() as usize;
    if len < (PAYLOAD_OFFSET + 5) as usize {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let raw = ctx.as_ptr().cast::<__sk_buff>();

    // Direct constant-size loads: aya's `SkBuff::load_bytes` clamps the
    // size to a *re-read* of `skb->len`, which the verifier cannot
    // correlate with the `len >= PAYLOAD_OFFSET + 5` gate above, so the
    // clamped size can include zero and `bpf_skb_load_bytes` rejects it.
    // That gate makes every load below a full read anyway.
    let mut eth = [0u8; 14];
    if unsafe { bpf_skb_load_bytes(raw.cast(), 0, eth.as_mut_ptr().cast(), ETH_HLEN) } != 0 {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }
    if u16::from_be_bytes([eth[12], eth[13]]) != ETH_IPV4 {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let mut ip = [0u8; 20];
    if unsafe { bpf_skb_load_bytes(raw.cast(), ETH_HLEN, ip.as_mut_ptr().cast(), IP_HLEN) } != 0 {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }
    // No IPv4 options, not an IP fragment, UDP only.
    if ip[0] != 0x45
        || u16::from_be_bytes([ip[2], ip[3]]) < IP_HLEN as u16
        || (u16::from_be_bytes([ip[6], ip[7]]) & 0x3FFF) != 0
        || ip[9] != IPPROTO_UDP
    {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let mut udp = [0u8; 8];
    if unsafe { bpf_skb_load_bytes(raw.cast(), UDP_OFFSET, udp.as_mut_ptr().cast(), UDP_HLEN) } != 0
    {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let payload_avail = len - PAYLOAD_OFFSET as usize; // >= 5 (gate above)
    let payload_len = payload_avail as u32;
    let mut head = [0u8; 29];
    // Clamp in u64 (before the u32 truncation): a u32 min is sign-extended
    // to u64 by the backend, and the verifier cannot bound that value (it is
    // negative for large `len`), so it would see size range [0, ..] and
    // reject the load. The u64 min keeps the >= 5 lower bound intact.
    let n = payload_avail.min(29);
    if unsafe {
        bpf_skb_load_bytes(
            raw.cast(),
            PAYLOAD_OFFSET,
            head.as_mut_ptr().cast(),
            n as u32,
        )
    } != 0
    {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }
    if payload_len < 5 || [head[0], head[1], head[2], head[3]] != MAGIC {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let ty = head[4];
    // (is_player, has_challenge, challenge). A flat bool+u32 instead of
    // Option<u32>: the verifier rejects the pointer `<<= 32` codegen the
    // Option match produces when surrounding code shifts register allocation.
    let (is_player, has_ch, challenge): (bool, bool, u32) = if ty == TYPE_INFO_REQ {
        if payload_len != INFO_REQ_LEN as u32 && payload_len != INFO_REQ_LEN_CHALLENGED as u32 {
            inc_stat(stats::NON_A2S);
            return TC_ACT_OK;
        }
        if head[5..25] != *INFO_BODY {
            inc_stat(stats::NON_A2S);
            return TC_ACT_OK;
        }
        if payload_len == INFO_REQ_LEN as u32 {
            (false, false, 0)
        } else {
            (
                false,
                true,
                u32::from_le_bytes([head[25], head[26], head[27], head[28]]),
            )
        }
    } else if ty == TYPE_PLAYER_REQ {
        if payload_len != PLAYER_REQ_LEN as u32 {
            inc_stat(stats::NON_A2S);
            return TC_ACT_OK;
        }
        (
            true,
            true,
            u32::from_le_bytes([head[5], head[6], head[7], head[8]]),
        )
    } else {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    };

    let ip_dst = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]);
    let ip_src = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);

    let key = cache_key(ip_dst, dport);
    // Safe: cache entries are only ever updated (never removed) by the daemon,
    // so the borrow cannot be invalidated by a concurrent free.
    let entry = match unsafe { CACHE_MAP.get(&key) } {
        Some(e) => e,
        None => {
            inc_stat(stats::UNKNOWN_KEY);
            return rate_limited_pass(&cfg, ip_src);
        }
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let ttl = cfg.ttl_ns;
    let fresh = |ts: u64| ts != 0 && now.saturating_sub(ts) < ttl;

    // A no-challenge or 0xFFFFFFFF request asks for the challenge, for both
    // INFO and PLAYER (modern TF2 dance: FFFFFFFF first, then real challenge).
    let wants_challenge = !has_ch || challenge == NO_CHALLENGE;
    let action: Option<Action> = if wants_challenge {
        if fresh(entry.ts_challenge) {
            Some(Action::Challenge(entry.challenge))
        } else {
            None
        }
    } else if challenge == entry.challenge {
        if is_player {
            if entry.player_len != 0 && fresh(entry.ts_player) {
                Some(Action::Player)
            } else {
                inc_stat(stats::DROPPED_STALE);
                None
            }
        } else if entry.info_len != 0 && fresh(entry.ts_info) {
            Some(Action::Info)
        } else {
            inc_stat(stats::DROPPED_STALE);
            None
        }
    } else {
        inc_stat(stats::DROPPED_BAD_CHALLENGE);
        None
    };

    match action {
        None => {
            inc_stat(stats::PASS_THROUGH);
            rate_limited_pass(&cfg, ip_src)
        }
        Some(Action::Challenge(ch)) => {
            let mut resp = [0u8; 12];
            // Direct byte stores with const indices: they fold away
            // completely, avoiding slice helpers that survive codegen.
            resp[0] = MAGIC[0];
            resp[1] = MAGIC[1];
            resp[2] = MAGIC[2];
            resp[3] = MAGIC[3];
            resp[4] = TYPE_CHALLENGE;
            let chb = ch.to_le_bytes();
            resp[5] = chb[0];
            resp[6] = chb[1];
            resp[7] = chb[2];
            resp[8] = chb[3];
            inc_stat(if is_player {
                stats::SENT_CHALLENGE_PLAYER
            } else {
                stats::SENT_CHALLENGE_INFO
            });
            let args = ServeArgs {
                udp,
                payload: resp.as_ptr(),
                payload_len: CHALLENGE_RESP_LEN as u32,
            };
            serve_response(ctx, &cfg, &eth, &ip, &args)
        }
        Some(Action::Info) => {
            inc_stat(stats::SERVED_INFO);
            let args = ServeArgs {
                udp,
                payload: entry.info.as_ptr(),
                payload_len: entry.info_len as u32,
            };
            serve_response(ctx, &cfg, &eth, &ip, &args)
        }
        Some(Action::Player) => {
            inc_stat(stats::SERVED_PLAYER);
            let args = ServeArgs {
                udp,
                payload: entry.player.as_ptr(),
                payload_len: entry.player_len as u32,
            };
            serve_response(ctx, &cfg, &eth, &ip, &args)
        }
    }
}

enum Action {
    Challenge(u32),
    Info,
    Player,
}

fn inc_stat(idx: u32) {
    if let Some(slot) = STATS_MAP.get_ptr_mut(idx) {
        unsafe {
            *slot += 1;
        }
    }
}

fn rate_entry_ptr(map: &HashMap<u32, RateEntry>, key: u32) -> Option<*mut RateEntry> {
    if let Some(p) = map.get_ptr_mut(&key) {
        return Some(p);
    }
    let _ = map.insert(key, RateEntry::default(), 0);
    map.get_ptr_mut(&key)
}

fn rate_limited_pass(cfg: &Config, src_ip: u32) -> i32 {
    let now = unsafe { bpf_ktime_get_ns() };
    let ip_next = next_tokens(
        rate_entry_ptr(&RATE_IP_MAP, src_ip),
        cfg.per_ip_capacity,
        cfg.per_ip_refill_per_s,
        now,
    );
    let g_next = next_tokens(
        RATE_GLOBAL_MAP.get_ptr_mut(0),
        cfg.global_capacity,
        cfg.global_refill_per_s,
        now,
    );
    match (ip_next, g_next) {
        (Some(ipn), Some(gn)) => {
            if let Some(p) = RATE_IP_MAP.get_ptr_mut(&src_ip) {
                unsafe {
                    (*p).tokens = ipn;
                    (*p).last_ns = now;
                }
            }
            if let Some(p) = RATE_GLOBAL_MAP.get_ptr_mut(0) {
                unsafe {
                    (*p).tokens = gn;
                    (*p).last_ns = now;
                }
            }
            TC_ACT_OK
        }
        (None, _) => {
            inc_stat(stats::DROPPED_RATE_IP);
            TC_ACT_SHOT
        }
        (Some(_), None) => {
            inc_stat(stats::DROPPED_RATE_GLOBAL);
            TC_ACT_SHOT
        }
    }
}

fn next_tokens(
    entry: Option<*mut RateEntry>,
    capacity: u32,
    refill_per_s: u32,
    now: u64,
) -> Option<u32> {
    let e = entry?;
    let e = unsafe { &*e };
    let elapsed = now.saturating_sub(e.last_ns);
    let refill = (elapsed * refill_per_s as u64) / NS_PER_SEC;
    let tokens = (e.tokens as u64 + refill).min(capacity as u64) as u32;
    if tokens >= MILLI_TOKEN {
        Some(tokens - MILLI_TOKEN)
    } else {
        None
    }
}

/// Trailing arguments of `serve_response`, passed as one pointer.
///
/// The BPF calling convention has only five register arguments; anything
/// beyond that is passed on the caller's stack via BPF_REG_PARAMS (r11)
/// instructions. Kernels older than ~7.1 (the r11 stack-arg verifier
/// support landed in mainline 2026-05) reject those instructions with
/// "R11 is invalid", so no BPF function in this program may take more
/// than five register arguments.
#[repr(C)]
struct ServeArgs {
    udp: [u8; 8],
    payload: *const u8,
    payload_len: u32,
}

/// Never inlined: keeps each BPF subprogram small so register pressure
/// stays low.
#[inline(never)]
fn serve_response(
    ctx: TcContext,
    cfg: &Config,
    eth: &[u8; 14],
    ip: &[u8; 20],
    args: *const ServeArgs,
) -> i32 {
    let args = unsafe { &*args };
    let udp = &args.udp;
    let payload = args.payload;
    let payload_len = args.payload_len;
    // The `> MAX_PAYLOAD` half of this guard is a compile-time constant,
    // which the verifier can use to bound the map-value accesses below
    // (payloads live in 2048-byte regions inside the 4144-byte entry);
    // `cfg.max_payload` alone is a runtime value it cannot prove against.
    // The `== 0` half proves a non-zero copy size: callers never serve an
    // empty body, and `bpf_skb_store_bytes` rejects ranges that include 0.
    if cfg.ifindex_out == 0
        || payload_len == 0
        || payload_len > cfg.max_payload
        || payload_len > MAX_PAYLOAD as u32
    {
        inc_stat(stats::DROPPED_REWRITE_GUARD);
        return TC_ACT_OK;
    }

    let raw = ctx.as_ptr().cast::<__sk_buff>();
    let frame_len = PAYLOAD_OFFSET + payload_len;
    if unsafe { bpf_skb_change_tail(raw, frame_len, 0) } != 0 {
        inc_stat(stats::DROPPED_REWRITE_TAIL);
        return TC_ACT_OK;
    }

    let ip_src = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    let ip_dst = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]);
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);

    let mut hdr = [0u8; 42];
    // Direct byte stores with const indices: they fold away completely,
    // avoiding slice helpers that survive codegen.
    hdr[0] = eth[6];
    hdr[1] = eth[7];
    hdr[2] = eth[8];
    hdr[3] = eth[9];
    hdr[4] = eth[10];
    hdr[5] = eth[11];
    if cfg.backend_mac != [0u8; 6] {
        hdr[6] = cfg.backend_mac[0];
        hdr[7] = cfg.backend_mac[1];
        hdr[8] = cfg.backend_mac[2];
        hdr[9] = cfg.backend_mac[3];
        hdr[10] = cfg.backend_mac[4];
        hdr[11] = cfg.backend_mac[5];
    } else {
        hdr[6] = eth[0];
        hdr[7] = eth[1];
        hdr[8] = eth[2];
        hdr[9] = eth[3];
        hdr[10] = eth[4];
        hdr[11] = eth[5];
    }
    // Frame layout: MAC[0..14) EtherType[12..14) IP[14..34) UDP[34..42)
    // payload[42..). The IP/UDP headers start at the standard offsets; an
    // off-by-two here puts the IP version nibble where the EtherType belongs
    // (0x4500) and the receiver drops the frame at L2.
    hdr[12] = 0x08;
    hdr[13] = 0x00;
    hdr[14] = 0x45;
    // u32 to_be_bytes of a small value is [0, 0, hi, lo]; the 16-bit field
    // is the low two bytes.
    let t = (IP_HLEN + UDP_HLEN + payload_len).to_be_bytes();
    hdr[16] = t[2];
    hdr[17] = t[3];
    let t = ((unsafe { bpf_get_prandom_u32() }) as u16).to_be_bytes();
    hdr[18] = t[0];
    hdr[19] = t[1];
    let t = IP_DF.to_be_bytes();
    hdr[20] = t[0];
    hdr[21] = t[1];
    hdr[22] = 64;
    hdr[23] = IPPROTO_UDP;
    // Response addressing: swap the request's src/dst (IP and UDP ports).
    // A reply goes client<-server, the request was client->server.
    // hdr[26..30) is the IP *source* field, hdr[30..34) the *destination*.
    let t = ip_dst.to_be_bytes(); // response src = request dst (server)
    hdr[26] = t[0];
    hdr[27] = t[1];
    hdr[28] = t[2];
    hdr[29] = t[3];
    let t = ip_src.to_be_bytes(); // response dst = request src (client)
    hdr[30] = t[0];
    hdr[31] = t[1];
    hdr[32] = t[2];
    hdr[33] = t[3];
    let t = dport.to_be_bytes(); // response sport = server port
    hdr[34] = t[0];
    hdr[35] = t[1];
    let t = sport.to_be_bytes(); // response dport = client ephemeral
    hdr[36] = t[0];
    hdr[37] = t[1];
    let t = (UDP_HLEN + payload_len).to_be_bytes();
    hdr[38] = t[2];
    hdr[39] = t[3];

    // bpf_csum_diff needs 4-byte aligned sizes; pad the checksummed view.
    // The `.min` is a no-op at runtime (alignment keeps the result at
    // <= MAX_PAYLOAD for any `payload_len` <= MAX_PAYLOAD), but it pins the
    // verifier's upper bound at 2048: without it the tracked range tops out
    // at 2051, which pushes the player payload (entry offset 2096) past the
    // end of the 4144-byte map value.
    let csum_len = ((payload_len + 3) & !3u32).min(MAX_PAYLOAD as u32);
    // UDP pseudo-header: response src ip (server), response dst ip (client),
    // zero, proto, udp length.
    let mut pseudo = [0u8; 12];
    let t = ip_dst.to_be_bytes();
    pseudo[0] = t[0];
    pseudo[1] = t[1];
    pseudo[2] = t[2];
    pseudo[3] = t[3];
    let t = ip_src.to_be_bytes();
    pseudo[4] = t[0];
    pseudo[5] = t[1];
    pseudo[6] = t[2];
    pseudo[7] = t[3];
    pseudo[9] = IPPROTO_UDP;
    let t = (UDP_HLEN + payload_len).to_be_bytes();
    pseudo[10] = t[2];
    pseudo[11] = t[3];

    let s = unsafe {
        bpf_csum_diff(
            pseudo.as_mut_ptr().cast(),
            0,
            pseudo.as_mut_ptr().cast(),
            12,
            0,
        )
    } as u32;
    let s = unsafe {
        bpf_csum_diff(
            hdr[34..42].as_mut_ptr().cast(),
            0,
            hdr[34..42].as_mut_ptr().cast(),
            8,
            s,
        )
    } as u32;
    let s = unsafe {
        bpf_csum_diff(
            payload as *mut __be32,
            0,
            payload as *mut __be32,
            csum_len,
            s,
        )
    } as u32;
    // `csum_partial` (behind bpf_csum_diff) sums *native-endian* 16-bit
    // words, so the folded result is a native u16 value. The kernel stores
    // such values natively (`ip->check = ip_fast_csum(...)`); on little
    // endian that lands the byte-swapped (network-order) bytes on the wire.
    // A `to_be_bytes()` store would double-swap them, so use native bytes.
    let udp_check = csum_fold(s);
    let t = (if udp_check == 0 { 0xFFFFu16 } else { udp_check }).to_ne_bytes();
    hdr[40] = t[0];
    hdr[41] = t[1];

    let ip_check = csum_fold(unsafe {
        bpf_csum_diff(
            hdr[14..34].as_mut_ptr().cast(),
            0,
            hdr[14..34].as_mut_ptr().cast(),
            20,
            0,
        )
    } as u32);
    let t = (if ip_check == 0 { 0xFFFFu16 } else { ip_check }).to_ne_bytes();
    hdr[24] = t[0];
    hdr[25] = t[1];

    if ctx.skb.store(0, &hdr, 0).is_err() {
        inc_stat(stats::DROPPED_REWRITE_HDR);
        return TC_ACT_SHOT;
    }
    if unsafe { bpf_skb_store_bytes(raw, PAYLOAD_OFFSET, payload.cast(), payload_len, 0) } != 0 {
        inc_stat(stats::DROPPED_REWRITE_PAYLOAD);
        return TC_ACT_SHOT;
    }

    // bpf_redirect_peer delivers the rewritten frame directly to the veth
    // peer's receive path (BPF_F_PEER): the kernel re-enters receive
    // processing on the peer device, re-running post-TC L2 handling. Plain
    // bpf_redirect cannot be used here because the peer-side receive state
    // (mac_header == network_header == data, i.e. L2 not yet pulled) fails
    // __bpf_redirect_common's "link layer header is carried" check.
    //
    // The helper returns the verdict: TC_ACT_REDIRECT on success,
    // TC_ACT_SHOT on error. The program must itself return TC_ACT_REDIRECT
    // for the kernel to act.
    // bpf_redirect_peer with flags 0 cannot fail: it either records the
    // peer target and returns the kernel's TC_ACT_REDIRECT verdict, or
    // returns TC_ACT_SHOT (2, stable across kernel versions).
    //
    // TC_ACT_REDIRECT was renumbered in newer kernels (0x20000000 on
    // 6.x, 7 on 7.x), so the verdict is passed through verbatim instead
    // of being re-emitted from a local constant; only the SHOT case is
    // distinguishable and needs handling.
    let ret = unsafe { bpf_redirect_peer(cfg.ifindex_out, 0) };
    if ret == i64::from(TC_ACT_SHOT) {
        inc_stat(stats::DROPPED_REWRITE_REDIRECT);
        return TC_ACT_SHOT;
    }
    ret as i32
}

fn csum_fold(c: u32) -> u16 {
    let c = c.wrapping_add(c >> 16);
    let c = c.wrapping_add(c >> 16);
    !((c & 0xFFFF) as u16)
}

#[panic_handler]
const fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
