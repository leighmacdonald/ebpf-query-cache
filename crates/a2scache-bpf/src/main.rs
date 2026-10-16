//! TC ingress program: serves cached TF2 A2S responses in place.
//!
//! For every UDP datagram whose (dst_ip, dst_port) has a cache entry, the
//! program either synthesizes the reply (challenge, INFO or PLAYER
//! response) by rewriting the skb and redirecting it to egress, or passes
//! the query through (rate limited) so the backend/daemon can refresh.

#![no_std]
#![no_main]

use a2s_protocol::{
    cache_key, stats, CacheEntry, Config, RateEntry, CHALLENGE_RESP_LEN, INFO_BODY, INFO_REQ_LEN,
    INFO_REQ_LEN_CHALLENGED, MAGIC, NO_CHALLENGE, PLAYER_REQ_LEN, TYPE_CHALLENGE, TYPE_INFO_REQ,
    TYPE_PLAYER_REQ,
};
use aya_ebpf::{
    bindings::{__be32, __sk_buff},
    helpers::{
        bpf_csum_diff, bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect, bpf_skb_change_tail,
        bpf_skb_store_bytes,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, PerCpuArray},
    programs::TcContext,
    EbpfContext,
};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_REDIRECT: i32 = 33;

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

#[map]
static CONFIG_MAP: Array<Config> = Array::<Config>::pinned(1, 0);

#[map]
static CACHE_MAP: HashMap<u64, CacheEntry> = HashMap::<u64, CacheEntry>::pinned(64, 0);

#[map]
static RATE_IP_MAP: HashMap<u32, RateEntry> = HashMap::<u32, RateEntry>::pinned(65536, 0);

#[map]
static RATE_GLOBAL_MAP: Array<RateEntry> = Array::<RateEntry>::pinned(1, 0);

#[map]
static STATS_MAP: PerCpuArray<u64> = PerCpuArray::<u64>::pinned(stats::COUNT as u32, 0);

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

    let mut eth = [0u8; 14];
    if ctx.skb.load_bytes(0, &mut eth).is_err() {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }
    if u16::from_be_bytes([eth[12], eth[13]]) != ETH_IPV4 {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let mut ip = [0u8; 20];
    if ctx.skb.load_bytes(14, &mut ip).is_err() {
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
    if ctx.skb.load_bytes(UDP_OFFSET as usize, &mut udp).is_err() {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let payload_len = (len - PAYLOAD_OFFSET as usize) as u32;
    let mut head = [0u8; 29];
    let n = match ctx.skb.load_bytes(PAYLOAD_OFFSET as usize, &mut head) {
        Ok(n) => n,
        Err(_) => {
            inc_stat(stats::NON_A2S);
            return TC_ACT_OK;
        }
    };
    if n < 5 || [head[0], head[1], head[2], head[3]] != MAGIC {
        inc_stat(stats::NON_A2S);
        return TC_ACT_OK;
    }

    let ty = head[4];
    let (is_player, challenge): (bool, Option<u32>) = if ty == TYPE_INFO_REQ {
        if payload_len != INFO_REQ_LEN as u32 && payload_len != INFO_REQ_LEN_CHALLENGED as u32 {
            inc_stat(stats::NON_A2S);
            return TC_ACT_OK;
        }
        if head[5..25] != *INFO_BODY {
            inc_stat(stats::NON_A2S);
            return TC_ACT_OK;
        }
        if payload_len == INFO_REQ_LEN as u32 {
            (false, None)
        } else {
            (
                false,
                Some(u32::from_le_bytes([head[25], head[26], head[27], head[28]])),
            )
        }
    } else if ty == TYPE_PLAYER_REQ {
        if payload_len != PLAYER_REQ_LEN as u32 {
            inc_stat(stats::NON_A2S);
            return TC_ACT_OK;
        }
        (
            true,
            Some(u32::from_le_bytes([head[5], head[6], head[7], head[8]])),
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
    let action: Option<Action> = match challenge {
        None | Some(NO_CHALLENGE) => {
            if fresh(entry.ts_challenge) {
                Some(Action::Challenge(entry.challenge))
            } else {
                None
            }
        }
        Some(c) => {
            if c == entry.challenge {
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
            }
        }
    };

    match action {
        None => {
            inc_stat(stats::PASS_THROUGH);
            rate_limited_pass(&cfg, ip_src)
        }
        Some(Action::Challenge(ch)) => {
            let mut resp = [0u8; 12];
            // Direct byte stores (not copy_from_slice / slice helpers): any
            // slice-length check or fat-pointer dance that survives codegen
            // becomes an outlined trap or an R11-relative spill that the
            // kernel verifier rejects. Const indices fold away completely.
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
            serve_response(
                ctx,
                &cfg,
                &eth,
                &ip,
                &udp,
                resp.as_ptr(),
                CHALLENGE_RESP_LEN as u32,
            )
        }
        Some(Action::Info) => {
            inc_stat(stats::SERVED_INFO);
            serve_response(
                ctx,
                &cfg,
                &eth,
                &ip,
                &udp,
                entry.info.as_ptr(),
                entry.info_len as u32,
            )
        }
        Some(Action::Player) => {
            inc_stat(stats::SERVED_PLAYER);
            serve_response(
                ctx,
                &cfg,
                &eth,
                &ip,
                &udp,
                entry.player.as_ptr(),
                entry.player_len as u32,
            )
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

/// Never inlined: keeps each BPF subprogram small so register pressure
/// stays low (LLVM's BPF backend otherwise spills via the reserved R11,
/// which the kernel verifier rejects as "R11 is invalid").
#[inline(never)]
fn serve_response(
    ctx: TcContext,
    cfg: &Config,
    eth: &[u8; 14],
    ip: &[u8; 20],
    udp: &[u8; 8],
    payload: *const u8,
    payload_len: u32,
) -> i32 {
    if cfg.ifindex_out == 0 || payload_len as usize > cfg.max_payload as usize {
        inc_stat(stats::DROPPED_REWRITE);
        return TC_ACT_OK;
    }

    let raw = ctx.as_ptr().cast::<__sk_buff>();
    let frame_len = PAYLOAD_OFFSET + payload_len;
    if unsafe { bpf_skb_change_tail(raw, frame_len, 0) } != 0 {
        inc_stat(stats::DROPPED_REWRITE);
        return TC_ACT_OK;
    }

    let ip_src = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    let ip_dst = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]);
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);

    let mut hdr = [0u8; 42];
    // Direct byte stores (not copy_from_slice / slice helpers): any
    // slice-length check or fat-pointer dance that survives codegen becomes
    // an outlined trap or an R11-relative spill that the kernel verifier
    // rejects. Const indices fold away completely.
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
    hdr[12] = 0x45;
    let t = (IP_HLEN + UDP_HLEN + payload_len).to_be_bytes();
    hdr[14] = t[0];
    hdr[15] = t[1];
    let t = ((unsafe { bpf_get_prandom_u32() }) as u16).to_be_bytes();
    hdr[16] = t[0];
    hdr[17] = t[1];
    let t = IP_DF.to_be_bytes();
    hdr[18] = t[0];
    hdr[19] = t[1];
    hdr[20] = 64;
    hdr[21] = IPPROTO_UDP;
    let t = ip_dst.to_be_bytes();
    hdr[24] = t[0];
    hdr[25] = t[1];
    hdr[26] = t[2];
    hdr[27] = t[3];
    let t = ip_src.to_be_bytes();
    hdr[28] = t[0];
    hdr[29] = t[1];
    hdr[30] = t[2];
    hdr[31] = t[3];
    let t = dport.to_be_bytes();
    hdr[32] = t[0];
    hdr[33] = t[1];
    let t = sport.to_be_bytes();
    hdr[34] = t[0];
    hdr[35] = t[1];
    let t = (UDP_HLEN + payload_len).to_be_bytes();
    hdr[36] = t[0];
    hdr[37] = t[1];

    // bpf_csum_diff needs 4-byte aligned sizes; pad the checksummed view.
    let csum_len = (payload_len + 3) & !3u32;
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
    pseudo[10] = t[0];
    pseudo[11] = t[1];

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
            hdr[32..40].as_mut_ptr().cast(),
            0,
            hdr[32..40].as_mut_ptr().cast(),
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
    let udp_check = csum_fold(s);
    let t = (if udp_check == 0 { 0xFFFFu16 } else { udp_check }).to_be_bytes();
    hdr[38] = t[0];
    hdr[39] = t[1];

    let ip_check = csum_fold(unsafe {
        bpf_csum_diff(
            hdr[12..32].as_mut_ptr().cast(),
            0,
            hdr[12..32].as_mut_ptr().cast(),
            20,
            0,
        )
    } as u32);
    let t = (if ip_check == 0 { 0xFFFFu16 } else { ip_check }).to_be_bytes();
    hdr[22] = t[0];
    hdr[23] = t[1];

    if ctx.skb.store(0, &hdr, 0).is_err() {
        inc_stat(stats::DROPPED_REWRITE);
        return TC_ACT_SHOT;
    }
    if unsafe { bpf_skb_store_bytes(raw, PAYLOAD_OFFSET, payload.cast(), payload_len, 0) } != 0 {
        inc_stat(stats::DROPPED_REWRITE);
        return TC_ACT_SHOT;
    }

    if unsafe { bpf_redirect(cfg.ifindex_out, 0) } != 0 {
        inc_stat(stats::DROPPED_REWRITE);
        return TC_ACT_SHOT;
    }
    TC_ACT_REDIRECT
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
