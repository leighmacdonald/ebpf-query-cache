use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use a2s_protocol::{
    CACHE_MAX_ENTRIES, CacheEntry, Config, MAX_PAYLOAD, REDIRECT_MODE_PEER, REDIRECT_MODE_XMIT,
    cache_key_unpack, info_banner_name, stats,
};
use aya::EbpfLoader;
use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray};
use aya::programs::tc;
use aya::programs::{SchedClassifier, TcAttachType};

use crate::{Error, Result};

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/a2scache";
pub const DEFAULT_TTL_SEC: u64 = 30;

pub const PROG_NAME: &str = "a2scache_ingress";
pub const MAP_CONFIG: &str = "CONFIG_MAP";
pub const MAP_CACHE: &str = "CACHE_MAP";
pub const MAP_RATE_IP: &str = "RATE_IP_MAP";
pub const MAP_RATE_GLOBAL: &str = "RATE_GLOBAL_MAP";
pub const MAP_STATS: &str = "STATS_MAP";

const MAPS: &[&str] = &[
    MAP_CONFIG,
    MAP_CACHE,
    MAP_RATE_IP,
    MAP_RATE_GLOBAL,
    MAP_STATS,
];

/// All pin names, program first.
const PINS: &[&str] = &[
    PROG_NAME,
    MAP_CONFIG,
    MAP_CACHE,
    MAP_RATE_IP,
    MAP_RATE_GLOBAL,
    MAP_STATS,
];

pub const STATS_NAMES: [&str; stats::COUNT] = [
    "pass_through",
    "served_info",
    "served_player",
    "sent_challenge_info",
    "sent_challenge_player",
    "dropped_rate_ip",
    "dropped_rate_global",
    "dropped_stale",
    "dropped_bad_challenge",
    "dropped_too_large",
    "dropped_rewrite",
    "non_a2s",
    "unknown_key",
    "dropped_rewrite_guard",
    "dropped_rewrite_tail",
    "dropped_rewrite_hdr",
    "dropped_rewrite_payload",
    "dropped_rewrite_redirect",
];

pub fn pin_path(pin_dir: &Path, name: &str) -> PathBuf {
    pin_dir.join(name)
}

fn iface_index(iface: &str) -> Result<u32> {
    let c = CString::new(iface)?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        Err(Error::Bad(format!("no such interface: {iface}")))
    } else {
        Ok(idx)
    }
}

fn iface_mac(iface: &str) -> Result<[u8; 6]> {
    let p = format!("/sys/class/net/{iface}/address");
    let s = fs::read_to_string(&p).map_err(|e| Error::Bad(format!("read {p}: {e}")))?;
    parse_mac(s.trim())
}

/// Parse a `aa:bb:cc:dd:ee:ff` MAC address (case-insensitive hex).
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(':');
    for o in mac.iter_mut() {
        let h = parts
            .next()
            .ok_or_else(|| Error::Bad(format!("bad MAC address `{s}`")))?;
        *o = u8::from_str_radix(h, 16).map_err(|_| Error::Bad(format!("bad MAC address `{s}`")))?;
    }
    if parts.next().is_some() {
        return Err(Error::Bad(format!("bad MAC address `{s}`")));
    }
    Ok(mac)
}

pub(crate) fn now_ns() -> Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if r != 0 {
        return Err(Error::Bad("clock_gettime failed".into()));
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// Reply delivery mode for an interface, from its topology.
///
/// A veth (or netkit) pair has an in-kernel peer reachable via
/// `bpf_redirect_peer`, which delivers synthesized replies across the pair
/// to the peer's receive path. Sysfs exposes the peer's ifindex in
/// `/sys/class/net/<iface>/iflink`; devices without a peer (real NICs,
/// bridges) report their *own* ifindex there (`dev_get_iflink` falls back
/// to it), so the two values differ exactly when a peer exists. This
/// matters because without a peer `skb_do_redirect()` cannot resolve
/// `skb_get_peer_dev()` (no `ndo_get_peer_dev`) and silently kfree()s the
/// frame, so those devices need XMIT mode (`bpf_redirect` on the same
/// ifindex transmits the frame on the interface's egress, out to the wire).
fn redirect_mode_for(iface: &str) -> u32 {
    let read = |name: &str| {
        fs::read_to_string(format!("/sys/class/net/{iface}/{name}"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    };
    match (read("ifindex"), read("iflink")) {
        (Some(idx), Some(link)) if link != idx => REDIRECT_MODE_PEER,
        _ => REDIRECT_MODE_XMIT,
    }
}

/// Human-readable name of a reply delivery mode.
pub fn redirect_mode_name(mode: u32) -> &'static str {
    match mode {
        REDIRECT_MODE_XMIT => "xmit (bpf_redirect to egress)",
        REDIRECT_MODE_PEER => "peer (bpf_redirect_peer to veth peer)",
        _ => "unknown",
    }
}

pub fn attach(elf: &[u8], iface: &str, pin_dir: &Path, ttl_sec: u64) -> Result<()> {
    fs::create_dir_all(pin_dir)?;

    // Idempotent attach: drop any pins from a previous run.
    for name in PINS {
        let p = pin_path(pin_dir, name);
        if p.exists() {
            fs::remove_file(&p)?;
            eprintln!("removed stale pin {p:?}");
        }
    }

    match tc::qdisc_add_clsact(iface) {
        Ok(()) => eprintln!("added clsact qdisc on {iface}"),
        // aya surfaces an existing clsact qdisc as a netlink EEXIST, not as
        // TcError::AlreadyAttached.
        Err(tc::TcError::NetlinkError(ne)) if ne.raw_os_error() == Some(libc::EEXIST) => {
            eprintln!("clsact qdisc already present on {iface}");
        }
        Err(e) => return Err(Error::Tc(e)),
    }

    // Drop any filter left by a previous attach so re-attach does not stack.
    match tc::qdisc_detach_program(iface, TcAttachType::Ingress, PROG_NAME) {
        Ok(()) => eprintln!("removed stale filter on {iface}"),
        // The io error's Display is just the program name; match the kind.
        Err(tc::TcError::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::Tc(e)),
    }

    let mut bpf = EbpfLoader::new().load(elf)?;

    let prog: &mut SchedClassifier = bpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| Error::Bad(format!("program {PROG_NAME} not in ELF")))?
        .try_into()?;
    prog.load()?;
    // Attach via netlink (classic clsact filter), not TCX (aya's default on
    // kernel >= 6.6): a TCX attachment is a bpf_link that our netlink-based
    // detach/clean cannot find or remove, so it would leak and stack on every
    // re-attach. A netlink filter keeps the program alive in-kernel after
    // this process exits, with the pins keeping the maps reachable.
    let link_id = prog.attach_with_options(
        iface,
        TcAttachType::Ingress,
        tc::TcAttachOptions::Netlink(tc::NlOptions::default()),
    )?;
    prog.pin(pin_path(pin_dir, PROG_NAME))?;
    // Take the attachment out of aya's tracked links: aya detaches every
    // tracked link when the program is dropped, which would remove the filter
    // when this process exits. The netlink link holds no kernel resources
    // (just ifindex/attach-type/priority/handle), so forgetting the wrapper
    // leaks only a few ints and leaves the filter in place.
    let link = prog.take_link(link_id)?;
    std::mem::forget(link);

    for name in MAPS {
        bpf.map(name)
            .ok_or_else(|| Error::Bad(format!("map {name} not in ELF")))?
            .pin(pin_path(pin_dir, name))?;
    }

    let cfg = Config {
        enabled: 1,
        ifindex_out: iface_index(iface)?,
        ttl_ns: ttl_sec.saturating_mul(1_000_000_000),
        redirect_mode: redirect_mode_for(iface),
        backend_mac: iface_mac(iface)?,
        ..Config::default()
    };
    let mut array: Array<&mut MapData, Config> = bpf
        .map_mut(MAP_CONFIG)
        .ok_or_else(|| Error::Bad(format!("map {MAP_CONFIG} not in ELF")))?
        .try_into()?;
    array.set(0, cfg, 0)?;

    println!(
        "attached {PROG_NAME} on {iface} (ingress); pins in {pin_dir:?}; \
         ttl {ttl_sec}s, cache capacity {CACHE_MAX_ENTRIES} instances, \
         max_payload {MAX_PAYLOAD} B, redirect_mode={}",
        redirect_mode_name(cfg.redirect_mode)
    );
    println!("run `a2scache serve --config <file>` to populate the cache");
    Ok(())
}

pub fn detach(iface: &str) -> Result<()> {
    match tc::qdisc_detach_program(iface, TcAttachType::Ingress, PROG_NAME) {
        Ok(()) => {
            println!("detached {PROG_NAME} from {iface}");
            Ok(())
        }
        // The io error's Display is just the program name; match the kind.
        Err(tc::TcError::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("nothing to detach on {iface}");
            Ok(())
        }
        Err(e) => Err(Error::Tc(e)),
    }
}

pub fn clean(iface: &str, pin_dir: &Path) -> Result<()> {
    detach(iface)?;
    for name in PINS {
        let p = pin_path(pin_dir, name);
        if p.exists() {
            fs::remove_file(&p)?;
            println!("removed pin {p:?}");
        }
    }
    if pin_dir.exists() {
        fs::remove_dir(pin_dir)?;
        println!("removed {pin_dir:?}");
    }
    Ok(())
}

fn truncate_40(s: &str) -> String {
    s.chars().take(40).collect()
}

/// JSON string literal with escaping for `\`, `"` and control characters
/// (server names come from arbitrary TF2 backends, so no charset is assumed).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One rendered `CACHE_MAP` entry for `status`. Ages are seconds since the
/// last refresh; `None` means the half has never been populated.
#[derive(Clone, Debug)]
struct StatusEntry {
    ip: u32,
    port: u16,
    /// A2S server name parsed from the cached INFO payload.
    name: Option<String>,
    challenge: u32,
    ch_age: Option<u64>,
    info_len: u16,
    info_age: Option<u64>,
    player_len: u16,
    player_age: Option<u64>,
    /// Effective per-instance TTL (ns/1e9) recorded inside the entry; 0
    /// means the entry has never been refreshed (global TTL applies).
    ttl_secs: u64,
}

pub fn status(pin_dir: &Path, json: bool) -> Result<()> {
    let data = MapData::from_pin(pin_path(pin_dir, MAP_CONFIG)).map_err(|e| {
        Error::Bad(format!(
            "cannot open {}: {e} (is the program attached? run `a2scache attach <iface>`)",
            pin_path(pin_dir, MAP_CONFIG).display()
        ))
    })?;
    let config: Array<MapData, Config> = Map::from_map_data(data)?.try_into()?;
    let zero = 0u32;
    let cfg = config.get(&zero, 0)?;

    let data = MapData::from_pin(pin_path(pin_dir, MAP_CACHE))?;
    let cache: HashMap<MapData, u64, CacheEntry> = Map::from_map_data(data)?.try_into()?;
    let now = now_ns()?;

    let mut entries = Vec::<StatusEntry>::new();
    for kv in cache.iter() {
        let (key, e) = kv?;
        let (ip, port) = cache_key_unpack(key);
        let age = |ts: u64| {
            if ts == 0 {
                None
            } else {
                Some(now.saturating_sub(ts) / 1_000_000_000)
            }
        };
        let name = info_banner_name(&e.info[..e.info_len as usize]).map(|s| s.to_owned());
        entries.push(StatusEntry {
            ip,
            port,
            name,
            challenge: e.challenge,
            ch_age: age(e.ts_challenge),
            info_len: e.info_len,
            info_age: age(e.ts_info),
            player_len: e.player_len,
            player_age: age(e.ts_player),
            ttl_secs: e.ttl_ns / 1_000_000_000,
        });
    }
    // Stable report order regardless of hash-table iteration.
    entries.sort_by_key(|e| u64::from(e.ip) << 16 | u64::from(e.port));

    if json {
        let o = |v: Option<u64>| match v {
            Some(v) => v.to_string(),
            None => "null".to_string(),
        };
        let items = entries
            .iter()
            .map(|e| {
                let oct = e.ip.to_be_bytes();
                format!(
                    "    {{\"ip\": \"{}.{}.{}.{}\", \"port\": {}, \"name\": {}, \
                     \"challenge\": {}, \"challenge_age_s\": {}, \
                     \"info_len\": {}, \"info_age_s\": {}, \
                     \"player_len\": {}, \"player_age_s\": {}, \"ttl_s\": {}}}",
                    oct[0],
                    oct[1],
                    oct[2],
                    oct[3],
                    e.port,
                    match &e.name {
                        Some(n) => json_str(n),
                        None => "null".to_string(),
                    },
                    e.challenge,
                    o(e.ch_age),
                    e.info_len,
                    o(e.info_age),
                    e.player_len,
                    o(e.player_age),
                    e.ttl_secs
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        println!("{{\"capacity\": {CACHE_MAX_ENTRIES}, \"entries\": [");
        if !items.is_empty() {
            println!("{items}");
        }
        println!("], \"count\": {}}}", entries.len());
    } else {
        println!("config:");
        println!("  enabled       : {}", cfg.enabled);
        println!("  ifindex_out   : {}", cfg.ifindex_out);
        println!(
            "  redirect_mode : {}",
            redirect_mode_name(cfg.redirect_mode)
        );
        println!(
            "  ttl           : {} s (instances may override per entry)",
            cfg.ttl_ns / 1_000_000_000
        );
        println!("  max_payload   : {}", cfg.max_payload);
        println!(
            "  rate per_ip : cap {} milli-tok, refill {}/s",
            cfg.per_ip_capacity, cfg.per_ip_refill_per_s
        );
        println!(
            "  rate global : cap {} milli-tok, refill {}/s",
            cfg.global_capacity, cfg.global_refill_per_s
        );
        println!(
            "  backend_mac   : {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            cfg.backend_mac[0],
            cfg.backend_mac[1],
            cfg.backend_mac[2],
            cfg.backend_mac[3],
            cfg.backend_mac[4],
            cfg.backend_mac[5]
        );

        println!(
            "cache entries: {} / {CACHE_MAX_ENTRIES} ({:.1}% full)",
            entries.len(),
            100.0 * entries.len() as f64 / f64::from(CACHE_MAX_ENTRIES)
        );
        for e in &entries {
            let oct = e.ip.to_be_bytes();
            let age = |v: Option<u64>| match v {
                Some(v) => format!("{v}s"),
                None => "-".to_string(),
            };
            let name = match &e.name {
                Some(n) => truncate_40(n),
                None => "-".to_string(),
            };
            println!(
                "  {}.{}.{}.{}:{}  info_len={} info_age={} player_len={} player_age={} \
                 ch={} ch_age={} ttl={}s name={name}",
                oct[0],
                oct[1],
                oct[2],
                oct[3],
                e.port,
                e.info_len,
                age(e.info_age),
                e.player_len,
                age(e.player_age),
                e.challenge,
                age(e.ch_age),
                e.ttl_secs
            );
        }
        if entries.is_empty() {
            println!("  (empty)");
        }
    }
    Ok(())
}

pub fn stats(pin_dir: &Path) -> Result<Vec<u64>> {
    let data = MapData::from_pin(pin_path(pin_dir, MAP_STATS)).map_err(|e| {
        Error::Bad(format!(
            "cannot open {}: {e} (is the program attached? run `a2scache attach <iface>`)",
            pin_path(pin_dir, MAP_STATS).display()
        ))
    })?;
    let map: PerCpuArray<MapData, u64> = Map::from_map_data(data)?.try_into()?;
    let mut totals = vec![0u64; stats::COUNT];
    let n = map.len();
    for idx in 0..n {
        let values = map.get(&idx, 0)?;
        totals[idx as usize] = values.iter().sum();
    }
    Ok(totals)
}
