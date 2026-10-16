use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use a2s_protocol::{CacheEntry, Config, MAX_PAYLOAD, cache_key_unpack, stats};
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
         ttl {ttl_sec}s, max_payload {MAX_PAYLOAD} B"
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

pub fn status(pin_dir: &Path) -> Result<()> {
    let data = MapData::from_pin(pin_path(pin_dir, MAP_CONFIG)).map_err(|e| {
        Error::Bad(format!(
            "cannot open {}: {e} (is the program attached? run `a2scache attach <iface>`)",
            pin_path(pin_dir, MAP_CONFIG).display()
        ))
    })?;
    let config: Array<MapData, Config> = Map::from_map_data(data)?.try_into()?;
    let zero = 0u32;
    let cfg = config.get(&zero, 0)?;
    println!("config:");
    println!("  enabled       : {}", cfg.enabled);
    println!("  ifindex_out   : {}", cfg.ifindex_out);
    println!("  ttl           : {} s", cfg.ttl_ns / 1_000_000_000);
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

    let data = MapData::from_pin(pin_path(pin_dir, MAP_CACHE))?;
    let cache: HashMap<MapData, u64, CacheEntry> = Map::from_map_data(data)?.try_into()?;
    let now = now_ns()?;

    println!("cache entries:");
    let mut n = 0usize;
    for kv in cache.iter() {
        let (key, e) = kv?;
        let (ip, port) = cache_key_unpack(key);
        let o = ip.to_be_bytes();
        let age = |ts: u64| {
            if ts == 0 {
                "-".to_string()
            } else {
                (now.saturating_sub(ts) / 1_000_000_000).to_string()
            }
        };
        println!(
            "  {}.{}.{}.{}:{}  ch={} ch_age={}s info_len={} info_age={}s player_len={} player_age={}s",
            o[0],
            o[1],
            o[2],
            o[3],
            port,
            e.challenge,
            age(e.ts_challenge),
            e.info_len,
            age(e.ts_info),
            e.player_len,
            age(e.ts_player)
        );
        n += 1;
    }
    if n == 0 {
        println!("  (empty)");
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
