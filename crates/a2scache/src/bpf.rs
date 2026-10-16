use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use a2s_protocol::{cache_key_unpack, stats, CacheEntry, Config, MAX_PAYLOAD};
use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray};
use aya::programs::tc;
use aya::programs::{SchedClassifier, TcAttachType};
use aya::EbpfLoader;

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
        Err(tc::TcError::AlreadyAttached) => eprintln!("clsact qdisc already present on {iface}"),
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("exist") {
                return Err(Error::Tc(e));
            }
            eprintln!("clsact qdisc already present on {iface}");
        }
    }

    let mut bpf = EbpfLoader::new().load(elf)?;

    let prog: &mut SchedClassifier = bpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| Error::Bad(format!("program {PROG_NAME} not in ELF")))?
        .try_into()?;
    prog.load()?;
    prog.attach(iface, TcAttachType::Ingress)?;
    prog.pin(pin_path(pin_dir, PROG_NAME))?;

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
        Err(e) if e.to_string().to_ascii_lowercase().contains("not found") => {
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
