//! Refresh daemon (`a2scache serve`): keeps BPF cache entries warm.
//!
//! One thread per `[[server]]` backend performs the modern A2S challenge
//! dance (INFO plain → `41` → retry with challenge; PLAYER `0xFFFFFFFF` →
//! `41` → retry with challenge), reassembles split fragments, and writes the
//! resulting payloads into `CACHE_MAP` with `CLOCK_MONOTONIC` timestamps (the
//! same clock as `bpf_ktime_get_ns`). On a cache hit the backend sees
//! nothing; on failure the old entry is left in place so traffic passes
//! through to the backend until the next refresh.
//!
//! The challenge-dance loop here is separate from [`crate::query`]'s: the
//! daemon tolerates re-challenges (challenge rotation mid-cycle) and reports
//! which challenge the final payload was fetched with.

use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use a2s_protocol::{
    build_info_request, build_info_request_challenged, build_player_request, cache_key,
    is_fragment, response_type, CacheEntry, Config, Reassembler, MAX_PAYLOAD, NO_CHALLENGE,
    TYPE_CHALLENGE, TYPE_INFO_RESP, TYPE_PLAYER_RESP,
};
use aya::maps::{Array, HashMap, Map, MapData};
use serde::Deserialize;

use crate::bpf;
use crate::{Error, Result};

/// Set once SIGTERM/SIGINT arrives; all threads poll it.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

const MAX_DGRAM: usize = 65535;
/// Cap on challenge round-trips per query so a wedged server cannot spin us.
const MAX_RECHALLENGE: u32 = 3;
/// Sleep granularity while waiting out the refresh interval.
const SLEEP_STEP: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// TOML config
// ---------------------------------------------------------------------------

/// Top-level `a2scache.toml`.
#[derive(Debug, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub bpf: BpfSection,
    #[serde(default)]
    pub defaults: DefaultsSection,
    #[serde(default)]
    pub server: Vec<ServerSection>,
}

#[derive(Debug, Deserialize)]
pub struct BpfSection {
    #[serde(default = "default_pin_dir")]
    pub pin_dir: PathBuf,
}

fn default_pin_dir() -> PathBuf {
    PathBuf::from(bpf::DEFAULT_PIN_DIR)
}

fn default_ttl_secs() -> u64 {
    bpf::DEFAULT_TTL_SEC
}
fn default_interval_secs() -> u64 {
    10
}
fn default_timeout_ms() -> u64 {
    2000
}
fn default_per_ip_capacity() -> u32 {
    10_000
}
fn default_per_ip_refill_per_s() -> u32 {
    2_000
}
fn default_global_capacity() -> u32 {
    200_000
}
fn default_global_refill_per_s() -> u32 {
    50_000
}

/// Daemon-wide defaults; every field has a default so `[defaults]` may be
/// omitted or partial.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct DefaultsSection {
    /// How long BPF serves an entry before passing through (seconds).
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    /// Time between refresh cycles per backend (seconds).
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Per-datagram receive timeout for the challenge dance (milliseconds).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_per_ip_capacity")]
    pub per_ip_capacity: u32,
    #[serde(default = "default_per_ip_refill_per_s")]
    pub per_ip_refill_per_s: u32,
    #[serde(default = "default_global_capacity")]
    pub global_capacity: u32,
    #[serde(default = "default_global_refill_per_s")]
    pub global_refill_per_s: u32,
}

impl Default for DefaultsSection {
    fn default() -> Self {
        Self {
            ttl_secs: default_ttl_secs(),
            interval_secs: default_interval_secs(),
            timeout_ms: default_timeout_ms(),
            per_ip_capacity: default_per_ip_capacity(),
            per_ip_refill_per_s: default_per_ip_refill_per_s(),
            global_capacity: default_global_capacity(),
            global_refill_per_s: default_global_refill_per_s(),
        }
    }
}

impl Default for BpfSection {
    fn default() -> Self {
        Self {
            pin_dir: default_pin_dir(),
        }
    }
}

/// One cached game server.
#[derive(Clone, Debug, Deserialize)]
pub struct ServerSection {
    /// Backend IPv4 address (the BPF program only handles IPv4).
    pub ip: String,
    /// Backend game port (e.g. 27015).
    pub port: u16,
    /// Optional source MAC for synthesized replies; overrides the MAC
    /// recorded by `attach` when set (first server wins, see [`serve`]).
    pub mac: Option<String>,
}

/// A validated backend: the per-thread refresh target.
#[derive(Clone, Debug)]
pub struct Backend {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub mac: Option<[u8; 6]>,
    /// `ip:port` label used in log lines.
    pub label: String,
}

impl Backend {
    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.ip, self.port)
    }
}

/// Read and validate the daemon config file.
pub fn load_config(path: &Path) -> Result<(FileConfig, Vec<Backend>)> {
    let raw = fs::read_to_string(path)
        .map_err(|e| Error::Bad(format!("read {}: {e}", path.display())))?;
    let cfg: FileConfig = toml::from_str(&raw)?;
    if cfg.server.is_empty() {
        return Err(Error::Bad(format!(
            "no [[server]] entries in {}",
            path.display()
        )));
    }
    if cfg.defaults.ttl_secs == 0 {
        return Err(Error::Bad("defaults.ttl_secs must be >= 1".into()));
    }
    if cfg.defaults.interval_secs == 0 {
        return Err(Error::Bad("defaults.interval_secs must be >= 1".into()));
    }
    if cfg.defaults.timeout_ms < 100 {
        return Err(Error::Bad("defaults.timeout_ms must be >= 100".into()));
    }

    let mut backends = Vec::with_capacity(cfg.server.len());
    for s in &cfg.server {
        let ip: Ipv4Addr =
            s.ip.parse()
                .map_err(|_| Error::Bad(format!("bad server ip `{}` (want IPv4)", s.ip)))?;
        let mac = s
            .mac
            .as_deref()
            .map(bpf::parse_mac)
            .transpose()
            .map_err(|_| {
                Error::Bad(format!(
                    "bad mac `{}` for server {}:{}",
                    s.mac.as_deref().unwrap_or(""),
                    s.ip,
                    s.port
                ))
            })?;
        backends.push(Backend {
            ip,
            port: s.port,
            mac,
            label: format!("{}:{}", s.ip, s.port),
        });
    }
    Ok((cfg, backends))
}

// ---------------------------------------------------------------------------
// Challenge dance + fragment reassembly (daemon variant)
// ---------------------------------------------------------------------------

/// One fetched query response.
pub struct DanceResult {
    /// Challenge the payload was fetched with; `None` if the server answered
    /// the unchallenged request directly.
    pub challenge: Option<u32>,
    pub payload: Vec<u8>,
}

/// What a refresh cycle learned about a backend.
#[derive(Debug, Default)]
pub struct RefreshData {
    /// Newest challenge observed (PLAYER result preferred: it ran last).
    pub challenge: Option<u32>,
    pub info: Option<Vec<u8>>,
    pub player: Option<Vec<u8>>,
}

/// Run one request/challenge/fragment exchange until the expected response
/// type arrives. `first` is the initial request; `rechallenge` rebuilds it
/// carrying the given challenge.
fn dance(
    sock: &UdpSocket,
    target: SocketAddr,
    first: Vec<u8>,
    rechallenge: &dyn Fn(u32) -> Vec<u8>,
    expect: u8,
) -> Result<DanceResult> {
    let mut reasm = Reassembler::new();
    let mut challenge = None;
    let mut rechallenges = 0u32;

    sock.send_to(&first, target)?;
    loop {
        let mut buf = vec![0u8; MAX_DGRAM];
        let n = match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if from != target {
                    continue;
                }
                n
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                return Err(Error::Bad("no response (timeout)".into()));
            }
            Err(e) => return Err(e.into()),
        };
        buf.truncate(n);
        let d = buf.as_slice();

        if is_fragment(d) {
            reasm
                .push(d)
                .map_err(|e| Error::Bad(format!("fragment: {e:?}")))?;
            if reasm.is_complete() {
                let payload = reasm.reassembled().unwrap().to_vec();
                return Ok(DanceResult { challenge, payload });
            }
            continue;
        }

        match response_type(d) {
            Some(TYPE_CHALLENGE) if d.len() >= 9 => {
                rechallenges += 1;
                if rechallenges > MAX_RECHALLENGE {
                    return Err(Error::Bad("too many challenges; aborting".into()));
                }
                let ch = u32::from_le_bytes([d[5], d[6], d[7], d[8]]);
                challenge = Some(ch);
                sock.send_to(&rechallenge(ch), target)?;
            }
            Some(t) if t == expect => {
                return Ok(DanceResult {
                    challenge,
                    payload: d.to_vec(),
                });
            }
            Some(t) => {
                return Err(Error::Bad(format!("unexpected response type {t:#04x}")));
            }
            None => return Err(Error::Bad("malformed response (bad magic)".into())),
        }
    }
}

fn bad(e: a2s_protocol::Error) -> Error {
    Error::Bad(format!("protocol: {e:?}"))
}

/// Keep a fetched payload only if it is a well-formed, cacheable response.
fn validated(payload: Vec<u8>, expect: u8, what: &str, label: &str) -> Option<Vec<u8>> {
    if response_type(&payload) != Some(expect) {
        log::warn!("[{label}] {what}: bad magic/type, not caching");
        return None;
    }
    if payload.len() > MAX_PAYLOAD {
        log::warn!(
            "[{label}] {what}: {} B exceeds {MAX_PAYLOAD} B, not caching",
            payload.len()
        );
        return None;
    }
    Some(payload)
}

/// Query INFO and PLAYER on an already-bound socket with the read timeout
/// set. A failed PLAYER still yields the INFO half (partial merge); a failed
/// INFO fails the cycle since no challenge is known.
pub fn refresh_once(sock: &UdpSocket, target: SocketAddrV4, label: &str) -> Result<RefreshData> {
    let target_sa = SocketAddr::V4(target);

    let mut first = [0u8; 33];
    let n = build_info_request(&mut first).map_err(bad)?;
    let info = dance(
        sock,
        target_sa,
        first[..n].to_vec(),
        &|ch| {
            let mut b = [0u8; 33];
            build_info_request_challenged(&mut b, ch)
                .map(|m| b[..m].to_vec())
                .unwrap()
        },
        TYPE_INFO_RESP,
    )?;

    let mut preq = [0u8; 9];
    let m = build_player_request(&mut preq, info.challenge.unwrap_or(NO_CHALLENGE)).map_err(bad)?;
    let player = match dance(
        sock,
        target_sa,
        preq[..m].to_vec(),
        &|ch| {
            let mut b = [0u8; 9];
            build_player_request(&mut b, ch)
                .map(|m| b[..m].to_vec())
                .unwrap()
        },
        TYPE_PLAYER_RESP,
    ) {
        Ok(p) => Some(p),
        Err(e) => {
            log::warn!("[{label}] PLAYER refresh failed ({e}); keeping old entry");
            None
        }
    };
    // Newest challenge wins (PLAYER ran last); the payloads themselves carry
    // no challenge bytes, so both stay servable under it.
    let challenge = player.as_ref().and_then(|p| p.challenge).or(info.challenge);

    Ok(RefreshData {
        challenge,
        info: validated(info.payload, TYPE_INFO_RESP, "INFO", label),
        player: player.and_then(|p| validated(p.payload, TYPE_PLAYER_RESP, "PLAYER", label)),
    })
}

/// Merge a refresh into the previous entry. Successful halves replace the
/// cached bytes (tails zeroed — BPF checksums the payload view rounded up to
/// a 4-byte multiple); failed halves keep their old bytes.
pub fn merge_entry(old: &CacheEntry, data: &RefreshData, now: u64) -> CacheEntry {
    let mut e = *old;
    if let Some(ch) = data.challenge {
        e.challenge = ch;
        e.ts_challenge = now;
    }
    if let Some(info) = &data.info {
        e.info.fill(0);
        e.info[..info.len()].copy_from_slice(info);
        e.info_len = info.len() as u16;
        e.ts_info = now;
    }
    if let Some(player) = &data.player {
        e.player.fill(0);
        e.player[..player.len()].copy_from_slice(player);
        e.player_len = player.len() as u16;
        e.ts_player = now;
    }
    e
}

// ---------------------------------------------------------------------------
// Map handling
// ---------------------------------------------------------------------------

/// Open a pinned map, retrying with backoff until it appears or we are asked
/// to shut down (covers `serve` starting before `attach`).
fn open_pinned(pin_dir: &Path, name: &str) -> Result<MapData> {
    let mut wait = Duration::from_millis(200);
    loop {
        match MapData::from_pin(bpf::pin_path(pin_dir, name)) {
            Ok(m) => return Ok(m),
            Err(e) => {
                if SHUTDOWN.load(Ordering::SeqCst) {
                    return Err(Error::Bad("shutting down".into()));
                }
                log::warn!(
                    "cannot open {}: {e}; retrying in {} ms",
                    bpf::pin_path(pin_dir, name).display(),
                    wait.as_millis()
                );
                if sleep_shutdown(wait) {
                    return Err(Error::Bad("shutting down".into()));
                }
                wait = (wait * 2).min(Duration::from_secs(5));
            }
        }
    }
}

fn open_cache(pin_dir: &Path) -> Result<HashMap<MapData, u64, CacheEntry>> {
    let data = open_pinned(pin_dir, bpf::MAP_CACHE)?;
    Ok(Map::from_map_data(data)?.try_into()?)
}

/// Write the global [`Config`] from the daemon config, preserving the
/// attach-time egress interface/MAC unless the backend list overrides the
/// MAC.
fn write_config(pin_dir: &Path, cfg: &FileConfig, backends: &[Backend]) -> Result<()> {
    let data = open_pinned(pin_dir, bpf::MAP_CONFIG)?;
    let mut array: Array<MapData, Config> = Map::from_map_data(data)?.try_into()?;
    let zero = 0u32;
    let old: Config = array.get(&zero, 0).unwrap_or_default();
    let d = cfg.defaults;

    let mut mac = old.backend_mac;
    let mut mac_from = None;
    for b in backends {
        if let Some(m) = b.mac {
            if mac_from.is_none() {
                mac = m;
                mac_from = Some(b.label.clone());
            } else if m != mac {
                log::warn!(
                    "[{}] mac differs from [{}]; BPF holds a single global MAC, ignoring",
                    b.label,
                    mac_from.as_deref().unwrap_or("")
                );
            }
        }
    }
    if let Some(src) = mac_from {
        log::info!("using backend_mac from [{src}] for synthesized replies");
    }

    let new = Config {
        enabled: 1,
        ifindex_out: old.ifindex_out,
        ttl_ns: d.ttl_secs.saturating_mul(1_000_000_000),
        max_payload: MAX_PAYLOAD as u32,
        per_ip_capacity: d.per_ip_capacity,
        per_ip_refill_per_s: d.per_ip_refill_per_s,
        global_capacity: d.global_capacity,
        global_refill_per_s: d.global_refill_per_s,
        backend_mac: mac,
        ..Config::default()
    };
    array.set(0, new, 0)?;
    if new.ifindex_out == 0 {
        log::warn!("config.ifindex_out is 0 (attach first?); replies cannot redirect yet");
    }
    log::info!(
        "config: ttl {}s, max_payload {MAX_PAYLOAD}B, per_ip {}/{}/s, global {}/{}/s",
        d.ttl_secs,
        d.per_ip_capacity,
        d.per_ip_refill_per_s,
        d.global_capacity,
        d.global_refill_per_s
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Threads + signals
// ---------------------------------------------------------------------------

/// Sleep `dur` in slices so shutdown is noticed promptly. Returns true when
/// shutdown was requested.
fn sleep_shutdown(dur: Duration) -> bool {
    let mut left = dur;
    while left > Duration::ZERO {
        let step = left.min(SLEEP_STEP);
        thread::sleep(step);
        if SHUTDOWN.load(Ordering::SeqCst) {
            return true;
        }
        left -= step;
    }
    false
}

/// Block SIGTERM/SIGINT process-wide (inherited by threads spawned later) so
/// delivery goes through the sigwait thread below instead of killing us.
fn block_signals() -> Result<()> {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(Error::Bad("pthread_sigmask failed".into()));
        }
    }
    Ok(())
}

fn spawn_signal_thread() -> thread::JoinHandle<()> {
    thread::spawn(|| unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        let mut sig = 0;
        libc::sigwait(&set, &mut sig);
        log::info!("received signal {sig}, shutting down");
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
}

/// Refresh loop for one backend. Reopens the cache map on failure so a single
/// wedged backend (or map hiccup) never kills the daemon.
fn backend_loop(pin_dir: PathBuf, backend: Backend, d: DefaultsSection) {
    let key = cache_key(u32::from(backend.ip), backend.port);
    let timeout = Duration::from_millis(d.timeout_ms);
    let interval = Duration::from_secs(d.interval_secs);
    log::info!(
        "[{}] watching (interval {}s)",
        backend.label,
        d.interval_secs
    );

    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        let mut cache = match open_cache(&pin_dir) {
            Ok(c) => c,
            Err(e) => {
                if SHUTDOWN.load(Ordering::SeqCst) {
                    break;
                }
                log::error!("[{}] bad {} map: {e}", backend.label, bpf::MAP_CACHE);
                if sleep_shutdown(interval) {
                    break;
                }
                continue;
            }
        };

        let cycle = (|| -> Result<()> {
            let sock = UdpSocket::bind("0.0.0.0:0")?;
            sock.set_read_timeout(Some(timeout))?;
            let data = refresh_once(&sock, backend.addr(), &backend.label)?;
            if data.info.is_none() && data.player.is_none() {
                return Err(Error::Bad("no cacheable payload".into()));
            }
            let now = bpf::now_ns()?;
            let old = cache.get(&key, 0).unwrap_or_default();
            let entry = merge_entry(&old, &data, now);
            cache.insert(key, entry, 0)?;
            log::info!(
                "[{}] refreshed: challenge {} info={}B player={}B",
                backend.label,
                entry.challenge,
                entry.info_len,
                entry.player_len
            );
            Ok(())
        })();
        if let Err(e) = cycle {
            log::warn!(
                "[{}] refresh failed ({e}); retrying in {}s",
                backend.label,
                d.interval_secs
            );
        }

        if sleep_shutdown(interval) {
            break;
        }
    }
    log::info!("[{}] stopped", backend.label);
}

/// Run the refresh daemon until SIGTERM/SIGINT.
pub fn serve(config_path: &Path, pin_dir_override: Option<&Path>) -> Result<()> {
    let (cfg, backends) = load_config(config_path)?;
    log::info!(
        "loaded {} ({} backends)",
        config_path.display(),
        backends.len()
    );

    block_signals()?;
    let _signals = spawn_signal_thread();

    let pin_dir = match pin_dir_override {
        Some(p) => p.to_path_buf(),
        None => cfg.bpf.pin_dir.clone(),
    };
    if let Err(e) = write_config(&pin_dir, &cfg, &backends) {
        if SHUTDOWN.load(Ordering::SeqCst) {
            log::info!("shutdown complete");
            return Ok(());
        }
        return Err(e);
    }

    let mut handles = Vec::with_capacity(backends.len());
    for b in backends {
        let pin_dir = pin_dir.clone();
        let d = cfg.defaults;
        handles.push(thread::spawn(move || backend_loop(pin_dir, b, d)));
    }

    // Park the main thread until a signal arrives; the waiter sets SHUTDOWN
    // and backend loops (plus the map-open retry) notice it promptly.
    while !SHUTDOWN.load(Ordering::SeqCst) {
        thread::sleep(SLEEP_STEP);
    }
    log::info!("waiting for backends to stop");
    for h in handles {
        let _ = h.join();
    }
    log::info!("shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn load_str(raw: &str) -> Result<(FileConfig, Vec<Backend>)> {
        // Scratch files go to the workspace ./.tmp (never the source tree):
        // derive it from the crate location, independent of CWD/TMPDIR.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/test-tmp");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "a2scache-test-{}-{}.toml",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, raw).unwrap();
        let r = load_config(&path);
        let _ = fs::remove_file(&path);
        r
    }

    const MINIMAL: &str = r#"
[[server]]
ip = "10.0.0.1"
port = 27015
"#;

    #[test]
    fn defaults_fill_in() {
        let (cfg, backends) = load_str(MINIMAL).unwrap();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(backends[0].port, 27015);
        assert_eq!(backends[0].mac, None);
        assert_eq!(cfg.bpf.pin_dir, PathBuf::from(bpf::DEFAULT_PIN_DIR));
        let d = cfg.defaults;
        assert_eq!(d.ttl_secs, 30);
        assert_eq!(d.interval_secs, 10);
        assert_eq!(d.timeout_ms, 2000);
        assert_eq!(d.per_ip_capacity, 10_000);
        assert_eq!(d.per_ip_refill_per_s, 2_000);
        assert_eq!(d.global_capacity, 200_000);
        assert_eq!(d.global_refill_per_s, 50_000);
    }

    #[test]
    fn full_config_parses() {
        let (cfg, backends) = load_str(
            r#"
[bpf]
pin_dir = "/tmp/pins"

[defaults]
ttl_secs = 60
interval_secs = 5
timeout_ms = 500
per_ip_capacity = 1
per_ip_refill_per_s = 2
global_capacity = 3
global_refill_per_s = 4

[[server]]
ip = "192.168.1.10"
port = 27015
mac = "AA:bb:CC:dd:EE:ff"

[[server]]
ip = "192.168.1.11"
port = 27016
"#,
        )
        .unwrap();
        assert_eq!(cfg.bpf.pin_dir, PathBuf::from("/tmp/pins"));
        assert_eq!(cfg.defaults.ttl_secs, 60);
        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0].mac, Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        assert_eq!(backends[1].mac, None);
    }

    #[test]
    fn rejects_bad_servers() {
        for raw in [
            // No backends at all.
            "[defaults]\nttl_secs = 30\n",
            // Hostname instead of IPv4.
            "[[server]]\nip = \"example.com\"\nport = 27015\n",
            // IPv6 is not served by the BPF program.
            "[[server]]\nip = \"::1\"\nport = 27015\n",
            // Malformed MAC.
            "[[server]]\nip = \"10.0.0.1\"\nport = 27015\nmac = \"not-a-mac\"\n",
            "[[server]]\nip = \"10.0.0.1\"\nport = 27015\nmac = \"aa:bb:cc:dd:ee:ff:00\"\n",
            // Timing floors.
            "[[server]]\nip = \"10.0.0.1\"\nport = 27015\n[defaults]\nttl_secs = 0\n",
            "[[server]]\nip = \"10.0.0.1\"\nport = 27015\n[defaults]\ninterval_secs = 0\n",
            "[[server]]\nip = \"10.0.0.1\"\nport = 27015\n[defaults]\ntimeout_ms = 50\n",
        ] {
            assert!(load_str(raw).is_err(), "accepted bad config: {raw}");
        }
    }

    #[test]
    fn cache_key_matches_bpf_byte_order() {
        // BPF decodes the IPv4 header with u32::from_be_bytes over the wire
        // octets; the daemon must pack the same numeric value.
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        assert_eq!(u32::from(ip), 0xC0A8_0164);
        let (back, _) = cache_key_parts_for_test();
        assert_eq!(back, cache_key(0xC0A8_0164, 27015));
    }

    fn cache_key_parts_for_test() -> (u64, SocketAddrV4) {
        let b = Backend {
            ip: Ipv4Addr::new(192, 168, 1, 100),
            port: 27015,
            mac: None,
            label: "x".into(),
        };
        (cache_key(u32::from(b.ip), b.port), b.addr())
    }
}
