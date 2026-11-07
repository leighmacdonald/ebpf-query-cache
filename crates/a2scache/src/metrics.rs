//! Prometheus metrics endpoint for the refresh daemon (`a2scache serve`).
//!
//! The daemon serves a private [`Registry`] on a configured listen
//! address (config `[metrics] listen`, or `serve --metrics-listen`, which
//! wins). The endpoint is off unless one of those is set.
//!
//! Values are refreshed *per scrape*, not on a timer: the updater thread
//! parks in [`prometheus_exporter::Exporter::wait_request`], which blocks
//! until the HTTP handler asks for a snapshot and returns a guard while
//! that handler waits. The thread then re-reads the pinned BPF maps (`STATS_MAP` +
//! `CACHE_MAP`) and the shared backend state, and only then drops the
//! guard, so every scrape renders one consistent snapshot. An idle daemon
//! does no work at all.
//!
//! The BPF stats map is re-created on every `attach` (the pins are
//! replaced), which would look like a counter *decrease* — the exposition
//! format forbids that and the `prometheus` crate refuses backwards
//! counter moves. [`UpdaterState`] therefore tracks the last value seen
//! per series and translates a drop into `reset()` + `inc_by()`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use prometheus_exporter::Builder;
use prometheus_exporter::prometheus::{
    GaugeVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

use a2s_protocol::{CACHE_MAX_ENTRIES, CacheEntry, cache_key_unpack, stats};

use crate::bpf;
use crate::daemon::Backend;
use crate::{Error, Result};

/// Refresh health of one backend, written by that backend's refresh
/// thread and read by the metrics updater on each scrape. The counters
/// only grow over the process lifetime (they reset with it).
#[derive(Clone, Copy, Debug, Default)]
pub struct BackendState {
    /// The last completed refresh cycle succeeded.
    pub up: bool,
    pub refreshes_success: u64,
    pub refreshes_failure: u64,
    /// Unix seconds of the last successful refresh (0 = never).
    pub last_success_unix: i64,
    /// Wall time of the last completed refresh cycle, success or failure.
    pub last_refresh: Duration,
}

/// Shared backend-health table: `ip:port` label → state.
pub type BackendStates = Arc<Mutex<HashMap<String, BackendState>>>;

/// An empty table (every backend reads as down until its first refresh).
pub fn new_backend_states() -> BackendStates {
    Arc::new(Mutex::new(HashMap::new()))
}

/// The registered metric families; one handle set for the updater.
#[derive(Debug)]
pub struct Families {
    /// BPF verdict counters, one series per `a2s_protocol::stats` index.
    pub events: IntCounterVec,
    pub cache_entries: IntGauge,
    pub cache_capacity: IntGauge,
    pub entry_info_age: IntGaugeVec,
    pub entry_player_age: IntGaugeVec,
    pub entry_challenge_age: IntGaugeVec,
    pub entry_info_bytes: IntGaugeVec,
    pub entry_player_bytes: IntGaugeVec,
    pub entry_ttl: IntGaugeVec,
    pub backend_up: IntGaugeVec,
    pub backend_refreshes: IntCounterVec,
    pub backend_last_success: IntGaugeVec,
    pub backend_last_refresh_latency: GaugeVec,
    pub daemon_uptime: IntGauge,
    pub daemon_backends: IntGauge,
    pub bpf_attached: IntGauge,
    pub build_info: IntGaugeVec,
}

/// Last-seen values the counter bookkeeping needs between scrapes. A
/// drop below the last seen value means the source re-zeroed (BPF
/// re-attach replaces the stats map; the backend counters never do).
/// A plain zero baseline is safe for first sight: the exposed counters
/// start at 0, so `inc_by(value - 0)` exposes exactly `value`.
#[derive(Default)]
pub struct UpdaterState {
    last_stats: [u64; stats::COUNT],
    last_success: HashMap<String, u64>,
    last_failure: HashMap<String, u64>,
    attached: bool,
}

fn bad(e: prometheus_exporter::prometheus::Error) -> Error {
    Error::Bad(format!("register prometheus metric: {e}"))
}

fn register<T: prometheus_exporter::prometheus::core::Collector + 'static>(
    reg: &Registry,
    m: T,
) -> Result<()> {
    reg.register(Box::new(m)).map_err(bad)
}

/// Register every family on `reg` and pre-create the series that exist
/// for the whole daemon lifetime: the 18 BPF event counters, and — per
/// configured backend — the refresh-result counters and the up/latency/
/// last-success gauges (an idle backend reads 0 from the first scrape).
/// Series for cache entries appear on first scrape (entries are only
/// ever added, never removed).
pub fn register_all(reg: &Registry, backends: &[Backend]) -> Result<Families> {
    let build_info = IntGaugeVec::new(
        Opts::new(
            "a2scache_build_info",
            "Daemon build; always 1, labelled with the version.",
        ),
        &["version"],
    )
    .map_err(bad)?;
    register(reg, build_info.clone())?;

    let daemon_uptime = IntGauge::new(
        "a2scache_daemon_uptime_seconds",
        "Daemon wall-clock uptime in seconds.",
    )
    .map_err(bad)?;
    register(reg, daemon_uptime.clone())?;

    let daemon_backends = IntGauge::new(
        "a2scache_daemon_backends",
        "Configured [[server]] backends.",
    )
    .map_err(bad)?;
    register(reg, daemon_backends.clone())?;

    let bpf_attached = IntGauge::new(
        "a2scache_bpf_attached",
        "1 if the pinned BPF maps were readable on the last scrape.",
    )
    .map_err(bad)?;
    register(reg, bpf_attached.clone())?;

    let events = IntCounterVec::new(
        Opts::new(
            "a2scache_bpf_events_total",
            "BPF verdict counters (STATS_MAP), per-CPU aggregated; reset \
             to zero when the program is re-attached.",
        ),
        &["stat"],
    )
    .map_err(bad)?;
    register(reg, events.clone())?;

    let cache_entries = IntGauge::new(
        "a2scache_cache_entries",
        "Instances currently cached in CACHE_MAP.",
    )
    .map_err(bad)?;
    register(reg, cache_entries.clone())?;

    let cache_capacity = IntGauge::new(
        "a2scache_cache_capacity",
        "Compile-time CACHE_MAP capacity (instances).",
    )
    .map_err(bad)?;
    register(reg, cache_capacity.clone())?;

    let entry_gauge = |name: &str, help: &str| {
        let g = IntGaugeVec::new(Opts::new(name, help), &["ip", "port"]).map_err(bad)?;
        register(reg, g.clone())?;
        Ok::<IntGaugeVec, Error>(g)
    };
    let entry_info_age = entry_gauge(
        "a2scache_entry_info_age_seconds",
        "Seconds since the cached INFO payload was last refreshed \
         (0 = never refreshed).",
    )?;
    let entry_player_age = entry_gauge(
        "a2scache_entry_player_age_seconds",
        "Seconds since the cached PLAYER payload was last refreshed \
         (0 = never refreshed).",
    )?;
    let entry_challenge_age = entry_gauge(
        "a2scache_entry_challenge_age_seconds",
        "Seconds since the cached challenge was last refreshed \
         (0 = never refreshed).",
    )?;
    let entry_info_bytes = entry_gauge(
        "a2scache_entry_info_bytes",
        "Cached INFO payload size in bytes (0 = never refreshed).",
    )?;
    let entry_player_bytes = entry_gauge(
        "a2scache_entry_player_bytes",
        "Cached PLAYER payload size in bytes (0 = never refreshed).",
    )?;
    let entry_ttl = entry_gauge(
        "a2scache_entry_ttl_seconds",
        "Effective per-instance freshness window (seconds) recorded in \
         the entry; 0 = never refreshed (global TTL applies).",
    )?;

    let backend_up = IntGaugeVec::new(
        Opts::new(
            "a2scache_backend_up",
            "1 if the daemon's last refresh of this backend succeeded.",
        ),
        &["ip", "port"],
    )
    .map_err(bad)?;
    register(reg, backend_up.clone())?;

    let backend_refreshes = IntCounterVec::new(
        Opts::new(
            "a2scache_backend_refreshes_total",
            "Daemon refresh cycles per backend; result is success|failure.",
        ),
        &["ip", "port", "result"],
    )
    .map_err(bad)?;
    register(reg, backend_refreshes.clone())?;

    let backend_last_success = IntGaugeVec::new(
        Opts::new(
            "a2scache_backend_last_success_seconds",
            "Unix time of the last successful refresh (0 = never).",
        ),
        &["ip", "port"],
    )
    .map_err(bad)?;
    register(reg, backend_last_success.clone())?;

    let backend_last_refresh_latency = GaugeVec::new(
        Opts::new(
            "a2scache_backend_last_refresh_latency_seconds",
            "Wall time of the last completed refresh cycle (success or \
             failure), in seconds.",
        ),
        &["ip", "port"],
    )
    .map_err(bad)?;
    register(reg, backend_last_refresh_latency.clone())?;

    // Pre-create the lifetime series so they read 0 from the first scrape.
    for name in bpf::STATS_NAMES {
        events.get_metric_with_label_values(&[name]).map_err(bad)?;
    }
    for b in backends {
        let ip = b.ip.to_string();
        let port = b.port.to_string();
        for result in ["success", "failure"] {
            backend_refreshes
                .get_metric_with_label_values(&[&ip, &port, result])
                .map_err(bad)?;
        }
        // Pre-create the per-backend gauges too, so an idle backend
        // reads 0 from the first scrape.
        backend_up.with_label_values(&[&ip, &port]);
        backend_last_success.with_label_values(&[&ip, &port]);
        backend_last_refresh_latency.with_label_values(&[&ip, &port]);
    }

    // Static gauges.
    cache_capacity.set(CACHE_MAX_ENTRIES as i64);
    daemon_backends.set(backends.len() as i64);
    build_info
        .with_label_values(&[env!("CARGO_PKG_VERSION")])
        .set(1);

    Ok(Families {
        events,
        cache_entries,
        cache_capacity,
        entry_info_age,
        entry_player_age,
        entry_challenge_age,
        entry_info_bytes,
        entry_player_bytes,
        entry_ttl,
        backend_up,
        backend_refreshes,
        backend_last_success,
        backend_last_refresh_latency,
        daemon_uptime,
        daemon_backends,
        bpf_attached,
        build_info,
    })
}

/// Move a Prometheus counter to `value` without ever letting it go
/// backwards: a drop below the last seen value (BPF re-attach re-zeros
/// the stats map) is `reset()` + `inc_by()`; a growth is a plain
/// `inc_by()` of the delta.
fn apply_counter(c: &IntCounter, last: &mut u64, value: u64) {
    if value >= *last {
        c.inc_by(value - *last);
    } else {
        c.reset();
        c.inc_by(value);
    }
    *last = value;
}

/// Apply one read of the BPF stats counters (already per-CPU summed),
/// handling re-attach resets.
fn apply_stats(f: &Families, totals: &[u64], st: &mut UpdaterState) {
    for (idx, name) in bpf::STATS_NAMES.iter().enumerate() {
        let c = f.events.with_label_values(&[name]);
        apply_counter(&c, &mut st.last_stats[idx], totals[idx]);
    }
}

/// Refresh one cached instance's per-entry gauges. `now` is
/// CLOCK_MONOTONIC nanoseconds — the same clock as the entry timestamps
/// (`bpf_ktime_get_ns`); a `ts == 0` half reads as age 0 / 0 bytes.
fn set_entry(f: &Families, key: u64, e: &CacheEntry, now: u64) {
    let (ip, port) = cache_key_unpack(key);
    let ip = Ipv4Addr::from(ip).to_string();
    let port = port.to_string();
    let l: [&str; 2] = [&ip, &port];
    let age = |ts: u64| -> i64 {
        if ts == 0 {
            0
        } else {
            (now.saturating_sub(ts) / 1_000_000_000) as i64
        }
    };
    f.entry_info_age.with_label_values(&l).set(age(e.ts_info));
    f.entry_player_age
        .with_label_values(&l)
        .set(age(e.ts_player));
    f.entry_challenge_age
        .with_label_values(&l)
        .set(age(e.ts_challenge));
    f.entry_info_bytes
        .with_label_values(&l)
        .set(e.info_len as i64);
    f.entry_player_bytes
        .with_label_values(&l)
        .set(e.player_len as i64);
    f.entry_ttl
        .with_label_values(&l)
        .set((e.ttl_ns / 1_000_000_000) as i64);
}

/// Refresh the per-backend families from the shared state table.
fn apply_backends(
    f: &Families,
    backends: &[Backend],
    states: &Mutex<HashMap<String, BackendState>>,
    st: &mut UpdaterState,
) {
    let states = states.lock().unwrap_or_else(|p| p.into_inner());
    for b in backends {
        let Some(s) = states.get(&b.label) else {
            continue;
        };
        let ip = b.ip.to_string();
        let port = b.port.to_string();
        let l: [&str; 2] = [&ip, &port];
        f.backend_up.with_label_values(&l).set(s.up as i64);
        f.backend_last_success
            .with_label_values(&l)
            .set(s.last_success_unix);
        f.backend_last_refresh_latency
            .with_label_values(&l)
            .set(s.last_refresh.as_secs_f64());
        apply_counter(
            &f.backend_refreshes
                .with_label_values(&[l[0], l[1], "success"]),
            st.last_success.entry(b.label.clone()).or_insert(0),
            s.refreshes_success,
        );
        apply_counter(
            &f.backend_refreshes
                .with_label_values(&[l[0], l[1], "failure"]),
            st.last_failure.entry(b.label.clone()).or_insert(0),
            s.refreshes_failure,
        );
    }
}

/// One scrape: re-read the pinned maps and the shared backend state and
/// refresh every family. Never fails — missing pins or a detached program
/// just read as `a2scache_bpf_attached 0` and the gauges keep their last
/// values.
pub fn update(
    f: &Families,
    pin_dir: &Path,
    backends: &[Backend],
    states: &Mutex<HashMap<String, BackendState>>,
    st: &mut UpdaterState,
    uptime: Duration,
) {
    f.daemon_uptime.set(uptime.as_secs() as i64);

    let attached = match bpf::stats(pin_dir) {
        Ok(totals) => {
            apply_stats(f, &totals, st);
            true
        }
        Err(e) => {
            log::debug!("stats map unreadable: {e}");
            false
        }
    };
    if attached != st.attached {
        log::info!("bpf_attached -> {attached}");
        st.attached = attached;
    }
    f.bpf_attached.set(attached as i64);

    if let Ok(entries) = bpf::cache_entries(pin_dir)
        && let Ok(now) = bpf::now_ns()
    {
        f.cache_entries.set(entries.len() as i64);
        for (key, e) in &entries {
            set_entry(f, *key, e, now);
        }
    }

    apply_backends(f, backends, states, st);
}

/// Start the exporter on `listen` and spawn the per-scrape updater
/// thread, which owns the [`prometheus_exporter::Exporter`] for the
/// process lifetime
/// (`prometheus_exporter` has no shutdown; the HTTP accept loop and the
/// updater, parked in `wait_request`, are reaped by the process exit).
/// Returns `false` when the address could not be bound or a family could
/// not be registered — in both cases the failure is logged and the
/// daemon runs without metrics.
pub fn start(
    listen: SocketAddr,
    pin_dir: PathBuf,
    backends: Vec<Backend>,
    states: BackendStates,
) -> bool {
    let reg = Registry::new();
    let families = match register_all(&reg, &backends) {
        Ok(f) => f,
        Err(e) => {
            log::error!("metrics: {e}");
            return false;
        }
    };
    let mut builder = Builder::new(listen);
    builder.with_registry(reg);
    let exporter = match builder.start() {
        Ok(e) => e,
        Err(e) => {
            log::warn!("metrics: cannot listen on {listen}: {e}; continuing without metrics");
            return false;
        }
    };

    let n_backends = backends.len();
    let started = Instant::now();
    let mut st = UpdaterState::default();
    thread::spawn(move || {
        loop {
            // Park until the next scrape; the returned guard keeps the HTTP
            // handler waiting so it renders the snapshot taken right below,
            // never a half-updated one.
            let _guard = exporter.wait_request();
            update(
                &families,
                &pin_dir,
                &backends,
                &states,
                &mut st,
                started.elapsed(),
            );
        }
    });
    log::info!("metrics: exporting on http://{listen}/metrics ({n_backends} backends)");
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use a2s_protocol::cache_key;
    use prometheus_exporter::prometheus::TextEncoder;

    fn test_backend(ip: Ipv4Addr, port: u16) -> Backend {
        Backend {
            ip,
            port,
            mac: None,
            label: format!("{ip}:{port}"),
            ttl_ns: 30_000_000_000,
            interval: Duration::from_secs(10),
            timeout: Duration::from_millis(2000),
        }
    }

    #[test]
    fn counter_reset_state_machine() {
        let reg = Registry::new();
        let f = register_all(&reg, &[test_backend(Ipv4Addr::new(10, 0, 0, 1), 27015)]).unwrap();
        let mut st = UpdaterState::default();
        let mut totals = vec![0u64; stats::COUNT];
        let idx = stats::SERVED_INFO as usize;
        let c = f.events.with_label_values(&[bpf::STATS_NAMES[idx]]);

        // First sight: sets the baseline.
        totals[idx] = 5;
        apply_stats(&f, &totals, &mut st);
        assert_eq!(c.get(), 5);

        // Monotonic growth: inc_by the delta.
        totals[idx] = 9;
        apply_stats(&f, &totals, &mut st);
        assert_eq!(c.get(), 9);

        // Re-attach: the map re-zeros, the value drops below the last
        // seen one -> reset + set.
        totals[idx] = 2;
        apply_stats(&f, &totals, &mut st);
        assert_eq!(c.get(), 2);

        // Growth again after the reset.
        totals[idx] = 4;
        apply_stats(&f, &totals, &mut st);
        assert_eq!(c.get(), 4);
    }

    #[test]
    fn scrape_body_shows_all_families() {
        let reg = Registry::new();
        let backends = vec![
            test_backend(Ipv4Addr::new(10, 0, 0, 1), 27015),
            test_backend(Ipv4Addr::new(10, 0, 0, 2), 27025),
        ];
        let f = register_all(&reg, &backends).unwrap();
        let mut st = UpdaterState::default();

        // BPF side: pretend the maps read fine.
        let mut totals = vec![0u64; stats::COUNT];
        totals[stats::PASS_THROUGH as usize] = 7;
        totals[stats::SERVED_INFO as usize] = 11;
        apply_stats(&f, &totals, &mut st);

        // One cached entry: INFO set 3s ago, PLAYER never, ttl 90s.
        let key = cache_key(0x0A00_0001, 27015);
        let now = 1_000_000_000_000;
        let e = CacheEntry {
            info_len: 140,
            ts_info: now - 3_000_000_000,
            ttl_ns: 90_000_000_000,
            ..Default::default()
        };
        set_entry(&f, key, &e, now);

        // Backend state: three successes, one failure, 812 ms last cycle.
        let states = Mutex::new(HashMap::new());
        states.lock().unwrap().insert(
            backends[0].label.clone(),
            BackendState {
                up: true,
                refreshes_success: 3,
                refreshes_failure: 1,
                last_success_unix: 1_760_000_000,
                last_refresh: Duration::from_millis(812),
            },
        );
        apply_backends(&f, &backends, &states, &mut st);

        f.daemon_uptime.set(42);
        f.bpf_attached.set(1);

        let mut out = String::new();
        TextEncoder::new()
            .encode_utf8(&reg.gather(), &mut out)
            .unwrap();

        // Every BPF event series is present, with its value.
        assert!(out.contains("# HELP a2scache_bpf_events_total"));
        assert!(out.contains("# TYPE a2scache_bpf_events_total counter"));
        assert_eq!(
            out.matches("a2scache_bpf_events_total{").count(),
            stats::COUNT,
            "want all {} stat series",
            stats::COUNT
        );
        assert!(out.contains("a2scache_bpf_events_total{stat=\"pass_through\"} 7"));
        assert!(out.contains("a2scache_bpf_events_total{stat=\"served_info\"} 11"));
        assert!(out.contains("a2scache_bpf_events_total{stat=\"dropped_rewrite_redirect\"} 0"));

        // Per-entry gauges (labels in registration order).
        assert!(out.contains("a2scache_entry_info_age_seconds{ip=\"10.0.0.1\",port=\"27015\"} 3"));
        assert!(
            out.contains("a2scache_entry_player_age_seconds{ip=\"10.0.0.1\",port=\"27015\"} 0")
        );
        assert!(out.contains("a2scache_entry_info_bytes{ip=\"10.0.0.1\",port=\"27015\"} 140"));
        assert!(out.contains("a2scache_entry_player_bytes{ip=\"10.0.0.1\",port=\"27015\"} 0"));
        assert!(out.contains("a2scache_entry_ttl_seconds{ip=\"10.0.0.1\",port=\"27015\"} 90"));

        // Backend gauges: the known-but-idle backend reads 0.
        assert!(out.contains("a2scache_backend_up{ip=\"10.0.0.1\",port=\"27015\"} 1"));
        assert!(out.contains("a2scache_backend_up{ip=\"10.0.0.2\",port=\"27025\"} 0"));
        assert!(out.contains(
            "a2scache_backend_refreshes_total{ip=\"10.0.0.1\",port=\"27015\",result=\"success\"} 3"
        ));
        assert!(out.contains(
            "a2scache_backend_refreshes_total{ip=\"10.0.0.1\",port=\"27015\",result=\"failure\"} 1"
        ));
        assert!(out.contains(
            "a2scache_backend_refreshes_total{ip=\"10.0.0.2\",port=\"27025\",result=\"success\"} 0"
        ));
        assert!(out.contains(
            "a2scache_backend_last_success_seconds{ip=\"10.0.0.1\",port=\"27015\"} 1760000000"
        ));
        assert!(out.contains(
            "a2scache_backend_last_refresh_latency_seconds{ip=\"10.0.0.1\",port=\"27015\"} 0.812"
        ));

        // Scalars.
        assert!(out.contains("a2scache_daemon_uptime_seconds 42"));
        assert!(out.contains("a2scache_daemon_backends 2"));
        assert!(out.contains(&format!("a2scache_cache_capacity {CACHE_MAX_ENTRIES}")));
        assert!(out.contains(&format!(
            "a2scache_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )));
    }

    #[test]
    fn update_survives_missing_pins() {
        // Scratch dir under the workspace ./.tmp (never the source tree).
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/metrics-test");
        std::fs::create_dir_all(&dir).unwrap();
        let reg = Registry::new();
        let backends = vec![test_backend(Ipv4Addr::new(10, 0, 0, 1), 27015)];
        let f = register_all(&reg, &backends).unwrap();
        let mut st = UpdaterState::default();
        let states = Mutex::new(HashMap::new());
        for up in [Duration::from_secs(42), Duration::from_secs(43)] {
            update(&f, &dir, &backends, &states, &mut st, up);
        }
        // No panic, no pins: attached reads 0 and the gauges stay put.
        assert_eq!(f.bpf_attached.get(), 0);
        assert_eq!(f.cache_entries.get(), 0);
        assert_eq!(f.daemon_uptime.get(), 43);
        let _ = std::fs::remove_dir(&dir);
    }
}
