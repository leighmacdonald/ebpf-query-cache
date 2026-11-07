//! Scrape round-trip against the real exporter (tiny-http) on loopback:
//! the registry the daemon registers, the per-scrape guard protocol, and
//! the exact text body a Prometheus client would read.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use a2s_protocol::CACHE_MAX_ENTRIES;
use a2scache::daemon::Backend;
use a2scache::metrics::register_all;
use prometheus_exporter::prometheus::Registry;

/// Raw HTTP/1.1 request on a fresh connection; returns (status, body).
fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).expect("write");
    s.shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("read");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status: u16 = text
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .expect("status line")
        .parse()
        .expect("status code");
    (status, text)
}

#[test]
fn scrape_roundtrip() {
    // Find a free loopback port (bind, read, drop; the small race is
    // acceptable in a single-host test).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let reg = Registry::new();
    let backends = vec![Backend {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        port: 27015,
        mac: None,
        label: "10.0.0.1:27015".into(),
        ttl_ns: 30_000_000_000,
        interval: Duration::from_secs(10),
        timeout: Duration::from_millis(2000),
    }];
    let f = register_all(&reg, &backends).expect("register");

    let mut builder =
        prometheus_exporter::Builder::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    builder.with_registry(reg);
    let exporter = builder.start().expect("exporter start");

    // Seed the values under the update guard, exactly like the updater
    // thread does while a scrape is pending.
    {
        let _guard = exporter.wait_duration(Duration::from_millis(200));
        f.events.with_label_values(&["pass_through"]).inc_by(7);
        f.cache_entries.set(1);
        f.daemon_uptime.set(42);
        f.backend_up
            .with_label_values(&["10.0.0.1", "27015"])
            .set(1);
    }

    let (status, body) = get(port, "/metrics");
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("200 OK"));
    // All 18 BPF event series exist, seeded and unseeded alike.
    assert_eq!(
        body.matches("a2scache_bpf_events_total{").count(),
        a2s_protocol::stats::COUNT
    );
    assert!(body.contains("a2scache_bpf_events_total{stat=\"pass_through\"} 7"));
    assert!(body.contains("a2scache_bpf_events_total{stat=\"served_player\"} 0"));
    assert!(body.contains("a2scache_cache_entries 1"));
    assert!(body.contains("a2scache_daemon_uptime_seconds 42"));
    assert!(body.contains("a2scache_backend_up{ip=\"10.0.0.1\",port=\"27015\"} 1"));
    assert!(body.contains(&format!("a2scache_cache_capacity {CACHE_MAX_ENTRIES}")));

    // A second scrape of the same values (guard dropped, handler renders
    // directly without waiting): nothing may have changed.
    let (status, body2) = get(port, "/metrics");
    assert_eq!(status, 200);
    assert!(body2.contains("a2scache_bpf_events_total{stat=\"pass_through\"} 7"));

    // Non-/metrics paths redirect to the endpoint.
    let (status, body) = get(port, "/");
    assert_eq!(status, 301, "body: {body}");
    assert!(body.contains("/metrics"));
}
