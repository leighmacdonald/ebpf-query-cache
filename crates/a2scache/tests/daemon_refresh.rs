//! Daemon refresh tests against fake TF2 responders (no BPF/maps needed).
use std::net::{SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use a2s_protocol::MAX_PAYLOAD;
use a2scache::daemon;

const TIMEOUT: Duration = Duration::from_secs(5);

fn info_response() -> Vec<u8> {
    let mut r = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x02];
    for s in [
        "testserver",
        "tm_play",
        "tf",
        "tf",
        "dedicated",
        "win32",
        "",
        "1.11.2",
    ] {
        r.extend(s.as_bytes());
        r.push(0);
    }
    r.extend(440u16.to_le_bytes()); // appid
    r.push(7); // players
    r.push(16); // max
    r.push(0); // bots
    r.push(1); // vac
    r
}

fn player_response() -> Vec<u8> {
    let mut r = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0x01];
    r.push(0); // index
    r.extend_from_slice(b"Player1\0");
    r.extend(1234i32.to_le_bytes()); // score
    r.extend(600u32.to_le_bytes()); // time
    r
}

fn challenge_msg(ch: u32) -> Vec<u8> {
    let mut r = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x41];
    r.extend(ch.to_le_bytes());
    r
}

fn fragment(id: u32, total: u8, number: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFE, 0xFF, 0xFF, 0xFF];
    v.extend_from_slice(&id.to_le_bytes());
    v.push(total);
    v.push(number);
    v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    v.extend_from_slice(payload);
    v
}

fn ch_of(req: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([req[at], req[at + 1], req[at + 2], req[at + 3]])
}

/// Fake TF2 backend: challenge-first INFO/PLAYER dance.
///
/// `player_fragments`: 1 = whole datagram, 2 = two FE fragments. Passing
/// distinct `info_ch`/`player_ch` simulates challenge rotation between the
/// two dances: a PLAYER request carrying the INFO challenge is re-challenged.
fn spawn_fake(info_ch: u32, player_ch: u32, player_fragments: u8) -> SocketAddrV4 {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let addr = sock.local_addr().unwrap();
        tx.send(addr).unwrap();
        let info = info_response();
        let player = player_response();

        loop {
            let mut buf = [0u8; 2048];
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => break,
            };
            let req = &buf[..n];
            if req.len() < 5 || req[0..4] != [0xFF, 0xFF, 0xFF, 0xFF] {
                continue;
            }
            match req[4] {
                0x54 if req.len() == 25 => {
                    sock.send_to(&challenge_msg(info_ch), from).unwrap();
                }
                0x54 if req.len() == 29 => {
                    if ch_of(req, 25) == info_ch {
                        sock.send_to(&info, from).unwrap();
                    } else {
                        sock.send_to(&challenge_msg(info_ch), from).unwrap();
                    }
                    // No break: the same socket must stay up for the PLAYER
                    // half of the refresh; the thread exits on read timeout.
                }
                0x55 if req.len() == 9 => {
                    let c = ch_of(req, 5);
                    if c == player_ch {
                        if player_fragments == 1 {
                            sock.send_to(&player, from).unwrap();
                        } else {
                            let (a, b) = player.split_at(player.len() / 2);
                            sock.send_to(&fragment(0x42, 2, 0, a), from).unwrap();
                            sock.send_to(&fragment(0x42, 2, 1, b), from).unwrap();
                        }
                    } else {
                        // Unknown or stale challenge (including
                        // NO_CHALLENGE): issue ours. When info_ch and
                        // player_ch differ this re-challenges a PLAYER
                        // request that carried the rotated-out challenge.
                        sock.send_to(&challenge_msg(player_ch), from).unwrap();
                    }
                }
                _ => {}
            }
        }
    });
    match rx.recv().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        std::net::SocketAddr::V6(_) => unreachable!(),
    }
}

fn refresh(target: SocketAddrV4) -> daemon::RefreshData {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(TIMEOUT)).unwrap();
    daemon::refresh_once(&sock, target, "test").expect("refresh failed")
}

#[test]
fn refresh_plain() {
    let target = spawn_fake(0x1111_2222, 0x1111_2222, 1);
    let data = refresh(target);
    assert_eq!(data.challenge, Some(0x1111_2222));
    assert_eq!(data.info.unwrap(), info_response());
    assert_eq!(data.player.unwrap(), player_response());
}

#[test]
fn refresh_fragmented_player() {
    let target = spawn_fake(0x3333_4444, 0x3333_4444, 2);
    let data = refresh(target);
    assert_eq!(data.challenge, Some(0x3333_4444));
    assert_eq!(data.info.unwrap(), info_response());
    // Fragments reassembled into one datagram starting with the magic.
    assert_eq!(data.player.unwrap(), player_response());
}

#[test]
fn refresh_challenge_rotation() {
    let target = spawn_fake(0xAAAA_BBBB, 0xCCCC_DDDD, 1);
    let data = refresh(target);
    // Newest challenge wins; both payloads stay servable under it.
    assert_eq!(data.challenge, Some(0xCCCC_DDDD));
    assert_eq!(data.info.unwrap(), info_response());
    assert_eq!(data.player.unwrap(), player_response());
}

#[test]
fn merge_zeroes_tails() {
    let old = a2s_protocol::CacheEntry {
        info: [0xAA; MAX_PAYLOAD],
        info_len: MAX_PAYLOAD as u16,
        player: [0xBB; MAX_PAYLOAD],
        player_len: MAX_PAYLOAD as u16,
        ..Default::default()
    };

    let data = daemon::RefreshData {
        challenge: Some(7),
        info: Some(info_response()),
        player: None, // failed half keeps the old bytes
    };
    let e = daemon::merge_entry(&old, &data, 12345);
    assert_eq!(e.challenge, 7);
    assert_eq!(e.ts_challenge, 12345);
    assert_eq!(e.info_len as usize, info_response().len());
    assert_eq!(&e.info[..info_response().len()], &info_response()[..]);
    assert_eq!(
        &e.info[info_response().len()..],
        &[0u8; MAX_PAYLOAD][info_response().len()..]
    );
    assert_eq!(e.ts_info, 12345);
    // Untouched half preserved verbatim.
    assert_eq!(e.player_len, MAX_PAYLOAD as u16);
    assert_eq!(e.player, [0xBB; MAX_PAYLOAD]);
    assert_eq!(e.ts_player, 0);
}

#[test]
fn example_config_parses() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/a2scache.toml");
    let (cfg, backends) = daemon::load_config(&path).expect("example config must parse");
    assert!(backends.len() >= 2, "want 2+ backends");
    assert_eq!(cfg.defaults.ttl_secs, 30);
    assert_eq!(cfg.defaults.interval_secs, 10);
}
