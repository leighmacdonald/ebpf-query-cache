//! Query-client tests against a fake TF2 responder (challenge-first dance).
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use a2scache::QueryKind;
use a2scache::query;

const CH: u32 = 0x7856_3412;

/// Expected S2C_INFO response body.
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

/// Expected S2C_PLAYER response: one player.
fn player_response() -> Vec<u8> {
    let mut r = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0x01];
    r.push(0); // index
    r.extend_from_slice(b"Player1\0");
    r.extend(1234i32.to_le_bytes()); // score
    r.extend(600u32.to_le_bytes()); // time
    r
}

fn challenge() -> Vec<u8> {
    let mut r = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x41];
    r.extend(CH.to_le_bytes());
    r
}

/// Fake server: replies with a challenge to the first request, then with the
/// final response once the request carries the challenge. Records all requests
/// it receives.
fn spawn_fake_server(
    kind: QueryKind,
    final_resp: Vec<u8>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
) -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        tx.send(sock.local_addr().unwrap()).unwrap();

        loop {
            let mut buf = [0u8; 2048];
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => break,
            };
            let req = buf[..n].to_vec();
            seen.lock().unwrap().push(req.clone());

            let challenged = if kind == QueryKind::Info {
                req.len() == 29
            } else {
                req.len() == 9 && u32::from_le_bytes([req[5], req[6], req[7], req[8]]) == CH
            };
            if challenged {
                sock.send_to(&final_resp, from).unwrap();
                break;
            } else {
                sock.send_to(&challenge(), from).unwrap();
            }
        }
    });
    rx.recv().unwrap()
}

#[test]
fn info_dance() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_fake_server(QueryKind::Info, info_response(), seen.clone());

    let resp = query::query(&addr.to_string(), QueryKind::Info, Duration::from_secs(5))
        .expect("query failed");
    assert_eq!(resp, info_response());

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "expected 2 requests, got {seen:?}");
    // First request: plain A2S_INFO.
    assert_eq!(&seen[0][4..], b"TSource Engine Query\0");
    assert_eq!(seen[0].len(), 25);
    // Second request: challenged, carrying our challenge LE.
    assert_eq!(seen[1].len(), 29);
    assert_eq!(
        u32::from_le_bytes([seen[1][25], seen[1][26], seen[1][27], seen[1][28]]),
        CH
    );
}

#[test]
fn player_dance() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_fake_server(QueryKind::Players, player_response(), seen.clone());

    let resp = query::query(
        &addr.to_string(),
        QueryKind::Players,
        Duration::from_secs(5),
    )
    .expect("query failed");
    assert_eq!(resp, player_response());

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0][4], 0x55);
    // First player request uses the no-challenge sentinel.
    assert_eq!(
        u32::from_le_bytes([seen[0][5], seen[0][6], seen[0][7], seen[0][8]]),
        0xFFFF_FFFF
    );
    assert_eq!(
        u32::from_le_bytes([seen[1][5], seen[1][6], seen[1][7], seen[1][8]]),
        CH
    );
}
