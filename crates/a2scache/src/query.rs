use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use a2s_protocol::{
    build_info_request, build_info_request_challenged, build_player_request, is_fragment,
    response_type, Reassembler, NO_CHALLENGE, TYPE_CHALLENGE, TYPE_INFO_RESP, TYPE_PLAYER_RESP,
};

use crate::{Error, QueryKind, Result};

const MAX_DGRAM: usize = 65535;

/// Perform the full A2S challenge dance against `addr` and return the final,
/// reassembled response datagram.
pub fn query(addr: &str, kind: QueryKind, timeout: Duration) -> Result<Vec<u8>> {
    let target: SocketAddr = addr.parse().map_err(|_| Error::Addr(addr.to_string()))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(timeout))?;

    let mut first = [0u8; 33];
    let (first_len, rechallenge): (usize, Box<dyn Fn(u32) -> Vec<u8>>) = match kind {
        QueryKind::Info => {
            let n = build_info_request(&mut first).map_err(bad)?;
            (
                n,
                Box::new(|ch: u32| {
                    let mut b = [0u8; 33];
                    build_info_request_challenged(&mut b, ch)
                        .map(|n| b[..n].to_vec())
                        .unwrap()
                }) as Box<dyn Fn(u32) -> Vec<u8>>,
            )
        }
        QueryKind::Players => {
            let n = build_player_request(&mut first, NO_CHALLENGE).map_err(bad)?;
            (
                n,
                Box::new(|ch: u32| {
                    let mut b = [0u8; 9];
                    build_player_request(&mut b, ch)
                        .map(|n| b[..n].to_vec())
                        .unwrap()
                }) as Box<dyn Fn(u32) -> Vec<u8>>,
            )
        }
    };
    let first = first[..first_len].to_vec();

    let resp = dance(&sock, target, first, &rechallenge)?;
    if matches!(
        response_type(&resp),
        Some(TYPE_INFO_RESP) | Some(TYPE_PLAYER_RESP)
    ) {
        Ok(resp)
    } else {
        Err(Error::Bad("malformed final response".into()))
    }
}

/// CLI entry: query and pretty-print the response.
pub fn run(addr: &str, kind: QueryKind, timeout_ms: u64) -> Result<()> {
    let resp = query(addr, kind, Duration::from_millis(timeout_ms))?;
    match response_type(&resp) {
        Some(TYPE_INFO_RESP) => print_info(&resp)?,
        Some(TYPE_PLAYER_RESP) => print_players(&resp)?,
        Some(t) => return Err(Error::Bad(format!("unexpected response type {t:#04x}"))),
        None => return Err(Error::Bad("malformed final response".into())),
    }
    Ok(())
}

fn bad(e: a2s_protocol::Error) -> Error {
    Error::Bad(format!("protocol: {e:?}"))
}

fn dance(
    sock: &UdpSocket,
    target: SocketAddr,
    first: Vec<u8>,
    rechallenge: &dyn Fn(u32) -> Vec<u8>,
) -> Result<Vec<u8>> {
    let mut reasm = Reassembler::new();
    let mut saw_challenge = false;

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
            reasm.push(d).map_err(bad)?;
            if reasm.is_complete() {
                return Ok(reasm.reassembled().unwrap().to_vec());
            }
            continue;
        }

        match response_type(d) {
            Some(TYPE_CHALLENGE) if d.len() >= 9 => {
                if saw_challenge {
                    return Err(Error::Bad("repeated challenge; aborting".into()));
                }
                saw_challenge = true;
                let ch = u32::from_le_bytes([d[5], d[6], d[7], d[8]]);
                let req = rechallenge(ch);
                sock.send_to(&req, target)?;
            }
            Some(TYPE_INFO_RESP) | Some(TYPE_PLAYER_RESP) => return Ok(d.to_vec()),
            Some(t) => return Err(Error::Bad(format!("unexpected response type {t:#04x}"))),
            None => return Err(Error::Bad("malformed response (bad magic)".into())),
        }
    }
}

fn need(buf: &mut &[u8], n: usize, what: &str) -> Result<()> {
    if buf.len() < n {
        return Err(Error::Bad(format!("truncated {what} field")));
    }
    Ok(())
}

fn cstr(buf: &mut &[u8]) -> Result<String> {
    let i = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::Bad("unterminated string".into()))?;
    let s = String::from_utf8_lossy(&buf[..i]).into_owned();
    *buf = &buf[i + 1..];
    Ok(s)
}

fn take<'a>(buf: &mut &'a [u8], n: usize, what: &str) -> Result<&'a [u8]> {
    need(buf, n, what)?;
    let out = &buf[..n];
    *buf = &buf[n..];
    Ok(out)
}

fn u8v(buf: &mut &[u8]) -> Result<u8> {
    let b = take(buf, 1, "byte")?;
    Ok(b[0])
}

fn u16le(buf: &mut &[u8]) -> Result<u16> {
    let b = take(buf, 2, "u16")?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32le(buf: &mut &[u8]) -> Result<u32> {
    let b = take(buf, 4, "u32")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn print_info(b: &[u8]) -> Result<()> {
    let mut rest = &b[5..];
    let proto = u8v(&mut rest)?;
    let name = cstr(&mut rest)?;
    let map = cstr(&mut rest)?;
    let folder = cstr(&mut rest)?;
    let game = cstr(&mut rest)?;
    let appid = u16le(&mut rest)?;
    let players = u8v(&mut rest)?;
    let max = u8v(&mut rest)?;
    let bots = u8v(&mut rest)?;
    let stype = cstr(&mut rest)?;
    let env = cstr(&mut rest)?;
    let vis = cstr(&mut rest)?;
    let vac = u8v(&mut rest)?;
    let version = cstr(&mut rest)?;

    println!("A2S_INFO:");
    println!("  protocol : {proto}");
    println!("  name     : {name}");
    println!("  map      : {map}");
    println!("  folder   : {folder}");
    println!("  game     : {game}");
    println!("  appid    : {appid}");
    println!("  players  : {players}/{max} (bots: {bots})");
    println!("  type     : {stype}");
    println!("  env      : {env}");
    println!("  visibility: {vis}");
    println!("  vac      : {vac}");
    println!("  version  : {version}");
    Ok(())
}

fn print_players(b: &[u8]) -> Result<()> {
    let mut rest = &b[5..];
    let count = u8v(&mut rest)?;
    println!("A2S_PLAYER ({count}):");
    for _ in 0..count {
        if rest.is_empty() {
            return Err(Error::Bad("player list truncated".into()));
        }
        let idx = u8v(&mut rest)?;
        let name = cstr(&mut rest)?;
        let sb = take(&mut rest, 4, "score")?;
        let score = i32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
        let time = u32le(&mut rest)?;
        println!("  {idx:<3} {name:<24} {score:>5}  {time}s");
    }
    Ok(())
}
