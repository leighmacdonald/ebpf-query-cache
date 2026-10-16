//! TF2 (Source 1) A2S wire codec and the `#[repr(C)]` layouts shared between
//! the eBPF program and the userspace daemon.
//!
//! Wire format (all UDP datagrams, little-endian):
//!
//! - A2S_INFO request:  `FF FF FF FF 54 "Source Engine Query\0"` (+4B challenge)
//! - A2S_PLAYER request: `FF FF FF FF 55 <challenge:4>`
//! - S2C_CHALLENGE:      `FF FF FF FF 41 <challenge:4>`
//! - A2S_INFO response:  `FF FF FF FF 49 protocol:1 name\0 map\0 ...`
//! - A2S_PLAYER response: `FF FF FF FF 44 count:1 {index:1 name\0 score:4 time:4}*`
//!
//! Oversized responses are split across datagrams:
//! `FE FF FF FF id:4 total:1 number:1 size:2 <payload chunk>`; the
//! reassembled payload chunks (sorted by number) form one normal datagram.
#![no_std]

/// Maximum cached payload per (server, query type). Larger responses are not
/// cached and always pass through to the backend.
pub const MAX_PAYLOAD: usize = 2048;

pub const MAGIC: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// Value of the 4-byte LE header of a split-fragment datagram (-2).
pub const SPLIT_MAGIC: u32 = 0xFFFF_FFFE;

pub const TYPE_CHALLENGE: u8 = 0x41;
pub const TYPE_PLAYER_RESP: u8 = 0x44;
pub const TYPE_INFO_RESP: u8 = 0x49;
pub const TYPE_INFO_REQ: u8 = 0x54;
pub const TYPE_PLAYER_REQ: u8 = 0x55;

/// Challenge value meaning "request a challenge".
pub const NO_CHALLENGE: u32 = 0xFFFF_FFFF;

pub const INFO_BODY: &[u8; 20] = b"Source Engine Query\0";

pub const INFO_REQ_LEN: usize = MAGIC.len() + 1 + INFO_BODY.len();
pub const INFO_REQ_LEN_CHALLENGED: usize = INFO_REQ_LEN + 4;
pub const PLAYER_REQ_LEN: usize = MAGIC.len() + 1 + 4;
pub const CHALLENGE_RESP_LEN: usize = MAGIC.len() + 1 + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BufferTooSmall,
    BadMagic,
    BadFragment,
    TooLarge,
}

fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// True if `dgram` is a split-fragment datagram (`FE FF FF FF` header).
pub fn is_fragment(dgram: &[u8]) -> bool {
    dgram.len() >= 4 && u32le(&dgram[0..4]) == SPLIT_MAGIC
}

/// Validate the `FF FF FF FF` magic and return the type byte, if present.
pub fn response_type(dgram: &[u8]) -> Option<u8> {
    if dgram.len() < 5 || dgram[0..4] != MAGIC {
        return None;
    }
    Some(dgram[4])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReqKind {
    Info,
    Player,
}

/// Classify a raw UDP payload as an A2S request.
///
/// Returns the request kind plus the challenge (`None` only for an
/// unchallenged A2S_INFO). Returns `None` for anything that is not a
/// well-formed INFO/PLAYER request.
pub fn classify_request(dgram: &[u8]) -> Option<(ReqKind, Option<u32>)> {
    let ty = response_type(dgram)?;
    match ty {
        TYPE_INFO_REQ => {
            if dgram.len() == INFO_REQ_LEN && dgram[5..] == *INFO_BODY {
                Some((ReqKind::Info, None))
            } else if dgram.len() == INFO_REQ_LEN_CHALLENGED && dgram[5..25] == *INFO_BODY {
                Some((ReqKind::Info, Some(u32le(&dgram[25..29]))))
            } else {
                None
            }
        }
        TYPE_PLAYER_REQ if dgram.len() == PLAYER_REQ_LEN => {
            Some((ReqKind::Player, Some(u32le(&dgram[5..9]))))
        }
        _ => None,
    }
}

/// Write an unchallenged A2S_INFO request (25 bytes).
pub fn build_info_request(buf: &mut [u8]) -> Result<usize, Error> {
    if buf.len() < INFO_REQ_LEN {
        return Err(Error::BufferTooSmall);
    }
    buf[..4].copy_from_slice(&MAGIC);
    buf[4] = TYPE_INFO_REQ;
    buf[5..INFO_REQ_LEN].copy_from_slice(INFO_BODY);
    Ok(INFO_REQ_LEN)
}

/// Write an A2S_INFO request with challenge (29 bytes).
pub fn build_info_request_challenged(buf: &mut [u8], challenge: u32) -> Result<usize, Error> {
    let n = build_info_request(buf)?;
    buf[n..n + 4].copy_from_slice(&challenge.to_le_bytes());
    Ok(n + 4)
}

/// Write an A2S_PLAYER request (9 bytes).
pub fn build_player_request(buf: &mut [u8], challenge: u32) -> Result<usize, Error> {
    if buf.len() < PLAYER_REQ_LEN {
        return Err(Error::BufferTooSmall);
    }
    buf[..4].copy_from_slice(&MAGIC);
    buf[4] = TYPE_PLAYER_REQ;
    buf[5..9].copy_from_slice(&challenge.to_le_bytes());
    Ok(PLAYER_REQ_LEN)
}

/// Write an S2C_CHALLENGE response (9 bytes).
pub fn build_challenge_response(buf: &mut [u8], challenge: u32) -> Result<usize, Error> {
    if buf.len() < CHALLENGE_RESP_LEN {
        return Err(Error::BufferTooSmall);
    }
    buf[..4].copy_from_slice(&MAGIC);
    buf[4] = TYPE_CHALLENGE;
    buf[5..9].copy_from_slice(&challenge.to_le_bytes());
    Ok(CHALLENGE_RESP_LEN)
}

/// Reassembles a split (FE FF FF FF) response into one datagram.
///
/// Fragments must arrive in `number` order, which holds for a single UDP
/// socket flow; an out-of-order fragment is rejected and the next refresh
/// cycle re-queries.
pub struct Reassembler {
    id: u32,
    total: u8,
    next: u8,
    len: usize,
    started: bool,
    buf: [u8; MAX_PAYLOAD],
}

impl Reassembler {
    pub const fn new() -> Self {
        Self {
            id: 0,
            total: 0,
            next: 0,
            len: 0,
            started: false,
            buf: [0; MAX_PAYLOAD],
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn is_complete(&self) -> bool {
        self.started && self.next == self.total
    }

    /// The reassembled datagram (only valid while `is_complete()`).
    pub fn reassembled(&self) -> Option<&[u8]> {
        if !self.is_complete() {
            return None;
        }
        Some(&self.buf[..self.len])
    }

    /// Feed one fragment datagram.
    ///
    /// The high bit of `id` marks a compressed A2S_PLAYER payload (used by
    /// Source servers with large player lists); reassembly is identical, and
    /// the cache serves the payload bytes verbatim, so it is accepted here.
    pub fn push(&mut self, dgram: &[u8]) -> Result<(), Error> {
        // FE FF FF FF + id:4 + total:1 + number:1 + size:2
        if dgram.len() < 12 || u32le(&dgram[0..4]) != SPLIT_MAGIC {
            return Err(Error::BadMagic);
        }
        let id = u32le(&dgram[4..8]);
        let total = dgram[8];
        let number = dgram[9];
        if total == 0 || number >= total {
            return Err(Error::BadFragment);
        }
        if !self.started {
            self.id = id;
            self.total = total;
            self.started = true;
        } else if id != self.id || total != self.total {
            return Err(Error::BadFragment);
        }
        if number != self.next {
            return Err(Error::BadFragment);
        }
        let chunk = &dgram[12..];
        if self.len + chunk.len() > MAX_PAYLOAD {
            return Err(Error::TooLarge);
        }
        self.buf[self.len..self.len + chunk.len()].copy_from_slice(chunk);
        self.len += chunk.len();
        self.next += 1;
        Ok(())
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shared map layouts (single source of truth for BPF and userspace).
// ---------------------------------------------------------------------------

/// Pack a (server ip, server port) pair into the cache map key.
pub fn cache_key(ip: u32, port: u16) -> u64 {
    ((u64::from(ip)) << 16) | u64::from(port)
}

pub fn cache_key_unpack(key: u64) -> (u32, u16) {
    ((key >> 16) as u32, (key & 0xFFFF) as u16)
}

/// Per-token-bucket state; `tokens` is in milli-tokens.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateEntry {
    pub tokens: u32,
    pub last_ns: u64,
}

/// Per-backend cache entry. Timestamps are `bpf_ktime_get_ns()`
/// (= `CLOCK_MONOTONIC`) nanoseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    pub challenge: u32,
    pub ts_challenge: u64,
    pub info_len: u16,
    pub _pad0: u16,
    pub ts_info: u64,
    pub player_len: u16,
    pub _pad1: u16,
    pub ts_player: u64,
    pub info: [u8; MAX_PAYLOAD],
    pub player: [u8; MAX_PAYLOAD],
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self {
            challenge: 0,
            ts_challenge: 0,
            info_len: 0,
            _pad0: 0,
            ts_info: 0,
            player_len: 0,
            _pad1: 0,
            ts_player: 0,
            info: [0; MAX_PAYLOAD],
            player: [0; MAX_PAYLOAD],
        }
    }
}

/// Global program configuration, written by the daemon.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub enabled: u32,
    pub ifindex_out: u32,
    pub ttl_ns: u64,
    pub max_payload: u32,
    pub _pad0: u32,
    /// Per-source-IP bucket capacity (milli-tokens).
    pub per_ip_capacity: u32,
    /// Per-source-IP refill rate (milli-tokens per second).
    pub per_ip_refill_per_s: u32,
    pub global_capacity: u32,
    pub global_refill_per_s: u32,
    /// MAC used as source address of synthesized replies (backend MAC).
    pub backend_mac: [u8; 6],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: 1,
            ifindex_out: 0,
            ttl_ns: 30_000_000_000,
            max_payload: MAX_PAYLOAD as u32,
            _pad0: 0,
            per_ip_capacity: 10_000,
            per_ip_refill_per_s: 2_000,
            global_capacity: 200_000,
            global_refill_per_s: 50_000,
            backend_mac: [0; 6],
        }
    }
}

/// Stats counter indices (percpu array of u64).
pub mod stats {
    pub const PASS_THROUGH: u32 = 0;
    pub const SERVED_INFO: u32 = 1;
    pub const SERVED_PLAYER: u32 = 2;
    pub const SENT_CHALLENGE_INFO: u32 = 3;
    pub const SENT_CHALLENGE_PLAYER: u32 = 4;
    pub const DROPPED_RATE_IP: u32 = 5;
    pub const DROPPED_RATE_GLOBAL: u32 = 6;
    pub const DROPPED_STALE: u32 = 7;
    pub const DROPPED_BAD_CHALLENGE: u32 = 8;
    pub const DROPPED_TOO_LARGE: u32 = 9;
    pub const DROPPED_REWRITE: u32 = 10;
    pub const NON_A2S: u32 = 11;
    pub const UNKNOWN_KEY: u32 = 12;
    pub const DROPPED_REWRITE_GUARD: u32 = 13;
    pub const DROPPED_REWRITE_TAIL: u32 = 14;
    pub const DROPPED_REWRITE_HDR: u32 = 15;
    pub const DROPPED_REWRITE_PAYLOAD: u32 = 16;
    pub const DROPPED_REWRITE_REDIRECT: u32 = 17;
    pub const COUNT: usize = 18;
}

const _: () = {
    assert!(core::mem::size_of::<RateEntry>() == 16);
    assert!(core::mem::align_of::<RateEntry>() == 8);
    assert!(core::mem::size_of::<CacheEntry>() == 48 + 2 * MAX_PAYLOAD);
    assert!(core::mem::align_of::<CacheEntry>() == 8);
    assert!(core::mem::size_of::<Config>() == 48);
    assert!(core::mem::align_of::<Config>() == 8);
    const {
        assert!(INFO_REQ_LEN == 25);
        assert!(INFO_REQ_LEN_CHALLENGED == 29);
        assert!(PLAYER_REQ_LEN == 9);
        assert!(CHALLENGE_RESP_LEN == 9);
    }
};

/// aya userspace marker impls (host builds only).
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for Config {}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for CacheEntry {}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::prelude::v1::*;

    fn dgram(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    #[test]
    fn info_request_bytes() {
        let mut buf = [0u8; 64];
        let n = build_info_request(&mut buf).unwrap();
        assert_eq!(n, 25);
        assert_eq!(
            &buf[..n],
            &[
                0xFF, 0xFF, 0xFF, 0xFF, 0x54, b'S', b'o', b'u', b'r', b'c', b'e', b' ', b'E', b'n',
                b'g', b'i', b'n', b'e', b' ', b'Q', b'u', b'e', b'r', b'y', 0x00
            ]
        );

        let n = build_info_request_challenged(&mut buf, 0x0102_0304).unwrap();
        assert_eq!(n, 29);
        assert_eq!(&buf[25..29], &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn player_request_bytes() {
        let mut buf = [0u8; 16];
        let n = build_player_request(&mut buf, NO_CHALLENGE).unwrap();
        assert_eq!(n, 9);
        assert_eq!(
            &buf[..9],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x55, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn challenge_response_bytes() {
        let mut buf = [0u8; 16];
        let n = build_challenge_response(&mut buf, 42).unwrap();
        assert_eq!(n, 9);
        assert_eq!(&buf[..9], &[0xFF, 0xFF, 0xFF, 0xFF, 0x41, 42, 0, 0, 0]);
    }

    #[test]
    fn classify_info_variants() {
        let plain = dgram(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0x54, b'S', b'o', b'u', b'r', b'c', b'e', b' ', b'E', b'n',
            b'g', b'i', b'n', b'e', b' ', b'Q', b'u', b'e', b'r', b'y', 0x00,
        ]);
        assert_eq!(classify_request(&plain), Some((ReqKind::Info, None)));

        let mut challenged = plain.clone();
        challenged.extend_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            classify_request(&challenged),
            Some((ReqKind::Info, Some(7)))
        );

        // Corrupt body.
        let mut bad = plain.clone();
        bad[5] = b'X';
        assert_eq!(classify_request(&bad), None);

        // Wrong length.
        let short = &plain[..24];
        assert_eq!(classify_request(short), None);
    }

    #[test]
    fn classify_player() {
        let req = dgram(&[0xFF, 0xFF, 0xFF, 0xFF, 0x55, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(
            classify_request(&req),
            Some((ReqKind::Player, Some(0x4433_2211)))
        );
        assert_eq!(classify_request(&req[..8]), None);
    }

    #[test]
    fn classify_rejects_other_types() {
        let resp = dgram(&[0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x31]);
        assert_eq!(classify_request(&resp), None);
        let fragment = dgram(&[0xFE, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 2, 0, 0, 0, 0xAA]);
        assert_eq!(classify_request(&fragment), None);
        assert!(is_fragment(&fragment));
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

    #[test]
    fn reassembly_single_fragment() {
        let inner = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x49, 0x31, b'h', b'i', 0];
        let mut r = Reassembler::new();
        r.push(&fragment(0x1234, 1, 0, &inner)).unwrap();
        assert!(r.is_complete());
        assert_eq!(r.reassembled().unwrap(), &inner[..]);
    }

    #[test]
    fn reassembly_multi_fragment() {
        let mut inner: Vec<u8> = (0..600u16).map(|i| (i % 251) as u8).collect();
        inner[0..5].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x49]);
        let (a, b) = inner.split_at(300);
        let mut r = Reassembler::new();
        assert!(!r.is_complete());
        r.push(&fragment(9, 2, 0, a)).unwrap();
        assert!(!r.is_complete());
        r.push(&fragment(9, 2, 1, b)).unwrap();
        assert!(r.is_complete());
        assert_eq!(r.reassembled().unwrap(), &inner[..]);
        assert_eq!(response_type(r.reassembled().unwrap()), Some(0x49));
    }

    #[test]
    fn reassembly_rejects_mismatch() {
        // Id changes after the first fragment.
        let mut r = Reassembler::new();
        r.push(&fragment(1, 2, 0, &[0xFF; 10])).unwrap();
        assert_eq!(
            r.push(&fragment(99, 2, 1, &[0; 10])),
            Err(Error::BadFragment)
        );

        // Fragment number not equal to the next expected one.
        let mut r = Reassembler::new();
        r.push(&fragment(1, 2, 0, &[0xFF; 10])).unwrap();
        assert_eq!(
            r.push(&fragment(1, 2, 0, &[0; 10])),
            Err(Error::BadFragment)
        );
        assert_eq!(r.push(&fragment(1, 2, 1, &[0; 10])), Ok(()));

        // Compressed id (high bit set) is accepted; reassembly is identical.
        let mut expected = vec![0xAA; 10];
        expected.extend([0xBB; 10]);
        let mut r = Reassembler::new();
        r.push(&fragment(0x8000_0001, 2, 0, &[0xAA; 10])).unwrap();
        r.push(&fragment(0x8000_0001, 2, 1, &[0xBB; 10])).unwrap();
        assert!(r.is_complete());
        assert_eq!(r.reassembled().unwrap(), &expected[..]);

        // Oversize.
        let big = vec![0u8; MAX_PAYLOAD + 1];
        let mut r = Reassembler::new();
        assert_eq!(r.push(&fragment(1, 1, 0, &big)), Err(Error::TooLarge));

        // Bad magic / too short.
        let mut r = Reassembler::new();
        assert_eq!(
            r.push(&[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 1, 0]),
            Err(Error::BadMagic)
        );
    }

    #[test]
    fn cache_key_roundtrip() {
        let k = cache_key(0xC0A8_0164, 27015);
        assert_eq!(cache_key_unpack(k), (0xC0A8_0164, 27015));
    }

    #[test]
    fn layout_offsets() {
        use core::mem::offset_of;
        assert_eq!(offset_of!(CacheEntry, challenge), 0);
        assert_eq!(offset_of!(CacheEntry, ts_challenge), 8);
        assert_eq!(offset_of!(CacheEntry, info_len), 16);
        assert_eq!(offset_of!(CacheEntry, ts_info), 24);
        assert_eq!(offset_of!(CacheEntry, player_len), 32);
        assert_eq!(offset_of!(CacheEntry, ts_player), 40);
        assert_eq!(offset_of!(CacheEntry, info), 48);
        assert_eq!(offset_of!(CacheEntry, player), 48 + MAX_PAYLOAD);
        assert_eq!(offset_of!(Config, backend_mac), 40);
    }
}
