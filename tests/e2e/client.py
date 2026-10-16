#!/usr/bin/env python3
"""Raw A2S client for the e2e harness.

Performs the full challenge dance over a fresh UDP socket and captures the
shape of the received datagrams (how many, sizes, whether the final answer
arrived as FE fragments or a single datagram). Modes:

  info    <ip:port> --expect-name N [--players N/M]
  players <ip:port> --count N --name-prefix P [--expect-single]
  burst   <ip:port> COUNT        # fire COUNT unchallenged INFO requests
  timeout <ip:port>              # expect no usable answer within the timeout

Exit 0 on success, 1 on assertion failure, 2 on protocol/timeout failure.
"""

import argparse
import socket
import struct
import sys
import time

MAGIC = b"\xff\xff\xff\xff"
FRAG = b"\xfe\xff\xff\xff"


def build_info(ch=None) -> bytes:
    d = MAGIC + b"\x54" + b"Source Engine Query\x00"
    if ch is not None:
        d += struct.pack("<I", ch)
    return d


def build_player(ch: int) -> bytes:
    return MAGIC + b"\x55" + struct.pack("<I", ch)


def cstr(buf: bytes) -> tuple[str, bytes]:
    i = buf.index(0)
    return buf[:i].decode("utf-8", "replace"), buf[i + 1 :]


def dance(sock, addr, first, rechallenge, expect, timeout):
    """Run the dance; return (final_payload, sizes, saw_fragment) or (None, sizes, saw)."""
    sizes = []
    saw_frag = False
    sock.sendto(first, addr)
    deadline = time.monotonic() + timeout
    reasm = {}
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, sizes, saw_frag
        sock.settimeout(remaining)
        try:
            d, fromaddr = sock.recvfrom(65535)
        except socket.timeout:
            return None, sizes, saw_frag
        if fromaddr != addr:
            continue
        sizes.append(len(d))

        if d[:4] == FRAG and len(d) >= 12:
            saw_frag = True
            _fid, total, num, _size = struct.unpack("<IBBH", d[4:12])
            reasm[num] = d[12:]
            if len(reasm) == total:
                full = b"".join(reasm[i] for i in range(total))
                if len(full) >= 5 and full[:4] == MAGIC and full[4] == expect:
                    return full, sizes, saw_frag
                return None, sizes, saw_frag
            continue

        if len(d) < 5 or d[:4] != MAGIC:
            continue
        ty = d[4]
        if ty == 0x41 and len(d) >= 9:
            ch = struct.unpack("<I", d[5:9])[0]
            sock.sendto(rechallenge(ch), addr)
        elif ty == expect:
            return d, sizes, saw_frag
        else:
            return None, sizes, saw_frag


def new_sock() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)
    return s


def fail(msg: str) -> None:
    print(f"CLIENT-FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["info", "players", "burst", "timeout"])
    ap.add_argument("addr", help="ip:port")
    ap.add_argument("count", nargs="?", type=int, help="burst count")
    ap.add_argument("--expect-name", default=None)
    ap.add_argument("--expect-single", action="store_true")
    ap.add_argument("--players-count", type=int, default=None)
    ap.add_argument("--name-prefix", default=None)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument(
        "--hex-out",
        default=None,
        help="write the final response as hex to this file (for byte comparisons)",
    )
    args = ap.parse_args()

    addr = args.addr.rsplit(":", 1)
    if len(addr) != 2:
        fail(f"bad address {args.addr}")
    ip, port = addr[0], int(addr[1])
    target = (ip, port)

    if args.mode == "burst":
        n = args.count or 0
        if n <= 0:
            fail("burst count must be > 0")
        s = new_sock()
        req = build_info()
        for _ in range(n):
            s.sendto(req, target)
        print(f"burst-sent {n}")
        return

    if args.mode == "timeout":
        sock = new_sock()
        final, _sizes, _fr = dance(
            sock, target, build_info(), lambda ch: build_info(ch), 0x49, args.timeout
        )
        if final is not None:
            fail(f"expected timeout but got an answer ({len(final)} B)")
        print("timeout-ok")
        return

    sock = new_sock()
    if args.mode == "info":
        final, sizes, saw_frag = dance(
            sock, target, build_info(), lambda ch: build_info(ch), 0x49, args.timeout
        )
    else:
        final, sizes, saw_frag = dance(
            sock,
            target,
            build_player(0xFFFFFFFF),
            lambda ch: build_player(ch),
            0x44,
            args.timeout,
        )
    if final is None:
        fail(f"no {args.mode} answer within {args.timeout}s (datagrams seen: {sizes})")
    if args.hex_out:
        with open(args.hex_out, "w") as f:
            f.write(final.hex())

    if args.expect_single and saw_frag:
        fail(f"expected a single-datagram answer, saw FE fragments (sizes {sizes})")
    if args.expect_single and len(sizes) != 2:
        # modern dance: challenge + one final datagram
        fail(f"expected challenge + single final datagram, got sizes {sizes}")

    if args.mode == "info":
        rest = final[6:]  # skip magic + type + protocol
        name, rest = cstr(rest)
        map_name, rest = cstr(rest)
        _folder, rest = cstr(rest)
        _game, rest = cstr(rest)
        if len(rest) < 5:
            fail("INFO response truncated at appid/players")
        appid = struct.unpack("<H", rest[:2])[0]
        nplayers, nmax, _bots = rest[2], rest[3], rest[4]
        rest = rest[5:]
        _stype, rest = cstr(rest)
        _env, rest = cstr(rest)
        _vis, rest = cstr(rest)
        _vac = rest[0] if rest else 0
        if rest:
            version, _rest = cstr(rest)
        else:
            version = ""
        print(
            f"info-ok name={name!r} map={map_name!r} appid={appid} players={nplayers}/{nmax} "
            f"version={version!r} sizes={sizes}"
        )
        if args.expect_name and name != args.expect_name:
            fail(f"expected name {args.expect_name!r}, got {name!r}")
        if appid != 440:
            fail(f"expected appid 440, got {appid}")
        if args.players_count is not None and nplayers != args.players_count:
            fail(f"expected {args.players_count} players, got {nplayers}")
    else:
        count = final[5]
        rest = final[6:]
        names = []
        for _ in range(count):
            if len(rest) < 1:
                fail("player list truncated")
            rest = rest[1:]  # index
            name, rest = cstr(rest)
            if len(rest) < 8:
                fail("player entry truncated")
            names.append(name)
            rest = rest[8:]  # score + time
        first = names[0] if names else None
        last = names[-1] if names else None
        print(f"players-ok count={count} sizes={sizes} first={first!r} last={last!r}")
        if args.players_count is not None and count != args.players_count:
            fail(f"expected {args.players_count} players, got {count}")
        if args.name_prefix is not None:
            want = [f"{args.name_prefix}{i:02d}" for i in range(count)]
            if names != want:
                fail(f"player names mismatch: got {names[:3]}... want {want[:3]}...")


if __name__ == "__main__":
    main()
