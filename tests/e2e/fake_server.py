#!/usr/bin/env python3
"""Fake TF2 (Source 1) A2S backend for the e2e harness.

Implements the modern challenge-first dance:

- A2S_INFO (54): unchallenged (25 B)  -> S2C_CHALLENGE (41)
                 challenged  (29 B)    -> A2S_INFO (49) if the challenge
                                          matches, re-challenge (41) otherwise
- A2S_PLAYER (55): 0xFFFFFFFF         -> S2C_CHALLENGE (41)
                 matching challenge    -> A2S_PLAYER (44)
                 anything else         -> S2C_CHALLENGE (41)

With --fragment, 44 responses are split into FE FF FF FF datagrams of at
most --chunk bytes (the reassembled payload still starts with
FF FF FF FF). Each logical 49/44 answer increments the counter file so the
runner can prove the BPF cache hid queries from the backend.
"""

import argparse
import struct
import socket


def cstr(b: bytes) -> bytes:
    return b + b"\x00"


def info_response(name: str, players: int, maxplayers: int) -> bytes:
    return (
        b"\xff\xff\xff\xff\x49\x0b"
        + cstr(name.encode())
        + cstr(b"de_dust2")
        + cstr(b"tf")
        + cstr(b"tf")
        + struct.pack("<H", 440)
        + bytes([players, maxplayers, 0])
        + cstr(b"dedicated")
        + cstr(b"win32")
        + cstr(b"")
        + bytes([1])
        + cstr(b"1.11.2")
    )


def player_response(prefix: str, players: int) -> bytes:
    out = b"\xff\xff\xff\xff\x44" + bytes([players])
    for i in range(players):
        name = f"{prefix}{i:02d}".encode()
        out += (
            bytes([i])
            + cstr(name)
            + struct.pack("<i", 1000 + i)
            + struct.pack("<I", 60 * (i + 1))
        )
    return out


def fragments(dgram: bytes, chunk: int, frag_id: int) -> list[bytes]:
    total = (len(dgram) + chunk - 1) // chunk
    if total > 255:
        raise SystemExit(f"too many fragments: {total}")
    frags = []
    for num in range(total):
        piece = dgram[num * chunk : (num + 1) * chunk]
        frags.append(
            b"\xfe\xff\xff\xff"
            + struct.pack("<I", frag_id)
            + bytes([total, num])
            + struct.pack("<H", len(piece))
            + piece
        )
    return frags


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True, help="address to bind (e.g. 10.200.1.1)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True, help="A2S_INFO server name")
    ap.add_argument("--players", type=int, default=2)
    ap.add_argument("--maxplayers", type=int, default=16)
    ap.add_argument("--player-prefix", default="P", help="player name prefix")
    ap.add_argument(
        "--fragment", action="store_true", help="split 44 responses into FE fragments"
    )
    ap.add_argument(
        "--chunk", type=int, default=300, help="fragment chunk size in bytes"
    )
    ap.add_argument(
        "--counter", required=True, help="file holding the served-answer count"
    )
    args = ap.parse_args()

    challenge = 0xC0FFEE00 + args.port
    info = info_response(args.name, args.players, args.maxplayers)
    players = player_response(args.player_prefix, args.players)
    frag_id = 0xA0000000 + args.port

    def count() -> int:
        try:
            with open(args.counter) as f:
                return int(f.read().strip() or 0)
        except FileNotFoundError:
            return 0

    def note_answer() -> None:
        n = count() + 1
        with open(args.counter, "w") as f:
            f.write(str(n))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))
    print(
        f"fake server {args.name} on {args.bind}:{args.port} "
        f"(players={args.players} fragment={args.fragment})",
        flush=True,
    )

    while True:
        data, addr = sock.recvfrom(65535)
        if len(data) < 5 or data[:4] != b"\xff\xff\xff\xff":
            continue
        ty = data[4]

        if ty == 0x54 and len(data) == 25:
            sock.sendto(b"\xff\xff\xff\xff\x41" + struct.pack("<I", challenge), addr)
        elif ty == 0x54 and len(data) == 29:
            if struct.unpack("<I", data[25:29])[0] == challenge:
                sock.sendto(info, addr)
                note_answer()
            else:
                sock.sendto(
                    b"\xff\xff\xff\xff\x41" + struct.pack("<I", challenge), addr
                )
        elif ty == 0x55 and len(data) == 9:
            ch = struct.unpack("<I", data[5:9])[0]
            if ch == challenge:
                if args.fragment:
                    for frag in fragments(players, args.chunk, frag_id):
                        sock.sendto(frag, addr)
                else:
                    sock.sendto(players, addr)
                note_answer()
            else:
                sock.sendto(
                    b"\xff\xff\xff\xff\x41" + struct.pack("<I", challenge), addr
                )


if __name__ == "__main__":
    main()
