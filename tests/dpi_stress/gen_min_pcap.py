#!/usr/bin/env python3
"""Generate a PCAP with >=10_000 Ethernet/IPv4/TCP (PSH|ACK) frames carrying HTTP GET.

Valid IPv4 header checksum and TCP checksum (pseudo-header). stdlib only; for tcpreplay +
`dpi-ingest-validate` / full probe ingress scaling tests.
"""
from __future__ import annotations

import struct
import sys
import time

PCAP_MAGIC = 0xA1B2C3D4
DLT_EN10MB = 1
MIN_PKT_COUNT = 10_000


def be16(x: int) -> bytes:
    return struct.pack("!H", x & 0xFFFF)


def be32(x: int) -> bytes:
    return struct.pack("!I", x & 0xFFFFFFFF)


def ipv4_checksum(hdr: bytes) -> int:
    if len(hdr) % 2 == 1:
        hdr += b"\x00"
    s = sum(struct.unpack(f"!{len(hdr) // 2}H", hdr))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def tcp_checksum(src: bytes, dst: bytes, proto: int, segment: bytes) -> int:
    pseudo = src + dst + bytes([0, proto, 0]) + be16(len(segment))
    return ipv4_checksum(pseudo + segment)


def build_frame(ident: int, tcp_seq: int) -> bytes:
    http = b"GET / HTTP/1.1\r\nHost: stress\r\n\r\n"
    sport, dport = 49152, 80
    ack = 0x2000

    eth = bytes.fromhex("ffffffffffff") + bytes.fromhex("020406080a0c") + be16(0x0800)

    src = bytes([10, 0, 0, 1])
    dst = bytes([10, 0, 0, 2])
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 20 + len(http)
    ip_hdr = bytes([ver_ihl, 0]) + be16(total_len) + be16(ident & 0xFFFF) + be16(0x4000)
    ip_hdr += bytes([64, 6]) + be16(0)
    ip_hdr += src + dst
    csum = ipv4_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + be16(csum) + ip_hdr[12:]

    off_res = (5 << 4) | 0
    flags = 0x18  # PSH | ACK
    tcp_hdr = be16(sport) + be16(dport) + be32(tcp_seq) + be32(ack)
    tcp_hdr += bytes([off_res, flags]) + be16(0xFFFF) + be16(0) + be16(0)
    tcp_seg = tcp_hdr + http
    tcs = tcp_checksum(src, dst, 6, tcp_seg)
    tcp_hdr = tcp_hdr[:16] + be16(tcs) + tcp_hdr[18:]

    payload = eth + ip_hdr + tcp_hdr + http
    if len(payload) < 60:
        payload += b"\x00" * (60 - len(payload))
    return payload


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    count = MIN_PKT_COUNT
    if len(sys.argv) > 2:
        count = max(MIN_PKT_COUNT, int(sys.argv[2]))

    ts = int(time.time())
    records = []
    for i in range(count):
        frame = build_frame(ident=0x5000 + (i & 0xFFFF), tcp_seq=0x1000 + i * 256)
        records.append(struct.pack("<IIII", ts, 0, len(frame), len(frame)) + frame)

    glob = struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, DLT_EN10MB)
    with open(out, "wb") as f:
        f.write(glob)
        for r in records:
            f.write(r)

    print(
        out,
        "packets",
        count,
        "Ethernet/IPv4/TCP PSH|ACK + HTTP GET, valid IP+TCP checksums",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
