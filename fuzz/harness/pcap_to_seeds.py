#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Convert captured DICOM traffic into AFLNet .raw seeds.

AFLNet replays a *client request stream* against a live SCP and mutates
within it, so a good seed is the exact byte sequence one peer sent the
other across a single TCP connection. The synthetic serializer
(seed_serializer.py) only emits the canonical DIMSE flows we hand-code;
this tool complements it by harvesting *real* exchanges — full
association negotiation, multi-PDU C-STORE datasets, real transfer-syntax
handling — straight out of a packet capture.

Given a pcap and the SCP's TCP port, it reassembles every client->server
stream and writes one .raw seed per stream. The DICOM PDU header
(1B type + 1B reserved + 4B big-endian length) is AFLNet's `-P DICOM`
message boundary, so each seed needs no further framing.

Capture sources that work well here:
  * scripts/capture_net_seeds.sh — a fresh, valid DCMTK exchange
  * the *.pcap artifacts the security-test workflows already upload —
    attack traffic makes useful, already-mutated extra seeds

Usage:
    pcap_to_seeds.py CAPTURE.pcap --port 11112 --out fuzz/seeds/net-storescp
"""
import argparse
import hashlib
import sys
from pathlib import Path

# DICOM upper-layer PDU type bytes (PS3.8 9.3). A client->server stream
# legitimately opens with one of these.
PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}


def _load_scapy():
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import rdpcap
    except ImportError as exc:  # pragma: no cover - dependency guard
        sys.exit(f"[pcap_to_seeds] scapy is required (pip install -e .): {exc}")
    return rdpcap, IP, IPv6, TCP


def reassemble(packets, TCP) -> bytes:
    """Concatenate one TCP direction's payloads in sequence order.

    Best-effort: dedupes pure retransmits and trims overlapping ones. This
    is adequate for the in-order loopback captures CI produces; it is not a
    full TCP stack and does not handle sequence-number wraparound.
    """
    data = bytearray()
    next_seq = None
    for pkt in sorted(packets, key=lambda p: p[TCP].seq):
        segment = bytes(pkt[TCP].payload)
        if not segment:
            continue
        seq = pkt[TCP].seq
        if next_seq is None:
            next_seq = seq
        end = seq + len(segment)
        if end <= next_seq:
            continue  # wholly retransmitted — already captured
        if seq < next_seq:
            segment = segment[next_seq - seq:]  # trim overlapping retransmit
        data += segment
        next_seq = end
    return bytes(data)


def pdu_framing(blob: bytes):
    """Walk the PDU headers of ``blob``.

    Returns ``(pdu_count, clean)`` where ``clean`` is True when the PDU
    chain consumes the buffer exactly — i.e. the seed is well-framed DICOM.
    """
    offset, count = 0, 0
    while offset + 6 <= len(blob):
        length = int.from_bytes(blob[offset + 2:offset + 6], "big")
        offset += 6 + length
        count += 1
    return count, offset == len(blob)


def extract_streams(packets, server_port, IP, IPv6, TCP):
    """Group client->server packets by TCP 4-tuple, ordered by first sight."""
    streams = {}
    order = []
    for pkt in packets:
        if TCP not in pkt:
            continue
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            continue
        if pkt[TCP].dport != server_port:
            continue  # keep only the client->server direction
        key = (src, pkt[TCP].sport, dst, pkt[TCP].dport)
        if key not in streams:
            streams[key] = []
            order.append(key)
        streams[key].append(pkt)
    return [(key, streams[key]) for key in order]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert captured DICOM traffic into AFLNet .raw seeds.")
    parser.add_argument("pcap", type=Path, help="packet capture to read")
    parser.add_argument("--port", type=int, default=11112,
                        help="SCP TCP port (client->server direction)")
    parser.add_argument("--out", type=Path,
                        default=Path("fuzz/seeds/net-storescp"),
                        help="directory to write .raw seeds into")
    parser.add_argument("--prefix", default="pcap",
                        help="filename prefix for emitted seeds")
    parser.add_argument("--keep-malformed", action="store_true",
                        help="also emit streams that are not DICOM-framed")
    args = parser.parse_args()

    if not args.pcap.is_file():
        sys.exit(f"[pcap_to_seeds] no such pcap: {args.pcap}")

    rdpcap, IP, IPv6, TCP = _load_scapy()
    packets = rdpcap(str(args.pcap))
    streams = extract_streams(packets, args.port, IP, IPv6, TCP)
    print(f"[pcap_to_seeds] {len(packets)} packets, "
          f"{len(streams)} client->server stream(s) on port {args.port}")

    args.out.mkdir(parents=True, exist_ok=True)
    seen_digests = set()
    written = 0
    for index, (key, pkts) in enumerate(streams):
        blob = reassemble(pkts, TCP)
        src, sport = key[0], key[1]
        if not blob:
            continue
        if blob[0] not in PDU_TYPES and not args.keep_malformed:
            print(f"[pcap_to_seeds] skip {src}:{sport} — "
                  f"first byte 0x{blob[0]:02x} is not a DICOM PDU type")
            continue
        digest = hashlib.sha1(blob).hexdigest()
        if digest in seen_digests:
            print(f"[pcap_to_seeds] skip {src}:{sport} — duplicate stream")
            continue
        seen_digests.add(digest)

        count, clean = pdu_framing(blob)
        out_path = args.out / f"{args.prefix}_{index:02d}.raw"
        out_path.write_bytes(blob)
        written += 1
        flag = "well-framed" if clean else "ragged framing"
        print(f"[pcap_to_seeds] wrote {out_path} "
              f"({len(blob)} bytes, {count} PDU(s), {flag})")

    if written == 0:
        print("[pcap_to_seeds] ERROR: no DICOM seeds extracted", file=sys.stderr)
        return 1
    print(f"[pcap_to_seeds] {written} seed(s) ready in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
