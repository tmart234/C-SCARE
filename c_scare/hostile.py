# SPDX-License-Identifier: GPL-2.0-only
"""
Hostile / malformation primitives.

Socket-free builders for malformed DICOM Upper Layer PDUs (to feed a connecting
SCU client from a rogue SCP) and byte-mutation helpers (to corrupt the static
DAST catalog on the wire). Everything here returns ``bytes`` and takes no
sockets, so it is directly unit-testable.

PDU wire format (PS3.8 9.1): 1-byte PDU type, 1-byte reserved, 4-byte big-endian
PDU length, then the variable field. The oversized/truncated builders set the
length field *independently* of the body so the lie survives onto the wire —
they do NOT use scapy, whose ``post_build`` would recompute the length.
"""

import struct
from typing import Optional

__all__ = [
    "ROGUE_MALFORMATION_MODES",
    "build_pdu",
    "bitflip_bytes",
    "mutate_payload",
    "malformed_ac_subitems",
    "oversized_pdu",
    "truncated_pdu",
    "illegal_role_response",
    "out_of_state_pdu",
    "rogue_response",
]

# PDU types (PS3.8 9.3)
PDU_ASSOCIATE_RQ = 0x01
PDU_ASSOCIATE_AC = 0x02
PDU_ASSOCIATE_RJ = 0x03
PDU_P_DATA_TF = 0x04
PDU_RELEASE_RQ = 0x05
PDU_RELEASE_RP = 0x06
PDU_ABORT = 0x07

# Rogue --mode values implemented here, beyond the original malformed-ac/reject/
# abort handled directly in the CLI.
ROGUE_MALFORMATION_MODES = (
    "malformed-subitems",
    "oversized-pdu",
    "truncated-pdu",
    "illegal-role",
    "out-of-state",
)


def build_pdu(pdu_type, body=b"", declared_length=None):
    # type: (int, bytes, Optional[int]) -> bytes
    """Assemble a raw PDU. ``declared_length`` overrides the length field
    (defaults to the true ``len(body)``); pass a different value to lie about
    the body size on the wire."""
    length = len(body) if declared_length is None else declared_length
    return struct.pack("!BBI", pdu_type & 0xFF, 0x00, length & 0xFFFFFFFF) + body


# ---------------------------------------------------------------------------
# Byte mutation (DAST outbound --mutate)
# ---------------------------------------------------------------------------

def bitflip_bytes(payload, n=1, seed=0):
    # type: (bytes, int, int) -> bytes
    """Flip ``n`` bits at deterministic pseudo-random positions. Deterministic
    in ``seed`` so a finding is reproducible."""
    if not payload:
        return payload
    import random
    rng = random.Random(seed)
    buf = bytearray(payload)
    for _ in range(max(1, n)):
        pos = rng.randrange(len(buf))
        bit = rng.randrange(8)
        buf[pos] ^= (1 << bit)
    return bytes(buf)


def mutate_payload(payload, modes, seed=0):
    # type: (bytes, list, int) -> bytes
    """Apply one or more mutation modes to a DICOM dataset/PDU payload.

    ``bitflip`` flips a byte regardless of structure. ``vr`` / ``length`` are
    structure-aware and reuse :class:`~c_scare.corruptor.Corruptor` so the
    mutation lands on a real element's VR / length field; if the payload is not
    parseable as a dataset they degrade to a raw byte flip rather than failing.
    Returns the (possibly) mutated bytes; on total failure returns the input
    unchanged so a delivery is never silently skipped."""
    out = payload
    for mode in modes:
        mode = mode.strip().lower()
        if not mode:
            continue
        if mode == "bitflip":
            out = bitflip_bytes(out, n=1, seed=seed)
        elif mode in ("vr", "length"):
            out = _structural_mutate(out, mode, seed)
        else:
            # Unknown mode: be conservative and flip a bit.
            out = bitflip_bytes(out, n=1, seed=seed)
    return out


def _structural_mutate(payload, mode, seed):
    # type: (bytes, str, int) -> bytes
    """Best-effort structure-aware mutation via Corruptor; falls back to a raw
    byte flip if the payload can't be parsed as a dataset."""
    try:
        import pydicom
        from io import BytesIO
        from .corruptor import Corruptor
        ds = pydicom.dcmread(BytesIO(payload), force=True)
        tags = [int(elem.tag) for elem in ds]
        if not tags:
            return bitflip_bytes(payload, n=1, seed=seed)
        target = tags[seed % len(tags)]
        c = Corruptor(payload)
        if mode == "vr":
            c.set_vr(target, "XX")
        else:  # length
            c.set_length(target, 0xFFFFFFFF)
        return c.encode()
    except Exception:
        return bitflip_bytes(payload, n=1, seed=seed)


# ---------------------------------------------------------------------------
# Malformed PDU builders (rogue SCP -> SCU client)
# ---------------------------------------------------------------------------

def _variable_item(item_type, data):
    # type: (int, bytes) -> bytes
    """A PS3.8 variable item: 1-byte type, 1-byte reserved, 2-byte length, data."""
    return struct.pack("!BBH", item_type & 0xFF, 0x00, len(data) & 0xFFFF) + data


def _assoc_ac_header():
    # type: () -> bytes
    """The fixed 68-byte A-ASSOCIATE-AC preamble: protocol version (2), reserved
    (2), called/calling AE titles (16 each, reserved on AC), 32 reserved."""
    return (struct.pack("!H", 0x0001) + b"\x00\x00"
            + b" " * 16 + b" " * 16 + b"\x00" * 32)


def malformed_ac_subitems():
    # type: () -> bytes
    """A-ASSOCIATE-AC carrying an illegal user-information sub-item (undefined
    item type 0x99). A conformant SCU must reject/abort rather than index a
    sub-item table out of range."""
    app_ctx = _variable_item(0x10, b"1.2.840.10008.3.1.1.1")
    bogus_sub = _variable_item(0x99, b"\xde\xad\xbe\xef")
    user_info = _variable_item(0x50, bogus_sub)
    body = _assoc_ac_header() + app_ctx + user_info
    return build_pdu(PDU_ASSOCIATE_AC, body)


def oversized_pdu(pdu_type=PDU_P_DATA_TF, body=b"\x00\x00\x00\x08"):
    # type: (int, bytes) -> bytes
    """A PDU whose length field claims far more than the body delivers
    (0xFFFFFFFF), to probe a client that trusts the declared length and blocks
    or over-allocates."""
    return build_pdu(pdu_type, body, declared_length=0xFFFFFFFF)


def truncated_pdu(pdu_type=PDU_P_DATA_TF, body=b"\x00" * 32):
    # type: (int, bytes) -> bytes
    """A PDU whose length field is half the real body, leaving trailing bytes
    that desynchronize the client's PDU framing."""
    return build_pdu(pdu_type, body, declared_length=max(1, len(body) // 2))


def illegal_role_response(sop_class_uid="1.2.840.10008.5.1.4.1.1.2",
                          scu_role=1, scp_role=1):
    # type: (str, int, int) -> bytes
    """A-ASSOCIATE-AC echoing a Type 0x54 SCP/SCU Role Selection for a SOP class
    the requestor never proposed, with both roles asserted — an illegal echo a
    strict SCU should not blindly trust."""
    uid = sop_class_uid.encode("ascii")
    if len(uid) % 2:
        uid += b"\x00"
    role = struct.pack("!H", len(uid)) + uid + bytes([scu_role & 1, scp_role & 1])
    role_item = _variable_item(0x54, role)
    max_len = _variable_item(0x51, struct.pack("!I", 16384))
    user_info = _variable_item(0x50, max_len + role_item)
    app_ctx = _variable_item(0x10, b"1.2.840.10008.3.1.1.1")
    body = _assoc_ac_header() + app_ctx + user_info
    return build_pdu(PDU_ASSOCIATE_AC, body)


def out_of_state_pdu():
    # type: () -> bytes
    """An A-RELEASE-RP sent unsolicited (no preceding A-RELEASE-RQ), violating
    the Upper Layer state machine (PS3.8 9.2). Body is the 4 reserved bytes."""
    return build_pdu(PDU_RELEASE_RP, b"\x00\x00\x00\x00")


def rogue_response(mode):
    # type: (str) -> bytes
    """Map a hostile ``--mode`` to its malformed-PDU bytes. Raises KeyError for
    a mode this module does not implement (the CLI handles malformed-ac/reject/
    abort itself)."""
    builders = {
        "malformed-subitems": malformed_ac_subitems,
        "oversized-pdu": oversized_pdu,
        "truncated-pdu": truncated_pdu,
        "illegal-role": illegal_role_response,
        "out-of-state": out_of_state_pdu,
    }
    return builders[mode]()
