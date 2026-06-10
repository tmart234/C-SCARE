#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 2: build the AFL++ -x dictionary from c_scare.scapy_dicom constants.

Extracts:
  - Transfer syntax / SOP class / app context / implementation UIDs
  - PDU type bytes (PS3.8 §9.3.1)
  - Variable-item type bytes (PS3.8 §9.3.2-3, PS3.7 D.3.3)
  - DIMSE command-field codes (PS3.7 E.1) as 16-bit big-endian
  - A handful of common (group,element) DICOM tags as 4-byte little-endian

Output: fuzz/dict/dicom.dict, AFL dict format (one entry per line:
  name="literal"   where literal supports \\xNN escapes).
"""
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from c_scare import scapy_dicom as sd  # noqa: E402

OUT_PATH = REPO_ROOT / "fuzz" / "dict" / "dicom.dict"


def _esc_str(s: str) -> str:
    """Escape a printable string for AFL dict (quote + escape backslash/quote)."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _esc_bytes(b: bytes) -> str:
    """All-hex-escape a byte string so it survives AFL dict parsing intact."""
    return "".join(f"\\x{c:02x}" for c in b)


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name).strip("_").lower()


def _emit(seen: set, lines: list, name: str, literal: str) -> None:
    if name in seen:
        return
    seen.add(name)
    lines.append(f'{name}="{literal}"')


def main() -> int:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    seen: set = set()
    lines: list = []

    # UIDs — every module-level *_UID constant
    for attr in dir(sd):
        if not attr.endswith("_UID"):
            continue
        value = getattr(sd, attr)
        if isinstance(value, str) and value:
            _emit(seen, lines, f"uid_{_slug(attr[:-4])}", _esc_str(value))

    # PDU types (1 byte each) — PS3.8 §9.3.1
    for code, label in sd.PDU_TYPES.items():
        _emit(seen, lines, f"pdu_{_slug(label)}", _esc_bytes(bytes([code])))

    # Variable-item types (1 byte each) — PS3.8 §9.3.2-3
    for code, label in sd.ITEM_TYPES.items():
        _emit(seen, lines, f"item_{_slug(label)}", _esc_bytes(bytes([code])))

    # DIMSE command fields — 2 bytes big-endian on the wire (PS3.7 E.1)
    for code, label in sd.DIMSE_COMMAND_FIELDS.items():
        be = struct.pack(">H", code)
        _emit(seen, lines, f"dimse_{_slug(label)}", _esc_bytes(be))

    # Common DICOM tags — 4 bytes little-endian (group, element)
    common_tags = [
        ("patient_name", 0x0010, 0x0010),
        ("patient_id", 0x0010, 0x0020),
        ("sop_class_uid", 0x0008, 0x0016),
        ("sop_instance_uid", 0x0008, 0x0018),
        ("transfer_syntax_uid", 0x0002, 0x0010),
        ("rows", 0x0028, 0x0010),
        ("columns", 0x0028, 0x0011),
        ("bits_allocated", 0x0028, 0x0100),
        ("bits_stored", 0x0028, 0x0101),
        ("samples_per_pixel", 0x0028, 0x0002),
        ("photometric_interpretation", 0x0028, 0x0004),
        ("pixel_representation", 0x0028, 0x0103),
        ("pixel_data", 0x7FE0, 0x0010),
        ("item_start", 0xFFFE, 0xE000),
        ("item_delim", 0xFFFE, 0xE00D),
        ("seq_delim", 0xFFFE, 0xE0DD),
    ]
    for label, group, elem in common_tags:
        wire = struct.pack("<HH", group, elem)
        _emit(seen, lines, f"tag_{label}", _esc_bytes(wire))

    # DICOM file preamble magic — Part 10 marker
    _emit(seen, lines, "magic_dicm", _esc_str("DICM"))

    # Encapsulated-pixel codec markers — the file/pixel campaign mutates
    # fragments inside JPEG / JPEG-LS / JPEG2000 / RLE wrappers, so the codec
    # framing bytes are high-value tokens for reaching decoder internals.
    codec_markers = [
        ("jpeg_soi", b"\xff\xd8"),          # JPEG start of image
        ("jpeg_eoi", b"\xff\xd9"),          # JPEG end of image
        ("jpeg_app0", b"\xff\xe0"),         # JFIF APP0
        ("jpeg_sof0", b"\xff\xc0"),         # baseline start of frame
        ("jpeg_sos", b"\xff\xda"),          # start of scan
        ("jpegls_sof55", b"\xff\xf7"),      # JPEG-LS start of frame
        ("j2k_soc", b"\xff\x4f"),           # JPEG2000 codestream start
        ("j2k_eoc", b"\xff\xd9"),           # JPEG2000 codestream end
        ("j2k_siz", b"\xff\x51"),           # JPEG2000 image/tile size
        ("jp2_signature", b"\x00\x00\x00\x0cjP  \r\n\x87\n"),  # JP2 box signature
    ]
    for label, marker in codec_markers:
        _emit(seen, lines, f"codec_{label}", _esc_bytes(marker))

    OUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT_PATH.relative_to(REPO_ROOT)} ({len(lines)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
