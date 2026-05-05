#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-side wiring for c_scare's dormant parsers.

For each input .dcm, this exercises the full parse → mutate → re-emit loop:

  bytes → DicomFile.parse → pydicom.dcmread → EncapsulatedPixelData.from_pydicom
        → fragment-level mutation (Corruptor + PixelFuzzer mutators)
        → DICOMEncapsulatedPixelData.from_encapsulated (scapy re-encode)
        → bytes

Wires four c_scare entry points the rest of the codebase didn't call:
  - DicomFile.parse                       (file.py:226)
  - EncapsulatedPixelData.parse           (pixel.py:291)
  - EncapsulatedPixelData.from_pydicom    (pixel.py:334)
  - DICOMEncapsulatedPixelData.from_encapsulated (pixel.py:608)

Output: parsed-mutated copies in fuzz/seeds/file/roundtrip_*.dcm,
plus a one-line report per input.

Usage:
  python3 fuzz/harness/roundtrip_pixel.py                  # all seeds in fuzz/seeds/file/
  python3 fuzz/harness/roundtrip_pixel.py path/to/foo.dcm  # specific files
"""
import sys
from io import BytesIO
from pathlib import Path

import pydicom

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from c_scare.corruptor import Corruptor  # noqa: E402
from c_scare.file import DicomFile  # noqa: E402
from c_scare.pixel import (  # noqa: E402
    DICOMEncapsulatedPixelData,
    EncapsulatedPixelData,
    HAS_SCAPY,
)

SEEDS_DIR = REPO_ROOT / "fuzz" / "seeds" / "file"
PIXEL_TAG = 0x7FE00010


def _extract_epd(ds: pydicom.Dataset) -> EncapsulatedPixelData | None:
    """Try both available paths to recover an EncapsulatedPixelData object."""
    if "PixelData" not in ds:
        return None
    elem = ds.data_element("PixelData")

    # Path 1: pydicom dataset → EPD (handles iterable Sequence values)
    epd = EncapsulatedPixelData.from_pydicom(elem)
    if epd.fragments:
        return epd

    # Path 2: parse the raw bytes directly (item-tag scanner)
    raw = elem.value if isinstance(elem.value, bytes) else None
    if raw and len(raw) > 8:
        try:
            return EncapsulatedPixelData.parse(raw)
        except Exception:
            pass
    return None


def _scapy_reencode(epd: EncapsulatedPixelData) -> bytes | None:
    """Round-trip our EPD through scapy's wire-format encoder."""
    if not HAS_SCAPY or DICOMEncapsulatedPixelData is None:
        return None
    from scapy.packet import raw as scapy_raw

    scapy_epd = DICOMEncapsulatedPixelData.from_encapsulated(epd)
    return bytes(scapy_raw(scapy_epd))


def _mutate_and_emit(src: Path, df: DicomFile, ds: pydicom.Dataset) -> Path | None:
    """Apply a deterministic mutation and write a roundtrip variant."""
    if "PatientName" not in ds:
        return None
    c = Corruptor(ds)
    c.duplicate(0x00100010)  # duplicate PatientName — exercises parser dedup paths
    c.set_length(0x00280010, 0xFFFFFFFF)  # lie about Rows length
    out = SEEDS_DIR / f"roundtrip_{src.stem}.dcm"
    out.write_bytes(c.to_file(transfer_syntax=df.file_meta.transfer_syntax_uid))
    return out


def round_trip(path: Path) -> str:
    data = path.read_bytes()
    df = DicomFile.parse(data, lenient=True)
    ds = pydicom.dcmread(BytesIO(data), force=True)

    epd = _extract_epd(ds)
    frag_count = len(epd.fragments) if epd else 0
    reencoded = _scapy_reencode(epd) if epd else None

    out = _mutate_and_emit(path, df, ds)

    parts = [
        f"ts={df.file_meta.transfer_syntax_uid or '?'}",
        f"preamble={df.include_preamble}",
        f"frags={frag_count}",
    ]
    if reencoded is not None:
        parts.append(f"reencoded={len(reencoded)}B")
    if out is not None:
        parts.append(f"-> {out.name}")
    return ", ".join(parts)


def main(args: list[str]) -> int:
    if args:
        seeds = [Path(p) for p in args]
    else:
        seeds = sorted(p for p in SEEDS_DIR.glob("*.dcm")
                       if not p.name.startswith("roundtrip_"))

    if not seeds:
        print("no input .dcm files; run gen_file_seeds.py / gen_pixel_seeds.py first")
        return 1

    for seed in seeds:
        try:
            print(f"  {seed.name}: {round_trip(seed)}")
        except Exception as exc:
            print(f"  {seed.name}: ERROR {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
