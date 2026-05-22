#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 2 extension: encapsulated-pixel-data and dimension-mismatch seeds.

Wires up dormant capabilities in c_scare/pixel.py:
  - PixelFuzzer: 7 strategies for mutating encapsulated pixel data
    (fuzz_lengths, fuzz_bot, drop_delimiter, corrupt_fragment,
     duplicate_fragments, empty_fragments, overflow_bot)
  - PixelData.overflow_dimensions / zero_dimensions: native pixel-data
    seeds with malformed Rows/Columns
  - YBR_FULL / PlanarConfiguration 1 frame whose Pixel Data holds far
    fewer samples than Rows*Columns*3, exercising the colour-plane
    stored-vs-expected length check in the image pipeline

Each seed is a complete DICOM Part 10 file dcm2pnm/dcmconv can chew on,
exercising the codec dispatch + image pipeline (the reason we picked
dcm2pnm over dcmconv for the file campaign).

Determinism: env C_SCARE_PIXEL_SEED (default 0x9112E1) seeds Python's
random module before invoking PixelFuzzer.
"""
import os
import random
import sys
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import SecondaryCaptureImageStorage, generate_uid

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from c_scare.corruptor import Corruptor  # noqa: E402
from c_scare.pixel import PixelData, PixelFuzzer  # noqa: E402

OUT_DIR = REPO_ROOT / "fuzz" / "seeds" / "file"
JPEG_BASELINE_UID = "1.2.840.10008.1.2.4.50"
EXPLICIT_VR_LE = "1.2.840.10008.1.2.1"
DEFAULT_SEED = 0x9112E1
PIXEL_TAG = 0x7FE00010


def _baseline(transfer_syntax: str) -> Dataset:
    """Image-pixel-module dataset with empty PixelData."""
    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = transfer_syntax

    ds = FileDataset("seed.dcm", {}, file_meta=file_meta, preamble=b"\0" * 128)
    ds.PatientName = "Phase1^Pixel"
    ds.PatientID = "0001"
    ds.SOPClassUID = SecondaryCaptureImageStorage
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.Modality = "OT"
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 16
    ds.Columns = 16
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = b""
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    return ds


def _splice_pixel(ds: Dataset, raw: bytes, undefined_length: bool) -> bytes:
    """Replace (7FE0,0010) with raw bytes; mark undefined-length for EPD."""
    c = Corruptor(ds)
    c.set_raw_value(PIXEL_TAG, raw)
    if undefined_length:
        c.set_length(PIXEL_TAG, 0xFFFFFFFF)
    return c.to_file(transfer_syntax=ds.file_meta.TransferSyntaxUID)


def _write(path: Path, data: bytes, label: str) -> None:
    path.write_bytes(data)
    print(f"  wrote {path.relative_to(REPO_ROOT)} ({len(data)} bytes, {label})")


def _ybr_full_planar_undersize() -> Dataset:
    """YBR_FULL + PlanarConfiguration 1 frame with far too few stored pixels.

    A YBR_FULL, planar-configuration-1 image whose Pixel Data holds far fewer
    samples than Rows*Columns*3 used to be processed regardless, reading past
    the pixel buffer. The hardened path renders an empty (black) frame and
    logs a warning instead. This seed reproduces that shape so the dcm2pnm
    colour pipeline exercises the new stored-vs-expected length check.

    Grey-box seed for CVE-2025-9732 — memory corruption in the YBR pixel
    template (dcmimage/.../diybrpxt.h) reachable through any dcmimage
    front-end (dcm2img, dcm2pnm).
    """
    ds = _baseline(EXPLICIT_VR_LE)
    ds.SamplesPerPixel = 3
    ds.PhotometricInterpretation = "YBR_FULL"
    ds.PlanarConfiguration = 1
    ds.Rows = 64
    ds.Columns = 64
    # Expected for an 8-bit YBR_FULL frame: 64*64*3 = 12288 bytes.
    # Supply 96 -- "much too less" -- to trip the length check.
    ds.PixelData = bytes(96)
    return ds


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    seed = int(os.environ.get("C_SCARE_PIXEL_SEED", str(DEFAULT_SEED)), 0)
    random.seed(seed)

    # Encapsulated pixel data — 7 strategies × 3 variants each = 21 seeds.
    fuzzer = PixelFuzzer()
    ds_jpeg = _baseline(JPEG_BASELINE_UID)
    for i, payload in enumerate(fuzzer.generate(count=21)):
        out = OUT_DIR / f"pixel_epd_{i:02d}.dcm"
        try:
            blob = _splice_pixel(ds_jpeg, payload, undefined_length=True)
        except Exception as exc:  # rare encoder issues on extreme payloads
            print(f"  skip {out.name}: {exc}")
            continue
        _write(out, blob, f"epd payload={len(payload)}B")

    # Native pixel data with malformed dimensions.
    for label, builder in (
        ("overflow", PixelData.overflow_dimensions),
        ("zero", PixelData.zero_dimensions),
    ):
        pd = builder(bits=8)
        ds_native = _baseline(EXPLICIT_VR_LE)
        ds_native.Rows = pd.rows if pd.rows <= 0xFFFF else 0xFFFF
        ds_native.Columns = pd.cols if pd.cols <= 0xFFFF else 0xFFFF
        blob = _splice_pixel(ds_native, pd.data, undefined_length=False)
        _write(OUT_DIR / f"pixel_dim_{label}.dcm", blob,
               f"rows={pd.rows} cols={pd.cols}")

    # YBR_FULL / PlanarConfiguration 1 frame with undersized Pixel Data.
    ybr_path = OUT_DIR / "pixel_ybr_full_planar1_undersize.dcm"
    _ybr_full_planar_undersize().save_as(str(ybr_path), write_like_original=False)
    print(f"  wrote {ybr_path.relative_to(REPO_ROOT)} "
          f"(YBR_FULL planar=1, 96B pixel data vs 12288B expected)")

    (OUT_DIR / "PIXEL_SEED.txt").write_text(f"{seed}\n")
    print(f"  wrote {(OUT_DIR / 'PIXEL_SEED.txt').relative_to(REPO_ROOT)} (seed={hex(seed)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
