#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 1 / Phase 2: generate a small DICOM seed corpus for AFL.

Synthesizes a minimal valid DICOM Part 10 file via pydicom, then uses
c_scare.corruptor.Corruptor to emit a handful of structurally-mutated
variants. Output goes to fuzz/seeds/file/.

The corpus is deliberately tiny — AFL's mutators do the heavy lifting.
We just need diverse enough starting points that coverage feedback has
something to chew on.
"""
import os
import sys
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import (
    ExplicitVRLittleEndian,
    ImplicitVRLittleEndian,
    SecondaryCaptureImageStorage,
    generate_uid,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from c_scare.corruptor import Corruptor  # noqa: E402

OUT_DIR = REPO_ROOT / "fuzz" / "seeds" / "file"


def _build_baseline(transfer_syntax) -> Dataset:
    """Minimal valid Secondary Capture image — enough to exercise dcm2pnm."""
    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = transfer_syntax

    ds = FileDataset("seed.dcm", {}, file_meta=file_meta, preamble=b"\0" * 128)
    ds.PatientName = "Phase1^Seed"
    ds.PatientID = "0001"
    ds.SOPClassUID = SecondaryCaptureImageStorage
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.Modality = "OT"
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 4
    ds.Columns = 4
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = bytes(range(16))

    ds.is_little_endian = True
    ds.is_implicit_VR = transfer_syntax == ImplicitVRLittleEndian
    return ds


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    print(f"  wrote {path.relative_to(REPO_ROOT)} ({len(data)} bytes)")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for ts, label in (
        (ExplicitVRLittleEndian, "explicit_le"),
        (ImplicitVRLittleEndian, "implicit_le"),
    ):
        ds = _build_baseline(ts)
        baseline_path = OUT_DIR / f"baseline_{label}.dcm"
        ds.save_as(str(baseline_path), write_like_original=False)
        print(f"  wrote {baseline_path.relative_to(REPO_ROOT)} (baseline {label})")

        c = Corruptor(ds)
        c.set_length(0x00280010, 0xFFFFFFFF)  # Rows: lie about length
        _write(OUT_DIR / f"corrupt_rows_len_{label}.dcm", c.to_file())

        c = Corruptor(ds)
        c.set_vr(0x00100010, "XX")  # PatientName: invalid VR
        _write(OUT_DIR / f"corrupt_vr_{label}.dcm", c.to_file())

        c = Corruptor(ds)
        c.duplicate(0x00100010)  # duplicate PatientName
        _write(OUT_DIR / f"corrupt_dup_{label}.dcm", c.to_file())

        c = Corruptor(ds)
        c.inject_after(0x00100010, b"\xff" * 64)
        _write(OUT_DIR / f"corrupt_inject_{label}.dcm", c.to_file())

    print(f"seed corpus ready in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
