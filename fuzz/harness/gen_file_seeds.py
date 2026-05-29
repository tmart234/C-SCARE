#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 1 / Phase 2: generate a small DICOM seed corpus for AFL.

Synthesizes a minimal valid DICOM Part 10 file via pydicom, then emits two
families of variants for AFL to mutate from:

  * structural corruption — invalid VR, lying lengths, duplicate and
    injected elements (via c_scare.corruptor.Corruptor).
  * polyglot seeds — files that are valid DICOM yet also carry a second
    file format, steering coverage feedback into DICOM's under-validated
    regions: the 128-byte preamble, private (odd-group) data elements,
    and trailing data after the dataset.

The polyglot seeds draw on Hetzel et al., "Incorporating S.P.I.C.Y. DICOM
Polyglot Threats into Cyber Warfare Exercises" (Biohacking Village, 2026),
which catalogues three structural polyglot shapes — sequential (files
back-to-back), embedded/container (one format inside another's data
fields) and interleaved (overlapping bytes) — and singles out the
preamble and opaque private elements as the regions that routinely pass
inspection unparsed. Seeding all three shapes gives the parser code that
handles them something to chew on.

These seeds are deliberately *inert*: each carries only format magic
bytes and minimal headers — no executable code, no payload logic. They
are fuzzing seeds (and double as a polyglot-detection test corpus), not
weapons. The corpus is kept tiny on purpose; AFL's mutators do the rest.
"""
import io
import struct
import sys
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import (
    ExplicitVRLittleEndian,
    ImplicitVRLittleEndian,
    generate_uid,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from c_scare.corruptor import Corruptor  # noqa: E402
from c_scare.profiles import load_profile, resolve_pydicom_uid  # noqa: E402

OUT_DIR = REPO_ROOT / "fuzz" / "seeds" / "file"

PREAMBLE_LEN = 128
PRIVATE_GROUP = 0x0009  # odd group -> private data element block
PRIVATE_CREATOR = "C-SCARE POLYGLOT"

# The baseline SOP class is profile-driven (file.yaml: file_seeds.baseline_sop_class).
# Default matches the historical literal so the corpus is byte-identical.
BASELINE_SOP_CLASS = resolve_pydicom_uid("SecondaryCaptureImageStorage")


def _build_baseline(transfer_syntax) -> Dataset:
    """Minimal valid Secondary Capture image — enough to exercise dcm2pnm."""
    file_meta = Dataset()
    file_meta.MediaStorageSOPClassUID = BASELINE_SOP_CLASS
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = transfer_syntax

    ds = FileDataset("seed.dcm", {}, file_meta=file_meta, preamble=b"\0" * 128)
    ds.PatientName = "Phase1^Seed"
    ds.PatientID = "0001"
    ds.SOPClassUID = BASELINE_SOP_CLASS
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


# --------------------------------------------------------------------------
# Polyglot seed helpers — every payload here is inert format scaffolding.
# --------------------------------------------------------------------------

def _even(data: bytes) -> bytes:
    """Pad to an even length — DICOM value fields must be even-length."""
    return data if len(data) % 2 == 0 else data + b"\x00"


def _fit_preamble(data: bytes) -> bytes:
    """NUL-pad (or truncate) to exactly the 128-byte preamble length."""
    return data[:PREAMBLE_LEN].ljust(PREAMBLE_LEN, b"\x00")


def _dos_preamble(e_lfanew: int) -> bytes:
    """An 'MZ' DOS header sized to the preamble (PEDICOM, interleaved).

    e_lfanew, the PE-header pointer at offset 0x3C, is where a PE loader
    jumps next; aiming it past the preamble is the polyglot trick. Inert —
    an 'MZ' stub with no DOS code.
    """
    hdr = bytearray(_fit_preamble(b"MZ"))
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    return bytes(hdr)


def _elf_preamble() -> bytes:
    """An ELF64 identification header padded into the preamble (ELFDICOM)."""
    return _fit_preamble(b"\x7fELF" + b"\x02\x01\x01\x00")  # 64-bit, LE, v1


def _script_preamble() -> bytes:
    """An inert POSIX shell shebang occupying the preamble.

    '#!/bin/sh' makes the file a (no-op) script as well as a DICOM image;
    the trailing '#' comments out the DICOM bytes that follow.
    """
    return _fit_preamble(b"#!/bin/sh\nexit 0\n#")


def _pe_body() -> bytes:
    """The PE header proper: 'PE\\0\\0' signature + a zeroed COFF header.

    A recognisable PE shape with no sections, no entry point and no code —
    it cannot execute.
    """
    coff = struct.pack("<HHIIIHH",
                       0x8664,  # Machine: x86-64
                       0,       # NumberOfSections
                       0,       # TimeDateStamp
                       0,       # PointerToSymbolTable
                       0,       # NumberOfSymbols
                       0,       # SizeOfOptionalHeader
                       0)       # Characteristics
    return b"PE\x00\x00" + coff


def _inert_pe() -> bytes:
    """A self-contained, non-functional PE skeleton: DOS stub + PE body."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew -> PE body at offset 64
    return _even(bytes(dos) + _pe_body())


def _empty_zip() -> bytes:
    """A structurally valid empty ZIP archive (end-of-central-directory)."""
    return b"PK\x05\x06" + b"\x00" * 18


def _encode(ds: Dataset) -> bytes:
    """Serialize a dataset to DICOM Part 10 bytes."""
    buf = io.BytesIO()
    ds.save_as(buf, write_like_original=False)
    return buf.getvalue()


def _with_private(value: bytes) -> Dataset:
    """A baseline dataset carrying ``value`` in a private (0009,10xx) element."""
    ds = _build_baseline(ExplicitVRLittleEndian)
    block = ds.private_block(PRIVATE_GROUP, PRIVATE_CREATOR, create=True)
    block.add_new(0x01, "OB", _even(value))
    return ds


def _polyglot_seeds(out_dir: Path) -> int:
    """Emit the polyglot seed family on the Explicit VR LE baseline."""
    seeds = []

    # Interleaved: a foreign header overlaid on the 128-byte preamble.
    for name, preamble in (
        ("polyglot_pe_preamble",     _dos_preamble(e_lfanew=PREAMBLE_LEN + 4)),
        ("polyglot_elf_preamble",    _elf_preamble()),
        ("polyglot_script_preamble", _script_preamble()),
    ):
        ds = _build_baseline(ExplicitVRLittleEndian)
        ds.preamble = preamble
        seeds.append((name, _encode(ds)))

    # Embedded/container: a foreign payload parked in an opaque private
    # element — the region viewers leave unparsed without a private dict.
    embedded_dicom = _encode(_build_baseline(ExplicitVRLittleEndian))
    seeds.append(("polyglot_private_pe", _encode(_with_private(_inert_pe()))))
    seeds.append(("polyglot_private_dicom",
                  _encode(_with_private(embedded_dicom))))

    # Sequential: a second complete file appended after the dataset.
    base = _encode(_build_baseline(ExplicitVRLittleEndian))
    seeds.append(("polyglot_trailing_zip", base + _empty_zip()))
    seeds.append(("polyglot_trailing_dicom", base + embedded_dicom))

    # Interleaved + embedded: the full PEDICOM cross-reference — a DOS
    # header in the preamble whose e_lfanew points at the PE body parked
    # in a private element (Hetzel et al., Fig. 3-4).
    pe_body = _even(_pe_body())
    ds = _with_private(pe_body)
    ds.preamble = _dos_preamble(e_lfanew=0)  # patched to the real offset below
    data = bytearray(_encode(ds))
    offset = data.find(pe_body)
    if offset != -1:
        struct.pack_into("<I", data, 0x3C, offset)
    seeds.append(("polyglot_pe_full", bytes(data)))

    for name, blob in seeds:
        _write(out_dir / f"{name}.dcm", blob)
    return len(seeds)


def main(argv=None) -> int:
    global BASELINE_SOP_CLASS
    argv = sys.argv[1:] if argv is None else argv
    target = argv[0] if argv else "file"
    profile = load_profile(target)

    # Profile drives the baseline SOP class and the transfer syntaxes each
    # baseline + corruption family is encoded in. Defaults reproduce the
    # historical literals so the corpus stays byte-identical.
    if profile.file_baseline_sop_class:
        BASELINE_SOP_CLASS = resolve_pydicom_uid(profile.file_baseline_sop_class)
    transfer_syntaxes = [
        (resolve_pydicom_uid(entry["uid"]), entry["label"])
        for entry in profile.file_transfer_syntaxes
    ] or [
        (ExplicitVRLittleEndian, "explicit_le"),
        (ImplicitVRLittleEndian, "implicit_le"),
    ]

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for ts, label in transfer_syntaxes:
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

    print("  --- polyglot seeds (S.P.I.C.Y. structural taxonomy) ---")
    n_poly = _polyglot_seeds(OUT_DIR)

    print(f"seed corpus ready in {OUT_DIR} ({n_poly} polyglot seeds)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
