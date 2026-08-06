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
import zlib
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset, FileDataset
from pydicom.sequence import Sequence as PydicomSequence
from pydicom.uid import (
    CTImageStorage,
    DeflatedExplicitVRLittleEndian,
    ExplicitVRBigEndian,
    ExplicitVRLittleEndian,
    ImplicitVRLittleEndian,
    MRImageStorage,
    generate_uid,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from c_scare.corruptor import Corruptor  # noqa: E402
from c_scare.element import Dataset as WireDataset  # noqa: E402
from c_scare.element import Element, Sequence as WireSequence  # noqa: E402
from c_scare.file import DicomFile  # noqa: E402
from c_scare.polyglot import elf_header  # noqa: E402
from c_scare.profiles import load_profile, resolve_pydicom_uid  # noqa: E402

DEFAULT_OUT_DIR = REPO_ROOT / "fuzz" / "seeds" / "file"
OUT_DIR = DEFAULT_OUT_DIR

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


def _profile_out_dir(profile) -> Path:
    if OUT_DIR != DEFAULT_OUT_DIR:
        return OUT_DIR
    return Path(profile.seeds_dir) if profile.seeds_dir else OUT_DIR


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
    """A complete Elf64_Ehdr occupying the preamble (ELFDICOM).

    The header is 64 bytes and fits the preamble's first half exactly, so the
    seed can carry the whole thing rather than an e_ident prefix — an ELF
    reader gets past the magic and into e_phoff, e_shoff and the size fields,
    which is where the parsing a fuzzer wants to reach actually starts. Inert:
    entry point 0, no program headers, no section headers.
    """
    return _fit_preamble(elf_header(ph_offset=0, ph_count=0, bits=64))


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


# --------------------------------------------------------------------------
# Parser-structure seed helpers — compact DICOM grammar edge cases.
# --------------------------------------------------------------------------

def _base_structural_pydicom(transfer_syntax=ExplicitVRLittleEndian) -> FileDataset:
    file_meta = Dataset()
    file_meta.FileMetaInformationVersion = b"\x00\x01"
    file_meta.MediaStorageSOPClassUID = BASELINE_SOP_CLASS
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = transfer_syntax
    file_meta.ImplementationClassUID = generate_uid()
    file_meta.ImplementationVersionName = "C-SCARE"

    ds = FileDataset("struct.dcm", {}, file_meta=file_meta, preamble=b"\x00" * 128)
    ds.PatientName = "Struct^Seed"
    ds.PatientID = "STRUCT-0001"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPClassUID = BASELINE_SOP_CLASS
    ds.SOPInstanceUID = ds.file_meta.MediaStorageSOPInstanceUID
    ds.Modality = "OT"
    ds.StudyDate = "20260612"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 2
    ds.Columns = 2
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = b"\x00\x40\x80\xff"
    ds.is_little_endian = transfer_syntax != ExplicitVRBigEndian
    ds.is_implicit_VR = transfer_syntax == ImplicitVRLittleEndian
    return ds


def _wire_core() -> WireDataset:
    return (WireDataset()
            / Element(0x00080016, "UI", str(BASELINE_SOP_CLASS))
            / Element(0x00080018, "UI", str(generate_uid()))
            / Element(0x00080060, "CS", "OT")
            / Element(0x00100010, "PN", "Struct^Wire")
            / Element(0x00100020, "LO", "WIRE-0001")
            / Element(0x00280002, "US", 1)
            / Element(0x00280004, "CS", "MONOCHROME2")
            / Element(0x00280010, "US", 2)
            / Element(0x00280011, "US", 2)
            / Element(0x00280100, "US", 8)
            / Element(0x00280101, "US", 8)
            / Element(0x00280102, "US", 7)
            / Element(0x00280103, "US", 0)
            / Element(0x7FE00010, "OB", b"\x00\x40\x80\xff"))


def _part10(dataset_bytes: bytes, transfer_syntax=ExplicitVRLittleEndian) -> bytes:
    df = DicomFile()
    df.set_meta(
        sop_class_uid=str(BASELINE_SOP_CLASS),
        sop_instance_uid=str(generate_uid()),
        transfer_syntax=str(transfer_syntax),
        implementation_version="C-SCARE",
    )
    df.dataset = dataset_bytes
    return df.encode()


def _patch_group_length(blob: bytes, value: int) -> bytes:
    data = bytearray(blob)
    marker = b"\x02\x00\x00\x00UL\x04\x00"
    pos = data.find(marker)
    if pos != -1:
        struct.pack_into("<I", data, pos + len(marker), value)
    return bytes(data)


def _pydicom_sequence_seed() -> bytes:
    ds = _base_structural_pydicom()
    code = Dataset()
    code.CodeValue = "T-D0050"
    code.CodingSchemeDesignator = "SRT"
    code.CodeMeaning = "Tissue"
    content = Dataset()
    content.ValueType = "CODE"
    content.ConceptNameCodeSequence = PydicomSequence([code])
    ds.ContentSequence = PydicomSequence([content])
    ref = Dataset()
    ref.ReferencedSOPClassUID = BASELINE_SOP_CLASS
    ref.ReferencedSOPInstanceUID = generate_uid()
    ds.ReferencedImageSequence = PydicomSequence([ref])
    return _encode(ds)


def _wire_sequence_seed(undefined_length: bool) -> bytes:
    code = (WireDataset()
            / Element(0x00080100, "SH", "T-D0050")
            / Element(0x00080102, "SH", "SRT")
            / Element(0x00080104, "LO", "Tissue"))
    seq = WireSequence([code])
    seq.undefined_length = undefined_length
    ds = _wire_core() / Element(0x00081140, "SQ", seq)
    return _part10(ds.encode(implicit_vr=False, little_endian=True))


def _nested_sequence_missing_delimiter() -> bytes:
    inner = WireSequence([WireDataset() / Element(0x00080100, "SH", "ABC")])
    inner.undefined_length = True
    outer_item = WireDataset() / Element(0x0040A043, "SQ", inner)
    outer = WireSequence([outer_item])
    outer.undefined_length = True
    ds = _wire_core() / Element(0x0040A730, "SQ", outer)
    dataset_bytes = ds.encode(implicit_vr=False, little_endian=True)
    if dataset_bytes.endswith(b"\xfe\xff\xdd\xe0\x00\x00\x00\x00"):
        dataset_bytes = dataset_bytes[:-8]
    return _part10(dataset_bytes)


def _unknown_private_seed() -> bytes:
    ds = (_wire_core()
          / Element(0x00090010, "LO", "C-SCARE")
          / Element.raw(tag=0x00091001, vr="UN", value=b"private-bytes")
          / Element.raw(tag=0x77770010, vr="ZZ", value=b"unknown-vr", length=32)
          / Element.raw(tag=0x77770011, vr="UN", value=b"undef", length=0xFFFFFFFF))
    return _part10(ds.encode(implicit_vr=False, little_endian=True))


def _deflated_seed() -> bytes:
    dataset_bytes = _wire_core().encode(implicit_vr=False, little_endian=True)
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    deflated = compressor.compress(dataset_bytes) + compressor.flush()
    return _part10(deflated, DeflatedExplicitVRLittleEndian)


def _structural_seeds(out_dir: Path) -> int:
    baseline = _encode(_base_structural_pydicom())
    explicit = _wire_core().encode(implicit_vr=False, little_endian=True)
    implicit = _wire_core().encode(implicit_vr=True, little_endian=True)
    big_endian = _wire_core().encode(implicit_vr=False, little_endian=False)
    seeds = {
        "struct_sequence_pydicom.dcm": _pydicom_sequence_seed(),
        "struct_sequence_undefined.dcm": _wire_sequence_seed(True),
        "struct_sequence_defined.dcm": _wire_sequence_seed(False),
        "struct_sequence_missing_delim.dcm": _nested_sequence_missing_delimiter(),
        "struct_unknown_private_tags.dcm": _unknown_private_seed(),
        "struct_meta_group_length_zero.dcm": _patch_group_length(baseline, 0),
        "struct_meta_group_length_huge.dcm": _patch_group_length(baseline, 0xFFFFFFFF),
        "struct_meta_says_implicit_dataset_explicit.dcm": _part10(explicit, ImplicitVRLittleEndian),
        "struct_meta_says_explicit_dataset_implicit.dcm": _part10(implicit, ExplicitVRLittleEndian),
        "struct_explicit_vr_big_endian.dcm": _part10(big_endian, ExplicitVRBigEndian),
        "struct_deflated_explicit_le.dcm": _deflated_seed(),
        "struct_raw_dataset_no_meta.dcm": explicit,
        "struct_bad_part10_prefix.dcm": baseline[:128] + b"NOPE" + baseline[132:],
    }
    for name, blob in seeds.items():
        _write(out_dir / name, blob)
    return len(seeds)


def _scan_metadata_seeds(out_dir: Path) -> int:
    seeds = {}

    ds = _base_structural_pydicom()
    ds.SpecificCharacterSet = "ISO_IR 100"
    ds.PatientName = "Muller^Jose"
    ds.PatientID = "LATIN1-0001"
    ds.StudyDescription = "Latin1 metadata"
    seeds["scan_charset_latin1.dcm"] = _encode(ds)

    ds = _base_structural_pydicom()
    ds.SpecificCharacterSet = "ISO_IR_BOGUS"
    ds.PatientName = "BadCharset^Patient"
    ds.PatientID = "BAD-CHARSET"
    seeds["scan_charset_invalid.dcm"] = _encode(ds)

    ds = _base_structural_pydicom()
    ds.PatientName = ""
    ds.PatientID = ""
    ds.StudyDescription = "empty identity fields"
    seeds["scan_empty_identity.dcm"] = _encode(ds)

    ds = _base_structural_pydicom()
    ds.file_meta.MediaStorageSOPClassUID = CTImageStorage
    ds.SOPClassUID = CTImageStorage
    ds.Modality = "CT"
    ds.Manufacturer = "C-SCARE"
    ds.ManufacturerModelName = "Aquilion"
    ds.ImageType = ["ORIGINAL", "PRIMARY", "AXIAL"]
    ds.PixelSpacing = ["0.8", "0.8"]
    ds.SliceThickness = "1.25"
    ds.ImagePositionPatient = ["0", "0", "1.25"]
    ds.ImageOrientationPatient = ["1", "0", "0", "0", "1", "0"]
    seeds["scan_ct_geometry_aquilion.dcm"] = _encode(ds)

    ds = _base_structural_pydicom()
    ds.file_meta.MediaStorageSOPClassUID = MRImageStorage
    ds.SOPClassUID = MRImageStorage
    ds.Modality = "MR"
    ds.RepetitionTime = "450"
    ds.EchoTime = "12"
    ds.PixelSpacing = ["1.0", "1.0"]
    ds.SliceThickness = "2.0"
    ds.ImagePositionPatient = ["0", "0", "2"]
    ds.ImageOrientationPatient = ["1", "0", "0", "0", "1", "0"]
    seeds["scan_mr_geometry.dcm"] = _encode(ds)

    ds = _base_structural_pydicom()
    shared = Dataset()
    ct_details = Dataset()
    ct_details.GantryDetectorTilt = "12.5"
    pixel_measures = Dataset()
    pixel_measures.SliceThickness = "1.5"
    pixel_measures.PixelSpacing = ["0.6", "0.6"]
    frame_voi = Dataset()
    frame_voi.WindowCenter = "40"
    frame_voi.WindowWidth = "400"
    shared.CTAcquisitionDetailsSequence = PydicomSequence([ct_details])
    shared.PixelMeasuresSequence = PydicomSequence([pixel_measures])
    shared.FrameVOILUTSequence = PydicomSequence([frame_voi])
    ds.SharedFunctionalGroupsSequence = PydicomSequence([shared])
    seeds["scan_shared_functional_groups.dcm"] = _encode(ds)

    ds = _base_structural_pydicom()
    ds.LossyImageCompression = "01"
    ds.LossyImageCompressionRatio = "12.5"
    ds.LossyImageCompressionMethod = "ISO_10918_1"
    seeds["scan_lossy_flags.dcm"] = _encode(ds)

    # Private blocks in two odd groups: vendor extensions are where a parser
    # meets data it has no dictionary entry for, so they reach the
    # unknown-VR / private-creator handling that public tags never touch.
    ds = _base_structural_pydicom()
    raw_block = ds.private_block(0x0019, "C_SCARE_PRIVATE_RAW", create=True)
    raw_block.add_new(0x01, "LO", "raw-metadata")
    viz_block = ds.private_block(0x0029, "C_SCARE_PRIVATE_VIZ", create=True)
    viz_block.add_new(0x01, "OB", b"private-blob")
    seeds["scan_private_tags.dcm"] = _encode(ds)

    for name, blob in seeds.items():
        _write(out_dir / name, blob)
    return len(seeds)


def _enum_storage_matrix_seeds(out_dir: Path) -> int:
    """Emit port-104 DICOM enum accepted SOP/transfer-syntax metadata seeds."""
    accepted = [
        ("ct_explicit", "1.2.840.10008.5.1.4.1.1.2", "CT", ExplicitVRLittleEndian),
        ("enhanced_ct_explicit", "1.2.840.10008.5.1.4.1.1.2.1", "CT", ExplicitVRLittleEndian),
        ("mr_explicit", "1.2.840.10008.5.1.4.1.1.4", "MR", ExplicitVRLittleEndian),
        ("enhanced_mr_explicit", "1.2.840.10008.5.1.4.1.1.4.1", "MR", ExplicitVRLittleEndian),
        ("us_explicit", "1.2.840.10008.5.1.4.1.1.6.1", "US", ExplicitVRLittleEndian),
        ("us_multiframe_explicit", "1.2.840.10008.5.1.4.1.1.3.1", "US", ExplicitVRLittleEndian),
        ("cr_explicit", "1.2.840.10008.5.1.4.1.1.1", "CR", ExplicitVRLittleEndian),
        ("dx_presentation_explicit", "1.2.840.10008.5.1.4.1.1.1.1", "DX", ExplicitVRLittleEndian),
        ("dx_processing_explicit", "1.2.840.10008.5.1.4.1.1.1.1.1", "DX", ExplicitVRLittleEndian),
        ("xa_explicit", "1.2.840.10008.5.1.4.1.1.12.1", "XA", ExplicitVRLittleEndian),
        ("xrf_explicit", "1.2.840.10008.5.1.4.1.1.12.2", "RF", ExplicitVRLittleEndian),
        ("enhanced_xrf_explicit", "1.2.840.10008.5.1.4.1.1.12.2.1", "RF", ExplicitVRLittleEndian),
        ("nm_explicit", "1.2.840.10008.5.1.4.1.1.20", "NM", ExplicitVRLittleEndian),
        ("pet_explicit", "1.2.840.10008.5.1.4.1.1.128", "PT", ExplicitVRLittleEndian),
        ("enhanced_pet_explicit", "1.2.840.10008.5.1.4.1.1.130", "PT", ExplicitVRLittleEndian),
        ("secondary_capture_explicit", "1.2.840.10008.5.1.4.1.1.7", "OT", ExplicitVRLittleEndian),
        ("mf_singlebit_sc_explicit", "1.2.840.10008.5.1.4.1.1.7.1", "OT", ExplicitVRLittleEndian),
        ("mf_graybyte_sc_explicit", "1.2.840.10008.5.1.4.1.1.7.2", "OT", ExplicitVRLittleEndian),
        ("mf_grayword_sc_explicit", "1.2.840.10008.5.1.4.1.1.7.3", "OT", ExplicitVRLittleEndian),
        ("mf_truecolor_sc_explicit", "1.2.840.10008.5.1.4.1.1.7.4", "OT", ExplicitVRLittleEndian),
        ("basic_text_sr_implicit", "1.2.840.10008.5.1.4.1.1.88.11", "SR", ImplicitVRLittleEndian),
        ("enhanced_sr_implicit", "1.2.840.10008.5.1.4.1.1.88.22", "SR", ImplicitVRLittleEndian),
        ("comprehensive_sr_implicit", "1.2.840.10008.5.1.4.1.1.88.33", "SR", ImplicitVRLittleEndian),
        ("kos_implicit", "1.2.840.10008.5.1.4.1.1.88.59", "KO", ImplicitVRLittleEndian),
        ("grayscale_pr_implicit", "1.2.840.10008.5.1.4.1.1.11.1", "PR", ImplicitVRLittleEndian),
        ("color_pr_implicit", "1.2.840.10008.5.1.4.1.1.11.2", "PR", ImplicitVRLittleEndian),
        ("pseudo_color_pr_implicit", "1.2.840.10008.5.1.4.1.1.11.3", "PR", ImplicitVRLittleEndian),
        ("blending_pr_implicit", "1.2.840.10008.5.1.4.1.1.11.4", "PR", ImplicitVRLittleEndian),
        ("xaxrf_pr_implicit", "1.2.840.10008.5.1.4.1.1.11.5", "PR", ImplicitVRLittleEndian),
        ("mr_spectroscopy_explicit", "1.2.840.10008.5.1.4.1.1.4.2", "MR", ExplicitVRLittleEndian),
        ("enhanced_mr_color_explicit", "1.2.840.10008.5.1.4.1.1.4.3", "MR", ExplicitVRLittleEndian),
        ("enhanced_us_volume_explicit", "1.2.840.10008.5.1.4.1.1.6.2", "US", ExplicitVRLittleEndian),
        ("raw_data_implicit", "1.2.840.10008.5.1.4.1.1.66", "OT", ImplicitVRLittleEndian),
        ("spatial_registration_implicit", "1.2.840.10008.5.1.4.1.1.66.1", "REG", ImplicitVRLittleEndian),
        ("rt_image_explicit", "1.2.840.10008.5.1.4.1.1.481.1", "RTIMAGE", ExplicitVRLittleEndian),
        ("rt_dose_implicit", "1.2.840.10008.5.1.4.1.1.481.2", "RTDOSE", ImplicitVRLittleEndian),
        ("rt_structure_set_implicit", "1.2.840.10008.5.1.4.1.1.481.3", "RTSTRUCT", ImplicitVRLittleEndian),
        ("rt_plan_implicit", "1.2.840.10008.5.1.4.1.1.481.5", "RTPLAN", ImplicitVRLittleEndian),
    ]

    for label, sop_class, modality, transfer_syntax in accepted:
        ds = _base_structural_pydicom(transfer_syntax)
        ds.file_meta.MediaStorageSOPClassUID = sop_class
        ds.SOPClassUID = sop_class
        ds.Modality = modality
        ds.PatientID = f"ENUM-{label[:12].upper()}"
        ds.SeriesDescription = "Port 104 accepted storage SOP"
        ds.ProtocolName = "nmap-dicom-enum-0616"
        ds.is_implicit_VR = transfer_syntax == ImplicitVRLittleEndian
        _write(out_dir / f"scan_enum_{label}.dcm", _encode(ds))
    return len(accepted)


def main(argv=None) -> int:
    global BASELINE_SOP_CLASS
    argv = sys.argv[1:] if argv is None else argv
    target = argv[0] if argv else "file"
    profile = load_profile(target)
    out_dir = _profile_out_dir(profile)

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

    out_dir.mkdir(parents=True, exist_ok=True)

    for ts, label in transfer_syntaxes:
        ds = _build_baseline(ts)
        baseline_path = out_dir / f"baseline_{label}.dcm"
        ds.save_as(str(baseline_path), write_like_original=False)
        print(f"  wrote {baseline_path.relative_to(REPO_ROOT)} (baseline {label})")

        c = Corruptor(ds)
        c.set_length(0x00280010, 0xFFFFFFFF)  # Rows: lie about length
        _write(out_dir / f"corrupt_rows_len_{label}.dcm", c.to_file())

        c = Corruptor(ds)
        c.set_vr(0x00100010, "XX")  # PatientName: invalid VR
        _write(out_dir / f"corrupt_vr_{label}.dcm", c.to_file())

        c = Corruptor(ds)
        c.duplicate(0x00100010)  # duplicate PatientName
        _write(out_dir / f"corrupt_dup_{label}.dcm", c.to_file())

        c = Corruptor(ds)
        c.inject_after(0x00100010, b"\xff" * 64)
        _write(out_dir / f"corrupt_inject_{label}.dcm", c.to_file())

    print("  --- polyglot seeds (S.P.I.C.Y. structural taxonomy) ---")
    n_poly = _polyglot_seeds(out_dir)
    print("  --- structural parser seeds ---")
    n_structural = _structural_seeds(out_dir)
    print("  --- scanner metadata seeds ---")
    n_scan = _scan_metadata_seeds(out_dir)
    print("  --- DICOM enum storage matrix seeds ---")
    n_enum = _enum_storage_matrix_seeds(out_dir)

    print(f"seed corpus ready in {out_dir} "
          f"({n_poly} polyglot, {n_structural} structural, {n_scan} scanner, {n_enum} enum seeds)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
