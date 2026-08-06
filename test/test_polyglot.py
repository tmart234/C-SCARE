# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the DICOM/PE polyglot machinery (CVE-2019-11687).

Three things are worth locking down here.

*The PE geometry is right.* Relocating a PE's headers away from offset 0x40 —
which is what parking them behind ``DICM``, the File Meta group and a private
element header does — invalidates ``SizeOfHeaders`` and every
``PointerToRawData`` unless they are fixed up. A polyglot that skips those
fixups is rejected by the loader, so the file stops being dual-format and the
payload stops testing anything.

*The zone enumeration is right.* The analyzer is how a defender sizes the
embedding surface; a zone it fails to report is a region nobody thinks to scan.

*The images stay inert.* ``pe_image`` builds header geometry, not a program.
The tests below assert that directly, so a later change that adds an entry
point or an executable section fails loudly rather than quietly turning a test
catalog into a malware builder.
"""

import struct

import pytest

pytest.importorskip("pydicom")

from c_scare import polyglot  # noqa: E402
from c_scare.polyglot import (  # noqa: E402
    FILE_ALIGNMENT, PREAMBLE_LEN, dos_header, enumerate_safe_zones, pe_image,
    validate_dicom, validate_pe, validate_polyglot,
)

# Offsets that exercise both the "headers fit in one FileAlignment block" and
# the "headers spill into the next" cases, plus a deliberately odd one.
OFFSETS = [0x40, 0x100, 0x180, 0x400]
BITS = [32, 64]


def _standalone(pe_offset, bits=64):
    """A minimal file: DOS header, filler, then the PE image at ``pe_offset``."""
    head = dos_header(pe_offset)
    return head + b"\x00" * (pe_offset - len(head)) + pe_image(pe_offset, bits=bits)


def _optional_header_offset(data):
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    return e_lfanew + 4 + 20


class TestPEGeometry:
    """The §5.2 header fixups a relocated PE needs to stay loadable."""

    @pytest.mark.parametrize("bits", BITS)
    @pytest.mark.parametrize("offset", OFFSETS)
    def test_relocated_image_passes_pe_validation(self, offset, bits):
        assert validate_pe(_standalone(offset, bits)) == []

    @pytest.mark.parametrize("bits", BITS)
    @pytest.mark.parametrize("offset", OFFSETS)
    def test_size_of_headers_spans_the_section_headers(self, offset, bits):
        """Fixup 1: SizeOfHeaders is measured from offset 0, so it has to grow
        by the relocation delta or the loader never maps the section table."""
        data = _standalone(offset, bits)
        opt = _optional_header_offset(data)
        size_of_headers = struct.unpack("<I", data[opt + 60:opt + 64])[0]
        section_headers_end = opt + struct.unpack(
            "<H", data[offset + 4 + 16:offset + 4 + 18])[0] + 40
        assert size_of_headers >= section_headers_end
        assert size_of_headers % FILE_ALIGNMENT == 0

    @pytest.mark.parametrize("bits", BITS)
    @pytest.mark.parametrize("offset", OFFSETS)
    def test_section_data_is_aligned_and_resident(self, offset, bits):
        """Fixups 2 and 3: PointerToRawData shifts with the headers, stays
        FileAlignment-aligned, and its data is fully present in the file."""
        data = _standalone(offset, bits)
        opt = _optional_header_offset(data)
        opt_len = struct.unpack("<H", data[offset + 4 + 16:offset + 4 + 18])[0]
        base = opt + opt_len
        size_of_raw, ptr_raw = struct.unpack("<II", data[base + 16:base + 24])
        assert ptr_raw % FILE_ALIGNMENT == 0
        assert ptr_raw + size_of_raw == len(data)

    @pytest.mark.parametrize("bits", BITS)
    def test_aslr_is_stripped(self, bits):
        """Fixup 5: the image has no relocation directory, so the ARM64
        emulation loader rejects it if DYNAMIC_BASE is still set."""
        data = _standalone(0x100, bits)
        opt = _optional_header_offset(data)
        dll_characteristics = struct.unpack("<H", data[opt + 70:opt + 72])[0]
        assert dll_characteristics & 0x0040 == 0, "DYNAMIC_BASE still set"

    def test_misaligned_pe_signature_is_reported(self):
        """The x86 loaders tolerate it; the ARM64 emulation layer does not, so
        the validator has to call it out rather than pass the file."""
        problems = validate_pe(_standalone(0x102))
        assert any("4-byte aligned" in p for p in problems), problems

    @pytest.mark.parametrize("bits", BITS)
    def test_optional_header_length_matches_the_declared_magic(self, bits):
        data = _standalone(0x100, bits)
        opt = _optional_header_offset(data)
        opt_len = struct.unpack("<H", data[opt - 4:opt - 2])[0]
        magic = struct.unpack("<H", data[opt:opt + 2])[0]
        assert (magic, opt_len) == ((0x020B, 240) if bits == 64
                                    else (0x010B, 224))


class TestImagesAreInert:
    """These payloads reproduce structure, not capability.

    C-SCARE builds test cases for scanners and importers. Header geometry is
    what a detector has to parse; a working entry point is not needed to test
    that and would make the catalog something else entirely.
    """

    @pytest.mark.parametrize("bits", BITS)
    def test_no_entry_point(self, bits):
        data = _standalone(0x100, bits)
        opt = _optional_header_offset(data)
        assert struct.unpack("<I", data[opt + 16:opt + 20])[0] == 0

    @pytest.mark.parametrize("bits", BITS)
    def test_no_executable_section(self, bits):
        data = _standalone(0x100, bits)
        opt = _optional_header_offset(data)
        opt_len = struct.unpack("<H", data[opt - 4:opt - 2])[0]
        flags = struct.unpack("<I", data[opt + opt_len + 36:opt + opt_len + 40])[0]
        assert flags & 0x20000000 == 0, "IMAGE_SCN_MEM_EXECUTE set"
        assert flags & 0x00000020 == 0, "IMAGE_SCN_CNT_CODE set"

    @pytest.mark.parametrize("bits", BITS)
    def test_section_contents_are_zero(self, bits):
        data = _standalone(0x100, bits)
        opt = _optional_header_offset(data)
        opt_len = struct.unpack("<H", data[opt - 4:opt - 2])[0]
        base = opt + opt_len
        size_of_raw, ptr_raw = struct.unpack("<II", data[base + 16:base + 24])
        assert data[ptr_raw:ptr_raw + size_of_raw] == b"\x00" * size_of_raw


class TestSafeZoneEnumeration:
    """All five zone types, on a file that has each of them."""

    @pytest.fixture
    def baseline(self):
        from c_scare.attacks import CVEAttacks
        return CVEAttacks._polyglot_part10(b"\x00" * PREAMBLE_LEN)

    def test_preamble_zones_are_always_reported(self, baseline):
        zones = {z.kind: z for z in enumerate_safe_zones(baseline)}
        header, stub = zones["preamble_dos_header"], zones["preamble_dos_stub"]
        assert (header.offset, header.length) == (0, 64)
        assert (stub.offset, stub.length) == (64, 64)
        # The MZ magic and e_lfanew are the only bytes the DOS header owes a
        # loader; the other 58 are free.
        assert header.usable == 58
        assert stub.usable == 64

    def test_private_element_insertion_point_follows_the_meta_group(self, baseline):
        [zone] = [z for z in enumerate_safe_zones(baseline)
                  if z.kind == "private_element"]
        # The File Meta group ends where the Data Set begins, and that is where
        # a private element can be spliced in.
        assert baseline[zone.offset - 4:zone.offset] != b"DICM"
        assert zone.offset > PREAMBLE_LEN + 4
        assert zone.usable == 0xFFFFFFFE

    def test_element_padding_slack_is_found(self, baseline):
        """(0008,0060) 'OT' and (0010,0020) '12345' are odd-length values, so
        each carries a pad byte the declared length covers."""
        pads = [z for z in enumerate_safe_zones(baseline)
                if z.kind == "element_padding"]
        assert pads, "no padding slack found in a file full of odd-length values"
        for zone in pads:
            assert baseline[zone.offset:zone.offset + zone.length].strip(b"\x00 ") == b""

    def test_trailing_zone_starts_where_the_data_set_ends(self, baseline):
        appended = baseline + b"\xde\xad\xbe\xef" * 8
        [zone] = [z for z in enumerate_safe_zones(appended) if z.kind == "trailing"]
        assert zone.offset == len(baseline)
        assert zone.length == 32

    def test_all_five_zone_kinds_are_reachable(self):
        """Every zone type the format admits shows up across the catalog."""
        from c_scare.attacks import CVEAttacks
        kinds = set()
        for result in CVEAttacks.cve_2019_11687_polyglot():
            kinds.update(z.kind for z in enumerate_safe_zones(result.payload))
        assert kinds == {"preamble_dos_header", "preamble_dos_stub",
                         "private_element", "element_padding", "trailing"}

    def test_a_non_part10_blob_yields_no_zones(self):
        assert enumerate_safe_zones(b"not a dicom file" * 20) == []


class TestValidation:
    def test_dicom_validation_rejects_a_bare_pe(self):
        assert validate_dicom(_standalone(0x100)) != []

    def test_pe_validation_rejects_a_dangling_e_lfanew(self):
        data = bytearray(_standalone(0x100))
        struct.pack_into("<I", data, 0x3C, 0xFFFFFF)
        assert any("past the end" in p for p in validate_pe(bytes(data)))

    def test_pe_validation_rejects_a_truncated_section(self):
        data = _standalone(0x100)
        assert any("past the end" in p for p in validate_pe(data[:-8]))

    def test_validate_polyglot_reports_both_pipelines(self):
        report = validate_polyglot(_standalone(0x100))
        assert set(report) == {"pe", "dicom"}
        assert report["pe"] == [] and report["dicom"] != []
