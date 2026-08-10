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
catalog into a malware builder. The same goes for ``elf_image`` (no ``PF_X``,
entry point 0) and ``macho_image`` (no ``VM_PROT_EXECUTE``).

*The formats are held to their own rules.* ELF and Mach-O are not PE with
different magic — the ELF header cannot leave offset 0, ``PT_LOAD`` wants a
congruence rather than an alignment, and Mach-O's load commands are pinned
behind its header with only 96 bytes of preamble to live in. Tests below pin
each of those constraints so a future "simplification" that assumes
equivalence fails.

*Fragmentation really fragments.* A PE split across zones is only a detection
test if the image is genuinely non-contiguous in the file, so that is asserted
against the built payload rather than assumed from the builder.
"""

import struct

import pytest

pytest.importorskip("pydicom")

from c_scare import polyglot  # noqa: E402
from c_scare.polyglot import (  # noqa: E402
    FILE_ALIGNMENT, FILL_PROFILES, MACHO_HEADER_LEN, PREAMBLE_LEN,
    SECTION_64_LEN, SEGMENT_COMMAND_64_LEN, dos_header, dos_stub, elf_header,
    elf_fragments, elf_image, enumerate_safe_zones, executable_format, filler,
    macho_header,
    macho_image, pe_fragments, pe_headers_len, pe_image, shannon_entropy,
    validate_dicom, validate_elf, validate_macho, validate_pe,
    validate_polyglot,
)

# Offsets that exercise both the "headers fit in one FileAlignment block" and
# the "headers spill into the next" cases, plus a deliberately odd one.
OFFSETS = [0x40, 0x100, 0x180, 0x400]
BITS = [32, 64]


def _standalone(pe_offset, bits=64):
    """A minimal file: DOS header, filler, then the PE image at ``pe_offset``."""
    head = dos_header(pe_offset)
    return head + b"\x00" * (pe_offset - len(head)) + pe_image(pe_offset, bits=bits)


def _standalone_elf(ph_offset, bits=64):
    """ELF header at 0, program headers and segment at ``ph_offset``."""
    head = elf_header(ph_offset, ph_count=1, bits=bits)
    return (head + b"\x00" * (ph_offset - len(head)) +
            elf_image(ph_offset, bits=bits))


def _standalone_macho(segment_offset, arch="arm64", segment_size=0x200):
    """Header and load commands at 0, segment contents at ``segment_offset``."""
    head = macho_header(segment_offset, segment_size, arch=arch)
    return (head + b"\x00" * (segment_offset - len(head)) +
            macho_image(segment_size))


def _optional_header_offset(data):
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    return e_lfanew + 4 + 20


def _read_pe_pieces(data):
    """Reassemble a PE from its section table: ``(headers, [section_data])``.

    This is what a scanner that follows structure does, as opposed to matching
    a contiguous run of bytes. On a fragmented payload the two disagree, which
    is the property under test.
    """
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    num_sections = struct.unpack("<H", data[e_lfanew + 6:e_lfanew + 8])[0]
    opt_len = struct.unpack("<H", data[e_lfanew + 20:e_lfanew + 22])[0]
    bits = 64 if struct.unpack(
        "<H", data[e_lfanew + 24:e_lfanew + 26])[0] == 0x020B else 32
    headers = data[e_lfanew:
                   e_lfanew + pe_headers_len(bits, sections=num_sections)]
    sections_offset = e_lfanew + 4 + 20 + opt_len
    sections = []
    for i in range(num_sections):
        base = sections_offset + i * 40
        size_of_raw, ptr_raw = struct.unpack("<II", data[base + 16:base + 24])
        sections.append(data[ptr_raw:ptr_raw + size_of_raw])
    return headers, sections


def _read_first_pt_load(data, bits=64):
    """``(p_offset, p_vaddr, p_align)`` of the first PT_LOAD segment."""
    if bits == 64:
        e_phoff = struct.unpack("<Q", data[32:40])[0]
        p_offset, p_vaddr = struct.unpack("<QQ", data[e_phoff + 8:e_phoff + 24])
        p_align = struct.unpack("<Q", data[e_phoff + 48:e_phoff + 56])[0]
    else:
        e_phoff = struct.unpack("<I", data[28:32])[0]
        p_offset, p_vaddr = struct.unpack("<II", data[e_phoff + 4:e_phoff + 12])
        p_align = struct.unpack("<I", data[e_phoff + 28:e_phoff + 32])[0]
    return p_offset, p_vaddr, p_align


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


class TestTrailingZoneIsNotClaimedOverParsedContent:
    """The trailing zone must mean "past the Data Set", not "past the walker".

    The walk stops at a sequence or an undefined length because it does not
    descend into them, not because the Data Set ended. Reporting the remainder
    as trailing slack told a defender that parsed content was unreachable —
    and since a clinical image nearly always carries a sequence or compressed
    pixel data, it said so on nearly every real file.
    """

    def _file_ending_with(self, element_bytes):
        from c_scare.attacks import CVEAttacks
        part10 = CVEAttacks._polyglot_file(b"\x00" * PREAMBLE_LEN)
        part10.dataset = CVEAttacks._polyglot_body() + element_bytes
        return part10.encode()

    @pytest.fixture
    def with_encapsulated_pixel_data(self):
        from c_scare.element import Element
        from c_scare.pixel import EncapsulatedPixelData
        epd = EncapsulatedPixelData()
        epd.add_fragment(b"\xff\xd8\xff\xe0JFIF\xff\xd9")
        return self._file_ending_with(Element.raw(
            tag=0x7FE00010, vr="OB", value=epd.encode(),
            length=0xFFFFFFFF).encode(implicit_vr=False, little_endian=True))

    @pytest.fixture
    def with_sequence(self):
        from c_scare.element import Dataset, Element, Sequence
        seq = Sequence([Dataset([Element(0x0008, 0x0100, "SH", "CODE1")])])
        return self._file_ending_with(Element.raw(
            tag=0x00081110, vr="SQ", value=seq.encode(),
            length=0xFFFFFFFF).encode(implicit_vr=False, little_endian=True))

    def test_encapsulated_pixel_data_is_not_reported_as_trailing(
            self, with_encapsulated_pixel_data):
        kinds = [z.kind for z in
                 enumerate_safe_zones(with_encapsulated_pixel_data)]
        assert "trailing" not in kinds, (
            "encapsulated Pixel Data reported as bytes readers never reach")

    def test_a_sequence_is_not_reported_as_trailing(self, with_sequence):
        kinds = [z.kind for z in enumerate_safe_zones(with_sequence)]
        assert "trailing" not in kinds, (
            "a sequence reported as bytes readers never reach")

    @pytest.mark.parametrize("fixture_name",
                             ["with_encapsulated_pixel_data", "with_sequence"])
    def test_no_zone_overlaps_the_unfollowable_element(self, fixture_name,
                                                       request):
        """Nothing reported may start at or past where the walk gave up.

        Stronger than the two checks above: it fails for any zone kind that
        starts claiming bytes the walker never classified, not just trailing.
        """
        data = request.getfixturevalue(fixture_name)
        scan = polyglot._scan_dataset(data, polyglot.dataset_offset(data))
        assert scan.stop == polyglot._STOP_UNFOLLOWABLE
        for zone in enumerate_safe_zones(data):
            assert zone.offset < scan.end or zone.length == 0, (
                f"{zone.kind} at {zone.offset} claims bytes past the point the "
                f"walk stopped ({scan.end})")

    def test_genuinely_appended_bytes_are_still_reported(self):
        """The fix must not cost the real case: junk after a flat Data Set."""
        from c_scare.attacks import CVEAttacks
        base = CVEAttacks._polyglot_part10(b"\x00" * PREAMBLE_LEN)
        appended = base + b"\xde\xad\xbe\xef" * 8
        [zone] = [z for z in enumerate_safe_zones(appended)
                  if z.kind == "trailing"]
        assert (zone.offset, zone.length) == (len(base), 32)

    def test_a_data_set_ending_at_eof_reports_an_empty_trailing_zone(self):
        """Exhausting the file is a real answer: zero bytes of slack."""
        from c_scare.attacks import CVEAttacks
        base = CVEAttacks._polyglot_part10(b"\x00" * PREAMBLE_LEN)
        [zone] = [z for z in enumerate_safe_zones(base) if z.kind == "trailing"]
        assert (zone.offset, zone.length) == (len(base), 0)

    def test_scan_distinguishes_its_two_stop_reasons(self, with_sequence):
        """The distinction the whole fix rests on, asserted directly."""
        from c_scare.attacks import CVEAttacks
        flat = CVEAttacks._polyglot_part10(b"\x00" * PREAMBLE_LEN)
        assert polyglot._scan_dataset(
            flat, polyglot.dataset_offset(flat)).stop == polyglot._STOP_EXHAUSTED
        assert polyglot._scan_dataset(
            flat + b"\xde\xad\xbe\xef",
            polyglot.dataset_offset(flat)).stop == polyglot._STOP_END_OF_DATASET
        assert polyglot._scan_dataset(
            with_sequence, polyglot.dataset_offset(with_sequence)
        ).stop == polyglot._STOP_UNFOLLOWABLE


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

    def test_validate_polyglot_dispatches_on_the_magic(self):
        """The executable half must be judged by its own format's rules."""
        assert set(validate_polyglot(_standalone_elf(0x200))) == {"elf", "dicom"}
        assert set(validate_polyglot(_standalone_macho(0x200))) == {
            "macho", "dicom"}
        assert set(validate_polyglot(b"not an executable" * 20)) == {
            "executable", "dicom"}

    @pytest.mark.parametrize("data,expected", [
        (b"MZ" + b"\x00" * 200, "pe"),
        (b"\x7fELF" + b"\x00" * 200, "elf"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 200, "macho"),
        (b"II*\x00" + b"\x00" * 200, None),
    ])
    def test_executable_format_is_a_magic_table(self, data, expected):
        assert executable_format(data) == expected


# ---------------------------------------------------------------------------
# §5.1 - fragmentation across zones
# ---------------------------------------------------------------------------

class TestFragmentation:
    """One image, several zones, nothing contiguous.

    ``PointerToRawData`` is a free file offset, so a PE's sections do not have
    to follow its headers or each other. Splitting them across safe zones with
    Data Set structure in between leaves the loader's job unchanged and breaks
    any signature written over a contiguous image. No executable content is
    involved - the evasion is entirely the layout, which is why it belongs in
    a detection-test catalog.
    """

    @pytest.fixture
    def catalog_payload(self):
        from c_scare.attacks import CVEAttacks
        return [r for r in CVEAttacks.cve_2019_11687_polyglot()
                if r.metadata.get("zone") == "fragmented"][0]

    def test_the_assembled_image_appears_nowhere_in_the_file(self,
                                                             catalog_payload):
        """The whole point: reassembly needs the section table, not a memcmp."""
        data = catalog_payload.payload
        headers, sections = _read_pe_pieces(data)
        assert len(sections) > 1, "a one-section image is not fragmented"
        assert headers + b"".join(sections) not in data
        assert headers + sections[0] not in data
        for first, second in zip(sections, sections[1:]):
            assert first + second not in data

    def test_every_fragment_is_where_the_metadata_says(self, catalog_payload):
        """``metadata['fragments']`` is what a consumer plans a scan around."""
        data = catalog_payload.payload
        _headers, sections = _read_pe_pieces(data)
        placed = {f["zone"]: f for f in catalog_payload.metadata["fragments"]}
        assert set(placed) >= {"private_element", "element_padding", "trailing"}
        for fragment in catalog_payload.metadata["fragments"]:
            assert fragment["offset"] + fragment["length"] <= len(data)
        for section, zone in zip(sections, ("element_padding", "trailing")):
            fragment = placed[zone]
            assert data[fragment["offset"]:
                        fragment["offset"] + len(section)] == section

    def test_the_fragments_are_separated_by_real_dicom_structure(
            self, catalog_payload):
        """Slack between fragments would be a giveaway; elements are not.

        Every gap has to contain a Data Element a reader actually parses, or
        the file is just an image with padding holes in it.
        """
        data = catalog_payload.payload
        zones = {z.kind for z in enumerate_safe_zones(data)}
        assert {"private_element", "element_padding", "trailing"} <= zones
        start = polyglot.dataset_offset(data)
        tags = [tag for tag, _vr, _off, _len
                in polyglot._walk_explicit_vr_le(data, start)]
        # The patient elements sit between the last private carrier and the
        # trailing region, so the last fragment is not merely appended slack.
        assert (0x0010, 0x0020) in tags
        assert (0x0009, 0x1001) in tags and (0x0009, 0x1002) in tags

    def test_fragmented_image_still_validates_as_a_pe(self, catalog_payload):
        assert validate_pe(catalog_payload.payload) == []

    def test_sections_may_be_placed_anywhere_aligned_and_clear(self):
        headers, sections = pe_fragments(
            0x200, [(0x1000, 0x200), (0x4000, 0x400)], names=[b".a", b".b"])
        assert len(sections) == 2
        assert len(headers) == pe_headers_len(64, sections=2)
        assert [len(s) for s in sections] == [0x200, 0x400]

    def test_a_misaligned_placement_is_rejected(self):
        """A section that is not FileAlignment-aligned makes the loader refuse
        the image, so the builder refuses it first."""
        with pytest.raises(ValueError, match="FileAlignment"):
            pe_fragments(0x200, [(0x1001, 0x200)])

    def test_a_placement_inside_the_headers_is_rejected(self):
        with pytest.raises(ValueError, match="overlaps the headers"):
            pe_fragments(0x200, [(0x200, 0x200)])

    def test_validate_pe_catches_a_section_moved_into_the_headers(self):
        """The validator has to catch it too, not just the builder."""
        data = bytearray(_standalone(0x100))
        opt = _optional_header_offset(data)
        opt_len = struct.unpack("<H", data[opt - 4:opt - 2])[0]
        struct.pack_into("<I", data, opt + opt_len + 20, 0)  # PointerToRawData
        assert any("overlaps the headers" in p
                   for p in validate_pe(bytes(data)))


# ---------------------------------------------------------------------------
# §9 - ELF and Mach-O are not PE
# ---------------------------------------------------------------------------

class TestELFGeometry:
    @pytest.mark.parametrize("bits", BITS)
    @pytest.mark.parametrize("offset", [0x100, 0x188, 0x200])
    def test_relocated_program_headers_pass_validation(self, offset, bits):
        assert validate_elf(_standalone_elf(offset, bits)) == []

    @pytest.mark.parametrize("bits", BITS)
    def test_header_size_matches_the_declared_class(self, bits):
        assert len(elf_header(bits=bits)) == polyglot.ELF_HEADER_LEN[bits]

    def test_the_elf_header_fits_the_first_half_of_the_preamble(self):
        """64 bytes exactly - the same span the MZ DOS header occupies."""
        assert len(elf_header()) == polyglot.DOS_HEADER_LEN

    @pytest.mark.parametrize("bits", BITS)
    @pytest.mark.parametrize("offset", [0x100, 0x188, 0x1F8])
    def test_pt_load_is_congruent_rather_than_aligned(self, offset, bits):
        """ELF's rule is ``p_offset ≡ p_vaddr (mod p_align)``.

        This is the concrete non-equivalence with PE: an ELF segment may start
        at an offset that is not a multiple of anything, so long as the virtual
        address agrees with it. 0x188 and 0x1F8 are deliberately not
        FileAlignment-aligned, and a PE section there would be rejected.
        """
        data = _standalone_elf(offset, bits)
        p_offset, p_vaddr, p_align = _read_first_pt_load(data, bits)
        assert p_offset % FILE_ALIGNMENT != 0, (
            f"p_offset={p_offset} happens to be FileAlignment-aligned, so this "
            "case no longer distinguishes ELF's rule from PE's")
        assert (p_offset - p_vaddr) % p_align == 0
        assert validate_elf(data) == [], (
            "an unaligned segment offset is legal ELF and must validate")

    def test_program_header_field_order_differs_by_class(self):
        """``p_flags`` is field 2 in Elf64_Phdr and field 7 in Elf32_Phdr."""
        image64 = elf_image(0x200, bits=64)
        image32 = elf_image(0x200, bits=32)
        assert struct.unpack("<I", image64[4:8])[0] == 4          # PF_R
        assert struct.unpack("<I", image32[24:28])[0] == 4        # PF_R

    @pytest.mark.parametrize("bits", BITS)
    def test_images_are_inert(self, bits):
        """No entry point and no executable segment."""
        data = _standalone_elf(0x200, bits)
        entry_offset = 24
        fmt = "<Q" if bits == 64 else "<I"
        assert struct.unpack(fmt, data[entry_offset:entry_offset +
                                       struct.calcsize(fmt)])[0] == 0
        image = elf_image(0x200, bits=bits)
        flags = (struct.unpack("<I", image[4:8])[0] if bits == 64
                 else struct.unpack("<I", image[24:28])[0])
        assert flags & 0x1 == 0, "PF_X set on a PT_LOAD segment"

    def test_validation_rejects_a_segment_running_past_the_file(self):
        data = _standalone_elf(0x200)
        assert any("past the end" in p for p in validate_elf(data[:-16]))

    def test_validation_rejects_a_broken_congruence(self):
        data = bytearray(_standalone_elf(0x200))
        e_phoff = struct.unpack("<Q", data[32:40])[0]
        p_vaddr = struct.unpack("<Q", data[e_phoff + 16:e_phoff + 24])[0]
        struct.pack_into("<Q", data, e_phoff + 16, p_vaddr + 1)
        assert any("congruent" in p for p in validate_elf(bytes(data)))

    def test_validation_rejects_a_mismatched_phentsize(self):
        data = bytearray(_standalone_elf(0x200))
        struct.pack_into("<H", data, 54, 48)  # e_phentsize
        assert any("e_phentsize" in p for p in validate_elf(bytes(data)))

    def test_a_pe_is_not_a_valid_elf(self):
        assert validate_elf(_standalone(0x100)) != []


class TestMachOGeometry:
    def test_the_preamble_bounds_the_load_commands(self):
        """96 bytes of load-command room: one LC_SEGMENT_64 and no sections.

        Mach-O defines its load commands to begin immediately after the header
        rather than at a pointer, so everything structural has to share the
        preamble with the magic. The arithmetic below is the whole reason
        ``macho_header`` emits ``nsects=0``, and it is asserted rather than
        described so the claim cannot rot.
        """
        header_and_segment = MACHO_HEADER_LEN[64] + SEGMENT_COMMAND_64_LEN
        assert header_and_segment <= PREAMBLE_LEN
        assert header_and_segment + SECTION_64_LEN > PREAMBLE_LEN
        assert header_and_segment + SEGMENT_COMMAND_64_LEN > PREAMBLE_LEN

    def test_header_block_is_104_bytes_and_fits_the_preamble(self):
        block = macho_header(0x200, 0x200)
        assert len(block) == MACHO_HEADER_LEN[64] + SEGMENT_COMMAND_64_LEN
        assert len(block) <= PREAMBLE_LEN

    @pytest.mark.parametrize("arch", ["arm64", "x86_64"])
    def test_relocated_segment_contents_pass_validation(self, arch):
        assert validate_macho(_standalone_macho(0x200, arch=arch)) == []

    def test_arm64_and_x86_64_disagree_about_page_alignment(self):
        """A vmaddr legal on x86-64 is not legal on arm64: 4 KiB against 16.

        Assuming one page size across architectures is exactly the kind of
        equivalence §9 warns against, so the builder rejects it.
        """
        assert macho_header(0x200, 0x200, arch="x86_64", vmaddr=0x1000)
        with pytest.raises(ValueError, match="page-aligned"):
            macho_header(0x200, 0x200, arch="arm64", vmaddr=0x1000)

    def test_vmsize_is_rounded_to_the_architecture_page(self):
        data = _standalone_macho(0x200, arch="arm64")
        pos = MACHO_HEADER_LEN[64]
        vmsize = struct.unpack("<Q", data[pos + 32:pos + 40])[0]
        assert vmsize == polyglot.MACHO_PAGE_SIZE["arm64"]

    def test_images_are_inert(self):
        """Neither maxprot nor initprot carries VM_PROT_EXECUTE."""
        data = _standalone_macho(0x200)
        pos = MACHO_HEADER_LEN[64]
        maxprot, initprot = struct.unpack("<ii", data[pos + 56:pos + 64])
        assert maxprot & 0x4 == 0 and initprot & 0x4 == 0

    def test_validation_rejects_a_segment_running_past_the_file(self):
        data = _standalone_macho(0x200)
        assert any("past the end" in p for p in validate_macho(data[:-16]))

    def test_validation_rejects_an_inconsistent_command_chain(self):
        data = bytearray(_standalone_macho(0x200))
        struct.pack_into("<I", data, MACHO_HEADER_LEN[64] + 4, 40)  # cmdsize
        assert validate_macho(bytes(data)) != []

    def test_a_pe_is_not_a_valid_macho(self):
        assert validate_macho(_standalone(0x100)) != []


# ---------------------------------------------------------------------------
# §9 - entropy shaping
# ---------------------------------------------------------------------------

class TestContentShaping:
    """Zero-filled sections are a tell, and a benchmark should not carry one.

    A detector evaluated only against zero-filled payloads can score well by
    keying on the zeros. These profiles give the same construction several
    different histograms so that shortcut stops working.
    """

    SIZE = 0x1000

    def test_profiles_are_ordered_by_entropy(self):
        measured = [shannon_entropy(filler(p, self.SIZE))
                    for p in FILL_PROFILES]
        assert measured == sorted(measured), dict(zip(FILL_PROFILES, measured))

    @pytest.mark.parametrize("profile,low,high", [
        ("zeros", 0.0, 0.0),
        ("tabular", 2.0, 4.0),
        ("strings", 4.0, 6.0),
        ("packed", 7.5, 8.0),
    ])
    def test_each_profile_lands_in_its_band(self, profile, low, high):
        assert low <= shannon_entropy(filler(profile, self.SIZE)) <= high

    def test_profiles_are_deterministic(self):
        for profile in FILL_PROFILES:
            assert filler(profile, 512, seed=3) == filler(profile, 512, seed=3)

    @pytest.mark.parametrize("profile", FILL_PROFILES)
    def test_requested_length_is_exact(self, profile):
        for length in (0, 1, 7, 512, 1000):
            assert len(filler(profile, length)) == length

    def test_an_unknown_profile_is_rejected(self):
        with pytest.raises(ValueError, match="unknown fill profile"):
            filler("gzip", 16)

    @pytest.mark.parametrize("profile", FILL_PROFILES)
    def test_shaping_does_not_compromise_inertness(self, profile):
        """Filling a section must not turn it into a code section.

        This is the guard that matters most here: 'make it look real' is
        exactly the change that would smuggle in an executable section or an
        entry point.
        """
        data = (dos_header(0x100) + b"\x00" * (0x100 - 64) +
                pe_image(0x100, fill=profile, section_size=self.SIZE))
        assert validate_pe(data) == []
        opt = _optional_header_offset(data)
        assert struct.unpack("<I", data[opt + 16:opt + 20])[0] == 0
        opt_len = struct.unpack("<H", data[opt - 4:opt - 2])[0]
        flags = struct.unpack("<I", data[opt + opt_len + 36:
                                         opt + opt_len + 40])[0]
        assert flags & 0x20000000 == 0, "IMAGE_SCN_MEM_EXECUTE set"
        assert flags & 0x00000020 == 0, "IMAGE_SCN_CNT_CODE set"

    def test_the_dos_stub_carries_a_message_and_no_code(self):
        """A real PE has the DOS message here; an all-NUL stub is the anomaly.

        The 16-bit code that prints it is deliberately not emitted, so the
        stub is inert even under a DOS loader.
        """
        stub = dos_stub()
        assert stub.startswith(b"This program cannot be run in DOS mode.")
        assert len(stub) == PREAMBLE_LEN - polyglot.DOS_HEADER_LEN
        assert b"\xcd\x21" not in stub, "INT 21h in a stub that should be data"
        assert b"\xb4\x09" not in stub, "DOS print-string call in the stub"

    def test_shaped_catalog_payloads_bracket_the_entropy_range(self):
        """The two shaped payloads must actually differ, not just be labelled."""
        from c_scare.attacks import CVEAttacks
        shaped = {r.metadata["fill"]: r
                  for r in CVEAttacks.cve_2019_11687_polyglot()
                  if r.metadata.get("fill")}
        assert set(shaped) == {"strings", "packed"}
        assert (shaped["strings"].metadata["section_entropy"] + 2 <
                shaped["packed"].metadata["section_entropy"])
        for result in shaped.values():
            assert validate_polyglot(result.payload) == {"pe": [], "dicom": []}


class TestELFFragmentsWhereAPECannot:
    """ELF's placement rule is weaker than PE's, and that widens the surface.

    A PE section must start on a 512-byte ``FileAlignment`` boundary at or
    past ``SizeOfHeaders``. An ELF ``PT_LOAD`` needs only ``p_offset``
    congruent to ``p_vaddr`` modulo ``p_align``, which any offset can satisfy
    by choosing the address. A scanner that searches only the regions a PE
    could occupy misses the ones an ELF can.
    """

    def _payload(self):
        from c_scare.attacks import CVEAttacks
        return CVEAttacks._fragmented_elfdicom()

    def test_a_segment_lands_in_the_zone_pe_had_to_leave_empty(self):
        """Preamble bytes 0x40-0x7F: 64 bytes, unaligned, before SizeOfHeaders."""
        _data, fragments = self._payload()
        stub = next(f for f in fragments if f["zone"] == "preamble_dos_stub")
        assert stub["offset"] == polyglot.DOS_HEADER_LEN
        assert stub["length"] == PREAMBLE_LEN - polyglot.DOS_HEADER_LEN
        # The same placement offered to the PE builder is rejected outright.
        with pytest.raises(ValueError):
            pe_fragments(0x200, [(stub["offset"], stub["length"])])

    def test_segments_sit_at_offsets_no_pe_section_could_use(self):
        data, fragments = self._payload()
        assert validate_elf(data) == []
        unaligned = [f for f in fragments
                     if f["zone"] != "private_element"
                     and f["offset"] % FILE_ALIGNMENT]
        assert len(unaligned) >= 2, (
            "every segment happens to be FileAlignment-aligned, so this "
            "payload no longer distinguishes ELF's rule from PE's")

    def test_the_assembled_image_appears_nowhere_in_the_file(self):
        data, fragments = self._payload()
        pieces = [data[f["offset"]:f["offset"] + f["length"]]
                  for f in fragments]
        assert b"".join(pieces) not in data
        for first, second in zip(pieces, pieces[1:]):
            assert first + second not in data

    def test_program_headers_describe_every_fragment(self):
        """readelf has to be able to reassemble it; so does a scanner."""
        data, fragments = self._payload()
        e_phoff = struct.unpack("<Q", data[32:40])[0]
        e_phnum = struct.unpack("<H", data[56:58])[0]
        segments = [f for f in fragments if f["zone"] != "private_element"]
        assert e_phnum == len(segments)
        for i, fragment in enumerate(segments):
            base = e_phoff + i * polyglot.ELF_PHDR_LEN[64]
            p_offset = struct.unpack("<Q", data[base + 8:base + 16])[0]
            assert p_offset == fragment["offset"], (
                f"PT_LOAD {i} points at {p_offset}, fragment map says "
                f"{fragment['offset']}")

    def test_virtual_addresses_ascend_without_overlapping(self):
        """The kernel maps PT_LOADs in order and rejects colliding ranges."""
        table, _segments = elf_fragments(0x100, [(0x40, 64), (0x23e, 0x100),
                                                 (0x35c, 0x100)])
        previous_end = 0
        for i in range(3):
            base = i * polyglot.ELF_PHDR_LEN[64]
            p_vaddr = struct.unpack("<Q", table[base + 16:base + 24])[0]
            p_memsz = struct.unpack("<Q", table[base + 40:base + 48])[0]
            assert p_vaddr >= previous_end
            previous_end = p_vaddr + p_memsz

    def test_validation_rejects_overlapping_segments(self):
        data, _fragments = self._payload()
        broken = bytearray(data)
        e_phoff = struct.unpack("<Q", data[32:40])[0]
        second = e_phoff + polyglot.ELF_PHDR_LEN[64]
        struct.pack_into("<Q", broken, second + 16, 0)   # p_vaddr below the first
        assert any("overlaps or precedes" in p
                   for p in validate_elf(bytes(broken)))

    @pytest.mark.parametrize("elf_type,label", [(polyglot.ELF_TYPE_EXEC, "EXEC"),
                                                (polyglot.ELF_TYPE_DYN, "DYN")])
    def test_both_elf_types_are_emitted(self, elf_type, label):
        """PIE binaries are ET_DYN, and file(1) calls them shared objects.

        A scanner keyed on 'ELF executable' misses every PIE on a modern
        Linux system, so both types have to be producible.
        """
        header = elf_header(0x200, ph_count=1, elf_type=elf_type)
        assert struct.unpack("<H", header[16:18])[0] == elf_type

    def test_an_unknown_elf_type_is_rejected(self):
        with pytest.raises(ValueError, match="elf_type"):
            elf_header(elf_type=99)
