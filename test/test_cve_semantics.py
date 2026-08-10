# SPDX-License-Identifier: GPL-2.0-only
"""Do CVE payloads carry the mechanism they claim?

``test_cve_coverage.py`` checks the plumbing: every ``cve_*`` method is wired
into ``all()``, payloads are non-empty, the expected CVE set is present. All of
that can pass while a payload has quietly stopped encoding the thing it is
named after — an edit to a shared helper, a changed offset, a padding fix.

These tests assert the *structure* instead. Each one names the property that
makes the payload a reproduction of its CVE rather than an arbitrary blob, so a
regression shows up as "this stopped being the attack" instead of silently
turning into a target-side rejection that reads like a clean result.
"""

import struct

import pytest

pytest.importorskip("pydicom")

from pydicom.filebase import DicomBytesIO  # noqa: E402
from pydicom.filereader import read_dataset  # noqa: E402

from c_scare import polyglot  # noqa: E402
from c_scare.attacks import CVEAttacks  # noqa: E402

ALL = list(CVEAttacks.all())

# Magic bytes that make each polyglot flavour recognisable as a second format.
POLYGLOT_MAGIC = {
    "PE": (b"MZ",),
    "ELF": (b"\x7fELF",),
    "shell": (b"#!",),
    "batch": (b"@", b"\xEF\xBB\xBF"),
    "TIFF": (b"II", b"MM"),
    "MachO": (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"),
}

# Zones that hold the second format's *body* somewhere a conforming DICOM
# reader traverses without inspecting, rather than in the preamble.
BURIED_ZONES = {"private_element", "element_padding", "trailing", "fragmented"}


def by_cve(cve):
    return [r for r in ALL if r.metadata.get("cve") == cve]


def with_meta(key):
    return [r for r in ALL if r.metadata.get(key) is not None]


def flavoured():
    """CVE-2019-11687 payloads that claim to be a second *executable* format.

    Not every payload under this CVE is one. The private-element container
    payloads exercise the same opaque-element property without pretending to
    be a PE, so holding them to dual-format rules would assert something they
    never claimed.
    """
    return [r for r in by_cve("CVE-2019-11687") if r.metadata.get("polyglot")]


def buried():
    """Polyglots whose second-format body lives past the preamble."""
    return [r for r in flavoured()
            if r.metadata.get("zone") in BURIED_ZONES]


def buried_pe():
    """The buried polyglots that are specifically PE."""
    return [r for r in buried() if r.metadata.get("polyglot") == "PE"]


def foreign_body_offset(payload):
    """Where the executable half says the rest of itself lives.

    Each format answers with a different field, and that is the point: a
    scanner has to know all three to follow any of them. PE hands over
    ``e_lfanew``, ELF ``e_phoff``, Mach-O the ``fileoff`` of its first
    ``LC_SEGMENT_64`` — which is buried behind the load-command walk rather
    than at a fixed offset.
    """
    fmt = polyglot.executable_format(payload)
    if fmt == "pe":
        return struct.unpack("<I", payload[60:64])[0]
    if fmt == "elf":
        # e_phoff sits at a different offset and width per ELF class: byte 32
        # as a 64-bit value in Elf64_Ehdr, byte 28 as a 32-bit one in
        # Elf32_Ehdr. Reading the 64-bit field out of a 32-bit header is the
        # exact mistake payload 19 exists to catch a scanner making.
        if payload[4] == 1:                      # EI_CLASS = ELFCLASS32
            return struct.unpack("<I", payload[28:32])[0]
        return struct.unpack("<Q", payload[32:40])[0]
    if fmt == "macho":
        pos = polyglot.MACHO_HEADER_LEN[64]
        ncmds = struct.unpack("<I", payload[16:20])[0]
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack("<II", payload[pos:pos + 8])
            if cmd == 0x19:  # LC_SEGMENT_64
                return struct.unpack("<Q", payload[pos + 40:pos + 48])[0]
            pos += cmdsize
    return None


class TestPolyglotsAreActuallyDualFormat:
    """CVE-2019-11687 is *executable embedding*: the file has to be both.

    A payload that is only valid DICOM tests nothing — the point is that the
    same bytes satisfy a loader and a DICOM reader at once, so an AV engine
    keyed on offset 0 and a PACS keyed on offset 128 disagree about what the
    file is.
    """

    @pytest.mark.parametrize("result", flavoured(), ids=lambda r: r.name)
    def test_executable_magic_sits_at_offset_zero(self, result):
        flavour = result.metadata["polyglot"]
        magic = POLYGLOT_MAGIC[flavour]
        assert result.payload.startswith(magic), (
            f"{flavour} polyglot does not start with {magic}; "
            f"got {result.payload[:4]!r}")

    @pytest.mark.parametrize("result", by_cve("CVE-2019-11687"),
                             ids=lambda r: r.name)
    def test_dicm_magic_still_sits_at_offset_128(self, result):
        """The preamble trick only works if the DICOM half stays valid."""
        assert result.payload[128:132] == b"DICM"

    @pytest.mark.parametrize("result", by_cve("CVE-2019-11687"),
                             ids=lambda r: r.name)
    def test_preamble_is_exactly_128_bytes(self, result):
        """Executable content must fit the preamble, not push DICM along."""
        assert result.payload.index(b"DICM") == 128

    @pytest.mark.parametrize("result", buried_pe(), ids=lambda r: r.name)
    def test_e_lfanew_lands_on_a_real_pe_signature(self, result):
        """e_lfanew must jump out of the preamble *and hit something*.

        A scanner that only matches 'MZ' at offset 0 flags the file; one that
        follows e_lfanew reaches the PE image. That divergence is the whole
        attack, and it only exists if there is a PE image at the other end —
        an e_lfanew pointing at DICM makes the payload a magic-byte probe
        wearing a PEDICOM label.
        """
        e_lfanew = struct.unpack("<I", result.payload[60:64])[0]
        assert e_lfanew >= 132, (
            f"e_lfanew={e_lfanew} still inside the preamble or the DICM magic")
        assert result.payload[e_lfanew:e_lfanew + 4] == b"PE\x00\x00", (
            f"e_lfanew={e_lfanew} points at "
            f"{result.payload[e_lfanew:e_lfanew + 4]!r}, not a PE signature")
        assert e_lfanew % 4 == 0, (
            f"e_lfanew={e_lfanew} is not 4-byte aligned; the ARM64 emulation "
            "loader rejects the image")

    @pytest.mark.parametrize("result", buried(), ids=lambda r: r.name)
    def test_both_halves_validate(self, result):
        """The dual-pipeline check: valid executable *and* valid DICOM.

        Either half failing collapses the test case. A broken executable half
        is a DICOM file no scanner cares about; a broken DICOM half is an
        executable no PACS accepts, and the storage path under test is never
        exercised. The executable half is dispatched on the magic at offset 0,
        so an ELF payload is held to ELF's rules rather than to PE's.
        """
        fmt = polyglot.executable_format(result.payload)
        assert fmt is not None, "no executable magic at offset 0"
        assert polyglot.validate_polyglot(result.payload) == {
            fmt: [], "dicom": []}

    @pytest.mark.parametrize("result", buried(), ids=lambda r: r.name)
    def test_the_foreign_body_sits_past_everything_dicom_parses(self, result):
        """Each buried payload must really use a region no reader inspects.

        The preamble and File Meta group are what every reader — and every
        scanner worth the name — parses. These payloads exist to test what
        comes after: regions a conforming parser traverses on its way past,
        which is only interesting if the second format's body is genuinely
        out there. Each format points at its body with a different field, so
        the check follows whichever one applies.
        """
        body = foreign_body_offset(result.payload)
        assert body is not None, "no relocation pointer found in the header"
        start = polyglot.dataset_offset(result.payload)
        assert start is not None, "File Meta group is not parseable"
        assert body >= start, (
            f"the body pointer {body} lands inside the File Meta group "
            f"(Data Set starts at {start}); nothing is hidden")


class TestTraversalPayloadsCarryTheirTraversal:
    """A path-traversal reproduction has to contain the traversal.

    If the escape sequence is dropped or sanitised while building the payload,
    the attack still delivers and the target still stores a file — in the
    correct directory. The run then reports no finding, which is wrong.
    """

    @pytest.mark.parametrize("result", with_meta("traversal_payload"),
                             ids=lambda r: r.name)
    def test_declared_traversal_is_present_in_the_bytes(self, result):
        declared = result.metadata["traversal_payload"]
        assert declared.encode() in result.payload, (
            f"{result.name} declares traversal {declared!r} that is not in "
            f"its payload")

    @pytest.mark.parametrize("result", with_meta("traversal_payload"),
                             ids=lambda r: r.name)
    def test_traversal_escapes_or_is_absolute(self, result):
        declared = result.metadata["traversal_payload"]
        assert declared.startswith("/") or ".." in declared, (
            f"{declared!r} neither escapes upward nor is absolute — "
            "it would land inside the storage root")


class TestPart10PayloadsAreWellFormed:
    """CVE payloads shipped as files must survive being read as files.

    43 of the CVE payloads are complete Part-10 objects so they double as
    file-parser fuzzing seeds. A malformed *wrapper* means the seed is rejected
    at the front door and the bug class inside it is never reached.
    """

    PART10 = [r for r in ALL if r.payload[128:132] == b"DICM"]

    @pytest.mark.parametrize("result", PART10, ids=lambda r: r.name)
    def test_preamble_and_magic(self, result):
        assert len(result.payload) > 132
        assert result.payload[128:132] == b"DICM"

    @pytest.mark.parametrize("result", PART10, ids=lambda r: r.name)
    def test_file_meta_group_starts_the_dataset(self, result):
        """Byte 132 begins the File Meta group, which is always (0002,xxxx)."""
        group = struct.unpack("<H", result.payload[132:134])[0]
        assert group == 0x0002, (
            f"{result.name}: first element after DICM is group "
            f"0x{group:04X}, not the File Meta group")


class TestCatalogWideInvariants:
    def test_every_payload_is_nonempty_bytes(self):
        for result in ALL:
            assert isinstance(result.payload, (bytes, bytearray)), result.name
            assert result.payload, result.name

    def test_every_payload_declares_a_cve(self):
        for result in ALL:
            assert result.metadata.get("cve"), result.name

    def test_no_payload_contains_a_python_repr(self):
        """The AT/list encoder bug produced b'[16, 0, 16]' inside values.

        Any Python container repr in a payload means a value was stringified
        instead of encoded, so the element is junk to the target.
        """
        for result in ALL:
            for marker in (b"[16,", b"', '", b"b'\\x"):
                assert marker not in result.payload, \
                    f"{result.name} contains a Python repr fragment {marker!r}"

    def test_dataset_shaped_payloads_parse_or_are_declared_malformations(self):
        """A payload meant to be read as a data set should be readable.

        Structural malformations are legitimate and expected; they declare
        themselves through ``bug_class``. What this catches is a payload that
        is broken *by accident* and has no bug_class explaining why.
        """
        unexplained = []
        for result in ALL:
            blob = result.payload
            if blob[128:132] == b"DICM" or blob[:1] == b"\x01":
                continue  # Part-10 file or a raw PDU, not a bare data set
            if result.metadata.get("steps"):
                continue  # multi-PDU sequence
            parsed = False
            for implicit in (True, False):
                try:
                    bio = DicomBytesIO(blob)
                    bio.is_implicit_VR = implicit
                    bio.is_little_endian = True
                    ds = read_dataset(bio, is_implicit_VR=implicit,
                                      is_little_endian=True)
                    if len(ds):
                        parsed = True
                        break
                except Exception:
                    continue
            if not parsed and not result.metadata.get("bug_class"):
                unexplained.append(result.name)
        assert not unexplained, (
            f"unparseable with no bug_class to explain it: {unexplained}")


class TestPart10Conformance:
    """PS3.10 §7.1 is a precondition, not decoration.

    A reader that cannot find (0002,0000) Group Length and (0002,0010)
    Transfer Syntax UID does not know how to decode the Data Set and is
    entitled to stop at the header. A payload that skips the File Meta group
    therefore never reaches the parser it is aimed at, and the run records a
    rejection that proves nothing about the bug under test.

    Payloads whose *malformation is the header* are exempt, named one by one
    below rather than waved through by ``bug_class`` — most payloads carry a
    ``bug_class`` for a Data Set defect and still need a header a reader will
    accept, or the Data Set is never reached.
    """

    # CVE-2026-3650 drives an allocation from a lying (0002,0000) Group
    # Length; CVE-2026-5437 drives an out-of-bounds read from one. For these
    # the malformed header is the reproduction, so conformance would remove
    # the attack. Anything else added here needs the same justification.
    HEADER_IS_THE_ATTACK = frozenset({
        "cve_2026_3650_01_nonstandard_vr_huge_length",
        "cve_2026_3650_02_unknown_vr_private_info",
        "cve_2026_3650_03_un_vr_oversized_length",
        "cve_2026_5437_01_grouplen_overdeclared",
        "cve_2026_5437_02_element_length_past_eof",
        "cve_2026_5437_03_length_arithmetic_overflow",
        "cve_2026_5437_04_grouplen_underdeclared",
    })

    TYPE1 = [(0x0002, 0x0001), (0x0002, 0x0002), (0x0002, 0x0003),
             (0x0002, 0x0010), (0x0002, 0x0012)]

    PART10 = [r for r in ALL if len(r.payload) > 132
              and r.payload[128:132] == b"DICM"]

    def _meta(self, blob):
        """(group_length_declared, {tag: value}, offset_after_group)."""
        assert blob[132:138] == b"\x02\x00\x00\x00UL", "no (0002,0000) UL first"
        declared = struct.unpack("<I", blob[140:144])[0]
        pos, found = 144, {}
        while pos + 8 <= len(blob):
            group, element = struct.unpack("<HH", blob[pos:pos + 4])
            if group != 0x0002:
                break
            vr = blob[pos + 4:pos + 6]
            if vr in (b"OB", b"OW", b"UN", b"SQ", b"UT", b"UC", b"UR"):
                length = struct.unpack("<I", blob[pos + 8:pos + 12])[0]
                voff = pos + 12
            else:
                length = struct.unpack("<H", blob[pos + 6:pos + 8])[0]
                voff = pos + 8
            found[(group, element)] = blob[voff:voff + length]
            pos = voff + length
        return declared, found, pos

    @pytest.mark.parametrize("result", PART10, ids=lambda r: r.name)
    def test_file_meta_group_is_present_and_complete(self, result):
        if result.name in self.HEADER_IS_THE_ATTACK:
            pytest.skip("the malformed File Meta header is the reproduction")
        _declared, found, _end = self._meta(result.payload)
        missing = [f"({t[0]:04X},{t[1]:04X})" for t in self.TYPE1
                   if t not in found]
        assert not missing, f"missing Type 1 File Meta elements: {missing}"

    @pytest.mark.parametrize("result", PART10, ids=lambda r: r.name)
    def test_group_length_matches_the_group(self, result):
        if result.name in self.HEADER_IS_THE_ATTACK:
            pytest.skip("the malformed File Meta header is the reproduction")
        declared, _found, end = self._meta(result.payload)
        assert declared == end - 144, (
            f"(0002,0000) declares {declared}, group is {end - 144} bytes")

    @pytest.mark.parametrize("result", PART10, ids=lambda r: r.name)
    def test_data_set_is_in_ascending_tag_order(self, result):
        """PS3.5 §7.1. Descending order is grounds for rejection, and a
        rejection at the header is a result that concludes nothing."""
        if result.name in self.HEADER_IS_THE_ATTACK:
            pytest.skip("the malformed File Meta header is the reproduction")
        _declared, found, end = self._meta(result.payload)
        ts = found.get((0x0002, 0x0010), b"").rstrip(b"\x00 ").decode()
        if ts != "1.2.840.10008.1.2.1":
            pytest.skip(f"data set is not Explicit VR LE ({ts})")

        blob, pos, last = result.payload, end, None
        while pos + 8 <= len(blob):
            tag = struct.unpack("<HH", blob[pos:pos + 4])
            vr = blob[pos + 4:pos + 6]
            if not (vr.isalpha() and vr.isupper()):
                break
            if vr in (b"OB", b"OW", b"UN", b"SQ", b"UT", b"UC", b"UR", b"OF",
                      b"OD", b"OL", b"OV"):
                if pos + 12 > len(blob):
                    break
                length = struct.unpack("<I", blob[pos + 8:pos + 12])[0]
                voff = pos + 12
            else:
                length = struct.unpack("<H", blob[pos + 6:pos + 8])[0]
                voff = pos + 8
            if length == 0xFFFFFFFF or voff + length > len(blob):
                break
            assert last is None or tag >= last, (
                f"({tag[0]:04X},{tag[1]:04X}) follows "
                f"({last[0]:04X},{last[1]:04X}) — Data Set descends")
            last = tag
            pos = voff + length


class TestCarriedPayloadsRideAStorableObject:
    """A payload an archive refuses on IOD grounds proves nothing.

    The self-built Part-10 payloads establish structure. These establish that
    the structure survives on an object a PACS would actually accept, so when
    one *is* refused the refusal is about the embedded content rather than
    about a Secondary Capture with no image in it.
    """

    CARRIED = [r for r in ALL if r.metadata.get("carrier")]

    def _read(self, result):
        import io
        import pydicom
        return pydicom.dcmread(io.BytesIO(result.payload), force=False)

    def test_there_are_carried_payloads(self):
        assert self.CARRIED, "no payloads declare a carrier"

    @pytest.mark.parametrize("result", CARRIED, ids=lambda r: r.name)
    def test_file_meta_passes_pydicom_validation(self, result):
        from pydicom.dataset import validate_file_meta
        validate_file_meta(self._read(result).file_meta, enforce_standard=True)

    @pytest.mark.parametrize("result", CARRIED, ids=lambda r: r.name)
    def test_required_iod_attributes_are_present(self, result):
        """The Type 1 attributes an archive checks before anything else."""
        ds = self._read(result)
        for keyword in ("SOPClassUID", "SOPInstanceUID", "StudyInstanceUID",
                        "SeriesInstanceUID", "Modality", "ConversionType",
                        "Rows", "Columns", "BitsAllocated", "BitsStored",
                        "HighBit", "PixelRepresentation", "SamplesPerPixel",
                        "PhotometricInterpretation", "PixelData"):
            assert keyword in ds, f"missing Type 1 attribute {keyword}"

    @pytest.mark.parametrize("result", CARRIED, ids=lambda r: r.name)
    def test_uids_agree_between_file_meta_and_data_set(self, result):
        """A receiver that cross-checks them rejects an object that disagrees."""
        ds = self._read(result)
        assert ds.SOPClassUID == ds.file_meta.MediaStorageSOPClassUID
        assert ds.SOPInstanceUID == ds.file_meta.MediaStorageSOPInstanceUID

    @pytest.mark.parametrize("result", CARRIED, ids=lambda r: r.name)
    def test_pixel_data_length_matches_the_image_geometry(self, result):
        ds = self._read(result)
        expected = (ds.Rows * ds.Columns * ds.SamplesPerPixel *
                    ds.BitsAllocated // 8)
        assert len(ds.PixelData) == expected, (
            f"Pixel Data is {len(ds.PixelData)} bytes, geometry implies "
            f"{expected}")

    @pytest.mark.parametrize("result", CARRIED, ids=lambda r: r.name)
    def test_the_embed_left_the_image_untouched(self, result):
        """The object must still render what the carrier rendered.

        An embed that shifted or truncated the pixel data would make the file
        conspicuous to a human before any scanner ran.
        """
        import io
        import pydicom
        from c_scare.attacks import secondary_capture_carrier

        pytest.importorskip("numpy")  # pixel_array needs it
        original = pydicom.dcmread(io.BytesIO(secondary_capture_carrier()),
                                   force=False)
        assert (self._read(result).pixel_array == original.pixel_array).all()

    @pytest.mark.parametrize("result", CARRIED, ids=lambda r: r.name)
    def test_the_payload_sits_ahead_of_the_pixel_data(self, result):
        """Group 0009 sorts before (7FE0,0010), and the bytes must agree."""
        offsets = [result.metadata[key]
                   for key in ("pe_offset", "ph_offset", "container_offset")
                   if key in result.metadata]
        assert len(offsets) == 1, (
            f"{result.name} declares {len(offsets)} payload offsets; each "
            "carried payload names exactly one")
        assert offsets[0] < result.metadata["carrier_pixel_data_offset"]
        assert result.metadata["carrier_pixel_data_intact"] is True

    @pytest.mark.parametrize("result", CARRIED, ids=lambda r: r.name)
    def test_the_private_block_is_conformant(self, result):
        """A creator element claiming the block, then the carrier in it.

        The published construction puts its payload straight into
        (0009,0000) or (0009,0010) — a Group Length tag and the private
        creator slot respectively. Neither may hold an OB payload, so a
        validator can reject that file for a reason that has nothing to do
        with what it is hiding.
        """
        ds = self._read(result)
        private = {f"{e.tag:08X}": e for e in ds if e.tag.group == 0x0009}
        assert "00090010" in private, "no private creator claiming the block"
        assert private["00090010"].VR == "LO"
        assert private["00090010"].value, "private creator is empty"
        carriers = [t for t in private if t != "00090010"]
        assert carriers, "creator claims a block with nothing in it"
        for tag in carriers:
            assert tag[4:6] == "10", (
                f"({tag[:4]},{tag[4:]}) is outside the block the creator claims")


class TestPrivateTagContainerFraming:
    """The container is ``[magic 8B][size uint32 LE][body]``.

    A detector keyed on the published magic string catches the demo and
    nothing else — the talk says the string is generated per engagement. The
    framing is the durable signal, so the catalog ships the same container
    under two magics and the pair only passes a detector that reads structure.
    """

    CONTAINERS = [r for r in ALL
                  if r.metadata.get("container_format") == "magic+len32+body"]

    def test_both_magics_ship(self):
        magics = {r.metadata["container_magic"] for r in self.CONTAINERS}
        assert len(magics) >= 2, (
            f"only {magics} ships; a literal-string detector would score a "
            "pass it has not earned")

    @pytest.mark.parametrize("result", CONTAINERS, ids=lambda r: r.name)
    def test_the_container_is_where_the_metadata_says(self, result):
        blob = result.payload
        at = result.metadata["container_offset"]
        magic = result.metadata["container_magic"].encode().ljust(8, b"\x00")
        assert blob[at:at + 8] == magic
        size = struct.unpack("<I", blob[at + 8:at + 12])[0]
        assert size == result.metadata["container_body_bytes"]
        assert at + 12 + size <= len(blob), "declared body runs past the file"

    @pytest.mark.parametrize("result", CONTAINERS, ids=lambda r: r.name)
    def test_the_body_is_an_inert_marker(self, result):
        """This catalog builds detection tests, not loaders."""
        at = result.metadata["container_offset"]
        size = struct.unpack("<I", result.payload[at + 8:at + 12])[0]
        body = result.payload[at + 12:at + 12 + size]
        assert b"INERT MARKER" in body
        assert body.decode("ascii")  # printable text, not machine code

    @pytest.mark.parametrize("result", CONTAINERS, ids=lambda r: r.name)
    def test_the_container_carries_no_executable_magic(self, result):
        """It is a container, not a polyglot — no second format is claimed."""
        assert polyglot.executable_format(result.payload) is None
        assert "polyglot" not in result.metadata
