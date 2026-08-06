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
BURIED_ZONES = {"private_element", "element_padding", "trailing"}


def by_cve(cve):
    return [r for r in ALL if r.metadata.get("cve") == cve]


def with_meta(key):
    return [r for r in ALL if r.metadata.get(key) is not None]


def buried():
    """Polyglots whose second-format body lives past the preamble."""
    return [r for r in by_cve("CVE-2019-11687")
            if r.metadata.get("zone") in BURIED_ZONES]


class TestPolyglotsAreActuallyDualFormat:
    """CVE-2019-11687 is *executable embedding*: the file has to be both.

    A payload that is only valid DICOM tests nothing — the point is that the
    same bytes satisfy a loader and a DICOM reader at once, so an AV engine
    keyed on offset 0 and a PACS keyed on offset 128 disagree about what the
    file is.
    """

    @pytest.mark.parametrize("result", by_cve("CVE-2019-11687"),
                             ids=lambda r: r.metadata.get("polyglot"))
    def test_executable_magic_sits_at_offset_zero(self, result):
        flavour = result.metadata["polyglot"]
        magic = POLYGLOT_MAGIC[flavour]
        assert result.payload.startswith(magic), (
            f"{flavour} polyglot does not start with {magic}; "
            f"got {result.payload[:4]!r}")

    @pytest.mark.parametrize("result", by_cve("CVE-2019-11687"),
                             ids=lambda r: r.metadata.get("polyglot"))
    def test_dicm_magic_still_sits_at_offset_128(self, result):
        """The preamble trick only works if the DICOM half stays valid."""
        assert result.payload[128:132] == b"DICM"

    @pytest.mark.parametrize("result", by_cve("CVE-2019-11687"),
                             ids=lambda r: r.metadata.get("polyglot"))
    def test_preamble_is_exactly_128_bytes(self, result):
        """Executable content must fit the preamble, not push DICM along."""
        assert result.payload.index(b"DICM") == 128

    @pytest.mark.parametrize("result", buried(), ids=lambda r: r.name)
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
        """The dual-pipeline check: valid PE *and* valid DICOM, same bytes.

        Either half failing collapses the test case. A broken PE half is a
        DICOM file no scanner cares about; a broken DICOM half is an
        executable no PACS accepts, and the storage path under test is never
        exercised.
        """
        assert polyglot.validate_polyglot(result.payload) == {
            "pe": [], "dicom": []}

    @pytest.mark.parametrize("result", buried(), ids=lambda r: r.name)
    def test_the_pe_body_sits_past_everything_dicom_parses(self, result):
        """Each buried payload must really use a region no reader inspects.

        The preamble and File Meta group are what every reader — and every
        scanner worth the name — parses. These payloads exist to test what
        comes after: regions a conforming parser traverses on its way past,
        which is only interesting if the PE image is genuinely out there.
        """
        e_lfanew = struct.unpack("<I", result.payload[60:64])[0]
        start = polyglot.dataset_offset(result.payload)
        assert start is not None, "File Meta group is not parseable"
        assert e_lfanew >= start, (
            f"e_lfanew={e_lfanew} lands inside the File Meta group "
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
