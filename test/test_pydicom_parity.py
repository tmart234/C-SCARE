# SPDX-License-Identifier: GPL-2.0-only
"""Differential tests: c_scare's encoders against pydicom, byte for byte.

C-SCARE hand-rolls its DICOM encoders so attacks can produce bytes pydicom
would refuse to write. That freedom is the point, but it means nothing catches
an encoder that is wrong *by accident* — a payload that malforms in a way the
attack never intended parses as garbage at the target and the result reads as
"rejected", which is indistinguishable from "defended against".

So: for every construct an attack is supposed to build *correctly*, pydicom is
the oracle. Deliberate malformations are built through ``Element.raw`` and the
explicit override parameters, which these tests leave alone.

Known, deliberate divergence: ``UN`` values are padded to even length here and
not by pydicom. PS3.5 §7.1.1 requires even-length values and the pad byte for
opaque content is unknowable; ``Element.raw`` is the unpadded escape hatch.
"""

import struct

import pytest

pytest.importorskip("pydicom")

from pydicom.dataelem import DataElement  # noqa: E402
from pydicom.dataset import Dataset as PDDataset  # noqa: E402
from pydicom.encaps import encapsulate, generate_pixel_data_fragment  # noqa: E402
from pydicom.filebase import DicomBytesIO  # noqa: E402
from pydicom.filereader import read_dataset  # noqa: E402
from pydicom.filewriter import write_dataset  # noqa: E402

from c_scare.element import Dataset, Element, Tag  # noqa: E402
from c_scare.pixel import EncapsulatedPixelData  # noqa: E402

SEQ_DELIM = b"\xFE\xFF\xDD\xE0\x00\x00\x00\x00"


def pydicom_bytes(tag, vr, value, implicit=True):
    """Encode one element the way pydicom's writer would."""
    ds = PDDataset()
    ds[tag] = DataElement(tag, vr, value)
    bio = DicomBytesIO()
    bio.is_implicit_VR = implicit
    bio.is_little_endian = True
    write_dataset(bio, ds)
    return bio.getvalue()


def cscare_bytes(tag, vr, value, implicit=True):
    return Element(tag, vr, value).encode(implicit_vr=implicit, little_endian=True)


# Text VRs pad with a space; the rest are covered by the binary cases below.
TEXT_VRS = ["AE", "CS", "LO", "LT", "PN", "SH", "ST", "UC", "UR", "UT"]
BINARY_VRS = ["OB", "OW", "OD", "OF", "OL"]
NUMERIC_VALUES = {
    "SS": -5, "US": 65535, "SL": -100000, "UL": 4000000000,
    "FL": 1.5, "FD": 2.25, "SV": -(2 ** 40), "UV": 2 ** 40,
}


class TestElementParity:
    @pytest.mark.parametrize("implicit", [True, False], ids=["implicit", "explicit"])
    @pytest.mark.parametrize("vr", TEXT_VRS)
    @pytest.mark.parametrize("value", ["ab", "abc", ""], ids=["even", "odd", "empty"])
    def test_text_vr_matches_pydicom(self, vr, value, implicit):
        tag = 0x00090001
        assert cscare_bytes(tag, vr, value, implicit) == \
            pydicom_bytes(tag, vr, value, implicit)

    @pytest.mark.parametrize("implicit", [True, False], ids=["implicit", "explicit"])
    @pytest.mark.parametrize("vr", BINARY_VRS)
    @pytest.mark.parametrize("value", [b"\x01\x02\x03\x04", b"\x01\x02\x03", b""],
                             ids=["even", "odd", "empty"])
    def test_binary_vr_matches_pydicom(self, vr, value, implicit):
        """Binary VRs pad with NULL, not a space — a space would be a data byte."""
        tag = 0x00090010
        assert cscare_bytes(tag, vr, value, implicit) == \
            pydicom_bytes(tag, vr, value, implicit)

    @pytest.mark.parametrize("implicit", [True, False], ids=["implicit", "explicit"])
    @pytest.mark.parametrize("vr,value", sorted(NUMERIC_VALUES.items()))
    def test_numeric_vr_matches_pydicom(self, vr, value, implicit):
        tag = 0x00090020
        assert cscare_bytes(tag, vr, value, implicit) == \
            pydicom_bytes(tag, vr, value, implicit)

    def test_uid_pads_with_null_not_space(self):
        """UI is null-padded (PS3.5 §6.2); a trailing space corrupts the UID."""
        out = cscare_bytes(0x00080016, "UI", "1.2.3")
        assert out.endswith(b"1.2.3\x00")
        assert out == pydicom_bytes(0x00080016, "UI", "1.2.3")


class TestAttributeTagVR:
    """AT is two 16-bit halves, not a decimal string.

    Encoding it via ``str()`` produced ASCII digits at twice the length, so any
    attack carrying an attribute-identifier list (N-GET, worklist matching
    keys) would have sent unparseable junk.
    """

    @pytest.mark.parametrize("value", [
        0x00100010, (0x0010, 0x0010), [0x00100010],
    ], ids=["int", "tuple", "single-item-list"])
    def test_single_tag_forms_all_encode_to_four_bytes(self, value):
        got = cscare_bytes(0x00090030, "AT", value)
        assert got == pydicom_bytes(0x00090030, "AT", value)
        assert got[-4:] == struct.pack("<HH", 0x0010, 0x0010)

    def test_cscare_tag_object_encodes_like_the_int(self):
        """A c_scare Tag is not a pydicom type, so compare it to the int form."""
        assert cscare_bytes(0x00090030, "AT", Tag(0x00100010)) == \
            cscare_bytes(0x00090030, "AT", 0x00100010)

    def test_multiple_tags_concatenate(self):
        value = [0x00100010, 0x00100020]
        got = cscare_bytes(0x00090030, "AT", value)
        assert got == pydicom_bytes(0x00090030, "AT", value)
        assert got[-8:] == struct.pack("<HHHH", 0x0010, 0x0010, 0x0010, 0x0020)

    def test_is_not_ascii_digits(self):
        """The specific regression: 0x00100010 must not become b'1048592'."""
        assert b"1048592" not in cscare_bytes(0x00090030, "AT", 0x00100010)


class TestMultiValuedElements:
    def test_text_values_join_with_backslash(self):
        value = ["ORIGINAL", "PRIMARY"]
        assert cscare_bytes(0x00080008, "CS", value) == \
            pydicom_bytes(0x00080008, "CS", value)

    def test_binary_values_concatenate(self):
        """A LUT Descriptor is three US values — it must not become a repr."""
        value = [16, 0, 16]
        got = cscare_bytes(0x00283002, "US", value)
        assert got == pydicom_bytes(0x00283002, "US", value)
        assert got[-6:] == struct.pack("<HHH", 16, 0, 16)

    def test_list_never_encodes_as_python_repr(self):
        for vr, value in (("US", [16, 0]), ("CS", ["A", "B"]), ("AT", [0x00100010])):
            assert b"[" not in cscare_bytes(0x00090040, vr, value)


class TestDatasetParity:
    ITEMS = [
        (0x00080016, "UI", "1.2.840.10008.5.1.4.1.1.7"),
        (0x00080018, "UI", "1.2.3.4.5"),
        (0x00080060, "CS", "OT"),
        (0x00100010, "PN", "Doe^John"),
        (0x00100020, "LO", "12345"),
        (0x0020000D, "UI", "1.2.3.4.5.1"),
    ]

    @pytest.mark.parametrize("implicit", [True, False], ids=["implicit", "explicit"])
    def test_whole_dataset_matches_pydicom(self, implicit):
        ds = Dataset()
        for tag, vr, value in self.ITEMS:
            ds = ds / Element(tag, vr, value)
        pdds = PDDataset()
        for tag, vr, value in self.ITEMS:
            pdds[tag] = DataElement(tag, vr, value)
        bio = DicomBytesIO()
        bio.is_implicit_VR = implicit
        bio.is_little_endian = True
        write_dataset(bio, pdds)
        assert ds.encode(implicit_vr=implicit) == bio.getvalue()

    @pytest.mark.parametrize("implicit", [True, False], ids=["implicit", "explicit"])
    def test_injection_base_dataset_round_trips(self, implicit):
        """The carrier every injection attack overlays must be readable."""
        from c_scare.attacks import _injection_base_dataset

        blob = _injection_base_dataset().encode(implicit_vr=implicit)
        bio = DicomBytesIO(blob)
        bio.is_implicit_VR = implicit
        bio.is_little_endian = True
        ds = read_dataset(bio, is_implicit_VR=implicit, is_little_endian=True)
        assert ds.PatientName == "Doe^John"
        assert ds.SOPClassUID == "1.2.840.10008.5.1.4.1.1.7"


class TestEncapsulationParity:
    EVEN = b"\xFF\xD8\xFF\xE0" + b"A" * 20 + b"\xFF\xD9"   # 26 bytes
    ODD = b"\xFF\xD8\xFF\xE0" + b"B" * 31 + b"\xFF\xD9"    # 37 bytes

    def _encode(self, fragments, bot=False):
        epd = EncapsulatedPixelData()
        for f in fragments:
            epd.add_fragment(f)
        if bot:
            epd.compute_offset_table()
        return epd.encode()

    @pytest.mark.parametrize("fragments", [[EVEN], [EVEN, ODD], [ODD]],
                             ids=["even", "mixed", "odd"])
    def test_item_stream_matches_pydicom_encapsulate(self, fragments):
        """Identical to pydicom apart from the trailing delimiter.

        ``pydicom.encapsulate`` returns fragments only and leaves the Sequence
        Delimitation Item to its element writer; c_scare's ``encode()`` returns
        the complete undefined-length value, delimiter included.
        """
        got = self._encode(fragments)
        assert got.endswith(SEQ_DELIM)
        assert got[:-len(SEQ_DELIM)] == encapsulate(fragments, has_bot=False)

    def test_odd_fragment_declares_the_padded_length(self):
        """The regression: declaring the unpadded length desyncs the stream.

        A fragment that writes a pad byte but declares the length without it
        leaves the pad sitting where the next item tag should start, shifting
        every following item — and the Basic Offset Table, which is computed
        assuming padding — by one byte.
        """
        blob = self._encode([self.ODD])
        # BOT item (8 bytes, empty) then the fragment item.
        declared = struct.unpack("<I", blob[12:16])[0]
        assert len(self.ODD) % 2 == 1
        assert declared == len(self.ODD) + 1
        assert declared % 2 == 0

    def test_stream_walks_cleanly_to_the_delimiter(self):
        """Walking item-by-item must land exactly on the delimiter."""
        blob = self._encode([self.EVEN, self.ODD], bot=True)
        pos = 0
        while pos + 8 <= len(blob):
            tag = blob[pos:pos + 4]
            length = struct.unpack("<I", blob[pos + 4:pos + 8])[0]
            if tag == b"\xFE\xFF\xDD\xE0":
                break
            assert tag == b"\xFE\xFF\x00\xE0", f"desync at offset {pos}"
            pos += 8 + length
        assert blob[pos:] == SEQ_DELIM

    def test_offset_table_points_at_real_item_boundaries(self):
        blob = self._encode([self.EVEN, self.ODD], bot=True)
        bot_len = struct.unpack("<I", blob[4:8])[0]
        offsets = struct.unpack(f"<{bot_len // 4}I", blob[8:8 + bot_len])
        body = blob[8 + bot_len:]
        for offset in offsets:
            assert body[offset:offset + 4] == b"\xFE\xFF\x00\xE0"

    @pytest.mark.parametrize("implicit", [True, False], ids=["implicit", "explicit"])
    def test_encode_element_is_a_valid_pixel_data_element(self, implicit):
        epd = EncapsulatedPixelData()
        epd.add_fragment(self.EVEN)
        blob = epd.encode_element(implicit_vr=implicit)

        assert struct.unpack("<HH", blob[:4]) == (0x7FE0, 0x0010)

        bio = DicomBytesIO(blob)
        bio.is_implicit_VR = implicit
        bio.is_little_endian = True
        ds = read_dataset(bio, is_implicit_VR=implicit, is_little_endian=True)
        tags = [(t.group, t.element) for t in ds.keys()]
        assert tags == [(0x7FE0, 0x0010)]

    def test_length_override_is_left_alone(self):
        """An explicit override is a deliberate lie and must survive."""
        epd = EncapsulatedPixelData()
        epd.add_fragment(self.ODD, length_override=0xDEADBEEF)
        blob = epd.encode()
        assert struct.unpack("<I", blob[12:16])[0] == 0xDEADBEEF


class TestEncapsulatedAttacksAreDeliverable:
    """Encapsulated pixel attacks must arrive as data sets, not item streams.

    Emitting the bare item stream makes the payload start with an Item tag
    (FFFE,E000); an SCP rejects that at the first element and the codec the
    attack targets is never reached, so the run records a false negative.
    """

    @pytest.mark.parametrize("name", ["fragment_count_bomb",
                                      "encapsulated_frame_overflow"])
    def test_payload_is_a_pixel_data_element(self, name):
        from c_scare.attacks import MemoryAttacks

        result = {r.name: r for r in MemoryAttacks.all()}[name]
        group, element = struct.unpack("<HH", result.payload[:4])
        assert (group, element) == (0x7FE0, 0x0010), \
            f"{name} starts with ({group:04X},{element:04X}), not Pixel Data"
        assert struct.unpack("<I", result.payload[4:8])[0] == 0xFFFFFFFF

    @pytest.mark.parametrize("name,min_fragments", [
        ("fragment_count_bomb", 10000),
        ("encapsulated_frame_overflow", 1),
    ])
    def test_pydicom_recovers_the_fragments(self, name, min_fragments):
        from c_scare.attacks import MemoryAttacks

        result = {r.name: r for r in MemoryAttacks.all()}[name]
        bio = DicomBytesIO(result.payload)
        bio.is_implicit_VR = True
        bio.is_little_endian = True
        ds = read_dataset(bio, is_implicit_VR=True, is_little_endian=True)

        value = DicomBytesIO(ds[0x7FE00010].value)
        value.is_implicit_VR = True
        value.is_little_endian = True
        fragments = list(generate_pixel_data_fragment(value))
        # The Basic Offset Table is the first item.
        assert len(fragments) - 1 >= min_fragments

    @pytest.mark.parametrize("name", ["fragment_count_bomb",
                                      "encapsulated_frame_overflow"])
    def test_routes_over_a_cstore_association(self, name):
        import argparse

        from c_scare.attacks import MemoryAttacks
        from c_scare.runner import _delivery_kind

        result = {r.name: r for r in MemoryAttacks.all()}[name]
        assert result.metadata.get("sop_class_uid")
        assert _delivery_kind(argparse.Namespace(delivery="auto"), result) == "cstore"


class TestServerLifecycle:
    """RawSCP teardown must be synchronous and leave no threads behind.

    ``stop()`` used to clear a flag and return while the accept loop was still
    parked in ``accept()``: threads accumulated for the length of a run and a
    caller that immediately rebound the port raced the dying server.
    """

    def test_start_binds_before_returning(self):
        """No readiness sleep should be needed after start()."""
        import socket

        from c_scare.server import RawSCP

        scp = RawSCP(host="127.0.0.1", port=0)
        scp.start(blocking=False)
        try:
            with socket.create_connection(("127.0.0.1", scp.port), timeout=2.0):
                pass  # connects immediately, without any sleep
        finally:
            scp.stop()

    def test_ephemeral_port_is_discoverable(self):
        """port=0 lets a caller avoid hardcoding (and colliding on) a port."""
        from c_scare.server import RawSCP

        scp = RawSCP(host="127.0.0.1", port=0)
        scp.start(blocking=False)
        try:
            assert scp.port != 0
        finally:
            scp.stop()

    def test_stop_joins_the_accept_thread(self):
        from c_scare.server import RawSCP

        scp = RawSCP(host="127.0.0.1", port=0)
        thread = scp.start(blocking=False)
        scp.stop()
        assert not thread.is_alive(), "stop() returned with the accept loop still running"

    def test_repeated_start_stop_leaks_no_threads(self):
        import threading

        from c_scare.server import RawSCP

        before = threading.active_count()
        for _ in range(5):
            scp = RawSCP(host="127.0.0.1", port=0)
            scp.start(blocking=False)
            scp.stop()
        assert threading.active_count() == before

    def test_port_is_reusable_immediately_after_stop(self):
        """Teardown must release the port synchronously."""
        from c_scare.server import RawSCP

        first = RawSCP(host="127.0.0.1", port=0)
        first.start(blocking=False)
        port = first.port
        first.stop()

        second = RawSCP(host="127.0.0.1", port=port)
        second.start(blocking=False)
        try:
            assert second.port == port
        finally:
            second.stop()
