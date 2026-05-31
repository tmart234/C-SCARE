"""
Pytest test suite for Scapy DICOM contribution.

Tests the current architecture:
- DICOMElementField-based DIMSE fields with TLV encoding
- DICOMAETitleField with automatic space-padding
- DIMSEPacket base class with post_build group length calculation
- DICOMSession for session management
- Native Scapy field patterns (StrLenField, PacketListField, etc.)
- DIMSE-N commands (PS3.7 Section 10.3)
- Transfer Syntax UIDs (PS3.5 Annex A)
"""
import pytest
import struct
import logging
import sys
import os
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.contrib.dicom").setLevel(logging.INFO)

from scapy.volatile import RandShort, RandInt, RandString

from c_scare.scapy_dicom import (
    # PDU classes
    DICOM,
    A_ASSOCIATE_RQ,
    A_ASSOCIATE_AC,
    A_ASSOCIATE_RJ,
    A_RELEASE_RQ,
    A_RELEASE_RP,
    A_ABORT,
    P_DATA_TF,
    PresentationDataValueItem,
    # Variable Item classes
    DICOMVariableItem,
    DICOMApplicationContext,
    DICOMPresentationContextRQ,
    DICOMPresentationContextAC,
    DICOMAbstractSyntax,
    DICOMTransferSyntax,
    DICOMUserInformation,
    DICOMMaximumLength,
    DICOMImplementationClassUID,
    DICOMAsyncOperationsWindow,
    DICOMSCPSCURoleSelection,
    DICOMImplementationVersionName,
    DICOMUserIdentity,
    DICOMUserIdentityResponse,
    # Field classes
    DICOMElementField,
    DICOMAETitleField,
    DICOMUIDField,
    DICOMUSField,
    DICOMULField,
    DICOMAEDIMSEField,
    DICOMATField,
    # DIMSE Packet classes - DIMSE-C
    DIMSEPacket,
    C_ECHO_RQ,
    C_ECHO_RSP,
    C_STORE_RQ,
    C_STORE_RSP,
    C_FIND_RQ,
    C_FIND_RSP,
    C_MOVE_RQ,
    C_MOVE_RSP,
    C_GET_RQ,
    C_GET_RSP,
    C_CANCEL_RQ,
    # DIMSE Packet classes - DIMSE-N (PS3.7 Section 10.3)
    N_EVENT_REPORT_RQ,
    N_EVENT_REPORT_RSP,
    N_GET_RQ,
    N_GET_RSP,
    N_SET_RQ,
    N_SET_RSP,
    N_ACTION_RQ,
    N_ACTION_RSP,
    N_CREATE_RQ,
    N_CREATE_RSP,
    N_DELETE_RQ,
    N_DELETE_RSP,
    # Helpers
    build_presentation_context_rq,
    build_user_information,
    parse_dimse_status,
    # Constants - Core
    APP_CONTEXT_UID,
    VERIFICATION_SOP_CLASS_UID,
    DEFAULT_TRANSFER_SYNTAX_UID,
    CT_IMAGE_STORAGE_SOP_CLASS_UID,
    PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
    PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
    PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
    # Constants - Transfer Syntax UIDs (PS3.5 Annex A)
    IMPLICIT_VR_LITTLE_ENDIAN_UID,
    EXPLICIT_VR_LITTLE_ENDIAN_UID,
    EXPLICIT_VR_BIG_ENDIAN_UID,
    DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID,
    JPEG_BASELINE_UID,
    JPEG_LOSSLESS_UID,
    JPEG_LS_LOSSLESS_UID,
    JPEG_LS_LOSSY_UID,
    JPEG_2000_LOSSLESS_UID,
    JPEG_2000_UID,
    RLE_LOSSLESS_UID,
    HTJP2K_LOSSLESS_UID,
    HTJP2K_LOSSLESS_RPCL_UID,
    HTJP2K_UID,
    # Utilities
    _uid_to_bytes,
    _uid_to_bytes_raw,
)
from c_scare.client import DICOMSession


# =============================================================================
# Test DICOMElementField and Subclasses
# =============================================================================

class TestDICOMElementFields:
    """Test the DICOM element field classes with TLV encoding."""

    def test_dicom_element_field_structure(self):
        """DICOMElementField should have tag_group and tag_elem attributes."""
        field = DICOMElementField("test", b"", tag_group=0x0000, tag_elem=0x0002)
        assert field.tag_group == 0x0000
        assert field.tag_elem == 0x0002

    def test_dicom_us_field_serialization(self):
        """DICOMUSField should serialize with TLV header (little-endian)."""
        field = DICOMUSField("test", 0x1234, 0x0000, 0x0100)

        result = field.addfield(None, b"", 0x5678)

        # Should be: tag_group(2) + tag_elem(2) + length(4) + value(2) = 10 bytes
        assert len(result) == 10

        # Check tag (little-endian)
        tag_g, tag_e = struct.unpack("<HH", result[:4])
        assert tag_g == 0x0000
        assert tag_e == 0x0100

        # Check length (should be 2 for US)
        length = struct.unpack("<I", result[4:8])[0]
        assert length == 2

        # Check value (little-endian)
        value = struct.unpack("<H", result[8:10])[0]
        assert value == 0x5678

    def test_dicom_ul_field_serialization(self):
        """DICOMULField should serialize with TLV header."""
        field = DICOMULField("test", 0, 0x0000, 0x0000)

        result = field.addfield(None, b"", 0x12345678)

        # Should be: tag(4) + length(4) + value(4) = 12 bytes
        assert len(result) == 12

        # Check value (little-endian)
        value = struct.unpack("<I", result[8:12])[0]
        assert value == 0x12345678

    def test_dicom_uid_field_pads_odd_length(self):
        """DICOMUIDField should pad odd-length UIDs to even length."""
        field = DICOMUIDField("uid", "", 0x0000, 0x0002)

        # Odd-length UID (17 bytes)
        result = field.addfield(None, b"", "1.2.840.10008.1.1")

        # Extract length from TLV
        length = struct.unpack("<I", result[4:8])[0]
        assert length % 2 == 0  # Should be even

    def test_dicom_us_field_randval(self):
        """DICOMUSField.randval() should return RandShort."""
        field = DICOMUSField("test", 0, 0x0000, 0x0100)
        rand_val = field.randval()
        assert isinstance(rand_val, RandShort)

    def test_dicom_ul_field_randval(self):
        """DICOMULField.randval() should return RandInt."""
        field = DICOMULField("test", 0, 0x0000, 0x0000)
        rand_val = field.randval()
        assert isinstance(rand_val, RandInt)

    def test_dicom_element_field_randval(self):
        """DICOMElementField.randval() should return RandString."""
        field = DICOMElementField("test", b"", 0x0000, 0x0002)
        rand_val = field.randval()
        assert isinstance(rand_val, RandString)


# =============================================================================
# Test DICOMATField (Attribute Tag Field)
# =============================================================================

class TestDICOMATField:
    """Test the DICOM Attribute Tag (AT) field for N-GET Attribute Identifier List."""

    def test_at_field_single_tag_tuple(self):
        """DICOMATField should encode a single tag tuple."""
        field = DICOMATField("attr_list", [], 0x0000, 0x1005)

        result = field.addfield(None, b"", [(0x0010, 0x0020)])

        # Header (8 bytes) + 1 tag (4 bytes) = 12 bytes
        assert len(result) == 12

        # Extract length - should be 4 (one tag)
        length = struct.unpack("<I", result[4:8])[0]
        assert length == 4

        # Extract the tag
        group, elem = struct.unpack("<HH", result[8:12])
        assert group == 0x0010
        assert elem == 0x0020

    def test_at_field_multiple_tags(self):
        """DICOMATField should encode multiple tags."""
        field = DICOMATField("attr_list", [], 0x0000, 0x1005)

        tags = [(0x0010, 0x0010), (0x0010, 0x0020), (0x0008, 0x0018)]
        result = field.addfield(None, b"", tags)

        # Header (8 bytes) + 3 tags (12 bytes) = 20 bytes
        assert len(result) == 20

        # Extract length - should be 12 (three tags)
        length = struct.unpack("<I", result[4:8])[0]
        assert length == 12

    def test_at_field_integer_tag(self):
        """DICOMATField should handle integer tag format."""
        field = DICOMATField("attr_list", [], 0x0000, 0x1005)

        # Tag 0x00100020 = (0x0010, 0x0020)
        result = field.addfield(None, b"", [0x00100020])

        # Extract the tag
        group, elem = struct.unpack("<HH", result[8:12])
        assert group == 0x0010
        assert elem == 0x0020

    def test_at_field_empty_list(self):
        """DICOMATField should handle empty tag list."""
        field = DICOMATField("attr_list", [], 0x0000, 0x1005)

        result = field.addfield(None, b"", [])

        # Header (8 bytes) + 0 tags = 8 bytes
        assert len(result) == 8

        # Length should be 0
        length = struct.unpack("<I", result[4:8])[0]
        assert length == 0

    def test_at_field_getfield_roundtrip(self):
        """DICOMATField should correctly decode encoded tags."""
        field = DICOMATField("attr_list", [], 0x0000, 0x1005)

        original_tags = [(0x0010, 0x0010), (0x0010, 0x0020), (0x0008, 0x0018)]
        encoded = field.addfield(None, b"", original_tags)

        # Decode (skip to data portion)
        remain, decoded_tags = field.getfield(None, encoded)

        assert len(decoded_tags) == 3
        assert decoded_tags == original_tags


# =============================================================================
# Test DICOMAETitleField
# =============================================================================

class TestDICOMAETitleField:
    """Test the AE Title field with automatic space-padding."""

    def test_ae_title_pads_to_16_bytes(self):
        """DICOMAETitleField should pad to exactly 16 bytes."""
        field = DICOMAETitleField("ae", b"")

        result = field.i2m(None, b"TEST")
        assert len(result) == 16
        assert result == b"TEST            "

    def test_ae_title_truncates_long_values(self):
        """DICOMAETitleField should truncate values longer than 16 bytes."""
        field = DICOMAETitleField("ae", b"")

        result = field.i2m(None, b"X" * 20)
        assert len(result) == 16
        assert result == b"X" * 16

    def test_ae_title_handles_string_input(self):
        """DICOMAETitleField should handle string input."""
        field = DICOMAETitleField("ae", b"")

        result = field.i2m(None, "MYAE")
        assert result == b"MYAE            "

    def test_ae_title_repr_strips_padding(self):
        """DICOMAETitleField.i2repr() should strip trailing spaces."""
        field = DICOMAETitleField("ae", b"")

        result = field.i2repr(None, b"TEST            ")
        assert result == "TEST"


# =============================================================================
# Test DIMSEPacket Base Class
# =============================================================================

class TestDIMSEPacketBaseClass:
    """Test the DIMSEPacket base class with group length calculation."""

    def test_dimse_packet_inheritance_dimse_c(self):
        """All DIMSE-C commands should inherit from DIMSEPacket."""
        assert issubclass(C_ECHO_RQ, DIMSEPacket)
        assert issubclass(C_ECHO_RSP, DIMSEPacket)
        assert issubclass(C_STORE_RQ, DIMSEPacket)
        assert issubclass(C_STORE_RSP, DIMSEPacket)
        assert issubclass(C_FIND_RQ, DIMSEPacket)
        assert issubclass(C_FIND_RSP, DIMSEPacket)
        assert issubclass(C_MOVE_RQ, DIMSEPacket)
        assert issubclass(C_MOVE_RSP, DIMSEPacket)
        assert issubclass(C_GET_RQ, DIMSEPacket)
        assert issubclass(C_GET_RSP, DIMSEPacket)
        assert issubclass(C_CANCEL_RQ, DIMSEPacket)

    def test_dimse_packet_inheritance_dimse_n(self):
        """All DIMSE-N commands should inherit from DIMSEPacket."""
        assert issubclass(N_EVENT_REPORT_RQ, DIMSEPacket)
        assert issubclass(N_EVENT_REPORT_RSP, DIMSEPacket)
        assert issubclass(N_GET_RQ, DIMSEPacket)
        assert issubclass(N_GET_RSP, DIMSEPacket)
        assert issubclass(N_SET_RQ, DIMSEPacket)
        assert issubclass(N_SET_RSP, DIMSEPacket)
        assert issubclass(N_ACTION_RQ, DIMSEPacket)
        assert issubclass(N_ACTION_RSP, DIMSEPacket)
        assert issubclass(N_CREATE_RQ, DIMSEPacket)
        assert issubclass(N_CREATE_RSP, DIMSEPacket)
        assert issubclass(N_DELETE_RQ, DIMSEPacket)
        assert issubclass(N_DELETE_RSP, DIMSEPacket)

    def test_dimse_post_build_adds_group_length(self):
        """DIMSEPacket.post_build() should prepend CommandGroupLength element."""
        pkt = C_ECHO_RQ(message_id=42)
        raw = bytes(pkt)

        # First element should be CommandGroupLength (0000,0000)
        tag_g, tag_e = struct.unpack("<HH", raw[:4])
        assert tag_g == 0x0000
        assert tag_e == 0x0000

        # Value length should be 4
        val_len = struct.unpack("<I", raw[4:8])[0]
        assert val_len == 4

        # The group length value should equal remaining bytes after this element
        group_len = struct.unpack("<I", raw[8:12])[0]
        remaining = len(raw) - 12
        assert group_len == remaining


# =============================================================================
# Test Transfer Syntax UIDs (PS3.5 Annex A)
# =============================================================================

class TestTransferSyntaxUIDs:
    """Test Transfer Syntax UID constants from PS3.5 Annex A."""

    def test_implicit_vr_little_endian(self):
        """Implicit VR Little Endian should be the default."""
        assert IMPLICIT_VR_LITTLE_ENDIAN_UID == "1.2.840.10008.1.2"
        assert DEFAULT_TRANSFER_SYNTAX_UID == IMPLICIT_VR_LITTLE_ENDIAN_UID

    def test_explicit_vr_little_endian(self):
        """Explicit VR Little Endian UID should be correct."""
        assert EXPLICIT_VR_LITTLE_ENDIAN_UID == "1.2.840.10008.1.2.1"

    def test_explicit_vr_big_endian_retired(self):
        """Explicit VR Big Endian (retired) UID should be correct."""
        assert EXPLICIT_VR_BIG_ENDIAN_UID == "1.2.840.10008.1.2.2"

    def test_deflated_explicit_vr(self):
        """Deflated Explicit VR Little Endian UID should be correct."""
        assert DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID == "1.2.840.10008.1.2.1.99"

    def test_jpeg_baseline(self):
        """JPEG Baseline (lossy) UID should be correct."""
        assert JPEG_BASELINE_UID == "1.2.840.10008.1.2.4.50"

    def test_jpeg_lossless(self):
        """JPEG Lossless UID should be correct."""
        assert JPEG_LOSSLESS_UID == "1.2.840.10008.1.2.4.70"

    def test_jpeg_ls_lossless(self):
        """JPEG-LS Lossless UID should be correct."""
        assert JPEG_LS_LOSSLESS_UID == "1.2.840.10008.1.2.4.80"

    def test_jpeg_ls_lossy(self):
        """JPEG-LS Near-Lossless UID should be correct."""
        assert JPEG_LS_LOSSY_UID == "1.2.840.10008.1.2.4.81"

    def test_jpeg_2000_lossless(self):
        """JPEG 2000 Lossless UID should be correct."""
        assert JPEG_2000_LOSSLESS_UID == "1.2.840.10008.1.2.4.90"

    def test_jpeg_2000(self):
        """JPEG 2000 UID should be correct."""
        assert JPEG_2000_UID == "1.2.840.10008.1.2.4.91"

    def test_rle_lossless(self):
        """RLE Lossless UID should be correct."""
        assert RLE_LOSSLESS_UID == "1.2.840.10008.1.2.5"

    def test_htjp2k_lossless(self):
        """High-Throughput JPEG 2000 Lossless UID should be correct."""
        assert HTJP2K_LOSSLESS_UID == "1.2.840.10008.1.2.4.201"

    def test_htjp2k_lossless_rpcl(self):
        """High-Throughput JPEG 2000 with RPCL UID should be correct."""
        assert HTJP2K_LOSSLESS_RPCL_UID == "1.2.840.10008.1.2.4.202"

    def test_htjp2k(self):
        """High-Throughput JPEG 2000 UID should be correct."""
        assert HTJP2K_UID == "1.2.840.10008.1.2.4.203"

    def test_transfer_syntax_in_presentation_context(self):
        """Transfer syntax UIDs should work in presentation context negotiation."""
        # Build presentation context with multiple transfer syntaxes
        transfer_syntaxes = [
            EXPLICIT_VR_LITTLE_ENDIAN_UID,
            IMPLICIT_VR_LITTLE_ENDIAN_UID,
            JPEG_2000_LOSSLESS_UID,
        ]
        pctx = build_presentation_context_rq(
            context_id=1,
            abstract_syntax_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            transfer_syntax_uids=transfer_syntaxes
        )

        raw = bytes(pctx)

        # Verify all transfer syntaxes are present
        for ts_uid in transfer_syntaxes:
            assert ts_uid.encode('ascii') in raw


# =============================================================================
# Test C-CANCEL Command (PS3.7 Section 9.3)
# =============================================================================

class TestCCancelCommand:
    """Test C-CANCEL-RQ command for canceling pending operations."""

    def test_c_cancel_rq_creation(self):
        """C_CANCEL_RQ should be creatable with message ID to cancel."""
        pkt = C_CANCEL_RQ(message_id_being_responded_to=42)
        raw = bytes(pkt)

        # Command field for C-CANCEL-RQ is 0x0FFF
        assert struct.pack("<H", 0x0FFF) in raw

    def test_c_cancel_rq_inherits_dimse_packet(self):
        """C_CANCEL_RQ should inherit from DIMSEPacket."""
        assert issubclass(C_CANCEL_RQ, DIMSEPacket)

    def test_c_cancel_rq_has_group_length(self):
        """C_CANCEL_RQ should have CommandGroupLength prepended."""
        pkt = C_CANCEL_RQ(message_id_being_responded_to=100)
        raw = bytes(pkt)

        # First element should be CommandGroupLength (0000,0000)
        tag_g, tag_e = struct.unpack("<HH", raw[:4])
        assert tag_g == 0x0000
        assert tag_e == 0x0000

    def test_c_cancel_rq_message_id_encoding(self):
        """C_CANCEL_RQ should encode the message ID being cancelled."""
        msg_id = 12345
        pkt = C_CANCEL_RQ(message_id_being_responded_to=msg_id)
        raw = bytes(pkt)

        # Message ID Being Responded To tag is (0000,0120)
        assert struct.pack("<H", msg_id) in raw


# =============================================================================
# Test DIMSE-N Commands (PS3.7 Section 10.3)
# =============================================================================

class TestDIMSENCommands:
    """Test DIMSE-N command packets per PS3.7 Section 10.3."""

    # -------------------------------------------------------------------------
    # N-EVENT-REPORT (Tables 10.3-1, 10.3-2)
    # -------------------------------------------------------------------------

    def test_n_event_report_rq_creation(self):
        """N_EVENT_REPORT_RQ should be creatable."""
        pkt = N_EVENT_REPORT_RQ(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7",
            message_id=1,
            event_type_id=1
        )
        raw = bytes(pkt)

        # Command field for N-EVENT-REPORT-RQ is 0x0100
        assert struct.pack("<H", 0x0100) in raw
        assert b'1.2.3.4.5' in raw

    def test_n_event_report_rsp_creation(self):
        """N_EVENT_REPORT_RSP should be creatable."""
        pkt = N_EVENT_REPORT_RSP(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7",
            message_id_responded=1,
            status=0x0000
        )
        raw = bytes(pkt)

        # Command field for N-EVENT-REPORT-RSP is 0x8100
        assert struct.pack("<H", 0x8100) in raw

    # -------------------------------------------------------------------------
    # N-GET (Tables 10.3-3, 10.3-4)
    # -------------------------------------------------------------------------

    def test_n_get_rq_creation(self):
        """N_GET_RQ should be creatable."""
        pkt = N_GET_RQ(
            requested_sop_class_uid="1.2.3.4.5",
            requested_sop_instance_uid="1.2.3.4.5.6.7",
            message_id=1
        )
        raw = bytes(pkt)

        # Command field for N-GET-RQ is 0x0110
        assert struct.pack("<H", 0x0110) in raw

    def test_n_get_rq_with_attribute_list(self):
        """N_GET_RQ should support Attribute Identifier List."""
        pkt = N_GET_RQ(
            requested_sop_class_uid="1.2.3.4.5",
            requested_sop_instance_uid="1.2.3.4.5.6.7",
            message_id=1,
            attribute_identifier_list=[(0x0010, 0x0010), (0x0010, 0x0020)]
        )
        raw = bytes(pkt)

        # Should contain the attribute tags
        assert len(raw) > 0

    def test_n_get_rsp_creation(self):
        """N_GET_RSP should be creatable."""
        pkt = N_GET_RSP(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7",
            message_id_responded=1,
            status=0x0000
        )
        raw = bytes(pkt)

        # Command field for N-GET-RSP is 0x8110
        assert struct.pack("<H", 0x8110) in raw

    # -------------------------------------------------------------------------
    # N-SET (Tables 10.3-5, 10.3-6)
    # -------------------------------------------------------------------------

    def test_n_set_rq_creation(self):
        """N_SET_RQ should be creatable."""
        pkt = N_SET_RQ(
            requested_sop_class_uid="1.2.3.4.5",
            requested_sop_instance_uid="1.2.3.4.5.6.7",
            message_id=1
        )
        raw = bytes(pkt)

        # Command field for N-SET-RQ is 0x0120
        assert struct.pack("<H", 0x0120) in raw

    def test_n_set_rsp_creation(self):
        """N_SET_RSP should be creatable."""
        pkt = N_SET_RSP(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7",
            message_id_responded=1,
            status=0x0000
        )
        raw = bytes(pkt)

        # Command field for N-SET-RSP is 0x8120
        assert struct.pack("<H", 0x8120) in raw

    # -------------------------------------------------------------------------
    # N-ACTION (Tables 10.3-7, 10.3-8)
    # -------------------------------------------------------------------------

    def test_n_action_rq_creation(self):
        """N_ACTION_RQ should be creatable."""
        pkt = N_ACTION_RQ(
            requested_sop_class_uid="1.2.3.4.5",
            requested_sop_instance_uid="1.2.3.4.5.6.7",
            message_id=1,
            action_type_id=1
        )
        raw = bytes(pkt)

        # Command field for N-ACTION-RQ is 0x0130
        assert struct.pack("<H", 0x0130) in raw

    def test_n_action_rsp_creation(self):
        """N_ACTION_RSP should be creatable."""
        pkt = N_ACTION_RSP(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7",
            message_id_responded=1,
            status=0x0000
        )
        raw = bytes(pkt)

        # Command field for N-ACTION-RSP is 0x8130
        assert struct.pack("<H", 0x8130) in raw

    # -------------------------------------------------------------------------
    # N-CREATE (Tables 10.3-9, 10.3-10)
    # -------------------------------------------------------------------------

    def test_n_create_rq_creation(self):
        """N_CREATE_RQ should be creatable."""
        pkt = N_CREATE_RQ(
            affected_sop_class_uid="1.2.3.4.5",
            message_id=1
        )
        raw = bytes(pkt)

        # Command field for N-CREATE-RQ is 0x0140
        assert struct.pack("<H", 0x0140) in raw

    def test_n_create_rq_with_instance_uid(self):
        """N_CREATE_RQ should support optional Affected SOP Instance UID."""
        pkt = N_CREATE_RQ(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7.8.9",
            message_id=1
        )
        raw = bytes(pkt)

        assert b'1.2.3.4.5.6.7.8.9' in raw

    def test_n_create_rsp_creation(self):
        """N_CREATE_RSP should be creatable."""
        pkt = N_CREATE_RSP(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7",
            message_id_responded=1,
            status=0x0000
        )
        raw = bytes(pkt)

        # Command field for N-CREATE-RSP is 0x8140
        assert struct.pack("<H", 0x8140) in raw

    # -------------------------------------------------------------------------
    # N-DELETE (Tables 10.3-11, 10.3-12)
    # -------------------------------------------------------------------------

    def test_n_delete_rq_creation(self):
        """N_DELETE_RQ should be creatable."""
        pkt = N_DELETE_RQ(
            requested_sop_class_uid="1.2.3.4.5",
            requested_sop_instance_uid="1.2.3.4.5.6.7",
            message_id=1
        )
        raw = bytes(pkt)

        # Command field for N-DELETE-RQ is 0x0150
        assert struct.pack("<H", 0x0150) in raw

    def test_n_delete_rsp_creation(self):
        """N_DELETE_RSP should be creatable."""
        pkt = N_DELETE_RSP(
            affected_sop_class_uid="1.2.3.4.5",
            affected_sop_instance_uid="1.2.3.4.5.6.7",
            message_id_responded=1,
            status=0x0000
        )
        raw = bytes(pkt)

        # Command field for N-DELETE-RSP is 0x8150
        assert struct.pack("<H", 0x8150) in raw

    # -------------------------------------------------------------------------
    # Common DIMSE-N Tests
    # -------------------------------------------------------------------------

    def test_dimse_n_commands_have_group_length(self):
        """All DIMSE-N commands should have CommandGroupLength prepended."""
        commands = [
            N_EVENT_REPORT_RQ(message_id=1),
            N_EVENT_REPORT_RSP(message_id_responded=1, status=0),
            N_GET_RQ(message_id=1),
            N_GET_RSP(message_id_responded=1, status=0),
            N_SET_RQ(message_id=1),
            N_SET_RSP(message_id_responded=1, status=0),
            N_ACTION_RQ(message_id=1, action_type_id=1),
            N_ACTION_RSP(message_id_responded=1, status=0),
            N_CREATE_RQ(message_id=1),
            N_CREATE_RSP(message_id_responded=1, status=0),
            N_DELETE_RQ(message_id=1),
            N_DELETE_RSP(message_id_responded=1, status=0),
        ]

        for cmd in commands:
            raw = bytes(cmd)
            # First element should be CommandGroupLength (0000,0000)
            tag_g, tag_e = struct.unpack("<HH", raw[:4])
            assert tag_g == 0x0000, f"{cmd.name} missing group length tag"
            assert tag_e == 0x0000, f"{cmd.name} missing group length tag"

    def test_dimse_n_in_pdata_tf(self):
        """DIMSE-N packets should work inside P-DATA-TF."""
        dimse = N_GET_RQ(
            requested_sop_class_uid="1.2.3.4.5",
            requested_sop_instance_uid="1.2.3.4.5.6.7",
            message_id=42
        )
        pdv = PresentationDataValueItem(
            context_id=1,
            data=bytes(dimse),
            is_command=1,
            is_last=1,
        )
        pdata = DICOM() / P_DATA_TF(pdv_items=[pdv])

        raw = bytes(pdata)
        assert raw[0] == 0x04  # P-DATA-TF PDU type
        assert b'1.2.3.4.5' in raw


# =============================================================================
# Test C-STORE Move Originator Fields
# =============================================================================

class TestCStoreMoveOriginatorFields:
    """Test C-STORE-RQ Move Originator fields per PS3.7 Table 9.3-1."""

    def test_c_store_rq_without_move_originator(self):
        """C_STORE_RQ without Move Originator should work normally."""
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8.9",
            message_id=1
        )
        raw = bytes(pkt)

        # Should not contain Move Originator tag (0000,1030)
        # This is tricky to test since the field is conditional
        assert b'1.2.3.4.5.6.7.8.9' in raw

    def test_c_store_rq_with_move_originator_ae(self):
        """C_STORE_RQ should support Move Originator AE Title."""
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8.9",
            message_id=1,
            move_originator_ae_title=b"MOVE_SCU"
        )
        raw = bytes(pkt)

        # Should contain Move Originator AE Title
        assert b'MOVE_SCU' in raw

    def test_c_store_rq_with_move_originator_message_id(self):
        """C_STORE_RQ should support Move Originator Message ID."""
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8.9",
            message_id=1,
            move_originator_ae_title=b"MOVE_SCU",
            move_originator_message_id=999
        )
        raw = bytes(pkt)

        # Should contain both Move Originator fields
        assert b'MOVE_SCU' in raw
        assert struct.pack("<H", 999) in raw


# =============================================================================
# Test LenField Auto-Calculation
# =============================================================================

class TestLenFieldAutoCalculation:
    """Test that LenField automatically calculates payload length."""

    def test_dicom_pdu_length_auto_calculated(self):
        """DICOM header should auto-calculate payload length."""
        pkt = DICOM() / A_RELEASE_RQ()
        raw = bytes(pkt)

        length_field = struct.unpack("!I", raw[2:6])[0]
        payload_size = len(raw) - 6

        assert length_field == payload_size
        assert length_field == 4

    def test_variable_item_length_auto_calculated(self):
        """DICOMVariableItem should auto-calculate payload length."""
        pkt = DICOMVariableItem() / DICOMApplicationContext()
        raw = bytes(pkt)

        length_field = struct.unpack("!H", raw[2:4])[0]
        payload_size = len(raw) - 4

        assert length_field == payload_size


# =============================================================================
# Test Variable Item Layer Binding
# =============================================================================

class TestVariableItemBindLayers:
    """Test that bind_layers correctly dispatches based on item_type."""

    def test_application_context_bind_layers(self):
        """DICOMVariableItem() / DICOMApplicationContext() should auto-set item_type=0x10."""
        pkt = DICOMVariableItem() / DICOMApplicationContext()
        assert pkt.item_type == 0x10

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x10
        assert parsed.haslayer(DICOMApplicationContext)

    def test_abstract_syntax_bind_layers(self):
        """DICOMVariableItem() / DICOMAbstractSyntax() should auto-set item_type=0x30."""
        uid = _uid_to_bytes(VERIFICATION_SOP_CLASS_UID)
        pkt = DICOMVariableItem() / DICOMAbstractSyntax(uid=uid)
        assert pkt.item_type == 0x30

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed.item_type == 0x30
        assert parsed.haslayer(DICOMAbstractSyntax)

    def test_transfer_syntax_bind_layers(self):
        """DICOMVariableItem() / DICOMTransferSyntax() should auto-set item_type=0x40."""
        pkt = DICOMVariableItem() / DICOMTransferSyntax()
        assert pkt.item_type == 0x40

    def test_maximum_length_bind_layers(self):
        """DICOMVariableItem() / DICOMMaximumLength() should auto-set item_type=0x51."""
        pkt = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=32768)
        assert pkt.item_type == 0x51

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMMaximumLength].max_pdu_length == 32768

    def test_user_information_bind_layers(self):
        """DICOMVariableItem() / DICOMUserInformation() should auto-set item_type=0x50."""
        max_len = DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=16384)
        pkt = DICOMVariableItem() / DICOMUserInformation(sub_items=[max_len])
        assert pkt.item_type == 0x50

    def test_presentation_context_rq_bind_layers(self):
        """DICOMVariableItem() / DICOMPresentationContextRQ() should auto-set item_type=0x20."""
        abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=_uid_to_bytes(VERIFICATION_SOP_CLASS_UID))
        ts = DICOMVariableItem() / DICOMTransferSyntax()
        pkt = DICOMVariableItem() / DICOMPresentationContextRQ(context_id=1, sub_items=[abs_syn, ts])
        assert pkt.item_type == 0x20

    def test_presentation_context_ac_bind_layers(self):
        """DICOMVariableItem() / DICOMPresentationContextAC() should auto-set item_type=0x21."""
        ts = DICOMVariableItem() / DICOMTransferSyntax()
        pkt = DICOMVariableItem() / DICOMPresentationContextAC(context_id=1, result=0, sub_items=[ts])
        assert pkt.item_type == 0x21

    def test_unknown_item_type_uses_guess_payload_class(self):
        """Unknown item_type should fall through guess_payload_class."""
        raw = struct.pack("!BBH", 0xFF, 0, 4) + b"test"
        parsed = DICOMVariableItem(raw)

        assert parsed.item_type == 0xFF
        assert parsed.length == 4


# =============================================================================
# Test DIMSE-C Packet Classes
# =============================================================================

class TestDIMSEPacketClasses:
    """Test the DIMSE packet classes."""

    def test_c_echo_rq_creation(self):
        """C_ECHO_RQ should be creatable with defaults."""
        pkt = C_ECHO_RQ()
        raw = bytes(pkt)

        # Should contain Verification SOP Class UID
        assert b'1.2.840.10008.1.1' in raw

    def test_c_echo_rq_custom_message_id(self):
        """C_ECHO_RQ should allow custom message_id."""
        pkt = C_ECHO_RQ(message_id=12345)
        raw = bytes(pkt)

        # Message ID tag is (0000,0110)
        assert struct.pack("<H", 12345) in raw

    def test_c_echo_rsp_creation(self):
        """C_ECHO_RSP should be creatable."""
        pkt = C_ECHO_RSP(message_id_responded=42, status=0x0000)
        raw = bytes(pkt)

        # Command field for C-ECHO-RSP is 0x8030
        assert struct.pack("<H", 0x8030) in raw

    def test_c_store_rq_creation(self):
        """C_STORE_RQ should be creatable with UIDs."""
        pkt = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid="1.2.3.4.5.6.7.8.9",
            message_id=100,
        )
        raw = bytes(pkt)

        assert b'1.2.840.10008.5.1.4.1.1.2' in raw
        assert b'1.2.3.4.5.6.7.8.9' in raw

    def test_c_find_rq_creation(self):
        """C_FIND_RQ should be creatable."""
        pkt = C_FIND_RQ(message_id=55)
        raw = bytes(pkt)

        # Command field for C-FIND-RQ is 0x0020
        assert struct.pack("<H", 0x0020) in raw

    def test_c_move_rq_with_destination(self):
        """C_MOVE_RQ should support move_destination field."""
        pkt = C_MOVE_RQ(message_id=100, move_destination=b"DEST_AE")
        raw = bytes(pkt)

        assert b'DEST_AE' in raw

    def test_c_move_rsp_with_counters(self):
        """C_MOVE_RSP should support sub-operation counters."""
        pkt = C_MOVE_RSP(
            message_id_responded=100,
            status=0xFF00,
            num_remaining=5,
            num_completed=3,
            num_failed=1,
            num_warning=0
        )
        raw = bytes(pkt)

        # Should contain the status
        assert struct.pack("<H", 0xFF00) in raw

    def test_c_get_rq_creation(self):
        """C_GET_RQ should be creatable."""
        pkt = C_GET_RQ(message_id=200)
        raw = bytes(pkt)

        # Command field for C-GET-RQ is 0x0010
        assert struct.pack("<H", 0x0010) in raw

    def test_dimse_in_pdata_tf(self):
        """DIMSE packets should work inside P-DATA-TF."""
        dimse = C_ECHO_RQ(message_id=42)
        pdv = PresentationDataValueItem(
            context_id=1,
            data=bytes(dimse),
            is_command=1,
            is_last=1,
        )
        pdata = DICOM() / P_DATA_TF(pdv_items=[pdv])

        raw = bytes(pdata)
        assert raw[0] == 0x04  # P-DATA-TF PDU type

        # Should contain the DIMSE data
        assert b'1.2.840.10008.1.1' in raw


# =============================================================================
# Test PDV Flag Encoding
# =============================================================================

class TestPDVFlagEncoding:
    """Test PresentationDataValueItem flag encoding."""

    def test_pdv_is_command_flag(self):
        """is_command flag should be encoded in message control byte."""
        pdv = PresentationDataValueItem(context_id=1, data=b'x', is_command=1, is_last=0)
        raw = bytes(pdv)

        msg_ctrl = raw[5]
        assert msg_ctrl & 0x01 == 1
        assert msg_ctrl & 0x02 == 0

    def test_pdv_is_last_flag(self):
        """is_last flag should be encoded in message control byte."""
        pdv = PresentationDataValueItem(context_id=1, data=b'x', is_command=0, is_last=1)
        raw = bytes(pdv)

        msg_ctrl = raw[5]
        assert msg_ctrl & 0x01 == 0
        assert msg_ctrl & 0x02 == 2

    def test_pdv_both_flags(self):
        """Both flags should combine correctly."""
        pdv = PresentationDataValueItem(context_id=1, data=b'x', is_command=1, is_last=1)
        raw = bytes(pdv)

        msg_ctrl = raw[5]
        assert msg_ctrl == 0x03

    def test_pdv_length_includes_header(self):
        """PDV length should include context_id and message_control bytes."""
        test_data = b"TEST_DATA_12345"
        pdv = PresentationDataValueItem(context_id=1, data=test_data, is_command=1, is_last=1)
        raw = bytes(pdv)

        length = struct.unpack("!I", raw[:4])[0]
        assert length == len(test_data) + 2  # +2 for context_id and msg_ctrl


# =============================================================================
# Test DIMSE Fuzzing Capabilities
# =============================================================================

class TestDIMSEFuzzing:
    """Test fuzzing capabilities - modifying fields before serialization."""

    def test_fuzz_message_id_boundary_values(self):
        """Test boundary message IDs."""
        for msg_id in [0, 1, 0x7FFF, 0xFFFF]:
            pkt = C_ECHO_RQ(message_id=msg_id)
            raw = bytes(pkt)
            assert struct.pack("<H", msg_id) in raw

    def test_fuzz_invalid_command_field(self):
        """Test setting invalid command field after creation."""
        pkt = C_ECHO_RQ()
        pkt.command_field = 0xDEAD
        raw = bytes(pkt)
        assert struct.pack("<H", 0xDEAD) in raw

    def test_fuzz_invalid_data_set_type(self):
        """Test invalid data set type."""
        pkt = C_ECHO_RQ()
        pkt.data_set_type = 0xBEEF
        raw = bytes(pkt)
        assert struct.pack("<H", 0xBEEF) in raw

    def test_fuzz_extreme_priority(self):
        """Test C-STORE with out-of-range priority."""
        pkt = C_STORE_RQ(priority=0xFFFF)
        raw = bytes(pkt)
        assert struct.pack("<H", 0xFFFF) in raw

    def test_mutate_group_length_via_raw_bytes(self):
        """Test mutating group_length after serialization for buffer over-read attacks."""
        pkt = C_ECHO_RQ(message_id=1)
        raw = bytearray(bytes(pkt))

        # Mutate group_length at bytes 8-12 to invalid value
        raw[8:12] = struct.pack("<I", 0xFFFFFFFF)

        # Verify mutation
        mutated_len = struct.unpack("<I", raw[8:12])[0]
        assert mutated_len == 0xFFFFFFFF

    def test_fuzz_dimse_n_invalid_event_type(self):
        """Test N-EVENT-REPORT with invalid event type ID."""
        pkt = N_EVENT_REPORT_RQ(
            message_id=1,
            event_type_id=0xFFFF  # Max value
        )
        raw = bytes(pkt)
        assert struct.pack("<H", 0xFFFF) in raw

    def test_fuzz_dimse_n_invalid_action_type(self):
        """Test N-ACTION with invalid action type ID."""
        pkt = N_ACTION_RQ(
            message_id=1,
            action_type_id=0xDEAD
        )
        raw = bytes(pkt)
        assert struct.pack("<H", 0xDEAD) in raw


# =============================================================================
# Test User Identity Negotiation
# =============================================================================

class TestUserIdentityNegotiation:
    """Tests for User Identity Negotiation sub-items."""

    def test_user_identity_username_only(self):
        """DICOMUserIdentity with username only (type 1)."""
        pkt = DICOMVariableItem() / DICOMUserIdentity(
            user_identity_type=1,
            primary_field=b"admin"
        )

        assert pkt.item_type == 0x58

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMUserIdentity].user_identity_type == 1
        assert parsed[DICOMUserIdentity].primary_field == b"admin"

    def test_user_identity_username_password(self):
        """DICOMUserIdentity with username+password (type 2)."""
        pkt = DICOMVariableItem() / DICOMUserIdentity(
            user_identity_type=2,
            primary_field=b"admin",
            secondary_field=b"password123"
        )

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMUserIdentity].user_identity_type == 2
        assert parsed[DICOMUserIdentity].secondary_field == b"password123"

    def test_user_identity_response(self):
        """DICOMUserIdentityResponse parsing."""
        pkt = DICOMVariableItem() / DICOMUserIdentityResponse(
            server_response=b"auth_token_12345"
        )

        assert pkt.item_type == 0x59

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMUserIdentityResponse].server_response == b"auth_token_12345"


# =============================================================================
# Test Async Operations Window
# =============================================================================

class TestAsyncOperationsWindow:
    """Tests for Asynchronous Operations Window sub-item."""

    def test_async_ops_default_values(self):
        """DICOMAsyncOperationsWindow should have default values of 1."""
        pkt = DICOMVariableItem() / DICOMAsyncOperationsWindow()
        assert pkt.item_type == 0x53

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMAsyncOperationsWindow].max_ops_invoked == 1
        assert parsed[DICOMAsyncOperationsWindow].max_ops_performed == 1

    def test_async_ops_custom_values(self):
        """DICOMAsyncOperationsWindow with custom values."""
        pkt = DICOMVariableItem() / DICOMAsyncOperationsWindow(
            max_ops_invoked=8,
            max_ops_performed=4
        )

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMAsyncOperationsWindow].max_ops_invoked == 8
        assert parsed[DICOMAsyncOperationsWindow].max_ops_performed == 4


# =============================================================================
# Test SCP/SCU Role Selection
# =============================================================================

class TestSCPSCURoleSelection:
    """Tests for SCP/SCU Role Selection sub-item."""

    def test_role_selection(self):
        """DICOMSCPSCURoleSelection should store role flags."""
        pkt = DICOMVariableItem() / DICOMSCPSCURoleSelection(
            sop_class_uid=b"1.2.840.10008.5.1.4.1.1.2",
            scu_role=1,
            scp_role=0
        )
        assert pkt.item_type == 0x54

        raw = bytes(pkt)
        parsed = DICOMVariableItem(raw)
        assert parsed[DICOMSCPSCURoleSelection].scu_role == 1
        assert parsed[DICOMSCPSCURoleSelection].scp_role == 0


# =============================================================================
# Test Round-Trip Serialization
# =============================================================================

class TestRoundTripSerialization:
    """Test that packets survive build -> serialize -> parse cycle."""

    def test_associate_rq_round_trip(self):
        """A-ASSOCIATE-RQ should survive serialization round-trip."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information(max_pdu_length=16384)

        original = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=b"TARGET",
            calling_ae_title=b"SOURCE",
            variable_items=[app_ctx, pctx, user_info]
        )
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(A_ASSOCIATE_RQ)
        assert parsed[A_ASSOCIATE_RQ].called_ae_title == b"TARGET          "
        assert parsed[A_ASSOCIATE_RQ].calling_ae_title == b"SOURCE          "

    def test_associate_rj_round_trip(self):
        """A-ASSOCIATE-RJ should survive serialization round-trip."""
        original = DICOM() / A_ASSOCIATE_RJ(result=1, source=2, reason_diag=2)
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(A_ASSOCIATE_RJ)
        assert parsed[A_ASSOCIATE_RJ].source == 2

    def test_release_rq_round_trip(self):
        """A-RELEASE-RQ should survive serialization round-trip."""
        original = DICOM() / A_RELEASE_RQ()
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(A_RELEASE_RQ)

    def test_release_rp_round_trip(self):
        """A-RELEASE-RP should survive serialization round-trip."""
        original = DICOM() / A_RELEASE_RP()
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(A_RELEASE_RP)

    def test_abort_round_trip(self):
        """A-ABORT should survive serialization round-trip."""
        original = DICOM() / A_ABORT(source=2, reason_diag=6)
        serialized = bytes(original)
        parsed = DICOM(serialized)

        assert parsed.haslayer(A_ABORT)
        assert parsed[A_ABORT].source == 2
        assert parsed[A_ABORT].reason_diag == 6

    def test_pdata_round_trip(self):
        """P-DATA-TF with PDV should survive serialization round-trip."""
        test_data = b"\x01\x02\x03\x04\x05"
        pdv = PresentationDataValueItem(
            context_id=3, data=test_data, is_command=1, is_last=1
        )
        original = DICOM() / P_DATA_TF(pdv_items=[pdv])
        serialized = bytes(original)

        # Verify structure
        assert serialized[0] == 0x04
        assert test_data in serialized


# =============================================================================
# Test Helper Functions
# =============================================================================

class TestHelperFunctions:
    """Test helper functions."""

    def test_build_presentation_context_rq(self):
        """build_presentation_context_rq should create proper structure."""
        pctx = build_presentation_context_rq(
            context_id=3,
            abstract_syntax_uid=VERIFICATION_SOP_CLASS_UID,
            transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID]
        )

        assert pctx.item_type == 0x20
        assert pctx[DICOMPresentationContextRQ].context_id == 3

        sub_items = pctx[DICOMPresentationContextRQ].sub_items
        assert len(sub_items) == 2
        assert sub_items[0].item_type == 0x30  # Abstract Syntax
        assert sub_items[1].item_type == 0x40  # Transfer Syntax

    def test_build_user_information(self):
        """build_user_information should create proper structure."""
        user_info = build_user_information(max_pdu_length=32768)

        assert user_info.item_type == 0x50
        sub_items = user_info[DICOMUserInformation].sub_items
        assert sub_items[0][DICOMMaximumLength].max_pdu_length == 32768

    def test_build_user_information_with_impl_info(self):
        """build_user_information with implementation details."""
        user_info = build_user_information(
            max_pdu_length=16384,
            implementation_class_uid="1.2.3.4.5",
            implementation_version="SCAPY_V1"
        )

        sub_items = user_info[DICOMUserInformation].sub_items
        assert len(sub_items) == 3

        types = [item.item_type for item in sub_items]
        assert 0x51 in types  # Maximum Length
        assert 0x52 in types  # Implementation Class UID
        assert 0x55 in types  # Implementation Version Name

    def test_uid_to_bytes_pads_odd_length(self):
        """_uid_to_bytes should pad odd-length UIDs."""
        result = _uid_to_bytes("1.2.3")  # 5 bytes - odd
        assert len(result) % 2 == 0
        assert result == b"1.2.3\x00"

    def test_uid_to_bytes_preserves_even_length(self):
        """_uid_to_bytes should preserve even-length UIDs but still pad."""
        result = _uid_to_bytes("1.2.3.4")  # 7 bytes - odd
        assert result == b"1.2.3.4\x00"

    def test_uid_to_bytes_raw_no_padding(self):
        """_uid_to_bytes_raw should not pad."""
        result = _uid_to_bytes_raw("1.2.3")  # 5 bytes - odd
        assert result == b"1.2.3"  # No padding

    def test_parse_dimse_status(self):
        """parse_dimse_status should extract status from DIMSE bytes."""
        # Build a C-ECHO-RSP and extract its status
        pkt = C_ECHO_RSP(message_id_responded=1, status=0x0000)
        raw = bytes(pkt)

        status = parse_dimse_status(raw)
        assert status == 0x0000

    def test_parse_dimse_status_multiple_values(self):
        """parse_dimse_status should work with different status values."""
        test_values = [0x0000, 0x0001, 0xFF00, 0xC000, 0xA700]

        for val in test_values:
            pkt = C_ECHO_RSP(message_id_responded=1, status=val)
            raw = bytes(pkt)
            status = parse_dimse_status(raw)
            assert status == val, f"Expected status 0x{val:04X}, got 0x{status:04X}"

    def test_parse_dimse_status_returns_none_for_invalid(self):
        """parse_dimse_status should return None for invalid data."""
        # Too short
        assert parse_dimse_status(b"short") is None

        # Empty
        assert parse_dimse_status(b"") is None

        # Random bytes
        assert parse_dimse_status(b"\x00" * 100) is None


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_variable_items(self):
        """A-ASSOCIATE-RQ with no variable items."""
        pkt = DICOM() / A_ASSOCIATE_RQ(variable_items=[])
        serialized = bytes(pkt)
        parsed = DICOM(serialized)
        assert parsed.haslayer(A_ASSOCIATE_RQ)

    def test_empty_pdv_items(self):
        """P-DATA-TF with no PDV items."""
        pkt = DICOM() / P_DATA_TF(pdv_items=[])
        serialized = bytes(pkt)
        assert len(serialized) == 6  # Just header

    def test_pdu_type_preservation(self):
        """Each PDU type should have correct type byte."""
        test_cases = [
            (A_ASSOCIATE_RQ(), 0x01),
            (A_ASSOCIATE_AC(), 0x02),
            (A_ASSOCIATE_RJ(), 0x03),
            (P_DATA_TF(), 0x04),
            (A_RELEASE_RQ(), 0x05),
            (A_RELEASE_RP(), 0x06),
            (A_ABORT(), 0x07),
        ]
        for pdu, expected_type in test_cases:
            pkt = DICOM() / pdu
            serialized = bytes(pkt)
            assert serialized[0] == expected_type

    def test_multiple_presentation_contexts(self):
        """A-ASSOCIATE-RQ with multiple presentation contexts."""
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx1 = build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        pctx2 = build_presentation_context_rq(3, CT_IMAGE_STORAGE_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID])
        user_info = build_user_information()

        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=b"TARGET",
            calling_ae_title=b"SOURCE",
            variable_items=[app_ctx, pctx1, pctx2, user_info]
        )

        raw = bytes(pkt)
        parsed = DICOM(raw)

        items = parsed[A_ASSOCIATE_RQ].variable_items
        assert len(items) == 4

        pctx_items = [i for i in items if i.item_type == 0x20]
        assert len(pctx_items) == 2


# =============================================================================
# Test DICOMSession
# =============================================================================

class TestDICOMSocket:
    """Test DICOMSession class structure (no network required)."""

    def test_dicom_socket_init(self):
        """DICOMSession should initialize with required parameters."""
        sock = DICOMSession(
            dst_ip="127.0.0.1",
            dst_port=104,
            dst_ae="TEST_SCP",
            src_ae="TEST_SCU"
        )

        assert sock.dst_ip == "127.0.0.1"
        assert sock.dst_port == 104
        assert sock.dst_ae == "TEST_SCP"
        assert sock.src_ae == "TEST_SCU"
        assert sock.assoc_established is False

    def test_dicom_socket_has_required_methods(self):
        """DICOMSession should have standard API methods."""
        sock = DICOMSession("127.0.0.1", 104, "TEST")

        assert hasattr(sock, 'connect')
        assert hasattr(sock, 'associate')
        assert hasattr(sock, 'c_echo')
        assert hasattr(sock, 'c_store')
        assert hasattr(sock, 'release')
        assert hasattr(sock, 'close')
        assert hasattr(sock, 'send')
        assert hasattr(sock, 'recv')
        assert hasattr(sock, 'sr1')
        assert hasattr(sock, 'send_raw_bytes')

    def test_dicom_socket_context_manager(self):
        """DICOMSession should support context manager protocol."""
        sock = DICOMSession("127.0.0.1", 104, "TEST")

        assert hasattr(sock, '__enter__')
        assert hasattr(sock, '__exit__')


# =============================================================================
# Test Constants
# =============================================================================

class TestConstants:
    """Test that required constants are exported."""

    def test_port_constant(self):
        """DICOM_PORT should be 104."""
        from c_scare.scapy_dicom import DICOM_PORT
        assert DICOM_PORT == 104

    def test_uid_constants(self):
        """UID constants should be defined."""
        assert APP_CONTEXT_UID == "1.2.840.10008.3.1.1.1"
        assert DEFAULT_TRANSFER_SYNTAX_UID == "1.2.840.10008.1.2"
        assert VERIFICATION_SOP_CLASS_UID == "1.2.840.10008.1.1"
        assert CT_IMAGE_STORAGE_SOP_CLASS_UID == "1.2.840.10008.5.1.4.1.1.2"

    def test_qr_sop_class_uids(self):
        """Query/Retrieve SOP Class UIDs should be defined."""
        assert PATIENT_ROOT_QR_FIND_SOP_CLASS_UID == "1.2.840.10008.5.1.4.1.2.1.1"
        assert PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID == "1.2.840.10008.5.1.4.1.2.1.2"
        assert PATIENT_ROOT_QR_GET_SOP_CLASS_UID == "1.2.840.10008.5.1.4.1.2.1.3"


# =============================================================================
# Integration Tests (require --ip, --port, --ae-title)
# =============================================================================

integration_test_marker = pytest.mark.skipif(
    "not config.getoption('--ip')",
    reason="Integration test requires --ip, --port, and --ae-title"
)


@integration_test_marker
def test_c_echo_integration(scp_ip, scp_port, scp_ae, my_ae, timeout):
    """Performs a full C-ECHO workflow against a live SCP using send/recv."""
    import socket
    from scapy.supersocket import StreamSocket

    # Create raw socket connection
    sock = socket.create_connection((scp_ip, scp_port), timeout=timeout)
    stream = StreamSocket(sock, basecls=DICOM)

    try:
        # Build A-ASSOCIATE-RQ
        app_ctx = DICOMVariableItem() / DICOMApplicationContext()
        pctx = build_presentation_context_rq(
            1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]
        )
        user_info = build_user_information(max_pdu_length=16384)

        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=scp_ae,
            calling_ae_title=my_ae,
            variable_items=[app_ctx, pctx, user_info],
        )

        # Send association request
        stream.send(assoc_rq)

        # Receive response (don't use sr1, use recv directly)
        response = stream.recv()
        assert response is not None, "No response received for A-ASSOCIATE-RQ"
        assert response.haslayer(A_ASSOCIATE_AC), f"Expected A-ASSOCIATE-AC, got {response.summary()}"

        # Find accepted context ID
        ctx_id = None
        for item in response[A_ASSOCIATE_AC].variable_items:
            if item.item_type == 0x21 and item.haslayer(DICOMPresentationContextAC):
                pctx_ac = item[DICOMPresentationContextAC]
                if pctx_ac.result == 0:
                    ctx_id = pctx_ac.context_id
                    break

        assert ctx_id is not None, "No accepted presentation context"

        # Build and send C-ECHO-RQ
        dimse_rq = C_ECHO_RQ(message_id=1)
        pdv_rq = PresentationDataValueItem(
            context_id=ctx_id,
            data=bytes(dimse_rq),
            is_command=1,
            is_last=1,
        )
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])
        stream.send(pdata_rq)

        # Receive C-ECHO-RSP
        echo_response = stream.recv()
        assert echo_response is not None, "No response received for C-ECHO-RQ"
        assert echo_response.haslayer(P_DATA_TF), f"Expected P-DATA-TF, got {echo_response.summary()}"

        # Parse status
        pdv_items = echo_response[P_DATA_TF].pdv_items
        assert len(pdv_items) > 0, "No PDV items in response"

        # Get PDV data and ensure it's bytes
        pdv_data = pdv_items[0].data
        if isinstance(pdv_data, str):
            pdv_data = pdv_data.encode('latin-1')
        elif not isinstance(pdv_data, bytes):
            pdv_data = bytes(pdv_data)

        # Debug: print the raw data to understand structure
        print(f"\nDEBUG: PDV data length: {len(pdv_data)}")
        print(f"DEBUG: First 64 bytes (hex): {pdv_data[:64].hex()}")
        print(f"DEBUG: is_command flag: {pdv_items[0].is_command}")
        print(f"DEBUG: is_last flag: {pdv_items[0].is_last}")

        status = parse_dimse_status(pdv_data)
        assert status is not None, (
            f"Failed to parse DIMSE status from response. "
            f"PDV data length: {len(pdv_data)}, "
            f"First 64 bytes (hex): {pdv_data[:64].hex()}"
        )
        assert status == 0x0000, f"C-ECHO failed with status: 0x{status:04X}"

        # Send A-RELEASE-RQ
        release_rq = DICOM() / A_RELEASE_RQ()
        stream.send(release_rq)

        # Receive A-RELEASE-RP
        release_response = stream.recv()
        assert release_response is not None, "No response received for A-RELEASE-RQ"
        assert release_response.haslayer(A_RELEASE_RP), f"Expected A-RELEASE-RP, got {release_response.summary()}"

    finally:
        try:
            stream.close()
        except Exception:
            pass

# =============================================================================
# Test SCP/SCU Role Selection negotiation (Phase 2 strict-peer C-GET)
# =============================================================================

class TestRoleNegotiation:
    """build_user_information emits 0x54 role items inside the 0x50 User
    Information item, and DICOMSession._parse_negotiated_roles reads them back
    out of an AC."""

    def test_build_user_information_includes_roles(self):
        ui = build_user_information(
            roles={"1.2.840.10008.5.1.4.1.1.2": (0, 1)})
        # The 0x54 item must be nested inside the 0x50 User Information item,
        # not a sibling at the A-ASSOCIATE level (PS3.7 D.3.3.4).
        sub_types = [s.item_type for s in ui[DICOMUserInformation].sub_items]
        assert 0x51 in sub_types  # max length
        assert 0x54 in sub_types  # role selection
        role = [s for s in ui[DICOMUserInformation].sub_items
                if s.item_type == 0x54][0][DICOMSCPSCURoleSelection]
        assert role.scu_role == 0
        assert role.scp_role == 1
        uid = role.sop_class_uid.rstrip(b"\x00").decode("ascii")
        assert uid == "1.2.840.10008.5.1.4.1.1.2"

    def test_build_user_information_omits_roles_when_none(self):
        ui = build_user_information()
        sub_types = [s.item_type for s in ui[DICOMUserInformation].sub_items]
        assert 0x54 not in sub_types

    def test_parse_negotiated_roles_reads_ac_echo(self):
        from c_scare.client import DICOMSession
        # Build an AC carrying an echoed 0x54 role item inside User Information.
        ui = build_user_information(roles={"1.2.840.10008.5.1.4.1.1.7": (0, 1)})
        ac = DICOM() / A_ASSOCIATE_AC(
            variable_items=[DICOMVariableItem() / DICOMApplicationContext(), ui])
        sock = DICOMSession("127.0.0.1", 11112, "X", "Y")
        sock._parse_negotiated_roles(ac)
        assert sock.negotiated_roles.get("1.2.840.10008.5.1.4.1.1.7") == (0, 1)
