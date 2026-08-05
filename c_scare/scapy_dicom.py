# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Tyler M

# scapy.contrib.description = DICOM Protocol
# scapy.contrib.status = loads

"""
DICOM Protocol Implementation for Scapy

This module implements:
- DICOM Upper Layer Protocol (PS3.8 - Network Communication Support)
- DIMSE Message Service Element (PS3.7 - Message Exchange)
- Association negotiation sub-items (PS3.7 Annex D.3.3)
- Transfer Syntax and encoding constants (PS3.5 - Data Structures and Encoding)

References:
- PS3.5: https://dicom.nema.org/medical/dicom/current/output/html/part05.html
- PS3.7: https://dicom.nema.org/medical/dicom/current/output/html/part07.html
- PS3.8: https://dicom.nema.org/medical/dicom/current/output/html/part08.html

The DICOM protocol stack:
    +---------------------------+
    |  DIMSE Messages (PS3.7)   |  <- C-ECHO, C-STORE, N-GET, etc.
    +---------------------------+
    |  P-DATA-TF PDV payload    |
    +---------------------------+
    |  Upper Layer PDUs (PS3.8) |  <- A-ASSOCIATE, P-DATA-TF, A-RELEASE
    +---------------------------+
    |          TCP              |
    +---------------------------+

Note on PS3.5 encoding:
    DIMSE Command Sets (this module) always use Implicit VR Little Endian
    encoding per PS3.7 Section 9.3, regardless of the negotiated Transfer
    Syntax for Data Sets. The Transfer Syntax UIDs defined here are for
    negotiation and identification purposes.
"""

import logging
import socket
import struct
from typing import Any, Dict, Generator, List, Optional, Tuple, Union, TYPE_CHECKING

# =============================================================================
# SCAPY IPv6 FIX - Must run before any scapy.layers imports
# Fixes KeyError: 'scope' in containerized environments without full IPv6
# =============================================================================
class _FakeRoute6:
    """Fake Route6 class to avoid IPv6 routing errors in containers."""
    routes = []
    def resync(self): pass
    def route(self, *args, **kwargs): return ("::", "::", "::")

try:
    import scapy.config
    scapy.config.conf.route6 = _FakeRoute6()
except Exception:
    pass
# =============================================================================

# Handle Self import for backwards compatibility across Python versions
# Per scapy devs: use scapy.compat.Self for backwards compatibility
try:
    from scapy.compat import Self
except ImportError:
    try:
        from typing import Self  # Python 3.11+
    except ImportError:
        # Fallback for Python < 3.11 without scapy.compat.Self
        if TYPE_CHECKING:
            from typing_extensions import Self
        else:
            Self = Any  # Runtime fallback

from scapy.packet import Packet, bind_layers
from scapy.error import Scapy_Exception
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    IntField,
    LenField,
    PacketListField,
    ShortField,
    StrFixedLenField,
    StrLenField,
)
from scapy.layers.inet import TCP
from scapy.supersocket import StreamSocket
from scapy.volatile import RandShort, RandInt, RandString

__all__ = [
 
    # Constants
 
    "DICOM_PORT",
    "DICOM_PORT_ALT",
    "APP_CONTEXT_UID",
    # Transfer Syntax UIDs (PS3.5 Annex A)
    "DEFAULT_TRANSFER_SYNTAX_UID",
    "IMPLICIT_VR_LITTLE_ENDIAN_UID",
    "EXPLICIT_VR_LITTLE_ENDIAN_UID",
    "EXPLICIT_VR_BIG_ENDIAN_UID",
    "DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID",
    "JPEG_BASELINE_UID",
    "JPEG_LOSSLESS_UID",
    "JPEG_LS_LOSSLESS_UID",
    "JPEG_LS_LOSSY_UID",
    "JPEG_2000_LOSSLESS_UID",
    "JPEG_2000_UID",
    "RLE_LOSSLESS_UID",
    "HTJP2K_LOSSLESS_UID",
    "HTJP2K_LOSSLESS_RPCL_UID",
    "HTJP2K_UID",
    # SOP Class UIDs (PS3.4)
    "VERIFICATION_SOP_CLASS_UID",
    "CT_IMAGE_STORAGE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_FIND_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_GET_SOP_CLASS_UID",
    "STUDY_ROOT_QR_FIND_SOP_CLASS_UID",
    "STUDY_ROOT_QR_MOVE_SOP_CLASS_UID",
    "STUDY_ROOT_QR_GET_SOP_CLASS_UID",
    "MODALITY_WORKLIST_FIND_SOP_CLASS_UID",
    "MPPS_SOP_CLASS_UID",
    "STORAGE_COMMITMENT_SOP_CLASS_UID",
    "STORAGE_COMMITMENT_SOP_INSTANCE_UID",
    "MR_IMAGE_STORAGE_SOP_CLASS_UID",
    "SECONDARY_CAPTURE_SOP_CLASS_UID",
    "IMPLEMENTATION_CLASS_UID",

    # PDU Classes (PS3.8 Section 9.3)
 
    "DICOM",
    "A_ASSOCIATE_RQ",
    "A_ASSOCIATE_AC",
    "A_ASSOCIATE_RJ",
    "P_DATA_TF",
    "A_RELEASE_RQ",
    "A_RELEASE_RP",
    "A_ABORT",
    "PresentationDataValueItem",
    # Transport (PS3.8 Section 9.1) - reusable DICOM UL socket + framing
    "DICOMSocket",
    "read_dul_pdu",
    "PDU_HEADER_LEN",
 
    # Variable Items (PS3.8 Section 9.3.2)
 
    "DICOMVariableItem",
    "DICOMApplicationContext",
    "DICOMPresentationContextRQ",
    "DICOMPresentationContextAC",
    "DICOMAbstractSyntax",
    "DICOMTransferSyntax",
    "DICOMUserInformation",
    "DICOMMaximumLength",
    "DICOMGenericItem",
 
    # Extended User Info Sub-Items (PS3.7 D.3.3)
 
    "DICOMImplementationClassUID",
    "DICOMAsyncOperationsWindow",
    "DICOMSCPSCURoleSelection",
    "DICOMImplementationVersionName",
    "DICOMSOPClassExtendedNegotiation",
    "DICOMSOPClassCommonExtendedNegotiation",
    "DICOMUserIdentity",
    "DICOMUserIdentityResponse",
    # DIMSE Field Classes
    "DICOMAETitleField",
    "DICOMElementField",
    "DICOMUIDField",
    "DICOMUSField",
    "DICOMULField",
    "DICOMAEDIMSEField",
    "DICOMATField",
    # DIMSE Base Class
    "DIMSEPacket",
    # DIMSE-C Commands (PS3.7 Section 9.3)
    "C_ECHO_RQ",
    "C_ECHO_RSP",
    "C_STORE_RQ",
    "C_STORE_RSP",
    "C_FIND_RQ",
    "C_FIND_RSP",
    "C_MOVE_RQ",
    "C_MOVE_RSP",
    "C_GET_RQ",
    "C_GET_RSP",
    "C_CANCEL_RQ",
     # DIMSE-N Commands (PS3.7 Section 10.3)
     "N_EVENT_REPORT_RQ",
    "N_EVENT_REPORT_RSP",
    "N_GET_RQ",
    "N_GET_RSP",
    "N_SET_RQ",
    "N_SET_RSP",
    "N_ACTION_RQ",
    "N_ACTION_RSP",
    "N_CREATE_RQ",
    "N_CREATE_RSP",
    "N_DELETE_RQ",
    "N_DELETE_RSP",
     # Utilities
     "parse_dimse_status",
    "parse_dimse_command_us",
    "parse_dimse_command_field",
    "_uid_to_bytes",
    "_uid_to_bytes_raw",
    "build_presentation_context_rq",
    "build_user_information",
    "raw_ae_title",
    "raw_item",
    "raw_presentation_context",
    "raw_user_information",
    "raw_associate_rq_with_items",
    "raw_associate_rq",
    "raw_release_rq",
    "_uid_to_bytes_raw",
    "build_user_identity",
     # DIMSE Status Codes (PS3.7 Annex C)
     "STATUS_SUCCESS",
    "STATUS_CANCEL",
    "STATUS_PENDING",
    "STATUS_PENDING_WARNINGS",
    "STATUS_WARNING_ATTRIBUTE_LIST",
    "STATUS_WARNING_ATTR_OUT_OF_RANGE",
    "STATUS_ERR_SOP_CLASS_NOT_SUPPORTED",
    "STATUS_ERR_CLASS_INSTANCE_CONFLICT",
    "STATUS_ERR_DUPLICATE_SOP_INSTANCE",
    "STATUS_ERR_DUPLICATE_INVOCATION",
    "STATUS_ERR_INVALID_ARGUMENT",
    "STATUS_ERR_INVALID_ATTRIBUTE_VALUE",
    "STATUS_ERR_INVALID_SOP_INSTANCE",
    "STATUS_ERR_MISSING_ATTRIBUTE",
    "STATUS_ERR_MISSING_ATTRIBUTE_VALUE",
    "STATUS_ERR_MISTYPED_ARGUMENT",
    "STATUS_ERR_NO_SUCH_ARGUMENT",
    "STATUS_ERR_NO_SUCH_ATTRIBUTE",
    "STATUS_ERR_NO_SUCH_EVENT_TYPE",
    "STATUS_ERR_NO_SUCH_SOP_INSTANCE",
    "STATUS_ERR_NO_SUCH_SOP_CLASS",
    "STATUS_ERR_PROCESSING_FAILURE",
    "STATUS_ERR_RESOURCE_LIMITATION",
    "STATUS_ERR_UNRECOGNIZED_OPERATION",
    "STATUS_ERR_NO_SUCH_ACTION_TYPE",
    "STATUS_ERR_NOT_AUTHORIZED",
]

log = logging.getLogger("scapy.contrib.dicom")

# Constants


# Standard DICOM ports (PS3.8 Section 9.1.1)
DICOM_PORT = 104        # Well-known port (privileged)
DICOM_PORT_ALT = 11112  # Registered port (non-privileged)

# Application Context Name (PS3.7 Annex A, B)
APP_CONTEXT_UID = "1.2.840.10008.3.1.1.1"


# Transfer Syntax UIDs (PS3.5 Annex A)


# Default - Implicit VR Little Endian (PS3.5 A.1)
DEFAULT_TRANSFER_SYNTAX_UID = "1.2.840.10008.1.2"
IMPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2"

# Explicit VR Little Endian (PS3.5 A.2)
EXPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2.1"

# Explicit VR Big Endian (PS3.5 A.3) - Retired but still encountered
EXPLICIT_VR_BIG_ENDIAN_UID = "1.2.840.10008.1.2.2"

# Deflated Explicit VR Little Endian (PS3.5 A.5)
DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN_UID = "1.2.840.10008.1.2.1.99"

# JPEG Baseline (Process 1) - Lossy (PS3.5 A.4.1)
JPEG_BASELINE_UID = "1.2.840.10008.1.2.4.50"

# JPEG Lossless, Non-Hierarchical (Process 14, First-Order Prediction)
JPEG_LOSSLESS_UID = "1.2.840.10008.1.2.4.70"

# JPEG-LS Lossless (PS3.5 A.4.4)
JPEG_LS_LOSSLESS_UID = "1.2.840.10008.1.2.4.80"

# JPEG-LS Near-Lossless (PS3.5 A.4.4)
JPEG_LS_LOSSY_UID = "1.2.840.10008.1.2.4.81"

# JPEG 2000 Image Compression (Lossless Only) (PS3.5 A.4.5)
JPEG_2000_LOSSLESS_UID = "1.2.840.10008.1.2.4.90"

# JPEG 2000 Image Compression (PS3.5 A.4.5)
JPEG_2000_UID = "1.2.840.10008.1.2.4.91"

# RLE Lossless (PS3.5 A.4.2)
RLE_LOSSLESS_UID = "1.2.840.10008.1.2.5"

# High-Throughput JPEG 2000 Lossless (HTJP2K) (PS3.5 A.4.7)
HTJP2K_LOSSLESS_UID = "1.2.840.10008.1.2.4.201"

# High-Throughput JPEG 2000 with RPCL (HTJP2K-RPL) (PS3.5 A.4.7)
HTJP2K_LOSSLESS_RPCL_UID = "1.2.840.10008.1.2.4.202"

# High-Throughput JPEG 2000 (HTJP2K) (PS3.5 A.4.7)
HTJP2K_UID = "1.2.840.10008.1.2.4.203"

# SOP Class UIDs (PS3.4 - commonly used)
VERIFICATION_SOP_CLASS_UID = "1.2.840.10008.1.1"
CT_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"
PATIENT_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.1"
PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.2"
PATIENT_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.1.3"
STUDY_ROOT_QR_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.1"
STUDY_ROOT_QR_MOVE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.2"
STUDY_ROOT_QR_GET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.2.2.3"
MODALITY_WORKLIST_FIND_SOP_CLASS_UID = "1.2.840.10008.5.1.4.31"
# DIMSE-N service classes. Storage Commitment addresses a well-known SOP
# instance (PS3.4 J.3.1) rather than one created by the SCU.
MPPS_SOP_CLASS_UID = "1.2.840.10008.3.1.2.3.3"
STORAGE_COMMITMENT_SOP_CLASS_UID = "1.2.840.10008.1.20.1"
STORAGE_COMMITMENT_SOP_INSTANCE_UID = "1.2.840.10008.1.20.1.1"
MR_IMAGE_STORAGE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.4"
SECONDARY_CAPTURE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.7"
IMPLEMENTATION_CLASS_UID = "1.2.3.4.5.6.7.8.9"


# PDU Type Definitions (PS3.8 Section 9.3.1)


PDU_TYPES = {
    0x01: "A-ASSOCIATE-RQ",
    0x02: "A-ASSOCIATE-AC",
    0x03: "A-ASSOCIATE-RJ",
    0x04: "P-DATA-TF",
    0x05: "A-RELEASE-RQ",
    0x06: "A-RELEASE-RP",
    0x07: "A-ABORT",
}



# Item Type Definitions (PS3.8 Section 9.3.2-9.3.3, PS3.7 Annex D.3.3)


ITEM_TYPES = {
    # PS3.8 defined items
    0x10: "Application Context",
    0x20: "Presentation Context RQ",
    0x21: "Presentation Context AC",
    0x30: "Abstract Syntax",
    0x40: "Transfer Syntax",
    0x50: "User Information",
    0x51: "Maximum Length",
    # PS3.7 D.3.3 defined items
    0x52: "Implementation Class UID",
    0x53: "Asynchronous Operations Window",
    0x54: "SCP/SCU Role Selection",
    0x55: "Implementation Version Name",
    0x56: "SOP Class Extended Negotiation",
    0x57: "SOP Class Common Extended Negotiation",
    0x58: "User Identity",
    0x59: "User Identity Server Response",
}



# DIMSE Command Field Values (PS3.7 E.1-1)


DIMSE_COMMAND_FIELDS = {
    # DIMSE-C (Section 9)
    0x0001: "C-STORE-RQ",
    0x8001: "C-STORE-RSP",
    0x0010: "C-GET-RQ",
    0x8010: "C-GET-RSP",
    0x0020: "C-FIND-RQ",
    0x8020: "C-FIND-RSP",
    0x0021: "C-MOVE-RQ",
    0x8021: "C-MOVE-RSP",
    0x0030: "C-ECHO-RQ",
    0x8030: "C-ECHO-RSP",
    0x0FFF: "C-CANCEL-RQ",
    # DIMSE-N (Section 10)
    0x0100: "N-EVENT-REPORT-RQ",
    0x8100: "N-EVENT-REPORT-RSP",
    0x0110: "N-GET-RQ",
    0x8110: "N-GET-RSP",
    0x0120: "N-SET-RQ",
    0x8120: "N-SET-RSP",
    0x0130: "N-ACTION-RQ",
    0x8130: "N-ACTION-RSP",
    0x0140: "N-CREATE-RQ",
    0x8140: "N-CREATE-RSP",
    0x0150: "N-DELETE-RQ",
    0x8150: "N-DELETE-RSP",
}

PRIORITY_VALUES = {
    0x0000: "MEDIUM",
    0x0001: "HIGH",
    0x0002: "LOW",
}



# DIMSE Status Codes (PS3.7 Annex C)


# Status Class convention per Annex C:
# Success: 0000
# Warning: 0001, Bxxx, 0107, 0116
# Failure: Axxx, Cxxx, 01xx (except 0107, 0116), 02xx
# Cancel: FE00
# Pending: FF00, FF01

STATUS_SUCCESS = 0x0000          # C.1.1 Success
STATUS_CANCEL = 0xFE00           # C.3.1 Cancel
STATUS_PENDING = 0xFF00          # C.2.1 Pending
STATUS_PENDING_WARNINGS = 0xFF01 # C.2.1 Pending (with optional keys)

# Warning Status Codes (C.4)
STATUS_WARNING_ATTRIBUTE_LIST = 0x0107   # C.4.2 Attribute List warning
STATUS_WARNING_ATTR_OUT_OF_RANGE = 0x0116  # C.4.3 Attribute Value out of range

# Failure Status Codes (C.5)
STATUS_ERR_SOP_CLASS_NOT_SUPPORTED = 0x0122  # C.5.6
STATUS_ERR_CLASS_INSTANCE_CONFLICT = 0x0119  # C.5.7
STATUS_ERR_DUPLICATE_SOP_INSTANCE = 0x0111   # C.5.8
STATUS_ERR_DUPLICATE_INVOCATION = 0x0210     # C.5.9
STATUS_ERR_INVALID_ARGUMENT = 0x0115         # C.5.10
STATUS_ERR_INVALID_ATTRIBUTE_VALUE = 0x0106  # C.5.11
STATUS_ERR_INVALID_SOP_INSTANCE = 0x0117     # C.5.12
STATUS_ERR_MISSING_ATTRIBUTE = 0x0120        # C.5.13
STATUS_ERR_MISSING_ATTRIBUTE_VALUE = 0x0121  # C.5.14
STATUS_ERR_MISTYPED_ARGUMENT = 0x0212        # C.5.15
STATUS_ERR_NO_SUCH_ARGUMENT = 0x0114         # C.5.16
STATUS_ERR_NO_SUCH_ATTRIBUTE = 0x0105        # C.5.17
STATUS_ERR_NO_SUCH_EVENT_TYPE = 0x0113       # C.5.18
STATUS_ERR_NO_SUCH_SOP_INSTANCE = 0x0112     # C.5.19
STATUS_ERR_NO_SUCH_SOP_CLASS = 0x0118        # C.5.20
STATUS_ERR_PROCESSING_FAILURE = 0x0110       # C.5.21
STATUS_ERR_RESOURCE_LIMITATION = 0x0213      # C.5.22
STATUS_ERR_UNRECOGNIZED_OPERATION = 0x0211   # C.5.23
STATUS_ERR_NO_SUCH_ACTION_TYPE = 0x0123      # C.5.24
STATUS_ERR_NOT_AUTHORIZED = 0x0124           # C.5.25



# Utility Functions


def _uid_to_bytes(uid):
    # type: (Any) -> bytes
    """
    Convert UID to bytes with even-length padding per PS3.8 Annex F.

    UIDs are encoded as ISO 646:1990-Basic G0 Set character strings.
    DICOM UIDs shall not exceed 64 characters.
    """
    if isinstance(uid, bytes):
        b_uid = uid
    elif isinstance(uid, str):
        b_uid = uid.encode("ascii")
    else:
        return b""
    # Pad to even length with null byte if needed
    if len(b_uid) % 2 != 0:
        b_uid += b"\x00"
    return b_uid

def _uid_to_bytes_raw(uid):
    # type: (Union[str, bytes]) -> bytes
    """Convert a UID to bytes with no even-length padding.

    PS3.5 9.1 pads UIDs to even length, and :func:`_uid_to_bytes` does that -
    it is required inside a data set, where the element length must be even,
    and permitted inside a PDU item. Real peers send PDU-item UIDs both ways
    and accept both. Use this when a test needs the unpadded form specifically,
    e.g. to check that a target's UID matching is padding-insensitive."""
    if isinstance(uid, bytes):
        return uid
    elif isinstance(uid, str):
        return uid.encode("ascii")
    else:
        return b""



# Field Classes


class DICOMAETitleField(StrFixedLenField):
    """
    DICOM AE Title field - 16 bytes, space-padded.

    Per PS3.8 Section 9.3.2 Table 9-11:
    "It shall be encoded as 16 characters as defined by the ISO 646:1990-Basic
    G0 Set with leading and trailing spaces (20H) being non-significant."
    """

    def __init__(self, name, default=b""):
        # type: (str, bytes) -> None
        super(DICOMAETitleField, self).__init__(name, default, length=16)

    def i2m(self, pkt, val):
        # type: (Optional[Packet], Any) -> bytes
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        return val.ljust(16, b" ")[:16]

    def m2i(self, pkt, val):
        # type: (Optional[Packet], bytes) -> bytes
        return val

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], Any) -> str
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").rstrip()
        return str(val).rstrip()



# Generic Item Handler


class DICOMGenericItem(Packet):
    """
    Generic fallback for unrecognized DICOM variable items.

    Per PS3.8 Section 9.3.1:
    "Items of unrecognized types shall be ignored and skipped."
    """

    name = "DICOM Generic Item"
    fields_desc = [
        StrLenField(
            "data", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else len(pkt.data)
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s



# Variable Item Header (PS3.8 Section 9.3.2)


class DICOMVariableItem(Packet):
    """
    DICOM Variable Item header structure.

    All variable items in A-ASSOCIATE-RQ/AC share this common header:
    - Item-type (1 byte)
    - Reserved (1 byte, shall be 0x00) - except 0x57 which uses Sub-Item-version
    - Item-length (2 bytes, unsigned, big-endian)
    """

    name = "DICOM Variable Item"
    fields_desc = [
        ByteEnumField("item_type", 0x10, ITEM_TYPES),
        ByteField("reserved", 0),  # Note: For 0x57, this is Sub-Item-version
        LenField("length", None, fmt="!H"),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        if self.length is not None:
            if len(s) < self.length:
                raise Scapy_Exception(
                    f"Variable item payload incomplete: expected {self.length} "
                    f"bytes, got {len(s)}"
                )
            return s[:self.length], s[self.length:]
        return s, b""

    def guess_payload_class(self, payload):
        # type: (bytes) -> type
        """Route to appropriate item class based on item_type."""
        type_to_class = {
            0x10: DICOMApplicationContext,
            0x20: DICOMPresentationContextRQ,
            0x21: DICOMPresentationContextAC,
            0x30: DICOMAbstractSyntax,
            0x40: DICOMTransferSyntax,
            0x50: DICOMUserInformation,
            0x51: DICOMMaximumLength,
            0x52: DICOMImplementationClassUID,
            0x53: DICOMAsyncOperationsWindow,
            0x54: DICOMSCPSCURoleSelection,
            0x55: DICOMImplementationVersionName,
            0x56: DICOMSOPClassExtendedNegotiation,
            0x57: DICOMSOPClassCommonExtendedNegotiation,
            0x58: DICOMUserIdentity,
            0x59: DICOMUserIdentityResponse,
        }
        return type_to_class.get(self.item_type, DICOMGenericItem)

    def mysummary(self):
        # type: () -> str
        return self.sprintf("Item %item_type%")



# Application Context Item (PS3.8 Section 9.3.2.1)


class DICOMApplicationContext(Packet):
    """
    Application Context Item.

    Per PS3.8 Section 9.3.2.1 Table 9-12:
    Contains the Application-context-name encoded per Annex F.
    """

    name = "DICOM Application Context"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes(APP_CONTEXT_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        uid_str = self.uid.decode("ascii", errors="replace").rstrip("\x00")
        return f"AppContext {uid_str}"



# Abstract Syntax Sub-Item (PS3.8 Section 9.3.2.2.1)


class DICOMAbstractSyntax(Packet):
    """
    Abstract Syntax Sub-Item.

    Per PS3.8 Section 9.3.2.2.1 Table 9-14:
    Contains the Abstract-syntax-name (SOP Class UID) encoded per Annex F.
    """

    name = "DICOM Abstract Syntax"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        uid_str = self.uid.decode("ascii", errors="replace").rstrip("\x00")
        return f"AbstractSyntax {uid_str}"



# Transfer Syntax Sub-Item (PS3.8 Section 9.3.2.2.2)


class DICOMTransferSyntax(Packet):
    """
    Transfer Syntax Sub-Item.

    Per PS3.8 Section 9.3.2.2.2 Table 9-15:
    Contains the Transfer-syntax-name encoded per Annex F.
    """

    name = "DICOM Transfer Syntax"
    fields_desc = [
        StrLenField(
            "uid", _uid_to_bytes(DEFAULT_TRANSFER_SYNTAX_UID),
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        uid_str = self.uid.decode("ascii", errors="replace").rstrip("\x00")
        return f"TransferSyntax {uid_str}"



# Presentation Context Item - Request (PS3.8 Section 9.3.2.2)


class DICOMPresentationContextRQ(Packet):
    """
    Presentation Context Item for A-ASSOCIATE-RQ.

    Per PS3.8 Section 9.3.2.2 Table 9-13:
    Contains one Abstract Syntax and one or more Transfer Syntaxes.
    Presentation Context IDs shall be odd integers between 1 and 255.
    """

    name = "DICOM Presentation Context RQ"
    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=64,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else 0
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        return f"PresentationContext-RQ ctx_id={self.context_id}"



# Presentation Context Item - Accept (PS3.8 Section 9.3.3.2)


class DICOMPresentationContextAC(Packet):
    """
    Presentation Context Item for A-ASSOCIATE-AC.

    Per PS3.8 Section 9.3.3.2 Table 9-18:
    Contains the result of presentation context negotiation and
    the accepted Transfer Syntax (if accepted).
    """

    name = "DICOM Presentation Context AC"

    RESULT_CODES = {
        0: "acceptance",
        1: "user-rejection",
        2: "no-reason (provider rejection)",
        3: "abstract-syntax-not-supported (provider rejection)",
        4: "transfer-syntaxes-not-supported (provider rejection)",
    }

    fields_desc = [
        ByteField("context_id", 1),
        ByteField("reserved1", 0),
        ByteEnumField("result", 0, RESULT_CODES),
        ByteField("reserved2", 0),
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=8,
            length_from=lambda pkt: (
                pkt.underlayer.length - 4
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else 0
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        return self.sprintf(
            "PresentationContext-AC ctx_id=%context_id% result=%result%"
        )



# Maximum Length Sub-Item (PS3.8 Annex D.1)


class DICOMMaximumLength(Packet):
    """
    Maximum Length Sub-Item.

    Per PS3.8 Annex D.1 Tables D.1-1 and D.1-2:
    Allows negotiation of maximum P-DATA-TF PDU size.
    Value of 0 indicates no maximum length specified.

    This is the ONLY User Information sub-item defined in PS3.8.
    Items 0x52-0x59 are defined in PS3.7 Annex D.3.3.
    """

    name = "DICOM Maximum Length"
    fields_desc = [
        IntField("max_pdu_length", 16384),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        if self.max_pdu_length == 0:
            return "MaxLength (unlimited)"
        return f"MaxLength {self.max_pdu_length}"



# Implementation Class UID Sub-Item (PS3.7 D.3.3.2)


class DICOMImplementationClassUID(Packet):
    """
    Implementation Class UID Sub-Item.

    Per PS3.7 D.3.3.2 Tables D.3-1 and D.3-2:
    Identifies the implementation class. Required in A-ASSOCIATE-RQ and AC.
    """

    name = "DICOM Implementation Class UID"
    fields_desc = [
        StrLenField(
            "uid", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else len(pkt.uid)
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        uid_str = self.uid.decode("ascii", errors="replace").rstrip("\x00")
        return f"ImplClassUID {uid_str}"



# Implementation Version Name Sub-Item (PS3.7 D.3.3.2)


class DICOMImplementationVersionName(Packet):
    """
    Implementation Version Name Sub-Item.

    Per PS3.7 D.3.3.2 Tables D.3-3 and D.3-4:
    Optional identification of implementation version (1-16 characters).
    """

    name = "DICOM Implementation Version Name"
    fields_desc = [
        StrLenField(
            "name", b"",
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else len(pkt.name)
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        name_str = self.name.decode("ascii", errors="replace").rstrip("\x00")
        return f"ImplVersion {name_str}"



# Asynchronous Operations Window Sub-Item (PS3.7 D.3.3.3)


class DICOMAsyncOperationsWindow(Packet):
    """
    Asynchronous Operations Window Sub-Item.

    Per PS3.7 D.3.3.3 Tables D.3-7 and D.3-8:
    Allows negotiation of asynchronous operations on the association.
    Value of 0 means unlimited. Default (absence) means 1,1 (synchronous).
    """

    name = "DICOM Async Operations Window"
    fields_desc = [
        ShortField("max_ops_invoked", 1),
        ShortField("max_ops_performed", 1),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        return f"AsyncOps inv={self.max_ops_invoked} perf={self.max_ops_performed}"



# SCP/SCU Role Selection Sub-Item (PS3.7 D.3.3.4)


class DICOMSCPSCURoleSelection(Packet):
    """
    SCP/SCU Role Selection Sub-Item.

    Per PS3.7 D.3.3.4 Tables D.3-9 and D.3-10:
    Allows negotiation of SCP and SCU roles for a SOP Class.
    """

    name = "DICOM SCP/SCU Role Selection"
    fields_desc = [
        FieldLenField("uid_length", None, length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.uid_length),
        ByteField("scu_role", 0),  # 0=non-support, 1=support
        ByteField("scp_role", 0),  # 0=non-support, 1=support
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        return f"RoleSelection SCU={self.scu_role} SCP={self.scp_role}"



# SOP Class Extended Negotiation Sub-Item (PS3.7 D.3.3.5)


class DICOMSOPClassExtendedNegotiation(Packet):
    """
    SOP Class Extended Negotiation Sub-Item.

    Per PS3.7 D.3.3.5 Table D.3-11:
    Allows application-specific negotiation for a SOP Class.
    """

    name = "DICOM SOP Class Extended Negotiation"
    fields_desc = [
        FieldLenField("sop_class_uid_length", None,
                      length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.sop_class_uid_length),
        StrLenField("service_class_application_information", b"",
                    length_from=lambda pkt: (
                        pkt.underlayer.length - 2 - pkt.sop_class_uid_length
                        if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                        else 0
                    )),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        uid_str = self.sop_class_uid.decode("ascii", errors="replace").rstrip("\x00")
        return f"SOPClassExtNeg {uid_str}"



# SOP Class Common Extended Negotiation Sub-Item (PS3.7 D.3.3.6)


class DICOMSOPClassCommonExtendedNegotiation(Packet):
    """
    SOP Class Common Extended Negotiation Sub-Item.

    Per PS3.7 D.3.3.6 Table D.3-12:
    Allows service class-level negotiation. Only in A-ASSOCIATE-RQ.

    Note: For this item type (0x57), byte 2 of the header is Sub-Item-version
    (not reserved). The version defined in PS3.7 2025e is 0.
    """

    name = "DICOM SOP Class Common Extended Negotiation"
    fields_desc = [
        FieldLenField("sop_class_uid_length", None,
                      length_of="sop_class_uid", fmt="!H"),
        StrLenField("sop_class_uid", b"",
                    length_from=lambda pkt: pkt.sop_class_uid_length),
        FieldLenField("service_class_uid_length", None,
                      length_of="service_class_uid", fmt="!H"),
        StrLenField("service_class_uid", b"",
                    length_from=lambda pkt: pkt.service_class_uid_length),
        FieldLenField("related_sop_class_uid_length", None,
                      length_of="related_sop_class_uids", fmt="!H"),
        StrLenField("related_sop_class_uids", b"",
                    length_from=lambda pkt: pkt.related_sop_class_uid_length),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        uid_str = self.sop_class_uid.decode("ascii", errors="replace").rstrip("\x00")
        return f"SOPClassCommonExtNeg {uid_str}"



# User Identity Sub-Item (PS3.7 D.3.3.7)


USER_IDENTITY_TYPES = {
    1: "Username",
    2: "Username and Passcode",
    3: "Kerberos Service Ticket",
    4: "SAML Assertion",
    5: "JSON Web Token (JWT)",
}


class DICOMUserIdentity(Packet):
    """
    User Identity Sub-Item (A-ASSOCIATE-RQ).

    Per PS3.7 D.3.3.7 Table D.3-14:
    Allows user identity negotiation during association.
    """

    name = "DICOM User Identity"
    fields_desc = [
        ByteEnumField("user_identity_type", 1, USER_IDENTITY_TYPES),
        ByteField("positive_response_requested", 0),
        FieldLenField("primary_field_length", None,
                      length_of="primary_field", fmt="!H"),
        StrLenField("primary_field", b"",
                    length_from=lambda pkt: pkt.primary_field_length),
        # Secondary-Field-Length is Type 1 in Table D.3-14: it is always on the
        # wire and carries 0 when there is no passcode. Only the Secondary-Field
        # *content* is specific to identity type 2 (username + passcode).
        # Omitting the length for types 1/3/4/5 produces a sub-item a conformant
        # peer rejects on framing, so the identity handler is never reached.
        FieldLenField("secondary_field_length", None,
                      length_of="secondary_field", fmt="!H"),
        StrLenField("secondary_field", b"",
                    length_from=lambda pkt: pkt.secondary_field_length or 0),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        return self.sprintf("UserIdentity %user_identity_type%")



# User Identity Server Response Sub-Item (PS3.7 D.3.3.7)


class DICOMUserIdentityResponse(Packet):
    """
    User Identity Server Response Sub-Item (A-ASSOCIATE-AC).

    Per PS3.7 D.3.3.7 Table D.3-15:
    Server response to user identity negotiation.
    """

    name = "DICOM User Identity Response"
    fields_desc = [
        FieldLenField("response_length", None,
                      length_of="server_response", fmt="!H"),
        StrLenField("server_response", b"",
                    length_from=lambda pkt: pkt.response_length),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        return "UserIdentityResponse"



# User Information Item (PS3.8 Section 9.3.2.3)


class DICOMUserInformation(Packet):
    """
    User Information Item.

    Per PS3.8 Section 9.3.2.3 Table 9-16:
    Contains User-data sub-items. The structure of these sub-items
    is defined in PS3.8 Annex D (Maximum Length) and PS3.7 D.3.3.

    Note: "User-Data Sub-Items may be present in any order within the
    User-Information Item. No significance should be placed on the order."
    """

    name = "DICOM User Information"
    fields_desc = [
        PacketListField(
            "sub_items", [],
            DICOMVariableItem,
            max_count=32,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else 0
            )
        ),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        return f"UserInfo ({len(self.sub_items)} items)"



# Layer Bindings for Variable Items


bind_layers(DICOMVariableItem, DICOMApplicationContext, item_type=0x10)
bind_layers(DICOMVariableItem, DICOMPresentationContextRQ, item_type=0x20)
bind_layers(DICOMVariableItem, DICOMPresentationContextAC, item_type=0x21)
bind_layers(DICOMVariableItem, DICOMAbstractSyntax, item_type=0x30)
bind_layers(DICOMVariableItem, DICOMTransferSyntax, item_type=0x40)
bind_layers(DICOMVariableItem, DICOMUserInformation, item_type=0x50)
bind_layers(DICOMVariableItem, DICOMMaximumLength, item_type=0x51)
bind_layers(DICOMVariableItem, DICOMImplementationClassUID, item_type=0x52)
bind_layers(DICOMVariableItem, DICOMAsyncOperationsWindow, item_type=0x53)
bind_layers(DICOMVariableItem, DICOMSCPSCURoleSelection, item_type=0x54)
bind_layers(DICOMVariableItem, DICOMImplementationVersionName, item_type=0x55)
bind_layers(DICOMVariableItem, DICOMSOPClassExtendedNegotiation, item_type=0x56)
bind_layers(DICOMVariableItem, DICOMSOPClassCommonExtendedNegotiation, item_type=0x57)
bind_layers(DICOMVariableItem, DICOMUserIdentity, item_type=0x58)
bind_layers(DICOMVariableItem, DICOMUserIdentityResponse, item_type=0x59)
bind_layers(DICOMVariableItem, DICOMGenericItem)



# -------------------------------------------------------------------------
# Variable-item traversal helpers
#
# A-ASSOCIATE-RQ/AC PDUs carry their negotiated parameters as nested
# ``variable_items`` -> (User Information) ``sub_items``. Reading them is the
# same walk every time: filter by item_type, guard the bound layer, decode the
# null-padded UID. These helpers centralise that idiom so the many
# ``_parse_*`` (DICOMSession) and ``parse_*`` (c_scare.responders) readers stay
# thin instead of re-implementing the loop.
# -------------------------------------------------------------------------

def decode_uid(value):
    # type: (Any) -> str
    """Decode a DICOM UID/text field to ``str``, stripping the trailing null
    DICOM uses to pad odd-length values even. Bytes decode as ASCII with
    replacement so malformed peer data never raises."""
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("ascii", "replace")
    return str(value)


def iter_variable_items(container, item_type):
    # type: (Packet, int) -> Generator[Packet, None, None]
    """Yield the ``variable_items`` of ``container`` (an A-ASSOCIATE-RQ/AC
    layer) whose ``item_type`` matches."""
    try:
        items = container.variable_items
    except AttributeError:
        return
    for item in items:
        if item.item_type == item_type:
            yield item


def iter_user_info_subitems(container, sub_type, layer=None):
    # type: (Packet, int, Any) -> Generator[Packet, None, None]
    """Yield the User Information (item_type 0x50) sub-items of ``container``
    whose ``item_type`` matches ``sub_type`` and which carry ``layer`` (when
    given). Encapsulates the two-level variable_items -> sub_items walk shared
    by every User-Information reader."""
    for item in iter_variable_items(container, 0x50):
        if not item.haslayer(DICOMUserInformation):
            continue
        for sub in item[DICOMUserInformation].sub_items:
            if sub.item_type == sub_type and (layer is None or sub.haslayer(layer)):
                yield sub



# DICOM Upper Layer PDU Header (PS3.8 Section 9.3.1)


class DICOM(Packet):
    """
    DICOM Upper Layer PDU Header.

    Per PS3.8 Section 9.3.1:
    All PDUs share this common 6-byte header structure:
    - PDU-type (1 byte)
    - Reserved (1 byte, shall be 0x00)
    - PDU-length (4 bytes, unsigned, big-endian)

    The PDU-length is the number of bytes from the first byte of the
    following field to the last byte of the variable field.
    """

    name = "DICOM UL"
    fields_desc = [
        ByteEnumField("pdu_type", 0x01, PDU_TYPES),
        ByteField("reserved1", 0),
        LenField("length", None, fmt="!I"),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        if self.length is not None:
            return s[:self.length], s[self.length:]
        return s, b""

    def mysummary(self):
        # type: () -> str
        return self.sprintf("DICOM %pdu_type%")



# Presentation Data Value Item (PS3.8 Section 9.3.5.1)


class PresentationDataValueItem(Packet):
    """
    Presentation Data Value (PDV) Item within P-DATA-TF PDU.

    Per PS3.8 Section 9.3.5.1 Table 9-23:
    - Item-length (4 bytes): includes context_id and message control header
    - Presentation-context-ID (1 byte): odd integer 1-255
    - Presentation-data-value: includes Message Control Header (Annex E.2)

    Message Control Header (first byte of data per PS3.8 Annex E.2):
    - Bit 0: 1=Command, 0=Data
    - Bit 1: 1=Last fragment, 0=Not last fragment
    - Bits 2-7: Reserved (always 0)
    """

    name = "PresentationDataValueItem"
    fields_desc = [
        FieldLenField("length", None, length_of="data", fmt="!I",
                      adjust=lambda pkt, x: x + 2),
        ByteField("context_id", 1),
        # Message Control Header per PS3.8 Annex E.2
        BitField("reserved_bits", 0, 6),  # Bits 7-2: reserved
        BitField("is_last", 0, 1),        # Bit 1: last fragment flag
        BitField("is_command", 0, 1),     # Bit 0: command/data flag
        StrLenField("data", b"",
                    length_from=lambda pkt: max(0, (pkt.length or 2) - 2)),
    ]

    def extract_padding(self, s):
        # type: (bytes) -> Tuple[bytes, bytes]
        return b"", s

    def mysummary(self):
        # type: () -> str
        frag_type = "CMD" if self.is_command else "DATA"
        last = " LAST" if self.is_last else ""
        return f"PDV ctx={self.context_id} {frag_type}{last} len={len(self.data)}"



# A-ASSOCIATE-RQ PDU (PS3.8 Section 9.3.2)


class A_ASSOCIATE_RQ(Packet):
    """
    A-ASSOCIATE-RQ PDU for initiating DICOM associations.

    Per PS3.8 Section 9.3.2 Table 9-11:
    Used by the association-requestor to propose an association.
    """

    name = "A-ASSOCIATE-RQ"
    fields_desc = [
        ShortField("protocol_version", 1),  # Bit 0 set for version 1
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),
        DICOMAETitleField("calling_ae_title", b""),
        StrFixedLenField("reserved2", b"\x00" * 32, 32),
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else 0
            )
        ),
    ]

    def mysummary(self):
        # type: () -> str
        called = self.called_ae_title
        if isinstance(called, bytes):
            called = called.decode("ascii", errors="replace").strip()
        calling = self.calling_ae_title
        if isinstance(calling, bytes):
            calling = calling.decode("ascii", errors="replace").strip()
        return f"A-ASSOCIATE-RQ {calling} -> {called}"

    def hashret(self):
        # type: () -> bytes
        return self.called_ae_title + self.calling_ae_title



# A-ASSOCIATE-AC PDU (PS3.8 Section 9.3.3)


class A_ASSOCIATE_AC(Packet):
    """
    A-ASSOCIATE-AC PDU for accepting DICOM associations.

    Per PS3.8 Section 9.3.3 Table 9-17:
    Used by the association-acceptor to accept an association.
    Reserved fields shall contain the same values as received in the RQ.
    """

    name = "A-ASSOCIATE-AC"
    fields_desc = [
        ShortField("protocol_version", 1),
        ShortField("reserved1", 0),
        DICOMAETitleField("called_ae_title", b""),   # Echo from RQ
        DICOMAETitleField("calling_ae_title", b""),  # Echo from RQ
        StrFixedLenField("reserved2", b"\x00" * 32, 32),  # Echo from RQ
        PacketListField(
            "variable_items", [],
            DICOMVariableItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length - 68
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else 0
            )
        ),
    ]

    def mysummary(self):
        # type: () -> str
        called = self.called_ae_title
        if isinstance(called, bytes):
            called = called.decode("ascii", errors="replace").strip()
        calling = self.calling_ae_title
        if isinstance(calling, bytes):
            calling = calling.decode("ascii", errors="replace").strip()
        return f"A-ASSOCIATE-AC {calling} <- {called}"

    def hashret(self):
        # type: () -> bytes
        return self.called_ae_title + self.calling_ae_title

    def answers(self, other):
        # type: (Packet) -> bool
        return isinstance(other, A_ASSOCIATE_RQ)



# A-ASSOCIATE-RJ PDU (PS3.8 Section 9.3.4)


class A_ASSOCIATE_RJ(Packet):
    """
    A-ASSOCIATE-RJ PDU for rejecting DICOM associations.

    Per PS3.8 Section 9.3.4 Table 9-21:
    Used to reject an association request.
    """

    name = "A-ASSOCIATE-RJ"

    RESULT_CODES = {
        1: "rejected-permanent",
        2: "rejected-transient",
    }

    SOURCE_CODES = {
        1: "DICOM UL service-user",
        2: "DICOM UL service-provider (ACSE related function)",
        3: "DICOM UL service-provider (Presentation related function)",
    }

    # Reason/Diagnostic codes depend on Source field value
    REASON_USER = {
        1: "no-reason-given",
        2: "application-context-name-not-supported",
        3: "calling-AE-title-not-recognized",
        7: "called-AE-title-not-recognized",
    }

    REASON_ACSE = {
        1: "no-reason-given",
        2: "protocol-version-not-supported",
    }

    REASON_PRESENTATION = {
        0: "reserved",
        1: "temporary-congestion",
        2: "local-limit-exceeded",
    }

    fields_desc = [
        ByteField("reserved1", 0),
        ByteEnumField("result", 1, RESULT_CODES),
        ByteEnumField("source", 1, SOURCE_CODES),
        ByteField("reason_diag", 1),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("A-ASSOCIATE-RJ %result% %source%")

    def answers(self, other):
        # type: (Packet) -> bool
        return isinstance(other, A_ASSOCIATE_RQ)



# P-DATA-TF PDU (PS3.8 Section 9.3.5)


class P_DATA_TF(Packet):
    """
    P-DATA-TF PDU for transferring DICOM data.

    Per PS3.8 Section 9.3.5 Table 9-22:
    Contains one or more Presentation Data Value Items.
    Used to transfer DICOM Messages (Command and Data Sets).
    """

    name = "P-DATA-TF"
    fields_desc = [
        PacketListField(
            "pdv_items", [],
            PresentationDataValueItem,
            max_count=256,
            length_from=lambda pkt: (
                pkt.underlayer.length
                if pkt.underlayer and hasattr(pkt.underlayer, 'length')
                else 0
            )
        ),
    ]

    def mysummary(self):
        # type: () -> str
        return f"P-DATA-TF ({len(self.pdv_items)} PDVs)"



# A-RELEASE-RQ PDU (PS3.8 Section 9.3.6)


class A_RELEASE_RQ(Packet):
    """
    A-RELEASE-RQ PDU for requesting graceful association release.

    Per PS3.8 Section 9.3.6 Table 9-24:
    Fixed 4-byte reserved field.
    """

    name = "A-RELEASE-RQ"
    fields_desc = [
        IntField("reserved1", 0),
    ]

    def mysummary(self):
        # type: () -> str
        return "A-RELEASE-RQ"



# A-RELEASE-RP PDU (PS3.8 Section 9.3.7)


class A_RELEASE_RP(Packet):
    """
    A-RELEASE-RP PDU for confirming graceful association release.

    Per PS3.8 Section 9.3.7 Table 9-25:
    Fixed 4-byte reserved field.
    """

    name = "A-RELEASE-RP"
    fields_desc = [
        IntField("reserved1", 0),
    ]

    def mysummary(self):
        # type: () -> str
        return "A-RELEASE-RP"

    def answers(self, other):
        # type: (Packet) -> bool
        return isinstance(other, A_RELEASE_RQ)



# A-ABORT PDU (PS3.8 Section 9.3.8)


class A_ABORT(Packet):
    """
    A-ABORT PDU for aborting DICOM associations.

    Per PS3.8 Section 9.3.8 Table 9-26:
    Supports both A-ABORT (user initiated) and A-P-ABORT (provider initiated).
    """

    name = "A-ABORT"

    SOURCE_CODES = {
        0: "DICOM UL service-user (initiated abort)",
        1: "reserved",
        2: "DICOM UL service-provider (initiated abort)",
    }

    # Reason/Diagnostic codes (only meaningful when source=2)
    REASON_PROVIDER = {
        0: "reason-not-specified",
        1: "unrecognized-PDU",
        2: "unexpected-PDU",
        3: "reserved",
        4: "unrecognized-PDU-parameter",
        5: "unexpected-PDU-parameter",
        6: "invalid-PDU-parameter-value",
    }

    fields_desc = [
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteEnumField("source", 0, SOURCE_CODES),
        ByteField("reason_diag", 0),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("A-ABORT %source%")



# TCP Port and PDU Type Bindings (PS3.8 Section 9.1)


bind_layers(TCP, DICOM, dport=DICOM_PORT)
bind_layers(TCP, DICOM, sport=DICOM_PORT)
bind_layers(TCP, DICOM, dport=DICOM_PORT_ALT)
bind_layers(TCP, DICOM, sport=DICOM_PORT_ALT)

bind_layers(DICOM, A_ASSOCIATE_RQ, pdu_type=0x01)
bind_layers(DICOM, A_ASSOCIATE_AC, pdu_type=0x02)
bind_layers(DICOM, A_ASSOCIATE_RJ, pdu_type=0x03)
bind_layers(DICOM, P_DATA_TF, pdu_type=0x04)
bind_layers(DICOM, A_RELEASE_RQ, pdu_type=0x05)
bind_layers(DICOM, A_RELEASE_RP, pdu_type=0x06)
bind_layers(DICOM, A_ABORT, pdu_type=0x07)


# -------------------------------------------------------------------------
# DICOM Upper Layer transport socket (PS3.8 Section 9.1)
#
# The reusable transport primitive of this layer. Everything above is pure
# wire format (declarative Packet classes); this is the one place that frames
# a TCP stream into DICOM PDUs. Higher-level consumers - the SCU client
# (c_scare.client.DICOMSession), the rogue SCP (c_scare.server.RawSCP),
# fuzzers and scanners - all share this instead of re-rolling PDU I/O.
# -------------------------------------------------------------------------

#: Fixed size of the DICOM UL PDU header: PDU-type(1) + reserved(1) + length(4).
PDU_HEADER_LEN = 6


def read_dul_pdu(sock, timeout=None):
    # type: (socket.socket, Optional[float]) -> bytes
    """Read exactly one DICOM Upper Layer PDU from a connected stream socket.

    Frames the stream per PS3.8 Section 9.3.1: read the fixed 6-byte header,
    take the big-endian PDU-length, then read exactly that many body bytes.
    Returns the complete PDU (header + body), or ``b""`` on a clean EOF before
    the header or on timeout. A peer that truncates mid-body yields the partial
    PDU read so far, so callers can still inspect a malformed/short PDU.

    This is the single PDU-boundary primitive shared by :class:`DICOMSocket`
    and ``server.RawSCP`` so neither re-implements framing.
    """
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        header = b""
        while len(header) < PDU_HEADER_LEN:
            chunk = sock.recv(PDU_HEADER_LEN - len(header))
            if not chunk:
                return b""
            header += chunk
        length = struct.unpack("!I", header[2:6])[0]
        body = b""
        while len(body) < length:
            chunk = sock.recv(min(65536, length - len(body)))
            if not chunk:
                break  # peer truncated the PDU; hand back what we have
            body += chunk
        return header + body
    except socket.timeout:
        return b""
    except OSError:
        return b""


class DICOMSocket(StreamSocket):
    """Reusable DICOM Upper Layer transport (PS3.8).

    A thin :class:`~scapy.supersocket.StreamSocket` subclass that frames a
    connected TCP stream into DICOM PDUs. It is the transport *primitive* of
    the layer: it knows about PDU boundaries and the :class:`DICOM` dissector,
    and nothing about association negotiation, presentation contexts, or DIMSE.
    Those concerns live in higher-level consumers (e.g.
    ``c_scare.client.DICOMSession``, fuzzers, scanners), which share this one
    socket rather than re-rolling PDU I/O::

        sock = DICOMSocket.connect("127.0.0.1", 11112)
        sock.send(DICOM() / A_ASSOCIATE_RQ(...))   # send a parsed PDU
        ac = sock.recv()                            # receive a parsed DICOM PDU
        raw = sock.recv_pdu()                       # ... or the raw PDU bytes
        sock.close()

    :meth:`recv` (inherited) returns a parsed ``DICOM`` packet, choosing the
    concrete PDU via the layer bindings above. :meth:`recv_pdu` returns the raw
    PDU bytes (for fuzzing / byte-level inspection). :meth:`send` (inherited)
    accepts a Scapy ``Packet``; :meth:`send_raw` accepts raw ``bytes`` for
    deliberately malformed PDUs.
    """

    desc = "DICOM Upper Layer stream socket"

    def __init__(self, sock, basecls=DICOM):
        # type: (socket.socket, type) -> None
        super(DICOMSocket, self).__init__(sock, basecls=basecls)

    @classmethod
    def connect(cls, host, port=DICOM_PORT, timeout=None, basecls=DICOM):
        # type: (str, int, Optional[float], type) -> DICOMSocket
        """Open a TCP connection to ``host:port`` and wrap it as a DICOMSocket."""
        sock = socket.create_connection((host, port), timeout=timeout)
        return cls(sock, basecls=basecls)

    def recv_pdu(self, timeout=None):
        # type: (Optional[float]) -> bytes
        """Read one whole PDU as raw bytes (header + body), honouring framing.

        Use this for byte-level work (fuzzing, inspection); use :meth:`recv` for
        a parsed packet. Don't mix the two on one socket - :meth:`recv` keeps
        its own peek buffer.
        """
        return read_dul_pdu(self.ins, timeout=timeout)

    def send_raw(self, data):
        # type: (bytes) -> None
        """Send raw bytes verbatim (e.g. a hand-crafted / malformed PDU)."""
        self.outs.sendall(data)



# DIMSE Data Element Fields (PS3.7 Section 9, PS3.5 for encoding)


class DICOMElementField(Field):
    """
    DICOM Data Element field with explicit tag and length encoding.

    Per PS3.5/PS3.7, DIMSE command elements use Implicit VR Little Endian:
    - Tag Group (2 bytes, LE)
    - Tag Element (2 bytes, LE)
    - Value Length (4 bytes, LE)
    - Value (variable)
    """

    __slots__ = ["tag_group", "tag_elem"]

    def __init__(self, name, default, tag_group, tag_elem):
        # type: (str, Any, int, int) -> None
        self.tag_group = tag_group
        self.tag_elem = tag_elem
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, Any) -> bytes
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        hdr = struct.pack("<HHI", self.tag_group, self.tag_elem, len(val))
        return s + hdr + val

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, bytes]
        if len(s) < 8:
            return s, b""
        tag_g, tag_e, length = struct.unpack("<HHI", s[:8])
        if len(s) < 8 + length:
            raise Scapy_Exception(
                f"Not enough bytes for DICOM element: expected {length}, "
                f"got {len(s) - 8}"
            )
        value = s[8:8 + length]
        return s[8 + length:], value

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], Any) -> str
        if isinstance(val, bytes):
            try:
                return val.decode("ascii").rstrip("\x00")
            except UnicodeDecodeError:
                return val.hex()
        return repr(val)

    def randval(self):
        # type: () -> RandString
        return RandString(8)


class DICOMUIDField(DICOMElementField):
    """DICOM UID element field with automatic even-length padding."""

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, Any) -> bytes
        val = _uid_to_bytes(val) if val else b""
        return DICOMElementField.addfield(self, pkt, s, val)

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], Any) -> str
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").rstrip("\x00")
        return str(val)

    def randval(self):
        # type: () -> str
        from scapy.volatile import RandNum
        return "1.2.3.%d.%d.%d" % (
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix(),
            RandNum(1, 99999)._fix()
        )


class DICOMUSField(DICOMElementField):
    """DICOM Unsigned Short (US) element field."""

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, int) -> bytes
        val_bytes = struct.pack("<H", val)
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, int]
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        if len(val_bytes) >= 2:
            return remain, struct.unpack("<H", val_bytes[:2])[0]
        return remain, 0

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], Any) -> str
        return "0x%04X" % val

    def randval(self):
        # type: () -> RandShort
        return RandShort()


class DICOMULField(DICOMElementField):
    """DICOM Unsigned Long (UL) element field."""

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, int) -> bytes
        val_bytes = struct.pack("<I", val)
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, int]
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        if len(val_bytes) >= 4:
            return remain, struct.unpack("<I", val_bytes[:4])[0]
        return remain, 0

    def randval(self):
        # type: () -> RandInt
        return RandInt()


class DICOMAEDIMSEField(DICOMElementField):
    """DICOM AE element field for DIMSE - 16 bytes, space-padded."""

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, Any) -> bytes
        if val is None:
            val = b""
        if isinstance(val, str):
            val = val.encode("ascii")
        val = val.ljust(16, b" ")[:16]
        return DICOMElementField.addfield(self, pkt, s, val)

    def i2repr(self, pkt, val):
        # type: (Optional[Packet], Any) -> str
        if isinstance(val, bytes):
            return val.decode("ascii", errors="replace").strip()
        return str(val).strip()


class DICOMATField(DICOMElementField):
    """DICOM Attribute Tag (AT) element field for N-GET Attribute Identifier List."""

    # This field holds a list, so set islist=True to fix Scapy packet iteration
    # when the list is empty (empty SetGen yields nothing, breaking do_build)
    islist = True

    def addfield(self, pkt, s, val):
        # type: (Optional[Packet], bytes, Any) -> bytes
        if val is None:
            val = []
        if not isinstance(val, (list, tuple)):
            val = [val]
        # Each tag is 4 bytes (group + element)
        val_bytes = b""
        for tag in val:
            if isinstance(tag, tuple) and len(tag) == 2:
                val_bytes += struct.pack("<HH", tag[0], tag[1])
            elif isinstance(tag, int):
                val_bytes += struct.pack("<HH", (tag >> 16) & 0xFFFF, tag & 0xFFFF)
        return DICOMElementField.addfield(self, pkt, s, val_bytes)

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, list]
        remain, val_bytes = DICOMElementField.getfield(self, pkt, s)
        tags = []
        offset = 0
        while offset + 4 <= len(val_bytes):
            group, elem = struct.unpack("<HH", val_bytes[offset:offset + 4])
            tags.append((group, elem))
            offset += 4
        return remain, tags

    def randval(self):
        # type: () -> list
        # Return empty list as default random value for attribute identifier list
        return []



# DIMSE Base Class (PS3.7 Section 9)


class DIMSEPacket(Packet):
    """
    Base class for DIMSE command packets with automatic group length.

    Per PS3.7, all DIMSE commands include a Command Group Length element
    (0000,0000) as the first element, containing the byte count of the
    remaining command elements.
    """

    GROUP_LENGTH_ELEMENT_SIZE = 12  # Tag (4) + Length (4) + Value (4)

    def post_build(self, pkt, pay):
        # type: (bytes, bytes) -> bytes
        """Prepend Command Group Length element."""
        group_len = len(pkt)
        header = struct.pack("<HHI", 0x0000, 0x0000, 4)  # Tag + VL
        header += struct.pack("<I", group_len)  # Value
        return header + pkt + pay



# DIMSE-C Commands (PS3.7 Section 9.3)


class C_ECHO_RQ(DIMSEPacket):
    """
    C-ECHO-RQ DIMSE Command for verification (PS3.7 Section 9.3.5).

    Per Table 9.3-12.
    """

    name = "C-ECHO-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0030, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-ECHO-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class C_ECHO_RSP(DIMSEPacket):
    """
    C-ECHO-RSP DIMSE Response (PS3.7 Section 9.3.5).

    Per Table 9.3-13.
    """

    name = "C-ECHO-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      VERIFICATION_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8030, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-ECHO-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, C_ECHO_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_STORE_RQ(DIMSEPacket):
    """
    C-STORE-RQ DIMSE Command for storing objects (PS3.7 Section 9.3.1).

    Per Table 9.3-1. Includes optional Move Originator fields.
    """

    name = "C-STORE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0001, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
        # Optional: Move Originator fields (used in C-MOVE sub-operations)
        # Note: Use getfieldval() to avoid recursion in ConditionalField evaluation
        ConditionalField(
            DICOMAEDIMSEField("move_originator_ae_title", b"", 0x0000, 0x1030),
            lambda pkt: pkt.fields.get("move_originator_ae_title") not in (None, b"", b" " * 16)
        ),
        ConditionalField(
            DICOMUSField("move_originator_message_id", 0, 0x0000, 0x1031),
            lambda pkt: pkt.fields.get("move_originator_message_id") not in (None, 0)
        ),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-STORE-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class C_STORE_RSP(DIMSEPacket):
    """
    C-STORE-RSP DIMSE Response (PS3.7 Section 9.3.1).

    Per Table 9.3-2.
    """

    name = "C-STORE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      CT_IMAGE_STORAGE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8001, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid",
                      "1.2.3.4.5.6.7.8.9", 0x0000, 0x1000),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-STORE-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, C_STORE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_FIND_RQ(DIMSEPacket):
    """
    C-FIND-RQ DIMSE Command for querying (PS3.7 Section 9.3.2).

    Per Table 9.3-3.
    """

    name = "C-FIND-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0020, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-FIND-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class C_FIND_RSP(DIMSEPacket):
    """
    C-FIND-RSP DIMSE Response (PS3.7 Section 9.3.2).

    Per Table 9.3-4.
    """

    name = "C-FIND-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8020, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-FIND-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, C_FIND_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_GET_RQ(DIMSEPacket):
    """
    C-GET-RQ DIMSE Command for retrieval (PS3.7 Section 9.3.3).

    Per Table 9.3-6.
    """

    name = "C-GET-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0010, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-GET-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class C_GET_RSP(DIMSEPacket):
    """
    C-GET-RSP DIMSE Response (PS3.7 Section 9.3.3).

    Per Table 9.3-7. Sub-operation counts required when status=Pending.
    """

    name = "C-GET-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_GET_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8010, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-GET-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, C_GET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_MOVE_RQ(DIMSEPacket):
    """
    C-MOVE-RQ DIMSE Command for retrieval (PS3.7 Section 9.3.4).

    Per Table 9.3-9.
    Note: Fields must be in increasing tag order per Section 6.3.1.
    """

    name = "C-MOVE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0021, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMAEDIMSEField("move_destination", b"", 0x0000, 0x0600),
        DICOMUSField("priority", 0x0002, 0x0000, 0x0700),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-MOVE-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class C_MOVE_RSP(DIMSEPacket):
    """
    C-MOVE-RSP DIMSE Response (PS3.7 Section 9.3.4).

    Per Table 9.3-10. Sub-operation counts required when status=Pending.
    """

    name = "C-MOVE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid",
                      PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8021, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUSField("num_remaining", 0, 0x0000, 0x1020),
        DICOMUSField("num_completed", 0, 0x0000, 0x1021),
        DICOMUSField("num_failed", 0, 0x0000, 0x1022),
        DICOMUSField("num_warning", 0, 0x0000, 0x1023),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-MOVE-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, C_MOVE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class C_CANCEL_RQ(DIMSEPacket):
    """
    C-CANCEL-RQ DIMSE Command for canceling operations (PS3.7 Section 9.3.2-9.3.4).

    Per Tables 9.3-5, 9.3-8, 9.3-11.
    Used to cancel pending C-FIND, C-GET, or C-MOVE operations.
    """

    name = "C-CANCEL-RQ"
    fields_desc = [
        DICOMUSField("command_field", 0x0FFF, 0x0000, 0x0100),
        DICOMUSField("message_id_being_responded_to", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("C-CANCEL-RQ canceling=%message_id_being_responded_to%")



# DIMSE-N Commands (PS3.7 Section 10.3)


class N_EVENT_REPORT_RQ(DIMSEPacket):
    """
    N-EVENT-REPORT-RQ DIMSE Notification (PS3.7 Section 10.3.1).

    Per Table 10.3-1.
    """

    name = "N-EVENT-REPORT-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0100, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("event_type_id", 0, 0x0000, 0x1002),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-EVENT-REPORT-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class N_EVENT_REPORT_RSP(DIMSEPacket):
    """
    N-EVENT-REPORT-RSP DIMSE Response (PS3.7 Section 10.3.1).

    Per Table 10.3-2.
    """

    name = "N-EVENT-REPORT-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8100, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("event_type_id", 0, 0x0000, 0x1002),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-EVENT-REPORT-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, N_EVENT_REPORT_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_GET_RQ(DIMSEPacket):
    """
    N-GET-RQ DIMSE Command (PS3.7 Section 10.3.2).

    Per Table 10.3-3.
    """

    name = "N-GET-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0110, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
        DICOMATField("attribute_identifier_list", [], 0x0000, 0x1005),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-GET-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class N_GET_RSP(DIMSEPacket):
    """
    N-GET-RSP DIMSE Response (PS3.7 Section 10.3.2).

    Per Table 10.3-4.
    """

    name = "N-GET-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8110, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-GET-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, N_GET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_SET_RQ(DIMSEPacket):
    """
    N-SET-RQ DIMSE Command (PS3.7 Section 10.3.3).

    Per Table 10.3-5.
    """

    name = "N-SET-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0120, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0000, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-SET-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class N_SET_RSP(DIMSEPacket):
    """
    N-SET-RSP DIMSE Response (PS3.7 Section 10.3.3).

    Per Table 10.3-6.
    """

    name = "N-SET-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8120, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-SET-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, N_SET_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_ACTION_RQ(DIMSEPacket):
    """
    N-ACTION-RQ DIMSE Command (PS3.7 Section 10.3.4).

    Per Table 10.3-7.
    """

    name = "N-ACTION-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0130, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
        DICOMUSField("action_type_id", 0, 0x0000, 0x1008),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-ACTION-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class N_ACTION_RSP(DIMSEPacket):
    """
    N-ACTION-RSP DIMSE Response (PS3.7 Section 10.3.4).

    Per Table 10.3-8.
    """

    name = "N-ACTION-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8130, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
        DICOMUSField("action_type_id", 0, 0x0000, 0x1008),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-ACTION-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, N_ACTION_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_CREATE_RQ(DIMSEPacket):
    """
    N-CREATE-RQ DIMSE Command (PS3.7 Section 10.3.5).

    Per Table 10.3-9.
    """

    name = "N-CREATE-RQ"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x0140, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-CREATE-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class N_CREATE_RSP(DIMSEPacket):
    """
    N-CREATE-RSP DIMSE Response (PS3.7 Section 10.3.5).

    Per Table 10.3-10.
    """

    name = "N-CREATE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8140, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-CREATE-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, N_CREATE_RQ):
            return self.message_id_responded == other.message_id
        return 0


class N_DELETE_RQ(DIMSEPacket):
    """
    N-DELETE-RQ DIMSE Command (PS3.7 Section 10.3.6).

    Per Table 10.3-11.
    """

    name = "N-DELETE-RQ"
    fields_desc = [
        DICOMUIDField("requested_sop_class_uid", "", 0x0000, 0x0003),
        DICOMUSField("command_field", 0x0150, 0x0000, 0x0100),
        DICOMUSField("message_id", 1, 0x0000, 0x0110),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUIDField("requested_sop_instance_uid", "", 0x0000, 0x1001),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-DELETE-RQ msg_id=%message_id%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id)


class N_DELETE_RSP(DIMSEPacket):
    """
    N-DELETE-RSP DIMSE Response (PS3.7 Section 10.3.6).

    Per Table 10.3-12.
    """

    name = "N-DELETE-RSP"
    fields_desc = [
        DICOMUIDField("affected_sop_class_uid", "", 0x0000, 0x0002),
        DICOMUSField("command_field", 0x8150, 0x0000, 0x0100),
        DICOMUSField("message_id_responded", 1, 0x0000, 0x0120),
        DICOMUSField("data_set_type", 0x0101, 0x0000, 0x0800),
        DICOMUSField("status", 0x0000, 0x0000, 0x0900),
        DICOMUIDField("affected_sop_instance_uid", "", 0x0000, 0x1000),
    ]

    def mysummary(self):
        # type: () -> str
        return self.sprintf("N-DELETE-RSP status=%status%")

    def hashret(self):
        # type: () -> bytes
        return struct.pack("<H", self.message_id_responded)

    def answers(self, other):
        # type: (Packet) -> int
        if isinstance(other, N_DELETE_RQ):
            return self.message_id_responded == other.message_id
        return 0


def parse_dimse_status(dimse_bytes):
    # type: (bytes) -> Optional[int]
    """
    Extract status code from DIMSE response bytes.

    Parses the Command Group Length and searches for the Status element
    (0000,0900) within the command data set.

    Status code meanings per PS3.7 Annex C:
    - 0x0000: Success
    - 0xFFxx: Pending
    - 0xFE00: Cancel
    - 0x01xx: Warning
    - 0x0Axx-0x0Cxx: Failure
    """
    return parse_dimse_command_us(dimse_bytes, 0x0000, 0x0900)


def parse_dimse_command_us(dimse_bytes, group, element):
    # type: (bytes, int, int) -> Optional[int]
    """Extract an unsigned-short command element (e.g. Data Set Type 0000,0800,
    or the C-MOVE/C-GET sub-operation counts 0000,1020-1023) from DIMSE command
    bytes. Generalises ``parse_dimse_status`` to any 2-byte command field."""
    try:
        if len(dimse_bytes) < 12:
            return None
        cmd_group_len = struct.unpack("<I", dimse_bytes[8:12])[0]
        offset = 12
        group_end_offset = offset + cmd_group_len
        while offset < group_end_offset and offset + 8 <= len(dimse_bytes):
            tag_group, tag_elem = struct.unpack("<HH", dimse_bytes[offset:offset + 4])
            value_len = struct.unpack("<I", dimse_bytes[offset + 4:offset + 8])[0]
            if tag_group == group and tag_elem == element and value_len == 2:
                if offset + 10 > len(dimse_bytes) or offset + 10 > group_end_offset:
                    break
                return struct.unpack("<H", dimse_bytes[offset + 8:offset + 10])[0]
            offset += 8 + value_len
    except struct.error:
        return None
    return None


def parse_dimse_command_field(dimse_bytes):
    # type: (bytes) -> Optional[int]
    """Return the DIMSE Command Field (0000,0100) — lets a receiver tell a
    C-STORE-RQ sub-operation (0x0001) apart from a C-GET/C-MOVE-RSP (0x8010 /
    0x8021) on the same association."""
    return parse_dimse_command_us(dimse_bytes, 0x0000, 0x0100)


def build_user_identity(identity):
    # type: (Any) -> Packet
    """Coerce a user-identity spec into a ``DICOMUserIdentity`` sub-item.

    Accepts a ready ``DICOMUserIdentity`` packet, or a dict such as
    ``{"type": 2, "primary": b"user", "secondary": b"pass",
    "positive_response_requested": 1}``. ``primary``/``secondary`` may be str
    or bytes; for type 2 (username+passcode) ``secondary`` is the passcode, for
    types 3-5 ``primary`` carries the Kerberos/SAML/JWT token bytes."""
    if isinstance(identity, DICOMUserIdentity):
        return identity

    def _b(v):
        if v is None:
            return b""
        return v if isinstance(v, bytes) else str(v).encode("utf-8")

    id_type = int(identity.get("type", 2))
    primary = _b(identity.get("primary"))
    secondary = _b(identity.get("secondary"))
    positive = int(identity.get("positive_response_requested", 1))
    kwargs = {
        "user_identity_type": id_type,
        "positive_response_requested": positive,
        "primary_field": primary,
    }
    if id_type == 2:
        kwargs["secondary_field"] = secondary
    return DICOMUserIdentity(**kwargs)


def build_presentation_context_rq(context_id, abstract_syntax_uid, transfer_syntax_uids):
    # type: (int, str, List[str]) -> Packet
    """Build a Presentation Context RQ item."""
    abs_uid = _uid_to_bytes(abstract_syntax_uid)
    abs_syn = DICOMVariableItem() / DICOMAbstractSyntax(uid=abs_uid)

    sub_items = [abs_syn]
    for ts_uid in transfer_syntax_uids:
        ts = DICOMVariableItem() / DICOMTransferSyntax(uid=_uid_to_bytes(ts_uid))
        sub_items.append(ts)

    return DICOMVariableItem() / DICOMPresentationContextRQ(
        context_id=context_id,
        sub_items=sub_items,
    )


def build_user_information(max_pdu_length=16384, implementation_class_uid=None,
                           implementation_version=None, user_identity=None,
                           roles=None):
    # type: (int, Optional[str], Optional[Union[str, bytes]], Optional[Any], Optional[Dict[str, Tuple[int, int]]]) -> Packet
    """Build a User Information item.

    ``user_identity`` (a ``DICOMUserIdentity`` packet or a dict, see
    :func:`build_user_identity`) adds a Type 0x58 User Identity Negotiation
    sub-item to the A-ASSOCIATE-RQ.

    ``roles`` maps a SOP Class UID to ``(scu_role, scp_role)`` and adds a Type
    0x54 SCP/SCU Role Selection sub-item per SOP class (PS3.7 D.3.3.4). For a
    C-GET requestor that must receive objects as Storage SCP, propose
    ``{storage_sop_uid: (0, 1)}``. Role items live *inside* this User
    Information item, alongside Max Length (0x51) and User Identity (0x58)."""
    sub_items = [
        DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=max_pdu_length)
    ]

    if implementation_class_uid:
        uid = _uid_to_bytes(implementation_class_uid)
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationClassUID(uid=uid)
        )

    if implementation_version:
        if isinstance(implementation_version, bytes):
            ver_bytes = implementation_version
        else:
            ver_bytes = implementation_version.encode('ascii')
        sub_items.append(
            DICOMVariableItem() / DICOMImplementationVersionName(name=ver_bytes)
        )

    if user_identity is not None:
        sub_items.append(
            DICOMVariableItem() / build_user_identity(user_identity)
        )

    if roles:
        for uid, role_pair in roles.items():
            scu_role, scp_role = role_pair
            sub_items.append(
                DICOMVariableItem() / DICOMSCPSCURoleSelection(
                    sop_class_uid=_uid_to_bytes(uid),
                    scu_role=int(scu_role),
                    scp_role=int(scp_role),
                )
            )

    return DICOMVariableItem() / DICOMUserInformation(sub_items=sub_items)


# =============================================================================
# Raw item builders - byte-level construction that bypasses field validation
# =============================================================================
#
# The Packet classes above are the right tool for well-formed DICOM: scapy
# computes item lengths, PDU lengths and DIMSE group lengths for you. That
# auto-calculation is exactly what a malformation test often needs to defeat -
# a payload whose declared length disagrees with its content cannot be built by
# a layer that keeps the two in sync.
#
# These builders emit the same structures with every length passed through
# verbatim, so a caller can state one thing and send another. Use the Packet
# classes for anything that should be valid, and these only for the field under
# test. They live here rather than in the attack catalog because wire format is
# this module's job.

def raw_ae_title(value: str) -> bytes:
    return value.encode('ascii', 'replace')[:16].ljust(16, b' ')


def raw_item(item_type: int, payload: bytes) -> bytes:
    return bytes([item_type, 0]) + struct.pack('!H', len(payload)) + payload


def raw_presentation_context(abstract_syntax_uid: str,
                                transfer_syntax_uid: str = DEFAULT_TRANSFER_SYNTAX_UID,
                                context_id: int = 1) -> bytes:
    payload = bytes([context_id, 0, 0, 0])
    payload += raw_item(0x30, abstract_syntax_uid.encode('ascii'))
    payload += raw_item(0x40, transfer_syntax_uid.encode('ascii'))
    return raw_item(0x20, payload)


def raw_user_information(payload: Optional[bytes] = None) -> bytes:
    if payload is None:
        payload = raw_item(0x51, struct.pack('!I', 16384))
        payload += raw_item(0x52, IMPLEMENTATION_CLASS_UID.encode('ascii'))
    return raw_item(0x50, payload)


def raw_associate_rq_with_items(called_ae: str,
                             calling_ae: str,
                             variable_items: bytes) -> bytes:
    body = b'\x00\x01\x00\x00'
    body += raw_ae_title(called_ae)
    body += raw_ae_title(calling_ae)
    body += b'\x00' * 32
    body += variable_items
    return b'\x01\x00' + struct.pack('!I', len(body)) + body


def raw_associate_rq(called_ae: str,
                        calling_ae: str,
                        abstract_syntax_uid: str,
                        user_info_payload: Optional[bytes] = None,
                        context_id: int = 1) -> bytes:
    variable_items = raw_item(
        0x10, b'1.2.840.10008.3.1.1.1')
    variable_items += raw_presentation_context(
        abstract_syntax_uid, context_id=context_id)
    variable_items += raw_user_information(user_info_payload)
    return raw_associate_rq_with_items(called_ae, calling_ae, variable_items)


def raw_release_rq() -> bytes:
    return b'\x05\x00\x00\x00\x00\x04\x00\x00\x00\x00'
