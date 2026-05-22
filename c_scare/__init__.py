# SPDX-License-Identifier: GPL-2.0-only
"""
C-Scare: DICOM Security Testing Framework

A comprehensive framework for testing DICOM protocol implementations
using Scapy-based packet crafting and fuzzing.
"""

__version__ = "0.2.0"
__author__ = "Tyler M"

# Import all symbols from scapy_dicom
from .scapy_dicom import (
    # Constants
    DICOM_PORT,
    DICOM_PORT_ALT,
    APP_CONTEXT_UID,
    # Transfer Syntax UIDs (PS3.5 Annex A)
    DEFAULT_TRANSFER_SYNTAX_UID,
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
    # SOP Class UIDs (PS3.4)
    VERIFICATION_SOP_CLASS_UID,
    CT_IMAGE_STORAGE_SOP_CLASS_UID,
    PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
    PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
    PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
    STUDY_ROOT_QR_FIND_SOP_CLASS_UID,
    STUDY_ROOT_QR_MOVE_SOP_CLASS_UID,
    STUDY_ROOT_QR_GET_SOP_CLASS_UID,
    # PDU Classes (PS3.8 Section 9.3)
    DICOM,
    A_ASSOCIATE_RQ,
    A_ASSOCIATE_AC,
    A_ASSOCIATE_RJ,
    P_DATA_TF,
    A_RELEASE_RQ,
    A_RELEASE_RP,
    A_ABORT,
    PresentationDataValueItem,
    # Variable Items (PS3.8 Section 9.3.2)
    DICOMVariableItem,
    DICOMApplicationContext,
    DICOMPresentationContextRQ,
    DICOMPresentationContextAC,
    DICOMAbstractSyntax,
    DICOMTransferSyntax,
    DICOMUserInformation,
    DICOMMaximumLength,
    DICOMGenericItem,
    # Extended User Info Sub-Items (PS3.7 D.3.3)
    DICOMImplementationClassUID,
    DICOMAsyncOperationsWindow,
    DICOMSCPSCURoleSelection,
    DICOMImplementationVersionName,
    DICOMSOPClassExtendedNegotiation,
    DICOMSOPClassCommonExtendedNegotiation,
    DICOMUserIdentity,
    DICOMUserIdentityResponse,
    # DIMSE Field Classes
    DICOMAETitleField,
    DICOMElementField,
    DICOMUIDField,
    DICOMUSField,
    DICOMULField,
    DICOMAEDIMSEField,
    DICOMATField,
    # DIMSE Base Class
    DIMSEPacket,
    # DIMSE-C Commands (PS3.7 Section 9.3)
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
    # DIMSE-N Commands (PS3.7 Section 10.3)
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
    # Utilities
    DICOMSocket,
    parse_dimse_status,
    _uid_to_bytes,
    _uid_to_bytes_raw,
    build_presentation_context_rq,
    build_user_information,
    # DIMSE Status Codes (PS3.7 Annex C)
    STATUS_SUCCESS,
    STATUS_CANCEL,
    STATUS_PENDING,
    STATUS_PENDING_WARNINGS,
    STATUS_WARNING_ATTRIBUTE_LIST,
    STATUS_WARNING_ATTR_OUT_OF_RANGE,
    STATUS_ERR_SOP_CLASS_NOT_SUPPORTED,
    STATUS_ERR_CLASS_INSTANCE_CONFLICT,
    STATUS_ERR_DUPLICATE_SOP_INSTANCE,
    STATUS_ERR_DUPLICATE_INVOCATION,
    STATUS_ERR_INVALID_ARGUMENT,
    STATUS_ERR_INVALID_ATTRIBUTE_VALUE,
    STATUS_ERR_INVALID_SOP_INSTANCE,
    STATUS_ERR_MISSING_ATTRIBUTE,
    STATUS_ERR_MISSING_ATTRIBUTE_VALUE,
    STATUS_ERR_MISTYPED_ARGUMENT,
    STATUS_ERR_NO_SUCH_ARGUMENT,
    STATUS_ERR_NO_SUCH_ATTRIBUTE,
    STATUS_ERR_NO_SUCH_EVENT_TYPE,
    STATUS_ERR_NO_SUCH_SOP_INSTANCE,
    STATUS_ERR_NO_SUCH_SOP_CLASS,
    STATUS_ERR_PROCESSING_FAILURE,
    STATUS_ERR_RESOURCE_LIMITATION,
    STATUS_ERR_UNRECOGNIZED_OPERATION,
    STATUS_ERR_NO_SUCH_ACTION_TYPE,
    STATUS_ERR_NOT_AUTHORIZED,
)

# DICOM dataset & Part-10 file construction
from .element import Tag, VR, Element, Dataset, Sequence, hexdump
from .file import FileMetaInformation, DicomFile, make_secondary_capture

# pydicom-bridged surgical corruption (parse with pydicom, emit invalid bytes)
from .corruptor import (
    Corruptor, InjectionPoint, Override, Injection, SequencePath,
    corrupt_vr, corrupt_length, duplicate_tag,
)

# Encapsulated pixel-data corruption
from .pixel import (
    Fragment, EncapsulatedPixelData, PixelData, PixelFuzzer,
    extract_frames, extract_frames_from_file,
)

# Rogue SCP (SCU / client fuzzing) and raw network delivery
from .server import RawSCP, ConnectionState, Connection
from .deliver import send_pdu, send_sequence, send_cstore

__all__ = [
    # Version
    "__version__",
    "__author__",
    # Constants
    "DICOM_PORT",
    "DICOM_PORT_ALT",
    "APP_CONTEXT_UID",
    # Transfer Syntax UIDs
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
    # SOP Class UIDs
    "VERIFICATION_SOP_CLASS_UID",
    "CT_IMAGE_STORAGE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_FIND_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID",
    "PATIENT_ROOT_QR_GET_SOP_CLASS_UID",
    "STUDY_ROOT_QR_FIND_SOP_CLASS_UID",
    "STUDY_ROOT_QR_MOVE_SOP_CLASS_UID",
    "STUDY_ROOT_QR_GET_SOP_CLASS_UID",
    # PDU Classes
    "DICOM",
    "A_ASSOCIATE_RQ",
    "A_ASSOCIATE_AC",
    "A_ASSOCIATE_RJ",
    "P_DATA_TF",
    "A_RELEASE_RQ",
    "A_RELEASE_RP",
    "A_ABORT",
    "PresentationDataValueItem",
    # Variable Items
    "DICOMVariableItem",
    "DICOMApplicationContext",
    "DICOMPresentationContextRQ",
    "DICOMPresentationContextAC",
    "DICOMAbstractSyntax",
    "DICOMTransferSyntax",
    "DICOMUserInformation",
    "DICOMMaximumLength",
    "DICOMGenericItem",
    # Extended User Info Sub-Items
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
    # DIMSE-C Commands
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
    # DIMSE-N Commands
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
    "DICOMSocket",
    "parse_dimse_status",
    "_uid_to_bytes",
    "_uid_to_bytes_raw",
    "build_presentation_context_rq",
    "build_user_information",
    # Status Codes
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
    # DICOM dataset & file construction
    "Tag", "VR", "Element", "Dataset", "Sequence", "hexdump",
    "FileMetaInformation", "DicomFile", "make_secondary_capture",
    # Surgical corruption
    "Corruptor", "InjectionPoint", "Override", "Injection", "SequencePath",
    "corrupt_vr", "corrupt_length", "duplicate_tag",
    # Pixel data
    "Fragment", "EncapsulatedPixelData", "PixelData", "PixelFuzzer",
    "extract_frames", "extract_frames_from_file",
    # Rogue server & network delivery
    "RawSCP", "ConnectionState", "Connection",
    "send_pdu", "send_sequence", "send_cstore",
    # Monitor framework
    "BaseMonitor",
    "MonitorReport",
    "SanitizerMonitor",
    "ProtocolMonitor",
    "ProcessMonitor",
    "InstrumentedProcess",
]

from .monitor import (
    BaseMonitor,
    MonitorReport,
    SanitizerMonitor,
    ProtocolMonitor,
    ProcessMonitor,
)
from .process_manager import InstrumentedProcess