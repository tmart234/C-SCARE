# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Part 10 File handling with corruption support.

DICOM file structure:
    ├── Preamble (128 bytes) - any content
    ├── Prefix "DICM" (4 bytes)
    ├── File Meta Information (Group 0002, always explicit VR LE)
    │   ├── (0002,0000) File Meta Information Group Length
    │   ├── (0002,0001) File Meta Information Version
    │   ├── (0002,0002) Media Storage SOP Class UID
    │   ├── (0002,0003) Media Storage SOP Instance UID
    │   ├── (0002,0010) Transfer Syntax UID
    │   ├── (0002,0012) Implementation Class UID
    │   └── (0002,0013) Implementation Version Name
    └── Dataset (encoding per Transfer Syntax)

Example:
    from dicom_hacker.file import DicomFile
    
    # Build file from dataset
    df = DicomFile()
    df.set_meta(
        sop_class_uid='1.2.840.10008.5.1.4.1.1.2',
        sop_instance_uid='1.2.3.4.5.6.7.8.9',
        transfer_syntax='1.2.840.10008.1.2.1'
    )
    df.dataset = dataset_bytes
    
    # Corrupt preamble
    df.preamble = b'EVIL' * 32
    
    # Lie about transfer syntax
    df.set_meta(transfer_syntax='1.2.840.10008.1.2')  # Implicit
    # But keep dataset as explicit...
    
    raw = df.encode()
"""

import struct
from io import BytesIO
from typing import List, Optional

import pydicom
from pydicom.filewriter import write_file_meta_info
from pydicom.uid import UID

from .element import Element, Dataset, Tag, hexdump

__all__ = [
    'DicomFile',
    'FileMetaInformation',
]


class FileMetaInformation:
    """
    DICOM File Meta Information (Group 0002).
    
    Always encoded as Explicit VR Little Endian.
    """
    
    def __init__(self):
        self.version: bytes = b'\x00\x01'
        self.media_storage_sop_class_uid: str = ''
        self.media_storage_sop_instance_uid: str = ''
        self.transfer_syntax_uid: str = '1.2.840.10008.1.2.1'  # Explicit VR LE
        self.implementation_class_uid: str = '1.2.3.4.5.6.7.8.9'
        self.implementation_version_name: str = 'DICOM_HACKER'
        self.source_ae_title: Optional[str] = None
        
        # Additional elements
        self._extra_elements: List[Element] = []
        
        # Override raw group length
        self._group_length_override: Optional[int] = None
    
    def add_element(self, elem: Element) -> 'FileMetaInformation':
        """Add additional element."""
        self._extra_elements.append(elem)
        return self
    
    def encode(self) -> bytes:
        """Encode File Meta Information."""
        # Build elements (not including group length)
        ds = Dataset()
        
        # (0002,0001) File Meta Information Version
        ds / Element(0x0002, 0x0001, 'OB', self.version)
        
        # (0002,0002) Media Storage SOP Class UID
        ds / Element(0x0002, 0x0002, 'UI', self.media_storage_sop_class_uid)
        
        # (0002,0003) Media Storage SOP Instance UID
        ds / Element(0x0002, 0x0003, 'UI', self.media_storage_sop_instance_uid)
        
        # (0002,0010) Transfer Syntax UID
        ds / Element(0x0002, 0x0010, 'UI', self.transfer_syntax_uid)
        
        # (0002,0012) Implementation Class UID
        ds / Element(0x0002, 0x0012, 'UI', self.implementation_class_uid)
        
        # (0002,0013) Implementation Version Name
        if self.implementation_version_name:
            ds / Element(0x0002, 0x0013, 'SH', self.implementation_version_name)
        
        # (0002,0016) Source Application Entity Title
        if self.source_ae_title:
            ds / Element(0x0002, 0x0016, 'AE', self.source_ae_title)
        
        # Extra elements
        for elem in self._extra_elements:
            ds / elem
        
        # Encode (always Explicit VR Little Endian)
        elements_bytes = ds.encode(implicit_vr=False, little_endian=True, sort_tags=True)
        
        # Group length
        if self._group_length_override is not None:
            length = self._group_length_override
        else:
            length = len(elements_bytes)
        
        group_length = Element(0x0002, 0x0000, 'UL', length)
        
        return group_length.encode(implicit_vr=False) + elements_bytes


class DicomFile:
    """
    DICOM Part 10 File with full corruption support.
    
    Usage:
        df = DicomFile()
        df.preamble = b'\\x00' * 128
        df.set_meta(
            sop_class_uid='1.2.840.10008.5.1.4.1.1.2',
            sop_instance_uid='1.2.3.4.5',
            transfer_syntax='1.2.840.10008.1.2.1'
        )
        df.dataset = dataset_bytes
        
        raw = df.encode()
    """
    
    def __init__(self):
        self.preamble: bytes = b'\x00' * 128
        self.prefix: bytes = b'DICM'
        self.file_meta: FileMetaInformation = FileMetaInformation()
        self.dataset: bytes = b''
        
        # Options
        self.include_preamble: bool = True
        self.include_prefix: bool = True
    
    def set_meta(self, sop_class_uid: str = None, sop_instance_uid: str = None,
                 transfer_syntax: str = None, implementation_uid: str = None,
                 implementation_version: str = None) -> 'DicomFile':
        """Set file meta information fields."""
        if sop_class_uid:
            self.file_meta.media_storage_sop_class_uid = sop_class_uid
        if sop_instance_uid:
            self.file_meta.media_storage_sop_instance_uid = sop_instance_uid
        if transfer_syntax:
            self.file_meta.transfer_syntax_uid = transfer_syntax
        if implementation_uid:
            self.file_meta.implementation_class_uid = implementation_uid
        if implementation_version:
            self.file_meta.implementation_version_name = implementation_version
        return self
    
    def set_dataset(self, data) -> 'DicomFile':
        """
        Set dataset.
        
        Args:
            data: bytes, Dataset, or Corruptor
        """
        if isinstance(data, bytes):
            self.dataset = data
        elif hasattr(data, 'encode') and callable(data.encode):
            ts = UID(self.file_meta.transfer_syntax_uid)
            implicit = ts.is_implicit_VR
            little_endian = ts.is_little_endian
            self.dataset = data.encode(implicit_vr=implicit, little_endian=little_endian)
        else:
            self.dataset = bytes(data)
        return self
    
    def encode(self) -> bytes:
        """Encode complete DICOM file."""
        bio = BytesIO()
        
        # Preamble
        if self.include_preamble:
            bio.write(self.preamble[:128].ljust(128, b'\x00'))
        
        # Prefix
        if self.include_prefix:
            bio.write(self.prefix[:4].ljust(4, b'\x00'))
        
        # File Meta Information
        bio.write(self.file_meta.encode())
        
        # Dataset
        bio.write(self.dataset)
        
        return bio.getvalue()
    
    def __bytes__(self) -> bytes:
        return self.encode()
    
    @classmethod
    def build(cls, dataset_bytes: bytes, sop_class_uid: str, sop_instance_uid: str,
              transfer_syntax_uid: str = None) -> bytes:
        """Quick file builder."""
        df = cls()
        df.set_meta(
            sop_class_uid=sop_class_uid,
            sop_instance_uid=sop_instance_uid,
            transfer_syntax=transfer_syntax_uid or '1.2.840.10008.1.2.1',
        )
        df.dataset = dataset_bytes
        return df.encode()
    
    @classmethod
    def parse(cls, data: bytes, lenient: bool = True) -> 'DicomFile':
        """Parse DICOM file using pydicom."""
        df = cls()

        # Check for preamble/prefix
        if len(data) >= 132 and data[128:132] == b'DICM':
            df.preamble = data[:128]
            df.prefix = data[128:132]
        else:
            df.include_preamble = False
            df.include_prefix = False

        # Use pydicom for the heavy lifting
        try:
            ds = pydicom.dcmread(BytesIO(data), force=True)
            if hasattr(ds, 'file_meta'):
                fm = ds.file_meta
                df.file_meta.media_storage_sop_class_uid = str(getattr(fm, 'MediaStorageSOPClassUID', ''))
                df.file_meta.media_storage_sop_instance_uid = str(getattr(fm, 'MediaStorageSOPInstanceUID', ''))
                df.file_meta.transfer_syntax_uid = str(getattr(fm, 'TransferSyntaxUID', '1.2.840.10008.1.2.1'))

            # Find where dataset body starts (after preamble + prefix + meta)
            meta_end = 132 if df.include_preamble else 0
            if hasattr(ds, 'file_meta') and len(ds.file_meta):
                buf = BytesIO()
                write_file_meta_info(buf, ds.file_meta, enforce_standard=False)
                meta_end += len(buf.getvalue())
            df.dataset = data[meta_end:]
        except Exception:
            if not lenient:
                raise
            df.dataset = data

        return df
    
    def hexdump(self) -> str:
        """Return hexdump of encoded file."""
        return hexdump(self.encode())


# =============================================================================
# Convenience Functions
# =============================================================================

def make_secondary_capture(patient_name: str = 'Test^Patient',
                           patient_id: str = '12345',
                           pixel_data: bytes = None) -> bytes:
    """Create a minimal Secondary Capture DICOM file."""
    from .element import Dataset, Element
    
    ds = Dataset()
    
    # Patient Module
    ds / Element(0x0010, 0x0010, 'PN', patient_name)
    ds / Element(0x0010, 0x0020, 'LO', patient_id)
    
    # Study Module
    ds / Element(0x0020, 0x000D, 'UI', '1.2.3.4.5.6.7.8.9.1')  # Study Instance UID
    ds / Element(0x0008, 0x0020, 'DA', '20240101')  # Study Date
    
    # Series Module
    ds / Element(0x0020, 0x000E, 'UI', '1.2.3.4.5.6.7.8.9.2')  # Series Instance UID
    ds / Element(0x0020, 0x0011, 'IS', '1')  # Series Number
    ds / Element(0x0008, 0x0060, 'CS', 'OT')  # Modality
    
    # SOP Common
    sop_class = '1.2.840.10008.5.1.4.1.1.7'  # Secondary Capture
    sop_instance = '1.2.3.4.5.6.7.8.9.3'
    ds / Element(0x0008, 0x0016, 'UI', sop_class)
    ds / Element(0x0008, 0x0018, 'UI', sop_instance)
    
    # Image Pixel Module (minimal)
    ds / Element(0x0028, 0x0010, 'US', 256)  # Rows
    ds / Element(0x0028, 0x0011, 'US', 256)  # Columns
    ds / Element(0x0028, 0x0100, 'US', 8)    # Bits Allocated
    ds / Element(0x0028, 0x0101, 'US', 8)    # Bits Stored
    ds / Element(0x0028, 0x0102, 'US', 7)    # High Bit
    ds / Element(0x0028, 0x0103, 'US', 0)    # Pixel Representation
    ds / Element(0x0028, 0x0004, 'CS', 'MONOCHROME2')  # Photometric Interpretation
    ds / Element(0x0028, 0x0002, 'US', 1)    # Samples per Pixel
    
    # Pixel Data
    if pixel_data is None:
        pixel_data = b'\x80' * (256 * 256)  # Gray image
    ds / Element(0x7FE0, 0x0010, 'OW', pixel_data)
    
    # Build file
    return DicomFile.build(
        ds.encode(),
        sop_class_uid=sop_class,
        sop_instance_uid=sop_instance,
    )
