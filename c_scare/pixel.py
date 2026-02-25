# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Pixel Data handling with fragment-level control.

Encapsulated pixel data (JPEG, JPEG2000, RLE) uses a fragment structure:
    PixelData (7FE0,0010) OB
    ├── Item (offset table) - may be empty
    ├── Item (fragment 1)
    ├── Item (fragment 2)
    ├── ...
    └── Sequence Delimitation Item

This module provides two complementary APIs:

1. Manual byte-level API (EncapsulatedPixelData, Fragment, PixelData)
   Full control over encoding, good for surgical corruption.

2. Scapy Packet API (DICOMFragment, DICOMBasicOffsetTable, etc.)
   Native Scapy layers with automatic length calculation. Use fuzz()
   to automatically mutate length fields, BOT pointers, and delimiters.

3. Hybrid Fuzzing Pipeline (PixelFuzzer)
   Seed extraction via pydicom + Scapy-based framing + fuzz() mutation.
   Pulls valid JPEG/JPEG2000 frames from real files, wraps them in
   Scapy DICOMFragment layers, then lets fuzz() attack the framing.

Example (manual):
    from c_scare.pixel import EncapsulatedPixelData, PixelData

    epd = EncapsulatedPixelData()
    epd.add_fragment(jpeg_frame_1)
    epd.set_offset_table([0x00, 0x1000, 0x2000])  # Wrong offsets
    raw = epd.encode()

Example (Scapy):
    from c_scare.pixel import (
        DICOMFragment, DICOMBasicOffsetTable,
        DICOMSequenceDelimiter, DICOMEncapsulatedPixelData,
    )
    from scapy.packet import fuzz, raw

    # Build valid encapsulated pixel data
    epd = DICOMEncapsulatedPixelData(fragments=[
        DICOMFragment(data=jpeg_bytes_1),
        DICOMFragment(data=jpeg_bytes_2),
    ])
    valid_bytes = raw(epd)

    # Fuzz it - Scapy auto-mutates length/tag fields
    fuzzed = raw(fuzz(DICOMEncapsulatedPixelData(fragments=[
        DICOMFragment(data=jpeg_bytes_1),
    ])))

Example (hybrid pipeline):
    from c_scare.pixel import PixelFuzzer

    fuzzer = PixelFuzzer()
    fuzzer.add_seed(jpeg_frame_bytes)
    for payload in fuzzer.generate(count=100):
        send_to_target(payload)
"""

import struct
import os
import random
from io import BytesIO
from typing import Callable, Generator, List, Optional, Tuple, Union

# Scapy imports - optional, gracefully degrade
try:
    from scapy.packet import Packet, Raw, fuzz as scapy_fuzz
    from scapy.fields import (
        FieldLenField,
        LEIntField,
        PacketListField,
        StrLenField,
        XLEIntField,
        XLEShortField,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# pydicom imports - optional, for seed extraction
try:
    import pydicom
    from pydicom.encaps import generate_pixel_data_frame
    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False
    try:
        import pydicom
        HAS_PYDICOM = True
    except ImportError:
        pass

__all__ = [
    # Manual API
    'EncapsulatedPixelData',
    'PixelData',
    'Fragment',
    # Scapy Packet API
    'DICOMFragment',
    'DICOMBasicOffsetTable',
    'DICOMSequenceDelimiter',
    'DICOMEncapsulatedPixelData',
    # Hybrid Fuzzer
    'PixelFuzzer',
    # Seed extraction
    'extract_frames',
    'extract_frames_from_file',
    # Corruption helpers
    'corrupt_jpeg_header',
    'corrupt_jpeg_eoi',
    'truncate_fragment',
    'duplicate_bytes',
]


# Item tags (little endian)
ITEM_TAG_LE = b'\xFE\xFF\x00\xE0'
ITEM_TAG_BE = b'\xFF\xFE\xE0\x00'
SEQ_DELIM_TAG_LE = b'\xFE\xFF\xDD\xE0'
SEQ_DELIM_TAG_BE = b'\xFF\xFE\xDD\xE0'


class Fragment:
    """
    Single fragment in encapsulated pixel data.
    
    Allows full control over fragment bytes.
    """
    
    def __init__(self, data: bytes = b'', length_override: int = None):
        self.data = data
        self.length_override = length_override
    
    def encode(self, little_endian: bool = True) -> bytes:
        """Encode as Item."""
        bio = BytesIO()
        
        # Item tag
        bio.write(ITEM_TAG_LE if little_endian else ITEM_TAG_BE)
        
        # Length
        length = self.length_override if self.length_override is not None else len(self.data)
        fmt = '<I' if little_endian else '>I'
        bio.write(struct.pack(fmt, length))
        
        # Data
        bio.write(self.data)
        
        # Pad to even if needed
        if len(self.data) % 2:
            bio.write(b'\x00')
        
        return bio.getvalue()


class EncapsulatedPixelData:
    """
    Encapsulated (compressed) pixel data with fragment-level control.
    
    Structure:
        - Offset table (first item, may be empty)
        - Fragments (one or more items)
        - Sequence delimitation item
    
    Usage:
        epd = EncapsulatedPixelData()
        epd.add_fragment(jpeg_data_1)
        epd.add_fragment(jpeg_data_2)
        
        # Corrupt offset table
        epd.set_offset_table_raw(b'\\x00\\x00\\x00\\x00\\xFF\\xFF\\xFF\\xFF')
        
        # Corrupt fragment
        epd.set_fragment(0, corrupt_jpeg(jpeg_data_1))
        
        # Get bytes
        raw = epd.encode()
    """
    
    def __init__(self, transfer_syntax: str = None):
        self.transfer_syntax = transfer_syntax
        self.offset_table: Optional[bytes] = None  # Raw offset table bytes
        self.offset_table_offsets: Optional[List[int]] = None  # Computed offsets
        self.fragments: List[Fragment] = []
        self.include_delimiter = True

        # Override options
        self._raw_offset_table_length: Optional[int] = None
        
    def add_fragment(self, data: bytes, length_override: int = None) -> 'EncapsulatedPixelData':
        """Add a fragment."""
        self.fragments.append(Fragment(data, length_override))
        return self
    
    def set_fragment(self, index: int, data: bytes, length_override: int = None) -> 'EncapsulatedPixelData':
        """Set fragment data at index."""
        if index < len(self.fragments):
            self.fragments[index] = Fragment(data, length_override)
        return self
    
    def corrupt_fragment(self, index: int, 
                         corruptor: Callable[[bytes], bytes]) -> 'EncapsulatedPixelData':
        """Apply corruption function to fragment."""
        if index < len(self.fragments):
            self.fragments[index].data = corruptor(self.fragments[index].data)
        return self
    
    def set_offset_table(self, offsets: List[int]) -> 'EncapsulatedPixelData':
        """Set offset table from list of offsets."""
        self.offset_table_offsets = offsets
        self.offset_table = None  # Clear raw override
        return self
    
    def set_offset_table_raw(self, data: bytes, 
                             length_override: int = None) -> 'EncapsulatedPixelData':
        """Set raw offset table bytes."""
        self.offset_table = data
        self.offset_table_offsets = None
        self._raw_offset_table_length = length_override
        return self
    
    def clear_offset_table(self) -> 'EncapsulatedPixelData':
        """Set empty offset table."""
        self.offset_table = b''
        self.offset_table_offsets = None
        return self
    
    def compute_offset_table(self) -> 'EncapsulatedPixelData':
        """Compute correct offset table from fragments."""
        offsets = []
        offset = 0
        
        for frag in self.fragments:
            offsets.append(offset)
            # Each fragment: 4 (tag) + 4 (length) + data (padded to even)
            data_len = len(frag.data)
            if data_len % 2:
                data_len += 1
            offset += 8 + data_len
        
        self.offset_table_offsets = offsets
        self.offset_table = None
        return self
    
    def _encode_offset_table(self, little_endian: bool) -> bytes:
        """Encode offset table item."""
        bio = BytesIO()
        
        # Item tag
        bio.write(ITEM_TAG_LE if little_endian else ITEM_TAG_BE)
        
        # Get offset table data
        if self.offset_table is not None:
            # Raw override
            data = self.offset_table
        elif self.offset_table_offsets:
            # Encode offsets
            fmt = '<I' if little_endian else '>I'
            data = b''.join(struct.pack(fmt, o) for o in self.offset_table_offsets)
        else:
            # Empty offset table
            data = b''
        
        # Length
        length = self._raw_offset_table_length if self._raw_offset_table_length is not None else len(data)
        fmt = '<I' if little_endian else '>I'
        bio.write(struct.pack(fmt, length))
        
        # Data
        bio.write(data)
        
        return bio.getvalue()
    
    def encode(self, little_endian: bool = True) -> bytes:
        """Encode complete pixel data value."""
        bio = BytesIO()
        
        # Offset table (first item)
        bio.write(self._encode_offset_table(little_endian))
        
        # Fragments
        for frag in self.fragments:
            bio.write(frag.encode(little_endian))
        
        # Sequence delimitation
        if self.include_delimiter:
            bio.write(SEQ_DELIM_TAG_LE if little_endian else SEQ_DELIM_TAG_BE)
            bio.write(b'\x00\x00\x00\x00')
        
        return bio.getvalue()
    
    @classmethod
    def parse(cls, data: bytes, little_endian: bool = True) -> 'EncapsulatedPixelData':
        """Parse encapsulated pixel data."""
        epd = cls()
        pos = 0
        first_item = True
        
        while pos < len(data) - 8:
            # Read tag
            tag = data[pos:pos+4]
            pos += 4
            
            # Check for sequence delimitation
            if tag == SEQ_DELIM_TAG_LE or tag == SEQ_DELIM_TAG_BE:
                break
            
            # Check for item tag
            if tag != ITEM_TAG_LE and tag != ITEM_TAG_BE:
                break
            
            # Read length
            fmt = '<I' if little_endian else '>I'
            length = struct.unpack(fmt, data[pos:pos+4])[0]
            pos += 4
            
            # Read data
            item_data = data[pos:pos+length]
            pos += length
            
            if first_item:
                # Offset table
                epd.offset_table = item_data
                first_item = False
            else:
                # Fragment
                epd.add_fragment(item_data)
            
            # Skip padding
            if length % 2:
                pos += 1
        
        return epd
    
    @classmethod
    def from_pydicom(cls, elem) -> 'EncapsulatedPixelData':
        """Create from pydicom pixel data element."""
        epd = cls()
        
        if hasattr(elem, 'value') and hasattr(elem.value, '__iter__'):
            for i, fragment in enumerate(elem.value):
                if hasattr(fragment, 'tobytes'):
                    epd.add_fragment(fragment.tobytes())
                elif isinstance(fragment, bytes):
                    epd.add_fragment(fragment)
        
        return epd


class PixelData:
    """
    Native (uncompressed) pixel data with dimension control.
    
    Allows creating pixel data with mismatched dimensions for fuzzing.
    
    Usage:
        pd = PixelData(rows=512, cols=512, bits=16)
        pd.set_data(b'\\x00' * 100)  # Much smaller than expected
        
        # Or with dimension mismatch
        pd = PixelData.dimension_mismatch(
            declared_rows=512,
            declared_cols=512,
            actual_data=b'\\x00' * 100
        )
    """
    
    def __init__(self, rows: int = 256, cols: int = 256, 
                 bits_allocated: int = 16, samples_per_pixel: int = 1,
                 data: bytes = None):
        self.rows = rows
        self.cols = cols
        self.bits_allocated = bits_allocated
        self.samples_per_pixel = samples_per_pixel
        self.data = data
        
    def expected_size(self) -> int:
        """Calculate expected pixel data size."""
        bytes_per_sample = self.bits_allocated // 8
        return self.rows * self.cols * self.samples_per_pixel * bytes_per_sample
    
    def set_data(self, data: bytes) -> 'PixelData':
        """Set raw pixel data."""
        self.data = data
        return self
    
    def generate_data(self, pattern: bytes = b'\x00') -> 'PixelData':
        """Generate pixel data of expected size."""
        size = self.expected_size()
        self.data = (pattern * (size // len(pattern) + 1))[:size]
        return self
    
    def encode(self, little_endian: bool = True) -> bytes:
        """Return pixel data bytes."""
        if self.data:
            return self.data
        return self.generate_data().data
    
    @classmethod
    def dimension_mismatch(cls, declared_rows: int, declared_cols: int,
                           actual_data: bytes, bits: int = 16) -> 'PixelData':
        """Create pixel data with dimension mismatch."""
        pd = cls(rows=declared_rows, cols=declared_cols, bits_allocated=bits)
        pd.data = actual_data
        return pd
    
    @classmethod
    def overflow_dimensions(cls, bits: int = 16) -> 'PixelData':
        """Create pixel data with overflow dimensions."""
        pd = cls(rows=0xFFFF, cols=0xFFFF, bits_allocated=bits)
        pd.data = b'\x00' * 100
        return pd
    
    @classmethod  
    def zero_dimensions(cls, bits: int = 16) -> 'PixelData':
        """Create pixel data with zero dimensions."""
        pd = cls(rows=0, cols=0, bits_allocated=bits)
        pd.data = b'\x00' * 100
        return pd


# =============================================================================
# Corruption Helpers
# =============================================================================

def corrupt_jpeg_header(data: bytes) -> bytes:
    """Corrupt JPEG header (SOI marker)."""
    if len(data) >= 2 and data[:2] == b'\xFF\xD8':
        return b'\xFF\x00' + data[2:]
    return data


def corrupt_jpeg_eoi(data: bytes) -> bytes:
    """Remove JPEG EOI marker."""
    if len(data) >= 2 and data[-2:] == b'\xFF\xD9':
        return data[:-2]
    return data


def truncate_fragment(data: bytes, keep: int) -> bytes:
    """Truncate fragment to specific size."""
    return data[:keep]


def duplicate_bytes(data: bytes, offset: int, count: int) -> bytes:
    """Duplicate bytes at offset."""
    return data[:offset] + data[offset:offset+count] * 2 + data[offset+count:]


# =============================================================================
# Scapy Packet Layers for Encapsulated Pixel Data
# =============================================================================
#
# DICOM encapsulated pixel data (PS3.5 Annex A.4) is structured as:
#
#   Item Tag (FFFE,E000) | Length (4 bytes LE) | Offset Table Data
#   Item Tag (FFFE,E000) | Length (4 bytes LE) | Fragment 1 Data
#   Item Tag (FFFE,E000) | Length (4 bytes LE) | Fragment 2 Data
#   ...
#   Seq Delim Tag (FFFE,E0DD) | Length 0x00000000
#
# Defining these as Scapy Packet classes allows:
#   1. Automatic length calculation via FieldLenField
#   2. Native fuzz() support that attacks length fields, causing
#      integer overflows and buffer overflows in target allocators
#   3. Clean layer stacking with Scapy's / operator
#
# =============================================================================

if HAS_SCAPY:

    class DICOMFragment(Packet):
        """
        DICOM Fragment Item (FFFE,E000) carrying compressed image data.

        The tag field is the DICOM Item tag (0xFFFEE000 little-endian).
        The length field is auto-calculated from the data field.

        When fuzz()'d, Scapy will mutate the length field independently
        of actual data size, triggering buffer over-reads/writes in
        parsers that trust the declared length.
        """
        name = "DICOM Fragment Item"
        fields_desc = [
            XLEShortField("tag_group", 0xFFFE),
            XLEShortField("tag_element", 0xE000),
            FieldLenField("length", None, length_of="data", fmt="<I"),
            StrLenField("data", b"", length_from=lambda pkt: pkt.length),
        ]

        def extract_padding(self, s):
            # If data length is odd, consume one padding byte
            if self.length is not None and self.length % 2:
                return s[1:], s[:1]
            return s, b""

    class DICOMBasicOffsetTable(Packet):
        """
        DICOM Basic Offset Table (BOT) - first Item in encapsulated pixel data.

        Contains a list of 32-bit little-endian offsets (one per frame)
        pointing into the fragment stream. An empty BOT (length=0) is valid.

        When fuzz()'d, the offset pointers get randomized, causing
        parsers to seek to wild addresses in the fragment stream.
        """
        name = "DICOM Basic Offset Table"
        fields_desc = [
            XLEShortField("tag_group", 0xFFFE),
            XLEShortField("tag_element", 0xE000),
            FieldLenField("length", None, length_of="offsets", fmt="<I"),
            StrLenField("offsets", b"", length_from=lambda pkt: pkt.length),
        ]

        def set_offsets(self, offset_list):
            """Set offset table from a list of integers."""
            self.offsets = b"".join(struct.pack("<I", o) for o in offset_list)
            return self

        def get_offsets(self):
            """Parse offset table into list of integers."""
            data = self.offsets if isinstance(self.offsets, bytes) else bytes(self.offsets)
            return [
                struct.unpack("<I", data[i:i + 4])[0]
                for i in range(0, len(data), 4)
                if i + 4 <= len(data)
            ]

    class DICOMSequenceDelimiter(Packet):
        """
        DICOM Sequence Delimitation Item (FFFE,E0DD) with zero length.

        Marks the end of encapsulated pixel data. Dropping or corrupting
        this causes parsers to read past the end of pixel data.
        """
        name = "DICOM Sequence Delimiter"
        fields_desc = [
            XLEShortField("tag_group", 0xFFFE),
            XLEShortField("tag_element", 0xE0DD),
            LEIntField("length", 0),
        ]

    class DICOMEncapsulatedPixelData(Packet):
        """
        Complete encapsulated pixel data structure as a Scapy layer.

        Composes: BOT + Fragment list + Sequence Delimiter.

        Usage:
            # Build valid encapsulated pixel data
            epd = DICOMEncapsulatedPixelData(
                bot=DICOMBasicOffsetTable(),
                fragments=[
                    DICOMFragment(data=jpeg_frame_1),
                    DICOMFragment(data=jpeg_frame_2),
                ],
            )
            valid_bytes = raw(epd)

            # Fuzz the framing (lengths, offsets, delimiter)
            fuzzed = raw(fuzz(DICOMEncapsulatedPixelData(
                bot=fuzz(DICOMBasicOffsetTable()),
                fragments=[fuzz(DICOMFragment(data=jpeg_frame_1))],
            )))

            # Drop the delimiter entirely
            epd = DICOMEncapsulatedPixelData(
                fragments=[DICOMFragment(data=b'\\xff\\xd8...')],
                include_delimiter=False,
            )
        """
        name = "DICOM Encapsulated Pixel Data"
        fields_desc = [
            # We handle sub-packets manually in build/dissect
        ]

        def __init__(self, bot=None, fragments=None, include_delimiter=True, **kwargs):
            super().__init__(**kwargs)
            self._bot = bot or DICOMBasicOffsetTable()
            self._fragments = fragments or []
            self._include_delimiter = include_delimiter

        def do_build(self):
            """Build the complete encapsulated pixel data bytes."""
            from scapy.packet import raw as scapy_raw
            bio = BytesIO()

            # Basic Offset Table
            bio.write(scapy_raw(self._bot))

            # Fragments
            for frag in self._fragments:
                bio.write(scapy_raw(frag))

            # Sequence Delimiter
            if self._include_delimiter:
                bio.write(scapy_raw(DICOMSequenceDelimiter()))

            return bio.getvalue()

        def add_fragment(self, data):
            """Add a fragment (bytes or DICOMFragment)."""
            if isinstance(data, bytes):
                self._fragments.append(DICOMFragment(data=data))
            else:
                self._fragments.append(data)
            return self

        @classmethod
        def from_encapsulated(cls, epd_obj):
            """Create from an EncapsulatedPixelData instance."""
            bot = DICOMBasicOffsetTable()
            if epd_obj.offset_table:
                bot.offsets = epd_obj.offset_table
            elif epd_obj.offset_table_offsets:
                bot.set_offsets(epd_obj.offset_table_offsets)

            fragments = [
                DICOMFragment(data=f.data) for f in epd_obj.fragments
            ]

            return cls(
                bot=bot,
                fragments=fragments,
                include_delimiter=epd_obj.include_delimiter,
            )

else:
    # Stub classes when Scapy is not available
    DICOMFragment = None
    DICOMBasicOffsetTable = None
    DICOMSequenceDelimiter = None
    DICOMEncapsulatedPixelData = None


# =============================================================================
# Seed Extraction - Pull valid compressed frames from real DICOM files
# =============================================================================

def extract_frames(dataset) -> List[bytes]:
    """
    Extract compressed pixel data frames from a pydicom Dataset.

    Uses pydicom's encapsulation handling to pull out individual
    JPEG/JPEG2000/RLE frames as raw byte streams. These serve as
    valid seeds for the fuzzer - real compressed data that will pass
    initial format checks in the target's decoder.

    Args:
        dataset: A pydicom Dataset with encapsulated pixel data.

    Returns:
        List of raw frame byte streams.
    """
    if not HAS_PYDICOM:
        raise ImportError("pydicom required for frame extraction")

    frames = []

    if not hasattr(dataset, 'PixelData'):
        return frames

    try:
        # pydicom >= 2.0 encapsulation API
        from pydicom.encaps import generate_pixel_data_frame
        nr_frames = getattr(dataset, 'NumberOfFrames', 1)
        if isinstance(nr_frames, str):
            nr_frames = int(nr_frames)

        for i in range(nr_frames):
            try:
                frame = generate_pixel_data_frame(
                    dataset.PixelData, i
                )
                frames.append(bytes(frame))
            except Exception:
                break
    except (ImportError, TypeError):
        # Fallback: parse encapsulated data manually
        try:
            from pydicom.encaps import decode_data_sequence
            fragment_list = decode_data_sequence(dataset.PixelData)
            for fragment in fragment_list:
                frames.append(bytes(fragment))
        except Exception:
            # Last resort: parse raw bytes
            raw_value = bytes(dataset.PixelData)
            epd = EncapsulatedPixelData.parse(raw_value)
            for frag in epd.fragments:
                frames.append(frag.data)

    return frames


def extract_frames_from_file(path: str) -> List[bytes]:
    """
    Extract compressed pixel data frames from a DICOM file.

    Args:
        path: Path to a DICOM file with encapsulated pixel data.

    Returns:
        List of raw frame byte streams.
    """
    if not HAS_PYDICOM:
        raise ImportError("pydicom required for frame extraction")

    ds = pydicom.dcmread(path, force=True)
    return extract_frames(ds)


# =============================================================================
# Hybrid Fuzzing Pipeline
# =============================================================================

class PixelFuzzer:
    """
    Hybrid pixel data fuzzer combining pydicom seeds with Scapy framing.

    Pipeline:
        1. Seed:  Pull valid JPEG/JPEG2000 frames from real files (pydicom)
        2. Frame: Wrap frames in Scapy DICOMFragment / BasicOffsetTable layers
        3. Fuzz:  Let Scapy's fuzz() mutate BOT pointers, fragment lengths,
                  or drop the Sequence Delimiter entirely
        4. Yield: Return raw bytes ready to send via DICOMSocket

    This keeps the architecture lean: pydicom harvests valid payload seeds,
    Scapy dynamically generates the vulnerable offset framing around them.

    Usage:
        fuzzer = PixelFuzzer()
        fuzzer.add_seed(jpeg_bytes)
        # or
        fuzzer.add_seeds_from_file('real_ct.dcm')

        for payload in fuzzer.generate(count=100):
            # payload is raw encapsulated pixel data bytes
            send_to_target(payload)
    """

    # Mutation strategies
    STRATEGY_FUZZ_LENGTHS = 'fuzz_lengths'
    STRATEGY_FUZZ_BOT = 'fuzz_bot'
    STRATEGY_DROP_DELIMITER = 'drop_delimiter'
    STRATEGY_CORRUPT_FRAGMENT = 'corrupt_fragment'
    STRATEGY_DUPLICATE_FRAGMENTS = 'duplicate_fragments'
    STRATEGY_EMPTY_FRAGMENTS = 'empty_fragments'
    STRATEGY_OVERFLOW_BOT = 'overflow_bot'

    ALL_STRATEGIES = [
        STRATEGY_FUZZ_LENGTHS,
        STRATEGY_FUZZ_BOT,
        STRATEGY_DROP_DELIMITER,
        STRATEGY_CORRUPT_FRAGMENT,
        STRATEGY_DUPLICATE_FRAGMENTS,
        STRATEGY_EMPTY_FRAGMENTS,
        STRATEGY_OVERFLOW_BOT,
    ]

    def __init__(self, strategies: List[str] = None):
        """
        Args:
            strategies: List of mutation strategies to use.
                        None = use all strategies.
        """
        self._seeds: List[bytes] = []
        self._strategies = strategies or self.ALL_STRATEGIES

    def add_seed(self, frame_data: bytes) -> 'PixelFuzzer':
        """Add a raw compressed frame as a seed."""
        self._seeds.append(frame_data)
        return self

    def add_seeds_from_file(self, path: str) -> 'PixelFuzzer':
        """Extract and add seeds from a DICOM file."""
        frames = extract_frames_from_file(path)
        self._seeds.extend(frames)
        return self

    def add_seeds_from_dataset(self, dataset) -> 'PixelFuzzer':
        """Extract and add seeds from a pydicom Dataset."""
        frames = extract_frames(dataset)
        self._seeds.extend(frames)
        return self

    def _get_seed(self) -> bytes:
        """Get a random seed, or a minimal JPEG stub if no seeds."""
        if self._seeds:
            return random.choice(self._seeds)
        # Minimal valid JPEG: SOI + EOI
        return b'\xFF\xD8\xFF\xD9'

    def generate(self, count: int = 100) -> Generator[bytes, None, None]:
        """
        Generate fuzzed encapsulated pixel data payloads.

        Args:
            count: Number of payloads to generate.

        Yields:
            Raw bytes of fuzzed encapsulated pixel data.
        """
        for _ in range(count):
            strategy = random.choice(self._strategies)
            yield self._apply_strategy(strategy)

    def _apply_strategy(self, strategy: str) -> bytes:
        """Apply a single mutation strategy and return raw bytes."""
        seed = self._get_seed()

        if HAS_SCAPY and DICOMFragment is not None:
            return self._apply_scapy_strategy(strategy, seed)
        else:
            return self._apply_manual_strategy(strategy, seed)

    def _apply_scapy_strategy(self, strategy: str, seed: bytes) -> bytes:
        """Apply strategy using Scapy packet layers."""
        from scapy.packet import raw as scapy_raw

        if strategy == self.STRATEGY_FUZZ_LENGTHS:
            # Fuzz fragment length fields - causes buffer over/under-reads
            epd = DICOMEncapsulatedPixelData(
                bot=DICOMBasicOffsetTable(),
                fragments=[scapy_fuzz(DICOMFragment(data=seed))],
            )
            return scapy_raw(epd)

        elif strategy == self.STRATEGY_FUZZ_BOT:
            # Fuzz BOT offsets - causes wild seeking in fragment stream
            bot = DICOMBasicOffsetTable()
            # Random bogus offsets
            num_offsets = random.randint(1, 20)
            bot.offsets = b"".join(
                struct.pack("<I", random.randint(0, 0xFFFFFFFF))
                for _ in range(num_offsets)
            )
            epd = DICOMEncapsulatedPixelData(
                bot=scapy_fuzz(bot),
                fragments=[DICOMFragment(data=seed)],
            )
            return scapy_raw(epd)

        elif strategy == self.STRATEGY_DROP_DELIMITER:
            # Drop sequence delimiter - parser reads past pixel data
            epd = DICOMEncapsulatedPixelData(
                bot=DICOMBasicOffsetTable(),
                fragments=[DICOMFragment(data=seed)],
                include_delimiter=False,
            )
            return scapy_raw(epd)

        elif strategy == self.STRATEGY_CORRUPT_FRAGMENT:
            # Apply random corruption to the seed data inside the fragment
            corrupted = self._random_corrupt(seed)
            epd = DICOMEncapsulatedPixelData(
                bot=DICOMBasicOffsetTable(),
                fragments=[DICOMFragment(data=corrupted)],
            )
            return scapy_raw(epd)

        elif strategy == self.STRATEGY_DUPLICATE_FRAGMENTS:
            # Blast thousands of fragments to exhaust allocations
            dup_count = random.choice([100, 1000, 5000])
            epd = DICOMEncapsulatedPixelData(
                bot=DICOMBasicOffsetTable(),
                fragments=[DICOMFragment(data=seed)] * dup_count,
            )
            return scapy_raw(epd)

        elif strategy == self.STRATEGY_EMPTY_FRAGMENTS:
            # Mix empty and populated fragments
            frags = []
            for _ in range(random.randint(2, 10)):
                if random.random() < 0.5:
                    frags.append(DICOMFragment(data=b""))
                else:
                    frags.append(DICOMFragment(data=seed))
            epd = DICOMEncapsulatedPixelData(
                bot=DICOMBasicOffsetTable(),
                fragments=frags,
            )
            return scapy_raw(epd)

        elif strategy == self.STRATEGY_OVERFLOW_BOT:
            # BOT with huge declared length but tiny actual data
            bot = DICOMBasicOffsetTable()
            bot.offsets = struct.pack("<I", 0)
            bot.length = 0xFFFFFFFF  # Lie about length
            epd = DICOMEncapsulatedPixelData(
                bot=bot,
                fragments=[DICOMFragment(data=seed)],
            )
            return scapy_raw(epd)

        # Fallback
        epd = DICOMEncapsulatedPixelData(
            bot=DICOMBasicOffsetTable(),
            fragments=[DICOMFragment(data=seed)],
        )
        return scapy_raw(epd)

    def _apply_manual_strategy(self, strategy: str, seed: bytes) -> bytes:
        """Apply strategy using manual byte-level API (no Scapy)."""
        epd = EncapsulatedPixelData()
        epd.add_fragment(seed)

        if strategy == self.STRATEGY_FUZZ_LENGTHS:
            # Lie about fragment length
            epd.fragments[0].length_override = random.randint(0, 0xFFFFFFFF)

        elif strategy == self.STRATEGY_FUZZ_BOT:
            num_offsets = random.randint(1, 20)
            offsets = [random.randint(0, 0xFFFFFFFF) for _ in range(num_offsets)]
            epd.set_offset_table(offsets)

        elif strategy == self.STRATEGY_DROP_DELIMITER:
            epd.include_delimiter = False

        elif strategy == self.STRATEGY_CORRUPT_FRAGMENT:
            epd.corrupt_fragment(0, self._random_corrupt)

        elif strategy == self.STRATEGY_DUPLICATE_FRAGMENTS:
            for _ in range(random.choice([100, 1000])):
                epd.add_fragment(seed)

        elif strategy == self.STRATEGY_EMPTY_FRAGMENTS:
            for _ in range(random.randint(2, 10)):
                if random.random() < 0.5:
                    epd.add_fragment(b"")
                else:
                    epd.add_fragment(seed)

        elif strategy == self.STRATEGY_OVERFLOW_BOT:
            epd.set_offset_table_raw(struct.pack("<I", 0), length_override=0xFFFFFFFF)

        return epd.encode()

    @staticmethod
    def _random_corrupt(data: bytes) -> bytes:
        """Apply random byte-level corruption to data."""
        if not data:
            return data
        ba = bytearray(data)
        mutation = random.choice(['bitflip', 'insert', 'delete', 'overwrite'])

        if mutation == 'bitflip':
            pos = random.randint(0, len(ba) - 1)
            ba[pos] ^= (1 << random.randint(0, 7))
        elif mutation == 'insert':
            pos = random.randint(0, len(ba))
            ba.insert(pos, random.randint(0, 255))
        elif mutation == 'delete' and len(ba) > 1:
            pos = random.randint(0, len(ba) - 1)
            del ba[pos]
        elif mutation == 'overwrite':
            pos = random.randint(0, len(ba) - 1)
            length = min(random.randint(1, 16), len(ba) - pos)
            for i in range(length):
                ba[pos + i] = random.randint(0, 255)

        return bytes(ba)
