# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Corruptor - Surgical modification of DICOM datasets.

Uses pydicom as SOURCE OF TRUTH for understanding DICOM structure,
then uses our encoder for OUTPUT without validation.

Key insight: pydicom is excellent at PARSING (transfer syntaxes, sequences,
private tags, encapsulated pixels) but VALIDATES on encoding.
We use pydicom to understand, our encoder to corrupt.

Example:
    from dicom_hacker.corruptor import Corruptor
    import pydicom
    
    # Load with pydicom (it understands everything)
    ds = pydicom.dcmread("real_scanner.dcm")
    
    # Wrap for corruption
    c = Corruptor(ds)
    
    # Surgical modifications
    c.set_vr(0x00100010, 'XX')           # Change VR only
    c.set_length(0x00100020, 0xFFFFFFFF) # Lie about length
    c.inject_before(0x00100010, b'garbage')
    c.duplicate(0x00100010)
    
    # Encode with our encoder (no validation)
    raw = c.encode()
"""

import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from .element import Element, Dataset, Tag, VR, Sequence, hexdump

__all__ = [
    'Corruptor',
    'Override',
    'Injection',
    'InjectionPoint',
    'SequencePath',
    'corrupt_vr', 'corrupt_length', 'duplicate_tag',
]


class InjectionPoint(Enum):
    """Where to inject bytes."""
    BEFORE_TAG = auto()
    AFTER_TAG = auto()
    REPLACE = auto()


@dataclass
class Override:
    """Override for a single element."""
    vr: Optional[str] = None
    length: Optional[int] = None
    value: Optional[Any] = None
    raw_value: Optional[bytes] = None
    raw_tag: Optional[bytes] = None
    raw_vr: Optional[bytes] = None
    # For undefined length sequences/items
    force_undefined_length: Optional[bool] = None
    force_defined_length: Optional[bool] = None


@dataclass
class Injection:
    """Raw bytes injection."""
    point: InjectionPoint
    tag: int  # Reference tag
    data: bytes


@dataclass
class SequencePath:
    """
    Path into nested sequences for deep corruption.
    
    Example:
        SequencePath((0x0040, 0xA730), 0, (0x0008, 0x0100))
        = ContentSequence, item 0, CodeValue
    """
    sequence_tag: Tuple[int, int]
    item_index: int
    element_tag: Tuple[int, int]
    # For deeper nesting
    nested: Optional['SequencePath'] = None
    
    def to_path_string(self) -> str:
        s = f"({self.sequence_tag[0]:04X},{self.sequence_tag[1]:04X})[{self.item_index}]"
        s += f".({self.element_tag[0]:04X},{self.element_tag[1]:04X})"
        if self.nested:
            s += "." + self.nested.to_path_string()
        return s


class Corruptor:
    """
    Surgical DICOM dataset corruptor with pydicom integration.
    
    Uses pydicom's understanding of DICOM structure (transfer syntax,
    sequences, private tags, pixel data) while allowing any corruption
    via our encoder.
    
    Usage:
        import pydicom
        from dicom_hacker.corruptor import Corruptor
        
        # Load with pydicom - it understands everything
        ds = pydicom.dcmread("real_scanner_output.dcm")
        
        # Wrap for corruption
        c = Corruptor(ds)
        
        # Surgical modifications - keep everything else intact
        c.set_vr(0x00100010, 'XX')           # Invalid VR
        c.set_length(0x00100020, 0xFFFFFFFF) # Lie about length
        c.set_raw_value(0x00100010, b'\\x00' * 1000)  # Buffer overflow attempt
        c.inject_after(0x00100010, b'garbage')        # Extra bytes
        c.duplicate(0x00100010)                       # Duplicate tag
        c.reorder([(0x0010,0x0020), (0x0010,0x0010)]) # Wrong order
        
        # Nested sequence corruption
        c.set_vr_in_sequence(
            (0x0040, 0xA730), 0,  # ContentSequence, item 0
            (0x0008, 0x0100),     # CodeValue
            'XX'
        )
        
        # Encode with our encoder (pydicom would reject these)
        raw = c.encode()
        
        # Or save as complete file
        with open('corrupted.dcm', 'wb') as f:
            f.write(c.to_file())
    """
    
    def __init__(self, source=None):
        """
        Initialize corruptor.
        
        Args:
            source: pydicom.Dataset, file path, bytes, or our Dataset
                    None creates empty corruptor for building from scratch
        """
        self._pydicom_ds = None
        self._our_ds = None
        self._file_meta = None  # pydicom file_meta if available
        
        # Modifications
        self._overrides: Dict[int, Override] = {}  # tag_int -> Override
        self._sequence_overrides: Dict[str, Override] = {}  # path_string -> Override
        self._injections: List[Injection] = []
        self._deletions: Set[int] = set()
        self._duplicates: Dict[int, str] = {}  # tag_int -> 'before'|'after'|'end'
        self._reorder: Optional[List[int]] = None
        self._append_raw: bytes = b''  # Raw bytes to append at end
        
        # Encoding options (auto-detected from source)
        self.transfer_syntax: Optional[str] = None
        self.force_implicit_vr: Optional[bool] = None
        self.force_little_endian: Optional[bool] = None
        
        if source is not None:
            self._load_source(source)
    
    def _load_source(self, source):
        """Load source dataset."""
        # Check if it's pydicom Dataset
        if hasattr(source, 'iterall'):
            self._pydicom_ds = source
            self._extract_pydicom_info()
            return
        
        # Check if it's our Dataset
        if isinstance(source, Dataset):
            self._our_ds = source
            return
        
        # File path
        if isinstance(source, str):
            self._load_file(source)
            return
        
        # Bytes
        if isinstance(source, bytes):
            self._load_bytes(source)
            return
        
        raise ValueError(f"Unknown source type: {type(source)}")
    
    def _load_file(self, path: str):
        """Load from file path."""
        try:
            import pydicom
            self._pydicom_ds = pydicom.dcmread(path, force=True)
            self._extract_pydicom_info()
        except ImportError:
            with open(path, 'rb') as f:
                self._load_bytes(f.read())
    
    def _load_bytes(self, data: bytes):
        """Load from raw bytes using pydicom."""
        import pydicom
        self._pydicom_ds = pydicom.dcmread(BytesIO(data), force=True)
        self._extract_pydicom_info()
    
    def _extract_pydicom_info(self):
        """Extract encoding info from pydicom dataset."""
        if self._pydicom_ds is None:
            return
        
        # File meta
        if hasattr(self._pydicom_ds, 'file_meta'):
            self._file_meta = self._pydicom_ds.file_meta
            ts = getattr(self._file_meta, 'TransferSyntaxUID', None)
            if ts:
                self.transfer_syntax = str(ts)
        
        # Encoding properties
        self.force_little_endian = getattr(self._pydicom_ds, 'is_little_endian', True)
        self.force_implicit_vr = getattr(self._pydicom_ds, 'is_implicit_VR', False)
    
    def _get_override(self, tag: int) -> Override:
        """Get or create override for tag."""
        if tag not in self._overrides:
            self._overrides[tag] = Override()
        return self._overrides[tag]

    def _get_sequence_override(self, path: str) -> Override:
        """Get or create override for a sequence-element path string."""
        if path not in self._sequence_overrides:
            self._sequence_overrides[path] = Override()
        return self._sequence_overrides[path]

    @staticmethod
    def _seq_path(seq_tag, item_index: int, elem_tag) -> str:
        """Build the path string keying a nested sequence element's override."""
        return SequencePath(
            Tag(seq_tag).tuple, item_index, Tag(elem_tag).tuple
        ).to_path_string()
    
    # =========================================================================
    # Top-level Modification API
    # =========================================================================
    
    def set_vr(self, tag, vr: str) -> 'Corruptor':
        """
        Override VR for a tag (can be invalid like 'XX').
        
        Args:
            tag: Tag as int (0x00100010), tuple ((0x0010, 0x0010)), or Tag
            vr: New VR string (2 characters, need not be valid)
        """
        self._get_override(Tag(tag).as_int).vr = vr
        return self
    
    def set_length(self, tag, length: int) -> 'Corruptor':
        """
        Override encoded length (lie about length independently of value).
        
        This is key for fuzzing - value stays the same, but encoded length differs.
        Can trigger buffer overflows in parsers that trust the length field.
        
        Args:
            tag: Target tag
            length: Length to encode (0xFFFFFFFF for undefined)
        """
        self._get_override(Tag(tag).as_int).length = length
        return self
    
    def set_value(self, tag, value: Any) -> 'Corruptor':
        """
        Override value (will be encoded according to VR).
        
        Args:
            tag: Target tag
            value: New value (string, int, bytes, etc.)
        """
        self._get_override(Tag(tag).as_int).value = value
        return self
    
    def set_raw_value(self, tag, raw: bytes) -> 'Corruptor':
        """
        Set raw bytes as value (no encoding/conversion).
        
        Use this for precise byte-level control of value content.
        
        Args:
            tag: Target tag
            raw: Exact bytes to use as value
        """
        self._get_override(Tag(tag).as_int).raw_value = raw
        return self
    
    def set_raw_tag(self, tag, raw: bytes) -> 'Corruptor':
        """
        Override the tag bytes themselves.
        
        Args:
            tag: Target tag (identifies which element)
            raw: 4 bytes to use as tag
        """
        self._get_override(Tag(tag).as_int).raw_tag = raw
        return self
    
    def set_raw_vr(self, tag, raw: bytes) -> 'Corruptor':
        """
        Override VR as raw bytes.
        
        Args:
            tag: Target tag
            raw: 2 bytes to use as VR
        """
        self._get_override(Tag(tag).as_int).raw_vr = raw
        return self
    
    def set_undefined_length(self, tag, undefined: bool = True) -> 'Corruptor':
        """
        Force element to use undefined length encoding.
        
        Args:
            tag: Target tag (typically sequence)
            undefined: True for undefined (0xFFFFFFFF), False for defined
        """
        override = self._get_override(Tag(tag).as_int)
        override.force_undefined_length = undefined
        override.force_defined_length = not undefined
        return self
    
    # =========================================================================
    # Sequence Modification API  
    # =========================================================================
    
    def set_vr_in_sequence(self, seq_tag, item_index: int, elem_tag, vr: str) -> 'Corruptor':
        """
        Override VR for element inside a sequence.
        
        Args:
            seq_tag: Sequence tag
            item_index: Item index (0-based)
            elem_tag: Element tag within the item
            vr: New VR
        """
        self._get_sequence_override(
            self._seq_path(seq_tag, item_index, elem_tag)).vr = vr
        return self
    
    def set_length_in_sequence(self, seq_tag, item_index: int, elem_tag, 
                               length: int) -> 'Corruptor':
        """Override length for element inside a sequence."""
        self._get_sequence_override(
            self._seq_path(seq_tag, item_index, elem_tag)).length = length
        return self
    
    def set_value_in_sequence(self, seq_tag, item_index: int, elem_tag,
                              value: Any) -> 'Corruptor':
        """Override value for element inside a sequence."""
        self._get_sequence_override(
            self._seq_path(seq_tag, item_index, elem_tag)).value = value
        return self
    
    # =========================================================================
    # Structural Modification API
    # =========================================================================
    
    def inject_before(self, tag, data: bytes) -> 'Corruptor':
        """
        Inject raw bytes before a tag.
        
        Args:
            tag: Reference tag
            data: Bytes to inject (can be anything)
        """
        self._injections.append(Injection(
            InjectionPoint.BEFORE_TAG, Tag(tag).as_int, data
        ))
        return self
    
    def inject_after(self, tag, data: bytes) -> 'Corruptor':
        """
        Inject raw bytes after a tag.
        
        Args:
            tag: Reference tag
            data: Bytes to inject
        """
        self._injections.append(Injection(
            InjectionPoint.AFTER_TAG, Tag(tag).as_int, data
        ))
        return self
    
    def replace(self, tag, data: bytes) -> 'Corruptor':
        """
        Replace entire element with raw bytes.
        
        Args:
            tag: Tag to replace
            data: Raw bytes to use instead of encoded element
        """
        self._injections.append(Injection(
            InjectionPoint.REPLACE, Tag(tag).as_int, data
        ))
        return self
    
    def delete(self, tag) -> 'Corruptor':
        """Delete an element."""
        self._deletions.add(Tag(tag).as_int)
        return self
    
    def duplicate(self, tag, position: str = 'end') -> 'Corruptor':
        """
        Duplicate an element (creates invalid DICOM with duplicate tags).
        
        Args:
            tag: Tag to duplicate
            position: 'end' (default), 'before', or 'after' the original
        """
        self._duplicates[Tag(tag).as_int] = position
        return self
    
    def reorder(self, tags: List) -> 'Corruptor':
        """
        Set custom tag order (violates DICOM ascending tag requirement).
        
        Elements not in the list will follow at the end.
        
        Args:
            tags: List of tags in desired order
        """
        self._reorder = [Tag(t).as_int for t in tags]
        return self
    
    def append_raw(self, data: bytes) -> 'Corruptor':
        """Append raw bytes after all elements."""
        self._append_raw += data
        return self
    
    def clear(self) -> 'Corruptor':
        """Clear all modifications."""
        self._overrides.clear()
        self._sequence_overrides.clear()
        self._injections.clear()
        self._deletions.clear()
        self._duplicates.clear()
        self._reorder = None
        self._append_raw = b''
        return self
    
    # =========================================================================
    # Encoding - THE KEY PART
    # =========================================================================
    
    def _encode_pydicom_value(self, elem, little_endian: bool) -> bytes:
        """
        Encode a pydicom element value to bytes.
        
        Handles all the pydicom value types (PersonName, MultiValue, etc.)
        """
        value = elem.value
        vr = elem.VR
        
        # None or empty
        if value is None:
            return b''
        
        # Already bytes
        if isinstance(value, bytes):
            return value
        
        # Sequence - handled separately
        if vr == 'SQ':
            return self._encode_sequence(elem, little_endian)
        
        # Numeric types
        if vr in ('SS', 'US', 'SL', 'UL', 'FL', 'FD', 'SV', 'UV', 'AT'):
            return self._encode_numeric(value, vr, little_endian)
        
        # String types
        if isinstance(value, str):
            return value.encode('ascii', errors='replace')
        
        # PersonName
        if hasattr(value, 'encode'):
            try:
                return value.encode()
            except Exception:
                return str(value).encode('ascii', errors='replace')
        
        # MultiValue
        if hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
            parts = []
            for v in value:
                if isinstance(v, bytes):
                    parts.append(v)
                elif isinstance(v, str):
                    parts.append(v.encode('ascii', errors='replace'))
                elif hasattr(v, 'encode'):
                    parts.append(v.encode())
                else:
                    parts.append(str(v).encode('ascii', errors='replace'))
            return b'\\'.join(parts)
        
        # Fallback
        return str(value).encode('ascii', errors='replace')
    
    def _encode_numeric(self, value, vr: str, little_endian: bool) -> bytes:
        """Encode numeric value(s)."""
        formats = {
            'SS': ('h', 2), 'US': ('H', 2),
            'SL': ('i', 4), 'UL': ('I', 4),
            'FL': ('f', 4), 'FD': ('d', 8),
            'SV': ('q', 8), 'UV': ('Q', 8),
            'AT': ('HH', 4),
        }
        
        if vr not in formats:
            return str(value).encode('ascii')
        
        fmt_char, size = formats[vr]
        endian = '<' if little_endian else '>'
        
        # Handle single value vs multiple
        if hasattr(value, '__iter__') and not isinstance(value, (str, bytes)):
            values = list(value)
        else:
            values = [value]
        
        result = BytesIO()
        for v in values:
            if vr == 'AT':
                # Tag value
                if isinstance(v, tuple):
                    result.write(struct.pack(endian + 'HH', v[0], v[1]))
                else:
                    result.write(struct.pack(endian + 'I', int(v)))
            else:
                result.write(struct.pack(endian + fmt_char, v))
        
        return result.getvalue()
    
    def _encode_sequence(self, elem, little_endian: bool) -> bytes:
        """Encode a sequence element's value."""
        bio = BytesIO()
        
        for item in elem.value:
            # Item tag
            if little_endian:
                bio.write(b'\xFE\xFF\x00\xE0')
            else:
                bio.write(b'\xFF\xFE\xE0\x00')
            
            # Encode item contents
            item_bytes = self._encode_dataset_recursive(item, little_endian)
            
            # For now, use undefined length
            bio.write(b'\xFF\xFF\xFF\xFF')
            bio.write(item_bytes)
            
            # Item delimitation
            if little_endian:
                bio.write(b'\xFE\xFF\x0D\xE0')
            else:
                bio.write(b'\xFF\xFE\xE0\x0D')
            bio.write(b'\x00\x00\x00\x00')
        
        # Sequence delimitation
        if little_endian:
            bio.write(b'\xFE\xFF\xDD\xE0')
        else:
            bio.write(b'\xFF\xFE\xDD\xE0')
        bio.write(b'\x00\x00\x00\x00')
        
        return bio.getvalue()
    
    def _encode_dataset_recursive(self, ds, little_endian: bool) -> bytes:
        """Encode a nested dataset (sequence item)."""
        bio = BytesIO()
        implicit_vr = self.force_implicit_vr or False
        
        for elem in ds:
            tag_int = (elem.tag.group << 16) | elem.tag.element
            bio.write(self._encode_element_from_pydicom(
                tag_int, elem, implicit_vr, little_endian
            ))
        
        return bio.getvalue()
    
    def _encode_element_from_pydicom(self, tag_int: int, elem,
                                      implicit_vr: bool, little_endian: bool,
                                      path_prefix: str = '') -> bytes:
        """
        Encode a single element, applying any overrides.
        
        This is the core encoding function that implements corruption.
        """
        override = self._overrides.get(tag_int, Override())
        
        # Construct path for sequence override lookup
        current_path = path_prefix + f"({elem.tag.group:04X},{elem.tag.element:04X})"
        seq_override = self._sequence_overrides.get(current_path, Override())
        
        # Merge overrides (sequence override takes precedence)
        effective_override = Override(
            vr=seq_override.vr or override.vr,
            length=seq_override.length if seq_override.length is not None else override.length,
            value=seq_override.value if seq_override.value is not None else override.value,
            raw_value=seq_override.raw_value or override.raw_value,
            raw_tag=seq_override.raw_tag or override.raw_tag,
            raw_vr=seq_override.raw_vr or override.raw_vr,
            force_undefined_length=override.force_undefined_length,
            force_defined_length=override.force_defined_length,
        )
        
        bio = BytesIO()
        
        # === TAG ===
        if effective_override.raw_tag:
            bio.write(effective_override.raw_tag[:4])
        else:
            endian = '<' if little_endian else '>'
            bio.write(struct.pack(endian + 'HH', elem.tag.group, elem.tag.element))
        
        # === VR ===
        vr = effective_override.vr or elem.VR
        
        # === VALUE ===
        if effective_override.raw_value is not None:
            val_bytes = effective_override.raw_value
        elif effective_override.value is not None:
            # Encode the override value
            if isinstance(effective_override.value, bytes):
                val_bytes = effective_override.value
            elif isinstance(effective_override.value, str):
                val_bytes = effective_override.value.encode('ascii', errors='replace')
            else:
                val_bytes = str(effective_override.value).encode('ascii', errors='replace')
        else:
            # Encode the original pydicom value
            val_bytes = self._encode_pydicom_value(elem, little_endian)
        
        # Pad to even length
        if len(val_bytes) % 2:
            if vr == 'UI':
                val_bytes += b'\x00'
            elif vr in ('OB', 'OW', 'OF', 'OD', 'UN', 'SQ'):
                val_bytes += b'\x00'
            else:
                val_bytes += b' '
        
        # === LENGTH ===
        if effective_override.length is not None:
            length = effective_override.length
        elif effective_override.force_undefined_length:
            length = 0xFFFFFFFF
        else:
            length = len(val_bytes)
        
        # === ENCODE VR AND LENGTH ===
        if implicit_vr:
            # Implicit VR: just 4-byte length
            endian = '<' if little_endian else '>'
            bio.write(struct.pack(endian + 'I', length))
        else:
            # Explicit VR
            if effective_override.raw_vr:
                bio.write(effective_override.raw_vr[:2])
            else:
                bio.write(vr[:2].encode('ascii', errors='replace'))
            
            # Length encoding depends on VR
            long_vrs = {'OB', 'OD', 'OF', 'OL', 'OV', 'OW', 'SQ', 'UC', 'UN', 'UR', 'UT', 'SV', 'UV'}
            endian = '<' if little_endian else '>'
            
            if vr.upper() in long_vrs or length > 0xFFFF:
                bio.write(b'\x00\x00')  # Reserved
                bio.write(struct.pack(endian + 'I', length))
            else:
                bio.write(struct.pack(endian + 'H', length & 0xFFFF))
        
        # === VALUE BYTES ===
        bio.write(val_bytes)
        
        return bio.getvalue()
    
    def _encode_element_from_ours(self, elem: Element,
                                   implicit_vr: bool, little_endian: bool) -> bytes:
        """Encode one of our Element objects with overrides."""
        override = self._overrides.get(elem.tag.as_int, Override())
        
        # Apply overrides to element
        if override.vr:
            elem = elem.with_vr(override.vr)
        if override.length is not None:
            elem = elem.with_length(override.length)
        if override.value is not None:
            elem = elem.with_value(override.value)
        if override.raw_value is not None:
            elem._raw_value = override.raw_value
        if override.raw_tag:
            elem._raw_tag = override.raw_tag
        if override.raw_vr:
            elem._raw_vr = override.raw_vr
        
        return elem.encode(implicit_vr, little_endian)
    
    def _iter_elements(self):
        """Iterate over source elements, yielding (tag_int, element, is_pydicom)."""
        if self._pydicom_ds:
            for elem in self._pydicom_ds:
                yield (elem.tag.group << 16) | elem.tag.element, elem, True
        elif self._our_ds:
            for elem in self._our_ds:
                yield elem.tag.as_int, elem, False
    
    def encode(self, implicit_vr: bool = None, little_endian: bool = None) -> bytes:
        """
        Encode dataset with all modifications applied.
        
        Args:
            implicit_vr: Use implicit VR (None = auto-detect from source)
            little_endian: Use little endian (None = auto-detect)
        
        Returns:
            Encoded bytes (dataset only, no file meta)
        """
        if implicit_vr is None:
            implicit_vr = self.force_implicit_vr or False
        if little_endian is None:
            little_endian = self.force_little_endian if self.force_little_endian is not None else True
        
        bio = BytesIO()
        
        # Build element list
        elements = list(self._iter_elements())
        
        # Apply custom order
        if self._reorder:
            tag_to_elem = {t: (e, is_p) for t, e, is_p in elements}
            ordered = []
            for tag_int in self._reorder:
                if tag_int in tag_to_elem:
                    elem, is_p = tag_to_elem[tag_int]
                    ordered.append((tag_int, elem, is_p))
            # Add remaining elements not in custom order
            for tag_int, elem, is_p in elements:
                if tag_int not in self._reorder:
                    ordered.append((tag_int, elem, is_p))
            elements = ordered
        
        # Pre-process injections
        before_inj = {}
        after_inj = {}
        replace_inj = {}
        
        for inj in self._injections:
            if inj.point == InjectionPoint.BEFORE_TAG:
                before_inj.setdefault(inj.tag, []).append(inj.data)
            elif inj.point == InjectionPoint.AFTER_TAG:
                after_inj.setdefault(inj.tag, []).append(inj.data)
            elif inj.point == InjectionPoint.REPLACE:
                replace_inj[inj.tag] = inj.data
        
        # Track elements for duplication
        element_cache = {}
        
        # Encode elements
        for tag_int, elem, is_pydicom in elements:
            # Skip deleted
            if tag_int in self._deletions:
                continue
            
            # Cache for duplication
            element_cache[tag_int] = (elem, is_pydicom)
            
            # Duplicate before (if requested)
            if self._duplicates.get(tag_int) == 'before':
                if is_pydicom:
                    bio.write(self._encode_element_from_pydicom(tag_int, elem, implicit_vr, little_endian))
                else:
                    bio.write(self._encode_element_from_ours(elem, implicit_vr, little_endian))
            
            # Inject before
            for data in before_inj.get(tag_int, []):
                bio.write(data)
            
            # Element or replacement
            if tag_int in replace_inj:
                bio.write(replace_inj[tag_int])
            else:
                if is_pydicom:
                    bio.write(self._encode_element_from_pydicom(tag_int, elem, implicit_vr, little_endian))
                else:
                    bio.write(self._encode_element_from_ours(elem, implicit_vr, little_endian))
            
            # Duplicate after (if requested)
            if self._duplicates.get(tag_int) == 'after':
                if is_pydicom:
                    bio.write(self._encode_element_from_pydicom(tag_int, elem, implicit_vr, little_endian))
                else:
                    bio.write(self._encode_element_from_ours(elem, implicit_vr, little_endian))
            
            # Inject after
            for data in after_inj.get(tag_int, []):
                bio.write(data)
        
        # Duplicates at end (default)
        for tag_int, pos in self._duplicates.items():
            if pos == 'end':
                if tag_int in element_cache:
                    elem, is_pydicom = element_cache[tag_int]
                    if is_pydicom:
                        bio.write(self._encode_element_from_pydicom(tag_int, elem, implicit_vr, little_endian))
                    else:
                        bio.write(self._encode_element_from_ours(elem, implicit_vr, little_endian))
        
        # Append raw data
        if self._append_raw:
            bio.write(self._append_raw)
        
        return bio.getvalue()
    
    def to_file(self, include_meta: bool = True, 
                transfer_syntax: str = None) -> bytes:
        """
        Encode as complete DICOM file (Part 10 format).
        
        Args:
            include_meta: Include preamble and file meta header
            transfer_syntax: Transfer syntax UID (None = detect or default)
        
        Returns:
            Complete DICOM file bytes
        """
        from .file import DicomFile
        
        ts = transfer_syntax or self.transfer_syntax or '1.2.840.10008.1.2.1'
        implicit_vr = ts == '1.2.840.10008.1.2'
        
        dataset_bytes = self.encode(implicit_vr=implicit_vr)
        
        if not include_meta:
            return dataset_bytes
        
        # Get SOP Class and Instance UID from source
        sop_class = '1.2.840.10008.5.1.4.1.1.7'  # Secondary Capture default
        sop_instance = '1.2.3.4.5.6.7.8.9'
        
        if self._pydicom_ds:
            sop_class = str(getattr(self._pydicom_ds, 'SOPClassUID', sop_class))
            sop_instance = str(getattr(self._pydicom_ds, 'SOPInstanceUID', sop_instance))
        
        return DicomFile.build(
            dataset_bytes,
            sop_class_uid=sop_class,
            sop_instance_uid=sop_instance,
            transfer_syntax_uid=ts,
        )
    
    # =========================================================================
    # Inspection
    # =========================================================================
    
    def hexdump(self) -> str:
        """Return hexdump of encoded data."""
        return hexdump(self.encode())
    
    def show_modifications(self) -> None:
        """Print all pending modifications."""
        print("=== Corruptor Modifications ===")
        
        if self._overrides:
            print("\nElement Overrides:")
            for tag_int, override in sorted(self._overrides.items()):
                tag = Tag(tag_int)
                parts = []
                if override.vr:
                    parts.append(f"vr='{override.vr}'")
                if override.length is not None:
                    parts.append(f"length=0x{override.length:X}")
                if override.value is not None:
                    parts.append(f"value={repr(override.value)[:30]}")
                if override.raw_value is not None:
                    parts.append(f"raw_value={len(override.raw_value)}b")
                if override.raw_tag:
                    parts.append(f"raw_tag={override.raw_tag.hex()}")
                if override.raw_vr:
                    parts.append(f"raw_vr={override.raw_vr.hex()}")
                if override.force_undefined_length:
                    parts.append("undefined_length")
                print(f"  {tag}: {', '.join(parts)}")
        
        if self._sequence_overrides:
            print("\nSequence Overrides:")
            for path, override in sorted(self._sequence_overrides.items()):
                parts = []
                if override.vr:
                    parts.append(f"vr='{override.vr}'")
                if override.length is not None:
                    parts.append(f"length=0x{override.length:X}")
                print(f"  {path}: {', '.join(parts)}")
        
        if self._injections:
            print("\nInjections:")
            for inj in self._injections:
                print(f"  {inj.point.name} {Tag(inj.tag)}: {len(inj.data)} bytes")
        
        if self._deletions:
            print("\nDeletions:")
            for tag_int in sorted(self._deletions):
                print(f"  {Tag(tag_int)}")
        
        if self._duplicates:
            print("\nDuplicates:")
            for tag_int, pos in self._duplicates.items():
                print(f"  {Tag(tag_int)} ({pos})")
        
        if self._reorder:
            print("\nCustom Order:")
            for i, tag_int in enumerate(self._reorder):
                print(f"  {i+1}. {Tag(tag_int)}")
        
        if self._append_raw:
            print(f"\nAppend Raw: {len(self._append_raw)} bytes")
    
    def show_source(self) -> None:
        """Print source dataset structure."""
        if self._pydicom_ds:
            print("=== Source (pydicom) ===")
            for elem in self._pydicom_ds:
                vr = elem.VR
                val = repr(elem.value)[:50]
                print(f"  ({elem.tag.group:04X},{elem.tag.element:04X}) {vr}: {val}")
        elif self._our_ds:
            print("=== Source (native) ===")
            self._our_ds.show()


# =============================================================================
# Convenience Functions
# =============================================================================

def corrupt_vr(source, tag, vr: str) -> bytes:
    """Quick VR corruption."""
    return Corruptor(source).set_vr(tag, vr).encode()


def corrupt_length(source, tag, length: int) -> bytes:
    """Quick length corruption."""
    return Corruptor(source).set_length(tag, length).encode()


def duplicate_tag(source, tag) -> bytes:
    """Quick tag duplication."""
    return Corruptor(source).duplicate(tag).encode()
