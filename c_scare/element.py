# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM Element and Dataset - Core building blocks.

Scapy-like API for building DICOM data structures with full byte control.

Example:
    from dicom_hacker.element import Element, Dataset
    
    ds = (Dataset()
        / Element(0x0010, 0x0010, 'PN', 'Doe^John')
        / Element.raw(tag=0x00100020, vr='XX', value=b'fuzz')
    )
"""

import struct
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

__all__ = [
    'Element', 'Dataset', 'Sequence', 'VR', 'Tag',
    'hexdump',
]


# =============================================================================
# Tag Helper
# =============================================================================

class Tag:
    """DICOM Tag helper."""
    
    def __init__(self, group_or_combined, element=None):
        if element is not None:
            self.group = group_or_combined
            self.element = element
        elif isinstance(group_or_combined, tuple):
            self.group, self.element = group_or_combined
        elif isinstance(group_or_combined, int): # Safe (defined before property)
            self.group = (group_or_combined >> 16) & 0xFFFF
            self.element = group_or_combined & 0xFFFF
        elif isinstance(group_or_combined, bytes):
            self.group = struct.unpack('<H', group_or_combined[0:2])[0]
            self.element = struct.unpack('<H', group_or_combined[2:4])[0]
        else:
            raise ValueError(f"Invalid tag: {group_or_combined}")
    
    @property
    def as_int(self) -> int:  # <--- RENAMED from 'int'
        return (self.group << 16) | self.element
    
    @property
    def tuple(self) -> Tuple[int, int]: # Now 'int' correctly refers to the type
        return (self.group, self.element)
    
    def encode(self, little_endian: bool = True) -> bytes:
        fmt = '<HH' if little_endian else '>HH'
        return struct.pack(fmt, self.group, self.element)
    
    def __eq__(self, other):
        if isinstance(other, Tag):
            return self.as_int == other.as_int  # <--- Updated
        elif isinstance(other, tuple):
            return self.tuple == other
        elif isinstance(other, int): # Now works correctly!
            return self.as_int == other         # <--- Updated
        return False
    
    def __hash__(self):
        return hash(self.as_int)  # <--- Updated
    
    def __repr__(self):
        return f'({self.group:04X},{self.element:04X})'
    
    @property
    def keyword(self) -> str:
        """Get DICOM keyword (requires pydicom)."""
        try:
            from pydicom.datadict import keyword_for_tag
            return keyword_for_tag(self.tuple) or ''
        except ImportError:
            return ''

# =============================================================================
# VR Definitions
# =============================================================================

class VR:
    """DICOM Value Representations — kept minimal for the encoder."""

    # VRs that use 4-byte length in explicit VR encoding (PS3.5 Section 7.1.2)
    LONG_LENGTH = {'OB', 'OD', 'OF', 'OL', 'OW', 'SQ', 'UC', 'UN', 'UR', 'UT', 'OV', 'SV', 'UV'}

    @classmethod
    def uses_long_length(cls, vr: str) -> bool:
        return vr.upper() in cls.LONG_LENGTH


# =============================================================================
# Element Class
# =============================================================================

@dataclass
class Element:
    """
    DICOM Data Element with full byte control.
    
    Normal usage:
        Element(0x0010, 0x0010, 'PN', 'Doe^John')
        Element((0x0010, 0x0010), 'PN', 'Doe^John')
        Element(0x00100010, 'PN', 'Doe^John')
    
    Raw/fuzzing usage (override anything):
        Element.raw(
            tag=0x00100010,      # or tuple, or bytes
            vr='XX',             # any 2 chars
            value=b'payload',
            length=0xDEAD,       # lie about length
        )
    """
    
    tag: Tag
    vr: str
    value: Any
    
    # Override fields for fuzzing
    _raw_tag: bytes = field(default=None, repr=False)
    _raw_vr: bytes = field(default=None, repr=False)
    _raw_length: int = field(default=None, repr=False)
    _raw_value: bytes = field(default=None, repr=False)
    
    def __init__(self, group_or_tag, element_or_vr=None, vr_or_value=None, value=None):
        """Flexible constructor."""
        if isinstance(group_or_tag, Element):
            # Copy constructor
            self.tag = group_or_tag.tag
            self.vr = group_or_tag.vr
            self.value = group_or_tag.value
            self._raw_tag = group_or_tag._raw_tag
            self._raw_vr = group_or_tag._raw_vr
            self._raw_length = group_or_tag._raw_length
            self._raw_value = group_or_tag._raw_value
            return
            
        # Parse flexible arguments
        if isinstance(group_or_tag, tuple):
            self.tag = Tag(group_or_tag)
            self.vr = element_or_vr
            self.value = vr_or_value
        elif isinstance(group_or_tag, int) and group_or_tag > 0xFFFF:
            self.tag = Tag(group_or_tag)
            self.vr = element_or_vr
            self.value = vr_or_value
        else:
            self.tag = Tag(group_or_tag, element_or_vr)
            self.vr = vr_or_value
            self.value = value
        
        self._raw_tag = None
        self._raw_vr = None
        self._raw_length = None
        self._raw_value = None
    
    @classmethod
    def raw(cls, tag: Union[int, Tuple[int, int], bytes],
            vr: Union[str, bytes],
            value: bytes,
            length: int = None) -> 'Element':
        """Create element with full byte control."""
        # Parse tag
        if isinstance(tag, bytes):
            t = Tag(tag)
            raw_tag = tag
        else:
            t = Tag(tag) if not isinstance(tag, Tag) else tag
            raw_tag = None
        
        # Parse VR
        if isinstance(vr, bytes):
            vr_str = vr.decode('ascii', errors='replace')[:2]
            raw_vr = vr
        else:
            vr_str = str(vr)[:2]
            raw_vr = None
        
        elem = cls(t.group, t.element, vr_str, value)
        elem._raw_tag = raw_tag
        elem._raw_vr = raw_vr
        elem._raw_length = length
        elem._raw_value = value if isinstance(value, bytes) else None
        
        return elem
    
    @classmethod
    def from_pydicom(cls, elem) -> 'Element':
        """Create from pydicom DataElement."""
        return cls(elem.tag.group, elem.tag.element, elem.VR, elem.value)
    
    @property
    def keyword(self) -> str:
        return self.tag.keyword
    
    def clone(self) -> 'Element':
        """Create a copy."""
        return Element(self)
    
    def with_vr(self, vr: str) -> 'Element':
        """Return copy with different VR."""
        e = self.clone()
        e.vr = vr
        return e
    
    def with_value(self, value: Any) -> 'Element':
        """Return copy with different value."""
        e = self.clone()
        e.value = value
        e._raw_value = None
        return e
    
    def with_length(self, length: int) -> 'Element':
        """Return copy with overridden length."""
        e = self.clone()
        e._raw_length = length
        return e
    
    def _encode_value(self, little_endian: bool = True) -> bytes:
        """Encode value to bytes."""
        if self._raw_value is not None:
            return self._raw_value
        
        if isinstance(self.value, bytes):
            return self.value
        elif isinstance(self.value, str):
            return self.value.encode('ascii', errors='replace')
        elif isinstance(self.value, (int, float)):
            vr_upper = self.vr.upper()
            _NUMERIC_FMT = {
                'SS': 'h', 'US': 'H', 'SL': 'i', 'UL': 'I',
                'SV': 'q', 'UV': 'Q', 'FL': 'f', 'FD': 'd',
            }
            if vr_upper in _NUMERIC_FMT:
                endian = '<' if little_endian else '>'
                return struct.pack(endian + _NUMERIC_FMT[vr_upper], self.value)
            return str(self.value).encode('ascii')
        elif self.value is None:
            return b''
        elif hasattr(self.value, 'encode'):
            # Sequence or EncapsulatedPixelData
            return self.value.encode(little_endian=little_endian)
        else:
            return str(self.value).encode('ascii', errors='replace')
    
    def encode(self, implicit_vr: bool = False, little_endian: bool = True) -> bytes:
        """Encode element to bytes."""
        bio = BytesIO()
        
        # Tag
        if self._raw_tag:
            bio.write(self._raw_tag[:4])
        else:
            bio.write(self.tag.encode(little_endian))
        
        # Value bytes
        val_bytes = self._encode_value(little_endian)
        
        # Pad to even length (unless raw length override)
        if self._raw_length is None and len(val_bytes) % 2:
            if self.vr.upper() == 'UI':
                val_bytes += b'\x00'
            elif self.vr.upper() in ('OB', 'OW', 'OF', 'OD', 'UN'):
                val_bytes += b'\x00'
            else:
                val_bytes += b' '
        
        # Length
        length = self._raw_length if self._raw_length is not None else len(val_bytes)
        
        if implicit_vr:
            # Implicit VR: 4-byte length only
            fmt = '<I' if little_endian else '>I'
            bio.write(struct.pack(fmt, length))
        else:
            # Explicit VR
            if self._raw_vr:
                bio.write(self._raw_vr[:2].ljust(2, b' '))
            else:
                bio.write(self.vr[:2].ljust(2).encode('ascii'))
            
            if VR.uses_long_length(self.vr) or (self._raw_length is not None and self._raw_length > 0xFFFF):
                # 4-byte length with 2-byte reserved
                bio.write(b'\x00\x00')
                fmt = '<I' if little_endian else '>I'
                bio.write(struct.pack(fmt, length))
            else:
                # 2-byte length
                fmt = '<H' if little_endian else '>H'
                bio.write(struct.pack(fmt, length & 0xFFFF))
        
        bio.write(val_bytes)
        return bio.getvalue()
    
    def __bytes__(self) -> bytes:
        return self.encode()
    
    def __repr__(self) -> str:
        kw = self.keyword
        tag_str = repr(self.tag)
        if kw:
            tag_str += f' {kw}'
        
        val_repr = repr(self.value)
        if len(val_repr) > 50:
            val_repr = val_repr[:47] + '...'
        
        return f'Element {tag_str} {self.vr}: {val_repr}'
    
    def hexdump(self) -> str:
        return hexdump(bytes(self))


# =============================================================================
# Dataset Class
# =============================================================================

class Dataset:
    """
    DICOM Dataset with Scapy-like chaining.
    
    Usage:
        ds = (Dataset()
            / Element(0x0010, 0x0010, 'PN', 'Doe^John')
            / Element(0x0010, 0x0020, 'LO', '12345')
        )
        
        ds[0x0010, 0x0010].value = 'New^Name'
        raw = bytes(ds)
    """
    
    def __init__(self, elements: List[Element] = None):
        self._elements: Dict[int, Element] = {}
        self._order: List[int] = []
        self._raw_list: Optional[List[Element]] = None

        if elements:
            for e in elements:
                self._add(e)
    
    def _add(self, elem: Element) -> None:
        tag_int = elem.tag.as_int
        self._elements[tag_int] = elem
        if tag_int not in self._order:
            self._order.append(tag_int)

    def _force_append(self, elem: Element) -> None:
        """Append element without dedup — for crafting malformed datasets."""
        if self._raw_list is None:
            self._raw_list = []
        self._raw_list.append(elem)

    def __truediv__(self, other: Element) -> 'Dataset':
        """Scapy-like chaining: ds / element."""
        self._add(other)
        return self
    
    def add(self, group_or_tag, element_or_vr=None, vr_or_value=None, value=None) -> 'Dataset':
        """Add element with flexible arguments."""
        self._add(Element(group_or_tag, element_or_vr, vr_or_value, value))
        return self
    
    def add_raw(self, **kwargs) -> 'Dataset':
        """Add raw element."""
        self._add(Element.raw(**kwargs))
        return self
    
    def __getitem__(self, key) -> Optional[Element]:
        if isinstance(key, str):
            # Keyword lookup
            try:
                from pydicom.datadict import tag_for_keyword
                tag = tag_for_keyword(key)
                if tag:
                    return self._elements.get((tag.group << 16) | tag.element)
            except ImportError:
                pass
            raise KeyError(f"Unknown keyword: {key}")
        
        tag = Tag(key)
        return self._elements.get(tag.as_int)
    
    def __setitem__(self, key, elem: Element) -> None:
        tag = Tag(key)
        self._elements[tag.as_int] = elem
        if tag.as_int not in self._order:
            self._order.append(tag.as_int) # <--- FIXED
    
    def __delitem__(self, key) -> None:
        tag = Tag(key)
        if tag.as_int in self._elements:  
            del self._elements[tag.as_int]
            self._order.remove(tag.as_int)
    
    def __contains__(self, key) -> bool:
        tag = Tag(key)
        return tag.as_int in self._elements # <--- FIXED
    
    def __iter__(self) -> Iterator[Element]:
        for tag_int in self._order:
            yield self._elements[tag_int]
    
    def __len__(self) -> int:
        return len(self._elements)
    
    def get(self, key, default=None) -> Optional[Element]:
        try:
            return self[key]
        except (KeyError, TypeError):
            return default
    
    def tags(self) -> List[Tag]:
        """Return all tags in order."""
        return [Tag(t) for t in self._order]
    
    def encode(self, implicit_vr: bool = False, little_endian: bool = True,
               sort_tags: bool = False) -> bytes:
        """Encode dataset to bytes."""
        bio = BytesIO()

        if self._raw_list is not None:
            for elem in self._raw_list:
                bio.write(elem.encode(implicit_vr, little_endian))
            return bio.getvalue()

        order = sorted(self._order) if sort_tags else self._order
        for tag_int in order:
            bio.write(self._elements[tag_int].encode(implicit_vr, little_endian))

        return bio.getvalue()
    
    def __bytes__(self) -> bytes:
        return self.encode()
    
    @classmethod
    def from_pydicom(cls, ds, recursive: bool = True) -> 'Dataset':
        """Convert pydicom Dataset to our Dataset."""
        result = cls()
        for elem in ds:
            if elem.VR == 'SQ' and recursive:
                # Handle sequence
                seq = Sequence()
                for item in elem.value:
                    seq.items.append(cls.from_pydicom(item, recursive))
                result._add(Element(elem.tag.group, elem.tag.element, 'SQ', seq))
            else:
                result._add(Element.from_pydicom(elem))
        return result
    
    def show(self) -> None:
        """Print dataset contents."""
        for elem in self:
            print(repr(elem))
    
    def hexdump(self) -> str:
        return hexdump(bytes(self))
    
    def diff(self, other: 'Dataset') -> List[str]:
        """Compare with another dataset."""
        diffs = []
        all_tags = set(self._order) | set(other._order)
        
        for tag_int in sorted(all_tags):
            if tag_int not in self._elements:
                diffs.append(f"+ {other._elements[tag_int]}")
            elif tag_int not in other._elements:
                diffs.append(f"- {self._elements[tag_int]}")
            elif bytes(self._elements[tag_int]) != bytes(other._elements[tag_int]):
                diffs.append(f"~ {self._elements[tag_int]} -> {other._elements[tag_int]}")
        
        return diffs

# =============================================================================
# Sequence Classes
# =============================================================================

class Sequence:
    """DICOM Sequence (SQ) value."""
    
    ITEM_TAG = b'\xFE\xFF\x00\xE0'
    ITEM_DELIM_TAG = b'\xFE\xFF\x0D\xE0'
    SEQ_DELIM_TAG = b'\xFE\xFF\xDD\xE0'
    
    def __init__(self, items: List[Dataset] = None):
        self.items = items or []
        self.undefined_length = True
    
    def __truediv__(self, other: Dataset) -> 'Sequence':
        """Allow chaining: seq / dataset."""
        self.items.append(other)
        return self
    
    def encode(self, implicit_vr: bool = False, little_endian: bool = True) -> bytes:
        bio = BytesIO()
        
        for item in self.items:
            # Item tag
            bio.write(self.ITEM_TAG if little_endian else b'\xFF\xFE\xE0\x00')
            
            # Item data
            item_bytes = item.encode(implicit_vr, little_endian)
            
            if self.undefined_length:
                # Undefined length
                bio.write(b'\xFF\xFF\xFF\xFF')
                bio.write(item_bytes)
                # Item delimitation
                bio.write(self.ITEM_DELIM_TAG if little_endian else b'\xFF\xFE\xE0\x0D')
                bio.write(b'\x00\x00\x00\x00')
            else:
                # Explicit length
                fmt = '<I' if little_endian else '>I'
                bio.write(struct.pack(fmt, len(item_bytes)))
                bio.write(item_bytes)
        
        if self.undefined_length:
            # Sequence delimitation
            bio.write(self.SEQ_DELIM_TAG if little_endian else b'\xFF\xFE\xDD\xE0')
            bio.write(b'\x00\x00\x00\x00')
        
        return bio.getvalue()


# =============================================================================
# Utilities
# =============================================================================

def hexdump(data: bytes, width: int = 16) -> str:
    """Format bytes as hex dump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:08x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(lines)
