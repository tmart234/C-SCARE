# SPDX-License-Identifier: GPL-2.0-only
"""
Byte-faithful carrier objects for C-STORE delivery (``--cstore-file``).

``--cstore-file`` hands the framework a real image the operator has already
proven the target accepts, and every dataset-shaped attack then rides a copy of
it. That only means something if the copy is *the operator's object*: an SCP
that rejected the framework's tiny synthetic dataset for missing device
elements will just as happily reject a carrier that a round-trip has quietly
rewritten, and the run reports a clean status for a test the parser never ran.

So this module holds a carrier as the bytes that were on disk and edits it by
splicing. Nothing is re-encoded on the way out; an element the attack does not
name comes off the wire byte-for-byte as it went in.

That is not what happens if you parse with pydicom and write with pydicom.
pydicom is a conformant writer, and conformance here is loss:

* ``write_dataset`` skips every retired Group Length element -- ``if
  tag.element == 0 and tag.group > 6: continue`` -- so ``(0008,0000)``,
  ``(0028,0000)`` and friends vanish from an object that shipped with them.
  Group length handling is itself an attack surface this catalog probes.
* It writes ``sorted(dataset.keys())``, silently repairing an object whose
  elements were out of tag order on disk.
* A ``UN`` element holding an implicit-VR sequence is re-read as ``SQ`` and
  re-emitted with different bytes and a different length.
* A truncated element is repaired; ambiguous VRs are resolved; padding is
  normalised.

Every one of those is a difference between what the operator validated and what
the target is asked to parse. ``corruptor.py`` says it in its own docstring:
pydicom is the source of truth for *understanding* DICOM, never for output.
This module applies the same rule to the carrier.

Scanning is deliberately structural rather than semantic. It reads tag, VR and
declared length, walks sequence and item delimiters to find where each
top-level element ends, and gives up cleanly the moment the bytes stop making
sense -- keeping everything from that point on as an opaque tail that is
delivered verbatim. A carrier that is already malformed stays exactly as
malformed as the operator made it.

Example::

    carrier = Carrier.from_file('scanner.dcm')
    edit = carrier.edit()
    edit.set_text(0x00080018, 'UI', '../../../../../../tmp/pwn')
    payload = edit.to_bytes()      # the operator's object, one element changed
"""

import os
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .element import Element, encode_vr_length, pad_to_even

__all__ = [
    'Carrier',
    'CarrierEdit',
    'CarrierElement',
    'CarrierError',
    'MAX_NESTING_DEPTH',
    'empty_basic_offset_table',
    'encapsulate_items',
    'is_part10',
    'scan_dataset',
    'dataset_from_part10',
    'decode_uid_value',
    'split_part10',
    'split_encapsulated',
    'sniff_encoding',
    'transcode_element_header',
    'IMPLICIT_VR_LITTLE_ENDIAN',
    'EXPLICIT_VR_LITTLE_ENDIAN',
    'EXPLICIT_VR_BIG_ENDIAN',
]


IMPLICIT_VR_LITTLE_ENDIAN = '1.2.840.10008.1.2'
EXPLICIT_VR_LITTLE_ENDIAN = '1.2.840.10008.1.2.1'
EXPLICIT_VR_BIG_ENDIAN = '1.2.840.10008.1.2.2'
DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN = '1.2.840.10008.1.2.1.99'

PREAMBLE_LEN = 128
DICM_PREFIX = b'DICM'

UNDEFINED_LENGTH = 0xFFFFFFFF

#: How deep a nesting of undefined-length Sequences and Items the scanner will
#: follow. Real objects nest a handful of levels; the catalog's sequence-depth
#: bombs nest thousands, and those are payloads to deliver, not objects to
#: splice into. Past this the scan stops and the rest becomes an opaque tail.
MAX_NESTING_DEPTH = 256

TAG_ITEM = 0xFFFEE000
TAG_ITEM_DELIMITER = 0xFFFEE00D
TAG_SEQUENCE_DELIMITER = 0xFFFEE0DD
_DELIMITER_TAGS = (TAG_ITEM, TAG_ITEM_DELIMITER, TAG_SEQUENCE_DELIMITER)

TAG_SOP_CLASS_UID = 0x00080016
TAG_SOP_INSTANCE_UID = 0x00080018
TAG_PIXEL_DATA = 0x7FE00010

# Explicit-VR value representations carried with a 2-byte reserved field and a
# 4-byte length (PS3.5 Section 7.1.2). Kept as bytes because the scanner reads
# the wire, and a carrier is allowed to hold a VR that is not in this list --
# or not a VR at all.
_LONG_FORM_VRS = frozenset({
    b'OB', b'OD', b'OF', b'OL', b'OV', b'OW', b'SQ',
    b'UC', b'UN', b'UR', b'UT',
})

# Transfer syntaxes whose Data Set is not a plain element stream. The carrier
# still delivers them byte-for-byte; it just cannot splice inside one.
_OPAQUE_DATASET_SYNTAXES = frozenset({DEFLATED_EXPLICIT_VR_LITTLE_ENDIAN})

# The transfer syntax to negotiate for a Data Set whose encoding had to be
# sniffed, keyed by ``(implicit_vr, little_endian)``.
_SNIFFED_SYNTAX = {
    (True, True): IMPLICIT_VR_LITTLE_ENDIAN,
    (False, True): EXPLICIT_VR_LITTLE_ENDIAN,
    (False, False): EXPLICIT_VR_BIG_ENDIAN,
}


def is_part10(blob: bytes) -> bool:
    """True if ``blob`` is a complete Part-10 file.

    PS3.10 Section 7.1 fixes the shape: a 128-byte File Preamble followed by
    the four-byte ``DICM`` prefix. Nothing a Data Set can start with looks like
    that, so it is a reliable structural answer to "is this a file, or bytes to
    be framed?".
    """
    return (len(blob) > PREAMBLE_LEN + len(DICM_PREFIX)
            and blob[PREAMBLE_LEN:PREAMBLE_LEN + len(DICM_PREFIX)]
            == DICM_PREFIX)


def split_part10(blob: bytes) -> Tuple[bytes, bytes, bytes,
                                       List['CarrierElement']]:
    """Split a Part-10 file into ``(preamble, file_meta, dataset, elements)``.

    The group-0002 elements are returned with spans relative to ``file_meta``.
    Bounded by the elements themselves rather than by (0002,0000) File Meta
    Information Group Length: a file whose group length disagrees with its
    contents is a thing the catalog deliberately builds, and trusting the
    declared value would make the split depend on the very field under test.

    Never raises. A blob that is not a Part-10 file is all Data Set, which is
    what a C-STORE payload is.
    """
    if not is_part10(blob):
        return b'', b'', blob, []

    start = PREAMBLE_LEN + len(DICM_PREFIX)
    elements: List[CarrierElement] = []
    pos = start
    end = len(blob)
    while pos + 8 <= end:
        group, element = struct.unpack_from('<HH', blob, pos)
        if group != 0x0002:
            break
        vr = bytes(blob[pos + 4:pos + 6])
        if vr in _LONG_FORM_VRS:
            if pos + 12 > end:
                break
            length = struct.unpack_from('<I', blob, pos + 8)[0]
            value_start = pos + 12
            long_form = True
        else:
            length = struct.unpack_from('<H', blob, pos + 6)[0]
            value_start = pos + 8
            long_form = False
        value_end = value_start + length
        if length == UNDEFINED_LENGTH or value_end > end:
            break
        elements.append(CarrierElement(
            tag=(group << 16) | element, vr=vr, declared_length=length,
            start=pos - start, value_start=value_start - start,
            end=value_end - start, long_form=long_form))
        pos = value_end
    return blob[:PREAMBLE_LEN], blob[start:pos], blob[pos:], elements


class CarrierError(Exception):
    """The carrier file could not be read as a DICOM object at all."""


def _uid_from_bytes(raw: bytes) -> str:
    """Decode a UID value the way the wire wrote it, padding included.

    UIDs are NULL-padded to an even length (PS3.5 Section 6.2). Trailing NULs
    are padding, not value, so they come off -- but nothing else does. A UID
    that carries a traversal path, an embedded NUL in the middle, or bytes no
    UID may hold survives this untouched, which is the point.
    """
    return raw.decode('ascii', errors='replace').rstrip('\x00').strip()


@dataclass
class CarrierElement:
    """One top-level Data Element, described by where it sits in the bytes.

    The value itself is never copied out of the carrier: ``start``..``end`` is
    the element's whole span including its header, so splicing one element out
    and another in is a slice operation on the original buffer.
    """

    tag: int
    vr: Optional[bytes]          # None under implicit VR: the wire has no VR
    declared_length: int         # exactly what the length field said
    start: int                   # offset of the tag
    value_start: int             # offset of the first value byte
    end: int                     # one past the element's last byte
    long_form: bool = False      # explicit VR written with the 4-byte length

    @property
    def group(self) -> int:
        return (self.tag >> 16) & 0xFFFF

    @property
    def element(self) -> int:
        return self.tag & 0xFFFF

    @property
    def undefined_length(self) -> bool:
        return self.declared_length == UNDEFINED_LENGTH

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        vr = self.vr.decode('ascii', 'replace') if self.vr else '--'
        return (f'<({self.group:04X},{self.element:04X}) {vr} '
                f'len={self.declared_length} @{self.start}..{self.end}>')


def _read_tag(data: bytes, pos: int, little_endian: bool) -> int:
    fmt = '<HH' if little_endian else '>HH'
    group, element = struct.unpack_from(fmt, data, pos)
    return (group << 16) | element


def _read_header(data: bytes, pos: int, end: int, little_endian: bool,
                 implicit_vr: bool):
    """Read one Data Element header. Never looks past the header itself."""
    if pos + 8 > end:
        raise ValueError('truncated element header')
    tag = _read_tag(data, pos, little_endian)
    long_fmt = '<I' if little_endian else '>I'
    short_fmt = '<H' if little_endian else '>H'

    if implicit_vr or tag in _DELIMITER_TAGS:
        # Delimiter items never carry a VR, whatever the transfer syntax.
        return (tag, None, struct.unpack_from(long_fmt, data, pos + 4)[0],
                pos + 8, False)
    vr = bytes(data[pos + 4:pos + 6])
    if vr in _LONG_FORM_VRS:
        if pos + 12 > end:
            raise ValueError('truncated long-form element header')
        return (tag, vr, struct.unpack_from(long_fmt, data, pos + 8)[0],
                pos + 12, True)
    return (tag, vr, struct.unpack_from(short_fmt, data, pos + 6)[0],
            pos + 8, False)


def _undefined_length_encoding(vr: Optional[bytes], implicit_vr: bool,
                               little_endian: bool) -> Tuple[bool, bool]:
    """The encoding inside an undefined-length element.

    A Sequence inherits the enclosing Data Set's encoding. A ``UN`` element
    with an undefined length does not: PS3.5 Section 6.2.2 (and CP-246) say its
    content is a Data Set encoded Implicit VR Little Endian, whatever the
    transfer syntax around it is. Real objects do this -- an explicit-VR file
    written by a toolkit that met a private sequence it had no dictionary entry
    for -- and reading such an element as explicit VR misreads the first
    nested tag's length and loses the rest of the file.
    """
    if vr == b'UN':
        return True, True
    return implicit_vr, little_endian


def _scan_undefined_length_span(data: bytes, start: int, end: int,
                                little_endian: bool, implicit_vr: bool) -> int:
    """Return the offset just past the delimiter closing an undefined length.

    Handles both shapes an undefined length can take: a Sequence of Items, each
    of which is itself a Data Set that may nest further, and encapsulated Pixel
    Data, whose Items are opaque fragments. Both end at a Sequence Delimitation
    Item; Items with an undefined length end at an Item Delimitation Item.

    Each nesting level carries its own encoding, because a ``UN`` element
    switches the Data Set inside it to Implicit VR Little Endian while the
    Sequence beside it keeps the enclosing one.

    The walk keeps its own stack rather than recursing. The catalog ships
    sequence-depth bombs on purpose, and a scanner that recursed would hit
    Python's stack limit on the framework's own payloads -- turning an attack
    that should have gone to the target into a traceback on the way out.

    Raises ``ValueError`` if the delimiter never arrives or the nesting runs
    past :data:`MAX_NESTING_DEPTH`, which is the signal to stop scanning and
    treat the rest as an opaque tail: still delivered, just not spliceable.
    """
    # Each frame is (mode, implicit_vr, little_endian) where mode is
    # 'SEQ' (expecting Items or a Sequence Delimitation Item) or
    # 'ITEM' (expecting Data Elements or an Item Delimitation Item).
    stack = [('SEQ', implicit_vr, little_endian)]
    pos = start
    while stack:
        if len(stack) > MAX_NESTING_DEPTH:
            raise ValueError(f'nesting deeper than {MAX_NESTING_DEPTH}')
        if pos + 8 > end:
            raise ValueError('undefined length never closed')
        mode, frame_implicit, frame_little = stack[-1]
        long_fmt = '<I' if frame_little else '>I'
        tag = _read_tag(data, pos, frame_little)
        if mode == 'SEQ':
            item_length = struct.unpack_from(long_fmt, data, pos + 4)[0]
            if tag == TAG_SEQUENCE_DELIMITER:
                stack.pop()
                pos += 8
                continue
            if tag != TAG_ITEM:
                raise ValueError(f'expected an Item at {pos}, saw {tag:08X}')
            if item_length == UNDEFINED_LENGTH:
                stack.append(('ITEM', frame_implicit, frame_little))
                pos += 8
                continue
            pos += 8 + item_length
            if pos > end:
                raise ValueError('Item runs past the end of the Data Set')
            continue

        # Inside an undefined-length Item: a Data Set.
        if tag == TAG_ITEM_DELIMITER:
            stack.pop()
            pos += 8
            continue
        if tag == TAG_SEQUENCE_DELIMITER:
            # Malformed, but unambiguous: the enclosing sequence ended without
            # closing this item. Hand the delimiter back to the sequence.
            stack.pop()
            continue
        _tag, vr, declared, value_start, _long = _read_header(
            data, pos, end, frame_little, frame_implicit)
        if declared == UNDEFINED_LENGTH:
            inner_implicit, inner_little = _undefined_length_encoding(
                vr, frame_implicit, frame_little)
            stack.append(('SEQ', inner_implicit, inner_little))
            pos = value_start
            continue
        pos = value_start + declared
        if pos > end:
            raise ValueError('element value runs past the end of the Data Set')
    return pos


def _read_element(data: bytes, pos: int, end: int, little_endian: bool,
                  implicit_vr: bool) -> CarrierElement:
    """Read one Data Element header and work out where the element ends."""
    tag, vr, declared, value_start, long_form = _read_header(
        data, pos, end, little_endian, implicit_vr)

    if declared == UNDEFINED_LENGTH:
        inner_implicit, inner_little = _undefined_length_encoding(
            vr, implicit_vr, little_endian)
        element_end = _scan_undefined_length_span(data, value_start, end,
                                                  inner_little, inner_implicit)
    else:
        element_end = value_start + declared
        if element_end > end:
            raise ValueError('element value runs past the end of the Data Set')

    return CarrierElement(tag=tag, vr=vr, declared_length=declared, start=pos,
                          value_start=value_start, end=element_end,
                          long_form=long_form)


def scan_dataset(data: bytes, implicit_vr: bool,
                 little_endian: bool) -> Tuple[List[CarrierElement], int]:
    """Locate every top-level Data Element in ``data``.

    Returns the elements and the offset where scanning stopped. Anything from
    that offset on is an opaque tail: bytes that did not parse as an element,
    which the carrier keeps and delivers unchanged rather than discarding. A
    well-formed object returns a tail offset equal to ``len(data)``.
    """
    elements: List[CarrierElement] = []
    pos = 0
    end = len(data)
    while pos < end:
        try:
            elem = _read_element(data, pos, end, little_endian, implicit_vr)
        except (ValueError, struct.error):
            break
        if elem.end <= elem.start:
            break
        elements.append(elem)
        pos = elem.end
    return elements, pos


def sniff_encoding(data: bytes) -> Tuple[bool, bool]:
    """Guess ``(implicit_vr, little_endian)`` for a Data Set with no File Meta.

    A Data Set with no File Meta Information carries no statement of its own
    encoding, and PS3.10 offers no way to recover one -- Part 10 puts that
    statement in group 0002, which is exactly what such a file is missing. So
    try each candidate and keep the one that reads the furthest: a wrong guess
    misreads a length within the first element or two and stops dead, while the
    right one walks the whole Data Set. Ties go to the earlier candidate, which
    orders them by how common they are in the wild.
    """
    candidates = (
        (False, True),   # Explicit VR Little Endian
        (True, True),    # Implicit VR Little Endian
        (False, False),  # Explicit VR Big Endian
    )
    best = (True, True)
    best_score = -1
    for implicit, little in candidates:
        _elements, consumed = scan_dataset(data, implicit, little)
        if consumed > best_score:
            best, best_score = (implicit, little), consumed
        if consumed == len(data):
            break
    return best


def transcode_element_header(elem: CarrierElement, value: bytes,
                             *, from_implicit: bool, from_little: bool,
                             to_implicit: bool, to_little: bool) -> bytes:
    """Re-frame one element for a different transfer syntax, value intact.

    An attack's malformation usually lives in the *value* and in the *declared
    length* -- a length that lies, a value padded to an odd size, bytes that no
    VR permits. Re-encoding such an element through a validating writer repairs
    exactly the thing under test. Re-framing keeps the declared length and the
    value bytes as the attack wrote them and rewrites only what the transfer
    syntax dictates: whether a VR appears on the wire, and which way the tag
    and length fields are packed.

    Where the two syntaxes disagree about what can be said at all -- an
    invalid VR cannot be expressed under implicit VR, because implicit VR has
    no VR field -- the VR is simply dropped, and the caller is expected to have
    checked ``carries_vr`` before deciding the attack is still meaningful.
    """
    tag_fmt = '<HH' if to_little else '>HH'
    out = struct.pack(tag_fmt, elem.group, elem.element)
    vr = (elem.vr or b'UN').decode('ascii', errors='replace')
    if elem.tag in _DELIMITER_TAGS:
        length_fmt = '<I' if to_little else '>I'
        return out + struct.pack(length_fmt, elem.declared_length)
    long_form = elem.long_form or elem.declared_length > 0xFFFF
    out += encode_vr_length(vr, elem.declared_length, to_implicit, to_little,
                            raw_vr=elem.vr, long_form=long_form)
    return out + value


def decode_uid_value(value: bytes) -> str:
    """Decode a DICOM UI value from file meta information."""
    return value.rstrip(b'\x00 ').decode('ascii', errors='ignore')


def dataset_from_part10(payload: bytes) -> Tuple[bytes, Dict[str, str]]:
    """Strip a Part-10 file wrapper for C-STORE delivery.

    C-STORE carries only a DICOM data set. Several catalog CVE payloads are
    stored as complete Part-10 files so they are useful as file-parser seeds;
    when those same payloads are delivered over C-STORE, remove the preamble
    and group-0002 file meta header while preserving the malformed data set.

    Sits beside :func:`split_part10` so the carrier and the delivery path
    cannot disagree about where a Data Set begins — they used to have separate
    implementations of the same walk, and a payload that straddled the
    difference was framed one way and spliced the other.
    """
    _preamble, file_meta, dataset, elements = split_part10(payload)
    meta: Dict[str, str] = {}
    if not is_part10(payload):
        return payload, meta

    for elem in elements:
        value = file_meta[elem.value_start:elem.end]
        if elem.tag == 0x00020002:
            meta['sop_class_uid'] = decode_uid_value(value)
        elif elem.tag == 0x00020003:
            meta['sop_instance_uid'] = decode_uid_value(value)
        elif elem.tag == 0x00020010:
            meta['transfer_syntax'] = decode_uid_value(value)

    if len(payload) - len(dataset) > 132:
        meta['part10_stripped'] = 'true'
        return dataset, meta
    return payload, meta


class Carrier:
    """A real DICOM object, held as the bytes it was stored as.

    ``dataset`` is what C-STORE puts on the wire: the Data Set alone, with the
    preamble and the group-0002 File Meta Information kept aside. Both halves
    are preserved so a transport that carries whole files (STOW-RS) can have
    the original back, unchanged.
    """

    def __init__(self, blob: bytes, path: Optional[str] = None):
        self.path = path
        self.raw = blob
        self.preamble = b''
        self.file_meta = b''
        self.dataset = blob
        self._file_meta_values: Dict[int, bytes] = {}

        self.preamble, self.file_meta, self.dataset, self.file_meta_elements = \
            split_part10(blob)
        for elem in self.file_meta_elements:
            self._file_meta_values[elem.tag] = \
                self.file_meta[elem.value_start:elem.end]

        self.sniffed_encoding = False
        self.transfer_syntax = _uid_from_bytes(
            self._file_meta_values.get(0x00020010, b'')) or None
        if self.transfer_syntax:
            self.implicit_vr = self.transfer_syntax == IMPLICIT_VR_LITTLE_ENDIAN
            self.little_endian = self.transfer_syntax != EXPLICIT_VR_BIG_ENDIAN
        else:
            # No File Meta Information: recover the encoding from the bytes.
            self.implicit_vr, self.little_endian = sniff_encoding(self.dataset)
            self.transfer_syntax = _SNIFFED_SYNTAX[(self.implicit_vr,
                                                    self.little_endian)]
            self.sniffed_encoding = True

        if self.transfer_syntax in _OPAQUE_DATASET_SYNTAXES:
            # A Deflated Data Set is a compressed stream, not an element
            # stream. It still travels intact; it just cannot be spliced.
            self.elements: List[CarrierElement] = []
            self.tail_offset = 0
        else:
            self.elements, self.tail_offset = scan_dataset(
                self.dataset, self.implicit_vr, self.little_endian)

        if not self.elements and not self.file_meta:
            raise CarrierError(
                f'{path or "carrier"} holds no readable DICOM Data Set '
                '(no File Meta Information and no parsable element)')

    # -- construction ----------------------------------------------------

    @classmethod
    def from_file(cls, path) -> 'Carrier':
        path = os.path.abspath(os.fspath(path))
        try:
            with open(path, 'rb') as fh:
                blob = fh.read()
        except OSError as exc:
            raise CarrierError(f'cannot read {path}: {exc}') from exc
        return cls(blob, path=path)

    @classmethod
    def from_bytes(cls, blob: bytes, path: Optional[str] = None) -> 'Carrier':
        return cls(blob, path=path)

    @classmethod
    def from_dataset(cls, blob: bytes, transfer_syntax: str,
                     path: Optional[str] = None) -> 'Carrier':
        """A bare Data Set whose encoding is already known.

        A Data Set that arrived over an association carries no File Meta
        Information -- C-STORE transmits a Data Set, not a file -- but the
        encoding is not in doubt either: the presentation context said what it
        is. Sniffing here would be guessing at something already known, and a
        guess that lands wrong on a deliberately malformed object turns the
        receiver's bytes into nonsense before anything has looked at them.
        """
        carrier = cls.__new__(cls)
        carrier.path = path
        carrier.raw = blob
        carrier.preamble = b''
        carrier.file_meta = b''
        carrier.dataset = blob
        carrier._file_meta_values = {}
        carrier.file_meta_elements = []
        carrier.sniffed_encoding = False
        carrier.transfer_syntax = transfer_syntax or IMPLICIT_VR_LITTLE_ENDIAN
        carrier.implicit_vr = (
            carrier.transfer_syntax == IMPLICIT_VR_LITTLE_ENDIAN)
        carrier.little_endian = (
            carrier.transfer_syntax != EXPLICIT_VR_BIG_ENDIAN)
        if carrier.transfer_syntax in _OPAQUE_DATASET_SYNTAXES:
            carrier.elements, carrier.tail_offset = [], 0
        else:
            carrier.elements, carrier.tail_offset = scan_dataset(
                blob, carrier.implicit_vr, carrier.little_endian)
        return carrier

    # -- reading ---------------------------------------------------------

    @property
    def carries_vr(self) -> bool:
        """True when the Data Set's encoding puts a VR on the wire."""
        return not self.implicit_vr

    @property
    def has_tail(self) -> bool:
        return self.tail_offset < len(self.dataset)

    def find(self, tag: int) -> Optional[CarrierElement]:
        for elem in self.elements:
            if elem.tag == tag:
                return elem
        return None

    def value_of(self, tag: int) -> Optional[bytes]:
        elem = self.find(tag)
        if elem is None:
            return None
        if elem.undefined_length:
            return self.dataset[elem.value_start:elem.end]
        return self.dataset[elem.value_start:elem.value_start + elem.declared_length]

    def text_of(self, tag: int) -> Optional[str]:
        raw = self.value_of(tag)
        return None if raw is None else _uid_from_bytes(raw)

    def file_meta_text(self, tag: int) -> Optional[str]:
        raw = self._file_meta_values.get(tag)
        return None if raw is None else _uid_from_bytes(raw)

    @property
    def sop_class_uid(self) -> Optional[str]:
        return self.text_of(TAG_SOP_CLASS_UID) or self.file_meta_text(0x00020002)

    @property
    def sop_instance_uid(self) -> Optional[str]:
        return (self.text_of(TAG_SOP_INSTANCE_UID)
                or self.file_meta_text(0x00020003))

    def vr_of(self, tag: int) -> Optional[str]:
        """The VR the carrier wrote for ``tag``, if its encoding carries one."""
        elem = self.find(tag)
        if elem is None or elem.vr is None:
            return None
        return elem.vr.decode('ascii', errors='replace')

    def pixel_data(self) -> Optional[CarrierElement]:
        return self.find(TAG_PIXEL_DATA)

    # -- editing ---------------------------------------------------------

    def edit(self) -> 'CarrierEdit':
        """Start an edit. The carrier itself is never mutated."""
        return CarrierEdit(self)


class CarrierEdit:
    """Pending splices against one carrier, applied on ``to_bytes()``.

    Edits are recorded per tag and resolved in one pass so the cost of an
    attack is one rebuild, not one buffer copy per element touched. Elements
    the edit never names are emitted from the original byte span.
    """

    def __init__(self, carrier: Carrier):
        self.carrier = carrier
        self._replacements: Dict[int, Optional[bytes]] = {}
        self._file_meta: Dict[int, bytes] = {}
        self._appended: List[bytes] = []
        self._applied: List[str] = []
        self._refused: List[str] = []

    # -- reporting -------------------------------------------------------

    @property
    def applied(self) -> List[str]:
        """Names of the edits that actually reached the bytes."""
        return list(self._applied)

    @property
    def refused(self) -> List[str]:
        """Edits that could not be made, as ``'<label>: <reason>'``.

        An edit that silently does nothing turns an untested attack into a
        clean result, so a refusal is recorded and surfaced rather than
        swallowed.
        """
        return list(self._refused)

    def refuse(self, label: str, reason: str) -> None:
        self._refused.append(f'{label}: {reason}')

    def note(self, label: str) -> None:
        if label not in self._applied:
            self._applied.append(label)

    # -- element-level edits ---------------------------------------------

    def set_raw_element(self, tag: int, encoded: bytes, label: str) -> None:
        """Replace (or insert) one element with fully-formed wire bytes."""
        self._replacements[tag] = encoded
        self.note(label)

    def set_value(self, tag: int, vr: str, value, label: Optional[str] = None,
                  *, declared_length: Optional[int] = None) -> None:
        """Write ``value`` into ``tag``, encoded for this carrier's syntax.

        The VR comes from the carrier's own element when it has one, so an
        object that stored Patient ID as ``LO`` keeps ``LO`` and an object that
        used something unusual keeps that too. ``vr`` is the fallback for a tag
        the carrier does not already carry, and the only source under implicit
        VR, where the wire has no VR to reuse.
        """
        existing_vr = self.carrier.vr_of(tag)
        effective_vr = existing_vr or vr
        elem = Element.raw(tag, effective_vr,
                           _encode_value_bytes(value, effective_vr),
                           length=declared_length)
        encoded = elem.encode(implicit_vr=self.carrier.implicit_vr,
                              little_endian=self.carrier.little_endian)
        self.set_raw_element(tag, encoded, label or f'{tag:08x}')

    def set_text(self, tag: int, vr: str, text: str,
                 label: Optional[str] = None) -> None:
        """Write a string value verbatim -- no validation, no normalisation.

        This is the path every value-carrying attack takes: a traversal path in
        a UID, a shell metacharacter in a Patient Name, a value longer than the
        VR permits. pydicom would warn, coerce a backslash into a multi-value,
        or refuse; the wire takes what it is given.
        """
        self.set_value(tag, vr, text, label)

    def delete(self, tag: int, label: Optional[str] = None) -> None:
        if self.carrier.find(tag) is None:
            self.refuse(label or f'{tag:08x}', 'element not present on carrier')
            return
        self._replacements[tag] = None
        self.note(label or f'delete_{tag:08x}')

    def merge_element(self, elem: CarrierElement, value: bytes,
                      *, from_implicit: bool, from_little: bool,
                      label: Optional[str] = None) -> None:
        """Splice one element from another Data Set into this carrier.

        Used to fold an attack's own elements into the operator's object. The
        element is re-framed for the carrier's transfer syntax but its declared
        length and value bytes are kept exactly as the attack wrote them, so a
        length that lies still lies and a value with no legal encoding still
        has none.
        """
        encoded = transcode_element_header(
            elem, value,
            from_implicit=from_implicit, from_little=from_little,
            to_implicit=self.carrier.implicit_vr,
            to_little=self.carrier.little_endian)
        self.set_raw_element(elem.tag, encoded,
                             label or f'merge_{elem.tag:08x}')

    def append_raw(self, blob: bytes, label: str = 'append_raw') -> None:
        """Put bytes after the Data Set's last element.

        A last resort: content here follows Pixel Data, so a conformant peer
        that stops at the end of the object never reads it. Prefer
        ``merge_element``.
        """
        if not blob:
            return
        self._appended.append(blob)
        self.note(label)

    # -- rendering -------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Render the edited Data Set.

        Untouched elements are copied from the original buffer, so group
        lengths, private blocks, odd padding, encapsulated fragments and any
        element order the operator's object happened to use all survive. New
        tags are inserted ahead of the first element with a higher tag, which
        puts them in ascending order in the ordinary case without re-sorting an
        object that was not sorted to begin with.
        """
        data = self.carrier.dataset
        pending = dict(self._replacements)
        out = bytearray()

        for elem in self.carrier.elements:
            # Insert any new tag that belongs before this one.
            for tag in sorted(t for t in pending
                              if t < elem.tag and self.carrier.find(t) is None):
                blob = pending.pop(tag)
                if blob:
                    out += blob
            if elem.tag in pending:
                blob = pending.pop(elem.tag)
                if blob is not None:
                    out += blob
                continue
            out += data[elem.start:elem.end]

        for tag in sorted(pending):
            blob = pending[tag]
            if blob:
                out += blob

        if self.carrier.has_tail:
            out += data[self.carrier.tail_offset:]
        for blob in self._appended:
            out += blob
        return bytes(out)

    def set_file_meta(self, tag: int, vr: str, value,
                      label: Optional[str] = None) -> None:
        """Rewrite one group-0002 element in the File Meta Information.

        C-STORE never carries group 0002 -- the command set says the SOP Class
        and Instance instead -- so this changes nothing on the wire. It matters
        for the Part-10 rendering: a ``--dry-run`` file whose (0002,0003) still
        names the original instance while (0008,0018) names the attack's is a
        file the operator has to reconcile by hand before they can trust what
        they are looking at.
        """
        existing = next((e for e in self.carrier.file_meta_elements
                         if e.tag == tag), None)
        effective_vr = (existing.vr.decode('ascii', 'replace')
                        if existing is not None and existing.vr else vr)
        encoded = Element.raw(
            tag, effective_vr, _encode_value_bytes(value, effective_vr)
        ).encode(implicit_vr=False, little_endian=True)
        self._file_meta[tag] = encoded
        self.note(label or f'file_meta_{tag:08x}')

    def render_file_meta(self) -> bytes:
        """The File Meta Information with any edits spliced in.

        (0002,0000) File Meta Information Group Length is recomputed from what
        the group actually holds, because that is the one field in a DICOM
        object whose only job is to agree with its neighbours: a Part-10 reader
        uses it to find where the Data Set starts.
        """
        meta = self.carrier.file_meta
        if not meta:
            return meta
        pending = dict(self._file_meta)
        if not pending:
            return meta
        out = bytearray()
        group_length_span = None
        for elem in self.carrier.file_meta_elements:
            blob = pending.pop(elem.tag, None)
            if elem.tag == 0x00020000:
                group_length_span = (len(out), elem)
                out += meta[elem.start:elem.end]
                continue
            out += blob if blob is not None else meta[elem.start:elem.end]
        for tag in sorted(pending):
            out += pending[tag]
        if group_length_span is not None:
            offset, elem = group_length_span
            header = elem.end - elem.value_start
            after = len(out) - (offset + (elem.end - elem.start))
            out[offset + (elem.end - elem.start) - header:
                offset + (elem.end - elem.start)] = struct.pack('<I', after)
        return bytes(out)

    def to_part10(self) -> bytes:
        """Render the edited object as a complete Part-10 file.

        The preamble comes back exactly as it was read, and so does every File
        Meta element the edit did not name. This is what a whole-file transport
        (STOW-RS) and ``--dry-run`` both want: a file the operator can open in
        the same viewer that accepted the original.

        A carrier that arrived with no File Meta Information gets a minimal one
        built for it, stating the encoding that was sniffed out of its bytes.
        Synthesising a header is not a change to the object -- group 0002 is
        outside the Data Set and never crosses a C-STORE association -- and
        without one there is no file to hand a viewer, a STOW-RS endpoint, or
        an operator reviewing a ``--dry-run`` directory.
        """
        body = self.to_bytes()
        if self.carrier.file_meta:
            return (self.carrier.preamble + DICM_PREFIX
                    + self.render_file_meta() + body)
        return (b'\x00' * PREAMBLE_LEN + DICM_PREFIX
                + self._synthesised_file_meta(body) + body)

    def _synthesised_file_meta(self, body: bytes) -> bytes:
        """A minimal group 0002 for a Data Set that arrived without one.

        The SOP Class and Instance are read back out of the rendered Data Set
        so the header states what the body actually says, edits included.
        """
        sop_class = (self._file_meta_uid(0x00020002)
                     or self._rendered_uid(body, TAG_SOP_CLASS_UID)
                     or '1.2.840.10008.5.1.4.1.1.7')
        sop_instance = (self._file_meta_uid(0x00020003)
                        or self._rendered_uid(body, TAG_SOP_INSTANCE_UID)
                        or '1.2.826.0.1.3680043.10.543.1')
        elements = [
            (0x00020001, 'OB', b'\x00\x01'),
            (0x00020002, 'UI', sop_class),
            (0x00020003, 'UI', sop_instance),
            (0x00020010, 'UI', self.carrier.transfer_syntax),
        ]
        meta = b''.join(
            Element.raw(tag, vr, _encode_value_bytes(value, vr)).encode(
                implicit_vr=False, little_endian=True)
            for tag, vr, value in elements)
        group_length = Element.raw(
            0x00020000, 'UL', struct.pack('<I', len(meta))).encode(
                implicit_vr=False, little_endian=True)
        return group_length + meta

    def _rendered_uid(self, body: bytes, tag: int) -> Optional[str]:
        """Read one UID out of a rendered Data Set, in the carrier's encoding."""
        elements, _tail = scan_dataset(body, self.carrier.implicit_vr,
                                       self.carrier.little_endian)
        for elem in elements:
            if elem.tag == tag:
                return _uid_from_bytes(body[elem.value_start:elem.end])
        return None

    def _file_meta_uid(self, tag: int) -> Optional[str]:
        """A group-0002 UID this edit set, if it set one."""
        encoded = self._file_meta.get(tag)
        if not encoded:
            return None
        header = 8 if encoded[4:6] not in _LONG_FORM_VRS else 12
        return _uid_from_bytes(encoded[header:])


def split_encapsulated(value: bytes, little_endian: bool = True):
    """Split an encapsulated Pixel Data value into its parts.

    Returns ``(basic_offset_table, fragments, delimiter)``: the first Item
    (PS3.5 Annex A.4 reserves it for the Basic Offset Table, and it is allowed
    to be empty), the fragment Items after it as whole encoded Items, and the
    closing Sequence Delimitation Item if one is present.

    Returns ``None`` when the value is not a fragment stream, which is the
    caller's cue to leave it alone rather than guess.
    """
    tag_fmt = '<HH' if little_endian else '>HH'
    len_fmt = '<I' if little_endian else '>I'
    items: List[bytes] = []
    delimiter = b''
    pos = 0
    end = len(value)
    while pos + 8 <= end:
        group, element = struct.unpack_from(tag_fmt, value, pos)
        tag = (group << 16) | element
        length = struct.unpack_from(len_fmt, value, pos + 4)[0]
        if tag == TAG_SEQUENCE_DELIMITER:
            delimiter = value[pos:pos + 8]
            pos += 8
            break
        if tag != TAG_ITEM or length == UNDEFINED_LENGTH:
            return None
        item_end = pos + 8 + length
        if item_end > end:
            return None
        items.append(value[pos:item_end])
        pos = item_end
    if pos != end or not items:
        return None
    return items[0], items[1:], delimiter


def encapsulate_items(basic_offset_table: bytes, fragments: List[bytes],
                      delimiter: bytes) -> bytes:
    """Reassemble an encapsulated Pixel Data value from its parts."""
    return basic_offset_table + b''.join(fragments) + delimiter


def empty_basic_offset_table(little_endian: bool = True) -> bytes:
    """A zero-length Basic Offset Table Item.

    Legal, and the honest thing to write once the fragment run has changed:
    an offset table whose entries no longer point at frame boundaries is worse
    than none at all, and PS3.5 A.4 says an empty one means the offsets are
    simply not provided.
    """
    tag_fmt = '<HH' if little_endian else '>HH'
    len_fmt = '<I' if little_endian else '>I'
    return (struct.pack(tag_fmt, 0xFFFE, 0xE000) + struct.pack(len_fmt, 0))


def _encode_value_bytes(value, vr: str) -> bytes:
    """Turn a Python value into value bytes for ``vr``, padded, never checked."""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        # latin-1 keeps every byte 0x00-0xFF addressable, which matters for
        # payloads that carry an embedded NUL or high-byte filler. Anything
        # outside it is a genuinely non-8-bit string; fall back to UTF-8 so the
        # value still reaches the wire.
        try:
            raw = value.encode('latin-1')
        except UnicodeEncodeError:
            raw = value.encode('utf-8')
    elif value is None:
        raw = b''
    else:
        raw = str(value).encode('ascii', errors='replace')
    return pad_to_even(raw, vr)


def merge_dataset(edit: CarrierEdit, blob: bytes, *, implicit_vr: bool,
                  little_endian: bool, label: str = 'merge',
                  skip: Optional[Callable[['CarrierElement', bytes], bool]]
                  = None) -> Tuple[int, int, int]:
    """Fold a whole attack Data Set into a carrier, element by element.

    ``skip`` is asked about each element before it is spliced; returning True
    leaves whatever the carrier already had. It exists for elements an attack
    carries only because every Data Set needs them -- placeholder identifiers
    -- which would otherwise overwrite the per-delivery identity the carrier
    was stamped with and let two attacks collide on one stored instance.

    Returns ``(merged, skipped, appended)``: elements spliced in, elements the
    predicate declined, and bytes appended because they did not scan as
    elements. The appended remainder is the honest answer for a payload whose
    malformation is the element stream itself -- a truncated header, a
    delimiter with no sequence -- which has no per-element position to occupy.
    """
    elements, tail = scan_dataset(blob, implicit_vr, little_endian)
    merged = 0
    skipped = 0
    for elem in elements:
        value = blob[elem.value_start:elem.end]
        if skip is not None and skip(elem, value):
            skipped += 1
            continue
        edit.merge_element(elem, value, from_implicit=implicit_vr,
                           from_little=little_endian, label=label)
        merged += 1
    remainder = blob[tail:]
    if remainder:
        edit.append_raw(remainder, f'{label}_tail')
    return merged, skipped, len(remainder)
