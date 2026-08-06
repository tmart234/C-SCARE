# SPDX-License-Identifier: GPL-2.0-only
"""Structural machinery for DICOM/PE polyglots (CVE-2019-11687).

CVE-2019-11687 is not a parser bug. Two PS3.10/PS3.5 provisions, both
mandatory, compose into a file that is simultaneously a conformant DICOM
object and a structurally valid Windows PE:

  * **Property 1 - the ignored preamble.** The first 128 bytes carry no
    semantics and parsers must not constrain them (PS3.10 §7.1), so an MZ
    DOS header fits there whole.
  * **Property 2 - the opaque private element.** Private (odd-group) data
    elements with VR ``OB`` hold up to 2^32-1 bytes that conforming parsers
    traverse without inspecting (PS3.5), which is enough room to park the
    PE image the preamble's ``e_lfanew`` points at.

This module supplies the three pieces C-SCARE needs to work with that
construction: PE image synthesis with the header fixups relocation forces
(:func:`pe_image`), enumeration of the regions of a Part-10 file that can
carry foreign bytes (:func:`enumerate_safe_zones`), and dual-pipeline
validation that a built artefact really is valid in both formats
(:func:`validate_polyglot`).

Everything here is deliberately **inert**. :func:`pe_image` emits correct PE
geometry - aligned headers, a resident section, in-bounds directories - and
nothing else: the section is zero-filled, marked read-only rather than
executable, and ``AddressOfEntryPoint`` is left at 0, so the image cannot run
even if a loader accepted it. That is the property a detector has to key on,
and it is what these payloads exercise. Synthesising an executable image is
not in scope for a test framework.

Structure of a built polyglot::

    0x00  MZ DOS header      <- Property 1 (preamble, bytes 0x00-0x3F)
    0x3C    e_lfanew --------+  points past DICM at the PE signature
    0x40  DOS stub           |  <- safe zone 2, never executed
    0x80  "DICM"             |
    0x84  File Meta group    |
    ....  private (gggg,eeee) OB header
    ....    alignment pad    |  4-byte align e_lfanew (ARM64 emulation)
    ....    PE signature <---+  <- Property 2 (private element value)
    ....    COFF + Optional + section headers
    ....    pad to SizeOfHeaders, then section data
    ....  rest of the Data Set
"""

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

import pydicom

from .element import VR

__all__ = [
    'SafeZone',
    'FILE_ALIGNMENT',
    'SECTION_ALIGNMENT',
    'PREAMBLE_LEN',
    'dos_header',
    'pe_image',
    'dataset_offset',
    'enumerate_safe_zones',
    'validate_pe',
    'validate_dicom',
    'validate_polyglot',
]

PREAMBLE_LEN = 128
DOS_HEADER_LEN = 64          # bytes 0x00-0x3F of the preamble
E_LFANEW_OFFSET = 0x3C       # PE-header pointer inside the DOS header

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000

EXPLICIT_VR_LE = '1.2.840.10008.1.2.1'

_KNOWN_VRS = frozenset(str(vr) for vr in pydicom.valuerep.STANDARD_VR)

# COFF Characteristics
_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
_IMAGE_FILE_32BIT_MACHINE = 0x0100

# Section Characteristics: initialised data, read-only. Deliberately *not*
# IMAGE_SCN_MEM_EXECUTE - see the module docstring.
_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
_IMAGE_SCN_MEM_READ = 0x40000000

_MACHINE = {32: 0x014C, 64: 0x8664}          # i386, AMD64
_OPT_MAGIC = {32: 0x010B, 64: 0x020B}        # PE32, PE32+
_OPT_HEADER_LEN = {32: 224, 64: 240}
_COFF_LEN = 20
_SECTION_HEADER_LEN = 40
_NUM_DATA_DIRECTORIES = 16


def _align_up(value: int, alignment: int) -> int:
    return -(-value // alignment) * alignment


# ---------------------------------------------------------------------------
# PE synthesis
# ---------------------------------------------------------------------------

def dos_header(e_lfanew: int) -> bytes:
    """A 64-byte MZ DOS header whose PE pointer is ``e_lfanew``.

    Only the two fields a PE loader actually consults on a modern Windows are
    set: the ``MZ`` magic and ``e_lfanew``. The remaining 58 bytes are the
    usable capacity of safe zone 1.
    """
    header = bytearray(DOS_HEADER_LEN)
    header[0:2] = b'MZ'
    struct.pack_into('<I', header, E_LFANEW_OFFSET, e_lfanew)
    return bytes(header)


def pe_image(pe_offset: int, bits: int = 64, section_size: int = 0x200,
             section_name: bytes = b'.pad') -> bytes:
    """Build the PE half of a polyglot, to be placed at ``pe_offset``.

    Returns the bytes from the PE signature through the end of the section
    data. The caller writes them at ``pe_offset`` in a file whose DOS header
    sits at offset 0 with ``e_lfanew == pe_offset``; the result is a single
    file that satisfies both a PE loader's structural checks and a DICOM
    reader.

    Relocating the PE headers away from offset 0x40 - which is what embedding
    them behind ``DICM``, the File Meta group and a private element header
    does - forces the header fixups the format otherwise gets for free:

    1. ``SizeOfHeaders`` must still span offset 0 through the end of the
       section headers, so it grows by the relocation delta.
    2. ``PointerToRawData`` must stay at or past ``SizeOfHeaders`` and
       ``FileAlignment``-aligned, so section data shifts with it.
    3. The gap between the section headers and the section data is
       zero-padded up to that boundary.
    4. ``IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`` is cleared: the image has no
       base relocation directory, and the ARM64 emulation loader refuses an
       ASLR-marked image it cannot relocate.

    ``pe_offset`` should be 4-byte aligned. The x86 and x86-64 loaders tolerate
    a misaligned PE signature; the ARM64 emulation layer does not.
    """
    if bits not in _OPT_MAGIC:
        raise ValueError(f'bits must be 32 or 64, got {bits}')

    opt_len = _OPT_HEADER_LEN[bits]
    headers_end = (pe_offset + 4 + _COFF_LEN + opt_len + _SECTION_HEADER_LEN)
    size_of_headers = _align_up(headers_end, FILE_ALIGNMENT)
    pointer_to_raw_data = size_of_headers
    size_of_raw_data = _align_up(section_size, FILE_ALIGNMENT)

    virtual_address = SECTION_ALIGNMENT
    size_of_image = _align_up(virtual_address + section_size, SECTION_ALIGNMENT)

    characteristics = _IMAGE_FILE_EXECUTABLE_IMAGE | (
        _IMAGE_FILE_LARGE_ADDRESS_AWARE if bits == 64
        else _IMAGE_FILE_32BIT_MACHINE)

    coff = struct.pack('<HHIIIHH',
                       _MACHINE[bits],
                       1,                 # NumberOfSections
                       0,                 # TimeDateStamp
                       0,                 # PointerToSymbolTable
                       0,                 # NumberOfSymbols
                       opt_len,
                       characteristics)

    if bits == 64:
        optional = struct.pack(
            '<HBBIIIIIQIIHHHHHHIIIIHHQQQQII',
            _OPT_MAGIC[64], 0, 0,
            size_of_raw_data,             # SizeOfCode
            0, 0,                         # SizeOf{Initialized,Uninitialized}Data
            0,                            # AddressOfEntryPoint - no entry point
            virtual_address,              # BaseOfCode
            0x0000000140000000,           # ImageBase
            SECTION_ALIGNMENT, FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0,             # OS / image / subsystem versions
            0,                            # Win32VersionValue
            size_of_image, size_of_headers,
            0,                            # CheckSum
            3,                            # Subsystem: WINDOWS_CUI
            0,                            # DllCharacteristics - ASLR stripped
            0x100000, 0x1000, 0x100000, 0x1000,
            0,                            # LoaderFlags
            _NUM_DATA_DIRECTORIES)
    else:
        optional = struct.pack(
            '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
            _OPT_MAGIC[32], 0, 0,
            size_of_raw_data,
            0, 0,
            0,
            virtual_address,              # BaseOfCode
            virtual_address,              # BaseOfData
            0x00400000,                   # ImageBase
            SECTION_ALIGNMENT, FILE_ALIGNMENT,
            6, 0, 0, 0, 6, 0,
            0,
            size_of_image, size_of_headers,
            0,
            3,
            0,
            0x100000, 0x1000, 0x100000, 0x1000,
            0,
            _NUM_DATA_DIRECTORIES)

    optional += b'\x00' * (8 * _NUM_DATA_DIRECTORIES)
    assert len(optional) == opt_len, (len(optional), opt_len)

    section = struct.pack('<8sIIIIIIHHI',
                          section_name[:8].ljust(8, b'\x00'),
                          section_size,          # VirtualSize
                          virtual_address,
                          size_of_raw_data,
                          pointer_to_raw_data,
                          0, 0, 0, 0,            # relocations / line numbers
                          _IMAGE_SCN_CNT_INITIALIZED_DATA | _IMAGE_SCN_MEM_READ)

    headers = b'PE\x00\x00' + coff + optional + section
    padding = b'\x00' * (size_of_headers - headers_end)
    return headers + padding + b'\x00' * size_of_raw_data


# ---------------------------------------------------------------------------
# Safe-zone enumeration
# ---------------------------------------------------------------------------

@dataclass
class SafeZone:
    """A region of a Part-10 file that can carry bytes no parser inspects.

    ``usable`` is the payload capacity, which differs from ``length`` where
    part of the region is spoken for (the MZ magic and ``e_lfanew`` in the DOS
    header) or where the region is an insertion point rather than existing
    slack (a private element, bounded by the 32-bit length field).
    """
    kind: str
    offset: int
    length: int
    usable: int
    note: str


def dataset_offset(data: bytes) -> Optional[int]:
    """Offset of the first Data Set element, from the File Meta group length.

    Everything before this point is structure a DICOM reader parses; everything
    from here on it only traverses. ``None`` if ``data`` is not a Part-10 file
    or its File Meta group does not lead with (0002,0000) Group Length.
    """
    if len(data) < 144 or data[PREAMBLE_LEN:PREAMBLE_LEN + 4] != b'DICM':
        return None
    meta_start = PREAMBLE_LEN + 4
    if data[meta_start:meta_start + 4] != b'\x02\x00\x00\x00':
        return None  # (0002,0000) Group Length must lead the File Meta group
    group_length = struct.unpack('<I', data[meta_start + 8:meta_start + 12])[0]
    start = meta_start + 12 + group_length
    return start if start <= len(data) else None


def _transfer_syntax(data: bytes) -> Optional[str]:
    """(0002,0010) from the File Meta group, which is always Explicit VR LE."""
    for tag, _vr, value_offset, length in _walk_explicit_vr_le(data,
                                                              PREAMBLE_LEN + 4):
        if tag == (0x0002, 0x0010):
            value = data[value_offset:value_offset + length]
            return value.rstrip(b'\x00 ').decode('ascii', errors='replace')
        if tag[0] != 0x0002:
            return None
    return None


def _walk_explicit_vr_le(data: bytes, start: int):
    """Yield ``(tag, vr, value_offset, value_length)`` for top-level elements.

    Stops at the first element it cannot advance past - an undefined length, a
    sequence, or a truncated header - because from that point the offsets it
    would report are guesses.

    An unrecognised VR also stops the walk, and that is what distinguishes the
    end of the Data Set from whatever follows it: Part-10 has no end marker, so
    appended bytes are only identifiable as non-DICOM by failing to decode as
    an element. A DICOM reader stops there too, which is precisely why the
    region past that point is a safe zone.
    """
    pos = start
    while pos + 8 <= len(data):
        group, element = struct.unpack('<HH', data[pos:pos + 4])
        vr = data[pos + 4:pos + 6].decode('ascii', errors='replace')
        if vr == 'SQ' or vr not in _KNOWN_VRS:
            return
        if VR.uses_long_length(vr):
            if pos + 12 > len(data):
                return
            length = struct.unpack('<I', data[pos + 8:pos + 12])[0]
            value_offset = pos + 12
        else:
            length = struct.unpack('<H', data[pos + 6:pos + 8])[0]
            value_offset = pos + 8
        if length == 0xFFFFFFFF or value_offset + length > len(data):
            return
        yield (group, element), vr, value_offset, length
        pos = value_offset + length


def enumerate_safe_zones(data: bytes) -> List[SafeZone]:
    """Enumerate the regions of ``data`` that can host foreign content.

    Covers the five zone types the format admits: the preamble's DOS-header
    and DOS-stub halves, an insertable private element after the File Meta
    group, padding slack inside existing Data Elements, and trailing bytes
    after the final element.

    Data Set walking handles top-level Explicit VR Little Endian elements. On
    any other transfer syntax, or once a sequence or undefined length is
    reached, only the zones established up to that point are returned - the
    preamble zones always are, since they precede any encoding choice.
    """
    zones: List[SafeZone] = []
    if len(data) < PREAMBLE_LEN + 4 or data[PREAMBLE_LEN:PREAMBLE_LEN + 4] != b'DICM':
        return zones

    zones.append(SafeZone(
        kind='preamble_dos_header', offset=0, length=DOS_HEADER_LEN,
        usable=DOS_HEADER_LEN - 2 - 4,
        note='preamble bytes 0x00-0x3F; the MZ magic (2) and e_lfanew (4) are '
             'spoken for, the rest is free'))
    zones.append(SafeZone(
        kind='preamble_dos_stub', offset=DOS_HEADER_LEN,
        length=PREAMBLE_LEN - DOS_HEADER_LEN,
        usable=PREAMBLE_LEN - DOS_HEADER_LEN,
        note='preamble bytes 0x40-0x7F; the DOS stub never executes in '
             'protected mode, so it is fully replaceable'))

    start = dataset_offset(data)
    if start is None:
        return zones

    zones.append(SafeZone(
        kind='private_element', offset=start, length=0,
        usable=0xFFFFFFFE,
        note='insertion point for a private (odd-group) OB element; '
             'conforming parsers traverse the value without inspecting it, '
             'and the 32-bit length field bounds it at 2^32-2 even bytes'))

    if _transfer_syntax(data) != EXPLICIT_VR_LE:
        return zones

    end_of_dataset = start
    for tag, vr, value_offset, length in _walk_explicit_vr_le(data, start):
        end_of_dataset = value_offset + length
        value = data[value_offset:value_offset + length]
        content = value.rstrip(b'\x00 ')
        pad = length - len(content)
        if pad:
            zones.append(SafeZone(
                kind='element_padding', offset=value_offset + len(content),
                length=pad, usable=pad,
                note=f'padding slack inside ({tag[0]:04X},{tag[1]:04X}) {vr}; '
                     'the declared length covers it but the value ends before '
                     'it, so a reader consumes it without looking at it'))

    zones.append(SafeZone(
        kind='trailing', offset=end_of_dataset,
        length=len(data) - end_of_dataset,
        usable=len(data) - end_of_dataset,
        note='bytes after the final Data Element; readers stop at the end of '
             'the Data Set and never reach them'))
    return zones


# ---------------------------------------------------------------------------
# Dual-pipeline validation
# ---------------------------------------------------------------------------

def validate_pe(data: bytes) -> List[str]:
    """Structural PE validation. Returns problems; empty means valid.

    Checks what a loader checks before it maps anything: MZ magic, an in-bounds
    ``e_lfanew``, the PE signature, COFF and Optional headers resident in the
    file, and every section ``FileAlignment``-aligned with its raw data fully
    present. It says nothing about whether the image would *run*.
    """
    problems: List[str] = []
    if data[:2] != b'MZ':
        return ['no MZ magic at offset 0']
    if len(data) < E_LFANEW_OFFSET + 4:
        return ['file too short to hold e_lfanew']

    e_lfanew = struct.unpack('<I', data[E_LFANEW_OFFSET:E_LFANEW_OFFSET + 4])[0]
    if e_lfanew + 4 + _COFF_LEN > len(data):
        return [f'e_lfanew={e_lfanew} points past the end of the file']
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return [f'no PE signature at e_lfanew={e_lfanew}: '
                f'{data[e_lfanew:e_lfanew + 4]!r}']
    if e_lfanew % 4:
        problems.append(f'e_lfanew={e_lfanew} is not 4-byte aligned; the ARM64 '
                        'emulation loader rejects it')

    coff_offset = e_lfanew + 4
    (_machine, num_sections, _stamp, _sym, _nsym, opt_len,
     _characteristics) = struct.unpack('<HHIIIHH',
                                       data[coff_offset:coff_offset + _COFF_LEN])
    opt_offset = coff_offset + _COFF_LEN
    sections_offset = opt_offset + opt_len
    if sections_offset + num_sections * _SECTION_HEADER_LEN > len(data):
        problems.append('section headers extend past the end of the file')
        return problems
    if opt_len < 2:
        problems.append('SizeOfOptionalHeader too small to hold a magic value')
        return problems

    magic = struct.unpack('<H', data[opt_offset:opt_offset + 2])[0]
    if magic not in _OPT_MAGIC.values():
        problems.append(f'unknown Optional Header magic 0x{magic:04X}')

    # SizeOfHeaders lands at the same offset in both layouts: PE32+ widens
    # ImageBase to 8 bytes, and PE32 spends the same 4 bytes on BaseOfData.
    size_of_headers_offset = opt_offset + 60
    size_of_headers = struct.unpack(
        '<I', data[size_of_headers_offset:size_of_headers_offset + 4])[0]
    if size_of_headers < sections_offset + num_sections * _SECTION_HEADER_LEN:
        problems.append(f'SizeOfHeaders={size_of_headers} does not span the '
                        'section headers')

    for i in range(num_sections):
        base = sections_offset + i * _SECTION_HEADER_LEN
        (name, _vsize, _rva, size_of_raw, ptr_raw,
         _r1, _r2, _n1, _n2, _flags) = struct.unpack(
            '<8sIIIIIIHHI', data[base:base + _SECTION_HEADER_LEN])
        label = name.rstrip(b'\x00').decode('ascii', errors='replace')
        if size_of_raw == 0:
            continue  # uninitialised data has no file presence to check
        if ptr_raw % FILE_ALIGNMENT:
            problems.append(f'section {label!r} PointerToRawData={ptr_raw} is '
                            f'not FileAlignment-aligned')
        if ptr_raw + size_of_raw > len(data):
            problems.append(f'section {label!r} raw data runs past the end of '
                            'the file')
    return problems


def validate_dicom(data: bytes) -> List[str]:
    """Structural Part-10 validation. Returns problems; empty means valid."""
    problems: List[str] = []
    if len(data) <= PREAMBLE_LEN + 4:
        return ['file too short to hold a preamble and DICM magic']
    if data[PREAMBLE_LEN:PREAMBLE_LEN + 4] != b'DICM':
        return [f'no DICM magic at offset {PREAMBLE_LEN}']
    if data.index(b'DICM') != PREAMBLE_LEN:
        problems.append('DICM appears before offset 128; the preamble is not '
                        'exactly 128 bytes')
    try:
        from io import BytesIO
        dataset = pydicom.dcmread(BytesIO(data), force=False)
    except Exception as exc:
        problems.append(f'pydicom cannot read the file: {exc}')
        return problems
    if 'TransferSyntaxUID' not in dataset.file_meta:
        problems.append('File Meta group has no (0002,0010) Transfer Syntax UID')
    if not len(dataset):
        problems.append('Data Set is empty')
    return problems


def validate_polyglot(data: bytes) -> Dict[str, List[str]]:
    """Run both validation pipelines. Empty lists on both sides means the file
    is simultaneously a valid PE and a valid DICOM object."""
    return {'pe': validate_pe(data), 'dicom': validate_dicom(data)}
