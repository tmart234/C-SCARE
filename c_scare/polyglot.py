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

This module supplies the pieces C-SCARE needs to work with that construction:
image synthesis for each of the three executable formats with the header
fixups relocation forces (:func:`pe_image`, :func:`elf_image`,
:func:`macho_image`), splitting one image across several non-adjacent regions
(:func:`pe_fragments`), enumeration of the regions of a Part-10 file that can
carry foreign bytes (:func:`enumerate_safe_zones`), content shaping so a
payload's byte statistics do not give it away (:func:`filler`), and
dual-pipeline validation that a built artefact really is valid in both formats
(:func:`validate_polyglot`).

Everything here is deliberately **inert**. The image builders emit correct
geometry - aligned headers, resident sections, in-bounds directories - and
nothing else: sections are filled with data rather than code, marked readable
rather than executable, and the entry point is left at 0, so an image cannot
run even if a loader accepted it. That is the property a detector has to key
on, and it is what these payloads exercise. Synthesising an executable image is
not in scope for a test framework.

**The three formats are not interchangeable.** PE is the only one whose entire
header block relocates: ``e_lfanew`` is a free file offset, so everything from
the PE signature onwards can live in a private element. ELF fixes its 64-byte
``Elf64_Ehdr`` at offset 0 and relocates only what ``e_phoff`` points at, and
its ``PT_LOAD`` segments want ``p_offset`` congruent to ``p_vaddr`` modulo
``p_align`` rather than absolutely aligned the way PE's ``PointerToRawData``
is. Mach-O relocates least of all: load commands must sit contiguously behind
``mach_header_64``, which caps a preamble-resident Mach-O at
``128 - 32 = 96`` bytes of load commands - room for one section-less
``LC_SEGMENT_64`` (72 bytes) and not one byte more, since a single
``section_64`` adds 80. Only segment *contents* relocate. Treating the three
as equivalent produces payloads that are valid PE reasoning applied to a
format that does not work that way, so each builder documents the constraint
it is actually subject to.

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

import hashlib
import math
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

import pydicom

from .element import VR

__all__ = [
    'SafeZone',
    'PESection',
    'FILE_ALIGNMENT',
    'SECTION_ALIGNMENT',
    'PREAMBLE_LEN',
    'FILL_PROFILES',
    'align_up',
    'shannon_entropy',
    'filler',
    'dos_header',
    'dos_stub',
    'pe_image',
    'pe_fragments',
    'pe_headers_len',
    'elf_header',
    'elf_image',
    'macho_header',
    'macho_image',
    'dataset_offset',
    'enumerate_safe_zones',
    'executable_format',
    'validate_pe',
    'validate_elf',
    'validate_macho',
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

# --- ELF -------------------------------------------------------------------
ELF_MAGIC = b'\x7fELF'
ELF_HEADER_LEN = {32: 52, 64: 64}            # Elf32_Ehdr / Elf64_Ehdr
ELF_PHDR_LEN = {32: 32, 64: 56}              # Elf32_Phdr / Elf64_Phdr
ELF_PAGE_SIZE = 0x1000
ELF_IMAGE_BASE = 0x00400000

_ELFCLASS = {32: 1, 64: 2}                   # EI_CLASS
_ELFDATA2LSB = 1                             # EI_DATA: two's complement, LE
_EV_CURRENT = 1
_ET_EXEC = 2
_ET_DYN = 3
_EM = {32: 0x03, 64: 0x3E}                   # EM_386, EM_X86_64
_PT_LOAD = 1
_PF_R = 4                                    # deliberately not PF_X (1)

# --- Mach-O ----------------------------------------------------------------
MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
MACHO_HEADER_LEN = {32: 28, 64: 32}          # mach_header / mach_header_64
SEGMENT_COMMAND_64_LEN = 72
SECTION_64_LEN = 80

# Page size the kernel enforces on segment addresses, per architecture. arm64
# is 16 KiB, which is why a vmaddr that is legal for x86-64 is not for arm64.
MACHO_PAGE_SIZE = {'arm64': 0x4000, 'x86_64': 0x1000}
_CPU_TYPE = {'arm64': 0x0100000C, 'x86_64': 0x01000007}
_CPU_SUBTYPE = {'arm64': 0x00000000, 'x86_64': 0x00000003}
_MH_EXECUTE = 2
_MH_DYLIB = 6
_MH_BUNDLE = 8
_LC_SEGMENT_64 = 0x19
_VM_PROT_READ = 1                            # deliberately not VM_PROT_EXECUTE


def align_up(value: int, alignment: int) -> int:
    """Round ``value`` up to the next multiple of ``alignment``."""
    return -(-value // alignment) * alignment


# ---------------------------------------------------------------------------
# Content shaping
# ---------------------------------------------------------------------------
#
# Zero-filling a section is free and structurally correct, and it is also the
# most distinctive byte profile a file can have: a run of thousands of NULs
# inside an image is not something a compiler emits. A payload built to
# benchmark a detector should not hand the answer over in its histogram, so
# the image builders take a ``fill`` profile and these produce the bytes.
#
# All four are deterministic in ``seed`` - the same arguments give the same
# bytes on every run and every platform, so payloads stay reproducible and
# diffable. None of them is code: 'packed' is a SHA-256 keystream, which is
# noise with the entropy of compressed data and the semantics of nothing.

FILL_PROFILES = ('zeros', 'tabular', 'strings', 'packed')

# Neutral, obviously-synthetic strings that give 'strings' the ~4.5 bits/byte
# profile of a real read-only string table. Nothing here imitates a Windows
# API import list - the point is to look ordinary, not to look capable.
_FILL_VOCAB = (
    b'C-SCARE structural test image',
    b'CVE-2019-11687 polyglot test case',
    b'This section contains data, not code',
    b'Secondary Capture Image Storage',
    b'1.2.840.10008.5.1.4.1.1.7',
    b'1.2.840.10008.1.2.1',
    b'vendor configuration block',
    b'InitializeConfiguration',
    b'ReadVendorParameters',
    b'ReleaseConfiguration',
    b'parameter table revision %u',
    b'calibration=%s offset=%d',
    b'unable to open configuration',
    b'default',
    b'enabled',
    b'disabled',
)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits per byte, 0.0 for empty input.

    Used to verify that a shaped payload landed in the profile it was asked
    for. Note the ceiling is ``log2(len(data))`` when the input is shorter
    than 256 bytes, so a short high-entropy buffer cannot reach 8.0.
    """
    if not data:
        return 0.0
    total = len(data)
    # max(0.0, ...) only to turn the -0.0 a single-symbol input produces into
    # a plain zero; entropy cannot otherwise be negative.
    return max(0.0, -sum((count / total) * math.log2(count / total)
                         for count in Counter(data).values()))


def _fill_zeros(length: int, seed: int) -> bytes:
    return b'\x00' * length


def _fill_tabular(length: int, seed: int) -> bytes:
    """Fixed-width records with mostly-zero high bytes - ~2.5 bits/byte.

    The profile of a relocation or import table: structured, repetitive, and
    low entropy without being a single repeated byte. The index is masked to
    8 bits so the record set repeats rather than growing new byte values,
    which keeps the entropy of the profile independent of how much of it is
    asked for.
    """
    out = bytearray()
    index = seed
    while len(out) < length:
        page = index & 0xFF
        out += struct.pack('<IHH', page * 0x1000, page, 0)
        index += 1
    return bytes(out[:length])


def _fill_strings(length: int, seed: int) -> bytes:
    """NUL-terminated printable strings - ~4.5 bits/byte, like ``.rdata``."""
    out = bytearray()
    index = seed
    while len(out) < length:
        out += _FILL_VOCAB[index % len(_FILL_VOCAB)] + b'\x00'
        index += 1
    return bytes(out[:length])


def _fill_packed(length: int, seed: int) -> bytes:
    """A SHA-256 keystream - the ~8 bits/byte profile of packed data.

    Chosen over ``random`` so the bytes do not depend on a PRNG whose
    implementation is free to change between Python versions.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(struct.pack('<QQ', seed, counter)).digest()
        counter += 1
    return bytes(out[:length])


_FILLERS = {
    'zeros': _fill_zeros,
    'tabular': _fill_tabular,
    'strings': _fill_strings,
    'packed': _fill_packed,
}


def filler(profile: str, length: int, seed: int = 0) -> bytes:
    """``length`` bytes of inert content with the byte profile ``profile``.

    One of :data:`FILL_PROFILES`, in ascending entropy: ``zeros`` (0.0),
    ``tabular`` (~2), ``strings`` (~4.5), ``packed`` (~8).
    """
    if profile not in _FILLERS:
        raise ValueError(f'unknown fill profile {profile!r}; '
                         f'expected one of {", ".join(FILL_PROFILES)}')
    if length < 0:
        raise ValueError(f'length must be non-negative, got {length}')
    return _FILLERS[profile](length, seed)


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


def dos_stub(message: bytes = b'This program cannot be run in DOS mode.\r\r\n$',
             length: int = PREAMBLE_LEN - DOS_HEADER_LEN) -> bytes:
    """A conventional-looking DOS stub for preamble bytes 0x40-0x7F.

    Every PE a compiler emits carries this string here, so a preamble that is
    an MZ header followed by 64 NULs is itself a tell - a scanner or a triage
    analyst spots the anomaly without parsing anything. This fills the zone
    with what a real image has there.

    The 14 bytes of 16-bit real-mode code that normally *print* the message
    are deliberately omitted: the stub is the string alone. A DOS loader
    entering at ``e_cs:e_ip`` would find data, and this module does not emit
    executable code even for a processor mode nothing has run in decades.
    """
    return message[:length].ljust(length, b'\x00')


def pe_headers_len(bits: int = 64, sections: int = 1) -> int:
    """Byte length of the PE header block: signature, COFF, Optional header
    and the section table.

    Laying a fragmented polyglot out needs this before any offset is known:
    the carrier element's declared length depends on the header size, and
    every section offset depends on where that carrier ends.
    """
    if bits not in _OPT_HEADER_LEN:
        raise ValueError(f'bits must be 32 or 64, got {bits}')
    return (4 + _COFF_LEN + _OPT_HEADER_LEN[bits] +
            sections * _SECTION_HEADER_LEN)


@dataclass
class PESection:
    """One section of a synthesised PE and where its raw data lands.

    ``file_offset`` is what goes in ``PointerToRawData``, which the format
    lets the builder choose freely as long as it is ``FileAlignment``-aligned
    and clear of the headers. That freedom is what makes a PE fragmentable:
    sections do not have to follow the headers, or each other, or be
    contiguous with anything.
    """
    name: bytes
    size: int
    file_offset: int


def pe_fragments(pe_offset: int, placements: Sequence[Tuple[int, int]],
                 bits: int = 64, names: Optional[Sequence[bytes]] = None,
                 fill: str = 'zeros', seed: int = 0
                 ) -> Tuple[bytes, List[bytes]]:
    """Build a PE whose sections live at caller-chosen file offsets.

    ``placements`` is a sequence of ``(file_offset, size)``, one per section.
    Returns ``(headers, [section_data, ...])``: the headers go at
    ``pe_offset``, and section *i* goes at ``placements[i][0]``. Nothing is
    concatenated for the caller, because the whole point is that these pieces
    do not end up adjacent - the bytes between them are DICOM structure.

    This is the §5.1 fragmentation primitive. A signature written over a
    contiguous PE image does not match a file where the headers sit in a
    private element, one section's data in another element's padding tail and
    the next past the end of the Data Set, yet the loader reassembles it
    without complaint because ``PointerToRawData`` was always just a file
    offset. No executable content is involved - the evasion is the layout.

    Every offset must be ``FileAlignment``-aligned and at or past
    ``SizeOfHeaders``, which is measured from file offset 0 and so grows with
    the relocation delta. Both are checked here rather than left to produce a
    file the loader quietly rejects.
    """
    if bits not in _OPT_MAGIC:
        raise ValueError(f'bits must be 32 or 64, got {bits}')
    if not placements:
        raise ValueError('a PE needs at least one section')
    if names is None:
        names = [b'.rdata%d' % i if i else b'.rdata'
                 for i in range(len(placements))]
    if len(names) != len(placements):
        raise ValueError(f'got {len(names)} names for {len(placements)} '
                         'sections')

    opt_len = _OPT_HEADER_LEN[bits]
    headers_end = (pe_offset + 4 + _COFF_LEN + opt_len +
                   len(placements) * _SECTION_HEADER_LEN)
    size_of_headers = align_up(headers_end, FILE_ALIGNMENT)

    sections: List[PESection] = []
    for (file_offset, size), name in zip(placements, names):
        if file_offset % FILE_ALIGNMENT:
            raise ValueError(f'section {name!r} at {file_offset} is not '
                             f'FileAlignment({FILE_ALIGNMENT})-aligned')
        if file_offset < size_of_headers:
            raise ValueError(f'section {name!r} at {file_offset} overlaps the '
                             f'headers, which run to SizeOfHeaders='
                             f'{size_of_headers}')
        sections.append(PESection(name, size, file_offset))

    # RVAs are assigned in order and stay contiguous in memory even though the
    # file offsets do not: the loader maps each section at its own RVA, so the
    # image is whole in memory and scattered on disk.
    virtual_address = SECTION_ALIGNMENT
    rvas = []
    for section in sections:
        rvas.append(virtual_address)
        virtual_address += align_up(section.size, SECTION_ALIGNMENT)
    size_of_image = align_up(virtual_address, SECTION_ALIGNMENT)
    size_of_initialized_data = sum(
        align_up(section.size, FILE_ALIGNMENT) for section in sections)

    characteristics = _IMAGE_FILE_EXECUTABLE_IMAGE | (
        _IMAGE_FILE_LARGE_ADDRESS_AWARE if bits == 64
        else _IMAGE_FILE_32BIT_MACHINE)

    coff = struct.pack('<HHIIIHH',
                       _MACHINE[bits],
                       len(sections),     # NumberOfSections
                       0,                 # TimeDateStamp
                       0,                 # PointerToSymbolTable
                       0,                 # NumberOfSymbols
                       opt_len,
                       characteristics)

    # SizeOfCode is 0 and BaseOfCode points at nothing: there is no section
    # marked IMAGE_SCN_CNT_CODE, so claiming otherwise would be a self-
    # contradiction a scanner could legitimately key on.
    if bits == 64:
        optional = struct.pack(
            '<HBBIIIIIQIIHHHHHHIIIIHHQQQQII',
            _OPT_MAGIC[64], 0, 0,
            0,                            # SizeOfCode - no code sections
            size_of_initialized_data,
            0,                            # SizeOfUninitializedData
            0,                            # AddressOfEntryPoint - no entry point
            0,                            # BaseOfCode
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
            0,                            # SizeOfCode
            size_of_initialized_data,
            0,
            0,                            # AddressOfEntryPoint
            0,                            # BaseOfCode
            rvas[0],                      # BaseOfData
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

    table = b''
    payloads = []
    for section, rva in zip(sections, rvas):
        size_of_raw_data = align_up(section.size, FILE_ALIGNMENT)
        table += struct.pack('<8sIIIIIIHHI',
                             section.name[:8].ljust(8, b'\x00'),
                             section.size,        # VirtualSize
                             rva,
                             size_of_raw_data,
                             section.file_offset,
                             0, 0, 0, 0,          # relocations / line numbers
                             _IMAGE_SCN_CNT_INITIALIZED_DATA |
                             _IMAGE_SCN_MEM_READ)
        payloads.append(filler(fill, size_of_raw_data, seed))

    return b'PE\x00\x00' + coff + optional + table, payloads


def pe_image(pe_offset: int, bits: int = 64, section_size: int = 0x200,
             section_name: bytes = b'.pad', fill: str = 'zeros',
             seed: int = 0) -> bytes:
    """Build the PE half of a polyglot, to be placed at ``pe_offset``.

    Returns the bytes from the PE signature through the end of the section
    data, contiguously - the single-section, single-region case of
    :func:`pe_fragments`. The caller writes them at ``pe_offset`` in a file
    whose DOS header sits at offset 0 with ``e_lfanew == pe_offset``; the
    result is a single file that satisfies both a PE loader's structural
    checks and a DICOM reader.

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

    ``fill`` shapes the section contents - see :func:`filler`. It defaults to
    ``'zeros'``, which is structurally correct and statistically conspicuous;
    pass something else when the payload is meant to survive a look at its
    histogram.
    """
    if bits not in _OPT_MAGIC:
        raise ValueError(f'bits must be 32 or 64, got {bits}')

    opt_len = _OPT_HEADER_LEN[bits]
    headers_end = pe_offset + 4 + _COFF_LEN + opt_len + _SECTION_HEADER_LEN
    size_of_headers = align_up(headers_end, FILE_ALIGNMENT)

    headers, (section_data,) = pe_fragments(
        pe_offset, [(size_of_headers, section_size)], bits=bits,
        names=[section_name], fill=fill, seed=seed)
    return headers + b'\x00' * (size_of_headers - headers_end) + section_data


# ---------------------------------------------------------------------------
# ELF synthesis
# ---------------------------------------------------------------------------

def elf_header(ph_offset: int = 0, ph_count: int = 0, bits: int = 64,
               entry: int = 0) -> bytes:
    """A complete ``Elf64_Ehdr`` (64 bytes) or ``Elf32_Ehdr`` (52 bytes).

    Unlike PE, this cannot be relocated: ``readelf``, the kernel's ``binfmt_elf``
    and every other reader take the ELF header to be at file offset 0, and
    there is no ``e_lfanew`` equivalent to say otherwise. What relocates is
    what ``e_phoff`` points at, so an ELF polyglot puts this header in the
    first 64 bytes of the DICOM preamble - which it fits exactly - and the
    program header table wherever :func:`elf_image` is placed.

    ``e_shoff`` is 0: section headers are link-time metadata that the loader
    never consults, so omitting them is legal for an executable and keeps the
    file honest about carrying no symbol or relocation data.

    ``entry`` defaults to 0, which makes the image inert - execution would
    transfer to an unmapped address 0 rather than to anything this module
    emitted.
    """
    if bits not in ELF_HEADER_LEN:
        raise ValueError(f'bits must be 32 or 64, got {bits}')

    e_ident = (ELF_MAGIC +
               bytes([_ELFCLASS[bits], _ELFDATA2LSB, _EV_CURRENT, 0, 0]) +
               b'\x00' * 7)               # EI_OSABI/ABIVERSION 0, EI_PAD
    assert len(e_ident) == 16, len(e_ident)

    if bits == 64:
        rest = struct.pack(
            '<HHIQQQIHHHHHH',
            _ET_EXEC, _EM[64], _EV_CURRENT,
            entry,                        # e_entry - no entry point
            ph_offset,                    # e_phoff - the relocatable pointer
            0,                            # e_shoff - no section headers
            0,                            # e_flags
            ELF_HEADER_LEN[64], ELF_PHDR_LEN[64], ph_count,
            0, 0, 0)                      # e_shentsize / e_shnum / e_shstrndx
    else:
        rest = struct.pack(
            '<HHIIIIIHHHHHH',
            _ET_EXEC, _EM[32], _EV_CURRENT,
            entry, ph_offset, 0, 0,
            ELF_HEADER_LEN[32], ELF_PHDR_LEN[32], ph_count,
            0, 0, 0)

    header = e_ident + rest
    assert len(header) == ELF_HEADER_LEN[bits], len(header)
    return header


def elf_image(ph_offset: int, bits: int = 64, segment_size: int = 0x200,
              fill: str = 'zeros', seed: int = 0,
              image_base: int = ELF_IMAGE_BASE) -> bytes:
    """Build the relocatable half of an ELF polyglot, for ``ph_offset``.

    Returns the program header table followed by the ``PT_LOAD`` segment it
    describes, to be written at ``ph_offset`` in a file whose ELF header sits
    at offset 0 with ``e_phoff == ph_offset``. The counterpart of
    :func:`pe_image`, with the differences the format forces:

    * **Alignment is a congruence, not a boundary.** PE demands
      ``PointerToRawData % FileAlignment == 0``. ELF demands only
      ``p_offset ≡ p_vaddr (mod p_align)`` - the segment may start at any file
      offset as long as the virtual address agrees with it modulo the page
      size. ``p_vaddr`` is chosen here to satisfy that for whatever
      ``ph_offset`` the DICOM layout produced, so an ELF payload needs no
      padding to reach an alignment boundary and a PE payload does.
    * **Field order differs by class.** ``Elf32_Phdr`` puts ``p_flags`` last
      and ``Elf64_Phdr`` puts it second, so a reader that handles one layout
      and assumes the other reads permissions out of an offset.
    * **A loadable ELF needs more than this.** The kernel expects the first
      ``PT_LOAD`` to cover the ELF header and program headers themselves, and
      a dynamically linked binary needs ``PT_INTERP`` and ``PT_DYNAMIC``.
      This image is structurally valid and deliberately not loadable; it
      tests what a scanner parses, not what a kernel would run.

    The segment is ``PF_R`` - readable, not executable - and carries
    :func:`filler` content rather than code.
    """
    if bits not in ELF_PHDR_LEN:
        raise ValueError(f'bits must be 32 or 64, got {bits}')
    if image_base % ELF_PAGE_SIZE:
        raise ValueError(f'image_base 0x{image_base:X} is not page-aligned')

    phdr_len = ELF_PHDR_LEN[bits]
    p_offset = ph_offset + phdr_len
    # The congruence, solved for p_vaddr: any page-aligned base plus the
    # segment's offset within its page.
    p_vaddr = image_base + (p_offset % ELF_PAGE_SIZE)

    if bits == 64:
        phdr = struct.pack('<IIQQQQQQ',
                           _PT_LOAD, _PF_R,
                           p_offset, p_vaddr, p_vaddr,
                           segment_size,          # p_filesz
                           segment_size,          # p_memsz
                           ELF_PAGE_SIZE)         # p_align
    else:
        phdr = struct.pack('<IIIIIIII',
                           _PT_LOAD,
                           p_offset, p_vaddr, p_vaddr,
                           segment_size, segment_size,
                           _PF_R,                 # p_flags is last in Elf32
                           ELF_PAGE_SIZE)
    assert len(phdr) == phdr_len, (len(phdr), phdr_len)

    return phdr + filler(fill, segment_size, seed)


# ---------------------------------------------------------------------------
# Mach-O synthesis
# ---------------------------------------------------------------------------

def macho_header(segment_offset: int, segment_size: int, arch: str = 'arm64',
                 segment_name: bytes = b'__DATA',
                 vmaddr: int = 0x100000000) -> bytes:
    """A ``mach_header_64`` plus one ``LC_SEGMENT_64``: 104 bytes.

    Mach-O is the least fragmentable of the three formats. Load commands are
    not pointed at - they are defined to begin immediately after the header
    and run for ``sizeofcmds`` contiguous bytes - so everything structural has
    to fit in the same region as the magic. In a DICOM preamble that leaves
    ``128 - 32 = 96`` bytes: exactly enough for one section-less
    ``LC_SEGMENT_64`` at 72 bytes, and not enough for a second, nor for a
    single ``section_64`` at 80. Only ``fileoff``/``filesize`` relocate, which
    is why :func:`macho_image` returns segment contents and nothing else.

    Two further constraints have no PE analogue and are worth stating because
    they bound what this payload can prove:

    * ``vmaddr`` and ``vmsize`` must be aligned to the architecture's page
      size, which is 16 KiB on arm64 and 4 KiB on x86-64 - so a header that is
      valid for one is rejected for the other.
    * arm64 macOS requires a valid code signature in an ``LC_CODE_SIGNATURE``
      command before ``execve`` will run an image at all. That cannot be
      synthesised inertly and is not attempted, so this payload tests whether
      a scanner *recognises* an embedded Mach-O, not whether the host would
      load one.
    """
    if arch not in _CPU_TYPE:
        raise ValueError(f'arch must be one of {", ".join(_CPU_TYPE)}, '
                         f'got {arch!r}')
    page = MACHO_PAGE_SIZE[arch]
    if vmaddr % page:
        raise ValueError(f'vmaddr 0x{vmaddr:X} is not {arch} page-aligned '
                         f'(0x{page:X})')

    vmsize = align_up(segment_size, page)
    header = struct.pack('<IiiIIII',
                         MH_MAGIC_64,
                         _CPU_TYPE[arch],
                         _CPU_SUBTYPE[arch],
                         _MH_EXECUTE,
                         1,                        # ncmds
                         SEGMENT_COMMAND_64_LEN,   # sizeofcmds
                         0)                        # flags
    header += b'\x00' * 4                          # reserved
    assert len(header) == MACHO_HEADER_LEN[64], len(header)

    segment = struct.pack('<II16sQQQQiiII',
                          _LC_SEGMENT_64,
                          SEGMENT_COMMAND_64_LEN,
                          segment_name[:16].ljust(16, b'\x00'),
                          vmaddr, vmsize,
                          segment_offset,          # fileoff
                          segment_size,            # filesize
                          _VM_PROT_READ,           # maxprot - not EXECUTE
                          _VM_PROT_READ,           # initprot
                          0,                       # nsects: see the docstring
                          0)                       # flags
    assert len(segment) == SEGMENT_COMMAND_64_LEN, len(segment)

    blob = header + segment
    if len(blob) > PREAMBLE_LEN:
        raise ValueError(f'Mach-O header block is {len(blob)} bytes and does '
                         f'not fit the {PREAMBLE_LEN}-byte preamble')
    return blob


def macho_image(segment_size: int = 0x200, fill: str = 'zeros',
                seed: int = 0) -> bytes:
    """The relocatable half of a Mach-O polyglot: segment contents.

    Deliberately thin, and that thinness is the finding. :func:`pe_image`
    relocates headers, section table and section data; :func:`elf_image`
    relocates the program header table and its segment; Mach-O relocates only
    what ``fileoff`` addresses, because its load commands are pinned behind
    the header. Written at the ``segment_offset`` given to
    :func:`macho_header`.
    """
    return filler(fill, segment_size, seed)


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
        if ptr_raw < size_of_headers:
            problems.append(f'section {label!r} PointerToRawData={ptr_raw} '
                            f'overlaps the headers (SizeOfHeaders='
                            f'{size_of_headers})')
        if ptr_raw + size_of_raw > len(data):
            problems.append(f'section {label!r} raw data runs past the end of '
                            'the file')
    return problems


def validate_elf(data: bytes) -> List[str]:
    """Structural ELF validation. Returns problems; empty means valid.

    Checks what a reader checks before it maps anything: the magic and
    ``e_ident`` fields, header and program-header sizes that match the
    declared class, a program header table resident in the file, and each
    ``PT_LOAD`` in bounds with ``p_offset`` congruent to ``p_vaddr`` modulo
    ``p_align``. As with :func:`validate_pe`, it says nothing about whether
    the image would *run* - an ELF with no ``PT_INTERP`` and a zero entry
    point is structurally fine and functionally inert.

    Only little-endian ELF is handled; anything else is reported rather than
    guessed at.
    """
    problems: List[str] = []
    if data[:4] != ELF_MAGIC:
        return ['no \\x7fELF magic at offset 0']
    if len(data) < 16:
        return ['file too short to hold e_ident']

    ei_class, ei_data, ei_version = data[4], data[5], data[6]
    bits = {1: 32, 2: 64}.get(ei_class)
    if bits is None:
        return [f'unknown EI_CLASS {ei_class}; expected 1 (32-bit) or '
                '2 (64-bit)']
    if ei_data != _ELFDATA2LSB:
        return [f'EI_DATA={ei_data} is not little-endian; this validator '
                'only handles ELFDATA2LSB']
    if ei_version != _EV_CURRENT:
        problems.append(f'EI_VERSION={ei_version}, expected {_EV_CURRENT}')

    header_len = ELF_HEADER_LEN[bits]
    if len(data) < header_len:
        return problems + [f'file too short to hold an {bits}-bit ELF header']

    if bits == 64:
        (e_type, _machine, e_version, _entry, e_phoff, _shoff, _flags,
         e_ehsize, e_phentsize, e_phnum) = struct.unpack(
            '<HHIQQQIHHH', data[16:16 + 42])
    else:
        (e_type, _machine, e_version, _entry, e_phoff, _shoff, _flags,
         e_ehsize, e_phentsize, e_phnum) = struct.unpack(
            '<HHIIIIIHHH', data[16:16 + 30])

    if e_type not in (_ET_EXEC, _ET_DYN):
        problems.append(f'e_type={e_type} is neither ET_EXEC nor ET_DYN')
    if e_version != _EV_CURRENT:
        problems.append(f'e_version={e_version}, expected {_EV_CURRENT}')
    if e_ehsize != header_len:
        problems.append(f'e_ehsize={e_ehsize} does not match the {bits}-bit '
                        f'header size {header_len}')
    if e_phnum == 0:
        problems.append('e_phnum=0: no program headers, so the file describes '
                        'nothing loadable')
        return problems

    phdr_len = ELF_PHDR_LEN[bits]
    if e_phentsize != phdr_len:
        problems.append(f'e_phentsize={e_phentsize} does not match the '
                        f'{bits}-bit program header size {phdr_len}')
        return problems
    if e_phoff + e_phnum * phdr_len > len(data):
        problems.append(f'program header table at e_phoff={e_phoff} runs past '
                        'the end of the file')
        return problems

    for i in range(e_phnum):
        base = e_phoff + i * phdr_len
        if bits == 64:
            (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
             p_memsz, p_align) = struct.unpack('<IIQQQQQQ',
                                               data[base:base + phdr_len])
        else:
            (p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz,
             _p_flags, p_align) = struct.unpack('<IIIIIIII',
                                                data[base:base + phdr_len])
        if p_type != _PT_LOAD:
            continue
        if p_offset + p_filesz > len(data):
            problems.append(f'PT_LOAD {i} contents run past the end of the '
                            'file')
        if p_filesz > p_memsz:
            problems.append(f'PT_LOAD {i} p_filesz={p_filesz} exceeds '
                            f'p_memsz={p_memsz}')
        if p_align > 1:
            if p_align & (p_align - 1):
                problems.append(f'PT_LOAD {i} p_align={p_align} is not a '
                                'power of two')
            elif (p_offset - p_vaddr) % p_align:
                problems.append(
                    f'PT_LOAD {i} p_offset={p_offset} is not congruent to '
                    f'p_vaddr=0x{p_vaddr:X} modulo p_align={p_align}')
    return problems


def validate_macho(data: bytes) -> List[str]:
    """Structural Mach-O validation. Returns problems; empty means valid.

    Walks the header and the load-command chain the way ``dyld`` does before
    mapping: magic, a command chain whose sizes add up to ``sizeofcmds`` and
    stay inside the file, and each ``LC_SEGMENT_64`` in bounds with a
    page-aligned address for its architecture.

    It does **not** check for a code signature. arm64 macOS will refuse to
    execute an unsigned image, but that is a loadability question, and the
    payloads here are structural test cases that carry no signature by
    design - see :func:`macho_header`.
    """
    problems: List[str] = []
    if len(data) < 4:
        return ['file too short to hold a Mach-O magic']
    magic = struct.unpack('<I', data[:4])[0]
    if magic == MH_MAGIC_64:
        bits = 64
    elif magic == MH_MAGIC:
        bits = 32
    else:
        return [f'no little-endian Mach-O magic at offset 0: 0x{magic:08X}']

    header_len = MACHO_HEADER_LEN[bits]
    if len(data) < header_len:
        return [f'file too short to hold a {bits}-bit mach_header']

    cputype, _subtype, filetype, ncmds, sizeofcmds, _flags = struct.unpack(
        '<iiIIII', data[4:28])
    if filetype not in (_MH_EXECUTE, _MH_DYLIB, _MH_BUNDLE):
        problems.append(f'filetype={filetype} is not an executable, dylib or '
                        'bundle')
    if header_len + sizeofcmds > len(data):
        problems.append(f'load commands ({sizeofcmds} bytes) run past the end '
                        'of the file')
        return problems

    arch = next((name for name, value in _CPU_TYPE.items()
                 if value == cputype), None)
    page = MACHO_PAGE_SIZE.get(arch, 0x1000)

    pos = header_len
    end = header_len + sizeofcmds
    for i in range(ncmds):
        if pos + 8 > end:
            problems.append(f'load command {i} starts past the end of the '
                            'command area')
            return problems
        cmd, cmdsize = struct.unpack('<II', data[pos:pos + 8])
        if cmdsize < 8 or pos + cmdsize > end:
            problems.append(f'load command {i} has cmdsize={cmdsize}, which '
                            'does not fit the command area')
            return problems
        if cmd == _LC_SEGMENT_64:
            if cmdsize < SEGMENT_COMMAND_64_LEN:
                problems.append(f'LC_SEGMENT_64 at command {i} is truncated')
            else:
                (vmaddr, vmsize, fileoff, filesize, _maxprot, _initprot,
                 nsects, _sflags) = struct.unpack(
                    '<QQQQiiII', data[pos + 24:pos + SEGMENT_COMMAND_64_LEN])
                if fileoff + filesize > len(data):
                    problems.append(f'LC_SEGMENT_64 at command {i} maps '
                                    f'{filesize} bytes from {fileoff}, past '
                                    'the end of the file')
                if filesize > vmsize:
                    problems.append(f'LC_SEGMENT_64 at command {i} has '
                                    f'filesize={filesize} above '
                                    f'vmsize={vmsize}')
                if vmaddr % page or vmsize % page:
                    problems.append(
                        f'LC_SEGMENT_64 at command {i} is not aligned to the '
                        f'{arch or "default"} page size 0x{page:X}')
                if cmdsize != SEGMENT_COMMAND_64_LEN + nsects * SECTION_64_LEN:
                    problems.append(f'LC_SEGMENT_64 at command {i} declares '
                                    f'nsects={nsects}, which does not match '
                                    f'cmdsize={cmdsize}')
        pos += cmdsize

    if pos != end:
        problems.append(f'load commands end at {pos}, not at the declared '
                        f'sizeofcmds boundary {end}')
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


def executable_format(data: bytes) -> Optional[str]:
    """Which executable format ``data`` claims to be at offset 0, if any.

    ``'pe'``, ``'elf'``, ``'macho'`` or ``None``. This is the magic-table
    lookup a scanner does first, and the whole reason a preamble polyglot
    works: it answers from the same 4 bytes a DICOM reader ignores.
    """
    if data[:2] == b'MZ':
        return 'pe'
    if data[:4] == ELF_MAGIC:
        return 'elf'
    if data[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe'):
        return 'macho'
    return None


_EXECUTABLE_VALIDATORS = {
    'pe': validate_pe,
    'elf': validate_elf,
    'macho': validate_macho,
}


def validate_polyglot(data: bytes,
                      fmt: Optional[str] = None) -> Dict[str, List[str]]:
    """Run both validation pipelines. Empty lists on both sides means the file
    is simultaneously a valid executable and a valid DICOM object.

    The executable half is dispatched on the magic at offset 0 unless ``fmt``
    names it explicitly, and the key it is reported under is the format that
    ran - ``{'pe': [], 'dicom': []}`` for a PEDICOM, ``{'elf': [], ...}`` for
    an ELFDICOM. A file with no recognised magic reports under
    ``'executable'``, since there is no format to name.
    """
    fmt = fmt or executable_format(data)
    if fmt is None:
        return {'executable': ['no recognised executable magic at offset 0'],
                'dicom': validate_dicom(data)}
    if fmt not in _EXECUTABLE_VALIDATORS:
        raise ValueError(f'unknown format {fmt!r}; expected one of '
                         f'{", ".join(_EXECUTABLE_VALIDATORS)}')
    return {fmt: _EXECUTABLE_VALIDATORS[fmt](data),
            'dicom': validate_dicom(data)}
