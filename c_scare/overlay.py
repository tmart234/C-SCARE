# SPDX-License-Identifier: GPL-2.0-only
"""
Render one catalog attack onto a real DICOM object.

This is the seam between two things that should not know about each other.
:mod:`c_scare.attacks` produces attacks — payload bytes plus metadata saying
what the attack is *about*. :mod:`c_scare.carrier` holds a real object as the
bytes it was stored as and splices edits into them. Neither should learn the
other's vocabulary: the catalog gains attacks constantly and must not have to
know how a carrier is edited, and the carrier is byte-level DICOM that must not
grow a table of attack metadata keys.

So the translation lives here, and it is driven entirely by what an attack
*declares*. An attack that names ``target_field`` has that element rewritten;
one that names each half of the C-STORE has each half rewritten; one that names
nothing recognisable has its own elements merged into the carrier in tag order.
Adding an attack never means editing this module — only declaring, in the
attack's metadata, where its payload belongs.

Why not in the runner: none of this is command-line work. It was there because
``--cstore-file`` is a flag, which is a bad reason — it made the only way to
test "does a traversal payload survive a big-endian carrier?" be to construct
an ``argparse.Namespace``, and it put a DICOM-domain decision (how to grow an
image without breaking its geometry) in a module whose job is parsing argv.

Why not in ``carrier.py``: the direction of the dependency. A carrier is a
DICOM object; it is useful to anything that needs one, and giving it knowledge
of ``AttackResult`` metadata would make ``import carrier`` pull in the attack
catalog. The retrieval path in :mod:`c_scare.client` already uses ``carrier``
and wants nothing to do with attacks.

The attack type is duck-typed rather than imported: anything with ``payload``
bytes and a ``metadata`` mapping will do. That keeps the catalog off this
module's import path, the same way ``responders.py`` keeps it off its own.

Example::

    from c_scare.carrier import Carrier
    from c_scare.overlay import carry

    carrier = Carrier.from_file('scanner.dcm')
    carried = carry(carrier, PathTraversalAttacks.sop_instance_uid_traversal())
    session.c_store(carried.dataset, carried.sop_class_uid,
                    carried.sop_instance_uid, carried.transfer_syntax)
"""

import hashlib
import os
import time
from typing import TYPE_CHECKING, Dict, List, NamedTuple, Optional, Tuple

from .carrier import (
    EXPLICIT_VR_BIG_ENDIAN, IMPLICIT_VR_LITTLE_ENDIAN, UNDEFINED_LENGTH,
    Carrier, dataset_from_part10, empty_basic_offset_table, encapsulate_items,
    merge_dataset, split_encapsulated,
)
from .element import Dataset, Element

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .attacks import AttackResult as Attack
else:  # An attack is anything with `.payload: bytes` and `.metadata: dict`.
    Attack = object

__all__ = [
    'CarriedPayload',
    'DEFAULT_STORE_SOP',
    'DEFAULT_STORE_TRANSFER_SYNTAX',
    'carry',
    'rss_pressure_bytes',
    'smoke_dataset',
]


#: Fallback storage SOP class when neither the carrier nor the attack names
#: one. Secondary Capture accepts arbitrary data sets and is what the
#: path-traversal payloads already target.
DEFAULT_STORE_SOP = "1.2.840.10008.5.1.4.1.1.7"

#: Fallback transfer syntax. Implicit VR Little Endian is the one every SCP
#: must accept (PS3.5 Section 10.1).
DEFAULT_STORE_TRANSFER_SYNTAX = "1.2.840.10008.1.2"

#: How the catalog encodes an attack's own Data Set unless the attack says
#: otherwise in ``encoded_transfer_syntax``. Needed to re-frame those elements
#: into a carrier's syntax without disturbing their values.
_DEFAULT_ENCODED_SYNTAX = "1.2.840.10008.1.2.1"  # Explicit VR LE

#: Sequence Delimitation Item (FFFE,E0DD) with a zero length, both byte orders.
#: Encapsulated Pixel Data ends with one; growing the fragment run means
#: splitting it off, repeating the fragments, and putting it back.
_SEQUENCE_DELIMITER_LE = b'\xfe\xff\xdd\xe0\x00\x00\x00\x00'
_SEQUENCE_DELIMITER_BE = b'\xff\xfe\xe0\xdd\x00\x00\x00\x00'


class CarriedPayload(NamedTuple):
    """One attack rendered onto the operator's carrier object.

    ``dataset`` is what C-STORE puts on the wire; ``part10`` is the same object
    as a complete file, for ``--dry-run`` and for any transport that carries
    whole instances. They are two renderings of one edit, never two edits.
    """

    dataset: bytes
    sop_class_uid: str
    sop_instance_uid: str
    transfer_syntax: str
    part10: bytes


def _unique_uid(suffix: int) -> str:
    return f"1.2.826.0.1.3680043.10.543.{time.time_ns()}.{suffix}"


def _uid_hash(value: str) -> int:
    digest = hashlib.sha1(value.encode('utf-8', errors='replace')).hexdigest()
    return int(digest[:8], 16) % 100000000


def _series_uid_for_result(result: 'Attack', suffix: int) -> str:
    run_id = os.environ.get('CSCARE_DAST_RUN_ID')
    if not run_id:
        return _unique_uid(suffix)
    return f"1.2.826.0.1.3680043.10.543.{_uid_hash(run_id)}.{_uid_hash(result.name)}.{suffix}"


def _slice_uid_for_result(result: 'Attack', carrier: Carrier,
                          suffix: int) -> str:
    run_id = os.environ.get('CSCARE_DAST_RUN_ID')
    if not run_id:
        return _unique_uid(suffix)
    source_id = str(carrier.sop_instance_uid or carrier.path or time.time_ns())
    return (
        f"1.2.826.0.1.3680043.10.543.{_uid_hash(run_id)}."
        f"{_uid_hash(result.name)}.{_uid_hash(source_id)}.{suffix}"
    )


# Tags the overlay writes by name, with the VR to use when the carrier does
# not already carry the element. When it does, the carrier's own VR wins —
# an object that stored Patient ID as something unusual keeps it.
_TAG_SOP_CLASS_UID = 0x00080016
_TAG_SOP_INSTANCE_UID = 0x00080018
_TAG_STUDY_INSTANCE_UID = 0x0020000D
_TAG_SERIES_INSTANCE_UID = 0x0020000E
_TAG_PATIENT_NAME = 0x00100010
_TAG_PATIENT_ID = 0x00100020
_TAG_STUDY_DESCRIPTION = 0x00081030
_TAG_SERIES_DESCRIPTION = 0x0008103E
_TAG_PATIENT_COMMENTS = 0x00104000
_TAG_PIXEL_DATA = 0x7FE00010
_TAG_NUMBER_OF_FRAMES = 0x00280008

_KEYWORD_TAGS = {
    'SOPClassUID': (_TAG_SOP_CLASS_UID, 'UI'),
    'SOPInstanceUID': (_TAG_SOP_INSTANCE_UID, 'UI'),
    'StudyInstanceUID': (_TAG_STUDY_INSTANCE_UID, 'UI'),
    'SeriesInstanceUID': (_TAG_SERIES_INSTANCE_UID, 'UI'),
    'PatientName': (_TAG_PATIENT_NAME, 'PN'),
    'PatientID': (_TAG_PATIENT_ID, 'LO'),
    'StudyDescription': (_TAG_STUDY_DESCRIPTION, 'LO'),
    'SeriesDescription': (_TAG_SERIES_DESCRIPTION, 'LO'),
    'PatientComments': (_TAG_PATIENT_COMMENTS, 'LT'),
    'AccessionNumber': (0x00080050, 'SH'),
    'StudyID': (0x00200010, 'SH'),
    'Modality': (0x00080060, 'CS'),
}


def _edit_set(edit, keyword: str, value: str, label: Optional[str] = None) -> bool:
    """Write one named element onto a carrier edit.

    Returns whether the write happened. A keyword this table does not know is
    refused out loud rather than dropped, because an overlay that silently
    does nothing reports an attack as delivered that the target never saw.
    """
    entry = _KEYWORD_TAGS.get(keyword)
    if entry is None:
        edit.refuse(label or keyword, f'no tag mapping for {keyword}')
        return False
    tag, vr = entry
    edit.set_text(tag, vr, value, label or keyword)
    return True


def _apply_field_overrides(edit, overrides: Dict[str, str]) -> None:
    for keyword, value in overrides.items():
        _edit_set(edit, keyword, value, 'cstore_field_overrides')


def _stamp_identity(edit, result: 'Attack', carrier: Carrier) -> str:
    """Give this delivery its own identity so attacks cannot collide.

    Every copy of the carrier gets a fresh Study/Series/SOP Instance UID and a
    per-attack Patient identity, so one attack's object cannot overwrite
    another's on the target and the operator can tell from the archive which
    test produced which stored instance.
    """
    sop_instance = _slice_uid_for_result(result, carrier, 1)
    study_instance = _series_uid_for_result(result, 2)
    series_instance = _series_uid_for_result(result, 3)
    run_id = os.environ.get('CSCARE_DAST_RUN_ID')
    patient_suffix = _uid_hash(f"{run_id}:{result.name}") if run_id else time.time_ns() & 0xFFFFFFFF
    patient_id = f"CSCARE-{patient_suffix:x}"
    patient_name = f"C-SCARE^{result.name[:48]}"

    _edit_set(edit, 'SOPInstanceUID', sop_instance, 'identity')
    # Keep the Part-10 rendering self-consistent: (0002,0003) names the same
    # instance as (0008,0018). Nothing of group 0002 crosses a C-STORE
    # association, so this is purely for the file an operator inspects.
    edit.set_file_meta(0x00020003, 'UI', sop_instance, 'identity')
    _edit_set(edit, 'StudyInstanceUID', study_instance, 'identity')
    _edit_set(edit, 'SeriesInstanceUID', series_instance, 'identity')
    _edit_set(edit, 'PatientName', patient_name, 'identity')
    _edit_set(edit, 'PatientID', patient_id, 'identity')

    result.metadata['cstore_file_base_sop_instance_uid'] = sop_instance
    result.metadata['cstore_file_base_study_instance_uid'] = study_instance
    result.metadata['cstore_file_base_series_instance_uid'] = series_instance
    result.metadata['cstore_file_base_patient_id'] = patient_id
    return sop_instance


def _path_display_marker(value: str) -> str:
    marker = str(value).replace('\x00', '')
    run_id = os.environ.get('CSCARE_DAST_RUN_ID')
    if run_id:
        marker = f"{marker}-{_uid_hash(run_id):08d}"
    return marker[:64] or 'C-SCARE-PATH'


def _set_path_display_markers(edit, value: str) -> None:
    marker = _path_display_marker(value)
    for keyword in ('PatientID', 'StudyDescription', 'SeriesDescription',
                    'PatientComments'):
        _edit_set(edit, keyword, marker, 'path_display_marker')


def _attack_dataset_payload(result: 'Attack') -> bytes:
    payload, _meta = dataset_from_part10(result.payload)
    return payload


def _attack_dataset_encoding(result: 'Attack') -> Tuple[bool, bool]:
    """How the attack encoded its own Data Set: ``(implicit_vr, little_endian)``.

    The catalog writes explicit VR little endian unless an attack says
    otherwise, and an attack that is *about* an encoding says so in
    ``encoded_transfer_syntax``. Getting this right is what lets the attack's
    elements be re-framed into the carrier's syntax without touching their
    values.
    """
    encoded = (result.metadata.get('encoded_transfer_syntax')
               or _DEFAULT_ENCODED_SYNTAX)
    return (encoded == IMPLICIT_VR_LITTLE_ENDIAN,
            encoded != EXPLICIT_VR_BIG_ENDIAN)


# DICOM element name (as attacks write it in `target_field`) -> the keyword
# the overlay writes, and the metadata key an attack uses to carry that
# element's value. An attack names the element it corrupts; this table says
# where to put it on the carrier object. Nothing here knows individual attack
# names.
_CSTORE_TARGET_FIELDS = {
    '(0008,0018) SOP Instance UID': ('SOPInstanceUID', 'sop_instance_uid'),
    '(0020,000D) Study Instance UID': ('StudyInstanceUID', 'study_instance_uid'),
    '(0020,000E) Series Instance UID': ('SeriesInstanceUID', 'series_instance_uid'),
    '(0010,0010) Patient Name': ('PatientName', 'patient_name'),
    '(0010,0020) Patient ID': ('PatientID', 'patient_id'),
}

# `coverage_scope` values that change how a payload is placed rather than
# where. The two traversal scopes split one value across the C-STORE command
# set and the data set to prove which half the target actually consumes.
_SCOPE_COMMAND_UID_ONLY = 'command-sop-instance-uid-only'
_SCOPE_DATASET_UID_ONLY = 'dataset-sop-instance-uid-only'
_SCOPE_IDENTITY_VALIDATION = 'identity-validation'
_SCOPE_DISK_PRESSURE = 'storage-quota-disk-pressure'


def _grow_pixel_data(edit, carrier: Carrier, result: 'Attack',
                     size: int) -> None:
    """Make the carrier's image bigger without making it stop being an image.

    Disk-pressure attacks need bulk, and the obvious way to get it — assign a
    few hundred kilobytes to Pixel Data — throws the operator's volume away and
    leaves Rows, Columns, Bits Allocated and Number of Frames describing an
    image that is no longer there. An SCP that checks pixel length against
    geometry then rejects the object on arrival, and the quota was never
    tested. On an encapsulated carrier it is worse: native bytes land in an
    element the transfer syntax says holds JPEG, so nothing downstream can
    decode it.

    So grow it the way a longer acquisition would. Native Pixel Data gains
    whole repeated frames and Number of Frames rises to match, keeping
    ``rows x columns x samples x bytes x frames`` exactly consistent.
    Encapsulated Pixel Data gains repeated fragment Items — each one a
    complete copy of a codestream the carrier already held, so every frame
    still decodes — and the Basic Offset Table is emptied rather than left
    pointing at boundaries that have moved.
    """
    pixel = carrier.pixel_data()
    if pixel is None:
        # No image to grow. Say so and add the bulk as a private element
        # rather than inventing a Pixel Data element the geometry cannot back.
        edit.set_value(0x00091001, 'OB', b'X' * size, 'bulk_private_element')
        result.metadata['cstore_file_effective_pixel_bytes'] = size
        result.metadata['cstore_file_bulk_placement'] = 'private_element'
        return

    original = carrier.value_of(_TAG_PIXEL_DATA) or b''
    if not original:
        result.metadata['cstore_file_bulk_placement'] = 'skipped_empty_pixel_data'
        return

    frames = _carrier_frame_count(carrier)

    if pixel.undefined_length:
        parts = split_encapsulated(original, carrier.little_endian)
        if parts is None:
            result.metadata['cstore_file_bulk_placement'] = 'skipped_unparsable_fragments'
            return
        _bot, fragments, delimiter = parts
        if not fragments:
            result.metadata['cstore_file_bulk_placement'] = 'skipped_empty_pixel_data'
            return
        run = b''.join(fragments)
        repeats = max(1, -(-size // max(len(run), 1)))
        grown = encapsulate_items(
            empty_basic_offset_table(carrier.little_endian),
            fragments * (repeats + 1),
            delimiter or _sequence_delimiter(carrier))
        edit.set_value(_TAG_PIXEL_DATA, pixel.vr.decode('ascii', 'replace')
                       if pixel.vr else 'OB', grown, 'pixel_data_pressure',
                       declared_length=UNDEFINED_LENGTH)
        if len(fragments) == frames:
            # One fragment per frame, so each repeat is another whole frame.
            edit.set_value(_TAG_NUMBER_OF_FRAMES, 'IS',
                           str(frames * (repeats + 1)), 'pixel_data_pressure')
        result.metadata['cstore_file_effective_pixel_bytes'] = len(grown)
        result.metadata['cstore_file_bulk_placement'] = 'encapsulated_fragments'
        return

    frame_bytes = max(1, len(original) // frames)
    extra_frames = max(1, -(-size // frame_bytes))
    grown = original + original[:frame_bytes] * extra_frames
    vr = carrier.vr_of(_TAG_PIXEL_DATA) or 'OW'
    edit.set_value(_TAG_PIXEL_DATA, vr, grown, 'pixel_data_pressure')
    edit.set_value(_TAG_NUMBER_OF_FRAMES, 'IS', str(frames + extra_frames),
                   'pixel_data_pressure')
    result.metadata['cstore_file_effective_pixel_bytes'] = len(grown)
    result.metadata['cstore_file_bulk_placement'] = 'native_frames'


def _carrier_frame_count(carrier: Carrier) -> int:
    """(0028,0008) Number of Frames, defaulting to the single-frame case."""
    raw = (carrier.text_of(_TAG_NUMBER_OF_FRAMES) or '').strip()
    if not raw.isdigit():
        return 1
    return max(1, int(raw))


def _sequence_delimiter(carrier: Carrier) -> bytes:
    return (_SEQUENCE_DELIMITER_LE if carrier.little_endian
            else _SEQUENCE_DELIMITER_BE)


def _apply_overlay(edit, carrier: Carrier, result: 'Attack',
                   command_sop_class: str,
                   command_sop_instance: str) -> Tuple[str, str]:
    """Overlay one attack onto an edit of the carrier object's data set.

    Returns the (possibly rewritten) command-set SOP Class/Instance UIDs.
    Placement is driven entirely by ``result.metadata``, so adding an attack
    never requires editing this function: an attack that declares nothing
    recognizable here has its own elements merged into the carrier instead.
    """
    metadata = result.metadata or {}
    scope = metadata.get('coverage_scope')
    applied: List[str] = []

    # Command-vs-dataset consistency attacks name each half explicitly.
    if isinstance(metadata.get('command_sop_class_uid'), str):
        command_sop_class = metadata['command_sop_class_uid']
        applied.append('command_sop_class_uid')
    if isinstance(metadata.get('dataset_sop_class_uid'), str):
        _edit_set(edit, 'SOPClassUID', metadata['dataset_sop_class_uid'],
                  'dataset_sop_class_uid')
        edit.set_file_meta(0x00020002, 'UI', metadata['dataset_sop_class_uid'],
                           'dataset_sop_class_uid')
        applied.append('dataset_sop_class_uid')
    if isinstance(metadata.get('command_sop_instance_uid'), str):
        command_sop_instance = metadata['command_sop_instance_uid']
        applied.append('command_sop_instance_uid')
    if isinstance(metadata.get('dataset_sop_instance_uid'), str):
        _edit_set(edit, 'SOPInstanceUID', metadata['dataset_sop_instance_uid'],
                  'dataset_sop_instance_uid')
        applied.append('dataset_sop_instance_uid')

    # An attack may spell out exactly which elements to rewrite.
    overrides = metadata.get('cstore_field_overrides')
    if isinstance(overrides, dict):
        _apply_field_overrides(edit, overrides)
        applied.append('cstore_field_overrides')
        # Command and data set must agree on the SOP Instance UID unless the
        # attack explicitly split them, or an SCP that names the stored file
        # from the command set would never see the payload.
        if 'SOPInstanceUID' in overrides and 'command_sop_instance_uid' not in applied:
            command_sop_instance = overrides['SOPInstanceUID']

    # The element named by `target_field` carries the payload. Its value comes
    # from `traversal_payload` or from the per-element metadata key.
    payload_value = metadata.get('traversal_payload')
    target = _CSTORE_TARGET_FIELDS.get(metadata.get('target_field'))
    if scope == _SCOPE_COMMAND_UID_ONLY and isinstance(payload_value, str):
        # The data set keeps a benign UID; only the command set carries the payload.
        command_sop_instance = payload_value
        applied.append('command_sop_instance_uid')
    elif scope == _SCOPE_DATASET_UID_ONLY and isinstance(payload_value, str):
        _edit_set(edit, 'SOPInstanceUID', payload_value, 'dataset_sop_instance_uid')
        applied.append('dataset_sop_instance_uid')
    elif target is not None:
        keyword, value_key = target
        value = payload_value if isinstance(payload_value, str) else metadata.get(value_key)
        if isinstance(value, str):
            _edit_set(edit, keyword, value, value_key)
            applied.append(value_key)
            if keyword == 'SOPInstanceUID':
                command_sop_instance = value

    if isinstance(payload_value, str) and applied:
        # Mirror the path string into human-visible fields so an operator
        # browsing the target's UI or storage tree can spot where it landed.
        _set_path_display_markers(edit, payload_value)

    if scope == _SCOPE_IDENTITY_VALIDATION:
        _edit_set(edit, 'PatientName', '', 'empty_identity')
        _edit_set(edit, 'PatientID', '', 'empty_identity')
        applied.append('empty_identity')

    if scope == _SCOPE_DISK_PRESSURE:
        size = max(int(metadata.get('size', 0)), rss_pressure_bytes())
        _grow_pixel_data(edit, carrier, result, size)
        applied.append('pixel_data_pressure')

    if not applied:
        # Nothing in the metadata said where this attack goes, so fold the
        # attack's own Data Set into the carrier element by element. Merging
        # beats appending: an appended Data Set sits past Pixel Data with tags
        # that run backwards, which a conformant SCP is entitled to stop at —
        # so the parser under test never reaches the malformation.
        merged, skipped, appended = _merge_attack_dataset(edit, carrier, result)
        applied.append('merge_attack_dataset' if merged else 'append_attack_dataset')
        result.metadata['cstore_file_merged_elements'] = merged
        if skipped:
            result.metadata['cstore_file_kept_carrier_identity'] = skipped
        if appended:
            result.metadata['cstore_file_appended_bytes'] = appended

    result.metadata['cstore_file_mutation'] = '+'.join(applied)
    if edit.refused:
        result.metadata['cstore_file_refused'] = '; '.join(edit.refused)
    return command_sop_class, command_sop_instance


#: Elements the carrier stamps with a per-delivery identity. An attack's own
#: Data Set carries placeholders for these because every Data Set needs them,
#: not because the attack is about them.
_IDENTITY_TAGS = frozenset({
    _TAG_SOP_INSTANCE_UID, _TAG_STUDY_INSTANCE_UID, _TAG_SERIES_INSTANCE_UID,
})

_UID_CHARACTERS = frozenset('0123456789.')


def _is_placeholder_uid(raw: bytes) -> bool:
    """True for a value that is an ordinary, conformant UID.

    The question this answers is "could this element be the attack?". A UID of
    nothing but digits and dots, within the 64-character limit, is not testing
    anything — it is the placeholder every catalog Data Set needs to be a Data
    Set at all. A traversal path, an embedded NUL, an over-long value or a
    backslash is the payload, and goes through untouched.
    """
    text = raw.decode('ascii', errors='replace').rstrip('\x00')
    if not text or len(text) > 64:
        return False
    return set(text) <= _UID_CHARACTERS


def _merge_attack_dataset(edit, carrier: Carrier,
                          result: 'Attack') -> Tuple[int, int, int]:
    """Fold an attack's own elements into the carrier, values untouched.

    Each element is re-framed for the carrier's transfer syntax — a VR appears
    or disappears, the tag and length fields change endianness — while its
    declared length and value bytes go through exactly as the attack wrote
    them. That is the difference between delivering a length that lies and
    delivering a length a writer has helpfully corrected.

    The one thing that does not come across is a placeholder identifier. Half
    the catalog writes ``1.2.3.4.5`` as its SOP Instance UID; merging that
    would undo the per-delivery identity the carrier was stamped with, and two
    attacks would land on the target as one instance overwriting the other.
    A *malformed* identifier is a different thing entirely and is merged, since
    that is the attack.
    """
    blob = _attack_dataset_payload(result)
    if not blob:
        return 0, 0, 0
    implicit, little = _attack_dataset_encoding(result)

    def _skip_placeholder_identity(elem, value) -> bool:
        return elem.tag in _IDENTITY_TAGS and _is_placeholder_uid(value)

    return merge_dataset(edit, blob, implicit_vr=implicit,
                         little_endian=little, label='merge_attack_dataset',
                         skip=_skip_placeholder_identity)


def _transfer_syntax_for(carrier: Carrier, result: Optional['Attack'],
                         override: Optional[str]) -> str:
    """The transfer syntax to negotiate for one carried attack.

    An explicit override wins (``--store-transfer-syntax``), then the attack's
    own declared syntax, then the syntax the carrier is actually encoded in.
    The middle term is the one that used to be missing: an attack whose whole
    mechanism is a mismatch between the negotiated syntax and the bytes on the
    wire has nothing left once the carrier's syntax silently overrides it.
    """
    if override:
        return override
    if result is not None:
        declared = (result.metadata or {}).get('transfer_syntax')
        if isinstance(declared, str) and declared:
            return declared
    return carrier.transfer_syntax or DEFAULT_STORE_TRANSFER_SYNTAX


def carry(carrier: Carrier, result: Optional['Attack'] = None, *,
          transfer_syntax: Optional[str] = None,
          store_sop: Optional[str] = None) -> CarriedPayload:
    """Render one attack onto a real DICOM object, ready to store.

    ``result`` is any attack: an object with ``payload`` bytes and a
    ``metadata`` mapping. ``None`` renders the carrier unchanged, which is what
    a known-good smoke store sends.

    The attack is *spliced* into the bytes that were on disk, never re-encoded
    from a parse of them, so payloads survive an SCP that rejects data sets
    missing device-specific required elements — and the object the target opens
    is the one the operator already proved it accepts.

    ``transfer_syntax`` overrides both the attack's declared syntax and the
    carrier's own; ``store_sop`` is the SOP Class to fall back on when neither
    the carrier nor the attack names one.
    """
    edit = carrier.edit()
    transfer_syntax = _transfer_syntax_for(carrier, result, transfer_syntax)
    command_sop_class = (carrier.sop_class_uid
                         or store_sop
                         or DEFAULT_STORE_SOP)
    command_sop_instance = (carrier.sop_instance_uid
                            or f"1.2.826.0.1.3680043.10.543.{int(time.time())}.4")

    if result is not None:
        result.metadata['cstore_file'] = carrier.path
        result.metadata['cstore_file_transfer_syntax'] = transfer_syntax
        result.metadata['cstore_file_encoding'] = carrier.transfer_syntax
        if carrier.has_tail:
            # Bytes the scan could not read as elements are still delivered;
            # say so, because they are also bytes no splice can reach.
            result.metadata['cstore_file_opaque_tail_bytes'] = (
                len(carrier.dataset) - carrier.tail_offset)
        # Every delivered object gets a fresh identity so one attack's object
        # cannot collide with, or overwrite, another's on the target.
        command_sop_instance = _stamp_identity(edit, result, carrier)
        command_sop_class, command_sop_instance = _apply_overlay(
            edit, carrier, result, command_sop_class, command_sop_instance)

    return CarriedPayload(edit.to_bytes(), command_sop_class,
                          command_sop_instance, transfer_syntax,
                          edit.to_part10())



def rss_pressure_bytes() -> int:
    """Pixel Data size for disk/memory-pressure attacks, in bytes.

    Defaults to 256 KiB. Raise it via ``CSCARE_CSTORE_RSS_PRESSURE_BYTES``
    when the target only shows growth under a larger object; capped at 512 MiB
    so a typo cannot try to allocate the test host's whole memory.
    """
    raw = os.environ.get('CSCARE_CSTORE_RSS_PRESSURE_BYTES')
    if not raw:
        return 256 * 1024
    try:
        size = int(raw, 0)
    except ValueError:
        return 256 * 1024
    return max(0, min(size, 512 * 1024 * 1024))


def smoke_dataset(sop_class_uid: str, sop_instance_uid: str,
                  transfer_syntax: str) -> bytes:
    """A minimal but wholly valid Secondary Capture object.

    What ``--cstore-smoke`` sends when there is no ``--cstore-file`` to send
    instead: proof that the association parameters can store *something*, so a
    rejection later in the run means the payload was rejected rather than the
    channel.
    """
    study_uid = f"1.2.826.0.1.3680043.10.543.{int(time.time())}.1"
    series_uid = f"1.2.826.0.1.3680043.10.543.{int(time.time())}.2"
    ds = Dataset()
    ds = ds / Element(0x0008, 0x0016, 'UI', sop_class_uid)
    ds = ds / Element(0x0008, 0x0018, 'UI', sop_instance_uid)
    ds = ds / Element(0x0008, 0x0020, 'DA', time.strftime('%Y%m%d'))
    ds = ds / Element(0x0008, 0x0030, 'TM', time.strftime('%H%M%S'))
    ds = ds / Element(0x0008, 0x0060, 'CS', 'OT')
    ds = ds / Element(0x0010, 0x0010, 'PN', 'C-SCARE^Smoke')
    ds = ds / Element(0x0010, 0x0020, 'LO', 'C-SCARE-SMOKE')
    ds = ds / Element(0x0020, 0x000D, 'UI', study_uid)
    ds = ds / Element(0x0020, 0x000E, 'UI', series_uid)
    ds = ds / Element(0x0028, 0x0002, 'US', 1)       # Samples per Pixel
    ds = ds / Element(0x0028, 0x0004, 'CS', 'MONOCHROME2')
    ds = ds / Element(0x0028, 0x0010, 'US', 1)       # Rows
    ds = ds / Element(0x0028, 0x0011, 'US', 1)       # Columns
    ds = ds / Element(0x0028, 0x0100, 'US', 8)       # Bits Allocated
    ds = ds / Element(0x0028, 0x0101, 'US', 8)       # Bits Stored
    ds = ds / Element(0x0028, 0x0102, 'US', 7)       # High Bit
    ds = ds / Element(0x0028, 0x0103, 'US', 0)       # Pixel Representation
    ds = ds / Element(0x7FE0, 0x0010, 'OB', b'\x00')
    return ds.encode(implicit_vr=(transfer_syntax == DEFAULT_STORE_TRANSFER_SYNTAX))
