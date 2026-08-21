# SPDX-License-Identifier: GPL-2.0-only
"""
``--cstore-file`` against real images: what the target actually receives.

The flag exists so an attack can ride an object the operator has already
watched their target accept. That promise has two halves, and both are tested
here on real scanner-derived files rather than a synthetic stub:

* the object the target opens is still the operator's object -- same elements,
  same pixel volume, same encoding, byte for byte where nothing was aimed at;
* the attack is still the attack -- the payload reaches the wire unmodified,
  in a place a conformant parser will read, under a transfer syntax that can
  express it.

Both halves used to fail, quietly, and a quiet failure here is the expensive
kind: the run reports a clean status for a test the target never ran.
"""

import argparse
import io
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dicom_corpus import (  # noqa: E402
    bundled_paths, corpus_paths, encoding_paths, image_id, is_nonconformant,
    is_truncated,
)

import c_scare.runner as runner  # noqa: E402
from c_scare import attacks as attack_catalog  # noqa: E402
from c_scare.carrier import (  # noqa: E402
    Carrier, TAG_PIXEL_DATA, TAG_SOP_INSTANCE_UID,
    empty_basic_offset_table, scan_dataset, split_encapsulated,
)

pydicom = pytest.importorskip('pydicom')

CORPUS = corpus_paths()
#: One image per Data Set encoding. Used wherever the variable under test is
#: framework logic and the image only has to supply an encoding to exercise it.
ENCODINGS = encoding_paths()
TAG_STUDY_INSTANCE_UID = 0x0020000D
TAG_NUMBER_OF_FRAMES = 0x00280008

CATALOGS = (
    attack_catalog.ParserAttacks,
    attack_catalog.ProtocolAttacks,
    attack_catalog.MemoryAttacks,
    attack_catalog.LogicAttacks,
    attack_catalog.StorageSCPAbuseAttacks,
    attack_catalog.CommandInjectionAttacks,
    attack_catalog.PathTraversalAttacks,
    attack_catalog.NegotiationAttacks,
    attack_catalog.DimseNAttacks,
    attack_catalog.CVEAttacks,
)


def _args(path, **overrides):
    base = dict(cstore_file=str(path), store_sop=None,
                store_transfer_syntax=None, delivery='auto')
    base.update(overrides)
    return argparse.Namespace(**base)


def _carry(path, result, **overrides):
    return runner._cstore_file_payload_for_result(_args(path, **overrides),
                                                  result)


def _cstore_attacks():
    """Every catalog attack that `auto` delivery routes through C-STORE."""
    routing = argparse.Namespace(delivery='auto')
    for catalog in CATALOGS:
        for result in catalog.all():
            if runner._delivery_kind(routing, result) == 'cstore':
                yield result


def _reference_image():
    return os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')


# ---------------------------------------------------------------------------
# The carrier is the operator's object
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_smoke_payload_is_the_files_own_data_set(path):
    """With no attack, the wire carries the file's Data Set unchanged.

    This is what ``--cstore-smoke`` sends, and what the operator's target has
    already accepted. Any difference at all here is the framework editing an
    object nobody asked it to edit.
    """
    carrier = Carrier.from_file(path)
    carried = _carry(path, None)
    assert carried.dataset == carrier.dataset
    if carrier.file_meta:
        assert carried.part10 == open(path, 'rb').read()
    else:
        # A Data Set that arrived with no File Meta Information gets a minimal
        # one built for it, so there is a file to hand a viewer. Group 0002 is
        # outside the Data Set and never crosses a C-STORE association, so
        # nothing the target parses has changed.
        assert carried.part10.endswith(carrier.dataset)
        assert carried.part10[128:132] == b'DICM' 


@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_carried_attack_keeps_every_untouched_element(path):
    """One attack overlaid, every other element intact.

    Includes the retired ``(gggg,0000)`` group lengths a scanner emitted, which
    a conformant writer drops and which the catalog has its own attacks about.
    """
    carrier = Carrier.from_file(path)
    result = attack_catalog.PathTraversalAttacks.study_instance_uid_traversal(
        'posix_proof')
    rendered = _carry(path, result).dataset

    for elem in carrier.elements:
        if elem.tag in (TAG_STUDY_INSTANCE_UID, TAG_SOP_INSTANCE_UID,
                        0x00100010, 0x00100020, 0x00081030, 0x0008103E,
                        0x00104000, 0x0020000E):
            continue
        assert carrier.dataset[elem.start:elem.end] in rendered, (
            f'({elem.group:04X},{elem.element:04X}) was dropped')


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_carried_attack_keeps_the_pixel_volume(path):
    """The image survives the attack that rides it.

    Not decoration: an SCP that checks Pixel Data length against Rows,
    Columns and Bits Allocated rejects an object whose volume went missing,
    and the attack is answered by a validator instead of a parser.
    """
    carrier = Carrier.from_file(path)
    original = carrier.value_of(TAG_PIXEL_DATA)
    if original is None:
        pytest.skip('carrier holds no Pixel Data')
    result = attack_catalog.PathTraversalAttacks.sop_instance_uid_traversal(
        'posix_proof')
    assert original in _carry(path, result).dataset


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_carried_object_reparses_in_the_negotiated_syntax(path):
    """The target can read back what we sent, in the syntax we negotiated."""
    result = attack_catalog.PathTraversalAttacks.sop_instance_uid_traversal(
        'posix_proof')
    carried = _carry(path, result)
    rebuilt = Carrier.from_bytes(carried.part10)
    assert rebuilt.transfer_syntax == carried.transfer_syntax
    if not is_truncated(path):
        assert rebuilt.tail_offset == len(rebuilt.dataset)


# ---------------------------------------------------------------------------
# The attack is still the attack
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
@pytest.mark.parametrize('payload_id', [
    p[0] for p in attack_catalog.PathTraversalAttacks._TRAVERSAL_PAYLOADS])
def test_every_sop_traversal_payload_reaches_the_wire(path, payload_id):
    """SOP Instance UID traversal survives the carrier, on every image.

    (0008,0018) is what storescp names the received file after (CVE-2022-2119),
    so this is the payload with the shortest path from "accepted" to "file
    written outside the storage root". It has to arrive byte for byte: an
    embedded NUL intact, an over-64-character value untruncated, a backslash
    not re-read as a value delimiter and re-joined.
    """
    value, _note = attack_catalog.PathTraversalAttacks._lookup(payload_id)
    result = attack_catalog.PathTraversalAttacks.sop_instance_uid_traversal(
        payload_id)
    carried = _carry(path, result)
    assert value.encode('latin-1') in carried.dataset
    # The command set names the same value, or an SCP that derives the stored
    # filename from (0000,1000) never sees the payload at all.
    assert carried.sop_instance_uid == value
    assert result.metadata['cstore_file_mutation'] == 'sop_instance_uid'


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
@pytest.mark.parametrize('factory,expected', [
    ('study_instance_uid_traversal', 'study_instance_uid'),
    ('patient_name_traversal', 'patient_name'),
], ids=['study_uid', 'patient_name'])
def test_other_traversal_targets_reach_the_wire(path, factory, expected):
    """Study Instance UID and Patient Name drive storescp's sort directories."""
    result = getattr(attack_catalog.PathTraversalAttacks, factory)('posix_proof')
    value = result.metadata['traversal_payload']
    carried = _carry(path, result)
    assert value.encode('latin-1') in carried.dataset
    assert result.metadata['cstore_file_mutation'] == expected


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_traversal_value_is_mirrored_into_operator_visible_fields(path):
    """The path also lands where a human browsing the archive will see it."""
    result = attack_catalog.PathTraversalAttacks.study_instance_uid_traversal(
        'posix_proof')
    value = result.metadata['traversal_payload']
    carried = _carry(path, result)
    assert carried.dataset.count(value.encode('latin-1')) >= 2


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_command_and_dataset_uids_can_be_split(path):
    """An attack that deliberately disagrees with itself still does."""
    result = attack_catalog.AttackResult(
        name='split', category='storage_abuse', payload=b'x', description='d',
        expected_behavior='e', metadata={
            'command_sop_instance_uid': '1.2.3.4.5',
            'dataset_sop_instance_uid': '1.2.3.4.5.31',
        })
    carried = _carry(path, result)
    assert carried.sop_instance_uid == '1.2.3.4.5'
    assert Carrier.from_bytes(carried.part10).text_of(
        TAG_SOP_INSTANCE_UID) == '1.2.3.4.5.31'


# ---------------------------------------------------------------------------
# Transfer syntax
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_negotiated_syntax_matches_the_carriers_own_encoding(path):
    """We negotiate what the bytes are, because we never re-encode them."""
    carrier = Carrier.from_file(path)
    result = attack_catalog.PathTraversalAttacks.sop_instance_uid_traversal(
        'posix')
    assert _carry(path, result).transfer_syntax == carrier.transfer_syntax


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_an_attacks_declared_syntax_overrides_the_carriers(path):
    """An attack whose mechanism *is* the syntax keeps its syntax.

    ``negotiated_transfer_syntax_mismatch`` sends explicit-VR bytes on an
    implicit-VR context on purpose. Letting the carrier's syntax win silently
    deletes the attack while still reporting it as delivered.
    """
    result = attack_catalog.AttackResult(
        name='mismatch', category='logic', payload=b'x', description='d',
        expected_behavior='e',
        metadata={'transfer_syntax': '1.2.840.10008.1.2'})
    assert _carry(path, result).transfer_syntax == '1.2.840.10008.1.2'


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_store_transfer_syntax_flag_wins_over_everything(path):
    result = attack_catalog.AttackResult(
        name='mismatch', category='logic', payload=b'x', description='d',
        expected_behavior='e',
        metadata={'transfer_syntax': '1.2.840.10008.1.2'})
    carried = _carry(path, result,
                     store_transfer_syntax='1.2.840.10008.1.2.1')
    assert carried.transfer_syntax == '1.2.840.10008.1.2.1'


def test_catalog_syntax_declarations_are_all_honoured():
    """No attack in the catalog loses its declared syntax to a carrier."""
    path = _reference_image()
    for result in _cstore_attacks():
        declared = result.metadata.get('transfer_syntax')
        if not declared:
            continue
        assert _carry(path, result).transfer_syntax == declared, result.name


# ---------------------------------------------------------------------------
# Merging attack elements into the carrier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_attack_elements_are_merged_ahead_of_pixel_data(path):
    """An attack with no declared placement goes into the object, not behind it.

    Appending a second Data Set after (7FE0,0010) makes the tags run backwards.
    A conformant SCP may stop at the end of the object, so the malformation
    never reaches the parser -- and the run reads clean.
    """
    result = attack_catalog.AttackResult(
        name='invalid_vr', category='parser',
        payload=(struct.pack('<HH', 0x0010, 0x0010) + b'XX'
                 + struct.pack('<H', 12) + b'Evil^Payload'),
        description='d', expected_behavior='e')
    carried = _carry(path, result)

    assert result.metadata['cstore_file_mutation'] == 'merge_attack_dataset'
    assert result.metadata['cstore_file_merged_elements'] == 1
    assert b'Evil^Payload' in carried.dataset

    rebuilt = Carrier.from_bytes(carried.part10)
    assert rebuilt.tail_offset == len(rebuilt.dataset)
    pixel = rebuilt.find(TAG_PIXEL_DATA)
    name_elem = rebuilt.find(0x00100010)
    assert name_elem is not None
    if pixel is not None:
        assert name_elem.start < pixel.start


@pytest.mark.parametrize('name,implicit', [
    ('CT_small.dcm', False),
    ('MR_small_implicit.dcm', True),
])
def test_merged_element_is_framed_for_the_carriers_encoding(name, implicit):
    """A merged element parses under the syntax we negotiate for it.

    The catalog writes explicit VR little endian. Dropped verbatim into an
    implicit-VR object, ``(0010,0010) XX 0x000C`` is read as a four-byte length
    of 0x000C5858 -- 808 kilobytes the object does not have. The attack becomes
    an accidental truncation error instead of the VR test it was written as.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), name)
    result = attack_catalog.AttackResult(
        name='invalid_vr', category='parser',
        payload=(struct.pack('<HH', 0x0010, 0x0010) + b'XX'
                 + struct.pack('<H', 12) + b'Evil^Payload'),
        description='d', expected_behavior='e')
    rebuilt = Carrier.from_bytes(_carry(path, result).part10)
    elem = rebuilt.find(0x00100010)
    assert elem is not None
    assert elem.declared_length == 12
    assert (elem.vr is None) is implicit
    if not implicit:
        assert elem.vr == b'XX'


def test_merge_preserves_a_length_that_lies():
    """A declared length the value does not back is the attack, not an error."""
    path = _reference_image()
    result = attack_catalog.AttackResult(
        name='length_overflow', category='parser',
        payload=(struct.pack('<HH', 0x0010, 0x0010) + b'PN'
                 + struct.pack('<H', 0xFF00) + b'AB'
                 + struct.pack('<HH', 0x0008, 0x0060) + b'CS'
                 + struct.pack('<H', 2) + b'OT'),
        description='d', expected_behavior='e')
    carried = _carry(path, result)
    # The over-declared element does not scan, so it rides at the end intact
    # rather than being silently repaired into a well-formed one.
    assert struct.pack('<H', 0xFF00) in carried.dataset
    assert result.metadata['cstore_file_appended_bytes'] > 0


# ---------------------------------------------------------------------------
# Disk-pressure bulk
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_disk_pressure_grows_the_image_instead_of_replacing_it(path):
    """Bulk is added as more of the operator's image, not instead of it.

    Overwriting Pixel Data with filler leaves Rows, Columns, Bits Allocated and
    Number of Frames describing an image that is no longer there, so the SCP
    rejects the object on geometry and the storage quota is never tested.
    """
    carrier = Carrier.from_file(path)
    original = carrier.value_of(TAG_PIXEL_DATA)
    result = next(r for r in attack_catalog.StorageSCPAbuseAttacks.all()
                  if r.metadata.get('coverage_scope')
                  == 'storage-quota-disk-pressure')
    carried = _carry(path, result)
    rebuilt = Carrier.from_bytes(carried.part10)
    grown = rebuilt.value_of(TAG_PIXEL_DATA)

    if original is None:
        assert result.metadata['cstore_file_bulk_placement'] in (
            'private_element', 'skipped_empty_pixel_data',
            'skipped_unparsable_fragments')
        return
    assert result.metadata['cstore_file_bulk_placement'] in (
        'native_frames', 'encapsulated_fragments')
    assert grown is not None and len(grown) > len(original)
    if result.metadata['cstore_file_bulk_placement'] == 'native_frames':
        assert grown.startswith(original), 'the original volume was discarded'
    else:
        # Encapsulated: the fragments survive, and only the Basic Offset Table
        # is replaced -- its offsets no longer point at frame boundaries, and
        # PS3.5 A.4 says an empty one is the correct way to say so.
        _bot, fragments, _delim = split_encapsulated(original,
                                                     carrier.little_endian)
        grown_parts = split_encapsulated(grown, carrier.little_endian)
        assert grown_parts is not None
        assert grown_parts[1][:len(fragments)] == fragments
        assert grown_parts[0] == empty_basic_offset_table(carrier.little_endian)
    assert result.metadata['cstore_file_effective_pixel_bytes'] >= 256 * 1024


@pytest.mark.parametrize('name', ['CT_small.dcm', 'MR_small.dcm',
                                  'MR_small_implicit.dcm',
                                  'MR_small_bigendian.dcm'])
def test_grown_native_pixel_data_still_matches_the_geometry(name):
    """rows x columns x samples x bytes x frames still equals the value length.

    The consistency check every SCP that validates images performs.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), name)
    result = next(r for r in attack_catalog.StorageSCPAbuseAttacks.all()
                  if r.metadata.get('coverage_scope')
                  == 'storage-quota-disk-pressure')
    dataset = pydicom.dcmread(io.BytesIO(_carry(path, result).part10))
    expected = (int(dataset.Rows) * int(dataset.Columns)
                * int(dataset.get('SamplesPerPixel', 1))
                * ((int(dataset.BitsAllocated) + 7) // 8)
                * int(dataset.get('NumberOfFrames', 1)))
    assert len(dataset.PixelData) == expected


@pytest.mark.parametrize('name', ['JPEG2000.dcm', 'SC_rgb_rle_2frame.dcm',
                                  'MR_small_RLE.dcm'])
def test_grown_encapsulated_pixel_data_is_still_decodable(name):
    """Every fragment is a whole codestream the carrier already held.

    Padding an encapsulated element with native filler produces bytes no
    decoder will touch. Repeating real fragments produces a longer study.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), name)
    result = next(r for r in attack_catalog.StorageSCPAbuseAttacks.all()
                  if r.metadata.get('coverage_scope')
                  == 'storage-quota-disk-pressure')
    carried = _carry(path, result)
    dataset = pydicom.dcmread(io.BytesIO(carried.part10))
    from pydicom.encaps import generate_frames

    frames = list(generate_frames(dataset.PixelData,
                                  number_of_frames=int(
                                      dataset.get('NumberOfFrames', 1))))
    assert len(frames) == int(dataset.get('NumberOfFrames', 1))
    original = pydicom.dcmread(path)
    first_original = next(iter(generate_frames(
        original.PixelData,
        number_of_frames=int(original.get('NumberOfFrames', 1)))))
    assert frames[0] == first_original


# ---------------------------------------------------------------------------
# The catalog as a whole
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_every_cstore_attack_renders_on_every_encoding(path):
    """No attack in the catalog raises while being placed on a carrier.

    A sequence-depth bomb used to raise RecursionError inside the framework, so
    the payload never left the machine and the operator saw a traceback where a
    finding belonged.
    """
    for result in _cstore_attacks():
        carried = _carry(path, result)
        assert carried.dataset, result.name
        assert result.metadata['cstore_file_mutation'], result.name


def _attack_declares(result, tag):
    """True when the attack's own Data Set writes ``tag``."""
    blob = runner._attack_dataset_payload(result)
    if not blob:
        return False
    implicit, little = runner._attack_dataset_encoding(result)
    elements, _tail = scan_dataset(blob, implicit, little)
    return any(elem.tag == tag for elem in elements)


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_every_cstore_attack_keeps_the_carriers_pixel_data(path):
    """Only attacks that are *about* the image are allowed to touch it.

    An attack that writes its own (7FE0,0010) -- a geometry-versus-data
    mismatch, an encapsulation bomb -- replaces it on purpose, and merging
    keeps that mechanism while leaving the rest of the operator's object in
    place. Everything else must find the image where it left it.
    """
    carrier = Carrier.from_file(path)
    original = carrier.value_of(TAG_PIXEL_DATA)
    assert original
    for result in _cstore_attacks():
        if result.metadata.get('coverage_scope') == 'storage-quota-disk-pressure':
            continue
        if _attack_declares(result, TAG_PIXEL_DATA):
            continue
        assert original in _carry(path, result).dataset, result.name


def test_every_attack_gets_its_own_instance_identity():
    """Two attacks never collide on, or overwrite, one stored instance.

    Half the catalog writes ``1.2.3.4.5`` into its own Data Set because a Data
    Set needs a SOP Instance UID. Merged verbatim, every one of those attacks
    would arrive as the same instance and the archive would keep the last.
    """
    path = _reference_image()
    seen = {}
    for result in _cstore_attacks():
        carried = _carry(path, result)
        uid = Carrier.from_bytes(carried.part10).text_of(TAG_SOP_INSTANCE_UID)
        # An attack whose payload *is* the SOP Instance UID keeps its value.
        mutation = result.metadata.get('cstore_file_mutation') or ''
        if 'sop_instance_uid' in mutation or 'cstore_field_overrides' in mutation:
            continue
        assert uid not in seen, (
            f'{result.name} reused {uid} from {seen.get(uid)}')
        seen[uid] = result.name


def test_a_placeholder_identity_never_overwrites_the_stamped_one():
    path = _reference_image()
    result = attack_catalog.AttackResult(
        name='placeholder', category='parser',
        payload=(struct.pack('<HH', 0x0008, 0x0018) + b'UI'
                 + struct.pack('<H', 10) + b'1.2.3.4.5\x00'),
        description='d', expected_behavior='e')
    carried = _carry(path, result)
    stamped = result.metadata['cstore_file_base_sop_instance_uid']
    assert Carrier.from_bytes(carried.part10).text_of(
        TAG_SOP_INSTANCE_UID) == stamped
    assert result.metadata['cstore_file_kept_carrier_identity'] == 1


def test_a_malformed_identity_is_the_attack_and_survives():
    """An identifier no UID may hold is the payload, not a placeholder."""
    path = _reference_image()
    payload = b'../../../../../../tmp/c-scare\x00'
    result = attack_catalog.AttackResult(
        name='traversal_uid', category='parser',
        payload=(struct.pack('<HH', 0x0008, 0x0018) + b'UI'
                 + struct.pack('<H', len(payload)) + payload),
        description='d', expected_behavior='e')
    carried = _carry(path, result)
    assert payload in carried.dataset
    assert 'cstore_file_kept_carrier_identity' not in result.metadata


def test_no_attack_is_reported_as_applied_when_it_was_refused():
    """A mutation the overlay could not make is named, not swallowed."""
    path = _reference_image()
    for result in _cstore_attacks():
        _carry(path, result)
        refused = result.metadata.get('cstore_file_refused')
        assert not refused, f'{result.name}: {refused}'


def test_unmappable_field_override_is_refused_out_loud():
    path = _reference_image()
    result = attack_catalog.AttackResult(
        name='bogus', category='parser', payload=b'x', description='d',
        expected_behavior='e',
        metadata={'cstore_field_overrides': {'NotADicomKeyword': 'value'}})
    _carry(path, result)
    assert 'NotADicomKeyword' in result.metadata['cstore_file_refused']


# ---------------------------------------------------------------------------
# The Part-10 rendering
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_part10_rendering_opens_as_a_file(path):
    """--dry-run output is a file a viewer opens, not a bare Data Set."""
    result = attack_catalog.PathTraversalAttacks.sop_instance_uid_traversal(
        'posix_proof')
    blob = _carry(path, result).part10
    dataset = pydicom.dcmread(io.BytesIO(blob), force=True)
    assert dataset.file_meta.TransferSyntaxUID
    assert blob[128:132] == b'DICM'


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_part10_file_meta_agrees_with_the_data_set(path):
    """(0002,0003) and (0008,0018) name the same instance.

    A file whose header disagrees with its body is one the operator has to
    reconcile by hand before they can trust what they are looking at.
    """
    if is_nonconformant(path):
        pytest.skip('image is not readable DICOM to begin with')
    result = attack_catalog.AttackResult(
        name='plain', category='parser', payload=b'', description='d',
        expected_behavior='e')
    carried = _carry(path, result)
    dataset = pydicom.dcmread(io.BytesIO(carried.part10), force=True)
    assert (str(dataset.file_meta.MediaStorageSOPInstanceUID)
            == str(dataset.SOPInstanceUID))
    assert (str(dataset.file_meta.MediaStorageSOPInstanceUID)
            == result.metadata['cstore_file_base_sop_instance_uid'])


@pytest.mark.parametrize('path', ENCODINGS, ids=image_id)
def test_part10_group_length_is_repaired_after_a_file_meta_edit(path):
    """(0002,0000) still says how many bytes the group holds."""
    result = attack_catalog.AttackResult(
        name='plain', category='parser', payload=b'', description='d',
        expected_behavior='e')
    rebuilt = Carrier.from_bytes(_carry(path, result).part10)
    declared = rebuilt._file_meta_values.get(0x00020000)
    assert declared is not None
    assert struct.unpack('<I', declared)[0] == len(rebuilt.file_meta) - 12
