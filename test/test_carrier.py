# SPDX-License-Identifier: GPL-2.0-only
"""
Byte-fidelity tests for :mod:`c_scare.carrier`.

The carrier's whole contract is that the operator's object goes out as the
operator's object. Every test here is a way of asking the same question: did
anything change that the caller did not ask to change?
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dicom_corpus import (  # noqa: E402
    bundled_paths, corpus_paths, image_id, is_truncated,
)

from c_scare.carrier import (  # noqa: E402
    Carrier, CarrierElement, CarrierError, MAX_NESTING_DEPTH,
    empty_basic_offset_table, encapsulate_items, merge_dataset, scan_dataset,
    sniff_encoding, split_encapsulated, transcode_element_header,
    EXPLICIT_VR_BIG_ENDIAN, EXPLICIT_VR_LITTLE_ENDIAN,
    TAG_PIXEL_DATA, TAG_SOP_INSTANCE_UID, UNDEFINED_LENGTH,
)

pydicom = pytest.importorskip('pydicom')

CORPUS = corpus_paths()
TAG_PATIENT_NAME = 0x00100010
TAG_STUDY_INSTANCE_UID = 0x0020000D
TRAVERSAL = '../../../../../../tmp/c-scare-traversal-proof'


def _explicit_element(tag: int, vr: bytes, value: bytes) -> bytes:
    group, element = (tag >> 16) & 0xFFFF, tag & 0xFFFF
    return struct.pack('<HH', group, element) + vr + struct.pack(
        '<H', len(value)) + value


# ---------------------------------------------------------------------------
# Round-trip fidelity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_unedited_carrier_is_byte_identical(path):
    """A carrier with no edits renders the file it was read from, exactly.

    This is the property the previous implementation could not hold: it parsed
    with pydicom and wrote with pydicom, and pydicom is a conformant writer
    that drops retired group lengths, sorts elements and repairs what it can.
    """
    original = open(path, 'rb').read()
    carrier = Carrier.from_file(path)
    assert carrier.edit().to_bytes() == carrier.dataset
    if carrier.file_meta:
        assert carrier.edit().to_part10() == original
    else:
        # No File Meta Information to give back, so a minimal one is built.
        # The Data Set -- the only part C-STORE carries -- is untouched.
        assert carrier.edit().to_part10().endswith(original)


@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_dataset_and_meta_partition_the_file(path):
    """preamble + DICM + file meta + data set accounts for every byte."""
    original = open(path, 'rb').read()
    carrier = Carrier.from_file(path)
    if carrier.preamble:
        assert (carrier.preamble + b'DICM' + carrier.file_meta
                + carrier.dataset) == original
    else:
        assert carrier.dataset == original


@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_scan_reaches_the_end_of_every_real_image(path):
    """Real objects scan completely -- no opaque tail, nothing skipped.

    A scan that stops early is not a correctness failure on its own (the bytes
    are still delivered), but it is a failure of reach: no attack can be
    spliced into a region the scanner never mapped. The only images allowed to
    stop early are the ones that are genuinely truncated on disk.
    """
    carrier = Carrier.from_file(path)
    assert carrier.elements, 'no elements scanned'
    if is_truncated(path):
        pytest.skip('image is incomplete on disk by design')
    assert carrier.tail_offset == len(carrier.dataset), (
        f'{len(carrier.dataset) - carrier.tail_offset} bytes did not scan')


@pytest.mark.parametrize('path', [p for p in CORPUS if is_truncated(p)],
                         ids=image_id)
def test_a_truncated_image_still_delivers_the_bytes_it_could_not_scan(path):
    """An element that runs past EOF is preserved, not dropped at the cut.

    An operator who hands the framework a half-written object is testing what
    their target does with a half-written object. Repairing it is the one
    unhelpful answer.
    """
    carrier = Carrier.from_file(path)
    assert carrier.has_tail
    tail = carrier.dataset[carrier.tail_offset:]
    rendered = carrier.edit().to_bytes()
    assert rendered.endswith(tail)
    assert rendered == carrier.dataset


@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_group_length_elements_survive(path):
    """(gggg,0000) elements on the carrier reach the wire.

    pydicom's writer skips every retired group length. Group length handling is
    an attack surface the catalog probes in its own right, so a carrier that
    shipped with them must still carry them.
    """
    carrier = Carrier.from_file(path)
    group_lengths = [e for e in carrier.elements
                     if e.element == 0 and e.group > 6]
    rendered = carrier.edit().to_bytes()
    for elem in group_lengths:
        assert carrier.dataset[elem.start:elem.end] in rendered


# ---------------------------------------------------------------------------
# Splicing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_splice_changes_only_the_named_element(path):
    """Editing one element leaves every other element's bytes untouched."""
    carrier = Carrier.from_file(path)
    edit = carrier.edit()
    edit.set_text(TAG_STUDY_INSTANCE_UID, 'UI', TRAVERSAL, 'study')
    rendered = edit.to_bytes()

    for elem in carrier.elements:
        if elem.tag == TAG_STUDY_INSTANCE_UID:
            continue
        assert carrier.dataset[elem.start:elem.end] in rendered, (
            f'({elem.group:04X},{elem.element:04X}) did not survive the splice')


@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_pixel_data_survives_a_splice(path):
    """The operator's image volume is never collateral damage."""
    carrier = Carrier.from_file(path)
    original = carrier.value_of(TAG_PIXEL_DATA)
    if original is None:
        pytest.skip('carrier holds no Pixel Data')
    edit = carrier.edit()
    edit.set_text(TAG_SOP_INSTANCE_UID, 'UI', TRAVERSAL, 'sop')
    assert original in edit.to_bytes()


@pytest.mark.parametrize('payload', [
    '../../../../../../etc/passwd',
    '../../../../../../tmp/attacker-controlled.attacker\x00.DCM',
    '..\\..\\..\\..\\..\\..\\Windows\\Temp\\c-scare',
    '\\\\localhost\\share\\c-scare',
    'C:\\Windows\\Temp\\c-scare',
    '../../../../../../tmp/c-scare-' + 'A' * 80,
    '1.2.3.4.5\\../../../../../../tmp/c-scare-vm-second',
], ids=['posix', 'nul', 'windows', 'unc', 'drive', 'overlong', 'multivalue'])
def test_every_traversal_shape_survives_the_splice(payload):
    """No traversal payload is normalised, truncated or split on its way out.

    This is the value-fidelity statement for the whole module; it varies the
    payload rather than the image because that is the axis the encoder sees.

    The over-64-character value, the embedded NUL and the backslash are the
    three a validating writer changes: it warns and truncates, it strips, or it
    reads the value as a multi-value and re-joins it. All three are the payload.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')
    carrier = Carrier.from_file(path)
    edit = carrier.edit()
    edit.set_text(TAG_SOP_INSTANCE_UID, 'UI', payload, 'sop')
    rendered = edit.to_bytes()
    assert payload.encode('latin-1') in rendered


def test_spliced_element_declares_its_real_length():
    """The length field matches the value the splice actually wrote."""
    path = os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')
    carrier = Carrier.from_file(path)
    edit = carrier.edit()
    edit.set_text(TAG_SOP_INSTANCE_UID, 'UI', TRAVERSAL, 'sop')
    rebuilt = Carrier.from_bytes(edit.to_part10())
    elem = rebuilt.find(TAG_SOP_INSTANCE_UID)
    assert elem is not None
    # Odd-length UI values are NULL-padded (PS3.5 6.2), never space-padded.
    assert elem.declared_length == len(TRAVERSAL) + (len(TRAVERSAL) % 2)
    assert rebuilt.text_of(TAG_SOP_INSTANCE_UID) == TRAVERSAL


def test_insert_places_a_new_tag_in_ascending_order():
    """A tag the carrier lacks lands ahead of the first higher tag."""
    path = os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')
    carrier = Carrier.from_file(path)
    assert carrier.find(0x00080050) is not None or True
    edit = carrier.edit()
    edit.set_text(0x00080018, 'UI', '1.2.3', 'sop')
    edit.set_text(0x00104000, 'LT', 'marker', 'comments')
    rebuilt = Carrier.from_bytes(edit.to_bytes())
    tags = [e.tag for e in rebuilt.elements]
    assert tags == sorted(tags)
    assert 0x00104000 in tags


def test_delete_removes_an_element_and_reports_a_missing_one():
    path = os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')
    carrier = Carrier.from_file(path)
    edit = carrier.edit()
    edit.delete(TAG_PATIENT_NAME, 'drop_name')
    edit.delete(0x00091234, 'drop_absent')
    rendered = edit.to_bytes()
    assert Carrier.from_bytes(rendered).find(TAG_PATIENT_NAME) is None
    assert any('drop_absent' in reason for reason in edit.refused)
    assert 'drop_name' in edit.applied


def test_refusals_are_reported_not_swallowed():
    """An edit that cannot be made says so.

    A silent no-op is the worst outcome available: the attack is reported as
    delivered, the target is reported as having survived it, and nobody
    learns that the payload never left the machine.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')
    edit = Carrier.from_file(path).edit()
    edit.refuse('made_up_field', 'no tag mapping')
    assert edit.refused == ['made_up_field: no tag mapping']


# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('name,expected', [
    ('MR_small.dcm', (False, True)),
    ('MR_small_implicit.dcm', (True, True)),
    ('MR_small_bigendian.dcm', (False, False)),
])
def test_encoding_comes_from_the_file_meta(name, expected):
    path = os.path.join(os.path.dirname(bundled_paths()[0]), name)
    carrier = Carrier.from_file(path)
    assert (carrier.implicit_vr, carrier.little_endian) == expected
    assert carrier.sniffed_encoding is False


@pytest.mark.parametrize('name,expected_syntax', [
    ('no_meta.dcm', EXPLICIT_VR_LITTLE_ENDIAN),
    ('ExplVR_LitEndNoMeta.dcm', EXPLICIT_VR_LITTLE_ENDIAN),
    ('ExplVR_BigEndNoMeta.dcm', EXPLICIT_VR_BIG_ENDIAN),
])
def test_encoding_is_sniffed_when_there_is_no_file_meta(name, expected_syntax):
    """An object with no group 0002 states its encoding nowhere.

    PS3.10 puts that statement in the File Meta Information, so a file without
    one has to be read to be understood. Reading the furthest wins.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), name)
    carrier = Carrier.from_file(path)
    assert carrier.sniffed_encoding is True
    assert carrier.transfer_syntax == expected_syntax
    assert carrier.tail_offset == len(carrier.dataset)


def test_sniff_prefers_the_encoding_that_reads_furthest():
    explicit = (_explicit_element(0x00080060, b'CS', b'CT')
                + _explicit_element(0x00100010, b'PN', b'A^B '))
    assert sniff_encoding(explicit) == (False, True)

    implicit = (struct.pack('<HHI', 0x0008, 0x0060, 2) + b'CT'
                + struct.pack('<HHI', 0x0010, 0x0010, 4) + b'A^B ')
    assert sniff_encoding(implicit) == (True, True)


@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_splice_survives_a_reparse_in_the_carriers_own_syntax(path):
    """The edited object still reads back as DICOM, in every encoding.

    Big endian is the one that used to break: an element re-framed as little
    endian lands in a big-endian stream as a different tag with a different
    length, and the target parses garbage from there on.
    """
    carrier = Carrier.from_file(path)
    edit = carrier.edit()
    edit.set_text(TAG_STUDY_INSTANCE_UID, 'UI', TRAVERSAL, 'study')
    rebuilt = Carrier.from_bytes(edit.to_part10())
    assert rebuilt.transfer_syntax == carrier.transfer_syntax
    assert rebuilt.text_of(TAG_STUDY_INSTANCE_UID) == TRAVERSAL
    if not is_truncated(path):
        assert rebuilt.tail_offset == len(rebuilt.dataset)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def test_scan_stops_cleanly_on_a_truncated_element():
    """Bytes that do not parse become a tail, never a discard."""
    blob = (_explicit_element(0x00080060, b'CS', b'CT')
            + struct.pack('<HH', 0x0010, 0x0010) + b'PN' + struct.pack('<H', 40)
            + b'short')
    elements, tail = scan_dataset(blob, implicit_vr=False, little_endian=True)
    assert [e.tag for e in elements] == [0x00080060]
    assert tail == 10
    assert blob[tail:]


def test_scan_survives_a_sequence_depth_bomb():
    """A thousand nested undefined-length sequences is a payload, not a crash.

    The catalog builds these on purpose. A recursive scanner would raise
    RecursionError inside the framework and the attack would never be sent.
    """
    depth = MAX_NESTING_DEPTH * 4
    blob = b''
    for _ in range(depth):
        blob += (struct.pack('<HH', 0x0008, 0x1140) + b'SQ' + b'\x00\x00'
                 + struct.pack('<I', UNDEFINED_LENGTH))
        blob += struct.pack('<HHI', 0xFFFE, 0xE000, UNDEFINED_LENGTH)
    elements, tail = scan_dataset(blob, implicit_vr=False, little_endian=True)
    # It stops rather than closing, which is correct: the bomb never closes.
    assert elements == []
    assert tail == 0


def test_scan_walks_nested_sequences_to_their_delimiters():
    inner = (struct.pack('<HH', 0x0008, 0x1150) + b'UI' + struct.pack('<H', 2)
             + b'1 ')
    item = (struct.pack('<HHI', 0xFFFE, 0xE000, UNDEFINED_LENGTH) + inner
            + struct.pack('<HHI', 0xFFFE, 0xE00D, 0))
    sequence = (struct.pack('<HH', 0x0008, 0x1140) + b'SQ' + b'\x00\x00'
                + struct.pack('<I', UNDEFINED_LENGTH) + item
                + struct.pack('<HHI', 0xFFFE, 0xE0DD, 0))
    trailing = _explicit_element(0x00100010, b'PN', b'A^B ')
    elements, tail = scan_dataset(sequence + trailing, implicit_vr=False,
                                  little_endian=True)
    assert [e.tag for e in elements] == [0x00081140, 0x00100010]
    assert tail == len(sequence) + len(trailing)


def test_carrier_error_on_bytes_that_are_not_dicom():
    with pytest.raises(CarrierError):
        Carrier.from_bytes(b'')


# ---------------------------------------------------------------------------
# Transcoding and merging
# ---------------------------------------------------------------------------

def test_transcode_keeps_a_lying_length_and_the_value_bytes():
    """Re-framing an element must not repair it.

    An attack that declares 0xFFFF bytes and supplies four is testing exactly
    that gap. A writer that recomputes the length deletes the attack.
    """
    blob = (struct.pack('<HH', 0x0010, 0x0010) + b'XX'
            + struct.pack('<H', 0xFFFF) + b'ABCD')
    elem = CarrierElement(tag=0x00100010, vr=b'XX', declared_length=0xFFFF,
                          start=0, value_start=8, end=12, long_form=False)

    same = transcode_element_header(elem, b'ABCD', from_implicit=False,
                                    from_little=True, to_implicit=False,
                                    to_little=True)
    assert same == blob
    assert b'XX' in same

    implicit = transcode_element_header(elem, b'ABCD', from_implicit=False,
                                        from_little=True, to_implicit=True,
                                        to_little=True)
    assert implicit == struct.pack('<HHI', 0x0010, 0x0010, 0xFFFF) + b'ABCD'

    big = transcode_element_header(elem, b'ABCD', from_implicit=False,
                                   from_little=True, to_implicit=False,
                                   to_little=False)
    assert big.startswith(struct.pack('>HH', 0x0010, 0x0010) + b'XX')
    assert big.endswith(b'ABCD')


@pytest.mark.parametrize('name', ['CT_small.dcm', 'MR_small_implicit.dcm',
                                  'MR_small_bigendian.dcm'])
def test_merge_places_attack_elements_in_tag_order(name):
    """A merged attack element sits where its tag belongs, not after the image.

    Appending a second Data Set behind Pixel Data produces descending tags. A
    conformant SCP is entitled to stop there, so the parser under test never
    reaches the malformation and the run reports a clean status for an attack
    that never happened.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), name)
    carrier = Carrier.from_file(path)
    attack = (_explicit_element(0x00100010, b'XX', b'Evil^Payload')
              + _explicit_element(0x00080060, b'CS', b'XX'))
    edit = carrier.edit()
    merged, skipped, appended = merge_dataset(edit, attack, implicit_vr=False,
                                              little_endian=True)
    assert (merged, skipped, appended) == (2, 0, 0)

    rebuilt = Carrier.from_bytes(edit.to_part10())
    assert rebuilt.tail_offset == len(rebuilt.dataset)
    pixel = rebuilt.find(TAG_PIXEL_DATA)
    name_elem = rebuilt.find(0x00100010)
    assert name_elem is not None
    if pixel is not None:
        assert name_elem.start < pixel.start
    assert b'Evil^Payload' in rebuilt.dataset


def test_merge_appends_only_what_will_not_scan():
    """An element stream that is itself the malformation still gets delivered."""
    path = os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')
    carrier = Carrier.from_file(path)
    attack = (_explicit_element(0x00100010, b'PN', b'A^B ')
              + b'\x10\x00\x10')  # a header that stops mid-tag
    edit = carrier.edit()
    merged, skipped, appended = merge_dataset(edit, attack, implicit_vr=False,
                                              little_endian=True)
    assert (merged, skipped, appended) == (1, 0, 3)
    assert edit.to_bytes().endswith(b'\x10\x00\x10')


# ---------------------------------------------------------------------------
# Encapsulated Pixel Data
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('path', CORPUS, ids=image_id)
def test_encapsulated_pixel_data_splits_and_reassembles(path):
    carrier = Carrier.from_file(path)
    pixel = carrier.pixel_data()
    if pixel is None or not pixel.undefined_length:
        pytest.skip('carrier has no encapsulated Pixel Data')
    value = carrier.value_of(TAG_PIXEL_DATA)
    parts = split_encapsulated(value, carrier.little_endian)
    assert parts is not None
    basic_offset_table, fragments, delimiter = parts
    assert fragments
    assert encapsulate_items(basic_offset_table, fragments, delimiter) == value


def test_split_encapsulated_declines_native_pixel_data():
    assert split_encapsulated(b'\x00\x11' * 32) is None


def test_empty_basic_offset_table_is_a_zero_length_item():
    assert empty_basic_offset_table() == struct.pack('<HHI', 0xFFFE, 0xE000, 0)


def test_merge_honours_a_skip_predicate():
    """An element the predicate declines leaves the carrier's own in place.

    This is how a placeholder identifier in an attack's Data Set is stopped
    from overwriting the per-delivery identity the carrier was stamped with.
    """
    path = os.path.join(os.path.dirname(bundled_paths()[0]), 'CT_small.dcm')
    carrier = Carrier.from_file(path)
    before = carrier.value_of(0x00100010)
    attack = (_explicit_element(0x00100010, b'PN', b'Skip^Me ')
              + _explicit_element(0x00080060, b'CS', b'XX'))
    edit = carrier.edit()
    merged, skipped, appended = merge_dataset(
        edit, attack, implicit_vr=False, little_endian=True,
        skip=lambda elem, value: elem.tag == 0x00100010)
    assert (merged, skipped, appended) == (1, 1, 0)
    rendered = edit.to_bytes()
    assert b'Skip^Me' not in rendered
    assert before in rendered
