"""
Characterization tests for c_scare.corruptor.Corruptor.

The corruptor is a core crafting path that previously had no direct test
coverage. These tests lock its observable encode() behaviour for every
corruption primitive so the internal state model can be refactored safely.

Byte layout is pinned to Explicit VR Little Endian via
``encode(implicit_vr=False, little_endian=True)`` so assertions on tag/VR/value
bytes are deterministic.
"""

import struct

import pytest

from c_scare.corruptor import Corruptor


def _tag_le(group, element):
    """4-byte Explicit-VR-LE on-the-wire encoding of a tag."""
    return struct.pack('<HH', group, element)


def _build():
    """A small, fresh pydicom dataset built the same way every test."""
    pydicom = pytest.importorskip('pydicom')
    ds = pydicom.Dataset()
    ds.add_new(0x00080060, 'CS', 'OT')          # Modality
    ds.PatientName = 'Doe^John'                  # (0010,0010) PN
    ds.PatientID = '12345'                       # (0010,0020) LO
    return ds


def _encode(c):
    return c.encode(implicit_vr=False, little_endian=True)


def test_baseline_encode_is_deterministic_and_nonempty():
    c1 = Corruptor(_build())
    c2 = Corruptor(_build())
    out1 = _encode(c1)
    out2 = _encode(c2)
    assert out1 == out2
    assert len(out1) > 0
    # The three tags are present in ascending order.
    pn = out1.index(_tag_le(0x0010, 0x0010))
    pid = out1.index(_tag_le(0x0010, 0x0020))
    mod = out1.index(_tag_le(0x0008, 0x0060))
    assert mod < pn < pid


def test_set_vr_overrides_vr_bytes():
    c = Corruptor(_build())
    baseline = _encode(c)
    assert b'PN' in baseline
    c.set_vr(0x00100010, 'XX')
    out = _encode(c)
    # The VR bytes immediately follow the 4-byte tag.
    off = out.index(_tag_le(0x0010, 0x0010))
    assert out[off + 4:off + 6] == b'XX'


def test_set_length_lies_about_length_without_changing_value():
    c = Corruptor(_build())
    c.set_length(0x00100020, 0xFF)
    out = _encode(c)
    off = out.index(_tag_le(0x0010, 0x0020))
    # Explicit VR LE short form: tag(4) + VR(2) + len(2 LE).
    length = struct.unpack('<H', out[off + 6:off + 8])[0]
    assert length == 0xFF
    # The actual value bytes are still emitted.
    assert b'12345' in out


def test_set_raw_value_replaces_value_bytes():
    c = Corruptor(_build())
    c.set_raw_value(0x00100010, b'\x00' * 16)
    out = _encode(c)
    assert b'Doe^John' not in out


def test_delete_removes_element():
    c = Corruptor(_build())
    assert _tag_le(0x0010, 0x0020) in _encode(c)
    c.delete(0x00100020)
    assert _tag_le(0x0010, 0x0020) not in _encode(c)


def test_inject_after_inserts_raw_bytes():
    marker = b'\xde\xad\xbe\xef'
    c = Corruptor(_build())
    assert marker not in _encode(c)
    c.inject_after(0x00100010, marker)
    assert marker in _encode(c)


@pytest.mark.parametrize('position', ['end', 'before', 'after'])
def test_duplicate_emits_two_copies(position):
    c = Corruptor(_build())
    tag = _tag_le(0x0010, 0x0010)
    assert _encode(c).count(tag) == 1
    c.duplicate(0x00100010, position=position)
    assert _encode(c).count(tag) == 2


def test_duplicate_before_and_after_position_relative_to_original():
    # 'before' places the dup at a lower byte offset than 'after' would.
    cb = Corruptor(_build())
    cb.duplicate(0x00100020, position='before')
    before_first = _encode(cb).index(_tag_le(0x0010, 0x0020))

    ca = Corruptor(_build())
    ca.duplicate(0x00100020, position='after')
    after_first = _encode(ca).index(_tag_le(0x0010, 0x0020))

    # The 'before' copy shifts the first occurrence earlier than 'after'.
    assert before_first <= after_first


def test_reorder_changes_element_order():
    c = Corruptor(_build())
    c.reorder([0x00100020, 0x00100010, 0x00080060])
    out = _encode(c)
    pid = out.index(_tag_le(0x0010, 0x0020))
    pn = out.index(_tag_le(0x0010, 0x0010))
    assert pid < pn


def test_clear_resets_all_modifications():
    base = _encode(Corruptor(_build()))
    c = Corruptor(_build())
    c.set_vr(0x00100010, 'XX').delete(0x00100020).duplicate(0x00080060)
    assert _encode(c) != base
    c.clear()
    assert _encode(c) == base


def test_set_vr_in_sequence_applies_override():
    pydicom = pytest.importorskip('pydicom')
    ds = _build()
    item = pydicom.Dataset()
    item.add_new(0x00080100, 'SH', 'CODE1')      # CodeValue
    ds.add_new(0x0040A730, 'SQ', [item])         # ContentSequence
    c = Corruptor(ds)
    c.set_vr_in_sequence(0x0040A730, 0, 0x00080100, 'XX')
    out = c.encode(implicit_vr=False, little_endian=True)
    assert _tag_le(0x0040, 0xA730) in out
    # Regression: the in-sequence override used to be a silent no-op because the
    # stored path key never matched the encoder's lookup. The nested CodeValue's
    # VR must now be the corrupt 'XX', not the original 'SH'.
    idx = out.find(_tag_le(0x0008, 0x0100))
    assert idx != -1
    assert out[idx + 4:idx + 6] == b'XX'


def test_set_vr_in_sequence_nested_depth():
    """The encoder threads the item path at every depth, so an override keyed by
    the nested path form resolves into a sequence-within-a-sequence."""
    pydicom = pytest.importorskip('pydicom')
    from c_scare.corruptor import Override
    ds = _build()
    inner = pydicom.Dataset()
    inner.add_new(0x00080102, 'SH', 'SCHEME')        # CodingSchemeDesignator
    middle = pydicom.Dataset()
    middle.add_new(0x00080100, 'SQ', [inner])        # nested sequence within item
    ds.add_new(0x0040A730, 'SQ', [middle])           # ContentSequence
    c = Corruptor(ds)
    # Two-level threaded path: ContentSequence[0] -> (0008,0100)[0] -> (0008,0102)
    c._sequence_overrides["(0040,A730)[0].(0008,0100)[0].(0008,0102)"] = \
        Override(vr='YY')
    out = c.encode(implicit_vr=False, little_endian=True)
    idx = out.find(_tag_le(0x0008, 0x0102))
    assert idx != -1
    assert out[idx + 4:idx + 6] == b'YY'
