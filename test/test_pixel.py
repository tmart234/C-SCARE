# SPDX-License-Identifier: GPL-2.0-only
"""
Tests for DICOM Pixel Data handling: Scapy layers, seed extraction, and PixelFuzzer.
"""
import struct
import sys
import os
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from c_scare.pixel import (
    # Manual API
    EncapsulatedPixelData,
    Fragment,
    PixelData,
    # Tags
    ITEM_TAG_LE,
    SEQ_DELIM_TAG_LE,
    # Corruption helpers
    corrupt_jpeg_header,
    corrupt_jpeg_eoi,
    truncate_fragment,
    duplicate_bytes,
)


# =============================================================================
# Manual API Tests (existing classes)
# =============================================================================

class TestFragment:
    def test_encode_basic(self):
        frag = Fragment(b'\xFF\xD8\xFF\xD9')
        encoded = frag.encode()
        # Item tag + 4-byte length + data
        assert encoded[:4] == ITEM_TAG_LE
        length = struct.unpack('<I', encoded[4:8])[0]
        assert length == 4
        assert encoded[8:] == b'\xFF\xD8\xFF\xD9'

    def test_encode_length_override(self):
        frag = Fragment(b'\x00\x00', length_override=0xDEAD)
        encoded = frag.encode()
        length = struct.unpack('<I', encoded[4:8])[0]
        assert length == 0xDEAD
        # Actual data is still 2 bytes
        assert encoded[8:10] == b'\x00\x00'

    def test_encode_odd_length_padded(self):
        frag = Fragment(b'\x01\x02\x03')
        encoded = frag.encode()
        # 3 bytes data + 1 byte padding = 4 bytes after header
        assert len(encoded) == 4 + 4 + 4  # tag + length + data+pad
        assert encoded[-1:] == b'\x00'  # padding byte


class TestEncapsulatedPixelData:
    def test_init_default(self):
        epd = EncapsulatedPixelData()
        assert epd.fragments == []
        assert epd.include_delimiter is True
        assert epd.transfer_syntax is None

    def test_init_with_transfer_syntax(self):
        epd = EncapsulatedPixelData(transfer_syntax='1.2.840.10008.1.2.4.50')
        assert epd.transfer_syntax == '1.2.840.10008.1.2.4.50'

    def test_add_fragment(self):
        epd = EncapsulatedPixelData()
        epd.add_fragment(b'\xFF\xD8')
        epd.add_fragment(b'\xFF\xD9')
        assert len(epd.fragments) == 2

    def test_encode_empty(self):
        epd = EncapsulatedPixelData()
        encoded = epd.encode()
        # Should have: BOT (empty) + seq delimiter
        # BOT: item_tag(4) + length(4) = 8 bytes
        # Delimiter: tag(4) + length(4) = 8 bytes
        assert len(encoded) == 16

    def test_encode_with_fragment(self):
        epd = EncapsulatedPixelData()
        epd.add_fragment(b'\xFF\xD8\xFF\xD9')
        encoded = epd.encode()
        # BOT(8) + Fragment(8+4) + Delimiter(8) = 28
        assert len(encoded) == 28
        # Check delimiter at end
        assert encoded[-8:-4] == SEQ_DELIM_TAG_LE
        assert encoded[-4:] == b'\x00\x00\x00\x00'

    def test_encode_no_delimiter(self):
        epd = EncapsulatedPixelData()
        epd.add_fragment(b'\xFF\xD8\xFF\xD9')
        epd.include_delimiter = False
        encoded = epd.encode()
        # BOT(8) + Fragment(8+4) = 20 (no delimiter)
        assert len(encoded) == 20
        assert SEQ_DELIM_TAG_LE not in encoded

    def test_set_offset_table(self):
        epd = EncapsulatedPixelData()
        epd.add_fragment(b'\x00' * 10)
        epd.set_offset_table([0, 18])
        encoded = epd.encode()
        # BOT should contain two 4-byte offsets
        bot_length = struct.unpack('<I', encoded[4:8])[0]
        assert bot_length == 8  # 2 offsets * 4 bytes

    def test_compute_offset_table(self):
        epd = EncapsulatedPixelData()
        epd.add_fragment(b'\x00' * 10)  # 10 bytes (padded to 10 even)
        epd.add_fragment(b'\x01' * 6)   # 6 bytes
        epd.compute_offset_table()
        assert epd.offset_table_offsets[0] == 0
        # First fragment: tag(4) + length(4) + data(10) = 18
        assert epd.offset_table_offsets[1] == 18

    def test_parse_roundtrip(self):
        epd = EncapsulatedPixelData()
        epd.add_fragment(b'\xFF\xD8\xFF\xD9')
        epd.add_fragment(b'\x00\x01\x02\x03')
        encoded = epd.encode()
        parsed = EncapsulatedPixelData.parse(encoded)
        assert len(parsed.fragments) == 2
        assert parsed.fragments[0].data == b'\xFF\xD8\xFF\xD9'
        assert parsed.fragments[1].data == b'\x00\x01\x02\x03'

    def test_corrupt_fragment(self):
        epd = EncapsulatedPixelData()
        epd.add_fragment(b'\xFF\xD8\xFF\xD9')
        epd.corrupt_fragment(0, lambda d: d + b'\x00' * 10)
        assert len(epd.fragments[0].data) == 14


class TestPixelData:
    def test_expected_size(self):
        pd = PixelData(rows=256, cols=256, bits_allocated=16)
        assert pd.expected_size() == 256 * 256 * 2

    def test_dimension_mismatch(self):
        pd = PixelData.dimension_mismatch(512, 512, b'\x00' * 10)
        assert pd.rows == 512
        assert pd.cols == 512
        assert len(pd.data) == 10  # Way too small

    def test_overflow_dimensions(self):
        pd = PixelData.overflow_dimensions()
        assert pd.rows == 0xFFFF
        assert pd.cols == 0xFFFF
        assert len(pd.data) == 100


# =============================================================================
# Scapy Packet Layer Tests
# =============================================================================

try:
    from c_scare.pixel import (
        DICOMFragment,
        DICOMBasicOffsetTable,
        DICOMSequenceDelimiter,
        DICOMEncapsulatedPixelData,
        HAS_SCAPY,
    )
    from scapy.packet import raw as scapy_raw, fuzz as scapy_fuzz
    SCAPY_AVAILABLE = HAS_SCAPY
except (ImportError, Exception):
    SCAPY_AVAILABLE = False


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
class TestDICOMFragment:
    def test_build_basic(self):
        frag = DICOMFragment(data=b'\xFF\xD8\xFF\xD9')
        raw = scapy_raw(frag)
        # tag_group(2) + tag_element(2) + length(4) + data(4) = 12
        assert len(raw) == 12
        assert raw[:2] == b'\xFE\xFF'   # group 0xFFFE LE
        assert raw[2:4] == b'\x00\xE0'  # element 0xE000 LE
        length = struct.unpack('<I', raw[4:8])[0]
        assert length == 4
        assert raw[8:] == b'\xFF\xD8\xFF\xD9'

    def test_build_empty(self):
        frag = DICOMFragment(data=b'')
        raw = scapy_raw(frag)
        assert len(raw) == 8
        length = struct.unpack('<I', raw[4:8])[0]
        assert length == 0

    def test_fuzz_mutates(self):
        """Fuzz should produce different output than valid build."""
        frag = DICOMFragment(data=b'\xFF\xD8\xFF\xD9')
        valid = scapy_raw(frag)
        # Run fuzz many times - at least one should differ
        found_different = False
        for _ in range(50):
            fuzzed = scapy_raw(scapy_fuzz(DICOMFragment(data=b'\xFF\xD8\xFF\xD9')))
            if fuzzed != valid:
                found_different = True
                break
        assert found_different, "fuzz() should mutate at least the length field"


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
class TestDICOMBasicOffsetTable:
    def test_build_empty(self):
        bot = DICOMBasicOffsetTable()
        raw = scapy_raw(bot)
        assert len(raw) == 8  # tag(4) + length(4), no offsets
        length = struct.unpack('<I', raw[4:8])[0]
        assert length == 0

    def test_set_offsets(self):
        bot = DICOMBasicOffsetTable()
        bot.set_offsets([0, 100, 200])
        raw = scapy_raw(bot)
        length = struct.unpack('<I', raw[4:8])[0]
        assert length == 12  # 3 offsets * 4 bytes
        offsets = bot.get_offsets()
        assert offsets == [0, 100, 200]

    def test_get_offsets_roundtrip(self):
        bot = DICOMBasicOffsetTable()
        original = [0, 0x1000, 0x2000, 0xFFFFFFFF]
        bot.set_offsets(original)
        assert bot.get_offsets() == original


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
class TestDICOMSequenceDelimiter:
    def test_build(self):
        delim = DICOMSequenceDelimiter()
        raw = scapy_raw(delim)
        assert len(raw) == 8
        assert raw[:2] == b'\xFE\xFF'   # group 0xFFFE LE
        assert raw[2:4] == b'\xDD\xE0'  # element 0xE0DD LE
        length = struct.unpack('<I', raw[4:8])[0]
        assert length == 0


@pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
class TestDICOMEncapsulatedPixelData:
    def test_build_single_fragment(self):
        jpeg_data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\xFF\xD9'
        epd = DICOMEncapsulatedPixelData(
            fragments=[DICOMFragment(data=jpeg_data)],
        )
        raw = scapy_raw(epd)
        # BOT(8) + Fragment(8 + len(jpeg_data)) + Delimiter(8)
        expected_len = 8 + 8 + len(jpeg_data) + 8
        assert len(raw) == expected_len

    def test_build_multiple_fragments(self):
        epd = DICOMEncapsulatedPixelData(
            fragments=[
                DICOMFragment(data=b'\xFF\xD8\xFF\xD9'),
                DICOMFragment(data=b'\xFF\xD8\xFF\xD9'),
            ],
        )
        raw = scapy_raw(epd)
        # BOT(8) + 2*Fragment(12) + Delimiter(8) = 40
        assert len(raw) == 40

    def test_build_no_delimiter(self):
        epd = DICOMEncapsulatedPixelData(
            fragments=[DICOMFragment(data=b'\xFF\xD8\xFF\xD9')],
            include_delimiter=False,
        )
        raw = scapy_raw(epd)
        # BOT(8) + Fragment(12) = 20 (no delimiter)
        assert len(raw) == 20
        # Ensure no delimiter tag
        assert b'\xFE\xFF\xDD\xE0' not in raw

    def test_build_with_offsets(self):
        bot = DICOMBasicOffsetTable()
        bot.set_offsets([0, 12])
        epd = DICOMEncapsulatedPixelData(
            bot=bot,
            fragments=[
                DICOMFragment(data=b'\xFF\xD8\xFF\xD9'),
                DICOMFragment(data=b'\x00\x01\x02\x03'),
            ],
        )
        raw = scapy_raw(epd)
        # BOT with 2 offsets: 8 + 8 = 16
        # 2 fragments: 2 * 12 = 24
        # Delimiter: 8
        assert len(raw) == 48

    def test_add_fragment_method(self):
        epd = DICOMEncapsulatedPixelData()
        epd.add_fragment(b'\xFF\xD8\xFF\xD9')
        epd.add_fragment(DICOMFragment(data=b'\x00\x01'))
        raw = scapy_raw(epd)
        # BOT(8) + Frag1(12) + Frag2(10) + Delimiter(8) = 38
        assert len(raw) == 38

    def test_from_encapsulated(self):
        """Test conversion from manual EncapsulatedPixelData."""
        epd_manual = EncapsulatedPixelData()
        epd_manual.add_fragment(b'\xFF\xD8\xFF\xD9')
        epd_manual.add_fragment(b'\x00\x01\x02\x03')
        epd_manual.set_offset_table([0, 12])

        epd_scapy = DICOMEncapsulatedPixelData.from_encapsulated(epd_manual)
        raw = scapy_raw(epd_scapy)
        assert len(raw) > 0
        # Should contain item tags
        assert raw.count(b'\xFE\xFF\x00\xE0') == 3  # BOT + 2 fragments

    def test_compatibility_with_manual_parse(self):
        """Scapy-built bytes should be parseable by manual API."""
        epd = DICOMEncapsulatedPixelData(
            fragments=[DICOMFragment(data=b'\xFF\xD8\xFF\xD9')],
        )
        raw = scapy_raw(epd)
        parsed = EncapsulatedPixelData.parse(raw)
        assert len(parsed.fragments) == 1
        assert parsed.fragments[0].data == b'\xFF\xD8\xFF\xD9'


# =============================================================================
# PixelFuzzer Tests
# =============================================================================

from c_scare.pixel import PixelFuzzer


class TestPixelFuzzer:
    def test_generate_without_seeds(self):
        """Fuzzer should work without seeds using minimal JPEG stub."""
        fuzzer = PixelFuzzer()
        payloads = list(fuzzer.generate(count=10))
        assert len(payloads) == 10
        for p in payloads:
            assert isinstance(p, bytes)
            assert len(p) > 0

    def test_generate_with_seed(self):
        """Fuzzer should incorporate provided seeds."""
        seed = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\xFF\xD9'
        fuzzer = PixelFuzzer()
        fuzzer.add_seed(seed)
        payloads = list(fuzzer.generate(count=20))
        assert len(payloads) == 20

    def test_specific_strategy_fuzz_lengths(self):
        fuzzer = PixelFuzzer(strategies=[PixelFuzzer.STRATEGY_FUZZ_LENGTHS])
        fuzzer.add_seed(b'\xFF\xD8\xFF\xD9')
        payloads = list(fuzzer.generate(count=5))
        assert all(isinstance(p, bytes) for p in payloads)

    def test_specific_strategy_fuzz_bot(self):
        fuzzer = PixelFuzzer(strategies=[PixelFuzzer.STRATEGY_FUZZ_BOT])
        fuzzer.add_seed(b'\xFF\xD8\xFF\xD9')
        payloads = list(fuzzer.generate(count=5))
        assert all(isinstance(p, bytes) for p in payloads)

    def test_specific_strategy_drop_delimiter(self):
        fuzzer = PixelFuzzer(strategies=[PixelFuzzer.STRATEGY_DROP_DELIMITER])
        fuzzer.add_seed(b'\xFF\xD8\xFF\xD9')
        payloads = list(fuzzer.generate(count=5))
        for p in payloads:
            assert b'\xFE\xFF\xDD\xE0' not in p

    def test_specific_strategy_corrupt_fragment(self):
        fuzzer = PixelFuzzer(strategies=[PixelFuzzer.STRATEGY_CORRUPT_FRAGMENT])
        fuzzer.add_seed(b'\xFF\xD8\xFF\xD9')
        payloads = list(fuzzer.generate(count=5))
        assert all(isinstance(p, bytes) for p in payloads)

    def test_specific_strategy_duplicate_fragments(self):
        fuzzer = PixelFuzzer(strategies=[PixelFuzzer.STRATEGY_DUPLICATE_FRAGMENTS])
        fuzzer.add_seed(b'\xFF\xD8\xFF\xD9')
        payloads = list(fuzzer.generate(count=3))
        for p in payloads:
            # Should have many item tags from duplicated fragments
            assert p.count(b'\xFE\xFF\x00\xE0') > 2

    def test_specific_strategy_empty_fragments(self):
        fuzzer = PixelFuzzer(strategies=[PixelFuzzer.STRATEGY_EMPTY_FRAGMENTS])
        fuzzer.add_seed(b'\xFF\xD8\xFF\xD9')
        payloads = list(fuzzer.generate(count=5))
        assert all(isinstance(p, bytes) for p in payloads)

    def test_specific_strategy_overflow_bot(self):
        fuzzer = PixelFuzzer(strategies=[PixelFuzzer.STRATEGY_OVERFLOW_BOT])
        fuzzer.add_seed(b'\xFF\xD8\xFF\xD9')
        payloads = list(fuzzer.generate(count=5))
        for p in payloads:
            # BOT length should be 0xFFFFFFFF
            bot_length = struct.unpack('<I', p[4:8])[0]
            assert bot_length == 0xFFFFFFFF

    def test_all_strategies_produce_output(self):
        """Every strategy should produce valid bytes."""
        seed = b'\xFF\xD8\xFF\xD9'
        for strategy in PixelFuzzer.ALL_STRATEGIES:
            fuzzer = PixelFuzzer(strategies=[strategy])
            fuzzer.add_seed(seed)
            payloads = list(fuzzer.generate(count=2))
            assert len(payloads) == 2, f"Strategy {strategy} failed"
            for p in payloads:
                assert isinstance(p, bytes), f"Strategy {strategy} returned non-bytes"
                assert len(p) > 0, f"Strategy {strategy} returned empty"

    def test_random_corrupt_static_method(self):
        data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\xFF\xD9'
        # Run many times - should sometimes produce different output
        results = set()
        for _ in range(50):
            corrupted = PixelFuzzer._random_corrupt(data)
            results.add(corrupted)
        assert len(results) > 1, "Corruption should produce varied output"


# =============================================================================
# Corruption Helper Tests
# =============================================================================

class TestCorruptionHelpers:
    def test_corrupt_jpeg_header(self):
        data = b'\xFF\xD8\xFF\xE0\x00\x10'
        result = corrupt_jpeg_header(data)
        assert result[:2] == b'\xFF\x00'
        assert result[2:] == data[2:]

    def test_corrupt_jpeg_eoi(self):
        data = b'\xFF\xD8\xFF\xE0\xFF\xD9'
        result = corrupt_jpeg_eoi(data)
        assert result == b'\xFF\xD8\xFF\xE0'

    def test_truncate_fragment(self):
        data = b'\x00\x01\x02\x03\x04\x05'
        assert truncate_fragment(data, 3) == b'\x00\x01\x02'

    def test_duplicate_bytes(self):
        data = b'\x00\x01\x02\x03'
        result = duplicate_bytes(data, 1, 2)
        assert result == b'\x00\x01\x02\x01\x02\x03'
