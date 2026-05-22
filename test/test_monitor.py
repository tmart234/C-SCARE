# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the monitor framework."""

import pytest
import sys
import os
import importlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import monitor module directly to avoid c_scare/__init__.py pulling in scapy
_spec = importlib.util.spec_from_file_location(
    'c_scare.monitor',
    os.path.join(os.path.dirname(__file__), '..', 'c_scare', 'monitor.py'),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

BaseMonitor = _mod.BaseMonitor
MonitorReport = _mod.MonitorReport
SanitizerMonitor = _mod.SanitizerMonitor
ProtocolMonitor = _mod.ProtocolMonitor
ProcessMonitor = _mod.ProcessMonitor
SanitizerFinding = _mod.SanitizerFinding
parse_sanitizer_output = _mod.parse_sanitizer_output
check_exit_code = _mod.check_exit_code


# --- Sample sanitizer outputs for testing ---

ASAN_HEAP_BUFFER_OVERFLOW = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x0000004a3b2c bp 0x7ffd12345678 sp 0x7ffd12345670
READ of size 4 at 0x602000000014 thread T0
    #0 0x4a3b2c in parse_element /src/dcmdata/libsrc/dcelem.cc:234
    #1 0x4a1234 in DcmDataset::read /src/dcmdata/libsrc/dcdata.cc:567
    #2 0x4b5678 in main /src/apps/storescp.cc:89
    #3 0x7f1234567890 in __libc_start_main /lib/x86_64-linux-gnu/libc.so.6

0x602000000014 is located 0 bytes to the right of 4-byte region [0x602000000010,0x602000000014)
allocated by thread T0 here:
    #0 0x7f9876543210 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.6+0xb0321)
    #1 0x4a0000 in DcmElement::alloc /src/dcmdata/libsrc/dcelem.cc:100

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/dcmdata/libsrc/dcelem.cc:234 in parse_element
"""

ASAN_USE_AFTER_FREE = """\
==99999==ERROR: AddressSanitizer: heap-use-after-free on address 0x607000000020 at pc 0x0000004c1234 bp 0x7fff87654321 sp 0x7fff87654319
READ of size 8 at 0x607000000020 thread T0
    #0 0x4c1234 in DcmSequence::getItem /src/dcmdata/libsrc/dcsequen.cc:445
    #1 0x4c5678 in process_sequence /src/dcmdata/libsrc/dcdata.cc:890

SUMMARY: AddressSanitizer: heap-use-after-free /src/dcmdata/libsrc/dcsequen.cc:445 in DcmSequence::getItem
"""

ASAN_STACK_OVERFLOW = """\
==55555==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd99999999 at pc 0x0000004d9999 bp 0x7ffd99999900 sp 0x7ffd999998f8
WRITE of size 256 at 0x7ffd99999999 thread T0
    #0 0x4d9999 in parse_vr /src/dcmdata/libsrc/dcvr.cc:78
    #1 0x4e1111 in DcmElement::read /src/dcmdata/libsrc/dcelem.cc:200

SUMMARY: AddressSanitizer: stack-buffer-overflow /src/dcmdata/libsrc/dcvr.cc:78 in parse_vr
"""

ASAN_DEADLYSIGNAL = """\
==77777==ERROR: AddressSanitizer: DEADLYSIGNAL
=================================================================
==77777==The signal is caused by a READ memory access.
    #0 0x4f0000 in bad_function /src/dcmdata/libsrc/crash.cc:42
    #1 0x4f1111 in caller /src/dcmdata/libsrc/caller.cc:100
"""

LSAN_MEMORY_LEAK = """\
=================================================================
==45678==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 1024 byte(s) in 1 object(s) allocated from:
    #0 0x7f9876543210 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.6+0xb0321)
    #1 0x4a0000 in DcmQueryRetrieveConfig::readPeerList /src/dcmqrdb/libsrc/dcmqrcnf.cc:512
    #2 0x4b1111 in main /src/apps/dcmqrscp.cc:201

SUMMARY: AddressSanitizer: 1024 byte(s) leaked in 1 allocation(s).
"""

UBSAN_SIGNED_OVERFLOW = """\
/src/dcmdata/libsrc/dcvr.cc:123:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
"""

UBSAN_SHIFT = """\
/src/dcmdata/libsrc/dcelem.cc:456:12: runtime error: shift exponent 64 is too large for 64-bit type 'unsigned long'
"""

UBSAN_MULTIPLE = """\
/src/file1.cc:10:3: runtime error: null pointer passed as argument 1
/src/file2.cc:20:5: runtime error: signed integer overflow: -2147483648 - 1
"""

MIXED_ASAN_UBSAN = """\
/src/pre.cc:1:1: runtime error: null pointer dereference
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
    #0 0x4a3b2c in func /src/main.cc:10

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/main.cc:10 in func
"""

CLEAN_OUTPUT = """\
I: Orthanc version 24.3.2
I: Starting DICOM server on port 4242
I: Received C-ECHO request
"""


class TestParseSanitizerOutput:
    def test_asan_heap_buffer_overflow(self):
        findings = parse_sanitizer_output(ASAN_HEAP_BUFFER_OVERFLOW)
        assert len(findings) == 1
        f = findings[0]
        assert f.sanitizer == 'asan'
        assert f.error_kind == 'heap-buffer-overflow'
        assert 'parse_element' in f.stack_trace
        assert 'dcelem.cc:234' in f.stack_trace

    def test_asan_use_after_free(self):
        findings = parse_sanitizer_output(ASAN_USE_AFTER_FREE)
        assert len(findings) == 1
        f = findings[0]
        assert f.sanitizer == 'asan'
        assert f.error_kind == 'heap-use-after-free'
        assert 'DcmSequence::getItem' in f.stack_trace

    def test_asan_stack_overflow(self):
        findings = parse_sanitizer_output(ASAN_STACK_OVERFLOW)
        assert len(findings) == 1
        f = findings[0]
        assert f.sanitizer == 'asan'
        assert f.error_kind == 'stack-buffer-overflow'

    def test_asan_deadlysignal(self):
        findings = parse_sanitizer_output(ASAN_DEADLYSIGNAL)
        assert len(findings) == 1
        f = findings[0]
        assert f.sanitizer == 'asan'
        assert f.error_kind == 'DEADLYSIGNAL'
        assert 'bad_function' in f.stack_trace

    def test_lsan_memory_leak(self):
        findings = parse_sanitizer_output(LSAN_MEMORY_LEAK)
        assert len(findings) == 1
        f = findings[0]
        assert f.sanitizer == 'lsan'
        assert f.error_kind == 'memory-leak'
        assert 'leaked' in f.summary
        assert 'readPeerList' in f.stack_trace

    def test_ubsan_signed_overflow(self):
        findings = parse_sanitizer_output(UBSAN_SIGNED_OVERFLOW)
        assert len(findings) == 1
        f = findings[0]
        assert f.sanitizer == 'ubsan'
        assert 'signed integer overflow' in f.error_kind
        assert 'dcvr.cc:123:5' in f.summary

    def test_ubsan_shift(self):
        findings = parse_sanitizer_output(UBSAN_SHIFT)
        assert len(findings) == 1
        f = findings[0]
        assert f.sanitizer == 'ubsan'
        assert 'shift exponent' in f.error_kind

    def test_ubsan_multiple(self):
        findings = parse_sanitizer_output(UBSAN_MULTIPLE)
        assert len(findings) == 2
        assert findings[0].sanitizer == 'ubsan'
        assert findings[1].sanitizer == 'ubsan'
        assert 'null pointer' in findings[0].error_kind
        assert 'signed integer overflow' in findings[1].error_kind

    def test_mixed_asan_and_ubsan(self):
        findings = parse_sanitizer_output(MIXED_ASAN_UBSAN)
        assert len(findings) == 2
        types = [f.sanitizer for f in findings]
        assert 'asan' in types
        assert 'ubsan' in types

    def test_clean_output_no_findings(self):
        findings = parse_sanitizer_output(CLEAN_OUTPUT)
        assert findings == []

    def test_empty_string(self):
        findings = parse_sanitizer_output('')
        assert findings == []


class TestCheckExitCode:
    def test_normal_exit(self):
        assert check_exit_code(0) is None

    def test_generic_error(self):
        assert check_exit_code(1) is None

    def test_sigsegv(self):
        f = check_exit_code(128 + 11)
        assert f is not None
        assert f.sanitizer == 'crash'
        assert f.error_kind == 'SIGSEGV'

    def test_sigabrt(self):
        f = check_exit_code(128 + 6)
        assert f is not None
        assert f.error_kind == 'SIGABRT'

    def test_sigbus(self):
        f = check_exit_code(128 + 7)
        assert f is not None
        assert f.error_kind == 'SIGBUS'

    def test_negative_signal(self):
        f = check_exit_code(-11)
        assert f is not None
        assert f.error_kind == 'SIGSEGV'

    def test_none_returncode(self):
        assert check_exit_code(None) is None


class TestProtocolMonitor:
    def setup_method(self):
        self.monitor = ProtocolMonitor()

    def test_timeout_detected(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(None)
        report = self.monitor.post_test()
        assert report.detected is True
        assert report.finding_type == 'network:timeout'

    def test_empty_response(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(b'')
        report = self.monitor.post_test()
        assert report.detected is True
        assert report.finding_type == 'network:empty_response'

    def test_associate_accept_detected(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(b'\x02' + b'\x00' * 10)
        report = self.monitor.post_test()
        assert report.detected is True
        assert report.finding_type == 'protocol:accepted'
        assert 'bypass' in report.description.lower()

    def test_associate_reject_normal(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(b'\x03' + b'\x00' * 10)
        report = self.monitor.post_test()
        assert report.detected is False

    def test_abort_normal(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(b'\x07' + b'\x00' * 4)
        report = self.monitor.post_test()
        assert report.detected is False

    def test_unexpected_pdu_type(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(b'\xff' + b'\x00' * 5)
        report = self.monitor.post_test()
        assert report.detected is True
        assert 'unexpected_pdu' in report.finding_type

    def test_connection_refused(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(None, error='refused')
        report = self.monitor.post_test()
        assert report.detected is True
        assert report.finding_type == 'network:connection_refused'

    def test_connection_reset(self):
        self.monitor.pre_test(1)
        self.monitor.set_response(None, error='reset')
        report = self.monitor.post_test()
        assert report.detected is True
        assert report.finding_type == 'network:connection_reset'


class FakeProcess:
    """Mock process manager for testing monitors.

    Simulates real behavior: pre_test drains clears old output,
    then new output (post_log) appears during the test, which
    post_test drains.
    """

    def __init__(self, log_text='', alive=True, code=0):
        self._pre_log = ''
        self._post_log = log_text
        self._alive = alive
        self._code = code
        self._drain_count = 0

    def drain_log(self):
        self._drain_count += 1
        if self._drain_count == 1:
            return self._pre_log
        return self._post_log

    def is_alive(self):
        return self._alive

    def exit_code(self):
        return None if self._alive else self._code


class TestSanitizerMonitor:
    def test_detects_asan_finding(self):
        proc = FakeProcess(log_text=ASAN_HEAP_BUFFER_OVERFLOW, alive=True)
        monitor = SanitizerMonitor(proc)
        monitor.pre_test(1)
        report = monitor.post_test()
        assert report.detected is True
        assert 'asan:heap-buffer-overflow' == report.finding_type
        assert report.evidence is not None

    def test_detects_crash_when_process_dies(self):
        proc = FakeProcess(log_text='', alive=False, code=139)  # 128+11=SIGSEGV
        monitor = SanitizerMonitor(proc)
        monitor.pre_test(1)
        report = monitor.post_test()
        assert report.detected is True
        assert 'crash:SIGSEGV' == report.finding_type

    def test_no_finding_clean_output(self):
        proc = FakeProcess(log_text=CLEAN_OUTPUT, alive=True)
        monitor = SanitizerMonitor(proc)
        monitor.pre_test(1)
        report = monitor.post_test()
        assert report.detected is False


class TestProcessMonitor:
    def test_process_alive(self):
        proc = FakeProcess(alive=True)
        monitor = ProcessMonitor(proc)
        monitor.pre_test(1)
        report = monitor.post_test()
        assert report.detected is False

    def test_process_crashed(self):
        proc = FakeProcess(alive=True)
        monitor = ProcessMonitor(proc)
        monitor.pre_test(1)
        proc._alive = False
        proc._code = 134  # 128+6=SIGABRT
        report = monitor.post_test()
        assert report.detected is True
        assert 'crash:SIGABRT' == report.finding_type

    def test_process_already_dead(self):
        proc = FakeProcess(alive=False, code=1)
        monitor = ProcessMonitor(proc)
        monitor.pre_test(1)
        report = monitor.post_test()
        assert report.detected is False


class TestBaseMonitor:
    def test_default_post_test_not_detected(self):
        m = BaseMonitor()
        report = m.post_test()
        assert report.detected is False
