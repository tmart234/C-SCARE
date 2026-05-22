# SPDX-License-Identifier: GPL-2.0-only
"""
Monitor framework for C-SCARE test detection.

Provides a generic BaseMonitor interface (inspired by Kitty fuzzer) with
concrete monitors for sanitizer output, protocol responses, and process health.
"""

import re
import signal
from dataclasses import dataclass, field
from typing import Dict, List, Optional

__all__ = [
    'MonitorReport',
    'BaseMonitor',
    'SanitizerMonitor',
    'ProtocolMonitor',
    'ProcessMonitor',
    'SanitizerFinding',
    'parse_sanitizer_output',
]


SIGNAL_NAMES = {
    1: 'SIGHUP', 2: 'SIGINT', 3: 'SIGQUIT', 4: 'SIGILL',
    6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE', 9: 'SIGKILL',
    11: 'SIGSEGV', 13: 'SIGPIPE', 14: 'SIGALRM', 15: 'SIGTERM',
}

# ASan error pattern: ==PID==ERROR: AddressSanitizer: <error_kind>
_ASAN_ERROR_RE = re.compile(
    r'==\d+==ERROR:\s*AddressSanitizer:\s*(.+?)(?:\s+on\s+|\s*$)',
    re.MULTILINE,
)

# ASan DEADLYSIGNAL pattern
_ASAN_SIGNAL_RE = re.compile(
    r'==\d+==ERROR:\s*AddressSanitizer:\s*DEADLYSIGNAL',
    re.MULTILINE,
)

# ASan stack frame: #N 0xADDR in func file:line
_ASAN_FRAME_RE = re.compile(
    r'^\s*#\d+\s+0x[0-9a-f]+\s+in\s+.+$',
    re.MULTILINE,
)

# ASan summary line
_ASAN_SUMMARY_RE = re.compile(
    r'^SUMMARY:\s*AddressSanitizer:\s*(.+)$',
    re.MULTILINE,
)

# UBSan: file:line:col: runtime error: <description>
_UBSAN_RE = re.compile(
    r'^(.+?:\d+:\d+):\s*runtime error:\s*(.+)$',
    re.MULTILINE,
)

# Full ASan report block (from ERROR to next blank line or SUMMARY)
_ASAN_BLOCK_RE = re.compile(
    r'(==\d+==ERROR:\s*AddressSanitizer:.+?)(?=\n\n|\nSUMMARY:|\Z)',
    re.DOTALL,
)

# LSan leak report header: ==PID==ERROR: LeakSanitizer: detected memory leaks
_LSAN_ERROR_RE = re.compile(
    r'==\d+==ERROR:\s*LeakSanitizer:\s*detected memory leaks',
    re.MULTILINE,
)

# LSan leak summary. When LSan runs inside ASan the line still reads
# "AddressSanitizer", standalone it reads "LeakSanitizer".
_LSAN_SUMMARY_RE = re.compile(
    r'^SUMMARY:\s*(?:Address|Leak)Sanitizer:\s*(\d+\s+byte\(s\)\s+leaked.+)$',
    re.MULTILINE,
)


@dataclass
class SanitizerFinding:
    """A single sanitizer finding parsed from process output."""
    sanitizer: str
    error_kind: str
    summary: str
    stack_trace: str


@dataclass
class MonitorReport:
    """Result from a monitor's post_test() check."""
    detected: bool
    finding_type: Optional[str] = None
    description: str = ''
    evidence: Optional[str] = None


def parse_sanitizer_output(text: str) -> List[SanitizerFinding]:
    """Parse ASan/UBSan reports from process stderr text."""
    findings: List[SanitizerFinding] = []

    for block_match in _ASAN_BLOCK_RE.finditer(text):
        block = block_match.group(1)
        error_match = _ASAN_ERROR_RE.search(block)
        if not error_match:
            continue
        error_kind = error_match.group(1).strip()

        frames = _ASAN_FRAME_RE.findall(block)
        stack_trace = '\n'.join(frames[:10])

        summary_match = _ASAN_SUMMARY_RE.search(text[block_match.end():block_match.end() + 500])
        summary = summary_match.group(1) if summary_match else error_kind

        findings.append(SanitizerFinding(
            sanitizer='asan',
            error_kind=error_kind,
            summary=summary,
            stack_trace=stack_trace,
        ))

    if not findings and _ASAN_SIGNAL_RE.search(text):
        frames = _ASAN_FRAME_RE.findall(text)
        findings.append(SanitizerFinding(
            sanitizer='asan',
            error_kind='DEADLYSIGNAL',
            summary='Process received deadly signal',
            stack_trace='\n'.join(frames[:10]),
        ))

    # LeakSanitizer reports a memory leak at clean process exit, not a
    # crash, so it carries no ASan ERROR block — match it on its own.
    if _LSAN_ERROR_RE.search(text):
        summary_match = _LSAN_SUMMARY_RE.search(text)
        summary = (summary_match.group(1).strip() if summary_match
                   else 'detected memory leaks')
        frames = _ASAN_FRAME_RE.findall(text)
        findings.append(SanitizerFinding(
            sanitizer='lsan',
            error_kind='memory-leak',
            summary=summary,
            stack_trace='\n'.join(frames[:10]),
        ))

    for ubsan_match in _UBSAN_RE.finditer(text):
        location = ubsan_match.group(1)
        description = ubsan_match.group(2)
        findings.append(SanitizerFinding(
            sanitizer='ubsan',
            error_kind=description.split(':')[0].strip() if ':' in description else description,
            summary=f"{location}: {description}",
            stack_trace='',
        ))

    return findings


def check_exit_code(returncode: int) -> Optional[SanitizerFinding]:
    """Interpret a process exit code for crash signals."""
    if returncode is None:
        return None
    if returncode > 128:
        sig_num = returncode - 128
        sig_name = SIGNAL_NAMES.get(sig_num, f'signal {sig_num}')
        return SanitizerFinding(
            sanitizer='crash',
            error_kind=sig_name,
            summary=f'Process killed by {sig_name}',
            stack_trace='',
        )
    if returncode < 0:
        sig_num = -returncode
        sig_name = SIGNAL_NAMES.get(sig_num, f'signal {sig_num}')
        return SanitizerFinding(
            sanitizer='crash',
            error_kind=sig_name,
            summary=f'Process killed by {sig_name}',
            stack_trace='',
        )
    return None


class BaseMonitor:
    """Base class for test monitors. Subclass and override lifecycle methods."""

    def setup(self):
        """Called once before fuzzing session starts."""

    def teardown(self):
        """Called once after fuzzing session ends."""

    def pre_test(self, test_number: int):
        """Reset state before each test payload is sent."""

    def post_test(self) -> MonitorReport:
        """Check for findings after payload delivery."""
        return MonitorReport(detected=False)


class SanitizerMonitor(BaseMonitor):
    """Monitors ASan/UBSan stderr output from a managed process."""

    def __init__(self, process_manager):
        self._proc = process_manager

    def pre_test(self, test_number: int):
        self._proc.drain_log()

    def post_test(self) -> MonitorReport:
        log = self._proc.drain_log()
        findings = parse_sanitizer_output(log)
        if findings:
            f = findings[0]
            return MonitorReport(
                detected=True,
                finding_type=f'{f.sanitizer}:{f.error_kind}',
                description=f.summary,
                evidence=f.stack_trace[:1000] if f.stack_trace else None,
            )
        if not self._proc.is_alive():
            exit_finding = check_exit_code(self._proc.exit_code())
            if exit_finding:
                return MonitorReport(
                    detected=True,
                    finding_type=f'crash:{exit_finding.error_kind}',
                    description=exit_finding.summary,
                    evidence=log[:500] if log else None,
                )
        return MonitorReport(detected=False, description='No sanitizer findings')


class ProtocolMonitor(BaseMonitor):
    """Monitors DICOM protocol responses for anomalies."""

    # Standard DICOM PDU types that indicate normal server behavior
    PDU_ASSOCIATE_AC = 0x02
    PDU_ASSOCIATE_RJ = 0x03
    PDU_DATA_TF = 0x04
    PDU_RELEASE_RQ = 0x05
    PDU_RELEASE_RP = 0x06
    PDU_ABORT = 0x07

    NORMAL_ASSOCIATION_RESPONSES = (PDU_ASSOCIATE_AC, PDU_ASSOCIATE_RJ, PDU_ABORT)

    def __init__(self):
        self._response: Optional[bytes] = None
        self._error: Optional[str] = None

    def pre_test(self, test_number: int):
        self._response = None
        self._error = None

    def set_response(self, response: Optional[bytes], error: Optional[str] = None):
        """Called by test runner after delivery, before post_test()."""
        self._response = response
        self._error = error

    def post_test(self) -> MonitorReport:
        if self._error == 'refused':
            return MonitorReport(
                detected=True,
                finding_type='network:connection_refused',
                description='Connection refused — server may have crashed',
            )
        if self._error == 'reset':
            return MonitorReport(
                detected=True,
                finding_type='network:connection_reset',
                description='Connection reset by server',
            )
        if self._response is None:
            return MonitorReport(
                detected=True,
                finding_type='network:timeout',
                description='No response (timeout or connection closed)',
            )
        if len(self._response) == 0:
            return MonitorReport(
                detected=True,
                finding_type='network:empty_response',
                description='Server sent empty response',
            )
        pdu_type = self._response[0]
        if pdu_type == self.PDU_ASSOCIATE_AC:
            return MonitorReport(
                detected=True,
                finding_type='protocol:accepted',
                description='Server accepted association — auth/AE title bypass?',
                evidence=f'PDU type: 0x{pdu_type:02x} (A-ASSOCIATE-AC)',
            )
        if pdu_type not in self.NORMAL_ASSOCIATION_RESPONSES:
            return MonitorReport(
                detected=True,
                finding_type=f'protocol:unexpected_pdu_0x{pdu_type:02x}',
                description=f'Unexpected PDU type byte: 0x{pdu_type:02x}',
                evidence=self._response[:64].hex(),
            )
        return MonitorReport(
            detected=False,
            description=f'Normal response: PDU type 0x{pdu_type:02x}',
        )


class ProcessMonitor(BaseMonitor):
    """Monitors target process health."""

    def __init__(self, process_manager):
        self._proc = process_manager
        self._was_alive = True

    def pre_test(self, test_number: int):
        self._was_alive = self._proc.is_alive()

    def post_test(self) -> MonitorReport:
        if self._was_alive and not self._proc.is_alive():
            exit_finding = check_exit_code(self._proc.exit_code())
            if exit_finding:
                return MonitorReport(
                    detected=True,
                    finding_type=f'crash:{exit_finding.error_kind}',
                    description=exit_finding.summary,
                )
            return MonitorReport(
                detected=True,
                finding_type='crash:unknown',
                description=f'Process died (exit code: {self._proc.exit_code()})',
            )
        return MonitorReport(detected=False, description='Process alive')
