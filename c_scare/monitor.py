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
    'PipelineMonitor',
    'SanitizerFinding',
    'parse_sanitizer_output',
    'stored_successfully',
]


def stored_successfully(status: Optional[int]) -> bool:
    """True if a DIMSE status means the SCP kept the object (PS3.7 Annex C).

    ``0x0000`` is Success. The ``0xBxxx`` warning class - coercion of data
    elements, elements discarded, data set does not match SOP class - all mean
    the object was stored anyway, with a note. ``0xAxxx`` and ``0xCxxx`` are
    refusals and errors, where it was not.

    The distinction matters because for some payloads storage *is* the
    finding, and a warning status is still storage.
    """
    if status is None:
        return False
    return status == 0x0000 or (status & 0xF000) == 0xB000


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

# MemorySanitizer reports use-of-uninitialized-value as a WARNING (not an
# ASan-style ERROR), so it needs its own header/summary patterns. SAND can
# run an MSan worker alongside ASan/UBSan, so triage must recognise it.
_MSAN_BLOCK_RE = re.compile(
    r'(==\d+==WARNING:\s*MemorySanitizer:.+?)(?=\n\n|\nSUMMARY:|\Z)',
    re.DOTALL,
)
_MSAN_ERROR_RE = re.compile(
    r'==\d+==WARNING:\s*MemorySanitizer:\s*(.+?)\s*$',
    re.MULTILINE,
)
_MSAN_SUMMARY_RE = re.compile(
    r'^SUMMARY:\s*MemorySanitizer:\s*(.+)$',
    re.MULTILINE,
)


def _frames_after(text: str, start: int, limit: int = 800) -> str:
    """Collect the stack frames immediately following offset ``start``.

    UBSan emits no stack trace unless ``UBSAN_OPTIONS=print_stacktrace=1``;
    when it does, the ``#N 0x... in ...`` frames follow the ``runtime error:``
    line. The scan window is cut at the next sanitizer report so a later
    finding's frames are not attributed to this one.
    """
    window = text[start:start + limit]
    nxt = re.search(r'runtime error:|==\d+==', window)
    if nxt:
        window = window[:nxt.start()]
    return '\n'.join(_ASAN_FRAME_RE.findall(window)[:10])


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
    """Parse ASan/UBSan/LSan/MSan reports from process stderr text."""
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

    # MemorySanitizer: WARNING block, parsed like an ASan block.
    for block_match in _MSAN_BLOCK_RE.finditer(text):
        block = block_match.group(1)
        error_match = _MSAN_ERROR_RE.search(block)
        if not error_match:
            continue
        error_kind = error_match.group(1).strip()
        frames = _ASAN_FRAME_RE.findall(block)
        summary_match = _MSAN_SUMMARY_RE.search(
            text[block_match.end():block_match.end() + 500])
        summary = summary_match.group(1) if summary_match else error_kind
        findings.append(SanitizerFinding(
            sanitizer='msan',
            error_kind=error_kind,
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
            stack_trace=_frames_after(text, ubsan_match.end()),
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

    #: ``metadata['finding_on']`` value meaning the payload is testing whether
    #: the peer *accepts* it, so a successful store is the detection rather
    #: than the absence of one.
    FINDING_ON_STORE = 'store_accepted'

    def __init__(self):
        self._response: Optional[bytes] = None
        self._error: Optional[str] = None
        self._finding_on: Optional[str] = None
        self._accepted: Optional[bool] = None

    def pre_test(self, test_number: int):
        self._response = None
        self._error = None
        self._finding_on = None
        self._accepted = None

    def set_response(self, response: Optional[bytes], error: Optional[str] = None,
                     finding_on: Optional[str] = None,
                     accepted: Optional[bool] = None):
        """Called by test runner after delivery, before post_test().

        ``finding_on`` carries the payload's own expectation. Most payloads
        are looking for the peer to misbehave, so an orderly answer is a pass.
        A few are looking for the peer to *comply* - "the archive should not
        store an executable" - and for those a clean DIMSE Success is the
        result worth reporting. Without it the monitor has no way to tell the
        two apart and calls a stored payload a normal response.
        """
        self._response = response
        self._error = error
        self._finding_on = finding_on
        # Whether the archive kept the object, as the transport reported it.
        # Deriving it from a DIMSE status here would only work for DIMSE: a
        # STOW-RS 200 is not a DIMSE 0x0000, and reading one as the other
        # made every DICOMweb store look like a refusal.
        self._accepted = accepted

    def post_test(self) -> MonitorReport:
        if self._error == 'dry_run':
            # Nothing was sent, so there is nothing to conclude. Reporting the
            # absent response as a timeout would mark every payload in a
            # --dry-run as a finding.
            return MonitorReport(
                detected=False,
                description='Dry run — payload written to disk, not sent',
            )
        if self._error and self._error.startswith('undelivered:'):
            # The payload never reached the target's parser — a rejected
            # association, an unnegotiated SOP class, a missing dependency.
            # Reporting the absent response as a timeout would turn every
            # payload in a misconfigured run into a finding against a target
            # that was never touched.
            reason = self._error.split(':', 1)[1]
            return MonitorReport(
                detected=False,
                finding_type='delivery:not_delivered',
                description=f'Not delivered ({reason}) — no conclusion about '
                            'the target',
                evidence=reason,
            )
        if self._error == 'cstore_status':
            status = None
            if self._response and len(self._response) >= 2:
                status = (self._response[0] << 8) | self._response[1]
            status_text = f'0x{status:04x}' if status is not None else 'unknown'
            kept = (self._accepted if self._accepted is not None
                    else stored_successfully(status))
            if self._finding_on == self.FINDING_ON_STORE and kept:
                # The payload asked whether the peer would accept it, and the
                # peer did. Reporting that as a normal response is the wrong
                # way round: for an object carrying an embedded executable, a
                # clean store is the outcome the test exists to catch.
                return MonitorReport(
                    detected=True,
                    finding_type='storage:payload_accepted',
                    description=(
                        f'SCP stored the object (DIMSE {status_text}), '
                        'including attacker-controlled bytes in a region a '
                        'conforming reader traverses without inspecting. '
                        'C-STORE does not carry the 128-byte preamble, so a '
                        'preamble-resident header is not what reached the '
                        'archive — retrieve the stored instance and compare '
                        'to establish what did.'),
                    evidence=status_text,
                )
            return MonitorReport(
                detected=False,
                description=f'C-STORE completed with DIMSE status {status_text}',
                evidence=status_text,
            )
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


class PipelineMonitor(BaseMonitor):
    """Did the archive hand the embedded payload back, or neutralise it?

    Acceptance alone cannot tell those apart, and they are opposite findings.
    This monitor is fed the payload that was sent and the copy the archive
    returned, and reports what the round trip did to the embedding — the
    S.P.I.C.Y. Cascading property.

    It says nothing about execution, deliberately. These images are inert by
    construction, and a polyglot never executes itself in any case: activation
    is a separate link in the chain, outside the file and specific to the
    environment. What lives in the bytes is whether the artifact is still the
    artifact after the pipeline handled it, and that is what this measures.
    """

    def __init__(self):
        self._sent: Optional[bytes] = None
        self._returned: Optional[bytes] = None
        self._reason: Optional[str] = None

    def pre_test(self, test_number: int):
        self._sent = None
        self._returned = None
        self._reason = None

    def set_round_trip(self, sent: Optional[bytes],
                       returned: Optional[bytes],
                       reason: Optional[str] = None):
        """Called by the runner after a store-and-retrieve."""
        self._sent = sent
        self._returned = returned
        self._reason = reason

    def post_test(self) -> MonitorReport:
        from .polyglot import (
            SURVIVED_ALTERED, SURVIVED_INTACT, SURVIVED_PAYLOAD,
            SURVIVED_STRIPPED, compare_after_pipeline,
        )

        if self._sent is None:
            return MonitorReport(detected=False,
                                 description='No round trip attempted')
        if self._returned is None:
            # Not a finding: a retrieve that never ran says nothing about the
            # archive, the same way an undelivered payload says nothing.
            return MonitorReport(
                detected=False,
                finding_type='retrieve:unavailable',
                description=f'Could not retrieve the stored instance '
                            f'({self._reason}) — the round trip concluded '
                            'nothing about what the archive kept',
                evidence=self._reason,
            )

        verdict = compare_after_pipeline(self._sent, self._returned)
        if verdict.outcome == SURVIVED_STRIPPED:
            return MonitorReport(
                detected=False,
                finding_type='pipeline:stripped',
                description=f'Archive removed the embedded content on ingest '
                            f'({verdict.detail}). This is the outcome a '
                            'defender wants.',
                evidence=verdict.detail,
            )
        if verdict.outcome == SURVIVED_INTACT:
            return MonitorReport(
                detected=True,
                finding_type='pipeline:survived_intact',
                description=f'Archive returned the artifact still valid in '
                            f'both formats ({verdict.detail}). It is a '
                            'distribution channel for this object, not just a '
                            'store that accepted it.',
                evidence=verdict.detail,
            )
        if verdict.outcome == SURVIVED_PAYLOAD:
            return MonitorReport(
                detected=True,
                finding_type='pipeline:payload_retained',
                description=f'Archive returned the embedded bytes unchanged '
                            f'({verdict.detail}). Anything that reads the '
                            'element still gets attacker-controlled content.',
                evidence=verdict.detail,
            )
        if verdict.outcome == SURVIVED_ALTERED:
            return MonitorReport(
                detected=True,
                finding_type='pipeline:altered',
                description=f'Archive returned a modified carrier '
                            f'({verdict.detail}). Worth checking whether the '
                            'change neutralises the content or merely moves it.',
                evidence=verdict.detail,
            )
        return MonitorReport(
            detected=False,
            description=f'Round trip inconclusive: {verdict.detail}')
