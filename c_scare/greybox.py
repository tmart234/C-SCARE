# SPDX-License-Identifier: GPL-2.0-only
"""
Grey-box fuzzing integration.

C-SCARE does not contain a fuzzing engine. AFL++ (file targets) and AFLNet
(network targets) own the mutation loop and coverage feedback - this module
is the thin bridge between those engines and C-SCARE's reporting layer:

  * run()          - launch a fuzz harness from scripts/ for a chosen target
  * list_crashes() - enumerate an AFL/AFLNet crashes directory
  * list_queue()   - enumerate the queue (leak-class bugs land here, not in
                     crashes/, because a leak is not a crash)
  * triage()       - replay each input through an instrumented binary and
                     parse the sanitizer output (ASan / UBSan / LSan) into
                     structured findings

The fuzzing itself is run via scripts/ (see scripts/campaign.sh). This
module turns the resulting crashes into triaged, reportable findings.

Leak detection: an AFL campaign runs with detect_leaks=0 (a leak at exit
is noise mid-loop and clashes with the forkserver). A triage replay is a
clean one-shot process, so LeakSanitizer's atexit scan works here -
_triage_env() forces detect_leaks back on. Leak-triggering inputs sit in
the queue, so pass include_queue=True to surface CVE-class leaks.
"""

import os
import subprocess
from typing import List, Optional

from .attacks import AttackResult
from .monitor import (
    MonitorReport, SanitizerFinding,
    parse_sanitizer_output, check_exit_code,
)

__all__ = [
    'TARGETS', 'repo_root', 'run', 'list_crashes', 'list_queue',
    'triage', 'triage_to_sarif',
]

# target -> fuzz harness script (mirrors scripts/campaign.sh).
# file/parse  = SCP grey-box, file path (AFL++)
# net-*       = SCP grey-box, network path (AFLNet)
# scu         = SCU grey-box, client path (AFL++ + desock)
TARGETS = {
    'file': 'fuzz_file.sh',
    'parse': 'fuzz_parse.sh',
    'net-storescp': 'fuzz_net.sh',
    'net-dcmrecv': 'fuzz_dcmrecv.sh',
    'net-dcmqrscp': 'fuzz_dcmqrscp.sh',
    'scu': 'fuzz_scu.sh',
}


def repo_root() -> str:
    """Absolute path to the C-SCARE repository root."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(target: str, repo: Optional[str] = None) -> int:
    """Launch the AFL++/AFLNet fuzz harness for ``target``.

    Shells out to ``scripts/<harness>.sh`` - AFL owns the fuzzing loop.
    Returns the harness process exit code.
    """
    if target not in TARGETS:
        raise ValueError(
            f"unknown target {target!r}; choose from {sorted(TARGETS)}"
        )
    repo = repo or repo_root()
    script = os.path.join(repo, 'scripts', TARGETS[target])
    if not os.path.isfile(script):
        raise FileNotFoundError(f"fuzz harness not found: {script}")
    return subprocess.call(['bash', script])


def list_crashes(out_dir: str) -> List[str]:
    """Return crash input files under an AFL/AFLNet output directory.

    Handles both the AFL++ (``<out>/default/crashes/``) and AFLNet /
    single-mode (``<out>/crashes/``) layouts. The ``README.txt`` that AFL
    drops in crash directories is skipped.
    """
    crashes: List[str] = []
    for root, _dirs, files in os.walk(out_dir):
        if os.path.basename(root) != 'crashes':
            continue
        for name in sorted(files):
            if name == 'README.txt':
                continue
            crashes.append(os.path.join(root, name))
    return crashes


def list_queue(out_dir: str) -> List[str]:
    """Return queue (non-crashing) input files under an AFL/AFLNet output dir.

    A memory leak is detected at process exit, not as a crash, so the input
    that first drives the leaking code path lands in ``queue/``, never in
    ``crashes/``. Triaging the queue is therefore required to surface
    leak-class bugs. Handles the AFL++ (``<out>/default/queue/``) and
    AFLNet / single-mode (``<out>/queue/``) layouts; AFL's ``queue/.state/``
    metadata directory is skipped because its basename is not ``queue``.
    """
    inputs: List[str] = []
    for root, _dirs, files in os.walk(out_dir):
        if os.path.basename(root) != 'queue':
            continue
        for name in sorted(files):
            if name == 'README.txt':
                continue
            inputs.append(os.path.join(root, name))
    return inputs


def _triage_env() -> dict:
    """Process environment for a triage replay.

    Forces ``detect_leaks=1`` on: an AFL campaign typically runs with
    ``detect_leaks=0``, but a triage replay is a clean one-shot process
    where LeakSanitizer's atexit scan is valid. ASan parses its options
    last-wins, so appending overrides any inherited ``detect_leaks=0``.
    """
    env = dict(os.environ)
    inherited = env.get('ASAN_OPTIONS', '')
    forced = 'detect_leaks=1'
    env['ASAN_OPTIONS'] = f'{inherited}:{forced}' if inherited else forced
    return env


def _replay(cmd: List[str], crash_path: str, timeout: float):
    """Run ``cmd`` with ``@@`` replaced by ``crash_path``.

    Returns ``(returncode, combined_output)``; returncode is ``None`` on
    timeout. Mirrors AFL's ``@@`` input-placeholder convention; if no ``@@``
    is present the crash path is appended as the final argument.
    """
    argv = [crash_path if tok == '@@' else tok for tok in cmd]
    if '@@' not in cmd:
        argv.append(crash_path)
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                              env=_triage_env())
        output = (proc.stdout or b'') + (proc.stderr or b'')
        return proc.returncode, output.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or b'') + (e.stderr or b'')
        return None, output.decode('utf-8', errors='replace')
    except FileNotFoundError as e:
        return None, f'replay failed: {e}'


def triage(crashes: List[str],
           cmd: Optional[List[str]] = None,
           timeout: float = 10.0) -> List[AttackResult]:
    """Triage AFL/AFLNet fuzz inputs into ``AttackResult`` findings.

    Accepts crash *and* queue inputs (see ``list_crashes`` / ``list_queue``).
    If ``cmd`` is given (e.g. ``['/build/dcm2pnm', '@@', '/tmp/o.pnm']``)
    each input is replayed through it and the sanitizer output is parsed
    into ``MonitorReport`` findings. The replay forces ``detect_leaks=1``,
    so a one-shot replay also surfaces LeakSanitizer findings. Without
    ``cmd`` the inputs are only inventoried (no instrumented binary).
    """
    results: List[AttackResult] = []
    for crash_path in crashes:
        try:
            with open(crash_path, 'rb') as fh:
                payload = fh.read()
        except OSError:
            payload = b''

        kind = 'queue' if f'{os.sep}queue{os.sep}' in crash_path else 'crash'
        result = AttackResult(
            name=os.path.basename(crash_path),
            category='greybox',
            payload=payload,
            description=f'AFL/AFLNet {kind} input: {crash_path}',
            expected_behavior='Target should not crash or leak on any input',
            metadata={'crash_path': crash_path, 'kind': kind,
                      'size': len(payload)},
        )

        if cmd:
            returncode, output = _replay(cmd, crash_path, timeout)
            findings: List[SanitizerFinding] = parse_sanitizer_output(output)
            exit_finding = check_exit_code(returncode)
            if exit_finding:
                findings.append(exit_finding)
            for finding in findings:
                result.monitor_reports.append(MonitorReport(
                    detected=True,
                    finding_type=f'{finding.sanitizer}:{finding.error_kind}',
                    description=finding.summary,
                    evidence=finding.stack_trace or None,
                ))
            result.success = bool(findings)
            result.metadata['exit_code'] = returncode

        results.append(result)
    return results


def triage_to_sarif(crashes_or_dir,
                     cmd: Optional[List[str]] = None,
                     sarif_path: Optional[str] = None,
                     timeout: float = 10.0,
                     include_queue: bool = False) -> List[AttackResult]:
    """Triage crashes and optionally write a SARIF v2.1.0 report.

    ``crashes_or_dir`` may be an AFL/AFLNet output directory (str) or an
    explicit list of input file paths.

    With ``include_queue`` and a directory argument, the queue inputs are
    triaged alongside the crashes. This is required to catch leak-class
    bugs, which never crash; the replay's clean one-shot exit lets
    LeakSanitizer report them (automatic for file targets such as
    dcm2pnm / dcmdump).
    """
    if isinstance(crashes_or_dir, str):
        crashes = list_crashes(crashes_or_dir)
        if include_queue:
            crashes += list_queue(crashes_or_dir)
    else:
        crashes = list(crashes_or_dir)
    results = triage(crashes, cmd=cmd, timeout=timeout)
    if sarif_path:
        from .test_runner import write_sarif
        write_sarif(results, sarif_path)
    return results
