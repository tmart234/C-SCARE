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
  * triage()       - replay each input through one or more sanitizer
                     binaries and parse the output (ASan / UBSan / LSan /
                     MSan) into structured findings

The fuzzing itself is run via scripts/ (see scripts/campaign.sh). This
module turns the resulting crashes into triaged, reportable findings.

SAND alignment (https://aflplus.plus/docs/sand/): SAND decouples
sanitization from the fuzz loop - the loop drives a fast native binary and
only suspicious inputs reach the sanitizer-instrumented worker binaries.
The triage pass here *is* that worker stage: it replays crash/queue inputs
through the sanitizer worker(s) to obtain a verdict. scripts/build_dcmtk.sh
with SAND=1 builds one worker per sanitizer under fuzz/build-san-<san>/;
find_san_workers() discovers them and triage() replays an input through
every worker so an ASan + UBSan (+ MSan) campaign is triaged in one pass.

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
    'find_san_workers', 'triage', 'triage_to_sarif',
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
    """Process environment for a one-shot triage / SAND-worker replay.

    A fuzzing campaign tunes the sanitizers for throughput - it sets
    ``symbolize=0`` (skip the symbolizer) and ``detect_leaks=0`` (a leak at
    exit clashes with the forkserver). Those settings make a triage report
    incomplete or unreadable, so override them: a triage replay is a clean
    one-shot process where the full, symbolized report is exactly the point.

      ASAN_OPTIONS  - detect_leaks=1 (LeakSanitizer's atexit scan is valid
                      in a one-shot replay) and symbolize=1.
      UBSAN_OPTIONS - print_stacktrace=1 (UBSan prints no stack trace at
                      all by default) and symbolize=1.
      MSAN_OPTIONS  - symbolize=1.

    Sanitizers parse their ``*_OPTIONS`` last-wins, so appending overrides
    any value inherited from the campaign environment.
    """
    env = dict(os.environ)
    overrides = {
        'ASAN_OPTIONS': 'detect_leaks=1:symbolize=1',
        'UBSAN_OPTIONS': 'print_stacktrace=1:symbolize=1',
        'MSAN_OPTIONS': 'symbolize=1',
    }
    for var, forced in overrides.items():
        inherited = env.get(var, '')
        env[var] = f'{inherited}:{forced}' if inherited else forced
    return env


def find_san_workers(bin_name: str, repo: Optional[str] = None) -> List[str]:
    """Return the SAND sanitizer-worker binaries built for ``bin_name``.

    ``scripts/build_dcmtk.sh`` run with ``SAND=1`` builds one worker tree
    per sanitizer under ``fuzz/build-san-<sanitizer>/`` (forkserver only,
    no PC instrumentation - see https://aflplus.plus/docs/sand/). This
    locates the ``bin_name`` executable inside each, sorted by sanitizer,
    so triage can replay an input through every sanitizer the campaign ran.
    Returns an empty list when no worker trees exist (non-SAND build).
    """
    repo = repo or repo_root()
    fuzz_dir = os.path.join(repo, 'fuzz')
    workers: List[str] = []
    if not os.path.isdir(fuzz_dir):
        return workers
    for name in sorted(os.listdir(fuzz_dir)):
        if not name.startswith('build-san-'):
            continue
        build_dir = os.path.join(fuzz_dir, name)
        if not os.path.isdir(build_dir):
            continue
        for root, _dirs, files in os.walk(build_dir):
            if bin_name in files:
                path = os.path.join(root, bin_name)
                if os.access(path, os.X_OK):
                    workers.append(path)
                    break
    return workers


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
           cmds: Optional[List[List[str]]] = None,
           timeout: float = 10.0) -> List[AttackResult]:
    """Triage AFL/AFLNet fuzz inputs into ``AttackResult`` findings.

    Accepts crash *and* queue inputs (see ``list_crashes`` / ``list_queue``).

    Pass the sanitizer binary to replay through as ``cmd`` (a single command,
    e.g. ``['/build/dcm2pnm', '@@', '/tmp/o.pnm']``) and/or ``cmds`` (a list
    of such commands). Every input is replayed through *each* command and the
    sanitizer output (ASan / UBSan / LSan / MSan) is parsed into
    ``MonitorReport`` findings - this is how a SAND-style campaign with one
    worker per sanitizer is triaged in a single pass (see ``find_san_workers``).
    The replay forces a full one-shot sanitizer report (``_triage_env``), so
    it also surfaces LeakSanitizer findings. With no command the inputs are
    only inventoried (no instrumented binary).
    """
    workers: List[List[str]] = []
    if cmd:
        workers.append(list(cmd))
    for extra in (cmds or []):
        if extra:
            workers.append(list(extra))

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

        if workers:
            exit_codes: List[Optional[int]] = []
            detected = False
            for worker in workers:
                returncode, output = _replay(worker, crash_path, timeout)
                exit_codes.append(returncode)
                findings: List[SanitizerFinding] = \
                    parse_sanitizer_output(output)
                exit_finding = check_exit_code(returncode)
                if exit_finding:
                    findings.append(exit_finding)
                for finding in findings:
                    detected = True
                    result.monitor_reports.append(MonitorReport(
                        detected=True,
                        finding_type=f'{finding.sanitizer}:{finding.error_kind}',
                        description=finding.summary,
                        evidence=finding.stack_trace or None,
                    ))
            result.success = detected
            result.metadata['exit_code'] = (
                exit_codes[0] if len(exit_codes) == 1 else exit_codes)

        results.append(result)
    return results


def triage_to_sarif(crashes_or_dir,
                     cmd: Optional[List[str]] = None,
                     cmds: Optional[List[List[str]]] = None,
                     sarif_path: Optional[str] = None,
                     timeout: float = 10.0,
                     include_queue: bool = False) -> List[AttackResult]:
    """Triage crashes and optionally write a SARIF v2.1.0 report.

    ``crashes_or_dir`` may be an AFL/AFLNet output directory (str) or an
    explicit list of input file paths. ``cmd`` / ``cmds`` select the
    sanitizer worker binary/binaries to replay through (see ``triage``).

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
    results = triage(crashes, cmd=cmd, cmds=cmds, timeout=timeout)
    if sarif_path:
        from .test_runner import write_sarif
        write_sarif(results, sarif_path)
    return results
