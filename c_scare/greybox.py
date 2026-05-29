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
                     MSan) into structured findings. File targets replay
                     the input as a file argument; AFLNet network targets
                     replay it at a freshly launched instrumented server
                     with aflnet-replay (net_target=...)

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

Network triage: an AFLNet input is a serialized DICOM message stream, not
a file - it cannot be replayed as a binary argument. triage(net_target=...)
launches a fresh instrumented server per input, replays the stream at it
with AFLNet's aflnet-replay, and parses the *server's* own stderr (where
the sanitizer report lands). A fresh server per input keeps every finding
attributable to exactly one input.

Leak detection: an AFL campaign runs with detect_leaks=0 (a leak at exit
is noise mid-loop and clashes with the forkserver). A triage replay is a
clean one-shot process, so LeakSanitizer's atexit scan works here -
_triage_env() forces detect_leaks back on. Leak-triggering inputs sit in
the queue, so pass include_queue=True to surface CVE-class leaks. For
network targets a leak is reported only if the server runs its atexit
scan on the triage shutdown signal, so file targets remain the reliable
path for leak-class bugs.
"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from typing import List, Optional

from .attacks import AttackResult
from .monitor import (
    MonitorReport, SanitizerFinding,
    parse_sanitizer_output, check_exit_code,
)

__all__ = [
    'TARGETS', 'NET_TARGETS', 'repo_root', 'run', 'list_crashes',
    'list_queue', 'find_san_workers', 'triage', 'triage_to_sarif',
]

# Targets are declared by per-target YAML profiles under fuzz/targets/ (see
# c_scare.profiles). TARGETS maps target name -> fuzz harness script and
# NET_TARGETS lists the AFLNet network targets (triaged by replaying the input
# at a launched instrumented server, see triage(net_target=...), not as a file
# argument). Both are derived from the profiles so adding a target is a matter
# of dropping in one YAML — no edit here, in scripts/campaign.sh, or in the
# seed generators. The literal fallback keeps `import c_scare` working if the
# profiles directory is ever absent.
_LITERAL_TARGETS = {
    'file': 'fuzz_file.sh',
    'parse': 'fuzz_parse.sh',
    'net-storescp': 'fuzz_net.sh',
    'net-dcmrecv': 'fuzz_dcmrecv.sh',
    'net-dcmqrscp': 'fuzz_dcmqrscp.sh',
    'scu': 'fuzz_scu.sh',
}
_LITERAL_NET_TARGETS = ('net-storescp', 'net-dcmrecv', 'net-dcmqrscp')

try:
    from . import profiles as _profiles
    _PROFILES = _profiles.load_profiles()
    if _PROFILES:
        TARGETS = {name: p.harness for name, p in _PROFILES.items()}
        NET_TARGETS = tuple(sorted(
            name for name, p in _PROFILES.items() if p.kind == 'net-scp'))
    else:
        TARGETS = dict(_LITERAL_TARGETS)
        NET_TARGETS = _LITERAL_NET_TARGETS
except Exception:
    # A missing/broken profile must never break importing the package.
    TARGETS = dict(_LITERAL_TARGETS)
    NET_TARGETS = _LITERAL_NET_TARGETS


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


def _free_port() -> int:
    """Return a currently-free local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait_port(host: str, port: int, deadline: float) -> bool:
    """Block until ``host:port`` accepts a connection, or ``deadline`` passes."""
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _render_config(repo: str, profile):
    """Render a target's config from its template into a throwaway tree.

    Returns ``(config_path, base_dir)``; remove ``base_dir`` to clean up.
    Mirrors the ``@REPO_ROOT@`` substitution scripts/fuzz_dcmqrscp.sh does, but
    points storage at a temp tree so triage never writes into the repo. The AE
    titles come from the same profile fields the seed A-ASSOCIATE-RQ uses
    (``@CALLING_AE@`` / ``@CALLED_AE@``), so the rendered config and the seeds
    agree on who may associate.
    """
    template = profile.config_template or os.path.join(
        repo, 'fuzz', 'configs', 'dcmqrscp.cfg.template')
    with open(template, 'r') as fh:
        body = fh.read()
    base = tempfile.mkdtemp(prefix='cscare-triage-qr-')
    os.makedirs(os.path.join(base, 'fuzz', 'storage', 'dcmqrscp'),
                exist_ok=True)
    cfg = os.path.join(base, 'dcmqrscp.cfg')
    body = body.replace('@REPO_ROOT@', base)
    if profile.calling_ae is not None:
        body = body.replace('@CALLING_AE@', profile.calling_ae)
    if profile.called_ae is not None:
        body = body.replace('@CALLED_AE@', profile.called_ae)
    with open(cfg, 'w') as fh:
        fh.write(body)
    return cfg, base


def _net_server_argv(profile, server_binary: str, port: int,
                     workdir: str, config: Optional[str]) -> List[str]:
    """Build the instrumented-server argv for a network triage replay.

    Driven by the profile's ``triage.server_argv`` (placeholder tokens
    substituted), so adding a network target needs no code change here.
    """
    from .profiles import subst
    return [server_binary] + [
        subst(tok, repo=None, port=port, workdir=workdir, config=config)
        for tok in profile.triage_server_argv
    ]


def _replay_net(server_binary: str, net_target: str, crash_path: str,
                timeout: float, repo: str):
    """Triage one AFLNet input against a freshly launched instrumented server.

    Returns ``(returncode, server_output)``. aflnet-replay is only the
    transport that delivers the recorded DICOM message stream; the verdict
    is the *server's* own stderr, where the sanitizer report is written.
    A fresh server per input means a crash is attributable to exactly that
    input and cannot mask the inputs that follow. The server argv, readiness
    wait, and shutdown signal all come from the target profile.
    """
    from .profiles import load_profile
    replay_bin = os.path.join(repo, 'fuzz', 'aflnet', 'aflnet-replay')
    if not os.access(replay_bin, os.X_OK):
        return None, (f'aflnet-replay not found at {replay_bin} — '
                      f'run scripts/install_afl.sh')
    if not (os.path.isfile(server_binary) and os.access(server_binary, os.X_OK)):
        return None, f'instrumented server not executable: {server_binary}'

    # The profile is intrinsic to C-SCARE (it defines the target), so it is
    # loaded from the C-SCARE repo root, not the caller's ``repo`` (which only
    # locates aflnet-replay / the data dictionary, e.g. a test fixture tree).
    try:
        profile = load_profile(net_target)
    except (FileNotFoundError, ValueError) as e:
        return None, f'profile load failed for {net_target!r}: {e}'

    port = _free_port()
    workdir = tempfile.mkdtemp(prefix='cscare-triage-net-')
    env = _triage_env()
    dict_path = os.path.join(repo, 'fuzz', 'dcmtk', 'dcmdata', 'data',
                             'dicom.dic')
    if os.path.isfile(dict_path):
        env['DCMDICTPATH'] = dict_path

    # Render the config only when the server argv asks for one ({{CONFIG}}).
    qr_base = None
    config_path = None
    if any('{{CONFIG}}' in tok for tok in profile.triage_server_argv):
        try:
            config_path, qr_base = _render_config(repo, profile)
        except OSError as e:
            shutil.rmtree(workdir, ignore_errors=True)
            return None, f'config setup failed: {e}'
    argv = _net_server_argv(profile, server_binary, port, workdir, config_path)

    proc = None
    try:
        proc = subprocess.Popen(argv, cwd=workdir, env=env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        # Wait for the listener; if it never comes up the server likely
        # exited early — its captured output below explains why.
        _wait_port('127.0.0.1', port, time.time() + profile.port_wait_s)
        try:
            subprocess.run(
                [replay_bin, crash_path, 'DICOM', str(port), '127.0.0.1'],
                capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        # Let the server fault / flush its sanitizer report.
        time.sleep(0.3)
        crashed = proc.poll() is not None
        if not crashed:
            # Survived the replay. The profile's shutdown signal (SIGINT by
            # default) gives the cleanest shot at an atexit LeakSanitizer
            # scan; escalate below if it is ignored.
            proc.send_signal(getattr(signal, profile.shutdown_signal))
        try:
            output, _ = proc.communicate(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()
        decoded = (output or b'').decode('utf-8', errors='replace')
        # A fault during the replay is the verdict; a shutdown we initiated
        # is not — only surface an exit status when the server faulted on
        # its own, so an ignored SIGINT / our SIGKILL is never a "finding".
        return (proc.returncode if crashed else None), decoded
    except FileNotFoundError as e:
        return None, f'replay failed: {e}'
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        shutil.rmtree(workdir, ignore_errors=True)
        if qr_base:
            shutil.rmtree(qr_base, ignore_errors=True)


def triage(crashes: List[str],
           cmd: Optional[List[str]] = None,
           cmds: Optional[List[List[str]]] = None,
           net_target: Optional[str] = None,
           timeout: float = 10.0,
           repo: Optional[str] = None) -> List[AttackResult]:
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

    For an AFLNet network target pass ``net_target`` (one of ``NET_TARGETS``):
    each command's first element is then the instrumented server binary, and
    every input is replayed at a freshly launched server with aflnet-replay
    (see ``_replay_net``). ``repo`` locates aflnet-replay / the data
    dictionary; it defaults to the C-SCARE repository root.
    """
    if net_target and net_target not in NET_TARGETS:
        raise ValueError(
            f'unknown net_target {net_target!r}; choose from {NET_TARGETS}')
    repo = repo or repo_root()

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
                if net_target:
                    returncode, output = _replay_net(
                        worker[0], net_target, crash_path, timeout, repo)
                else:
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
                     net_target: Optional[str] = None,
                     sarif_path: Optional[str] = None,
                     timeout: float = 10.0,
                     include_queue: bool = False,
                     repo: Optional[str] = None) -> List[AttackResult]:
    """Triage crashes and optionally write a SARIF v2.1.0 report.

    ``crashes_or_dir`` may be an AFL/AFLNet output directory (str) or an
    explicit list of input file paths. ``cmd`` / ``cmds`` select the
    sanitizer worker binary/binaries to replay through; ``net_target``
    switches to AFLNet server-replay triage (see ``triage``).

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
    results = triage(crashes, cmd=cmd, cmds=cmds, net_target=net_target,
                     timeout=timeout, repo=repo)
    if sarif_path:
        from .test_runner import write_sarif
        write_sarif(results, sarif_path)
    return results
