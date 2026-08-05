#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""DUT-side evidence collector for C-SCARE DAST runs.

Run this on the device under test while C-SCARE runs from the test host. It is
dependency-free Python and writes timestamped logs for signals black-box DAST
cannot observe remotely: process/listener health, filesystem canaries, DICOM
logs, per-process RSS/fd/thread growth, filtered kernel faults, coredumps, and
optional inotify evidence. Packet capture is enabled by default and written in
pcap format.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Pattern, Sequence, Set, Tuple


STOP = threading.Event()
CHILDREN: List[subprocess.Popen] = []

# Every DUT-specific value is a flag, not a constant: the device's log paths,
# service name, storage root, and test-host address are all deployment facts.
# --log-dir/--dicom-log, --proc-re, --watch-root, and --peer-host take the
# values for the device under test; the defaults below only cover the generic
# cases (a stock DICOM SCP on the standard port, no device log to follow).
DEFAULT_STORAGE_PORT = 104
DEFAULT_PROC_RE = r"(?:^|/|\()(?:storescp|dcmrecv|dcmqrscp|orthanc)(?:\s|\[|\)|$)"
DEFAULT_WATCH_ROOTS = (Path("/tmp"), Path("/var/tmp"))
DEFAULT_RSS_GROWTH_MB = 128.0
DEFAULT_FD_GROWTH = 64
DEFAULT_THREAD_GROWTH = 32
DEFAULT_RESOURCE_CONSECUTIVE = 3
DMESG_ARGV = ("dmesg", "--follow-new", "--human")
KERNEL_PROCESS_FAILURE_RE = re.compile(
    r"segfault|general protection fault|invalid opcode|trap|oom-kill|"
    r"out of memory|killed process|hung task|core dumped",
    re.IGNORECASE,
)
KERNEL_CRITICAL_RE = re.compile(
    r"kernel panic|BUG: unable to handle|KASAN:|UBSAN:|double fault",
    re.IGNORECASE,
)
COMMAND_ERROR_RE = re.compile(r"permission denied|operation not permitted", re.IGNORECASE)
APPLICATION_FAILURE_RE = re.compile(
    r"AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|"
    r"segmentation fault|segfault|core dumped|stack smashing detected|"
    r"terminate called|std::bad_alloc|out of memory|"
    r"assert(?:ion)?[^\r\n]{0,120}\bfailed\b",
    re.IGNORECASE,
)
# Reachability evidence, not findings: these confirm the DUT's DICOM service
# actually saw the test traffic, so "no crash" can be distinguished from "the
# payloads never arrived". Wording varies per implementation — extend with
# --activity-pattern NAME=REGEX for a device whose log phrasing differs.
APPLICATION_ACTIVITY_PATTERNS = (
    ("association-received", re.compile(
        r"\bassociation\b[^\r\n]{0,40}\b(?:received|request|accepted)\b",
        re.IGNORECASE)),
    ("association-ended", re.compile(
        r"\bassociation\b[^\r\n]{0,40}\b(?:released|ended|closed|terminated)\b",
        re.IGNORECASE)),
    ("listener-started", re.compile(
        r"\b(?:listen|listening|started)\b[^\r\n]{0,40}\bport\b", re.IGNORECASE)),
)


class ProcessResources(NamedTuple):
    rss_kb: Optional[int]
    fd_count: Optional[int]
    thread_count: Optional[int]


class ResourceLimits(NamedTuple):
    rss_growth_kb: int
    fd_growth: int
    thread_growth: int
    consecutive: int


class PathEvidence(NamedTuple):
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int


class EvidenceRecorder:
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.started_at = timestamp()
        self.events: List[Dict[str, str]] = []
        self.coverage: Dict[str, Dict[str, str]] = {}
        self.lock = threading.Lock()

    def record(
        self,
        severity: str,
        kind: str,
        message: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = {
            "timestamp": timestamp(),
            "severity": severity,
            "kind": kind,
            "message": message,
        }
        if properties:
            event["properties"] = properties
        with self.lock:
            self.events.append(event)
            evidence_path = self.out_dir / "evidence.jsonl"
            with evidence_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
            try:
                evidence_path.chmod(0o600)
            except OSError:
                pass
        if severity in ("finding", "warning"):
            print(f"{event['timestamp']} [{severity.upper()}] {kind}: {message}", flush=True)

    def set_coverage(self, name: str, status: str, detail: str) -> None:
        with self.lock:
            self.coverage[name] = {"status": status, "detail": detail}

    def coverage_status(self, name: str) -> Optional[str]:
        with self.lock:
            check = self.coverage.get(name)
            return check["status"] if check is not None else None

    def build_summary(self) -> Dict[str, Any]:
        with self.lock:
            events = list(self.events)
            coverage = dict(self.coverage)
        findings = [event for event in events if event["severity"] == "finding"]
        warnings = [event for event in events if event["severity"] == "warning"]
        gaps = {
            name: check
            for name, check in coverage.items()
            if check["status"] not in ("ok", "active", "optional")
        }
        return {
            "schema": 1,
            "started_at": self.started_at,
            "ended_at": timestamp(),
            "security_finding": "DETECTED" if findings else "NONE_DETECTED",
            "dut_observed_impact": "FAIL" if findings else "NONE",
            "coverage": "REDUCED" if gaps else "FULL",
            "finding_count": len(findings),
            "warning_count": len(warnings),
            "findings": findings,
            "warnings": warnings,
            "coverage_checks": coverage,
        }

    def write_summary(self) -> Dict[str, Any]:
        summary = self.build_summary()
        summary_json = self.out_dir / "summary.json"
        summary_json.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        lines = [
            "C-SCARE DUT monitor summary",
            f"security_finding={summary['security_finding']}",
            f"dut_observed_impact={summary['dut_observed_impact']}",
            f"coverage={summary['coverage']}",
            f"findings={summary['finding_count']}",
            f"warnings={summary['warning_count']}",
            "",
            "Findings",
        ]
        findings = summary["findings"]
        if findings:
            lines.extend(
                f"- {event['timestamp']} {event['kind']}: {event['message']}"
                for event in findings
            )
        else:
            lines.append("- No monitored host-impact signal was detected.")
        lines.extend(("", "Coverage"))
        coverage_checks = summary["coverage_checks"]
        if coverage_checks:
            lines.extend(
                f"- {name}: {check['status']} - {check['detail']}"
                for name, check in sorted(coverage_checks.items())
            )
        else:
            lines.append("- No coverage checks were registered.")
        summary_text = self.out_dir / "summary.txt"
        summary_text.write_text("\n".join(lines) + "\n", encoding="utf-8")
        for path in (summary_json, summary_text):
            try:
                path.chmod(0o600)
            except OSError:
                pass
        self.write_sarif(summary)
        return summary

    def write_sarif(self, summary: Dict[str, Any]) -> Path:
        reportable = [
            event for event in summary["findings"] + summary["warnings"]
            if event["severity"] in ("finding", "warning")
        ]
        kinds = sorted({event["kind"] for event in reportable})
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
                       "sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "C-SCARE DUT Monitor",
                        "informationUri": "https://github.com/tmart234/C-SCARE",
                        "rules": [
                            {
                                "id": f"dut/{kind}",
                                "shortDescription": {"text": kind},
                            }
                            for kind in kinds
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f"dut/{event['kind']}",
                        "level": "error" if event["severity"] == "finding" else "warning",
                        "message": {"text": event["message"]},
                        "properties": {
                            "timestamp": event["timestamp"],
                            "evidence_severity": event["severity"],
                            **event.get("properties", {}),
                        },
                    }
                    for event in reportable
                ],
            }],
        }
        sarif_path = self.out_dir / "dut-monitor.sarif"
        sarif_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
        try:
            sarif_path.chmod(0o600)
        except OSError:
            pass
        return sarif_path


def timestamp() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="microseconds")


def timestamp_from_ns(value: int) -> str:
    return dt.datetime.fromtimestamp(value / 1_000_000_000).astimezone().isoformat(
        timespec="microseconds"
    )


def default_out_dir() -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(f"/tmp/c-scare-monitor-{stamp}")


def open_log(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a", encoding="utf-8", errors="replace", buffering=1)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return handle


def write_line(handle, message: str) -> None:
    handle.write(f"{timestamp()} {message}\n")
    handle.flush()


def sanitize_log_name(value: str, index: int) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip("/")) or "dicom"
    return f"dicom-{index}-{name[-80:]}.log"


def resolve_dicom_logs(selected: Optional[Sequence[Path]],
                       log_dirs: Sequence[Path] = ()) -> List[Path]:
    """Every *.log under each --log-dir, plus every explicit --dicom-log.

    Directories are globbed rather than named so a device that rotates or
    splits its DICOM logs across several files is covered without listing them.
    """
    paths: List[Path] = list(selected or [])
    for directory in log_dirs:
        if directory.is_dir():
            paths.extend(sorted(directory.glob("*.log")))
    return list(dict.fromkeys(paths))


def reset_canaries() -> List[str]:
    candidates = [Path("/tmp/c-scare-rce"), Path("/tmp/c-scare-traversal")]
    candidates.extend(Path("/tmp").glob("c-scare-traversal*"))
    errors: List[str] = []
    for path in candidates:
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        except OSError as exc:
            message = f"could not remove {path}: {exc}"
            errors.append(message)
            print(f"warning: {message}", file=sys.stderr)
    return errors


def run_command(argv: Sequence[str], timeout: float = 10.0) -> Tuple[int, str]:
    try:
        result = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout if isinstance(exc.stdout, str) else ""
        return 124, output + "\nCOMMAND TIMED OUT\n"
    except OSError as exc:
        return 127, f"COMMAND FAILED: {exc}\n"


def application_failure_signature(line: str) -> Optional[str]:
    match = APPLICATION_FAILURE_RE.search(line)
    return match.group(0) if match else None


ACTIVITY_PATTERNS: List[Tuple[str, Pattern[str]]] = list(APPLICATION_ACTIVITY_PATTERNS)
PEER_ADDRESS_RE = re.compile(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b")


def application_activity_signature(line: str) -> Optional[Tuple[str, Optional[str]]]:
    """Classify a log line as DICOM activity, with the peer address if present.

    The address is extracted separately from the activity match so a pattern
    does not have to model where in the line its implementation prints the
    peer -- only whether the line means what it means.
    """
    for activity, regex in ACTIVITY_PATTERNS:
        match = regex.search(line)
        if not match:
            continue
        if match.lastindex:
            return activity, match.group(1)
        peer = PEER_ADDRESS_RE.search(line)
        return activity, peer.group(1) if peer else None
    return None


def follow_file(
    source: Path,
    out_path: Path,
    from_start: bool,
    interval: float,
    recorder: EvidenceRecorder,
) -> None:
    coverage_name = f"log:{source}"
    with open_log(out_path) as out:
        write_line(out, f"following {source}")
        handle = None
        identity: Optional[Tuple[int, int]] = None
        missing_reported = False
        opened_once = False
        captured_lines = 0
        activity_counts: Dict[str, int] = {}
        reported_activity: Set[str] = set()
        while not STOP.is_set():
            try:
                stat = source.stat()
                current_identity = (stat.st_dev, stat.st_ino)
                if handle is None or current_identity != identity:
                    appeared_after_wait = missing_reported
                    rotated = handle is not None
                    if handle is not None:
                        handle.close()
                    handle = source.open("r", encoding="utf-8", errors="replace")
                    identity = current_identity
                    missing_reported = False
                    if not from_start and not opened_once and not appeared_after_wait:
                        handle.seek(0, os.SEEK_END)
                    opened_once = True
                    recorder.set_coverage(coverage_name, "active", f"following {source}")
                    write_line(out, f"opened {source}")
                    if rotated:
                        write_line(out, f"detected rotation for {source}; reading replacement from start")
                elif stat.st_size < handle.tell():
                    handle.seek(0)
                    write_line(out, f"detected truncation for {source}; restarted at beginning")
                line = handle.readline()
                if line:
                    out.write(line if line.endswith("\n") else line + "\n")
                    out.flush()
                    captured_lines += 1
                    signature = application_failure_signature(line)
                    if signature:
                        recorder.record(
                            "finding",
                            "application-runtime-failure",
                            f"{source.name} emitted crash-class signature: {signature}",
                        )
                    activity = application_activity_signature(line)
                    if activity:
                        activity_name, detail = activity
                        activity_counts[activity_name] = activity_counts.get(activity_name, 0) + 1
                        if activity_name not in reported_activity:
                            reported_activity.add(activity_name)
                            suffix = f" from {detail}" if detail else ""
                            recorder.record(
                                "info",
                                f"log:{activity_name}",
                                f"{source.name}: {activity_name}{suffix}",
                            )
                else:
                    STOP.wait(interval)
            except FileNotFoundError:
                if handle is not None:
                    handle.close()
                    handle = None
                    identity = None
                if not missing_reported:
                    write_line(out, f"waiting for {source}")
                    recorder.set_coverage(coverage_name, "gap", f"log file not found: {source}")
                    missing_reported = True
                STOP.wait(interval)
            except OSError as exc:
                write_line(out, f"error following {source}: {exc}")
                recorder.set_coverage(coverage_name, "gap", f"cannot follow {source}: {exc}")
                STOP.wait(interval)
        if handle is not None:
            handle.close()
        if opened_once:
            activity_detail = ", ".join(
                f"{name}={count}" for name, count in sorted(activity_counts.items())
            ) or "none"
            recorder.set_coverage(
                coverage_name,
                "ok",
                f"captured {captured_lines} new lines; activity: {activity_detail}",
            )
        write_line(out, "stopped")


def iter_processes() -> Iterable[Tuple[int, str]]:
    proc_root = Path("/proc")
    if proc_root.is_dir():
        for child in proc_root.iterdir():
            if not child.name.isdigit():
                continue
            try:
                raw = (child / "cmdline").read_bytes()
                if raw:
                    cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                else:
                    cmd = (child / "comm").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if cmd:
                yield int(child.name), cmd
        return

    rc, output = run_command(["ps", "-eo", "pid=,args="], timeout=5.0)
    if rc != 0:
        return
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        pid_text, _, cmdline = line.partition(" ")
        if pid_text.isdigit() and cmdline:
            yield int(pid_text), cmdline.strip()


def parent_pid(pid: int) -> Optional[int]:
    try:
        for line in (Path("/proc") / str(pid) / "status").read_text(
                encoding="ascii", errors="ignore").splitlines():
            if line.startswith("PPid:"):
                value = line.partition(":")[2].strip()
                return int(value) if value.isdigit() else None
    except OSError:
        return None
    return None


def monitor_process_chain() -> Set[int]:
    excluded = {os.getpid()}
    current = os.getppid()
    while current > 1 and current not in excluded:
        excluded.add(current)
        next_pid = parent_pid(current)
        if next_pid is None:
            break
        current = next_pid
    return excluded


def matching_processes(
    processes: Iterable[Tuple[int, str]],
    regex: Pattern[str],
    excluded_pids: Set[int],
) -> Dict[int, str]:
    return {
        pid: command
        for pid, command in processes
        if pid not in excluded_pids
        and command.split(None, 1)
        and regex.search(command.split(None, 1)[0])
    }


def read_process_resources(pid: int, proc_root: Path = Path("/proc")) -> Optional[ProcessResources]:
    process_root = proc_root / str(pid)
    try:
        status_lines = (process_root / "status").read_text(
            encoding="ascii", errors="ignore"
        ).splitlines()
    except OSError:
        return None

    rss_kb: Optional[int] = None
    thread_count: Optional[int] = None
    for line in status_lines:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        fields = value.strip().split()
        if key == "VmRSS" and fields and fields[0].isdigit():
            rss_kb = int(fields[0])
        elif key == "Threads" and fields and fields[0].isdigit():
            thread_count = int(fields[0])

    try:
        fd_count: Optional[int] = sum(1 for _entry in (process_root / "fd").iterdir())
    except OSError:
        fd_count = None
    if rss_kb is None and fd_count is None and thread_count is None:
        return None
    return ProcessResources(rss_kb=rss_kb, fd_count=fd_count, thread_count=thread_count)


def resource_deltas(
    current: ProcessResources,
    baseline: ProcessResources,
) -> Dict[str, Optional[int]]:
    def delta(value: Optional[int], initial: Optional[int]) -> Optional[int]:
        return value - initial if value is not None and initial is not None else None

    return {
        "rss_kb": delta(current.rss_kb, baseline.rss_kb),
        "fd_count": delta(current.fd_count, baseline.fd_count),
        "thread_count": delta(current.thread_count, baseline.thread_count),
    }


class ResourceTracker:
    def __init__(self, path: Path, limits: ResourceLimits, recorder: EvidenceRecorder):
        self.path = path
        self.limits = limits
        self.recorder = recorder
        self.baselines: Dict[int, ProcessResources] = {}
        self.breach_counts: Dict[Tuple[int, str], int] = {}
        self.reported: Set[Tuple[int, str]] = set()
        self.peak_deltas = {"rss_kb": 0, "fd_count": 0, "thread_count": 0}
        self.metric_samples = {"rss_kb": 0, "fd_count": 0, "thread_count": 0}
        self.samples = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        write_header = not path.exists() or path.stat().st_size == 0
        self.handle = path.open("a", encoding="utf-8", errors="replace", newline="", buffering=1)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        self.writer = csv.writer(self.handle)
        if write_header:
            self.writer.writerow([
                "timestamp", "pid", "rss_kb", "rss_delta_kb", "fd_count", "fd_delta",
                "thread_count", "thread_delta",
            ])
        recorder.set_coverage("process-resources", "active", f"sampling to {path.name}")

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        self.close()

    def sample_processes(self, processes: Dict[int, str]) -> None:
        for pid in sorted(processes):
            current = read_process_resources(pid)
            if current is None:
                continue
            baseline = self.baselines.setdefault(pid, current)
            deltas = resource_deltas(current, baseline)
            self.samples += 1
            for metric in self.metric_samples:
                if getattr(current, metric) is not None:
                    self.metric_samples[metric] += 1
            self.writer.writerow([
                timestamp(), pid,
                current.rss_kb if current.rss_kb is not None else "",
                deltas["rss_kb"] if deltas["rss_kb"] is not None else "",
                current.fd_count if current.fd_count is not None else "",
                deltas["fd_count"] if deltas["fd_count"] is not None else "",
                current.thread_count if current.thread_count is not None else "",
                deltas["thread_count"] if deltas["thread_count"] is not None else "",
            ])
            self._check_growth(pid, current, baseline, deltas)

    def _check_growth(
        self,
        pid: int,
        current: ProcessResources,
        baseline: ProcessResources,
        deltas: Dict[str, Optional[int]],
    ) -> None:
        checks = (
            ("rss_kb", self.limits.rss_growth_kb, "resource:rss-growth"),
            ("fd_count", self.limits.fd_growth, "resource:fd-growth"),
            ("thread_count", self.limits.thread_growth, "resource:thread-growth"),
        )
        for metric, threshold, finding_type in checks:
            growth = deltas[metric]
            if growth is not None:
                self.peak_deltas[metric] = max(self.peak_deltas[metric], growth)
            key = (pid, metric)
            if threshold > 0 and growth is not None and growth >= threshold:
                self.breach_counts[key] = self.breach_counts.get(key, 0) + 1
            else:
                self.breach_counts[key] = 0
            if self.breach_counts[key] < self.limits.consecutive or key in self.reported:
                continue
            self.reported.add(key)
            initial = getattr(baseline, metric)
            value = getattr(current, metric)
            if metric == "rss_kb":
                detail = (f"pid={pid} RSS grew by {growth / 1024:.1f} MiB "
                          f"from {initial / 1024:.1f} to {value / 1024:.1f} MiB")
            else:
                label = "file descriptors" if metric == "fd_count" else "threads"
                detail = f"pid={pid} {label} grew by {growth} from {initial} to {value}"
            self.recorder.record("finding", finding_type, detail)

    def close(self) -> None:
        self.handle.close()
        detail = (
            f"samples={self.samples}, peak_rss_growth={self.peak_deltas['rss_kb'] / 1024:.1f} MiB, "
            f"peak_fd_growth={self.peak_deltas['fd_count']}, "
            f"peak_thread_growth={self.peak_deltas['thread_count']}, "
            f"metric_samples={self.metric_samples}"
        )
        complete = self.samples > 0 and all(count > 0 for count in self.metric_samples.values())
        self.recorder.set_coverage(
            "process-resources", "ok" if complete else "gap", detail
        )


def parse_proc_net(path: Path, ports: Sequence[int]) -> Dict[int, bool]:
    found = {port: False for port in ports}
    try:
        lines = path.read_text(encoding="ascii", errors="ignore").splitlines()[1:]
    except OSError:
        return found
    wanted = set(ports)
    for line in lines:
        fields = line.split()
        if len(fields) < 4 or fields[3] != "0A":
            continue
        try:
            port = int(fields[1].rsplit(":", 1)[1], 16)
        except (IndexError, ValueError):
            continue
        if port in wanted:
            found[port] = True
    return found


def listening_ports(ports: Sequence[int]) -> Dict[int, bool]:
    merged = {port: False for port in ports}
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        for port, found in parse_proc_net(path, ports).items():
            merged[port] = merged[port] or found
    return merged


def process_listener_monitor(
    out_path: Path,
    proc_re: str,
    ports: Sequence[int],
    interval: float,
    resource_limits: ResourceLimits,
    recorder: EvidenceRecorder,
    ready: threading.Event,
) -> None:
    regex = re.compile(proc_re, re.IGNORECASE)
    excluded_pids = monitor_process_chain()
    previous_processes: Optional[Dict[int, str]] = None
    previous_ports: Optional[Dict[int, bool]] = None
    resource_path = out_path.parent / "process-resources.csv"
    with ResourceTracker(resource_path, resource_limits, recorder) as resources, open_log(out_path) as out:
        write_line(out, f"process regex: {proc_re}")
        write_line(out, f"excluded monitor/ancestor pids: {sorted(excluded_pids)}")
        write_line(out, "ports: " + (", ".join(str(port) for port in ports) if ports else "(none)"))
        while not STOP.is_set():
            current_processes = matching_processes(iter_processes(), regex, excluded_pids)
            current_ports = listening_ports(ports)
            resources.sample_processes(current_processes)

            if previous_processes is None:
                process_status = "ok" if current_processes else "gap"
                detail = f"baseline pids={sorted(current_processes)}" if current_processes else \
                    "no matching target process at monitor start"
                recorder.set_coverage("target-process", process_status, detail)
                if not current_processes:
                    recorder.record("warning", "process-baseline-missing", detail)
                write_line(out, f"BASELINE process_count={len(current_processes)}")
                for pid, command in sorted(current_processes.items())[:25]:
                    write_line(out, f"pid={pid} cmd={command}")
                for port, is_listening in current_ports.items():
                    state = "LISTENING" if is_listening else "NOT_LISTENING"
                    recorder.set_coverage(
                        f"listener-{port}",
                        "ok" if is_listening else "gap",
                        f"port {port} was {state.lower()} at monitor start",
                    )
                    if not is_listening:
                        recorder.record("warning", "listener-baseline-missing",
                                        f"port {port} was not listening at monitor start")
                    write_line(out, f"BASELINE port={port} state={state}")
                ready.set()
            else:
                previous_pids = set(previous_processes)
                current_pids = set(current_processes)
                if previous_pids and not current_pids:
                    message = f"target process disappeared; previous pids={sorted(previous_pids)}"
                    write_line(out, f"FINDING {message}")
                    recorder.record("finding", "target-process-lost", message)
                elif previous_pids and current_pids and previous_pids.isdisjoint(current_pids):
                    message = (f"target process pids replaced; previous={sorted(previous_pids)} "
                               f"current={sorted(current_pids)}")
                    write_line(out, f"FINDING {message}")
                    recorder.record("finding", "target-process-restarted", message)
                elif not previous_pids and current_pids:
                    message = f"target process appeared; pids={sorted(current_pids)}"
                    write_line(out, message)
                    recorder.record("info", "target-process-appeared", message)
                    recorder.set_coverage("target-process", "ok", message)
                elif previous_pids != current_pids:
                    write_line(out, f"process set changed from {sorted(previous_pids)} to {sorted(current_pids)}")

                for port, is_listening in current_ports.items():
                    was_listening = previous_ports.get(port, False) if previous_ports else False
                    if was_listening and not is_listening:
                        message = f"DICOM listener port {port} stopped listening"
                        write_line(out, f"FINDING {message}")
                        recorder.record("finding", "listener-lost", message)
                    elif not was_listening and is_listening:
                        message = f"DICOM listener port {port} started listening"
                        write_line(out, message)
                        recorder.record("info", "listener-appeared", message)
                        recorder.set_coverage(f"listener-{port}", "ok", message)

            previous_processes = current_processes
            previous_ports = current_ports
            STOP.wait(interval)

        final_processes = matching_processes(iter_processes(), regex, excluded_pids)
        final_ports = listening_ports(ports)
        resources.sample_processes(final_processes)
        previous_pids = set(previous_processes or {})
        final_pids = set(final_processes)
        if previous_pids and not final_pids:
            message = f"target process absent at monitor shutdown; previous pids={sorted(previous_pids)}"
            write_line(out, f"FINDING {message}")
            recorder.record("finding", "target-process-lost", message)
        elif previous_pids and final_pids and previous_pids.isdisjoint(final_pids):
            message = (f"target process pids replaced at monitor shutdown; "
                       f"previous={sorted(previous_pids)} current={sorted(final_pids)}")
            write_line(out, f"FINDING {message}")
            recorder.record("finding", "target-process-restarted", message)
        for port, is_listening in final_ports.items():
            was_listening = (previous_ports or {}).get(port, False)
            if was_listening and not is_listening:
                message = f"DICOM listener port {port} was not listening at monitor shutdown"
                write_line(out, f"FINDING {message}")
                recorder.record("finding", "listener-lost", message)
        write_line(out, "stopped")
    ready.set()


def should_report_path(path: Path) -> bool:
    name = path.name.lower()
    return name == "c-scare-rce" or "c-scare-traversal" in name


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def walk_limited(root: Path, max_depth: int, excluded: Sequence[Path] = ()) -> Iterable[Path]:
    if not root.exists():
        return
    root = root.resolve()
    for current, dirs, files in os.walk(root, topdown=True, onerror=lambda _err: None):
        if STOP.is_set():
            return
        current_path = Path(current)
        dirs[:] = [
            name for name in dirs
            if not any(path_is_within(current_path / name, excluded_path)
                       for excluded_path in excluded)
        ]
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            depth = 0
        if depth >= max_depth:
            dirs[:] = []
        for name in list(dirs) + files:
            path = current_path / name
            if should_report_path(path):
                yield path


def path_fingerprint(path: Path) -> PathEvidence:
    stat = path.lstat()
    return PathEvidence(stat.st_mode, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def filesystem_monitor(
    out_path: Path,
    roots: Sequence[Path],
    excluded: Sequence[Path],
    max_depth: int,
    interval: float,
    recorder: EvidenceRecorder,
) -> None:
    seen: Dict[str, PathEvidence] = {}
    explicit = [Path("/tmp/c-scare-rce"), Path("/tmp/c-scare-traversal")]
    with open_log(out_path) as out:
        write_line(out, "watch roots: " + ", ".join(str(root) for root in roots))
        write_line(out, "excluded paths: " + ", ".join(str(path) for path in excluded))
        recorder.set_coverage("filesystem-canaries", "active", "canary scan started")
        while not STOP.is_set():
            current: Dict[str, PathEvidence] = {}
            candidates: List[Path] = []
            for root in roots:
                candidates.extend(walk_limited(root, max_depth, excluded) or [])
            candidates.extend(path for path in explicit if path.exists() or path.is_symlink())
            for path in sorted(set(candidates), key=str):
                try:
                    fingerprint = path_fingerprint(path)
                except OSError:
                    continue
                key = str(path)
                current[key] = fingerprint
                if seen.get(key) != fingerprint:
                    mode = oct(fingerprint.mode)
                    properties = {
                        "path": key,
                        "mode": mode,
                        "size": fingerprint.size,
                        "mtime": timestamp_from_ns(fingerprint.mtime_ns),
                        "mtime_epoch_ns": fingerprint.mtime_ns,
                        "ctime": timestamp_from_ns(fingerprint.ctime_ns),
                        "ctime_epoch_ns": fingerprint.ctime_ns,
                    }
                    message = (
                        f"canary path={path} mode={mode} size={fingerprint.size} "
                        f"mtime={properties['mtime']} ctime={properties['ctime']}"
                    )
                    write_line(out, f"FINDING {message}")
                    recorder.record("finding", "filesystem-canary", message, properties)
            for removed in sorted(set(seen) - set(current)):
                write_line(out, f"CANARY_REMOVED path={removed}")
            seen = current
            STOP.wait(interval)
        write_line(out, "stopped")
        recorder.set_coverage("filesystem-canaries", "ok", "canary scan stopped cleanly")


def coredump_monitor(
    out_path: Path,
    since: str,
    proc_re: str,
    interval: float,
    recorder: EvidenceRecorder,
) -> None:
    with open_log(out_path) as out:
        if shutil.which("coredumpctl") is None:
            write_line(out, "coredumpctl not found")
            recorder.set_coverage("coredumps", "unavailable", "coredumpctl not found")
            return
        write_line(out, f"coredumpctl since: {since}")
        recorder.set_coverage("coredumps", "active", f"querying since {since}")
        process_regex = re.compile(proc_re, re.IGNORECASE)
        seen: Set[str] = set()
        failed = False
        while not STOP.is_set():
            rc, output = run_command(
                ["coredumpctl", "--no-pager", "--no-legend", "list", "--since", since],
                timeout=20.0,
            )
            if rc not in (0, 1) or COMMAND_ERROR_RE.search(output):
                detail = f"coredumpctl failed rc={rc}: {output.strip()[:240]}"
                write_line(out, detail)
                recorder.set_coverage("coredumps", "unavailable", detail)
                if not failed:
                    recorder.record("warning", "coredump-monitor-unavailable", detail)
                failed = True
            for line in output.splitlines():
                normalized = line.strip()
                if not normalized or normalized in seen or not process_regex.search(normalized):
                    continue
                seen.add(normalized)
                write_line(out, f"FINDING {normalized}")
                recorder.record("finding", "target-coredump", normalized)
            STOP.wait(interval)
        write_line(out, "stopped")
        if not failed:
            recorder.set_coverage("coredumps", "ok", f"target coredumps detected={len(seen)}")


def relevant_kernel_line(line: str, process_regex: Pattern[str]) -> bool:
    if COMMAND_ERROR_RE.search(line) or KERNEL_CRITICAL_RE.search(line):
        return True
    return bool(process_regex.search(line) and KERNEL_PROCESS_FAILURE_RE.search(line))


def _copy_filtered_dmesg(
    proc: subprocess.Popen,
    out,
    process_regex: Pattern[str],
    recorder: EvidenceRecorder,
) -> None:
    captured = 0
    filtered = 0
    command_failed = False
    try:
        if proc.stdout is None:
            return
        for line in proc.stdout:
            if relevant_kernel_line(line, process_regex):
                normalized = line.rstrip()
                write_line(out, normalized)
                captured += 1
                if COMMAND_ERROR_RE.search(normalized):
                    recorder.set_coverage("kernel-events", "unavailable", normalized)
                    recorder.record("warning", "kernel-monitor-unavailable", normalized)
                    command_failed = True
                else:
                    recorder.record("finding", "kernel-runtime-failure", normalized[:500])
            else:
                filtered += 1
    finally:
        returncode = proc.poll()
        write_line(out, f"dmesg stopped rc={returncode} captured={captured} filtered={filtered}")
        if not STOP.is_set() and returncode not in (0, None) and not command_failed:
            detail = f"dmesg exited before monitor shutdown with rc={returncode}"
            recorder.set_coverage("kernel-events", "unavailable", detail)
            recorder.record("warning", "kernel-monitor-exited", detail)
        elif not command_failed:
            recorder.set_coverage(
                "kernel-events", "ok", f"captured={captured} filtered={filtered}"
            )
        out.close()


def start_dmesg_monitor(
    out_path: Path,
    proc_re: str,
    recorder: EvidenceRecorder,
) -> Optional[threading.Thread]:
    argv = list(DMESG_ARGV)
    if shutil.which(argv[0]) is None:
        with open_log(out_path) as out:
            write_line(out, "dmesg: command not found")
        recorder.set_coverage("kernel-events", "unavailable", "dmesg command not found")
        return None

    out = open_log(out_path)
    write_line(out, f"starting filtered dmesg: {' '.join(argv)}")
    write_line(out, f"target process regex: {proc_re}")
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        write_line(out, f"failed to start dmesg: {exc}")
        out.close()
        return None

    CHILDREN.append(proc)
    recorder.set_coverage("kernel-events", "active", "filtered dmesg follow started")
    thread = threading.Thread(
        target=_copy_filtered_dmesg,
        args=(proc, out, re.compile(proc_re, re.IGNORECASE), recorder),
        daemon=True,
    )
    thread.start()
    return thread


def start_command(
    name: str,
    argv: Sequence[str],
    out_path: Path,
    recorder: Optional[EvidenceRecorder] = None,
    coverage_name: Optional[str] = None,
) -> Optional[subprocess.Popen]:
    if not argv or shutil.which(argv[0]) is None:
        with open_log(out_path) as out:
            command = argv[0] if argv else ""
            write_line(out, f"{name}: command not found: {command}")
        if recorder is not None and coverage_name is not None:
            recorder.set_coverage(coverage_name, "unavailable", f"command not found: {command}")
            recorder.record("warning", f"{coverage_name}-unavailable",
                            f"command not found: {command}")
        return None
    handle = open_log(out_path)
    write_line(handle, f"starting {name}: {' '.join(argv)}")
    try:
        proc = subprocess.Popen(list(argv), stdout=handle, stderr=subprocess.STDOUT)
    except OSError as exc:
        write_line(handle, f"failed to start {name}: {exc}")
        handle.close()
        if recorder is not None and coverage_name is not None:
            recorder.set_coverage(coverage_name, "unavailable", str(exc))
            recorder.record("warning", f"{coverage_name}-unavailable", str(exc))
        return None
    proc._cscare_log_handle = handle  # type: ignore[attr-defined]
    proc._cscare_name = name  # type: ignore[attr-defined]
    proc._cscare_coverage_name = coverage_name  # type: ignore[attr-defined]
    CHILDREN.append(proc)
    if recorder is not None and coverage_name is not None:
        recorder.set_coverage(coverage_name, "active", f"{name} started")
    return proc


def stop_children(recorder: EvidenceRecorder) -> None:
    for proc in CHILDREN:
        returncode = proc.poll()
        if returncode is None:
            proc.terminate()
        else:
            name = getattr(proc, "_cscare_name", "collector")
            coverage_name = getattr(proc, "_cscare_coverage_name", None)
            detail = f"{name} exited before monitor shutdown with rc={returncode}"
            if coverage_name is not None:
                recorder.set_coverage(coverage_name, "unavailable", detail)
                recorder.record("warning", f"{coverage_name}-exited", detail)
    deadline = time.time() + 5
    for proc in CHILDREN:
        remaining = max(0.1, deadline - time.time())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        handle = getattr(proc, "_cscare_log_handle", None)
        if handle is not None:
            handle.close()


def install_signal_handlers() -> None:
    def _handle(_signum, _frame):
        STOP.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)


def start_thread(target, *args) -> threading.Thread:
    thread = threading.Thread(
        target=target,
        args=args,
        name=f"dut-{target.__name__}",
        daemon=True,
    )
    thread.start()
    return thread


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect DUT-side evidence during a C-SCARE DAST run."
    )
    parser.add_argument("--out-dir", type=Path, default=None,
                        help="output directory (default: /tmp/c-scare-monitor-<timestamp>)")
    parser.add_argument("--dicom-log", action="append", default=None, type=Path,
                        help="DUT log file to follow for DICOM activity and crash "
                             "signatures; repeat for several files")
    parser.add_argument("--log-dir", action="append", default=[], type=Path,
                        help="directory whose *.log files are all followed; repeat as needed")
    parser.add_argument("--activity-pattern", action="append", default=[], metavar="NAME=REGEX",
                        help="extra DICOM-activity log pattern for a device whose log "
                             "phrasing differs from the built-in ones; repeat as needed")
    parser.add_argument("--from-start", action="store_true",
                        help="read DICOM logs from the beginning instead of tailing new lines")
    parser.add_argument("--proc-re", default=DEFAULT_PROC_RE,
                        help="case-insensitive process regex")
    parser.add_argument("--port", action="append", type=int, default=[],
                        help="listener port to monitor; repeat as needed")
    parser.add_argument("--storage-port", type=int, default=DEFAULT_STORAGE_PORT,
                        help=f"storage SCP listener port to monitor (default: {DEFAULT_STORAGE_PORT})")
    parser.add_argument("--qr-port", type=int,
                        help="query/retrieve listener port to monitor")
    parser.add_argument("--watch-root", action="append", default=[], type=Path,
                        help="filesystem root to scan for c-scare traversal canaries; "
                             "repeat as needed. Point this at the DUT's DICOM storage "
                             "root so a write that escapes it is visible (default: "
                             + ", ".join(str(root) for root in DEFAULT_WATCH_ROOTS) + ")")
    parser.add_argument("--max-depth", type=int, default=5,
                        help="filesystem scan depth below each watch root")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="process/filesystem polling interval in seconds")
    parser.add_argument("--rss-growth-mb", type=float, default=DEFAULT_RSS_GROWTH_MB,
                        help=f"persistent RSS growth finding threshold in MiB; 0 disables "
                             f"(default: {DEFAULT_RSS_GROWTH_MB:g})")
    parser.add_argument("--fd-growth", type=int, default=DEFAULT_FD_GROWTH,
                        help=f"persistent file-descriptor growth threshold; 0 disables "
                             f"(default: {DEFAULT_FD_GROWTH})")
    parser.add_argument("--thread-growth", type=int, default=DEFAULT_THREAD_GROWTH,
                        help=f"persistent thread growth threshold; 0 disables "
                             f"(default: {DEFAULT_THREAD_GROWTH})")
    parser.add_argument("--resource-consecutive", type=int, default=DEFAULT_RESOURCE_CONSECUTIVE,
                        help=f"consecutive samples required for a resource finding "
                             f"(default: {DEFAULT_RESOURCE_CONSECUTIVE})")
    parser.add_argument("--coredump-interval", type=float, default=10.0,
                        help="coredumpctl polling interval in seconds")
    parser.add_argument("--duration", type=float, default=None,
                        help="stop after this many seconds; default runs until Ctrl-C")
    parser.add_argument("--fail-on-finding", action="store_true",
                        help="exit 1 when host-impact evidence is detected")
    parser.add_argument("--since", default=None,
                        help="coredumpctl --since value (default: monitor start time)")
    canary_group = parser.add_mutually_exclusive_group()
    canary_group.add_argument("--reset-canaries", dest="reset_canaries", action="store_true",
                              default=True,
                              help="remove /tmp/c-scare-rce and /tmp/c-scare-traversal* at startup (default)")
    canary_group.add_argument("--no-reset-canaries", dest="reset_canaries", action="store_false",
                              help="preserve existing C-SCARE canaries")
    parser.add_argument("--no-dmesg", action="store_true",
                        help="do not monitor filtered kernel crash/OOM events")
    parser.add_argument("--no-coredumpctl", action="store_true", help="do not poll coredumpctl")
    parser.add_argument("--no-process", action="store_true", help="do not monitor processes/listeners")
    parser.add_argument("--no-filesystem", action="store_true", help="do not scan filesystem canaries")
    parser.add_argument("--inotify", action="store_true", help="also run inotifywait if installed")
    tcpdump_group = parser.add_mutually_exclusive_group()
    tcpdump_group.add_argument("--tcpdump", dest="tcpdump", action="store_true", default=True,
                               help="capture packets to network.pcap (default)")
    tcpdump_group.add_argument("--no-tcpdump", dest="tcpdump", action="store_false",
                               help="disable packet capture")
    parser.add_argument("--tcpdump-interface", default="any", help="tcpdump interface (default: any)")
    parser.add_argument("--tcpdump-snaplen", type=int, default=256,
                        help="bytes captured per packet; use 0 for full packets (default: 256)")
    parser.add_argument("--peer-host", default=None,
                        help="address of the host running C-SCARE; narrows the capture "
                             "filter to that peer (default: capture all peers)")
    parser.add_argument("--tcpdump-filter", default=None,
                        help="override the capture filter (default: the monitored ports, "
                             "restricted to --peer-host when given)")
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    if args.coredump_interval <= 0:
        parser.error("--coredump-interval must be greater than zero")
    if args.duration is not None and args.duration < 0:
        parser.error("--duration cannot be negative")
    if args.max_depth < 0:
        parser.error("--max-depth cannot be negative")
    if args.rss_growth_mb < 0 or args.fd_growth < 0 or args.thread_growth < 0:
        parser.error("resource growth thresholds cannot be negative")
    if args.resource_consecutive < 1:
        parser.error("--resource-consecutive must be at least 1")
    if args.tcpdump_snaplen < 0:
        parser.error("--tcpdump-snaplen cannot be negative")
    for port in list(args.port) + [args.storage_port, args.qr_port]:
        if port is not None and not 1 <= port <= 65535:
            parser.error(f"invalid TCP port: {port}")
    try:
        re.compile(args.proc_re)
    except re.error as exc:
        parser.error(f"invalid --proc-re: {exc}")
    for spec in args.activity_pattern:
        name, sep, pattern = spec.partition("=")
        if not sep or not name.strip() or not pattern:
            parser.error(f"--activity-pattern must be NAME=REGEX: {spec!r}")
        try:
            ACTIVITY_PATTERNS.append((name.strip(), re.compile(pattern, re.IGNORECASE)))
        except re.error as exc:
            parser.error(f"invalid --activity-pattern regex for {name.strip()!r}: {exc}")
    try:
        shlex.split(resolved_tcpdump_filter(args))
    except ValueError as exc:
        parser.error(f"invalid --tcpdump-filter: {exc}")
    return args


def merged_ports(args: argparse.Namespace) -> List[int]:
    ports = list(args.port)
    if args.storage_port is not None:
        ports.append(args.storage_port)
    if args.qr_port is not None:
        ports.append(args.qr_port)
    return sorted(set(ports))


def tcpdump_argv(args: argparse.Namespace, capture_path: Path) -> List[str]:
    argv = [
        "tcpdump", "-i", args.tcpdump_interface, "-nn", "-s", str(args.tcpdump_snaplen), "-U",
        "-w", str(capture_path),
    ]
    capture_filter = resolved_tcpdump_filter(args)
    if capture_filter.strip():
        argv.extend(shlex.split(capture_filter))
    return argv


def resolved_tcpdump_filter(args: argparse.Namespace) -> str:
    if args.tcpdump_filter is not None:
        return args.tcpdump_filter
    ports = merged_ports(args)
    if len(ports) == 1:
        port_filter = f"port {ports[0]}"
    else:
        port_filter = "(" + " or ".join(f"port {port}" for port in ports) + ")"
    if not args.peer_host:
        return port_filter
    return f"host {args.peer_host} and {port_filter}"


def validate_pcap(path: Path) -> Tuple[bool, str]:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        return False, f"packet capture unavailable: {exc}"
    valid_magic = {
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    }
    if size < 24 or magic not in valid_magic:
        return False, f"invalid or incomplete pcap: size={size} magic={magic.hex()}"
    return True, f"valid pcap: {size} bytes"


def main(argv: Optional[Sequence[str]] = None) -> int:
    STOP.clear()
    CHILDREN.clear()
    args = parse_args(argv)
    install_signal_handlers()

    out_dir: Path = args.out_dir or default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        out_dir.chmod(0o700)
    except OSError:
        pass
    recorder = EvidenceRecorder(out_dir)
    if args.reset_canaries:
        reset_errors = reset_canaries()
        if reset_errors:
            recorder.set_coverage("canary-reset", "gap", "; ".join(reset_errors))
            for error in reset_errors:
                recorder.record("warning", "canary-reset-failed", error)
        else:
            recorder.set_coverage("canary-reset", "ok", "known /tmp canaries removed")
    else:
        recorder.set_coverage("canary-reset", "disabled", "disabled by --no-reset-canaries")

    ports = merged_ports(args)
    resource_limits = ResourceLimits(
        rss_growth_kb=int(args.rss_growth_mb * 1024),
        fd_growth=args.fd_growth,
        thread_growth=args.thread_growth,
        consecutive=args.resource_consecutive,
    )
    roots = list(dict.fromkeys(list(DEFAULT_WATCH_ROOTS) + list(args.watch_root)))
    dicom_logs = resolve_dicom_logs(args.dicom_log, args.log_dir)
    since = args.since or dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open_log(out_dir / "run-info.log") as info:
        write_line(info, f"host={socket.gethostname()}")
        write_line(info, f"argv={' '.join(sys.argv)}")
        write_line(info, f"out_dir={out_dir}")
        write_line(info, f"ports={ports}")
        write_line(info, f"tcpdump_filter={resolved_tcpdump_filter(args)}")
        write_line(info, f"watch_roots={[str(root) for root in roots]}")
        write_line(info, f"dicom_logs={[str(path) for path in dicom_logs]}")
        write_line(info, f"resource_limits={resource_limits}")

    threads: List[threading.Thread] = []
    health_ready = threading.Event()
    for index, log_path in enumerate(dicom_logs):
        out_name = sanitize_log_name(str(log_path), index)
        threads.append(start_thread(follow_file, log_path, out_dir / out_name,
                                    args.from_start, args.interval, recorder))

    if not args.no_process:
        threads.append(start_thread(process_listener_monitor, out_dir / "process-listener.log",
                                    args.proc_re, ports, args.interval, resource_limits,
                                    recorder, health_ready))
    else:
        recorder.set_coverage("process-listener", "disabled", "disabled by --no-process")
        recorder.set_coverage("process-resources", "disabled", "disabled by --no-process")
        health_ready.set()

    if not args.no_filesystem:
        threads.append(start_thread(filesystem_monitor, out_dir / "filesystem-canaries.log",
                                    roots, [out_dir], args.max_depth, args.interval, recorder))
    else:
        recorder.set_coverage("filesystem-canaries", "disabled", "disabled by --no-filesystem")

    if not args.no_coredumpctl:
        threads.append(start_thread(coredump_monitor, out_dir / "coredumpctl.log",
                                    since, args.proc_re, args.coredump_interval, recorder))
    else:
        recorder.set_coverage("coredumps", "disabled", "disabled by --no-coredumpctl")

    if not args.no_dmesg:
        dmesg_thread = start_dmesg_monitor(out_dir / "kernel-events.log", args.proc_re, recorder)
        if dmesg_thread is not None:
            threads.append(dmesg_thread)
    else:
        recorder.set_coverage("kernel-events", "disabled", "disabled by --no-dmesg")

    if args.inotify:
        start_command("inotifywait", ["inotifywait", "-m", "-r", "-e",
                                      "create,close_write,moved_to,delete"]
                      + [str(root) for root in roots], out_dir / "inotify.log",
                      recorder, "inotify")
    else:
        recorder.set_coverage("inotify", "optional", "not requested")

    pcap_path = out_dir / "network.pcap"
    if args.tcpdump:
        with pcap_path.open("wb"):
            pass
        try:
            pcap_path.chmod(0o600)
        except OSError:
            pass
        start_command("tcpdump", tcpdump_argv(args, pcap_path),
                      out_dir / "tcpdump.log", recorder, "packet-capture")
    else:
        recorder.set_coverage("packet-capture", "disabled", "disabled by --no-tcpdump")

    readiness_timeout = max(5.0, args.interval * 3)
    if not health_ready.wait(readiness_timeout):
        detail = f"process/listener baseline did not complete within {readiness_timeout:g} seconds"
        recorder.set_coverage("process-listener", "gap", detail)
        recorder.record("warning", "health-baseline-timeout", detail)

    print(f"C-SCARE DUT monitor ready. Writing to: {out_dir}")
    message = "Press Ctrl-C to stop." if args.duration is None else f"Stopping after {args.duration} seconds."
    print(message)

    try:
        if args.duration is None:
            while not STOP.is_set():
                STOP.wait(1.0)
        else:
            STOP.wait(args.duration)
            STOP.set()
    finally:
        STOP.set()
        stop_children(recorder)
        for index, thread in enumerate(threads):
            thread.join(timeout=2)
            if thread.is_alive():
                detail = f"{thread.name} did not stop within 2 seconds"
                recorder.set_coverage(f"collector-thread-{index}", "gap", detail)
                recorder.record("warning", "collector-shutdown-timeout", detail)
    if args.tcpdump:
        valid_pcap, pcap_detail = validate_pcap(pcap_path)
        if recorder.coverage_status("packet-capture") != "unavailable":
            recorder.set_coverage(
                "packet-capture", "ok" if valid_pcap else "unavailable", pcap_detail
            )
        if not valid_pcap:
            recorder.record("warning", "packet-capture-invalid", pcap_detail)
        try:
            pcap_path.chmod(0o600)
        except OSError:
            pass
    summary = recorder.write_summary()
    print(f"C-SCARE DUT monitor stopped. Logs: {out_dir}")
    print(f"Security finding: {summary['security_finding']}; coverage: {summary['coverage']}")
    return 1 if args.fail_on_finding and summary["finding_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())