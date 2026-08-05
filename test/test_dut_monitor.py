# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the standalone DUT evidence collector."""

import importlib.util
import json
from pathlib import Path
import re


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "dut_monitor.py"
SPEC = importlib.util.spec_from_file_location("dut_monitor", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
dut_monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dut_monitor)


def test_defaults_are_device_agnostic():
    """No default may name a specific product's paths, service, or network."""
    args = dut_monitor.parse_args([])

    assert args.dicom_log is None
    assert args.log_dir == []
    assert args.watch_root == []
    assert args.peer_host is None
    assert args.storage_port == 104
    assert args.reset_canaries is True
    assert args.tcpdump is True
    assert args.tcpdump_snaplen == 256
    assert args.tcpdump_filter is None
    # Without a --peer-host the filter must not invent one.
    assert dut_monitor.resolved_tcpdump_filter(args) == "port 104"
    assert dut_monitor.merged_ports(args) == [104]

    command = dut_monitor.tcpdump_argv(args, Path("network.pcap"))
    assert command == [
        "tcpdump", "-i", "any", "-nn", "-s", "256", "-U", "-w", "network.pcap",
        "port", "104",
    ]

    full_capture = dut_monitor.parse_args(["--tcpdump-snaplen", "0"])
    assert dut_monitor.tcpdump_argv(full_capture, Path("network.pcap"))[5] == "0"


def test_peer_host_narrows_the_capture_filter():
    args = dut_monitor.parse_args(["--peer-host", "192.0.2.50", "--qr-port", "105"])
    assert dut_monitor.resolved_tcpdump_filter(args) == (
        "host 192.0.2.50 and (port 104 or port 105)")


def test_dicom_logs_come_from_flags_not_baked_in_paths(tmp_path):
    assert dut_monitor.resolve_dicom_logs(None) == []

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "service.log").write_text("")
    (log_dir / "bridge.log").write_text("")
    (log_dir / "ignored.txt").write_text("")
    explicit = tmp_path / "extra.log"
    explicit.write_text("")

    logs = dut_monitor.resolve_dicom_logs([explicit], [log_dir, tmp_path / "missing"])
    assert logs == [explicit, log_dir / "bridge.log", log_dir / "service.log"]


def test_kernel_filter_rejects_general_noise():
    target = re.compile(r"(?:^|/|\()dicomd(?:\s|\[|\)|$)", re.IGNORECASE)

    assert dut_monitor.DMESG_ARGV == ("dmesg", "--follow-new", "--human")
    assert not dut_monitor.relevant_kernel_line(
        "usb 2-1: device descriptor read/64, error -71", target
    )
    assert not dut_monitor.relevant_kernel_line(
        "unrelatedService[44]: segfault at 0 ip 0", target
    )
    assert dut_monitor.relevant_kernel_line(
        "dicomd[1234]: segfault at 0 ip 0", target
    )
    assert dut_monitor.relevant_kernel_line(
        "Out of memory: Killed process 1234 (dicomd)", target
    )
    assert dut_monitor.relevant_kernel_line(
        "Kernel panic - not syncing: fatal exception", target
    )


def test_default_process_regex_matches_common_dicom_scps():
    regex = re.compile(dut_monitor.DEFAULT_PROC_RE, re.IGNORECASE)
    for cmdline in ("/usr/bin/storescp 104", "/opt/dcmtk/bin/dcmrecv 104",
                    "dcmqrscp -c qr.cfg 104", "/usr/sbin/orthanc /etc/orthanc"):
        assert regex.search(cmdline), cmdline
    assert not regex.search("/usr/bin/sshd -D")


def test_application_filter_uses_crash_class_signals_only():
    assert dut_monitor.application_failure_signature("ERROR invalid VR rejected") is None
    assert dut_monitor.application_failure_signature("WARN malformed association aborted") is None
    assert dut_monitor.application_failure_signature(
        "[ERROR][dicom][Unable to add Presentation context for C-STORE: Normal]"
    ) is None
    assert dut_monitor.application_failure_signature("terminate called after std::bad_alloc")
    assert dut_monitor.application_failure_signature("AddressSanitizer: heap-use-after-free")


def test_application_activity_matches_common_log_phrasings():
    """Reachability evidence must not depend on one product's wording."""
    assert dut_monitor.application_activity_signature(
        "2026-07-21 INFO: Association Received 192.0.2.50:  ->"
    ) == ("association-received", "192.0.2.50")
    assert dut_monitor.application_activity_signature(
        "I: Association Request accepted from AE C-SCARE"
    )[0] == "association-received"
    assert dut_monitor.application_activity_signature(
        "[INFO][dicom][Association has ended, checking import into DB]"
    ) == ("association-ended", None)
    assert dut_monitor.application_activity_signature(
        "I: association released"
    ) == ("association-ended", None)
    assert dut_monitor.application_activity_signature(
        "I: started listening on port 104"
    ) == ("listener-started", None)
    assert dut_monitor.application_activity_signature("routine status line") is None


def test_activity_pattern_flag_extends_the_built_in_set():
    original = list(dut_monitor.ACTIVITY_PATTERNS)
    try:
        dut_monitor.parse_args(["--activity-pattern", "custom=DICOM-XYZ ready"])
        assert dut_monitor.application_activity_signature(
            "vendor log: DICOM-XYZ ready"
        ) == ("custom", None)
    finally:
        dut_monitor.ACTIVITY_PATTERNS[:] = original


def test_monitor_process_is_excluded_from_target_matches():
    processes = [
        (10, "python dut_monitor.py --dicom-log /var/log/dicom/service.log"),
        (20, "/usr/bin/storescp 104"),
        (30, "python helper.py /usr/bin/storescp 104"),
    ]
    regex = re.compile(dut_monitor.DEFAULT_PROC_RE, re.IGNORECASE)

    assert dut_monitor.matching_processes(processes, regex, {10}) == {
        20: "/usr/bin/storescp 104"
    }


def test_process_resource_sampling_and_deltas(tmp_path):
    process_root = tmp_path / "4242"
    process_root.mkdir()
    (process_root / "status").write_text(
        "Name:\tstorescp\nVmRSS:\t204800 kB\nThreads:\t12\n",
        encoding="ascii",
    )
    fd_root = process_root / "fd"
    fd_root.mkdir()
    for descriptor in range(7):
        (fd_root / str(descriptor)).touch()

    baseline = dut_monitor.read_process_resources(4242, tmp_path)
    assert baseline == dut_monitor.ProcessResources(204800, 7, 12)
    current = dut_monitor.ProcessResources(337920, 72, 45)
    assert dut_monitor.resource_deltas(current, baseline) == {
        "rss_kb": 133120,
        "fd_count": 65,
        "thread_count": 33,
    }


def test_resource_tracker_requires_persistent_growth(tmp_path, monkeypatch):
    samples = iter([
        dut_monitor.ProcessResources(1000, 10, 2),
        dut_monitor.ProcessResources(1200, 16, 5),
        dut_monitor.ProcessResources(1200, 16, 5),
    ])
    monkeypatch.setattr(dut_monitor, "read_process_resources", lambda _pid: next(samples))
    recorder = dut_monitor.EvidenceRecorder(tmp_path)
    limits = dut_monitor.ResourceLimits(
        rss_growth_kb=200,
        fd_growth=6,
        thread_growth=3,
        consecutive=2,
    )
    with dut_monitor.ResourceTracker(tmp_path / "process-resources.csv", limits, recorder) as tracker:
        tracker.sample_processes({42: "storescp"})
        tracker.sample_processes({42: "storescp"})
        assert recorder.build_summary()["finding_count"] == 0
        tracker.sample_processes({42: "storescp"})

    finding_types = {event["kind"] for event in recorder.build_summary()["findings"]}
    assert finding_types == {
        "resource:rss-growth", "resource:fd-growth", "resource:thread-growth"
    }
    assert (tmp_path / "process-resources.csv").read_text(encoding="utf-8").count("\n") == 4


def test_partial_resource_sampling_reduces_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(
        dut_monitor,
        "read_process_resources",
        lambda _pid: dut_monitor.ProcessResources(1000, None, 2),
    )
    recorder = dut_monitor.EvidenceRecorder(tmp_path)
    limits = dut_monitor.ResourceLimits(0, 0, 0, 1)
    with dut_monitor.ResourceTracker(tmp_path / "partial.csv", limits, recorder) as tracker:
        tracker.sample_processes({42: "storescp"})

    assert recorder.coverage_status("process-resources") == "gap"


def test_canary_scan_excludes_monitor_output(tmp_path):
    dut_monitor.STOP.clear()
    canary = tmp_path / "c-scare-rce"
    canary.write_text("proof", encoding="ascii")
    output_dir = tmp_path / "c-scare-monitor-20260721"
    output_dir.mkdir()
    (output_dir / "c-scare-traversal").write_text("not a finding", encoding="ascii")
    previous_output = tmp_path / "c-scare-monitor-previous"
    previous_output.mkdir()

    found = set(dut_monitor.walk_limited(tmp_path, 5, [output_dir]))

    assert found == {canary}


def test_pcap_validation(tmp_path):
    pcap = tmp_path / "network.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    assert dut_monitor.validate_pcap(pcap)[0] is True

    pcap.write_bytes(b"not a pcap")
    valid, detail = dut_monitor.validate_pcap(pcap)
    assert valid is False
    assert "invalid or incomplete pcap" in detail


def test_evidence_summary_distinguishes_findings_and_gaps(tmp_path):
    recorder = dut_monitor.EvidenceRecorder(tmp_path)
    recorder.set_coverage("inotify", "optional", "not requested")
    clean = recorder.build_summary()
    assert clean["security_finding"] == "NONE_DETECTED"
    assert clean["dut_observed_impact"] == "NONE"
    assert clean["coverage"] == "FULL"

    recorder.set_coverage("packet-capture", "unavailable", "tcpdump not found")
    recorder.record("warning", "packet-capture-unavailable", "tcpdump not found")
    recorder.record("finding", "listener-lost", "DICOM listener port 104 stopped listening")
    finding = recorder.write_summary()

    assert finding["security_finding"] == "DETECTED"
    assert finding["dut_observed_impact"] == "FAIL"
    assert finding["coverage"] == "REDUCED"
    assert (tmp_path / "summary.json").is_file()
    assert (tmp_path / "summary.txt").is_file()
    sarif = json.loads((tmp_path / "dut-monitor.sarif").read_text(encoding="utf-8"))
    levels = {
        result["ruleId"]: result["level"]
        for result in sarif["runs"][0]["results"]
    }
    assert levels == {
        "dut/listener-lost": "error",
        "dut/packet-capture-unavailable": "warning",
    }


def test_canary_finding_sets_automation_exit_code(tmp_path, monkeypatch):
    monkeypatch.setattr(dut_monitor, "install_signal_handlers", lambda: None)
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "c-scare-rce").write_text("proof", encoding="ascii")
    out_dir = tmp_path / "evidence"

    returncode = dut_monitor.main([
        "--out-dir", str(out_dir),
        "--duration", "0.2",
        "--interval", "0.01",
        "--max-depth", "2",
        "--watch-root", str(watched),
        "--dicom-log", str(tmp_path / "missing.log"),
        "--no-reset-canaries",
        "--no-process",
        "--no-coredumpctl",
        "--no-dmesg",
        "--no-tcpdump",
        "--fail-on-finding",
    ])

    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert returncode == 1
    assert summary["security_finding"] == "DETECTED"
    assert summary["dut_observed_impact"] == "FAIL"
    canary = next(event for event in summary["findings"] if event["kind"] == "filesystem-canary")
    assert canary["properties"]["path"] == str(watched / "c-scare-rce")
    assert canary["properties"]["mtime_epoch_ns"] > 0
    assert "mtime=" in canary["message"]

    sarif = json.loads((out_dir / "dut-monitor.sarif").read_text(encoding="utf-8"))
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["path"] == str(watched / "c-scare-rce")
    assert result["properties"]["mtime_epoch_ns"] == canary["properties"]["mtime_epoch_ns"]