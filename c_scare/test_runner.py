# SPDX-License-Identifier: GPL-2.0-only
"""
C-SCARE CLI - DICOM security testing across the role x method matrix.

                   | black-box (DAST)         | grey-box (fuzzing)
  -----------------+--------------------------+---------------------------
  SCP  (server)    | c-scare [--category X]   | c-scare greybox ...
  SCU  (client)    | c-scare rogue ...        | (instrument the client)

Subcommands:
    rogue    - SCU/client fuzzing: run a rogue DICOM SCP that feeds
               malformed responses to a connecting client
    corpus   - generate a seed corpus (.dcm/.bin) for AFL++/AFLNet
    greybox  - grey-box bridge: launch an AFL++/AFLNet harness, or
               triage its crashes into a SARIF report

With no subcommand, C-SCARE runs in black-box DAST mode: it delivers the
static attack catalog at a live DICOM server (--ip/--port/--category).
The grey-box mutation loop itself is owned by AFL++/AFLNet (see scripts/).

Examples:
    c-scare --ip 127.0.0.1 --port 4242 --category cve
    c-scare corpus -o ./corpus
    c-scare rogue --port 11112 --mode malformed-ac
    c-scare greybox triage fuzz/out/file --binary dcm2pnm --arg @@ --sarif x.sarif
"""

import sys
import os
import argparse
import time
from typing import List, Optional
import tempfile

# Import attack modules
try:
    from .attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        CommandInjectionAttacks, StateMachineAttacks, CVEAttacks,
        ProtocolFuzzer, AttackResult, SCAPY_AVAILABLE
    )
    from . import deliver
    from .monitor import (
        BaseMonitor, MonitorReport, SanitizerMonitor,
        ProtocolMonitor, ProcessMonitor,
    )
    from .process_manager import InstrumentedProcess
except ImportError:
    from attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        CommandInjectionAttacks, StateMachineAttacks, CVEAttacks,
        ProtocolFuzzer, AttackResult, SCAPY_AVAILABLE
    )
    import deliver
    from monitor import (
        BaseMonitor, MonitorReport, SanitizerMonitor,
        ProtocolMonitor, ProcessMonitor,
    )
    from process_manager import InstrumentedProcess

__all__ = ['main', 'run_command', 'write_sarif']

SANITIZER_FLUSH_DELAY = 0.3


def _collect_results(args, results: list):
    """Append results to the shared collector if present."""
    collector = getattr(args, 'result_collector', None)
    if collector is not None:
        collector.extend(results)


def _get_monitors(args):
    """Get active monitors based on CLI args."""
    return getattr(args, '_monitors', [])


def _get_process(args):
    """Get managed process if one was started."""
    return getattr(args, '_managed_process', None)


def _run_monitored_test(args, result: AttackResult, target, timeout: float):
    """Send a payload and check all monitors for findings."""
    monitors = _get_monitors(args)
    if not monitors:
        return

    for i, monitor in enumerate(monitors):
        monitor.pre_test(i)

    response = deliver.send_pdu(target, result.payload, timeout=timeout)
    result.response = response

    error = None
    if response is None:
        error = 'timeout'

    for monitor in monitors:
        if isinstance(monitor, ProtocolMonitor):
            monitor.set_response(response, error=error)

    if any(isinstance(m, SanitizerMonitor) for m in monitors):
        time.sleep(SANITIZER_FLUSH_DELAY)

    for monitor in monitors:
        report = monitor.post_test()
        result.monitor_reports.append(report)
        if report.detected:
            result.success = True

    proc = _get_process(args)
    if proc and not proc.is_alive():
        proc.restart()
        time.sleep(0.5)


def write_sarif(results: list, filepath: str):
    """Write SARIF v2.1.0 report from AttackResult objects."""
    import json

    rules = {}
    sarif_results = []
    for r in results:
        rule_id = f"{r.category}/{r.name}"
        if rule_id not in rules:
            rule_def = {
                "id": rule_id,
                "shortDescription": {"text": r.name},
            }
            if r.cve:
                rule_def["helpUri"] = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={r.cve}"
            rules[rule_id] = rule_def

        if r.success is False:
            level = "error"
        elif r.success is True:
            level = "note"
        else:
            level = "warning"

        result_obj = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": r.description},
            "properties": {
                "category": r.category,
                "expected_behavior": r.expected_behavior,
            },
        }
        if r.cve:
            result_obj["properties"]["cve"] = r.cve
        detections = [rpt for rpt in r.monitor_reports if rpt.detected]
        if detections:
            result_obj["properties"]["monitors"] = [
                {
                    "finding_type": rpt.finding_type,
                    "description": rpt.description,
                    "evidence": rpt.evidence,
                }
                for rpt in detections
            ]
        sarif_results.append(result_obj)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "C-SCARE",
                        "informationUri": "https://github.com/tmart234/C-SCARE",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    with open(filepath, "w") as f:
        json.dump(sarif, f, indent=2)


def print_banner():
    """Print C-Scare banner."""
    banner = r"""
   ____        ____                       
  / ___|      / ___|  ___ __ _ _ __ ___  
 | |   _____ \___ \ / __/ _` | '__/ _ \ 
 | |__|_____|___) | (_| (_| | | |  __/ 
  \____|     |____/ \___\__,_|_|  \___|
                                        
    DICOM Security Testing Framework
    """
    print(banner)


def print_result(result: AttackResult, verbose: bool = False):
    """Print an attack result."""
    status = "✓" if result.success is True else ("✗" if result.success is False else "?")
    cve_tag = f" [{result.cve}]" if result.cve else ""

    detections = [r for r in result.monitor_reports if r.detected]
    if detections:
        detection_str = f" → {detections[0].finding_type}"
    else:
        detection_str = ""

    print(f"{status} {result.name}{cve_tag}{detection_str}")
    if verbose:
        print(f"  Category: {result.category}")
        print(f"  Description: {result.description}")
        print(f"  Expected: {result.expected_behavior}")
        if result.metadata:
            print(f"  Metadata: {result.metadata}")
        print(f"  Payload size: {len(result.payload)} bytes")
        if result.response:
            print(f"  Response size: {len(result.response)} bytes")
        for report in result.monitor_reports:
            if report.detected:
                print(f"  Monitor: {report.finding_type} - {report.description}")
                if report.evidence:
                    for line in report.evidence.split('\n')[:5]:
                        print(f"    {line}")
        print()


def run_cve_attacks(args) -> int:
    """Run CVE-specific attack reproductions."""
    print("\n=== CVE Attack Patterns ===\n")

    all_results = []
    for i, result in enumerate(CVEAttacks.all()):
        _maybe_deliver(args, result, i)
        print_result(result, args.verbose)
        all_results.append(result)

    print(f"\nTotal CVE test cases: {len(all_results)}")
    _collect_results(args, all_results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in all_results:
            filepath = _save_corpus_file(result, args.output)
            if args.verbose:
                print(f"Saved: {filepath}")

    return 0


def run_fuzz_packets(args) -> int:
    """Test fuzzed DIMSE packets."""
    if not SCAPY_AVAILABLE:
        print("⚠ Scapy not available - skipping fuzz packet tests")
        print("  (This is optional, install with: pip install scapy)")
        return 0  # Return success - Scapy is optional
    
    print("\n=== Fuzz Packet Tests ===\n")
    print("Testing: Fuzzed DIMSE packets with various malformations")
    print()
    
    # Try to import fuzz classes - they may not exist
    try:
        try:
            from .attacks import C_ECHO_RQ, C_STORE_RQ
            from scapy.packet import raw, fuzz
        except ImportError:
            from attacks import C_ECHO_RQ, C_STORE_RQ
            from scapy.packet import raw, fuzz
        
    except ImportError as e:
        print(f"ERROR: Could not import DIMSE classes: {e}")
        return 1
    
    count = args.count if hasattr(args, 'count') else 10
    results = []
    
    # Test 1: C_ECHO with various modifications
    print("1. C_ECHO_RQ with field variations")
    for i in range(min(5, count)):
        try:
            cmd = C_ECHO_RQ(message_id=i+1)
            
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_echo_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-ECHO-RQ test case #{i}",
                expected_behavior="Parser should handle malformed fields",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ Failed to create C_ECHO_RQ #{i}: {e}")
    
    # Test 2: C_STORE with variations
    print("\n2. C_STORE_RQ with field variations")
    for i in range(min(5, count)):
        try:
            cmd = C_STORE_RQ(
                    affected_sop_class_uid='1.2.840.10008.5.1.4.1.1.2',
                    affected_sop_instance_uid=f'1.2.3.4.5.6.{i}',
                    message_id=i+1
                )
            
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_store_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-STORE-RQ test case #{i}",
                expected_behavior="Parser should handle variations",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ Failed to create C_STORE_RQ #{i}: {e}")
    
    # Test 3: Generic Scapy fuzz()
    print("\n3. Generic Scapy fuzz()")
    for i in range(min(5, count)):
        try:
            cmd = fuzz(C_ECHO_RQ())
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_echo_scapy_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-ECHO-RQ with Scapy fuzz() #{i}",
                expected_behavior="Parser should handle malformed fields",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ Failed to create fuzzed C_ECHO_RQ #{i}: {e}")
    
    print(f"\nTotal fuzz test cases: {len(results)}")
    _collect_results(args, results)

    # Save if output dir specified
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filename = f"{result.name}.bin"
            filepath = os.path.join(args.output, filename)
            with open(filepath, 'wb') as f:
                f.write(result.payload)
            if args.verbose:
                print(f"Saved: {filepath}")
    
    return 0


def run_protocol_fuzzing(args) -> int:
    """Run live protocol fuzzing against a target."""
    if not SCAPY_AVAILABLE:
        print("⚠ Scapy not available - skipping protocol fuzzing tests")
        print("  (This is optional, install with: pip install scapy)")
        return 0

    if not args.target:
        print("ERROR: --target required (format: host:port)")
        return 1

    print("\n=== Live Protocol Fuzzing ===\n")

    try:
        host, port = args.target.rsplit(':', 1)
        port = int(port)
        target = (host, port)
    except ValueError:
        print(f"ERROR: Invalid target format: {args.target}")
        print("Expected format: host:port (e.g., 192.168.1.100:11112)")
        return 1

    print(f"Target: {host}:{port}")
    print(f"Running {args.count} fuzzed A-ASSOCIATE-RQ packets against server")
    print()

    try:
        interesting_count = 0
        monitors = _get_monitors(args)
        all_results = []

        for i, result in enumerate(ProtocolFuzzer.fuzz_association(count=args.count)):
            if not result.payload:
                print(f"✗ #{i+1}: {result.description}")
                continue

            if monitors:
                _run_monitored_test(args, result, target, args.timeout)
                detected = any(r.detected for r in result.monitor_reports)
                status = "!" if detected else "✓"
                print(f"{status} #{i+1}: {result.name}")
                if detected:
                    interesting_count += 1
                    if args.verbose:
                        for report in result.monitor_reports:
                            if report.detected:
                                print(f"  Monitor: {report.finding_type} - {report.description}")
            else:
                response = deliver.send_pdu(target, result.payload, timeout=args.timeout)
                interesting = (
                    response is None or
                    len(response) == 0 or
                    (response and response[0] not in (0x02, 0x03, 0x07))
                )
                status = "!" if interesting else "✓"
                print(f"{status} #{i+1}: {result.name}")
                if interesting:
                    interesting_count += 1
                    if args.verbose:
                        print(f"  Mutation: {result.metadata.get('mutation')}")
                        if response:
                            print(f"  Response: {len(response)} bytes")
                        else:
                            print(f"  Response: None (timeout or connection closed)")

            all_results.append(result)

        print(f"\nInteresting results: {interesting_count}/{args.count}")
        _collect_results(args, all_results)

    except Exception as e:
        print(f"ERROR: Fuzzing failed: {e}")
        return 1

    return 0


def _save_corpus_file(result: AttackResult, output_dir: str) -> str:
    """Save an AttackResult payload as a corpus file, return the path."""
    # Protocol-level payloads use .bin, dataset payloads use .dcm
    if result.category in ('protocol', 'state_machine', 'fuzzer'):
        ext = '.bin'
        file_data = result.payload
    else:
        ext = '.dcm'
        payload = result.payload or b''
        # A payload already carrying the Part 10 magic — a raw file (DICM at
        # offset 0) or a complete file with a 128-byte preamble (DICM at
        # offset 128, e.g. the CVE-2019-11687 polyglots) — must be written
        # verbatim. Re-wrapping a polyglot buries its executable preamble at
        # offset 132 and destroys the seed.
        if payload.startswith(b'DICM') or payload[128:132] == b'DICM':
            file_data = payload
        else:
            file_data = b'\x00' * 128 + b'DICM' + payload

    filepath = os.path.join(output_dir, f"{result.name}{ext}")
    with open(filepath, 'wb') as f:
        f.write(file_data)
    return filepath


def run_generate_corpus(args) -> int:
    """Generate fuzzing corpus files."""
    print("\n=== Generating Fuzzing Corpus ===\n")

    output_dir = args.output or tempfile.mkdtemp(prefix='c_scare_corpus_')
    os.makedirs(output_dir, exist_ok=True)

    print(f"Output directory: {output_dir}")
    print(f"Generating test cases...")
    print()

    categories = [
        ('Parser attacks', ParserAttacks),
        ('Memory attacks', MemoryAttacks),
        ('Logic attacks', LogicAttacks),
        ('Command injection attacks', CommandInjectionAttacks),
        ('CVE attacks', CVEAttacks),
        ('Protocol attacks', ProtocolAttacks),
        ('State machine attacks', StateMachineAttacks),
    ]

    results = []
    for label, cls in categories:
        print(f"{label}...")
        for result in cls.all():
            try:
                filepath = _save_corpus_file(result, output_dir)
                filesize = len(result.payload)
                print(f"  {os.path.basename(filepath):30s} {filesize:>8} bytes  {result.description}")
                results.append(result)
            except Exception as e:
                print(f"  ✗ {result.name:30s}  SKIPPED  {e}")

    print(f"\nCorpus saved to: {output_dir}")
    print(f"Total files: {len(results)}")

    return 0


def _maybe_deliver(args, result: AttackResult, index: int):
    """If monitors are active, deliver the payload and run monitors."""
    monitors = _get_monitors(args)
    if not monitors:
        return
    try:
        host, port = args.target.rsplit(':', 1)
        target = (host, int(port))
    except (ValueError, AttributeError):
        return
    _run_monitored_test(args, result, target, args.timeout)


def run_parser_attacks(args) -> int:
    """Run parser attack tests."""
    print("\n=== Parser Attacks ===\n")

    results = []
    for i, result in enumerate(ParserAttacks.all()):
        try:
            _maybe_deliver(args, result, i)
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal parser attack tests: {len(results)}")
    _collect_results(args, results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filepath = os.path.join(args.output, f"{result.name}.dcm")
            file_data = b'\x00' * 128 + b'DICM' + result.payload
            with open(filepath, 'wb') as f:
                f.write(file_data)

    return 0


def run_protocol_attacks(args) -> int:
    """Run protocol-level attack tests."""
    print("\n=== Protocol Attacks ===\n")

    results = []
    for i, result in enumerate(ProtocolAttacks.all()):
        try:
            _maybe_deliver(args, result, i)
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal protocol attack tests: {len(results)}")
    _collect_results(args, results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filepath = os.path.join(args.output, f"{result.name}.bin")
            with open(filepath, 'wb') as f:
                f.write(result.payload)

    return 0


def run_logic_attacks(args) -> int:
    """Run logic attack tests."""
    print("\n=== Logic Attacks ===\n")

    results = []
    for i, result in enumerate(LogicAttacks.all()):
        try:
            _maybe_deliver(args, result, i)
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal logic attack tests: {len(results)}")
    _collect_results(args, results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filepath = os.path.join(args.output, f"{result.name}.dcm")
            if not result.payload.startswith(b'DICM'):
                file_data = b'\x00' * 128 + b'DICM' + result.payload
            else:
                file_data = result.payload
            with open(filepath, 'wb') as f:
                f.write(file_data)
    
    return 0


def run_command_injection_attacks(args) -> int:
    """Run command-injection attack tests (storescp exec placeholders)."""
    print("\n=== Command Injection Attacks ===\n")

    results = []
    for i, result in enumerate(CommandInjectionAttacks.all()):
        try:
            _maybe_deliver(args, result, i)
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal command injection attack tests: {len(results)}")
    print("Note: confirming RCE needs a live storescp started with "
          "--exec-on-reception and a C-STORE (see deliver.send_cstore).")
    _collect_results(args, results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filepath = os.path.join(args.output, f"{result.name}.dcm")
            file_data = b'\x00' * 128 + b'DICM' + result.payload
            with open(filepath, 'wb') as f:
                f.write(file_data)

    return 0


def run_state_machine_attacks(args) -> int:
    """Run state machine attack tests."""
    if not args.target:
        print("ERROR: --target required for state machine attacks (format: host:port)")
        print("Example: python -m c_scare state_machine_attacks --target 127.0.0.1:4242")
        return 1

    print("\n=== State Machine Attacks ===\n")

    try:
        host, port = args.target.rsplit(':', 1)
        port = int(port)
        target = (host, port)
    except ValueError:
        print(f"ERROR: Invalid target format: {args.target}")
        print("Expected format: host:port (e.g., 192.168.1.100:11112)")
        return 1

    print(f"Target: {host}:{port}")
    print()

    results = []
    monitors = _get_monitors(args)

    for i, result in enumerate(StateMachineAttacks.all()):
        try:
            if monitors:
                for monitor in monitors:
                    monitor.pre_test(i)

            steps = result.metadata.get('steps')
            if steps:
                responses = deliver.send_sequence(target, steps, timeout=args.timeout)
                result.response = responses[-1] if responses else None
            else:
                result.response = deliver.send_pdu(target, result.payload, timeout=args.timeout)

            if monitors:
                for monitor in monitors:
                    if isinstance(monitor, ProtocolMonitor):
                        monitor.set_response(result.response)
                if any(isinstance(m, SanitizerMonitor) for m in monitors):
                    time.sleep(SANITIZER_FLUSH_DELAY)
                for monitor in monitors:
                    report = monitor.post_test()
                    result.monitor_reports.append(report)
                    if report.detected:
                        result.success = True
                proc = _get_process(args)
                if proc and not proc.is_alive():
                    proc.restart()
                    time.sleep(0.5)
            else:
                result.success = True
        except Exception as e:
            result.success = False
            result.description = f'Failed: {e}'

        print_result(result, args.verbose)
        results.append(result)

    print(f"\nTotal state machine attack tests: {len(results)}")
    _collect_results(args, results)
    return 0


def run_memory_attacks(args) -> int:
    """Run memory corruption attack tests."""
    print("\n=== Memory Attacks ===\n")

    results = []
    for i, result in enumerate(MemoryAttacks.all()):
        try:
            _maybe_deliver(args, result, i)
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal memory attack tests: {len(results)}")
    _collect_results(args, results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filepath = os.path.join(args.output, f"{result.name}.dcm")
            if not result.payload.startswith(b'DICM'):
                file_data = b'\x00' * 128 + b'DICM' + result.payload
            else:
                file_data = result.payload
            with open(filepath, 'wb') as f:
                f.write(file_data)

    return 0


def run_all_tests(args) -> int:
    """Run all tests."""
    print_banner()
    
    # Run each test suite
    commands = [
        ('CVE Attacks', run_cve_attacks),
        ('Parser Attacks', run_parser_attacks),
        ('Protocol Attacks', run_protocol_attacks),
        ('Memory Attacks', run_memory_attacks),
        ('Logic Attacks', run_logic_attacks),
        ('Command Injection Attacks', run_command_injection_attacks),
        ('Fuzz Packets', run_fuzz_packets),
    ]
    
    results = {}
    for name, func in commands:
        print(f"\n{'='*60}")
        print(f"Running: {name}")
        print('='*60)
        try:
            ret = func(args)
            results[name] = 'PASS' if ret == 0 else 'FAIL'
        except Exception as e:
            print(f"\nERROR in {name}: {e}")
            results[name] = 'ERROR'
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print('='*60)
    for name, status in results.items():
        symbol = '✓' if status == 'PASS' else '✗'
        print(f"{symbol} {name}: {status}")
    
    return 0


def run_command(command: str, args) -> int:
    """Run a specific command."""
    commands = {
        'cve_attacks': run_cve_attacks,
        'fuzz_packets': run_fuzz_packets,
        'protocol_fuzzing': run_protocol_fuzzing,
        'protocol_attacks': run_protocol_attacks,
        'generate_corpus': run_generate_corpus,
        'parser_attacks': run_parser_attacks,
        'memory_attacks': run_memory_attacks,
        'logic_attacks': run_logic_attacks,
        'command_injection_attacks': run_command_injection_attacks,
        'state_machine_attacks': run_state_machine_attacks,
        'all': run_all_tests,
    }
    
    if command not in commands:
        print(f"ERROR: Unknown command: {command}")
        print(f"Available commands: {', '.join(commands.keys())}")
        return 1
    
    return commands[command](args)


def _cmd_corpus(argv: List[str]) -> int:
    """`corpus` subcommand: generate a seed corpus for AFL++/AFLNet."""
    p = argparse.ArgumentParser(
        prog='c-scare corpus',
        description='Generate a seed corpus (.dcm/.bin) for AFL++/AFLNet.')
    p.add_argument('-o', '--out', required=True, help='output directory')
    a = p.parse_args(argv)
    return run_generate_corpus(argparse.Namespace(output=a.out))


def _cmd_rogue(argv: List[str]) -> int:
    """`rogue` subcommand: SCU/client fuzzing via a rogue DICOM SCP."""
    p = argparse.ArgumentParser(
        prog='c-scare rogue',
        description='Run a rogue DICOM SCP that feeds malformed responses '
                    'to a connecting DICOM client (SCU/client fuzzing).')
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=11112)
    p.add_argument('--ae-title', dest='ae_title', default='C_SCARE')
    p.add_argument('--mode', choices=['malformed-ac', 'reject', 'abort'],
                   default='malformed-ac',
                   help='response sent on A-ASSOCIATE-RQ (default: malformed-ac)')
    a = p.parse_args(argv)

    from .server import RawSCP
    try:
        from .scapy_dicom import DICOM, A_ASSOCIATE_AC, A_ASSOCIATE_RJ, A_ABORT
        from scapy.packet import raw
    except Exception as e:  # pragma: no cover - scapy is a hard dependency
        print(f"ERROR: rogue server requires scapy: {e}")
        return 1

    def _response() -> bytes:
        if a.mode == 'reject':
            return raw(DICOM() / A_ASSOCIATE_RJ())
        if a.mode == 'abort':
            return raw(DICOM() / A_ABORT())
        return raw(DICOM() / A_ASSOCIATE_AC(protocol_version=0xFFFF))

    scp = RawSCP(host=a.host, port=a.port, ae_title=a.ae_title)

    @scp.on_connect
    def _on_connect(conn):
        print(f"[rogue] client connected: {conn.address}")

    @scp.on_associate_rq
    def _on_assoc(conn, pdu_bytes, pkt):
        print(f"[rogue] A-ASSOCIATE-RQ ({len(pdu_bytes)} bytes) -> {a.mode}")
        return _response()

    @scp.on_pdata
    def _on_pdata(conn, pdu_bytes, pkt):
        print(f"[rogue] P-DATA-TF ({len(pdu_bytes)} bytes)")
        return None

    print(f"[rogue] mode={a.mode}  listening on {a.host}:{a.port}  (Ctrl-C to stop)")
    try:
        scp.start()
    except KeyboardInterrupt:
        print("\n[rogue] stopping")
        scp.stop()
    return 0


def _cmd_greybox(argv: List[str]) -> int:
    """`greybox` subcommand: AFL++/AFLNet harness launch + crash triage."""
    from . import greybox

    p = argparse.ArgumentParser(
        prog='c-scare greybox',
        description='Grey-box bridge to the AFL++/AFLNet fuzzing engines.')
    sub = p.add_subparsers(dest='gbcmd', required=True)

    runp = sub.add_parser('run', help='launch an AFL++/AFLNet fuzz harness')
    runp.add_argument('target', choices=sorted(greybox.TARGETS))

    trp = sub.add_parser('triage', help='triage AFL/AFLNet crashes into SARIF')
    trp.add_argument('crashes', help='AFL/AFLNet output directory or crashes dir')
    trp.add_argument('--binary',
                     help='instrumented binary to replay crashes through')
    trp.add_argument('--arg', action='append', default=[], dest='args',
                     help='binary argument; use @@ for the crash file path')
    trp.add_argument('--sarif', help='write a SARIF v2.1.0 report here')
    trp.add_argument('--timeout', type=float, default=10.0)
    a = p.parse_args(argv)

    if a.gbcmd == 'run':
        return greybox.run(a.target)

    cmd = ([a.binary] + a.args) if a.binary else None
    results = greybox.triage_to_sarif(
        a.crashes, cmd=cmd, sarif_path=a.sarif, timeout=a.timeout)
    detected = sum(1 for r in results if r.success)
    print(f"\nTriaged {len(results)} crash input(s); "
          f"{detected} reproduced a sanitizer/crash finding")
    for r in results:
        mark = '!' if r.success else ('.' if cmd else '?')
        print(f"  {mark} {r.name} ({r.metadata.get('size', 0)} bytes)")
        for report in r.monitor_reports:
            print(f"      {report.finding_type}: {report.description}")
    if a.sarif:
        print(f"\nSARIF report written to: {a.sarif}")
    return 0


def main(argv: Optional[List[str]] = None):
    """Main entry point."""
    if argv is None:
        argv = sys.argv[1:]

    # Matrix subcommands. With no subcommand, fall through to black-box DAST
    # mode (the --ip/--port/--category flag interface below).
    if argv and argv[0] in ('rogue', 'corpus', 'greybox', 'dast'):
        sub = argv[0]
        if sub == 'rogue':
            return _cmd_rogue(argv[1:])
        if sub == 'corpus':
            return _cmd_corpus(argv[1:])
        if sub == 'greybox':
            return _cmd_greybox(argv[1:])
        argv = argv[1:]  # 'dast' is the default mode: strip and continue

    parser = argparse.ArgumentParser(
        description='C-Scare DICOM Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Connection parameters (matching GitHub Actions workflow)
    parser.add_argument(
        '--ip',
        default='127.0.0.1',
        help='Target IP address (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=11112,
        help='Target port (default: 11112)'
    )
    
    parser.add_argument(
        '--ae-title',
        dest='ae_title',
        default='ANY-SCP',
        help='Called AE title (default: ANY-SCP)'
    )
    
    # Test selection
    parser.add_argument(
        '--category',
        choices=['parser', 'protocol', 'memory', 'logic', 'command_injection',
                 'state_machine', 'cve', 'fuzz_packet', 'live_fuzz', 'all'],
        help='Test category to run (if not specified, runs all)'
    )
    
    # Additional options
    parser.add_argument(
        '-o', '--output',
        help='Output directory for generated files'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=10.0,
        help='Timeout for network operations (default: 10.0)'
    )
    
    parser.add_argument(
        '--live-fuzz-count',
        type=int,
        default=10,
        help='Number of live fuzz iterations (default: 10)'
    )
    
    parser.add_argument(
        '--generate-corpus',
        metavar='DIR',
        help='Generate fuzzing corpus in specified directory'
    )

    parser.add_argument(
        '--sarif',
        metavar='FILE',
        help='Write SARIF v2.1.0 report to file'
    )

    parser.add_argument(
        '--asan-binary',
        metavar='PATH',
        help='Path to ASan-instrumented target binary (e.g., storescp compiled with -fsanitize=address,undefined). '
             'Enables SanitizerMonitor + ProcessMonitor + ProtocolMonitor for per-test detection.'
    )

    parser.add_argument(
        '--asan-port',
        type=int,
        default=None,
        help='Port for ASan-instrumented binary (default: same as --port)'
    )

    args = parser.parse_args(argv)

    # Build target string
    args.target = f"{args.ip}:{args.port}"
    args.count = args.live_fuzz_count

    # Map category to command
    category_map = {
        'parser': 'parser_attacks',
        'protocol': 'protocol_attacks',
        'memory': 'memory_attacks',
        'logic': 'logic_attacks',
        'command_injection': 'command_injection_attacks',
        'state_machine': 'state_machine_attacks',
        'cve': 'cve_attacks',
        'fuzz_packet': 'fuzz_packets',
        'live_fuzz': 'protocol_fuzzing',
        'all': 'all',
    }

    # Handle corpus generation
    if args.generate_corpus:
        args.output = args.generate_corpus
        return run_command('generate_corpus', args)

    # Determine command from category
    if args.category:
        command = category_map.get(args.category, 'all')
    else:
        command = 'all'

    # Set up result collector for JUnit XML output
    args.result_collector = []

    # Set up monitors if --asan-binary is specified
    args._monitors = []
    args._managed_process = None

    if args.asan_binary:
        asan_port = args.asan_port or args.port
        cmd = [args.asan_binary, str(asan_port)]
        proc = InstrumentedProcess(cmd)
        proc.start()
        time.sleep(1.0)

        if not proc.is_alive():
            log = proc.get_full_log()
            print(f"ERROR: ASan binary failed to start: {log[:500]}")
            return 1

        args._managed_process = proc
        args._monitors = [
            SanitizerMonitor(proc),
            ProcessMonitor(proc),
            ProtocolMonitor(),
        ]
        args.target = f"{args.ip}:{asan_port}"
        print(f"Monitors: SanitizerMonitor, ProcessMonitor, ProtocolMonitor")
        print(f"Target: {args.target} (ASan-instrumented)")
        print()

    try:
        ret = run_command(command, args)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        ret = 130
    except Exception as e:
        print(f"\nERROR: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        ret = 1
    finally:
        if args._managed_process:
            args._managed_process.stop()
            for monitor in args._monitors:
                monitor.teardown()

    # Print monitor summary
    if args._monitors and args.result_collector:
        detected_count = sum(
            1 for r in args.result_collector
            if any(rpt.detected for rpt in r.monitor_reports)
        )
        total = len(args.result_collector)
        print(f"\n{'='*50}")
        print(f"Monitor Summary: {detected_count}/{total} tests triggered detections")
        print(f"{'='*50}")

    if args.sarif and args.result_collector:
        write_sarif(args.result_collector, args.sarif)
        print(f"\nSARIF report written to: {args.sarif}")

    return ret


if __name__ == '__main__':
    sys.exit(main())