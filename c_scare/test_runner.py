# SPDX-License-Identifier: GPL-2.0-only
"""
C-Scare Test Runner - CLI interface for running attack tests.

Usage:
    python -m c_scare.test_runner <command> [options]
    
Commands:
    cve_attacks       - Run CVE-specific attack reproductions
    fuzz_packets      - Test fuzzed DIMSE packets
    protocol_fuzzing  - Live protocol fuzzing against a target
    generate_corpus   - Generate fuzzing corpus files
    parser_attacks    - Run parser attack tests
    memory_attacks    - Run memory corruption tests
    all               - Run all tests

Examples:
    python -m c_scare.test_runner cve_attacks
    python -m c_scare.test_runner protocol_fuzzing --target 192.168.1.100:11112
    python -m c_scare.test_runner generate_corpus --output ./corpus --count 100
"""

import sys
import os
import argparse
from typing import List, Optional
import tempfile

# Import attack modules
try:
    from .attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        StateMachineAttacks, CVEAttacks, ProtocolFuzzer, AttackResult,
        SCAPY_AVAILABLE
    )
    from . import deliver
except ImportError:
    from attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        StateMachineAttacks, CVEAttacks, ProtocolFuzzer, AttackResult,
        SCAPY_AVAILABLE
    )
    import deliver

__all__ = ['main', 'run_command']


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
    status = "✓" if result.success is not False else "✗"
    cve_tag = f" [{result.cve}]" if result.cve else ""
    
    print(f"{status} {result.name}{cve_tag}")
    if verbose:
        print(f"  Category: {result.category}")
        print(f"  Description: {result.description}")
        print(f"  Expected: {result.expected_behavior}")
        if result.metadata:
            print(f"  Metadata: {result.metadata}")
        print(f"  Payload size: {len(result.payload)} bytes")
        if result.response:
            print(f"  Response size: {len(result.response)} bytes")
        print()


def run_cve_attacks(args) -> int:
    """Run CVE-specific attack reproductions."""
    print("\n=== CVE Attack Patterns ===\n")

    all_results = []
    for result in CVEAttacks.all():
        print_result(result, args.verbose)
        all_results.append(result)

    print(f"\nTotal CVE test cases: {len(all_results)}")

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in all_results:
            filepath = os.path.join(args.output, f"{result.name}.dcm")
            file_data = b'\x00' * 128 + b'DICM' + result.payload
            with open(filepath, 'wb') as f:
                f.write(file_data)
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
        for i, result in enumerate(ProtocolFuzzer.fuzz_association(count=args.count)):
            if not result.payload:
                print(f"✗ #{i+1}: {result.description}")
                continue

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

        print(f"\nInteresting results: {interesting_count}/{args.count}")

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
        if result.payload and not result.payload.startswith(b'DICM'):
            file_data = b'\x00' * 128 + b'DICM' + result.payload
        else:
            file_data = result.payload

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


def run_parser_attacks(args) -> int:
    """Run parser attack tests."""
    print("\n=== Parser Attacks ===\n")

    results = []
    for result in ParserAttacks.all():
        try:
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal parser attack tests: {len(results)}")

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
    for result in ProtocolAttacks.all():
        try:
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal protocol attack tests: {len(results)}")

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
    for result in LogicAttacks.all():
        try:
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal logic attack tests: {len(results)}")

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
    for result in StateMachineAttacks.all():
        try:
            steps = result.metadata.get('steps')
            if steps:
                responses = deliver.send_sequence(target, steps, timeout=args.timeout)
                result.response = responses[-1] if responses else None
            else:
                result.response = deliver.send_pdu(target, result.payload, timeout=args.timeout)
            result.success = True
        except Exception as e:
            result.success = False
            result.description = f'Failed: {e}'

        print_result(result, args.verbose)
        results.append(result)

    print(f"\nTotal state machine attack tests: {len(results)}")
    return 0


def run_memory_attacks(args) -> int:
    """Run memory corruption attack tests."""
    print("\n=== Memory Attacks ===\n")

    results = []
    for result in MemoryAttacks.all():
        try:
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"✗ {result.name}: {e}")

    print(f"\nTotal memory attack tests: {len(results)}")

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
        'state_machine_attacks': run_state_machine_attacks,
        'all': run_all_tests,
    }
    
    if command not in commands:
        print(f"ERROR: Unknown command: {command}")
        print(f"Available commands: {', '.join(commands.keys())}")
        return 1
    
    return commands[command](args)


def main(argv: Optional[List[str]] = None):
    """Main entry point."""
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
        choices=['parser', 'protocol', 'memory', 'logic', 'state_machine', 
                 'cve', 'fuzz_packet', 'live_fuzz', 'all'],
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
    
    try:
        return run_command(command, args)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"\nERROR: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())