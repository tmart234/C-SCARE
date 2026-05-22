# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the grey-box fuzzing bridge (crash triage)."""

import shutil
import subprocess
import sys
import textwrap

import pytest

from c_scare import greybox


def _make_afl_out(tmp_path, layout='afl'):
    """Create a fake AFL/AFLNet output directory with two crash files."""
    if layout == 'afl':
        crashes = tmp_path / 'default' / 'crashes'
    else:
        crashes = tmp_path / 'crashes'
    crashes.mkdir(parents=True)
    (crashes / 'README.txt').write_text('afl crash dir readme')
    (crashes / 'id:000000,sig:06,src:000000').write_bytes(b'\x00crash-a')
    (crashes / 'id:000001,sig:11,src:000001').write_bytes(b'\x00crash-b-longer')
    return crashes


def test_targets_match_campaign_script():
    assert set(greybox.TARGETS) == {
        'file', 'parse', 'net-storescp', 'net-dcmrecv', 'net-dcmqrscp', 'scu',
    }


def test_list_crashes_afl_layout(tmp_path):
    _make_afl_out(tmp_path, 'afl')
    crashes = greybox.list_crashes(str(tmp_path))
    assert len(crashes) == 2
    assert all('README' not in c for c in crashes)


def test_list_crashes_aflnet_layout(tmp_path):
    _make_afl_out(tmp_path, 'aflnet')
    crashes = greybox.list_crashes(str(tmp_path))
    assert len(crashes) == 2


def test_triage_inventory_without_binary(tmp_path):
    _make_afl_out(tmp_path, 'afl')
    crashes = greybox.list_crashes(str(tmp_path))
    results = greybox.triage(crashes)
    assert len(results) == 2
    assert all(r.category == 'greybox' for r in results)
    # No binary supplied -> inventory only, no findings.
    assert all(r.success is None for r in results)
    assert all(r.metadata['size'] > 0 for r in results)


def test_triage_replays_crash_through_binary(tmp_path):
    # A fake target that emits an ASan report and exits non-zero.
    fake = tmp_path / 'fake_target.py'
    fake.write_text(textwrap.dedent('''\
        import sys
        sys.stderr.write(
            "==123==ERROR: AddressSanitizer: heap-buffer-overflow on addr 0x1\\n"
            "    #0 0x4 in parse foo.c:9\\n"
            "    #1 0x5 in main bar.c:2\\n\\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow foo.c:9 in parse\\n"
        )
        sys.exit(1)
    '''))
    crash_dir = tmp_path / 'crashes'
    crash_dir.mkdir()
    (crash_dir / 'id:000000,sig:06').write_bytes(b'bad-input')

    crashes = greybox.list_crashes(str(tmp_path))
    results = greybox.triage(
        crashes, cmd=[sys.executable, str(fake), '@@'], timeout=20,
    )
    assert len(results) == 1
    finding = results[0]
    assert finding.success is True
    assert finding.monitor_reports
    assert 'heap-buffer-overflow' in finding.monitor_reports[0].finding_type


def test_triage_to_sarif_writes_report(tmp_path):
    _make_afl_out(tmp_path, 'afl')
    sarif_path = tmp_path / 'out.sarif'
    greybox.triage_to_sarif(str(tmp_path), sarif_path=str(sarif_path))
    assert sarif_path.exists()
    import json
    doc = json.loads(sarif_path.read_text())
    assert doc['version'] == '2.1.0'
    assert len(doc['runs'][0]['results']) == 2


def test_list_queue(tmp_path):
    """list_queue enumerates queue inputs, skipping AFL's .state metadata."""
    queue = tmp_path / 'default' / 'queue'
    queue.mkdir(parents=True)
    (queue / '.state').mkdir()
    (queue / '.state' / 'redundant_edges').write_text('afl metadata')
    (queue / 'id:000000,orig:seed').write_bytes(b'q-a')
    (queue / 'id:000001,src:000000').write_bytes(b'q-b-longer')
    inputs = greybox.list_queue(str(tmp_path))
    assert len(inputs) == 2
    assert all('.state' not in i for i in inputs)


def test_triage_detects_memory_leak(tmp_path):
    """A clean-exit replay that leaks is classified as an lsan finding."""
    fake = tmp_path / 'leaky_target.py'
    fake.write_text(textwrap.dedent('''\
        import sys
        sys.stderr.write(
            "==45678==ERROR: LeakSanitizer: detected memory leaks\\n\\n"
            "Direct leak of 1024 byte(s) in 1 object(s) allocated from:\\n"
            "    #0 0x7f in malloc\\n"
            "    #1 0x4a in readPeerList dcmqrcnf.cc:512\\n\\n"
            "SUMMARY: AddressSanitizer: 1024 byte(s) leaked in 1 allocation(s).\\n"
        )
        sys.exit(0)
    '''))
    queue = tmp_path / 'queue'
    queue.mkdir()
    (queue / 'id:000000,orig:seed').write_bytes(b'leak-input')

    results = greybox.triage(
        greybox.list_queue(str(tmp_path)),
        cmd=[sys.executable, str(fake), '@@'], timeout=20,
    )
    assert len(results) == 1
    r = results[0]
    assert r.success is True
    assert r.metadata['kind'] == 'queue'
    assert r.monitor_reports
    assert 'lsan:memory-leak' in r.monitor_reports[0].finding_type


def test_triage_to_sarif_include_queue(tmp_path):
    """include_queue folds queue inputs into the triaged set."""
    _make_afl_out(tmp_path, 'afl')          # 2 crash inputs
    queue = tmp_path / 'default' / 'queue'
    queue.mkdir(parents=True)
    (queue / 'id:000000,orig:seed').write_bytes(b'q-a')
    crashes_only = greybox.triage_to_sarif(str(tmp_path))
    with_queue = greybox.triage_to_sarif(str(tmp_path), include_queue=True)
    assert len(crashes_only) == 2
    assert len(with_queue) == 3


def test_triage_env_forces_full_report(monkeypatch):
    """Triage overrides a campaign's throughput-tuned sanitizer options."""
    # A campaign runs with the symbolizer off and leak detection off.
    monkeypatch.setenv('ASAN_OPTIONS', 'symbolize=0:detect_leaks=0')
    monkeypatch.delenv('UBSAN_OPTIONS', raising=False)
    monkeypatch.delenv('MSAN_OPTIONS', raising=False)
    env = greybox._triage_env()
    # Last-wins: the forced values land after the inherited campaign ones.
    assert env['ASAN_OPTIONS'].endswith('detect_leaks=1:symbolize=1')
    assert 'symbolize=0' in env['ASAN_OPTIONS']
    assert 'print_stacktrace=1' in env['UBSAN_OPTIONS']
    assert 'symbolize=1' in env['MSAN_OPTIONS']


def test_triage_multiple_workers(tmp_path):
    """Each input is replayed through every worker; findings merge (SAND)."""
    asan_fake = tmp_path / 'asan_worker.py'
    asan_fake.write_text(textwrap.dedent('''\
        import sys
        sys.stderr.write(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on addr 0x1\\n"
            "    #0 0x4 in parse foo.c:9\\n\\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow foo.c:9 in parse\\n"
        )
        sys.exit(1)
    '''))
    ubsan_fake = tmp_path / 'ubsan_worker.py'
    ubsan_fake.write_text(textwrap.dedent('''\
        import sys
        sys.stderr.write(
            "foo.c:42:7: runtime error: signed integer overflow: 1 + 1\\n"
            "    #0 0x9 in parse foo.c:42:7\\n"
        )
        sys.exit(0)
    '''))
    crash_dir = tmp_path / 'crashes'
    crash_dir.mkdir()
    (crash_dir / 'id:000000,sig:06').write_bytes(b'bad-input')

    results = greybox.triage(
        greybox.list_crashes(str(tmp_path)),
        cmds=[[sys.executable, str(asan_fake), '@@'],
              [sys.executable, str(ubsan_fake), '@@']],
        timeout=20,
    )
    assert len(results) == 1
    r = results[0]
    assert r.success is True
    kinds = ' '.join(rep.finding_type for rep in r.monitor_reports)
    assert 'asan:heap-buffer-overflow' in kinds
    assert 'ubsan' in kinds
    # One exit code recorded per worker.
    assert isinstance(r.metadata['exit_code'], list)
    assert len(r.metadata['exit_code']) == 2


def test_find_san_workers(tmp_path):
    """find_san_workers locates one worker binary per build-san-* tree."""
    import stat
    fuzz = tmp_path / 'fuzz'
    for san in ('address', 'undefined'):
        bindir = fuzz / f'build-san-{san}' / 'bin'
        bindir.mkdir(parents=True)
        binpath = bindir / 'dcm2pnm'
        binpath.write_text('#!/bin/sh\n')
        binpath.chmod(binpath.stat().st_mode | stat.S_IEXEC)

    workers = greybox.find_san_workers('dcm2pnm', repo=str(tmp_path))
    assert len(workers) == 2
    assert any('build-san-address' in w for w in workers)
    assert any('build-san-undefined' in w for w in workers)
    # A binary that was never built yields no workers.
    assert greybox.find_san_workers('nonexistent', repo=str(tmp_path)) == []


@pytest.mark.skipif(shutil.which('gcc') is None, reason='gcc not available')
def test_triage_real_asan_binary(tmp_path):
    """End-to-end: replay a crash through a real ASan-instrumented binary."""
    src = tmp_path / 'target.c'
    src.write_text(textwrap.dedent('''\
        #include <stdio.h>
        int main(int argc, char **argv) {
            if (argc < 2) return 0;
            FILE *f = fopen(argv[1], "rb");
            if (!f) return 0;
            char buf[8];
            size_t n = fread(buf, 1, 4096, f);  /* overflow if input > 8 */
            fclose(f);
            return (int)n;
        }
    '''))
    binary = tmp_path / 'asan_target'
    subprocess.run(
        ['gcc', '-fsanitize=address', '-g', '-o', str(binary), str(src)],
        check=True,
    )
    crash_dir = tmp_path / 'crashes'
    crash_dir.mkdir()
    (crash_dir / 'id:000000,sig:06').write_bytes(b'A' * 40)

    results = greybox.triage(
        greybox.list_crashes(str(tmp_path)),
        cmd=[str(binary), '@@'], timeout=30,
    )
    assert len(results) == 1
    assert results[0].success is True
    kinds = ' '.join(r.finding_type for r in results[0].monitor_reports)
    assert 'overflow' in kinds
