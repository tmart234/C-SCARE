# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the grey-box fuzzing bridge (crash triage)."""

import sys
import textwrap

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
        'file', 'net-storescp', 'net-dcmrecv', 'net-dcmqrscp',
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
