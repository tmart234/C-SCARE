# SPDX-License-Identifier: GPL-2.0-only
"""Tests for declarative target profiles and their wiring into the fuzzer.

These lock down (a) that the profiles are the single source of truth for the
grey-box targets, and (b) that a profile's AE titles / SOP classes / transfer
syntaxes actually flow into the A-ASSOCIATE-RQ + P-DATA-TF seed bytes, the
DICOM file-seed baselines, and the rendered dcmqrscp.cfg — not inert metadata.
"""
import importlib.util
import os

import pytest

import c_scare
from c_scare import greybox, profiles

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(REPO_ROOT, 'fuzz', 'harness')

EXPECTED = {
    'file', 'parse', 'net-storescp', 'net-dcmrecv', 'net-dcmqrscp', 'scu',
}


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ae(value):
    """Normalise a (possibly bytes, space-padded) AE-title field to str."""
    if isinstance(value, bytes):
        value = value.decode('ascii', 'replace')
    return value.strip()


# --------------------------------------------------------------------------
# Loader + derivation
# --------------------------------------------------------------------------

def test_load_all_profiles():
    profs = profiles.load_profiles()
    assert set(profs) == EXPECTED
    for p in profs.values():
        assert p.engine in ('aflpp', 'aflnet')
        assert p.kind in ('file', 'net-scp', 'scu')
        assert p.harness and p.binary and p.build_subdir


def test_targets_derived_from_profiles():
    assert greybox.TARGETS == {
        'file': 'fuzz_file.sh',
        'parse': 'fuzz_parse.sh',
        'net-storescp': 'fuzz_net.sh',
        'net-dcmrecv': 'fuzz_dcmrecv.sh',
        'net-dcmqrscp': 'fuzz_dcmqrscp.sh',
        'scu': 'fuzz_scu.sh',
    }
    assert set(greybox.NET_TARGETS) == {
        'net-storescp', 'net-dcmrecv', 'net-dcmqrscp',
    }


def test_profile_name_mismatch_rejected(tmp_path):
    targets = tmp_path / 'fuzz' / 'targets'
    targets.mkdir(parents=True)
    (targets / 'bogus.yaml').write_text(
        'name: not-bogus\nengine: aflpp\nkind: file\nharness: x.sh\n')
    with pytest.raises(ValueError):
        profiles.load_profile('bogus', repo=str(tmp_path))


def test_missing_profile_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        profiles.load_profile('does-not-exist', repo=str(tmp_path))


# --------------------------------------------------------------------------
# UID resolution + token substitution
# --------------------------------------------------------------------------

def test_resolve_cscare_uid():
    assert profiles.resolve_cscare_uid('VERIFICATION_SOP_CLASS_UID') == \
        c_scare.VERIFICATION_SOP_CLASS_UID
    # Raw dotted UID passes through verbatim.
    assert profiles.resolve_cscare_uid('1.2.840.10008.1.1') == '1.2.840.10008.1.1'
    with pytest.raises(ValueError):
        profiles.resolve_cscare_uid('NOT_A_REAL_SYMBOL')


def test_resolve_pydicom_uid():
    from pydicom.uid import ExplicitVRLittleEndian
    assert profiles.resolve_pydicom_uid('ExplicitVRLittleEndian') == \
        ExplicitVRLittleEndian
    assert str(profiles.resolve_pydicom_uid('1.2.840.10008.1.2.1')) == \
        '1.2.840.10008.1.2.1'
    with pytest.raises(ValueError):
        profiles.resolve_pydicom_uid('NotAUid')


def test_subst_tokens():
    assert profiles.subst('{{REPO_ROOT}}/x', repo='/r') == '/r/x'
    assert profiles.subst('p={{PORT}}', port=11112) == 'p=11112'
    assert profiles.subst('{{CONFIG}}', config='/c') == '/c'
    # Unset runtime tokens collapse to empty.
    assert profiles.subst('a{{WORKDIR}}b') == 'ab'
    # Non-strings pass through untouched.
    assert profiles.subst(5) == 5


# --------------------------------------------------------------------------
# AE titles / SOP classes / transfer syntaxes WIRED into the seed bytes
# --------------------------------------------------------------------------

def test_associate_rq_carries_profile_identity():
    ser = _load_module('seed_serializer',
                        os.path.join(HARNESS, 'seed_serializer.py'))
    prof = profiles.load_profile('net-dcmqrscp')

    by_name = {fl.name: fl for fl in prof.flows}
    for flow_name in ('echo', 'find', 'move', 'get'):
        flow = by_name[flow_name]
        blob = ser._associate_rq(prof, flow)

        # AE titles parse back out of the A-ASSOCIATE-RQ.
        pkt = c_scare.DICOM(blob)
        rq = pkt[c_scare.A_ASSOCIATE_RQ]
        assert _ae(rq.calling_ae_title) == prof.calling_ae      # C-SCARE-FZ
        assert _ae(rq.called_ae_title) == prof.called_ae        # DCMQRSCP

        # The abstract syntax (SOP class) + transfer syntax UIDs are encoded
        # (ASCII) in the presentation context, so they appear in the bytes.
        assert flow.abstract_syntax.encode() in blob
        for ts in flow.transfer_syntaxes:
            assert ts.encode() in blob


def test_dimse_affected_sop_class_from_profile():
    ser = _load_module('seed_serializer',
                        os.path.join(HARNESS, 'seed_serializer.py'))
    import random
    prof = profiles.load_profile('net-storescp')
    store = next(fl for fl in prof.flows if fl.name == 'store')
    pkt = ser._build_dimse(store, random.Random(1))
    assert pkt.affected_sop_class_uid == store.abstract_syntax
    # Per-flow dimse_kwargs were applied.
    assert pkt.affected_sop_instance_uid == '1.2.3.4.5.6.7.8.9.10'


def test_move_destination_resolves_to_calling_ae():
    prof = profiles.load_profile('net-dcmqrscp')
    move = next(fl for fl in prof.flows if fl.name == 'move')
    assert move.dimse_kwargs['move_destination'] == prof.calling_ae


def test_file_baseline_transfer_syntax_from_profile(tmp_path, monkeypatch):
    import pydicom
    gen = _load_module('gen_file_seeds',
                       os.path.join(HARNESS, 'gen_file_seeds.py'))
    out = tmp_path / 'file'
    monkeypatch.setattr(gen, 'OUT_DIR', out)
    monkeypatch.setattr(gen, 'REPO_ROOT', tmp_path)   # for the progress prints
    gen.main(['file'])

    prof = profiles.load_profile('file')
    for entry in prof.file_transfer_syntaxes:
        ts = profiles.resolve_pydicom_uid(entry['uid'])
        ds = pydicom.dcmread(str(out / f"baseline_{entry['label']}.dcm"))
        assert ds.file_meta.TransferSyntaxUID == ts
        assert ds.file_meta.MediaStorageSOPClassUID == \
            profiles.resolve_pydicom_uid(prof.file_baseline_sop_class)


# --------------------------------------------------------------------------
# dcmqrscp config coherence + triage argv
# --------------------------------------------------------------------------

def test_dcmqrscp_config_ae_coherence():
    prof = profiles.load_profile('net-dcmqrscp')
    cfg, base = greybox._render_config(REPO_ROOT, prof)
    try:
        body = open(cfg).read()
        # HostTable caller uses the calling AE; AETable entry is the called AE.
        assert f'({prof.calling_ae},' in body
        assert prof.called_ae in body
        # The same AE titles the seed A-ASSOCIATE-RQ carries.
        ser = _load_module('seed_serializer',
                           os.path.join(HARNESS, 'seed_serializer.py'))
        echo = next(fl for fl in prof.flows if fl.name == 'echo')
        rq = c_scare.DICOM(ser._associate_rq(prof, echo))[c_scare.A_ASSOCIATE_RQ]
        assert _ae(rq.calling_ae_title) == prof.calling_ae
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


@pytest.mark.parametrize('target,expected', [
    ('net-storescp', ['S', '7777', '--eostudy-timeout', '1']),
    ('net-dcmrecv', ['S', '7777', '--output-directory', '/wd',
                     '--eostudy-timeout', '1']),
    ('net-dcmqrscp', ['S', '-c', '/cfg', '7777']),
])
def test_net_server_argv_from_profile(target, expected):
    prof = profiles.load_profile(target)
    argv = greybox._net_server_argv(prof, 'S', 7777, '/wd', '/cfg')
    assert argv == expected
