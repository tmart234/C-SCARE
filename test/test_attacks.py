# SPDX-License-Identifier: GPL-2.0-only
"""Tests for attack catalog payload coverage and routing metadata."""

import argparse

from c_scare.attacks import (
    CVEAttacks,
    PathTraversalAttacks,
    ProtocolAttacks,
    StorageSCPAbuseAttacks,
)
from c_scare.runner import _delivery_kind

ADVISORY = 'ICSMA-26-181-01'
EXPECTED_ICSMA_CVES = {
    'CVE-2026-50003',
    'CVE-2026-50254',
    'CVE-2026-35505',
    'CVE-2026-52868',
    'CVE-2026-44628',
}


def _args(delivery='auto'):
    return argparse.Namespace(delivery=delivery)


def _advisory_cases():
    return [r for r in CVEAttacks.all()
            if r.metadata.get('advisory') == ADVISORY]


def test_icsma_26_181_01_cves_are_in_catalog():
    cases = _advisory_cases()
    assert {r.cve for r in cases} == EXPECTED_ICSMA_CVES
    assert all(r.metadata['coverage_mode'] == 'both' for r in cases)
    assert all(r.payload for r in cases)
    for result in cases:
        assert result.metadata['blackbox_driver']
        assert result.metadata['greybox_driver']
        assert result.metadata['target']
        assert result.metadata['cwe'].startswith('CWE-')


def test_icsma_delivery_modes_are_explicit():
    for cve in ('CVE-2026-50254', 'CVE-2026-35505'):
        [result] = [r for r in _advisory_cases() if r.cve == cve]
        assert result.payload[:1] == b'\x01'
        assert result.metadata['expected_monitor'] == 'memory-growth-or-lsan'
        assert _delivery_kind(_args(), result) == 'pdu'

    worklist = [r for r in _advisory_cases()
                if r.cve in ('CVE-2026-52868', 'CVE-2026-44628')]
    assert len(worklist) == 2
    for result in worklist:
        steps = result.metadata['steps']
        assert len(steps) == 3
        assert steps[0][:1] == b'\x01'
        assert steps[1][:1] == b'\x04'
        assert steps[2][:1] == b'\x05'
        assert 'net-dcmqrscp is not a worklist server' in \
            result.metadata['greybox_prerequisite']
        assert _delivery_kind(_args(), result) == 'sequence'

    cget_cases = [r for r in _advisory_cases() if r.cve == 'CVE-2026-50003']
    assert {r.metadata['traversal_payload'] for r in cget_cases} == {
        '../../outside-cget/c-scare-cget.dcm',
        '/tmp/c-scare-cget/escaped.dcm',
    }
    for result in cget_cases:
        assert result.metadata['target_role'] == 'scu-client'
        assert result.metadata['delivery'] == 'hostile-cget-cstore'
        assert _delivery_kind(_args(), result) == 'cstore'


def test_protocol_catalog_includes_association_negotiation_edges():
    cases = {r.name: r for r in ProtocolAttacks.all()}
    assert 'duplicate_presentation_context_id' in cases
    assert 'even_presentation_context_id' in cases
    assert 'presentation_context_without_transfer_syntax' in cases
    assert 'tiny_max_pdu_length' in cases

    for result in (
        ProtocolAttacks.duplicate_presentation_context_id(),
        ProtocolAttacks.even_presentation_context_id(),
        ProtocolAttacks.presentation_context_without_transfer_syntax(),
        ProtocolAttacks.tiny_max_pdu_length(),
    ):
        assert result.category == 'protocol'
        assert result.payload[:1] == b'\x01'
        assert result.metadata['coverage_scope'].startswith('association-')

    duplicate = ProtocolAttacks.duplicate_presentation_context_id()
    even = ProtocolAttacks.even_presentation_context_id()
    no_ts = ProtocolAttacks.presentation_context_without_transfer_syntax()
    tiny = ProtocolAttacks.tiny_max_pdu_length()
    assert duplicate.payload.count(b'\x20\x00') >= 2
    assert b'\x02\x00\x00\x00' in even.payload
    assert b'\x40\x00\x00\x11' not in no_ts.payload
    assert b'\x51\x00\x00\x04\x00\x00\x00\x01' in tiny.payload


def test_storage_scp_abuse_catalog_covers_push_abuse_axes():
    cases = {r.metadata['coverage_scope']: r for r in StorageSCPAbuseAttacks.all()}
    assert set(cases) == {
        'identity-validation',
        'identity-merge-poisoning',
        'command-dataset-sop-class-mismatch',
        'command-dataset-instance-uid-mismatch',
        'storage-quota-disk-pressure',
        'private-tag-metadata-pressure',
        'cstore-command-data-set-type-mismatch',
        'cstore-missing-data-pdv',
        'cstore-invalid-priority',
        'cstore-move-originator-spoofing',
    }


def test_storage_scp_abuse_payloads_route_correctly():
    for result in StorageSCPAbuseAttacks.all():
        assert result.category == 'storage_abuse'
        assert result.metadata['sop_class_uid']
        assert result.metadata['sop_instance_uid']
        assert result.payload
        if result.metadata.get('steps'):
            assert _delivery_kind(_args(), result) == 'sequence'
        else:
            assert _delivery_kind(_args(), result) == 'cstore'


def test_storage_scp_abuse_payload_specifics():
    empty = StorageSCPAbuseAttacks.empty_required_identity_store()
    dup = StorageSCPAbuseAttacks.duplicate_patient_identity_conflict()
    sop_class = StorageSCPAbuseAttacks.command_dataset_sop_class_conflict()
    sop_instance = StorageSCPAbuseAttacks.command_dataset_instance_uid_conflict()

    assert b'\x10\x00\x10\x00' in empty.payload
    assert b'\x10\x00\x20\x00' in empty.payload
    assert dup.payload.count(b'\x10\x00\x10\x00') == 2
    assert dup.payload.count(b'\x10\x00\x20\x00') == 2
    assert b'TRUSTED-ID' in dup.payload
    assert b'INJECTED-ID' in dup.payload
    assert sop_class.metadata['command_sop_class_uid'] != \
        sop_class.metadata['dataset_sop_class_uid']
    assert sop_instance.metadata['command_sop_instance_uid'] != \
        sop_instance.metadata['dataset_sop_instance_uid']

    bulk = StorageSCPAbuseAttacks.bulkdata_disk_pressure()
    private_tags = StorageSCPAbuseAttacks.private_tag_pressure()
    assert bulk.metadata['repeat_for_detection'] == 100
    assert bulk.metadata['size'] == 256 * 1024
    assert b'X' * 64 in bulk.payload
    assert private_tags.metadata['private_tag_count'] == 128
    assert private_tags.payload.count(b'private-') == 128


def test_storage_scp_abuse_cstore_command_sequence_payloads():
    cases = {
        r.metadata['coverage_scope']: r
        for r in StorageSCPAbuseAttacks.all()
        if r.metadata.get('steps')
    }
    assert set(cases) == {
        'cstore-command-data-set-type-mismatch',
        'cstore-missing-data-pdv',
        'cstore-invalid-priority',
        'cstore-move-originator-spoofing',
    }
    for result in cases.values():
        assert len(result.metadata['steps']) == 3
        assert result.metadata['steps'][0][:1] == b'\x01'
        assert result.metadata['steps'][1][:1] == b'\x04'
        assert result.metadata['steps'][2][:1] == b'\x05'
        assert _delivery_kind(_args(), result) == 'sequence'


def test_null_byte_sop_uid_payload_preserves_attacker_extension_before_nul():
    result = PathTraversalAttacks.sop_instance_uid_traversal('null_byte')
    assert result.metadata['regression_case'] == 'null-byte-extension-bypass'
    assert result.metadata['null_byte_filename_truncation'] is True
    assert result.metadata['attacker_controlled_extension'] == '.attacker'
    assert result.metadata['traversal_payload'] == \
        '../../../../../../tmp/attacker-controlled.attacker\x00.DCM'
    assert b'../../../../../../tmp/attacker-controlled.attacker\x00.DCM' in \
        result.payload
    assert _delivery_kind(_args(), result) == 'cstore'


def test_path_traversal_source_ambiguity_variants():
    command = PathTraversalAttacks.command_sop_instance_uid_traversal('null_byte')
    dataset = PathTraversalAttacks.dataset_only_sop_instance_uid_traversal('null_byte')
    file_meta = PathTraversalAttacks.file_meta_sop_instance_uid_traversal('null_byte')

    assert command.metadata['coverage_scope'] == 'command-sop-instance-uid-only'
    assert command.metadata['target_field'] == \
        '(0000,1000) Affected SOP Instance UID'
    assert command.metadata['sop_instance_uid'] == \
        command.metadata['traversal_payload']
    assert b'attacker-controlled' not in command.payload

    assert dataset.metadata['coverage_scope'] == 'dataset-sop-instance-uid-only'
    assert dataset.metadata['sop_instance_uid'] == '1.2.3.4.5'
    assert b'attacker-controlled.attacker\x00.DCM' in dataset.payload

    assert file_meta.metadata['coverage_scope'] == 'file-meta-sop-instance-uid'
    assert file_meta.metadata['target_field'] == \
        '(0002,0003) Media Storage SOP Instance UID'
    assert b'\x02\x00\x03\x00' in file_meta.payload
    assert b'attacker-controlled.attacker\x00.DCM' in file_meta.payload
    for result in (command, dataset, file_meta):
        assert result.metadata['regression_case'] == 'null-byte-extension-bypass'
        assert result.metadata['null_byte_filename_truncation'] is True
        assert _delivery_kind(_args(), result) == 'cstore'


def test_dicom_ui_and_vm_boundary_path_traversal_variants():
    pad = PathTraversalAttacks.sop_instance_uid_traversal('ui_pad_nul')
    overlong = PathTraversalAttacks.sop_instance_uid_traversal('overlong_uid')
    first = PathTraversalAttacks.sop_instance_uid_traversal('vm_first')
    second = PathTraversalAttacks.sop_instance_uid_traversal('vm_second')

    assert pad.metadata['dicom_ui_boundary'] == 'ui_pad_nul'
    assert pad.metadata['null_byte_filename_truncation'] is True
    assert b'../../../../../../tmp/c-scare-ui-pad0\x00' in pad.payload
    assert b'../../../../../../tmp/c-scare-ui-pad0\x00 ' not in pad.payload

    assert overlong.metadata['dicom_ui_boundary'] == 'overlong_uid'
    assert overlong.metadata['overlong_uid'] is True
    assert len(overlong.metadata['traversal_payload']) > 64
    assert b'c-scare-' + (b'A' * 80) in overlong.payload

    assert first.metadata['dicom_vm_boundary'] == 'vm_first'
    assert first.metadata['vm_separator'] is True
    assert first.metadata['traversal_payload'].startswith('../../')
    assert b'../../../../../../tmp/c-scare-vm-first\\1.2.3.4.5' in first.payload

    assert second.metadata['dicom_vm_boundary'] == 'vm_second'
    assert second.metadata['vm_separator'] is True
    assert second.metadata['traversal_payload'].startswith('1.2.3.4.5\\')
    assert b'1.2.3.4.5\\../../../../../../tmp/c-scare-vm-second' in second.payload


def test_path_traversal_targets_etc_passwd():
    result = PathTraversalAttacks.sop_instance_uid_traversal('etc_passwd')
    assert result.name == 'path_traversal_sop_uid_etc_passwd'
    assert result.metadata['traversal_payload'] == '../../../../../../etc/passwd'
    assert result.metadata['sop_instance_uid'] == '../../../../../../etc/passwd'
    assert b'../../../../../../etc/passwd' in result.payload
    assert _delivery_kind(_args(), result) == 'cstore'
    assert 'path_traversal_sop_uid_etc_passwd' in {
        r.name for r in PathTraversalAttacks.all()}


def test_path_traversal_sweep_and_routing():
    cases = {r.name: r for r in PathTraversalAttacks.all()}
    assert 'path_traversal_sop_uid_posix_proof' in cases
    assert 'path_traversal_multi_field_storage_probe' in cases
    assert 'path_traversal_sop_uid_null_byte' in cases
    assert 'path_traversal_command_sop_uid_null_byte' in cases
    assert 'path_traversal_dataset_only_sop_uid_null_byte' in cases
    assert 'path_traversal_file_meta_sop_uid_null_byte' in cases
    assert 'path_traversal_sop_uid_ui_pad_nul' in cases
    assert 'path_traversal_sop_uid_overlong_uid' in cases
    assert 'path_traversal_sop_uid_vm_first' in cases
    assert 'path_traversal_sop_uid_vm_second' in cases
    assert 'path_traversal_sop_uid_windows_absolute' in cases
    assert cases['path_traversal_sop_uid_absolute'].metadata[
        'traversal_payload'] == '/tmp/c-scare-traversal'
    assert 'path_traversal_sop_uid_unc' in cases
    assert cases['path_traversal_sop_uid_null_byte'].metadata[
        'null_byte_filename_truncation'] is True
    for result in PathTraversalAttacks.all():
        assert _delivery_kind(_args(), result) == 'cstore'


def test_path_traversal_multi_field_probe_marks_every_storage_field():
    result = PathTraversalAttacks.multi_field_storage_path_probe()
    overrides = result.metadata['cstore_field_overrides']

    assert result.metadata['coverage_scope'] == 'multi-field-storage-path-proof'
    assert result.metadata['proof_canary_leaf'] == 'c-scare-traversal-proof'
    assert overrides['SOPInstanceUID'].endswith('/sop-instance')
    assert overrides['StudyInstanceUID'].endswith('/study-instance')
    assert overrides['SeriesInstanceUID'].endswith('/series-instance')
    assert overrides['PatientName'].endswith('/patient-name')
    assert b'../../../../../../tmp/c-scare-traversal-proof/sop-instance' in \
        result.payload
    assert b'../../../../../../tmp/c-scare-traversal-proof/patient-name' in \
        result.payload
