# SPDX-License-Identifier: GPL-2.0-only
"""Socket-free tests for the Phase 2 hostile/malformation primitives.

Covers the malformed-PDU builders (c_scare.hostile), the DAST byte-mutation
helpers, and the delivery-kind routing that decides whether a payload goes out
as a raw PDU, a PDU sequence, or wrapped in a C-STORE association.
"""

import struct

from c_scare import hostile


def _pdu_header(b):
    pdu_type, _reserved, length = struct.unpack("!BBI", b[:6])
    return pdu_type, length


class TestMalformedPDUBuilders:
    def test_oversized_pdu_overstates_length(self):
        b = hostile.oversized_pdu()
        _t, declared = _pdu_header(b)
        assert declared == 0xFFFFFFFF
        assert declared > len(b) - 6  # the lie: claims far more than delivered

    def test_truncated_pdu_understates_length(self):
        body = b"\x00" * 32
        b = hostile.truncated_pdu(body=body)
        _t, declared = _pdu_header(b)
        assert declared < len(body)  # trailing bytes desync the framing

    def test_malformed_ac_has_illegal_subitem(self):
        b = hostile.malformed_ac_subitems()
        pdu_type, _ = _pdu_header(b)
        assert pdu_type == hostile.PDU_ASSOCIATE_AC
        assert b"\x99" in b  # the undefined sub-item type byte

    def test_illegal_role_response_embeds_role_item(self):
        b = hostile.illegal_role_response(scu_role=1, scp_role=1)
        pdu_type, _ = _pdu_header(b)
        assert pdu_type == hostile.PDU_ASSOCIATE_AC
        # Role-item type 0x54 appears in the user-information block.
        assert b"\x54" in b

    def test_out_of_state_pdu_is_release_rp(self):
        b = hostile.out_of_state_pdu()
        pdu_type, _ = _pdu_header(b)
        assert pdu_type == hostile.PDU_RELEASE_RP

    def test_rogue_response_covers_every_mode(self):
        for mode in hostile.ROGUE_MALFORMATION_MODES:
            assert isinstance(hostile.rogue_response(mode), bytes)


class TestByteMutation:
    def test_bitflip_changes_one_byte(self):
        original = b"AAAAAAAA"
        mutated = hostile.bitflip_bytes(original, n=1, seed=3)
        assert mutated != original
        assert len(mutated) == len(original)
        diff = sum(1 for a, b in zip(original, mutated) if a != b)
        assert diff == 1

    def test_bitflip_is_deterministic_in_seed(self):
        assert hostile.bitflip_bytes(b"hello", seed=7) == \
            hostile.bitflip_bytes(b"hello", seed=7)

    def test_mutate_payload_never_raises_on_garbage(self):
        # Non-dataset bytes: structural modes must not raise (they either parse
        # something and re-encode, or degrade to a raw byte flip).
        out = hostile.mutate_payload(b"\x00\x01\x02\x03garbage", ["vr", "length"],
                                     seed=1)
        assert isinstance(out, bytes)
        assert out  # non-empty

    def test_mutate_empty_payload(self):
        assert hostile.mutate_payload(b"", ["bitflip"]) == b""


class TestSarifAdapters:
    def test_role_negotiation_abort_is_error_finding(self):
        from c_scare import RoleNegotiationResult
        rn = RoleNegotiationResult(
            sop_class_uid="1.2.840.10008.5.1.4.1.1.2",
            requested_scp_role=1, granted_scp_role=0, aborted=True,
            negotiated_roles={"1.2.840.10008.5.1.4.1.1.2": (0, 0)})
        ar = rn.to_attack_result()
        assert ar.category == "role-negotiation"
        assert ar.success is False  # SARIF "error"
        assert ar.metadata["granted_scp_role"] == 0

    def test_role_negotiation_grant_is_not_a_finding(self):
        from c_scare import RoleNegotiationResult
        rn = RoleNegotiationResult(
            sop_class_uid="1.2.840.10008.5.1.4.1.1.2",
            requested_scp_role=1, granted_scp_role=1, aborted=False)
        ar = rn.to_attack_result()
        assert ar.success is None

    def test_hostile_observation_carries_monitor_reports(self):
        from c_scare import HostileObservation
        from c_scare.monitor import MonitorReport
        rpt = MonitorReport(detected=True, finding_type="crash:segv",
                            description="client crashed", evidence="bt...")
        obs = HostileObservation(name="oversized-store", description="pushed oversized",
                                 monitor_reports=[rpt])
        ar = obs.to_attack_result()
        assert ar.category == "hostile-scu"
        assert ar.success is True  # a detection promotes success
        assert ar.monitor_reports[0].finding_type == "crash:segv"

    def test_hostile_observation_renders_in_sarif(self, tmp_path):
        from c_scare import HostileObservation
        from c_scare.monitor import MonitorReport
        from c_scare.runner import write_sarif
        rpt = MonitorReport(detected=True, finding_type="asan:heap-overflow",
                            description="oops", evidence="frame0")
        ar = HostileObservation(name="hostile-cget", description="d",
                                monitor_reports=[rpt]).to_attack_result()
        out = tmp_path / "r.sarif"
        write_sarif([ar], str(out))
        import json
        doc = json.loads(out.read_text())
        res = doc["runs"][0]["results"][0]
        assert res["properties"]["monitors"][0]["finding_type"] == "asan:heap-overflow"

    def test_sarif_severity_and_dedup(self, tmp_path):
        """A confirmed crash is an error and a clean result is a note.

        Identical findings must also share a partialFingerprint for dedup.
        """
        import json
        from c_scare.attacks import AttackResult
        from c_scare.monitor import MonitorReport
        from c_scare.runner import write_sarif

        def crash(name):
            rpt = MonitorReport(detected=True, finding_type="asan:heap-overflow",
                                description="oops", evidence="frame0\nframe1")
            return AttackResult(name=name, category="greybox", payload=b"x",
                                description="crash", expected_behavior="no crash",
                                success=True, monitor_reports=[rpt],
                                metadata={"crash_path": "fuzz/out/file/crashes/id:1"})

        clean = AttackResult(name="ok", category="parser", payload=b"x",
                             description="delivered", expected_behavior="ok",
                             success=None,
                             metadata={
                                 "started_at": "2026-07-29T10:00:00.000001+00:00",
                                 "ended_at": "2026-07-29T10:00:00.000250+00:00",
                                 "started_epoch_ns": 1785319200000001000,
                                 "ended_epoch_ns": 1785319200000250000,
                                 "duration_ms": 0.249,
                             })
        out = tmp_path / "r.sarif"
        write_sarif([crash("a"), crash("b"), clean], str(out))
        results = json.loads(out.read_text())["runs"][0]["results"]
        by_rule = {r["ruleId"]: r for r in results}

        assert by_rule["greybox/a"]["level"] == "error"
        assert by_rule["parser/ok"]["level"] == "note"
        # same stack -> same fingerprint (consumer collapses duplicate crashes)
        assert (by_rule["greybox/a"]["partialFingerprints"]
                == by_rule["greybox/b"]["partialFingerprints"])
        # grey-box crash carries its input path as a location
        assert (by_rule["greybox/a"]["locations"][0]["physicalLocation"]
                ["artifactLocation"]["uri"].endswith("id:1"))
        assert by_rule["parser/ok"]["properties"]["started_epoch_ns"] == 1785319200000001000
        assert by_rule["parser/ok"]["properties"]["duration_ms"] == 0.249

    def test_sarif_monitor_severity_tracks_evidence_strength(self, tmp_path):
        import json
        from c_scare.attacks import AttackResult
        from c_scare.monitor import MonitorReport
        from c_scare.runner import write_sarif

        def detected(name, finding_type):
            report = MonitorReport(
                detected=True,
                finding_type=finding_type,
                description=finding_type,
            )
            return AttackResult(
                name=name,
                category="severity",
                payload=b"x",
                description=name,
                expected_behavior="remain healthy",
                success=True,
                monitor_reports=[report],
            )

        results = [
            detected("reset", "network:connection_reset"),
            detected("timeout", "network:timeout"),
            detected("accepted", "protocol:accepted"),
            detected("resource", "resource:rss-growth"),
            detected("canary", "filesystem-canary"),
            detected("coredump", "target-coredump"),
            detected("crash", "crash:SIGSEGV"),
        ]
        out = tmp_path / "severity.sarif"
        write_sarif(results, str(out))
        by_rule = {
            result["ruleId"]: result
            for result in json.loads(out.read_text())["runs"][0]["results"]
        }

        assert by_rule["severity/reset"]["level"] == "warning"
        assert by_rule["severity/timeout"]["level"] == "warning"
        for name in ("accepted", "resource", "canary", "coredump", "crash"):
            assert by_rule[f"severity/{name}"]["level"] == "error"

    def test_monitored_delivery_records_execution_window(self, monkeypatch):
        from types import SimpleNamespace
        from c_scare.attacks import AttackResult
        from c_scare.monitor import MonitorReport
        from c_scare import runner

        class DummyMonitor:
            def pre_test(self, index):
                self.index = index

            def post_test(self):
                return MonitorReport(detected=False)

        def deliver_stub(_args, _result, _target, _timeout):
            return b"\x00", None

        monkeypatch.setattr(runner, "_deliver", deliver_stub)
        result = AttackResult(
            name="timed",
            category="parser",
            payload=b"x",
            description="timed delivery",
            expected_behavior="remain healthy",
        )

        runner._run_monitored_test(
            SimpleNamespace(_monitors=[DummyMonitor()]), result, ("127.0.0.1", 104), 1.0
        )

        assert result.metadata["started_epoch_ns"] <= result.metadata["ended_epoch_ns"]
        assert result.metadata["duration_ms"] >= 0
        assert result.metadata["started_at"].startswith("20")
        assert result.metadata["ended_at"].startswith("20")


class TestDeliveryRouting:
    """_delivery_kind routes payloads by --delivery mode and catalog metadata."""

    def _result(self, category="parser", metadata=None):
        from c_scare.attacks import AttackResult
        return AttackResult(name="t", category=category, payload=b"x",
                            description="d", expected_behavior="e",
                            metadata=metadata or {})

    def _args(self, delivery="auto"):
        import argparse
        return argparse.Namespace(delivery=delivery)

    def _write_cstore_file(self, tmp_path):
        import pytest
        pydicom = pytest.importorskip('pydicom')
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, SecondaryCaptureImageStorage

        path = tmp_path / 'known-good.dcm'
        sop_instance_uid = '1.2.826.0.1.3680043.10.543.1'
        meta = FileMetaDataset()
        meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
        meta.MediaStorageSOPInstanceUID = sop_instance_uid
        meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds = FileDataset(str(path), {}, file_meta=meta, preamble=b'\0' * 128)
        ds.is_little_endian = True
        ds.is_implicit_VR = False
        ds.SOPClassUID = SecondaryCaptureImageStorage
        ds.SOPInstanceUID = sop_instance_uid
        ds.PatientName = 'Good^Patient'
        ds.PatientID = 'GOODID'
        ds.Modality = 'OT'
        ds.StudyInstanceUID = '1.2.826.0.1.3680043.10.543.2'
        ds.SeriesInstanceUID = '1.2.826.0.1.3680043.10.543.3'
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = 'MONOCHROME2'
        ds.Rows = 1
        ds.Columns = 1
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7
        ds.PixelRepresentation = 0
        ds.PixelData = b'\x00'
        ds.save_as(path, write_like_original=False)
        return path

    def test_auto_routes_dataset_category_to_cstore(self):
        from c_scare.runner import _delivery_kind
        assert _delivery_kind(self._args("auto"),
                              self._result("parser")) == "cstore"
        assert _delivery_kind(self._args("auto"),
                              self._result("memory")) == "cstore"
        assert _delivery_kind(self._args("auto"),
                              self._result("logic")) == "cstore"
        assert _delivery_kind(self._args("auto"),
                              self._result("storage_abuse")) == "cstore"

    def test_auto_routes_metadata_sop_to_cstore(self):
        from c_scare.runner import _delivery_kind
        r = self._result("path_traversal",
                         {"sop_class_uid": "1.2.840.10008.5.1.4.1.1.7"})
        assert _delivery_kind(self._args("auto"), r) == "cstore"

    def test_auto_routes_cve_delivery_hint_to_cstore(self):
        from c_scare.runner import _delivery_kind
        r = self._result("cve", {"delivery_hint": "cstore"})
        assert _delivery_kind(self._args("auto"), r) == "cstore"

    def test_auto_routes_steps_to_sequence(self):
        from c_scare.runner import _delivery_kind
        r = self._result("state_machine", {"steps": [b"a", b"b"]})
        assert _delivery_kind(self._args("auto"), r) == "sequence"

    def test_auto_routes_protocol_to_pdu(self):
        from c_scare.runner import _delivery_kind
        assert _delivery_kind(self._args("auto"),
                              self._result("protocol")) == "pdu"

    def test_pdu_mode_forces_raw_pdu_for_datasets(self):
        from c_scare.runner import _delivery_kind
        assert _delivery_kind(self._args("pdu"),
                              self._result("parser")) == "pdu"

    def test_cstore_mode_forces_cstore(self):
        from c_scare.runner import _delivery_kind
        assert _delivery_kind(self._args("cstore"),
                              self._result("protocol")) == "cstore"

    def test_blackbox_catalog_delivery_runs_protocol_monitor(self, monkeypatch):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult
        from c_scare.monitor import ProtocolMonitor

        sent = []

        def fake_send_pdu(target, payload, timeout):
            sent.append((target, payload, timeout))
            return b'\x03' + b'\x00' * 10

        monkeypatch.setattr(runner.deliver, 'send_pdu', fake_send_pdu)
        args = argparse.Namespace(
            _monitors=[ProtocolMonitor()],
            target='127.0.0.1:11112',
            timeout=1.0,
            delivery='pdu',
            mutate=None,
        )
        result = AttackResult(
            name='probe', category='protocol', payload=b'payload',
            description='probe', expected_behavior='reject cleanly')

        runner._maybe_deliver(args, result, 0)

        assert sent == [(('127.0.0.1', 11112), b'payload', 1.0)]
        assert result.response == b'\x03' + b'\x00' * 10
        assert len(result.monitor_reports) == 1
        assert result.monitor_reports[0].detected is False

    def test_cstore_delivery_strips_part10_and_uses_file_meta(self, monkeypatch):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult
        from c_scare.file import DicomFile

        dataset = b'\x10\x00\x10\x00PN\x08\x00Doe^John'
        payload = DicomFile.build(
            dataset,
            sop_class_uid='1.2.840.10008.5.1.4.1.1.7',
            sop_instance_uid='1.2.3.4.5.6',
            transfer_syntax_uid='1.2.840.10008.1.2.1',
        )
        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0x0000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(delivery='auto', store_sop=None,
                                  store_transfer_syntax=None, mutate=None,
                                  ae_title='STORESCP', calling_ae='C-SCARE')
        result = AttackResult(
            name='part10-cve', category='cve', payload=payload,
            description='d', expected_behavior='e',
            metadata={'delivery_hint': 'cstore'})

        response, error = runner._deliver(args, result, ('127.0.0.1', 11112), 2.0)

        assert (response, error) == (b'\x00\x00', 'cstore_status')
        assert sent['args'] == (
            ('127.0.0.1', 11112), dataset,
            '1.2.840.10008.5.1.4.1.1.7', '1.2.3.4.5.6',
            '1.2.840.10008.1.2.1', 2.0, 'STORESCP', 'C-SCARE')
        assert result.metadata['cstore_stripped_part10'] is True

    def test_cstore_delivery_uses_cli_transfer_syntax(self, monkeypatch):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult

        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0x0000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            delivery='auto', store_sop='1.2.840.10008.5.1.4.1.1.7',
            store_transfer_syntax='1.2.840.10008.1.2.1', mutate=None,
            ae_title='PACS', calling_ae='MOVEDEST')
        result = AttackResult(
            name='dataset', category='storage_abuse', payload=b'DATASET',
            description='d', expected_behavior='e')

        response, error = runner._deliver(args, result, ('127.0.0.1', 104), 3.0)

        assert (response, error) == (b'\x00\x00', 'cstore_status')
        assert sent['args'] == (
            ('127.0.0.1', 104), b'DATASET',
            '1.2.840.10008.5.1.4.1.1.7', '1.2.3.4.5',
            '1.2.840.10008.1.2.1', 3.0, 'PACS', 'MOVEDEST')

    def test_sequence_delivery_renders_live_ae_titles(self, monkeypatch):
        import argparse
        import struct
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult

        assoc = (b'\x01\x00' + struct.pack('!I', 68) + b'\x00\x01\x00\x00' +
                 b'STORESCP        ' + b'C-SCARE-FZ      ' + b'\x00' * 32)
        sent = {}

        def fake_send_sequence(target, steps, timeout):
            sent['steps'] = steps
            return [b'\x02', b'\x05']

        monkeypatch.setattr(runner.deliver, 'send_sequence', fake_send_sequence)
        args = argparse.Namespace(delivery='auto', mutate=None,
                                  ae_title='PACS', calling_ae='MOVEDEST')
        result = AttackResult(
            name='cstore-state', category='storage_abuse', payload=b'',
            description='d', expected_behavior='e',
            metadata={'steps': [assoc, b'\x05\x00\x00\x00\x00\x04\x00\x00\x00\x00']})

        runner._deliver(args, result, ('127.0.0.1', 104), 2.0)

        rendered = sent['steps'][0]
        assert rendered[10:26] == b'PACS            '
        assert rendered[26:42] == b'MOVEDEST        '
        assert result.metadata['rendered_called_ae_title'] == 'PACS'
        assert result.metadata['rendered_calling_ae_title'] == 'MOVEDEST'

    def test_sequence_delivery_preserves_ae_title_tests(self, monkeypatch):
        import argparse
        import struct
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult

        assoc = (b'\x01\x00' + struct.pack('!I', 68) + b'\x00\x01\x00\x00' +
                 b'../ORTHO        '[:16] + b'C-SCARE-FZ      ' + b'\x00' * 32)
        sent = {}

        def fake_send_sequence(target, steps, timeout):
            sent['steps'] = steps
            return [b'\x02']

        monkeypatch.setattr(runner.deliver, 'send_sequence', fake_send_sequence)
        args = argparse.Namespace(delivery='auto', mutate=None,
                                  ae_title='PACS', calling_ae='MOVEDEST')
        result = AttackResult(
            name='worklist-called-ae', category='cve', payload=b'',
            description='Called AE Title traversal', expected_behavior='reject',
            metadata={'steps': [assoc], 'called_ae_title': '../ORTHO'})

        runner._deliver(args, result, ('127.0.0.1', 104), 2.0)

        assert sent['steps'][0] == assoc

    def test_cstore_smoke_sends_known_good_dataset(self, monkeypatch):
        import argparse
        import c_scare.runner as runner

        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0x0000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            store_sop='1.2.840.10008.5.1.4.1.1.7',
            store_transfer_syntax='1.2.840.10008.1.2.1',
            ae_title='PACS', calling_ae='MOVEDEST', timeout=4.0)

        assert runner._run_cstore_smoke(args, ('127.0.0.1', 104)) == 0

        target, payload, sop_class, _sop_inst, ts, timeout, called, calling = sent['args']
        assert target == ('127.0.0.1', 104)
        assert sop_class == '1.2.840.10008.5.1.4.1.1.7'
        assert ts == '1.2.840.10008.1.2.1'
        assert timeout == 4.0
        assert (called, calling) == ('PACS', 'MOVEDEST')
        assert b'C-SCARE^Smoke' in payload

    def test_cstore_smoke_file_sends_real_dataset(self, monkeypatch, tmp_path):
        import argparse
        import c_scare.runner as runner

        cstore_file = self._write_cstore_file(tmp_path)
        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0x0000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            cstore_file=str(cstore_file), store_sop=None,
            store_transfer_syntax=None, ae_title='PACS',
            calling_ae='MOVEDEST', timeout=10.0)

        assert runner._run_cstore_smoke(args, ('127.0.0.1', 104)) == 0

        _target, payload, sop_class, sop_inst, ts, _timeout, called, calling = sent['args']
        assert sop_class == '1.2.840.10008.5.1.4.1.1.7'
        assert sop_inst == '1.2.826.0.1.3680043.10.543.1'
        assert ts == '1.2.840.10008.1.2.1'
        assert (called, calling) == ('PACS', 'MOVEDEST')
        assert b'Good^Patient' in payload
        assert b'C-SCARE^Smoke' not in payload

    def test_cstore_file_mutates_storage_identity(self, monkeypatch, tmp_path):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult

        cstore_file = self._write_cstore_file(tmp_path)
        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0xC000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            delivery='auto', cstore_file=str(cstore_file), store_sop=None,
            store_transfer_syntax=None, mutate=None, ae_title='PACS',
            calling_ae='MOVEDEST')
        result = AttackResult(
            name='storage_empty_required_identity', category='storage_abuse',
            payload=b'synthetic', description='d', expected_behavior='e',
            metadata={'coverage_scope': 'identity-validation'})

        response, error = runner._deliver(args, result, ('127.0.0.1', 104), 6.0)

        assert (response, error) == (b'\xC0\x00', 'cstore_status')
        payload = sent['args'][1]
        assert b'Good^Patient' not in payload
        assert b'GOODID' not in payload
        assert result.metadata['cstore_file_mutation'] == 'empty_identity'

    def test_cstore_file_mutates_command_dataset_instance_conflict(self, monkeypatch, tmp_path):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult

        cstore_file = self._write_cstore_file(tmp_path)
        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0xC000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            delivery='auto', cstore_file=str(cstore_file), store_sop=None,
            store_transfer_syntax=None, mutate=None, ae_title='PACS',
            calling_ae='MOVEDEST')
        result = AttackResult(
            name='storage_command_dataset_instance_uid_conflict',
            category='storage_abuse', payload=b'synthetic', description='d',
            expected_behavior='e', metadata={
                'command_sop_instance_uid': '1.2.3.4.5',
                'dataset_sop_instance_uid': '1.2.3.4.5.31',
            })

        runner._deliver(args, result, ('127.0.0.1', 104), 6.0)

        _target, payload, _sop_class, sop_inst, _ts, _timeout, _called, _calling = sent['args']
        assert sop_inst == '1.2.3.4.5'
        assert b'1.2.3.4.5.31' in payload
        assert result.metadata['cstore_file_mutation'] == (
            'command_sop_instance_uid+dataset_sop_instance_uid')

    def test_cstore_file_applies_path_traversal_to_real_dataset(self, monkeypatch, tmp_path):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import PathTraversalAttacks

        cstore_file = self._write_cstore_file(tmp_path)
        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0xC000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            delivery='auto', cstore_file=str(cstore_file), store_sop=None,
            store_transfer_syntax=None, mutate=None, ae_title='PACS',
            calling_ae='MOVEDEST')
        result = PathTraversalAttacks.study_instance_uid_traversal('posix_proof')

        runner._deliver(args, result, ('127.0.0.1', 104), 6.0)

        _target, payload, _sop_class, sop_inst, _ts, _timeout, _called, _calling = sent['args']
        assert sop_inst == result.metadata['cstore_file_base_sop_instance_uid']
        assert b'C-SCARE^path_traversal_study_uid_posix_proof' in payload
        assert b'Good^Patient' not in payload
        assert b'GOODID' not in payload
        assert b'../../../../../../tmp/c-scare-traversal-proof' in payload
        assert payload.count(b'../../../../../../tmp/c-scare-traversal-proof') >= 2
        assert result.metadata['cstore_file_mutation'] == 'study_instance_uid'

    def test_cstore_file_stamps_unique_identity_for_appended_payloads(self, monkeypatch, tmp_path):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import AttackResult

        cstore_file = self._write_cstore_file(tmp_path)
        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0x0000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            delivery='auto', cstore_file=str(cstore_file), store_sop=None,
            store_transfer_syntax=None, mutate=None, ae_title='PACS',
            calling_ae='MOVEDEST')
        result = AttackResult(
            name='invalid_vr', category='parser', payload=b'attack',
            description='d', expected_behavior='e')

        runner._deliver(args, result, ('127.0.0.1', 104), 6.0)

        _target, payload, _sop_class, sop_inst, _ts, _timeout, _called, _calling = sent['args']
        assert sop_inst == result.metadata['cstore_file_base_sop_instance_uid']
        assert len(sop_inst) <= 64
        assert len(result.metadata['cstore_file_base_study_instance_uid']) <= 64
        assert len(result.metadata['cstore_file_base_series_instance_uid']) <= 64
        assert b'C-SCARE^invalid_vr' in payload
        assert b'Good^Patient' not in payload
        assert b'GOODID' not in payload
        assert payload.endswith(b'attack')
        assert result.metadata['cstore_file_mutation'] == 'append_attack_dataset'

    def test_cstore_file_applies_command_injection_to_real_dataset(self, monkeypatch, tmp_path):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import CommandInjectionAttacks

        cstore_file = self._write_cstore_file(tmp_path)
        sent = []

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent.append((target, payload, sop_class, sop_inst,
                         transfer_syntax, timeout, called_ae, calling_ae))
            return 0x0000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            delivery='auto', cstore_file=str(cstore_file), store_sop=None,
            store_transfer_syntax=None, mutate=None, ae_title='PACS',
            calling_ae='MOVEDEST')

        study = CommandInjectionAttacks.study_instance_uid_injection('semicolon')
        patient = CommandInjectionAttacks.patient_name_injection('newline')

        runner._deliver(args, study, ('127.0.0.1', 104), 6.0)
        runner._deliver(args, patient, ('127.0.0.1', 104), 6.0)

        _target, study_payload, _sop_class, study_sop_inst, _ts, _timeout, _called, _calling = sent[0]
        _target, patient_payload, _sop_class, patient_sop_inst, _ts, _timeout, _called, _calling = sent[1]
        assert study_sop_inst == study.metadata['cstore_file_base_sop_instance_uid']
        assert patient_sop_inst == patient.metadata['cstore_file_base_sop_instance_uid']
        assert b'C-SCARE^cmd_injection_study_uid_semicolon' in study_payload
        assert b'1.2.3.4.5.1; touch /tmp/c-scare-rce ;' in study_payload
        assert b'Doe^John\ntouch /tmp/c-scare-rce\n' in patient_payload
        assert study.metadata['cstore_file_mutation'] == 'study_instance_uid'
        assert patient.metadata['cstore_file_mutation'] == 'patient_name'

    def test_cstore_file_applies_multi_field_path_traversal_probe(self, monkeypatch, tmp_path):
        import argparse
        import c_scare.runner as runner
        from c_scare.attacks import PathTraversalAttacks

        cstore_file = self._write_cstore_file(tmp_path)
        sent = {}

        def fake_send_cstore(target, payload, sop_class, sop_inst,
                             transfer_syntax=None, timeout=5.0,
                             called_ae='TARGET', calling_ae='ATTACKER'):
            sent['args'] = (target, payload, sop_class, sop_inst,
                            transfer_syntax, timeout, called_ae, calling_ae)
            return 0xC000

        monkeypatch.setattr(runner.deliver, 'send_cstore', fake_send_cstore)
        args = argparse.Namespace(
            delivery='auto', cstore_file=str(cstore_file), store_sop=None,
            store_transfer_syntax=None, mutate=None, ae_title='PACS',
            calling_ae='MOVEDEST')
        result = PathTraversalAttacks.multi_field_storage_path_probe()

        runner._deliver(args, result, ('127.0.0.1', 104), 6.0)

        _target, payload, _sop_class, sop_inst, _ts, _timeout, _called, _calling = sent['args']
        assert sop_inst == result.metadata['sop_instance_uid']
        assert b'../../../../../../tmp/c-scare-traversal-proof/sop-instance' in payload
        assert b'../../../../../../tmp/c-scare-traversal-proof/study-instance' in payload
        assert b'../../../../../../tmp/c-scare-traversal-proof/series-instance' in payload
        assert b'../../../../../../tmp/c-scare-traversal-proof/patient-name' in payload
        assert result.metadata['cstore_file_mutation'] == 'cstore_field_overrides'

    def test_dcmtk_file_cves_auto_route_to_cstore(self):
        from c_scare.attacks import CVEAttacks
        from c_scare.runner import _delivery_kind

        expected = {
            'CVE-2022-2121', 'CVE-2024-28130', 'CVE-2024-47796',
            'CVE-2025-14607', 'CVE-2026-10528',
        }
        seen = {r.metadata.get('cve') for r in CVEAttacks.all()
                if _delivery_kind(self._args('auto'), r) == 'cstore'}
        assert expected <= seen


class TestSendCStore:
    """send_cstore must drive a real DICOMSession, not silently no-op.

    Regression: send_cstore previously imported DICOMSession from the wrong
    module (scapy_dicom instead of client), so the import raised ImportError,
    was swallowed, and every live C-STORE delivery returned None.
    """

    def test_resolvable_import(self):
        # The names send_cstore relies on must be importable from where it
        # looks for them; a wrong path is exactly the swallowed-ImportError bug.
        from c_scare.client import DICOMSession  # noqa: F401
        from c_scare.scapy_dicom import DEFAULT_TRANSFER_SYNTAX_UID  # noqa: F401

    def test_drives_session_and_returns_status(self, monkeypatch):
        import c_scare.client as client_mod
        from c_scare import deliver

        calls = {}

        class FakeSession:
            def __init__(self, *a, **k):
                calls["init"] = (a, k)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def associate(self, contexts, user_identity=None):
                calls["associate"] = (contexts, user_identity)
                return True

            def c_store(self, payload, sop_class_uid, sop_instance_uid, ts):
                calls["c_store"] = (payload, sop_class_uid, sop_instance_uid, ts)
                return 0x0000

        monkeypatch.setattr(client_mod, "DICOMSession", FakeSession)
        status = deliver.send_cstore(
            ("127.0.0.1", 104), b"DATASET", "1.2.840.10008.5.1.4.1.1.7",
            sop_instance_uid="1.2.3", user_identity={"username": "u"},
            called_ae="STORESCP", calling_ae="C-SCARE")
        assert status == 0x0000  # not None: the delivery path actually ran
        assert calls["init"][0] == ("127.0.0.1", 104, "STORESCP", "C-SCARE")
        assert calls["c_store"][0] == b"DATASET"
        assert calls["associate"][1] == {"username": "u"}


class TestCategoryCoverage:
    """`--category all` must actually mean all.

    A category the CLI accepts but `all` skips is silently missing from every
    run that does not name it — which is how state_machine went unrun.
    """

    # live_fuzz is a randomized loop sized by --live-fuzz-count, not a static
    # catalog, so `all` deliberately leaves it out. Any *other* omission is a bug.
    DELIBERATE_OMISSIONS = {'live_fuzz'}

    def _runner_source(self):
        import inspect
        import c_scare.runner as runner
        return runner, inspect.getsource(runner)

    def _category_map(self, source):
        import re
        block = re.search(r"category_map = \{(.*?)\n    \}", source, re.S).group(1)
        return dict(re.findall(r"'([a-z_]+)': '([a-z_]+)',", block))

    def test_runner_all_covers_every_category(self):
        import re
        _runner, source = self._runner_source()
        category_map = self._category_map(source)

        all_block = re.search(
            r"def run_all_tests.*?commands = \[(.*?)\]", source, re.S).group(1)
        run_by_all = set(re.findall(r"run_([a-z_]+)\)", all_block))

        expected = {
            command for category, command in category_map.items()
            if category != 'all' and category not in self.DELIBERATE_OMISSIONS
        }
        missing = expected - run_by_all
        assert not missing, (
            f"--category all skips: {sorted(missing)}. Add them to "
            f"run_all_tests or to DELIBERATE_OMISSIONS with a reason.")

    def test_every_cli_category_resolves_to_a_runner(self):
        import re
        runner, source = self._runner_source()
        category_map = self._category_map(source)

        choices = set(re.findall(
            r"'([a-z_]+)'",
            re.search(r"choices=\[('parser'.*?)\],", source, re.S).group(1)))
        unmapped = choices - set(category_map) - {'all'}
        assert not unmapped, f"--category accepts but cannot dispatch: {sorted(unmapped)}"

        commands_block = re.search(
            r"def run_command.*?commands = \{(.*?)\n    \}", source, re.S).group(1)
        dispatchable = set(re.findall(r"'([a-z_]+)':", commands_block))
        dangling = {c for c in category_map.values() if c not in dispatchable}
        assert not dangling, f"category_map points at missing runners: {sorted(dangling)}"

    def test_all_categories_reach_a_nonempty_catalog(self):
        """Every category must actually produce payloads."""
        from c_scare.attacks import (
            ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
            StorageSCPAbuseAttacks, CommandInjectionAttacks, PathTraversalAttacks,
            StateMachineAttacks, CVEAttacks, NegotiationAttacks, DimseNAttacks,
        )
        catalogs = {
            'parser': ParserAttacks, 'protocol': ProtocolAttacks,
            'memory': MemoryAttacks, 'logic': LogicAttacks,
            'storage_abuse': StorageSCPAbuseAttacks,
            'command_injection': CommandInjectionAttacks,
            'path_traversal': PathTraversalAttacks,
            'state_machine': StateMachineAttacks, 'cve': CVEAttacks,
            'negotiation': NegotiationAttacks, 'dimse_n': DimseNAttacks,
        }
        for category, cls in catalogs.items():
            results = list(cls.all())
            assert results, f'{category} yields no payloads'
            assert all(r.category for r in results), category
