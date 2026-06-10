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
        from c_scare.test_runner import write_sarif
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
        """A detection (success=True) is an 'error'; a clean result (None) is a
        'note'. Regression: detections previously rendered as the lowest level.
        Identical findings must also share a partialFingerprint for dedup."""
        import json
        from c_scare.attacks import AttackResult
        from c_scare.monitor import MonitorReport
        from c_scare.test_runner import write_sarif

        def crash(name):
            rpt = MonitorReport(detected=True, finding_type="asan:heap-overflow",
                                description="oops", evidence="frame0\nframe1")
            return AttackResult(name=name, category="greybox", payload=b"x",
                                description="crash", expected_behavior="no crash",
                                success=True, monitor_reports=[rpt],
                                metadata={"crash_path": "fuzz/out/file/crashes/id:1"})

        clean = AttackResult(name="ok", category="parser", payload=b"x",
                             description="delivered", expected_behavior="ok",
                             success=None)
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

    def test_auto_routes_dataset_category_to_cstore(self):
        from c_scare.test_runner import _delivery_kind
        assert _delivery_kind(self._args("auto"),
                              self._result("parser")) == "cstore"
        assert _delivery_kind(self._args("auto"),
                              self._result("memory")) == "cstore"

    def test_auto_routes_metadata_sop_to_cstore(self):
        from c_scare.test_runner import _delivery_kind
        r = self._result("path_traversal",
                         {"sop_class_uid": "1.2.840.10008.5.1.4.1.1.7"})
        assert _delivery_kind(self._args("auto"), r) == "cstore"

    def test_auto_routes_steps_to_sequence(self):
        from c_scare.test_runner import _delivery_kind
        r = self._result("state_machine", {"steps": [b"a", b"b"]})
        assert _delivery_kind(self._args("auto"), r) == "sequence"

    def test_auto_routes_protocol_to_pdu(self):
        from c_scare.test_runner import _delivery_kind
        assert _delivery_kind(self._args("auto"),
                              self._result("protocol")) == "pdu"

    def test_pdu_mode_forces_raw_pdu_for_datasets(self):
        from c_scare.test_runner import _delivery_kind
        assert _delivery_kind(self._args("pdu"),
                              self._result("parser")) == "pdu"

    def test_cstore_mode_forces_cstore(self):
        from c_scare.test_runner import _delivery_kind
        assert _delivery_kind(self._args("cstore"),
                              self._result("protocol")) == "cstore"


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
            sop_instance_uid="1.2.3", user_identity={"username": "u"})
        assert status == 0x0000  # not None: the delivery path actually ran
        assert calls["c_store"][0] == b"DATASET"
        assert calls["associate"][1] == {"username": "u"}
