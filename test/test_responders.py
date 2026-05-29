# SPDX-License-Identifier: GPL-2.0-only
"""SCP-side workflow responder tests (Phase 1).

Each test stands up a C-SCARE WorkflowResponder and drives it with a *real*
pynetdicom SCU, asserting the client gets through association and DIMSE. This
covers the SCU-exercising (client-fuzzing) half of the workflows — the mirror
of test_workflows.py.

Contrast with test_rogue.py: there a malformed AC blocks the client; here a
conformant AC (accept_association) lets it through to the DIMSE stage.
"""

import logging
import time

import pytest

pytest.importorskip("pynetdicom")

from c_scare import (  # noqa: E402
    WorkflowResponder, build_cfind_rsp_stream, accept_association,
)

HOST = "127.0.0.1"


def _quiet():
    logging.disable(logging.CRITICAL)


def _start(responder):
    responder.start(blocking=False)
    time.sleep(0.5)
    return responder


def test_accept_association_lets_a_real_scu_associate_and_echo():
    """A conformant AC (the piece RawSCP lacked) lets a real SCU associate and
    the default C-ECHO handler answers Success."""
    _quiet()
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification

    responder = _start(WorkflowResponder(host=HOST, port=11630,
                                         ae_title="C_SCARE_SCP"))
    try:
        ae = AE()
        ae.add_requested_context(Verification)
        assoc = ae.associate(HOST, 11630)
        assert assoc.is_established
        status = assoc.send_c_echo()
        assert status and status.Status == 0x0000
        assoc.release()
    finally:
        responder.stop()


def test_responder_injects_implementation_version_name():
    """The SCP-side W1 payload: a custom Implementation Version Name shows up in
    the AC the client receives."""
    _quiet()
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification

    # Implementation Version Name is SH (max 16 chars); a strict SCU rejects
    # longer values, so a long flag belongs in the Implementation Class UID arc.
    responder = _start(WorkflowResponder(
        host=HOST, port=11631, ae_title="C_SCARE_SCP",
        implementation_version_name="C_SCARE_RSP_42"))
    try:
        ae = AE()
        ae.add_requested_context(Verification)
        assoc = ae.associate(HOST, 11631)
        assert assoc.is_established
        ver = assoc.acceptor.implementation_version_name
        if isinstance(ver, bytes):
            ver = ver.decode()
        assert ver == "C_SCARE_RSP_42"
        assoc.release()
    finally:
        responder.stop()


def test_responder_serves_cfind_stream_to_a_real_scu():
    """A C-FIND SCU receives the sculpted stream the responder serves —
    exercising the client's C-FIND-RSP handling end to end."""
    _quiet()
    from pynetdicom import AE
    from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelFind
    from pydicom.dataset import Dataset

    responder = WorkflowResponder(host=HOST, port=11632, ae_title="C_SCARE_SCP")

    matches = []
    for uid, desc in (("1.2.1", "FLAG_DESC"), ("1.2.2", "CHEST_CT")):
        ds = Dataset()
        ds.QueryRetrieveLevel = "STUDY"
        ds.StudyInstanceUID = uid
        ds.StudyDescription = desc
        matches.append(ds)

    @responder.on_c_find
    def _find(resp, conn, ctx_id, cmd, data):
        from c_scare.scapy_dicom import PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, parse_dimse_command_us
        msg_id = parse_dimse_command_us(cmd, 0x0000, 0x0110) or 1
        return build_cfind_rsp_stream(
            ctx_id, msg_id, matches,
            sop_class_uid=PATIENT_ROOT_QR_FIND_SOP_CLASS_UID, implicit_vr=True)

    _start(responder)
    try:
        ae = AE()
        ae.add_requested_context(PatientRootQueryRetrieveInformationModelFind)
        assoc = ae.associate(HOST, 11632)
        assert assoc.is_established

        query = Dataset()
        query.QueryRetrieveLevel = "STUDY"
        query.StudyInstanceUID = ""
        query.StudyDescription = ""

        received = []
        for status, identifier in assoc.send_c_find(
                query, PatientRootQueryRetrieveInformationModelFind):
            if status and status.Status in (0xFF00, 0xFF01) and identifier is not None:
                received.append(identifier)
        assoc.release()

        assert len(received) == 2
        descs = {getattr(d, "StudyDescription", None) for d in received}
        assert "FLAG_DESC" in descs
    finally:
        responder.stop()


# --------------------------------------------------------------------------
# Issuer <-> responder round-trips: validate both halves of a workflow at once.
# --------------------------------------------------------------------------

def test_w1_aet_keyed_responder_vs_ae_brute():
    """W1 both directions: an AET-keyed responder accepts one Called AE Title
    (advertising an impl version) and rejects others with
    called-AE-title-not-recognized; ae_brute reads that back."""
    from c_scare import ae_brute

    responder = _start(WorkflowResponder(
        host=HOST, port=11634, ae_title="C_SCARE_SCP",
        known_aets={"GOOD_AET": {"implementation_version_name": "FLAG_VER_1"}}))
    try:
        results = {r.aet: r for r in ae_brute(
            HOST, 11634, ["GOOD_AET", "BAD_AET"], calling_ae="C_SCARE", timeout=5.0)}
        assert results["GOOD_AET"].accepted is True
        assert results["GOOD_AET"].implementation_version_name == "FLAG_VER_1"
        assert results["BAD_AET"].accepted is False
        assert results["BAD_AET"].aet_recognized is False
        assert results["BAD_AET"].reason == "called-AE-title-not-recognized"
    finally:
        responder.stop()


def test_w2_require_identity_responder_vs_cred_brute():
    """W2 both directions: a require-and-validate responder returns the 0x59
    payload only on the right credential; cred_brute surfaces it. Mirrors the
    username+passcode (type 2) + 0x59 scenario end to end between two C-SCARE
    endpoints."""
    from c_scare import cred_brute

    FLAG = b"flag{0x58_passed_2026}"

    def check(ident):
        ok = ident["primary"] == b"admin" and ident["secondary"] == b"s3cret"
        return ok, (FLAG if ok else None)

    responder = _start(WorkflowResponder(
        host=HOST, port=11635, ae_title="C_SCARE_SCP", require_identity=check))
    try:
        results = cred_brute(
            HOST, 11635, "C_SCARE_SCP",
            creds=[("admin", "wrong"), ("admin", "s3cret")],
            identity_type=2, stop_on_success=False, timeout=5.0)
        by_user = {(r.username, r.accepted): r for r in results}
        ok = [r for r in results if r.accepted]
        assert len(ok) == 1 and ok[0].server_response == FLAG
        bad = [r for r in results if not r.accepted][0]
        assert bad.aet_problem is False  # cred is the problem, not the AET
    finally:
        responder.stop()


def test_w5_cmove_responder_vs_cmove_issuer():
    """W5 both directions: the responder reports sub-op counts in C-MOVE-RSP;
    the issuer parses them."""
    from c_scare import DICOMSocket, build_query, build_cmove_rsp
    from c_scare.scapy_dicom import (
        PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, DEFAULT_TRANSFER_SYNTAX_UID,
        parse_dimse_command_us, STATUS_SUCCESS)

    responder = WorkflowResponder(host=HOST, port=11636, ae_title="C_SCARE_SCP")

    @responder.on_c_move
    def _move(resp, conn, ctx_id, cmd, data):
        msg_id = parse_dimse_command_us(cmd, 0x0000, 0x0110) or 1
        return build_cmove_rsp(ctx_id, msg_id, STATUS_SUCCESS, completed=2,
                               sop_class_uid=PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID)

    _start(responder)
    try:
        query = build_query(level="study",
                            match_keys={(0x0020, 0x000D, "UI"): "1.2.3"})
        with DICOMSocket(HOST, 11636, "C_SCARE_SCP", "C_SCARE", read_timeout=5) as sock:
            assert sock.associate(
                {PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]})
            out = sock.c_move(query, "RESEARCH_VIEWER",
                              sop_class_uid=PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID)
        assert out["status"] == STATUS_SUCCESS
        assert out["completed"] == 2
    finally:
        responder.stop()


def test_w4_cget_responder_vs_cget_issuer():
    """W4 both directions: the responder delivers objects as inbound C-STORE
    sub-operations on the negotiated storage context; the c_get issuer collects
    them and parses their metadata. Validates the experimental c_get issuer and
    the C-GET responder against each other."""
    from pydicom.dataset import Dataset
    from c_scare import DICOMSocket, build_query
    from c_scare.scapy_dicom import (
        PATIENT_ROOT_QR_GET_SOP_CLASS_UID, CT_IMAGE_STORAGE_SOP_CLASS_UID,
        DEFAULT_TRANSFER_SYNTAX_UID, STATUS_SUCCESS)

    def _obj(uid, desc):
        ds = Dataset()
        ds.SOPClassUID = CT_IMAGE_STORAGE_SOP_CLASS_UID
        ds.SOPInstanceUID = uid
        ds.StudyDescription = desc
        return (CT_IMAGE_STORAGE_SOP_CLASS_UID, uid, ds)

    objects = [_obj("1.2.10", "FLAG_OBJ_A"), _obj("1.2.11", "OBJ_B")]

    responder = WorkflowResponder(host=HOST, port=11637, ae_title="C_SCARE_SCP")

    @responder.on_c_get
    def _get(resp, conn, ctx_id, cmd, data):
        resp.serve_cget(conn, ctx_id, cmd, objects)
        return None

    _start(responder)
    try:
        query = build_query(level="study",
                            match_keys={(0x0020, 0x000D, "UI"): "1.2.3"})
        contexts = {
            PATIENT_ROOT_QR_GET_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
            CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        }
        with DICOMSocket(HOST, 11637, "C_SCARE_SCP", "C_SCARE", read_timeout=5) as sock:
            assert sock.associate(contexts)
            out = sock.c_get(query, sop_class_uid=PATIENT_ROOT_QR_GET_SOP_CLASS_UID)
        assert out["status"] == STATUS_SUCCESS
        assert out["num_objects"] == 2
        descs = {getattr(o, "StudyDescription", None) for o in out["objects"]}
        assert "FLAG_OBJ_A" in descs
    finally:
        responder.stop()


def test_reject_association_blocks_scu():
    """A custom reject (called-AE-title-not-recognized) is delivered to the
    client — the SCP-side mirror of the AE-title axis."""
    _quiet()
    from c_scare import RawSCP
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification

    scp = RawSCP(host=HOST, port=11633)

    @scp.on_associate_rq
    def _rq(conn, pdu_bytes, pkt):
        from c_scare import reject_association
        return reject_association(result=1, source=1, reason=7)

    scp.start(blocking=False)
    time.sleep(0.4)
    try:
        ae = AE()
        ae.add_requested_context(Verification)
        assoc = ae.associate(HOST, 11633)
        assert assoc.is_established is False
    finally:
        scp.stop()
