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
