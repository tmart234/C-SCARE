# SPDX-License-Identifier: GPL-2.0-only
"""SCU / client-fuzzing tests: a rogue SCP must not let a real client associate.

These cover the black-box SCU quadrant. RawSCP runs in-process on a worker
thread; a real pynetdicom SCU then attempts to associate and must fail.
"""

import logging

import pytest

from c_scare import RawSCP
from c_scare.scapy_dicom import DICOM, A_ASSOCIATE_RJ, A_ABORT
from scapy.packet import raw

pytest.importorskip('pynetdicom')


@pytest.fixture(autouse=True)
def _quiet_logging():
    """Undo the process-global logging suppression after each test."""
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)


def _start_rogue(port, response):
    """Start a rogue SCP that answers every A-ASSOCIATE-RQ with ``response``.

    ``RawSCP.start`` completes bind() and listen() before returning, so the
    port accepts connections immediately and no readiness sleep is required.
    """
    scp = RawSCP(host='127.0.0.1', port=port)

    @scp.on_associate_rq
    def _handle(conn, pdu_bytes, pkt):  # noqa: ARG001 - handler signature
        return response

    scp.start(blocking=False)
    return scp


def _scu_associates(port):
    """Return True iff a real pynetdicom SCU can associate with ``port``."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification

    logging.disable(logging.CRITICAL)
    ae = AE()
    ae.add_requested_context(Verification)
    assoc = ae.associate('127.0.0.1', port)
    established = assoc.is_established
    if established:
        assoc.release()
    return established


def test_rogue_reject_blocks_scu():
    scp = _start_rogue(11531, raw(DICOM() / A_ASSOCIATE_RJ()))
    try:
        assert _scu_associates(11531) is False
    finally:
        scp.stop()


def test_rogue_abort_blocks_scu():
    scp = _start_rogue(11532, raw(DICOM() / A_ABORT()))
    try:
        assert _scu_associates(11532) is False
    finally:
        scp.stop()


import pytest as _pytest


# Each mode gets its own fixed, unique port. A previous version derived the
# port from ``hash(mode) % 30``, but Python randomizes string hashing per
# process (PYTHONHASHSEED), so two modes could collide on the same port and the
# second bind() would fail with EADDRINUSE -- flaky run to run.
_ROGUE_MODE_PORTS = {
    mode: 11540 + i
    for i, mode in enumerate([
        "malformed-subitems", "oversized-pdu", "truncated-pdu",
        "illegal-role", "out-of-state",
    ])
}


@_pytest.mark.parametrize("mode", list(_ROGUE_MODE_PORTS))
def test_rogue_malformation_modes_block_scu(mode):
    """Every Phase 2 rogue malformation mode must keep a real SCU from
    establishing a clean association (it rejects, aborts, or hangs/desyncs)."""
    from c_scare.hostile import rogue_response
    port = _ROGUE_MODE_PORTS[mode]
    scp = _start_rogue(port, rogue_response(mode))
    try:
        assert _scu_associates(port) is False
    finally:
        scp.stop()


def test_hostile_cget_pushes_malicious_store():
    """The hostile C-GET responder accepts an association and, on C-GET, pushes a
    path-traversal C-STORE sub-operation at the SCU without crashing the
    harness. We drive it with the in-process DICOMSession SCU so we can inspect
    the sub-op the client received."""
    from c_scare import WorkflowResponder, build_query, DICOMSession
    from c_scare.scapy_dicom import (
        PATIENT_ROOT_QR_GET_SOP_CLASS_UID, CT_IMAGE_STORAGE_SOP_CLASS_UID,
        DEFAULT_TRANSFER_SYNTAX_UID)

    responder = WorkflowResponder(host='127.0.0.1', port=11572,
                                  ae_title='C_SCARE_SCP', echo_roles=True)

    @responder.on_c_get
    def _get(resp, conn, ctx_id, cmd, data):
        resp.serve_cget_hostile(conn, ctx_id, cmd, mode='path-traversal')
        return None

    responder.start(blocking=False)
    try:
        query = build_query(level='study',
                            match_keys={(0x0020, 0x000D, 'UI'): '1.2.3'})
        contexts = {
            PATIENT_ROOT_QR_GET_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
            CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        }
        with DICOMSession('127.0.0.1', 11572, 'C_SCARE_SCP', 'C_SCARE',
                         read_timeout=5) as sock:
            assert sock.associate(contexts)
            out = sock.c_get(query, sop_class_uid=PATIENT_ROOT_QR_GET_SOP_CLASS_UID)
        # The client received exactly one (malicious) object and survived.
        assert out['num_objects'] == 1
    finally:
        responder.stop()


def test_cget_hands_back_the_peers_raw_dataset_bytes():
    """C-GET keeps the Data Set the peer sent, not just a parse of it.

    ``--verify-retrieval`` asks whether the *archive* altered a payload. It can
    only answer from the bytes that arrived: a decoded object re-serialised on
    the way out answers "what would pydicom write?", and pydicom writes
    conformant DICOM, which is not what a malformed object is. So c_get carries
    the raw Data Set alongside the decoded one, paired with the transfer syntax
    its presentation context negotiated.

    Driven with the hostile responder on purpose -- the object it pushes is a
    path-traversal C-STORE sub-operation, which is exactly the shape a writer
    would tidy up.
    """
    from c_scare import WorkflowResponder, build_query, DICOMSession
    from c_scare.carrier import split_part10
    from c_scare.client import render_retrieved
    from c_scare.scapy_dicom import (
        PATIENT_ROOT_QR_GET_SOP_CLASS_UID, CT_IMAGE_STORAGE_SOP_CLASS_UID,
        DEFAULT_TRANSFER_SYNTAX_UID)

    responder = WorkflowResponder(host='127.0.0.1', port=11573,
                                  ae_title='C_SCARE_SCP', echo_roles=True)

    @responder.on_c_get
    def _get(resp, conn, ctx_id, cmd, data):
        resp.serve_cget_hostile(conn, ctx_id, cmd, mode='path-traversal')
        return None

    responder.start(blocking=False)
    try:
        query = build_query(level='study',
                            match_keys={(0x0020, 0x000D, 'UI'): '1.2.3'})
        contexts = {
            PATIENT_ROOT_QR_GET_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
            CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID],
        }
        with DICOMSession('127.0.0.1', 11573, 'C_SCARE_SCP', 'C_SCARE',
                          read_timeout=5) as sock:
            assert sock.associate(contexts)
            out = sock.c_get(query,
                             sop_class_uid=PATIENT_ROOT_QR_GET_SOP_CLASS_UID)
    finally:
        responder.stop()

    raw_objects = out['raw_objects']
    assert len(raw_objects) == out['num_objects'] == 1
    raw, transfer_syntax = raw_objects[0]
    assert raw, 'the Data Set the peer sent was not kept'
    assert transfer_syntax == DEFAULT_TRANSFER_SYNTAX_UID

    # The traversal value the responder put in the SOP Instance UID is what a
    # comparison has to see, and it has to see it as bytes: pydicom warns on
    # this value and a writer would coerce it. (Note the responder sends the
    # catalog's explicit-VR bytes on an implicit-VR context, so this object
    # does not parse cleanly either -- all the more reason not to route it
    # through a parser on the way to a comparison.)
    assert b'../../../../../../tmp/c-scare-traversal' in raw

    # And the render step adds a File Meta group without touching the Data Set.
    rendered = render_retrieved(raw, transfer_syntax)
    _preamble, file_meta, dataset, _elements = split_part10(rendered)
    assert dataset == raw
    assert file_meta, 'no File Meta Information was built for the file'
