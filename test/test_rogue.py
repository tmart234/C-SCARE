# SPDX-License-Identifier: GPL-2.0-only
"""SCU / client-fuzzing tests: a rogue SCP must not let a real client associate.

These cover the black-box SCU quadrant. RawSCP runs in-process on a worker
thread; a real pynetdicom SCU then attempts to associate and must fail.
"""

import logging
import time

import pytest

from c_scare import RawSCP
from c_scare.scapy_dicom import DICOM, A_ASSOCIATE_RJ, A_ABORT
from scapy.packet import raw

pytest.importorskip('pynetdicom')


def _start_rogue(port, response):
    """Start a rogue SCP that answers every A-ASSOCIATE-RQ with ``response``."""
    scp = RawSCP(host='127.0.0.1', port=port)

    @scp.on_associate_rq
    def _handle(conn, pdu_bytes, pkt):  # noqa: ARG001 - handler signature
        return response

    scp.start(blocking=False)
    time.sleep(0.5)
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
