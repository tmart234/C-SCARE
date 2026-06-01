# SPDX-License-Identifier: GPL-2.0-only
"""SCU-side workflow tests (Phase 0 issuer drivers).

Each test stands up a real pynetdicom SCP and drives a C-SCARE workflow against
it, asserting the *decisive capability*: read the response payload, not just
accept/reject. Covers W1 (ae_brute), W2 (cred_brute / User Identity 0x59),
W3 (c_find sculpting + stream count), and W5 (c_move counts parsing).
"""

import time

import pytest

pytest.importorskip("pynetdicom")

from pydicom.dataset import Dataset as PydicomDataset  # noqa: E402

from c_scare import ae_brute, cred_brute, build_query, DICOMSession  # noqa: E402
from c_scare.scapy_dicom import (  # noqa: E402
    VERIFICATION_SOP_CLASS_UID,
    PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
    PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
    DEFAULT_TRANSFER_SYNTAX_UID,
    STATUS_SUCCESS,
)

HOST = "127.0.0.1"


def _shutdown(server):
    try:
        server.shutdown()
    except Exception:
        pass


# --------------------------------------------------------------------------
# W1 — AE Title brute force
# --------------------------------------------------------------------------

def test_ae_brute_reads_ac_payload_of_accepted_aet():
    """Only one Called AE Title associates; ae_brute must report its AC payload
    (implementation version name), not merely 'accepted'."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification

    ae = AE()
    ae.ae_title = "RAD_BACKUP_2017"
    ae.require_called_aet = True
    ae.add_supported_context(Verification)
    server = ae.start_server((HOST, 11620), block=False)
    time.sleep(0.4)
    try:
        results = ae_brute(
            HOST, 11620,
            ["GENERIC_SCP", "RAD_BACKUP_2017", "NOPE"],
            calling_ae="C_SCARE", timeout=5.0,
        )
        by_aet = {r.aet: r for r in results}
        assert by_aet["RAD_BACKUP_2017"].accepted is True
        assert by_aet["GENERIC_SCP"].accepted is False
        assert by_aet["NOPE"].accepted is False
        # Decisive capability: we read the *value* of the AC payload, not just
        # that it accepted (and not the field's class name — see getfieldval).
        ver = by_aet["RAD_BACKUP_2017"].implementation_version_name
        assert ver and "PYNETDICOM" in ver
        assert by_aet["RAD_BACKUP_2017"].application_context_uid == \
            "1.2.840.10008.3.1.1.1"
        assert by_aet["RAD_BACKUP_2017"].implementation_class_uid
    finally:
        _shutdown(server)


def test_ae_brute_and_cred_brute_are_independent_axes():
    """A wrong AE title and a bad credential reject with *different* codes, so
    each axis is brute-forceable on its own.

    Isolate the AET axis by NOT sending credentials (servers commonly check
    identity before the AET, so sending creds can mask the AET code). Then
    brute credentials against the discovered AET.
    """
    from pynetdicom import AE, evt
    from pynetdicom.sop_class import Verification

    def handle_user_id(event):
        return (event.primary_field == b"GOOD"), None

    ae = AE()
    ae.ae_title = "REAL_AET"
    ae.require_called_aet = True
    ae.add_supported_context(Verification)
    server = ae.start_server(
        (HOST, 11624), block=False,
        evt_handlers=[(evt.EVT_USER_ID, handle_user_id)],
    )
    time.sleep(0.4)
    try:
        # AE-title axis: no identity sent, so the AET check is what fails.
        ae_results = {
            r.aet: r for r in ae_brute(
                HOST, 11624, ["WRONG_AET", "REAL_AET"],
                calling_ae="C_SCARE", timeout=5.0)
        }
        # Wrong AET -> called-AE-title-not-recognized; AET axis not solved.
        assert ae_results["WRONG_AET"].accepted is False
        assert ae_results["WRONG_AET"].aet_recognized is False
        assert ae_results["WRONG_AET"].reason == "called-AE-title-not-recognized"
        # Right AET (no identity required for a bare association here) -> the
        # AET axis is solved.
        assert ae_results["REAL_AET"].aet_recognized is True
        wrong_reject = ae_results["WRONG_AET"].reject

        # Credential axis against the discovered AET: GOOD passes, BAD fails
        # with an ACSE reject that is NOT an AET problem and whose reject code
        # differs from the wrong-AET case.
        cred_results = cred_brute(
            HOST, 11624, "REAL_AET", creds=[("BAD", ""), ("GOOD", "")],
            identity_type=3, stop_on_success=False, timeout=5.0)
        by_user = {r.username: r for r in cred_results}
        assert by_user["GOOD"].accepted is True
        assert by_user["BAD"].accepted is False
        assert by_user["BAD"].aet_problem is False
        # The decisive point: the two failure modes are distinguishable.
        assert by_user["BAD"].reject != wrong_reject
    finally:
        _shutdown(server)


# --------------------------------------------------------------------------
# W2 — User Identity credential brute force (0x58 / 0x59)
# --------------------------------------------------------------------------

def test_cred_brute_surfaces_0x59_server_response():
    """The Type 0x59 server-response payload appears only on a valid credential
    and must be surfaced to the caller.

    Uses identity type 3 (Kerberos): per PS3.7 D.3.3.7 the server response is a
    types-3/4/5 artifact, and pynetdicom (acse.py) only returns it for those
    types. Type-2 acceptance is signalled by association success with no 0x59 —
    cred_brute reports that via ``accepted`` regardless.
    """
    from pynetdicom import AE, evt
    from pynetdicom.sop_class import Verification

    FLAG = b"flag{0x58_passed_2026}"
    GOOD_TICKET = "KERB_TICKET_GOOD"

    def handle_user_id(event):
        if event.user_id_type in (3, 4, 5) and event.primary_field == GOOD_TICKET.encode():
            return True, FLAG
        return False, None

    ae = AE()
    ae.add_supported_context(Verification)
    server = ae.start_server(
        (HOST, 11621), block=False,
        evt_handlers=[(evt.EVT_USER_ID, handle_user_id)],
    )
    time.sleep(0.4)
    try:
        results = cred_brute(
            HOST, 11621, "ANY-SCP",
            creds=[("BAD_TICKET", ""), (GOOD_TICKET, ""), ("guest", "")],
            calling_ae="C_SCARE", identity_type=3,
            stop_on_success=True, timeout=5.0,
        )
        ok = [r for r in results if r.accepted]
        assert len(ok) == 1
        assert ok[0].username == GOOD_TICKET
        assert ok[0].server_response == FLAG
        # stop_on_success: we stopped before trying 'guest'.
        assert all(r.username != "guest" for r in results)
    finally:
        _shutdown(server)


# --------------------------------------------------------------------------
# W3 — Sculpted C-FIND (stream enumeration + identifier parse)
# --------------------------------------------------------------------------

def _study(study_uid, desc, patient):
    ds = PydicomDataset()
    ds.QueryRetrieveLevel = "STUDY"
    ds.StudyInstanceUID = study_uid
    ds.StudyDescription = desc
    ds.PatientName = patient
    return ds


def test_c_find_enumerates_stream_and_parses_identifiers():
    from pynetdicom import AE, evt
    from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelFind

    studies = [
        _study("1.2.3.1", "FLAG_STUDY_DESC", "Doe^John"),
        _study("1.2.3.2", "CHEST_CT", "Roe^Jane"),
        _study("1.2.3.3", "MR_BRAIN", "Poe^Sam"),
    ]

    def handle_find(event):
        for ds in studies:
            if event.is_cancelled:
                yield (0xFE00, None)
                return
            yield (0xFF00, ds)  # Pending
        yield (0x0000, None)    # Success

    ae = AE()
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelFind)
    server = ae.start_server(
        (HOST, 11622), block=False,
        evt_handlers=[(evt.EVT_C_FIND, handle_find)],
    )
    time.sleep(0.4)
    try:
        query = build_query(level="study",
                            return_keys=[(0x0008, 0x1030), (0x0020, 0x000D)])
        with DICOMSession(HOST, 11622, "ANY-SCP", "C_SCARE", read_timeout=5) as sock:
            assert sock.associate(
                {PATIENT_ROOT_QR_FIND_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]})
            responses = sock.c_find(
                query, sop_class_uid=PATIENT_ROOT_QR_FIND_SOP_CLASS_UID)

        identifiers = [d for _s, d in responses if d is not None]
        assert len(identifiers) == 3  # full stream enumerated
        descs = {getattr(d, "StudyDescription", None) for d in identifiers}
        assert "FLAG_STUDY_DESC" in descs
        # terminal status is Success
        assert responses[-1][0] == STATUS_SUCCESS
    finally:
        _shutdown(server)


# --------------------------------------------------------------------------
# W5 — C-MOVE pivot (request issuance + counts/status parsing)
# --------------------------------------------------------------------------

def test_c_move_parses_status_and_counts():
    from pynetdicom import AE, evt
    from pynetdicom.sop_class import PatientRootQueryRetrieveInformationModelMove

    def handle_move(event):
        # Unknown destination -> pynetdicom returns a failure status. We only
        # need to confirm the issuer parses status + counts off the RSP.
        yield (None, None)

    ae = AE()
    ae.add_supported_context(PatientRootQueryRetrieveInformationModelMove)
    server = ae.start_server(
        (HOST, 11623), block=False,
        evt_handlers=[(evt.EVT_C_MOVE, handle_move)],
    )
    time.sleep(0.4)
    try:
        query = build_query(level="study", match_keys={(0x0020, 0x000D, "UI"): "1.2.3.1"})
        with DICOMSession(HOST, 11623, "ANY-SCP", "C_SCARE", read_timeout=5) as sock:
            assert sock.associate(
                {PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]})
            out = sock.c_move(query, "RESEARCH_VIEWER",
                              sop_class_uid=PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID)
        assert out["status"] is not None       # a terminal status was parsed
        assert out["responses"]                 # at least one RSP captured
    finally:
        _shutdown(server)
