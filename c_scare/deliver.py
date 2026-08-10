# SPDX-License-Identifier: GPL-2.0-only
"""
Thin network delivery layer for C-SCARE attack payloads.

All attack classes generate payloads (bytes) without touching the network.
This module delivers those payloads to a target DICOM endpoint.

Two transport details matter here and are handled in one place so every
delivery path inherits them:

* **PDU framing.** A DICOM peer speaks PDUs, not TCP segments. A single
  ``recv()`` may return a fragment of one PDU or several aggregated PDUs, so
  responses are framed with :func:`~c_scare.scapy_dicom.read_dul_pdu` — the
  same primitive ``DICOMSocket`` and ``server.RawSCP`` use.
* **Teardown.** Closing an associated socket outright makes the peer's DUL
  provider log a protocol error and can get the source address blocklisted.
  Every connection is torn down with an A-ABORT first.
"""

import socket
import time
from typing import List, NamedTuple, Optional, Sequence, Tuple

__all__ = [
    'CStoreOutcome',
    'CSTORE_REASONS',
    'send_pdu',
    'send_sequence',
    'send_cstore',
    'send_cstore_outcome',
    'RetrieveOutcome',
    'retrieve_instance',
]


# Why a C-STORE produced no DIMSE status. The distinction that matters to a
# caller is whether the *target* did something (and the run learned
# something) or whether the payload never got there (and the run learned
# nothing) - collapsing the two makes an undelivered payload read like a
# target that went quiet.
CSTORE_UNAVAILABLE = 'unavailable'   # scapy/client not importable here
CSTORE_REJECTED = 'rejected'         # peer sent an A-ASSOCIATE-RJ
CSTORE_NO_CONTEXT = 'no_context'     # associated, but our SOP class/TS was not accepted
CSTORE_UNREACHABLE = 'unreachable'   # the TCP connection could not be made
CSTORE_REFUSED = 'refused'           # TCP connection refused
CSTORE_RESET = 'reset'               # connection reset mid-exchange
CSTORE_TIMEOUT = 'timeout'           # no answer within the timeout
CSTORE_NO_STATUS = 'no_status'       # object sent, no C-STORE-RSP came back

#: Reasons that describe something the target did. The rest mean the payload
#: never reached the target's parser, so they support no conclusion about it.
#: Refused/reset/timeout are on the target side here for the same reason the
#: raw-PDU path treats them that way: against a target that answered the
#: opening smoke test, they are how a process that has died presents.
CSTORE_REASONS = {
    CSTORE_UNAVAILABLE: False,
    CSTORE_REJECTED: False,
    CSTORE_NO_CONTEXT: False,
    CSTORE_UNREACHABLE: False,
    CSTORE_REFUSED: True,
    CSTORE_RESET: True,
    CSTORE_TIMEOUT: True,
    CSTORE_NO_STATUS: True,
}


class CStoreOutcome(NamedTuple):
    """What one C-STORE attempt actually did.

    ``status`` is the DIMSE status when the exchange completed and ``None``
    otherwise; ``reason`` says why not, and is ``None`` on success. They are
    separate fields because "the target rejected my object", "the target
    stopped answering" and "I never reached the target" used to be the same
    value, which let a run that delivered nothing look like a run that found
    nothing.
    """
    status: Optional[int]
    reason: Optional[str]

    @property
    def delivered(self) -> bool:
        """True when the payload reached the target's parser.

        A DIMSE status means it certainly did. A dropped or silent connection
        means it very likely did and the target is the reason it stopped -
        which is a finding, not a delivery problem. Everything else means it
        did not.
        """
        if self.status is not None:
            return True
        return CSTORE_REASONS.get(str(self.reason).split(':')[0], False)


def _read_response(sock: socket.socket, timeout: float) -> Optional[bytes]:
    """Read exactly one framed PDU from ``sock``.

    Returns ``None`` when nothing came back (timeout or the peer closed), and
    the complete PDU otherwise.

    The ``None`` return is load-bearing: ``monitor.ProtocolMonitor`` reports a
    ``None`` response as ``network:timeout`` and a zero-length response as
    ``network:empty_response`` — two different findings. ``read_dul_pdu``
    collapses both timeout and clean EOF to ``b""``, so it is mapped back to
    ``None`` here rather than reporting an empty response the peer never sent.
    """
    try:
        from .scapy_dicom import read_dul_pdu
    except ImportError:
        # Scapy is unavailable; fall back to an unframed read. This keeps the
        # black-box paths working without scapy, at the cost of the PDU
        # framing guarantee above.
        try:
            return sock.recv(65536) or None
        except socket.timeout:
            return None
    return read_dul_pdu(sock, timeout=timeout) or None


def _abort_and_close(sock: socket.socket) -> None:
    """Tear down ``sock`` with an A-ABORT, then close it.

    A bare ``close()`` on an open association leaves the peer to discover the
    disconnect as a transport error; PS3.8 §9.3.8 wants an A-ABORT PDU.
    Sending one keeps the target's logs readable and avoids tripping rate
    limiters that watch for aborted connections. Best-effort — the peer may
    already be gone, which is exactly the case a crash test is trying to
    produce.
    """
    try:
        from scapy.packet import raw

        from .scapy_dicom import DICOM, A_ABORT
        sock.sendall(raw(DICOM() / A_ABORT(source=0, reason_diag=0)))
    except Exception:
        pass
    try:
        sock.close()
    except OSError:
        pass


def send_pdu(target: Tuple[str, int],
             payload: bytes,
             timeout: float = 5.0) -> Optional[bytes]:
    """Send a single PDU and return the response (or ``None`` on timeout)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(target)
        sock.sendall(payload)
        return _read_response(sock, timeout)
    finally:
        _abort_and_close(sock)


def send_sequence(target: Tuple[str, int],
                  steps: List[bytes],
                  timeout: float = 5.0,
                  expect_response: Optional[Sequence[bool]] = None,
                  step_delay: float = 0.0) -> List[Optional[bytes]]:
    """Send a sequence of PDUs on one connection, collecting responses.

    By default every step blocks for one framed PDU, which is right for a
    lock-step exchange (A-ASSOCIATE-RQ -> A-ASSOCIATE-AC).

    ``expect_response`` gives a per-step override. Steps marked ``False`` are
    fired without waiting and record ``None`` in the returned list. This is
    what a state-machine sequence wants: only the association request is
    answered one-for-one, while pipelined P-DATA-TF and a trailing A-ABORT
    draw no reply at all and would otherwise burn the full ``timeout`` each —
    turning a sub-second sequence into a multi-minute one, and spacing the
    steps so far apart the peer never sees them as a sequence.

    ``step_delay`` inserts a pause between steps for a target that needs a
    moment to advance its state machine.
    """
    responses: List[Optional[bytes]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(target)
        for i, step in enumerate(steps):
            sock.sendall(step)
            wait = True if expect_response is None else bool(
                expect_response[i] if i < len(expect_response) else False)
            responses.append(_read_response(sock, timeout) if wait else None)
            if step_delay and i < len(steps) - 1:
                time.sleep(step_delay)
    finally:
        _abort_and_close(sock)
    return responses


def _associate_failure_reason(session) -> str:
    """Why ``DICOMSession.associate`` returned ``False``.

    It collapses four outcomes into one ``False``, and they are not the same
    result: nothing listening on the port, an explicit A-ASSOCIATE-RJ, and a
    peer that went silent mid-handshake mean a dead target, a working target
    and a possibly-dying target respectively. The session records enough to
    tell them apart — ``last_reject`` for a rejection, ``last_error`` for
    everything the transport caught — so the distinction is recovered here
    rather than reported as whichever one came first in the code.
    """
    if getattr(session, 'last_reject', None):
        return CSTORE_REJECTED
    error = getattr(session, 'last_error', None) or ''
    if error.startswith('ConnectionRefusedError'):
        return CSTORE_REFUSED
    if error.startswith('ConnectionResetError'):
        return CSTORE_RESET
    if error.startswith(('timeout', 'TimeoutError', 'no response')):
        return CSTORE_TIMEOUT
    if error:
        # Some other transport failure — host unreachable, DNS, a bad bind.
        # Name the exception type so it stays triageable.
        return f'{CSTORE_UNREACHABLE}:{error.split(":")[0]}'
    return CSTORE_REJECTED


def send_cstore_outcome(target: Tuple[str, int],
                        payload: bytes,
                        sop_class_uid: str,
                        sop_instance_uid: str = '1.2.3.4.5',
                        transfer_syntax: str = None,
                        timeout: float = 5.0,
                        user_identity=None,
                        called_ae: str = 'TARGET',
                        calling_ae: str = 'ATTACKER') -> CStoreOutcome:
    """Perform a DICOM C-STORE, reporting both the status and why there isn't
    one. Requires Scapy and scapy_dicom.

    This is :func:`send_cstore` with the failure reason kept instead of
    discarded. A bare status cannot distinguish these, and they call for
    opposite responses from an operator:

    * the SCP refused the association, or accepted it but not our SOP class —
      the target is working and the payload never reached a parser, so the run
      learned nothing about it and should say so;
    * the connection was refused, reset, or went silent after the object was
      sent — the target is the reason, and that is a finding;
    * scapy is not importable — the run is misconfigured, and reporting that
      as target behaviour would be a fabrication.

    ``user_identity`` (a dict / ``DICOMUserIdentity``) lets a DAST C-STORE
    attack authenticate via User Identity Negotiation first, so payload
    delivery can start from an associated state against an auth-gated SCP —
    the workflow-as-precondition synergy.

    Datasets larger than the negotiated Maximum Length are fragmented across
    multiple P-DATA-TF PDUs by :meth:`DICOMSession.c_store`, so callers do not
    need to pre-chunk large payloads.
    """
    try:
        from .client import DICOMSession
        from .scapy_dicom import DEFAULT_TRANSFER_SYNTAX_UID
    except ImportError as exc:
        return CStoreOutcome(None, f'{CSTORE_UNAVAILABLE}:{exc.name or "scapy"}')

    ts = transfer_syntax or DEFAULT_TRANSFER_SYNTAX_UID
    try:
        with DICOMSession(target[0], target[1], called_ae, calling_ae) as sock:
            if not sock.associate({sop_class_uid: [ts]},
                                  user_identity=user_identity):
                return CStoreOutcome(None, _associate_failure_reason(sock))

            # c_store() returns None for "no presentation context was
            # accepted" and for "no C-STORE-RSP came back", which are a
            # negotiation outcome and a possible crash respectively. The
            # accepted-context table settles which one this was before the
            # information is lost.
            status = sock.c_store(payload, sop_class_uid, sop_instance_uid, ts)
            if status is not None:
                return CStoreOutcome(status, None)
            negotiated = any(
                abs_syntax == sop_class_uid and ts_syntax == ts
                for abs_syntax, ts_syntax in sock.accepted_contexts.values())
            return CStoreOutcome(
                None, CSTORE_NO_STATUS if negotiated else CSTORE_NO_CONTEXT)
    except ConnectionRefusedError:
        return CStoreOutcome(None, CSTORE_REFUSED)
    except ConnectionResetError:
        return CStoreOutcome(None, CSTORE_RESET)
    except socket.timeout:
        return CStoreOutcome(None, CSTORE_TIMEOUT)
    except Exception as exc:
        # Anything left is a fault in this tool or an unmodelled transport
        # error. Naming the type keeps it triageable instead of silently
        # becoming an absent response.
        return CStoreOutcome(None, f'error:{type(exc).__name__}')


class RetrieveOutcome(NamedTuple):
    """What came back when an instance was fetched from the archive.

    ``data`` is the retrieved object re-serialised as Part-10 bytes, or
    ``None``. ``reason`` says why not. As with :class:`CStoreOutcome`, the two
    are separate because "the archive returned nothing" and "the retrieve
    never ran" are different results.
    """
    data: Optional[bytes]
    reason: Optional[str]


def retrieve_instance(target: Tuple[str, int],
                      sop_class_uid: str,
                      sop_instance_uid: str,
                      transfer_syntax: str = None,
                      timeout: float = 10.0,
                      called_ae: str = 'TARGET',
                      calling_ae: str = 'ATTACKER') -> RetrieveOutcome:
    """Fetch one stored instance back with C-GET, on a single association.

    C-GET rather than C-MOVE because it needs no inbound listener and no AE
    registration on the target — the objects come back as C-STORE
    sub-operations on the same association. The cost is that fewer archives
    implement it; a C-MOVE path would need a Storage SCP of our own running
    and the target configured to know it.

    The SCU proposes the Storage SCP role for ``sop_class_uid``, without which
    the archive has nowhere to send the sub-operation.

    Note what the returned bytes are: a re-serialisation of the Data Set the
    archive sent, not the file on its disk. C-GET moves Data Sets, so the
    128-byte preamble is ours, not theirs — which is exactly why
    :func:`~c_scare.polyglot.compare_after_pipeline` reports the offset-0
    header separately from the private-element content.
    """
    try:
        from io import BytesIO

        import pydicom

        from .client import DICOMSession
        from .scapy_dicom import (
            DEFAULT_TRANSFER_SYNTAX_UID, STUDY_ROOT_QR_GET_SOP_CLASS_UID,
        )
    except ImportError as exc:
        return RetrieveOutcome(None, f'{CSTORE_UNAVAILABLE}:{exc.name or "scapy"}')

    ts = transfer_syntax or DEFAULT_TRANSFER_SYNTAX_UID
    try:
        with DICOMSession(target[0], target[1], called_ae, calling_ae) as sock:
            contexts = {
                STUDY_ROOT_QR_GET_SOP_CLASS_UID: [ts],
                sop_class_uid: [ts],
            }
            if not sock.associate(contexts,
                                  roles={sop_class_uid: (1, 1)}):
                return RetrieveOutcome(None, _associate_failure_reason(sock))

            query = pydicom.Dataset()
            query.QueryRetrieveLevel = 'IMAGE'
            query.StudyInstanceUID = ''
            query.SeriesInstanceUID = ''
            query.SOPInstanceUID = sop_instance_uid
            result = sock.c_get(
                query, sop_class_uid=STUDY_ROOT_QR_GET_SOP_CLASS_UID)

            objects = result.get('objects') or []
            if not objects:
                return RetrieveOutcome(
                    None, f'no_objects:status={result.get("status")}')

            retrieved = objects[0]
            if not hasattr(retrieved, 'file_meta') or not retrieved.file_meta:
                meta = pydicom.dataset.FileMetaDataset()
                meta.MediaStorageSOPClassUID = sop_class_uid
                meta.MediaStorageSOPInstanceUID = sop_instance_uid
                meta.TransferSyntaxUID = ts
                retrieved.file_meta = meta
            retrieved.preamble = b'\x00' * 128
            buffer = BytesIO()
            retrieved.save_as(buffer, enforce_file_format=True)
            return RetrieveOutcome(buffer.getvalue(), None)
    except ConnectionRefusedError:
        return RetrieveOutcome(None, CSTORE_REFUSED)
    except ConnectionResetError:
        return RetrieveOutcome(None, CSTORE_RESET)
    except socket.timeout:
        return RetrieveOutcome(None, CSTORE_TIMEOUT)
    except Exception as exc:
        return RetrieveOutcome(None, f'error:{type(exc).__name__}')


def send_cstore(target: Tuple[str, int],
                payload: bytes,
                sop_class_uid: str,
                sop_instance_uid: str = '1.2.3.4.5',
                transfer_syntax: str = None,
                timeout: float = 5.0,
                user_identity=None,
                called_ae: str = 'TARGET',
                calling_ae: str = 'ATTACKER') -> Optional[int]:
    """Perform a DICOM C-STORE and return the DIMSE status, or ``None``.

    The status-only view of :func:`send_cstore_outcome`, kept because it is
    the published signature. Prefer the outcome form where the difference
    between "rejected" and "never delivered" matters, which for anything
    reporting results is always.
    """
    return send_cstore_outcome(
        target, payload, sop_class_uid, sop_instance_uid,
        transfer_syntax=transfer_syntax, timeout=timeout,
        user_identity=user_identity, called_ae=called_ae,
        calling_ae=calling_ae).status
