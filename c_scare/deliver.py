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
from typing import List, Optional, Sequence, Tuple

__all__ = ['send_pdu', 'send_sequence', 'send_cstore']


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


def send_cstore(target: Tuple[str, int],
                payload: bytes,
                sop_class_uid: str,
                sop_instance_uid: str = '1.2.3.4.5',
                transfer_syntax: str = None,
                timeout: float = 5.0,
                user_identity=None,
                called_ae: str = 'TARGET',
                calling_ae: str = 'ATTACKER') -> Optional[int]:
    """Perform a DICOM C-STORE with the given dataset payload.

    Returns the DIMSE status code, or ``None`` if the operation failed.
    Requires Scapy and scapy_dicom.

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
    except ImportError:
        return None

    ts = transfer_syntax or DEFAULT_TRANSFER_SYNTAX_UID
    try:
        with DICOMSession(target[0], target[1], called_ae, calling_ae) as sock:
            if not sock.associate({sop_class_uid: [ts]}, user_identity=user_identity):
                return None
            return sock.c_store(payload, sop_class_uid, sop_instance_uid, ts)
    except Exception:
        return None
