# SPDX-License-Identifier: GPL-2.0-only
"""
Thin network delivery layer for C-SCARE attack payloads.

All attack classes generate payloads (bytes) without touching the network.
This module delivers those payloads to a target DICOM endpoint.
"""

import socket
from typing import List, Optional, Tuple

__all__ = ['send_pdu', 'send_sequence', 'send_cstore']


def send_pdu(target: Tuple[str, int],
             payload: bytes,
             timeout: float = 5.0) -> Optional[bytes]:
    """Send a single PDU and return the response (or ``None`` on timeout)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(target)
        sock.sendall(payload)
        try:
            return sock.recv(65536)
        except socket.timeout:
            return None
    finally:
        sock.close()


def send_sequence(target: Tuple[str, int],
                  steps: List[bytes],
                  timeout: float = 5.0) -> List[Optional[bytes]]:
    """Send a sequence of PDUs on one connection, collecting responses."""
    responses: List[Optional[bytes]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(target)
        for step in steps:
            sock.sendall(step)
            try:
                responses.append(sock.recv(65536))
            except socket.timeout:
                responses.append(None)
    finally:
        sock.close()
    return responses


def send_cstore(target: Tuple[str, int],
                payload: bytes,
                sop_class_uid: str,
                sop_instance_uid: str = '1.2.3.4.5',
                transfer_syntax: str = None,
                timeout: float = 5.0) -> Optional[int]:
    """Perform a DICOM C-STORE with the given dataset payload.

    Returns the DIMSE status code, or ``None`` if the operation failed.
    Requires Scapy and scapy_dicom.
    """
    try:
        from .scapy_dicom import (
            DICOMSocket, DEFAULT_TRANSFER_SYNTAX_UID,
        )
    except ImportError:
        return None

    ts = transfer_syntax or DEFAULT_TRANSFER_SYNTAX_UID
    try:
        with DICOMSocket(target[0], target[1], 'TARGET', 'ATTACKER') as sock:
            if not sock.associate({sop_class_uid: [ts]}):
                return None
            return sock.c_store(payload, sop_class_uid, sop_instance_uid, ts)
    except Exception:
        return None
