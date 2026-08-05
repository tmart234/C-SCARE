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
  * Findings convert to the catalog's ``AttackResult`` (e.g.
    :meth:`RoleNegotiationResult.to_attack_result`) so they flow through the
    existing SARIF writer.

The decisive capability across all of these is *reading the response payload*,
not just classifying accept/reject — see docs/dicom-attack-workflows.md.
"""

import uuid
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
    "RoleNegotiationResult",
    "HostileObservation",
    "AETResult",
    "CredResult",
    "QR_MODELS",
    "default_vr_for_tag",
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
class RoleNegotiationResult:
    """Outcome of a strict-peer C-GET role negotiation, convertible to the
    catalog AttackResult so it rides the same SARIF path.

    Both outcomes can be reportable, for opposite reasons:

    * ``aborted=True`` — the peer withheld the storage SCP role, so the C-GET
      could not proceed. Interop failure; ``success=False`` (SARIF ``error``).
    * granted to an *unauthenticated* requestor (``authenticated=False``) — the
      peer handed an anonymous SCU the Storage SCP role, which is what lets a
      C-GET pull objects back. That is an authorization finding in its own
      right, reported as ``authz_bypass`` with ``success=True``.

    A grant to a requestor that *did* authenticate is normal operation and is
    recorded without being flagged.
    """

    sop_class_uid: str
    requested_scp_role: int = 1
    granted_scp_role: int = 0
    aborted: bool = False
    authenticated: bool = False
    negotiated_roles: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_authz_bypass(self) -> bool:
        """The peer granted the storage SCP role without authenticating us."""
        return (not self.aborted
                and int(self.granted_scp_role) == 1
                and not self.authenticated)

    def to_attack_result(self):
        """Adapt to ``attacks.AttackResult`` for SARIF output."""
        from .attacks import AttackResult
        category = "role-negotiation"
        success = None
        expected = ("Peer should grant scp_role=1 for the storage SOP "
                    "class so a C-GET SCU can receive objects")
        if self.aborted:
            desc = (f"Peer withheld the storage SCP role for {self.sop_class_uid} "
                    f"(requested scp_role={self.requested_scp_role}, "
                    f"granted={self.granted_scp_role}); C-GET aborted")
            success = False
        elif self.is_authz_bypass:
            category = "authz_bypass"
            desc = (f"Peer granted the storage SCP role for {self.sop_class_uid} "
                    f"to an unauthenticated requestor (scp_role="
                    f"{self.granted_scp_role}); a C-GET SCU can retrieve "
                    f"objects with no credentials")
            expected = ("Peer should require authentication before granting "
                        "scp_role=1 for a storage SOP class")
            success = True
        else:
            desc = (f"Peer granted the storage SCP role for {self.sop_class_uid} "
                    f"(scp_role={self.granted_scp_role})")
        return AttackResult(
            name=f"storage-scp-role/{self.sop_class_uid}",
            category=category,
            payload=b"",
            description=desc,
            expected_behavior=expected,
            metadata={
                "sop_class_uid": self.sop_class_uid,
                "requested_scp_role": self.requested_scp_role,
                "granted_scp_role": self.granted_scp_role,
                "authenticated": self.authenticated,
                "negotiated_roles": dict(self.negotiated_roles),
            },
            success=success,
        )


@dataclass
class HostileObservation:
    """An observation from hostile/rogue mode, where the system under test is a
    CLIENT (SCU). Findings come from monitors watching the client process, so
    the ``monitor_reports`` are passed straight through to the SARIF detection
    block (``runner.write_sarif``)."""

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
    #: Set when the attempt never produced a DICOM answer (connection refused,
    #: timeout, reset). ``accepted`` and ``aet_recognized`` say nothing in that
    #: case - an unreachable target must not read as "every AET rejected", nor
    #: as "every AET recognized".
    error: Optional[str] = None

    @property
    def conclusive(self) -> bool:
        """True when the target actually answered, so the verdict means something."""
        return self.error is None and (self.accepted or self.reject is not None)


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
    #: Transport failure - no DICOM answer was received (see AETResult.error).
    error: Optional[str] = None
    #: False once the baseline probe shows the target accepts a credential it
    #: cannot possibly know, i.e. it is not checking identity at all. None when
    #: no baseline was run.
    identity_enforced: Optional[bool] = None
    #: True only for a credential this target actually validated. An accepted
    #: association is NOT evidence on its own: User Identity Negotiation is
    #: optional in DICOM, so most SCPs accept the association and ignore the
    #: sub-item entirely.
    credential_verified: bool = False
    #: Marks the synthetic credential used to calibrate the run.
    is_baseline: bool = False


def default_vr_for_tag(tag: int) -> str:
    """VR for ``tag`` from the DICOM data dictionary, or ``LO`` if unknown.

    Guessing ``LO`` for everything is wrong in ways that bite: Study Instance
    UID is UI, Study Date is DA, Patient Name is PN. Implicit VR hides the
    mistake because the VR is not on the wire, but an explicit-VR identifier
    built that way is malformed, and an SCP that validates the VR of a matching
    key can fail to match on a correctly-spelled value. Private and unknown
    tags legitimately fall back to LO.
    """
    try:
        from pydicom.datadict import dictionary_VR
        vr = dictionary_VR(tag)
    except Exception:
        return "LO"
    # Dictionary entries for ambiguous or multi-VR tags are written like
    # "US or SS"; pick the first, and never hand back a sequence VR here.
    vr = str(vr).split(" or ")[0].strip()
    if not vr or vr in ("SQ", "??"):
        return "LO"
    return vr


def build_query(level: str = "study",
                return_keys: Optional[Sequence] = None,
                match_keys: Optional[Dict[Any, Any]] = None) -> Dataset:
    """Build a sculpted C-FIND/C-MOVE/C-GET identifier dataset.

    ``level``      - one of patient/study/series/image (sets QueryRetrieveLevel).
                     An unrecognized level raises: an identifier with no
                     QueryRetrieveLevel is invalid, and silently omitting it
                     turns a typo into an unexplained empty result set.
    ``return_keys``- tags requested back with universal matching (empty value).
                     Each entry is ``(group, element[, vr])`` or an int tag. The
                     VR is looked up in the DICOM dictionary unless given
                     explicitly; private tags fall back to LO.
    ``match_keys`` - ``{(group, element[, vr]): value}`` matching constraints.

    The return-key discipline is the point: a key is returned only if it is in
    the set, so an operator must ask for exactly what they want.
    """
    ds = Dataset()
    key = level.lower() if isinstance(level, str) else level
    if key not in _QR_LEVEL:
        raise ValueError(
            f"unknown query level {level!r}; expected one of "
            f"{sorted(_QR_LEVEL)}")
    ds / Element(0x0008, 0x0052, "CS", _QR_LEVEL[key])  # QueryRetrieveLevel

    def _coerce(key):
        # Returns (group, element, vr)
        if isinstance(key, (tuple, list)):
            if len(key) == 3:
                return int(key[0]), int(key[1]), str(key[2])
            group, element = int(key[0]), int(key[1])
            return group, element, default_vr_for_tag((group << 16) | element)
        tag = int(key)
        return (tag >> 16) & 0xFFFF, tag & 0xFFFF, default_vr_for_tag(tag)

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
                if rj is None:
                    # associate() failed without an A-ASSOCIATE-RJ: the peer
                    # never answered. Reporting aet_recognized here would mark
                    # every AET valid against an unreachable host.
                    results.append(AETResult(
                        aet=aet, accepted=False,
                        error=sock.last_error or "no response from peer"))
                else:
                    results.append(AETResult(
                        aet=aet, accepted=False, reject=rj,
                        reason=classify_reject(rj),
                        aet_recognized=not reject_is_called_aet_unrecognized(rj),
                    ))
        except Exception as exc:
            results.append(AETResult(
                aet=aet, accepted=False, error=f"{type(exc).__name__}: {exc}"))
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
               timeout: float = 10.0,
               baseline: bool = True) -> List[CredResult]:
    """Brute-force User Identity credentials (workflow W2).

    Sends a real Type 0x58 sub-item per attempt and surfaces the Type 0x59
    server-response bytes when the peer returns one.

    **An accepted association is not evidence that a credential is valid.**
    User Identity Negotiation is optional in DICOM, so a great many SCPs accept
    the association and ignore the sub-item entirely. Taken at face value that
    makes the first credential tried look correct - and with
    ``stop_on_success`` the run then stops and reports it.

    So the run calibrates itself first: ``baseline=True`` submits one synthetic
    credential the target cannot know. If that is accepted, the target is not
    enforcing identity, every later acceptance is meaningless, and results are
    marked ``identity_enforced=False`` with ``credential_verified=False``.
    ``credential_verified`` is the field to report on; ``accepted`` only
    records what the association did.

    ``creds`` is a sequence of ``(username, passcode)`` (passcode ignored for
    non-type-2 identities, where ``username`` carries the token bytes).
    """
    if requested_contexts is None:
        from .scapy_dicom import VERIFICATION_SOP_CLASS_UID
        requested_contexts = {VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}

    def _attempt(username: str, passcode: str, is_baseline: bool = False) -> CredResult:
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
                return CredResult(
                    username=username, accepted=True, is_baseline=is_baseline,
                    server_response=sock.user_identity_response,
                )
            rj = sock.last_reject
            if rj is None:
                return CredResult(
                    username=username, accepted=False, is_baseline=is_baseline,
                    error=sock.last_error or "no response from peer")
            return CredResult(
                username=username, accepted=False, is_baseline=is_baseline,
                reject=rj, reason=classify_reject(rj),
                aet_problem=reject_is_called_aet_unrecognized(rj))
        except Exception as exc:
            return CredResult(username=username, accepted=False,
                              is_baseline=is_baseline,
                              error=f"{type(exc).__name__}: {exc}")
        finally:
            try:
                sock.__exit__(None, None, None)
            except Exception:
                pass

    results: List[CredResult] = []
    identity_enforced: Optional[bool] = None

    if baseline:
        # Random enough that no target could have it provisioned, and clearly
        # labelled so it is recognizable in the target's logs.
        probe_user = f"c-scare-baseline-{uuid.uuid4().hex[:16]}"
        probe = _attempt(probe_user, uuid.uuid4().hex, is_baseline=True)
        if probe.error is None:
            # Only conclusive when the peer actually answered.
            identity_enforced = not probe.accepted
        probe.identity_enforced = identity_enforced
        results.append(probe)
        if identity_enforced is False:
            # Nothing further can be learned about credentials from this target;
            # run the list anyway so the operator sees it was not a fluke, but
            # never mark any of it verified.
            for username, passcode in creds:
                attempt = _attempt(username, passcode)
                attempt.identity_enforced = False
                results.append(attempt)
            return results

    for username, passcode in creds:
        attempt = _attempt(username, passcode)
        attempt.identity_enforced = identity_enforced
        # A credential counts as verified only when the target demonstrably
        # discriminates. A Type 0x59 response is the affirmative signal; with a
        # passing baseline, an accepted association is sufficient evidence.
        attempt.credential_verified = bool(
            attempt.accepted and identity_enforced is not False)
        results.append(attempt)
        if attempt.credential_verified and stop_on_success:
            break
    return results
