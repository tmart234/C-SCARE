# SPDX-License-Identifier: GPL-2.0-only
"""How a payload reaches an archive, and how it is fetched back.

Two protocols put DICOM objects into an archive and take them out again: DIMSE
over an association, and DICOMweb over HTTP. They agree on almost nothing at
the wire level and on one thing that matters here — **what crosses**:

* **DIMSE C-STORE sends a Data Set.** PS3.10 defines the 128-byte File
  Preamble outside the Data Set, so it is never transmitted; the receiver
  writes its own. Bytes past the final Data Element go the same way.
* **DICOMweb STOW-RS sends files.** Instances go up as ``application/dicom``
  parts, byte for byte, preamble included, and WADO-RS returns them the same.

That difference used to be recorded the wrong way round, as a per-payload
``survives_cstore`` flag. It is not a property of a payload: the same polyglot
survives one transport and not the other. So a payload now declares *where its
content lives* (:data:`REGION_DATA_SET` or :data:`REGION_WHOLE_FILE`) and a
transport declares *what it carries*, and :func:`survives` puts the two
together. Adding a transport does not mean re-tagging the catalog.

The runner and the monitors talk to this module, not to ``deliver``,
``client`` or ``dicomweb`` directly, so a finding reads the same whichever
protocol produced it.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, NamedTuple, Optional

__all__ = [
    'REGION_DATA_SET',
    'REGION_WHOLE_FILE',
    'StoreOutcome',
    'RetrieveOutcome',
    'Transport',
    'DimseTransport',
    'DicomWebTransport',
    'survives',
    'for_args',
]

#: The payload's foreign content sits inside a Data Element, so every
#: transport carries it.
REGION_DATA_SET = 'data_set'

#: The content sits in the preamble or past the final Data Element, so only a
#: transport that moves whole files carries it.
REGION_WHOLE_FILE = 'whole_file'


class StoreOutcome(NamedTuple):
    """What one store attempt did, whatever protocol performed it.

    ``accepted`` is the question a payload asks of an archive and the only
    field a monitor needs. ``status`` is protocol-specific evidence — a DIMSE
    status or an HTTP one — and ``reason`` says why there is none.
    """
    accepted: bool
    status: Optional[int]
    reason: Optional[str]

    @property
    def delivered(self) -> bool:
        """True when the payload reached the archive's parser.

        A status means it certainly did. Otherwise the reason decides: a
        connection that dropped is the target's doing and a finding, while a
        rejected association or a missing dependency means the payload never
        arrived and the run learned nothing.
        """
        if self.status is not None:
            return True
        head = str(self.reason).split(':')[0]
        return head in ('refused', 'reset', 'timeout', 'no_status')


class RetrieveOutcome(NamedTuple):
    """What came back when an instance was fetched, or why nothing did."""
    data: Optional[bytes]
    reason: Optional[str]


@dataclass
class Transport:
    """Base class. Subclasses implement :meth:`store` and :meth:`retrieve`.

    ``carries_whole_file`` is the property the rest of the framework asks
    about, because it decides whether a given payload's mechanism is even
    present on the far side.
    """
    name: str = 'transport'
    carries_whole_file: bool = False

    def store(self, payload: bytes, *, sop_class_uid: str,
              sop_instance_uid: str, transfer_syntax: Optional[str] = None,
              study_instance_uid: Optional[str] = None,
              timeout: float = 10.0) -> StoreOutcome:
        raise NotImplementedError

    def retrieve(self, *, sop_class_uid: str, sop_instance_uid: str,
                 study_instance_uid: Optional[str] = None,
                 series_instance_uid: Optional[str] = None,
                 transfer_syntax: Optional[str] = None,
                 timeout: float = 10.0) -> RetrieveOutcome:
        raise NotImplementedError


@dataclass
class DimseTransport(Transport):
    """C-STORE to put an object in, C-GET to pull it back.

    ``carries_whole_file`` is False and that is not a shortcoming to fix: it
    is what PS3.10 says. C-STORE moves a Data Set, so a preamble-resident
    payload is not present on the receiving side at all.
    """
    host: str = '127.0.0.1'
    port: int = 104
    called_ae: str = 'TARGET'
    calling_ae: str = 'ATTACKER'
    name: str = 'dimse'
    carries_whole_file: bool = False

    @property
    def target(self):
        return (self.host, self.port)

    def store(self, payload, *, sop_class_uid, sop_instance_uid,
              transfer_syntax=None, study_instance_uid=None, timeout=10.0):
        from . import deliver
        outcome = deliver.send_cstore_outcome(
            self.target, payload, sop_class_uid, sop_instance_uid,
            transfer_syntax=transfer_syntax, timeout=timeout,
            called_ae=self.called_ae, calling_ae=self.calling_ae)
        from .monitor import stored_successfully
        return StoreOutcome(stored_successfully(outcome.status),
                            outcome.status, outcome.reason)

    def retrieve(self, *, sop_class_uid, sop_instance_uid,
                 study_instance_uid=None, series_instance_uid=None,
                 transfer_syntax=None, timeout=10.0):
        from .client import retrieve_instance
        outcome = retrieve_instance(
            self.target, sop_class_uid, sop_instance_uid,
            transfer_syntax=transfer_syntax, timeout=timeout,
            called_ae=self.called_ae, calling_ae=self.calling_ae)
        return RetrieveOutcome(outcome.data, outcome.reason)


@dataclass
class DicomWebTransport(Transport):
    """STOW-RS to put an object in, WADO-RS to pull it back.

    ``carries_whole_file`` is True: instances travel as ``application/dicom``,
    so the preamble crosses in both directions. This is the transport on which
    a preamble-resident polyglot is still a polyglot at the far end, and the
    only one on which a round trip can return ``survived_intact``.
    """
    base_url: str = ''
    verify_tls: bool = True
    headers: Dict[str, str] = field(default_factory=dict)
    name: str = 'dicomweb'
    carries_whole_file: bool = True

    def store(self, payload, *, sop_class_uid, sop_instance_uid,
              transfer_syntax=None, study_instance_uid=None, timeout=30.0):
        from . import dicomweb
        outcome = dicomweb.stow_rs(
            self.base_url, [payload], timeout=timeout,
            headers=self.headers, verify_tls=self.verify_tls)
        return StoreOutcome(outcome.accepted, outcome.status, outcome.reason)

    def retrieve(self, *, sop_class_uid, sop_instance_uid,
                 study_instance_uid=None, series_instance_uid=None,
                 transfer_syntax=None, timeout=30.0):
        from . import dicomweb
        if not (study_instance_uid and series_instance_uid):
            # WADO-RS addresses an instance by its full path. Without the
            # Study and Series UIDs there is no URL to request, and guessing
            # one would produce a 404 that reads like the archive dropped the
            # object.
            return RetrieveOutcome(None, 'no_study_series_uid')
        data, outcome = dicomweb.wado_rs_instance(
            self.base_url, study_instance_uid, series_instance_uid,
            sop_instance_uid, timeout=timeout, headers=self.headers,
            verify_tls=self.verify_tls)
        return RetrieveOutcome(data, outcome.reason)


def survives(payload_region: Optional[str], transport: Transport) -> bool:
    """Would this payload's foreign content exist on the far side?

    The one place the payload's ``region`` and the transport's
    ``carries_whole_file`` are combined. Anything that needs to know — whether
    to score a store as a finding, whether a round trip means anything — asks
    here rather than re-deriving it, so the two facts cannot drift apart.
    """
    if payload_region == REGION_WHOLE_FILE:
        return bool(transport.carries_whole_file)
    return True


def for_args(args: Any, target: Optional[tuple] = None) -> Transport:
    """Build the transport the CLI asked for.

    ``target`` is the ``(host, port)`` the caller already resolved, and wins
    over anything on ``args`` — the delivery paths receive it as an argument
    and it is what they are actually pointed at. Falling back to ``args``
    silently sent everything to the default port.

    Defaults to DIMSE, because ``--ip``/``--port`` is how every existing
    invocation names a target and changing that would break them.
    """
    base_url = getattr(args, 'dicomweb_url', None)
    if base_url:
        return DicomWebTransport(
            base_url=base_url,
            verify_tls=not getattr(args, 'insecure', False),
            headers=_auth_headers(args))
    if target:
        host, port = target[0], int(target[1])
    else:
        configured = getattr(args, 'target', '') or ''
        host, _, port_text = configured.rpartition(':')
        host = host or getattr(args, 'ip', '127.0.0.1')
        port = int(port_text) if port_text.isdigit() else 104
    return DimseTransport(
        host=host, port=port,
        called_ae=getattr(args, 'ae_title', 'TARGET'),
        calling_ae=getattr(args, 'calling_ae', 'ATTACKER'))


def _auth_headers(args: Any) -> Dict[str, str]:
    """Authorization for a DICOMweb endpoint, if the CLI supplied one.

    Most deployments sit behind a bearer token or basic auth, and a run that
    401s on every request reports nothing about the archive.
    """
    headers: Dict[str, str] = {}
    token = getattr(args, 'dicomweb_token', None)
    if token:
        headers['Authorization'] = f'Bearer {token}'
    return headers
