# SPDX-License-Identifier: GPL-2.0-only
"""DICOMweb client: STOW-RS and WADO-RS over HTTP (PS3.18).

The HTTP counterpart of :mod:`c_scare.client`, which speaks DIMSE over an
association. Both put objects into an archive and fetch them back; what
separates them is what actually crosses the wire, and for this project that
difference is the whole point:

* **C-STORE carries a Data Set.** The 128-byte File Preamble is a *file*
  construct PS3.10 defines outside the Data Set, so it is never transmitted -
  the receiving SCP writes its own. Anything past the final Data Element goes
  the same way.
* **STOW-RS carries files.** Instances are posted as ``application/dicom``
  parts, byte for byte, preamble included. WADO-RS returns them the same way.

So a polyglot whose second format lives in the preamble simply does not exist
on the far side of a C-STORE, and does on the far side of a STOW-RS POST. That
is measured in ``test_delivery_safety.py`` rather than assumed, and it is why
:mod:`c_scare.transport` asks a transport whether it ``carries_whole_file``
instead of asking a payload whether it "survives C-STORE".

Deliberately stdlib-only. ``urllib.request`` does everything needed here, and
DICOMweb is a plain multipart HTTP API - not enough surface to justify adding
a dependency to a tool that installs into clinical-adjacent environments.
"""

import re
import ssl
import urllib.error
import urllib.request
import uuid
from typing import Dict, List, NamedTuple, Optional, Tuple

__all__ = [
    'DICOM_MEDIA_TYPE',
    'WebOutcome',
    'stow_rs',
    'wado_rs_instance',
    'build_multipart',
    'split_multipart',
]

#: The media type a DICOM instance travels under in both directions (PS3.18).
DICOM_MEDIA_TYPE = 'application/dicom'

# Why a DICOMweb request produced no usable result. Deliberately the same
# vocabulary as client.ASSOC_* where the meanings line up, so a monitor does
# not need to know which transport produced a reason.
WEB_UNREACHABLE = 'unreachable'
WEB_REFUSED = 'refused'
WEB_TIMEOUT = 'timeout'
WEB_REJECTED = 'rejected'        # the server answered, and said no
WEB_NO_OBJECTS = 'no_objects'    # 200/204 with nothing in the body


class WebOutcome(NamedTuple):
    """What one DICOMweb request did.

    ``status`` is the HTTP status when the server answered, ``None`` when the
    request never got that far. ``reason`` says why not. The split is the same
    one :class:`c_scare.deliver.CStoreOutcome` makes and for the same reason:
    "the archive refused this" and "I never reached the archive" are different
    results that must not collapse into one value.
    """
    status: Optional[int]
    reason: Optional[str]
    body: bytes = b''

    @property
    def accepted(self) -> bool:
        """True if the archive stored what was posted.

        PS3.18 has STOW-RS answer 200 when every instance was stored and 202
        when some were - both mean at least one landed, which is what a
        payload asking "will you keep this?" needs to know. 409 and 400 are
        refusals.
        """
        return self.status in (200, 202)


def build_multipart(parts: List[bytes],
                    media_type: str = DICOM_MEDIA_TYPE
                    ) -> Tuple[bytes, str]:
    """Encode ``parts`` as a ``multipart/related`` body.

    Returns ``(body, boundary)``. Each part carries ``media_type`` and its
    bytes verbatim - no transfer encoding, no rewriting - because a payload
    that the transport reshaped is no longer the payload under test.
    """
    boundary = f'cscare-{uuid.uuid4().hex}'
    chunks: List[bytes] = []
    for part in parts:
        chunks.append(f'--{boundary}\r\n'.encode('ascii'))
        chunks.append(f'Content-Type: {media_type}\r\n'.encode('ascii'))
        chunks.append(f'Content-Length: {len(part)}\r\n\r\n'.encode('ascii'))
        chunks.append(part)
        chunks.append(b'\r\n')
    chunks.append(f'--{boundary}--\r\n'.encode('ascii'))
    return b''.join(chunks), boundary


def split_multipart(body: bytes, content_type: str) -> List[bytes]:
    """Pull the parts out of a ``multipart/related`` response body.

    Written by hand rather than through :mod:`email` because these bodies are
    binary and may be malformed - the archive under test is not assumed to be
    well behaved, and a parser that raises on a bad boundary would turn a
    finding into a traceback.
    """
    match = re.search(r'boundary="?([^";]+)"?', content_type or '')
    if not match:
        return [body] if body else []
    delimiter = b'--' + match.group(1).strip().encode('ascii')

    parts: List[bytes] = []
    for segment in body.split(delimiter):
        if not segment or segment.startswith(b'--'):
            continue          # preamble, epilogue, or the closing delimiter
        header_end = segment.find(b'\r\n\r\n')
        if header_end == -1:
            continue
        payload = segment[header_end + 4:]
        if payload.endswith(b'\r\n'):
            payload = payload[:-2]
        if payload:
            parts.append(payload)
    return parts


def _request(url: str, *, method: str, data: Optional[bytes] = None,
             headers: Optional[Dict[str, str]] = None,
             timeout: float = 30.0,
             verify_tls: bool = True) -> WebOutcome:
    """One HTTP round trip, with failures named rather than raised.

    ``verify_tls=False`` exists because clinical DICOMweb endpoints routinely
    present self-signed or internal-CA certificates, and refusing to talk to
    them would make the tool useless in exactly the environments it is for.
    It is opt-in per call and the caller has to ask for it.
    """
    request = urllib.request.Request(url, data=data, method=method,
                                     headers=headers or {})
    context = None
    if url.lower().startswith('https') and not verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=context) as response:
            return WebOutcome(response.status, None, response.read())
    except urllib.error.HTTPError as exc:
        # The server answered; a 4xx/5xx is a result, not a delivery failure.
        return WebOutcome(exc.code, WEB_REJECTED, exc.read() or b'')
    except urllib.error.URLError as exc:
        inner = exc.reason
        if isinstance(inner, ConnectionRefusedError):
            return WebOutcome(None, WEB_REFUSED)
        if isinstance(inner, TimeoutError):
            return WebOutcome(None, WEB_TIMEOUT)
        return WebOutcome(None, f'{WEB_UNREACHABLE}:{type(inner).__name__}')
    except TimeoutError:
        return WebOutcome(None, WEB_TIMEOUT)
    except Exception as exc:
        return WebOutcome(None, f'error:{type(exc).__name__}')


def stow_rs(base_url: str, instances: List[bytes], *,
            study_instance_uid: Optional[str] = None,
            timeout: float = 30.0,
            headers: Optional[Dict[str, str]] = None,
            verify_tls: bool = True) -> WebOutcome:
    """POST complete Part-10 instances to a STOW-RS endpoint (PS3.18 §10.5).

    ``base_url`` is the DICOMweb root, e.g. ``http://host:8042/dicom-web``.
    Posting to ``/studies`` lets the archive place each instance by its own
    Study Instance UID; passing ``study_instance_uid`` targets
    ``/studies/{uid}`` instead, which some archives require.

    The instances go up byte for byte. That is the property that matters: a
    preamble-resident polyglot arrives intact here and does not over C-STORE.
    """
    url = base_url.rstrip('/') + '/studies'
    if study_instance_uid:
        url += '/' + study_instance_uid
    body, boundary = build_multipart(instances)
    request_headers = {
        'Content-Type': f'multipart/related; type="{DICOM_MEDIA_TYPE}"; '
                        f'boundary={boundary}',
        'Accept': 'application/dicom+json',
    }
    request_headers.update(headers or {})
    return _request(url, method='POST', data=body, headers=request_headers,
                    timeout=timeout, verify_tls=verify_tls)


def wado_rs_instance(base_url: str, study_instance_uid: str,
                     series_instance_uid: str, sop_instance_uid: str, *,
                     timeout: float = 30.0,
                     headers: Optional[Dict[str, str]] = None,
                     verify_tls: bool = True
                     ) -> Tuple[Optional[bytes], WebOutcome]:
    """Fetch one instance back as a complete Part-10 file (PS3.18 §10.4).

    Returns ``(instance_bytes, outcome)``. The bytes are what the archive
    holds, preamble included - which is what makes a DICOMweb round trip able
    to answer whether a polyglot is still a polyglot, where a C-GET round trip
    can only speak for the Data Set.
    """
    url = (f'{base_url.rstrip("/")}/studies/{study_instance_uid}'
           f'/series/{series_instance_uid}/instances/{sop_instance_uid}')
    request_headers = {
        'Accept': f'multipart/related; type="{DICOM_MEDIA_TYPE}"',
    }
    request_headers.update(headers or {})
    outcome = _request(url, method='GET', headers=request_headers,
                       timeout=timeout, verify_tls=verify_tls)
    if outcome.status != 200:
        return None, outcome

    # The Content-Type is needed to find the boundary, and _request does not
    # keep response headers; re-derive it from the body's own first delimiter
    # when the server did not echo one we can see.
    parts = split_multipart(outcome.body, _sniff_boundary(outcome.body))
    if not parts:
        return None, WebOutcome(outcome.status, WEB_NO_OBJECTS, outcome.body)
    return parts[0], outcome


def _sniff_boundary(body: bytes) -> str:
    """Recover the multipart boundary from the body's opening delimiter.

    A DICOMweb response always opens with ``--<boundary>\\r\\n``, so the
    boundary is readable from the body itself. Doing it this way keeps
    :func:`_request` free of header plumbing that only one caller needs.
    """
    first_line = body.split(b'\r\n', 1)[0]
    if first_line.startswith(b'--'):
        return f'boundary="{first_line[2:].decode("ascii", "replace")}"'
    return ''
