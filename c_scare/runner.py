# SPDX-License-Identifier: GPL-2.0-only
"""
C-SCARE CLI - DICOM security testing across the role x method matrix.

                   | black-box (DAST)         | grey-box (fuzzing)
  -----------------+--------------------------+---------------------------
  SCP  (server)    | c-scare [--category X]   | c-scare greybox ...
  SCU  (client)    | c-scare rogue ...        | (instrument the client)

Subcommands:
    rogue    - SCU/client fuzzing: run a rogue DICOM SCP that feeds
               malformed responses to a connecting client
    corpus   - generate a seed corpus (.dcm/.bin) for AFL++/AFLNet
    greybox  - grey-box bridge: launch an AFL++/AFLNet harness, or
               triage its crashes into a SARIF report

With no subcommand, C-SCARE runs in black-box DAST mode: it delivers the
static attack catalog at a live DICOM server (--ip/--port/--category).
The grey-box mutation loop itself is owned by AFL++/AFLNet (see scripts/).

Examples:
    c-scare --ip 127.0.0.1 --port 4242 --category cve
    c-scare corpus -o ./corpus
    c-scare rogue --port 11112 --mode malformed-ac
    c-scare greybox triage fuzz/out/file --binary dcm2pnm --arg @@ --sarif x.sarif
"""

import sys
import os
import argparse
import datetime as dt
import time
import re
from typing import List, Optional
import tempfile

# Import attack modules
try:
    from .attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        StorageSCPAbuseAttacks, CommandInjectionAttacks,
        PathTraversalAttacks, StateMachineAttacks, CVEAttacks,
        NegotiationAttacks, DimseNAttacks,
        ProtocolFuzzer, AttackResult, SCAPY_AVAILABLE,
        DICM_PREFIX, EXPLICIT_VR_LE_UID,
        part10_file, standard_file_meta,
    )
    from . import client, deliver, transport
    from . import carrier as carrier_mod
    from . import overlay
    from .carrier import Carrier, CarrierError
    from .monitor import (
        BaseMonitor, MonitorReport, SanitizerMonitor,
        ProtocolMonitor, ProcessMonitor, PipelineMonitor,
    )
    from .process_manager import InstrumentedProcess
except ImportError:
    from attacks import (
        ParserAttacks, ProtocolAttacks, MemoryAttacks, LogicAttacks,
        StorageSCPAbuseAttacks, CommandInjectionAttacks,
        PathTraversalAttacks, StateMachineAttacks, CVEAttacks,
        NegotiationAttacks, DimseNAttacks,
        ProtocolFuzzer, AttackResult, SCAPY_AVAILABLE,
        DICM_PREFIX, EXPLICIT_VR_LE_UID,
        part10_file, standard_file_meta,
    )
    import client
    import deliver
    import transport
    import carrier as carrier_mod
    import overlay
    from carrier import Carrier, CarrierError
    from monitor import (
        BaseMonitor, MonitorReport, SanitizerMonitor,
        ProtocolMonitor, ProcessMonitor, PipelineMonitor,
    )
    from process_manager import InstrumentedProcess

__all__ = ['main', 'run_command', 'write_sarif']

SANITIZER_FLUSH_DELAY = 0.3

# What each C-STORE failure reason means for an operator staring at a red
# smoke test. Every one of these used to print as "association/C-STORE
# failed", which names the symptom and not one of the causes.
_CSTORE_SMOKE_HINTS = {
    'unavailable': 'scapy is not installed — no payload was sent',
    'rejected': 'the SCP sent an A-ASSOCIATE-RJ (AE title? auth?)',
    'unreachable': 'the TCP connection could not be made — wrong host/port?',
    'no_context': 'the SCP accepted the association but not the SOP class / '
                  'transfer syntax (try --store-sop / --store-transfer-syntax)',
    'refused': 'connection refused — is the SCP listening?',
    'reset': 'the SCP reset the connection mid-exchange',
    'timeout': 'the SCP did not answer within the timeout',
    'no_status': 'the object was sent but no C-STORE-RSP came back',
    'error': 'an unexpected error in the delivery path',
}


def _timestamp_from_ns(value: int) -> str:
    return dt.datetime.fromtimestamp(value / 1_000_000_000).astimezone().isoformat(
        timespec="microseconds"
    )


def _collect_results(args, results: list):
    """Append results to the shared collector if present."""
    collector = getattr(args, 'result_collector', None)
    if collector is not None:
        collector.extend(results)


def _get_monitors(args):
    """Get active monitors based on CLI args."""
    return getattr(args, '_monitors', [])


def _get_process(args):
    """Get managed process if one was started."""
    return getattr(args, '_managed_process', None)


# Categories whose payloads are DICOM datasets (not whole PDUs): to exercise
# the target's import/parse path they must ride inside a valid C-STORE
# association, not be dropped raw on the listening port.
DATASET_CATEGORIES = frozenset({
    'parser', 'memory', 'logic', 'storage_abuse',
    'path_traversal', 'command_injection',
})

# Categories that can degrade the target's availability rather than just probe
# it: allocation/disk-pressure payloads, and state-machine sequences that leave
# associations aborted. Against a live PACS these are the ones that show up as
# a clinical outage, so they require --allow-availability.
AVAILABILITY_CATEGORIES = frozenset({'memory', 'storage_abuse', 'state_machine'})


# Fallback storage SOP class for C-STORE delivery when an attack does not name
# one. Secondary Capture accepts arbitrary datasets and is what the
# path-traversal payloads already target. Hard-coded so this module imports
# without scapy; delivery itself (send_cstore) requires scapy at call time.
overlay.DEFAULT_STORE_SOP = "1.2.840.10008.5.1.4.1.1.7"  # Secondary Capture Image Storage
overlay.DEFAULT_STORE_TRANSFER_SYNTAX = "1.2.840.10008.1.2"  # Implicit VR Little Endian

# How the catalog encodes an attack's own Data Set unless the attack says
# otherwise in `encoded_transfer_syntax`. Needed to re-frame those elements
# into a carrier's syntax without disturbing their values.
_DEFAULT_ENCODED_TRANSFER_SYNTAX = "1.2.840.10008.1.2.1"  # Explicit VR LE

# Sequence Delimitation Item (FFFE,E0DD) with a zero length, both byte orders.
# Encapsulated Pixel Data ends with one; growing the fragment run means
# splitting it off, repeating the fragments, and putting it back.
_SEQUENCE_DELIMITER_LE = b'\xfe\xff\xdd\xe0\x00\x00\x00\x00'
_SEQUENCE_DELIMITER_BE = b'\xff\xfe\xe0\xdd\x00\x00\x00\x00'

_ASSOCIATE_RQ_PDU_TYPE = 0x01
_PDATA_PDU_TYPE = 0x04
_ABORT_PDU_TYPE = 0x07
_PDU_HEADER_LEN = 6
_ASSOCIATE_RQ_MIN_LEN = 74
_ASSOCIATE_CALLED_AE_OFFSET = 10
_ASSOCIATE_CALLING_AE_OFFSET = 26
_ASSOCIATE_AE_LEN = 16


def _ae_title_field(value: str) -> bytes:
    return str(value or "")[:_ASSOCIATE_AE_LEN].ljust(_ASSOCIATE_AE_LEN).encode(
        "ascii", errors="replace")


def _is_associate_rq(payload: bytes) -> bool:
    return len(payload) >= _ASSOCIATE_RQ_MIN_LEN and payload[0] == _ASSOCIATE_RQ_PDU_TYPE


def _association_ae_titles_are_tested(result: AttackResult) -> bool:
    metadata = result.metadata or {}
    if metadata.get("preserve_association_ae_titles"):
        return True
    if any(key in metadata for key in (
        "called_ae_title", "calling_ae_title", "called_ae", "calling_ae")):
        return True
    text = " ".join(str(value) for value in (
        result.name,
        result.description,
        metadata.get("target_field", ""),
        metadata.get("coverage_scope", ""),
    )).lower()
    return ("ae title" in text or "called ae" in text or "calling ae" in text
            or "called_ae" in text or "calling_ae" in text)


def _render_association_ae_titles(payload: bytes, args, result: AttackResult) -> bytes:
    """Apply live-target AE titles to raw A-ASSOCIATE-RQ payloads.

    Catalog sequences are useful as corpus seeds with fixed AE fields, but live
    product DAST should negotiate against the operator-selected AE titles unless
    the test itself is probing AE-title handling.
    """
    if _association_ae_titles_are_tested(result) or not _is_associate_rq(payload):
        return payload

    called_ae = getattr(args, "ae_title", None)
    calling_ae = getattr(args, "calling_ae", None)
    if called_ae is None and calling_ae is None:
        return payload

    rendered = bytearray(payload)
    if called_ae is not None:
        rendered[_ASSOCIATE_CALLED_AE_OFFSET:
                 _ASSOCIATE_CALLED_AE_OFFSET + _ASSOCIATE_AE_LEN] = _ae_title_field(called_ae)
        result.metadata["rendered_called_ae_title"] = str(called_ae)
    if calling_ae is not None:
        rendered[_ASSOCIATE_CALLING_AE_OFFSET:
                 _ASSOCIATE_CALLING_AE_OFFSET + _ASSOCIATE_AE_LEN] = _ae_title_field(calling_ae)
        result.metadata["rendered_calling_ae_title"] = str(calling_ae)
    return bytes(rendered)


def _render_sequence_steps(args, result: AttackResult, steps: List[bytes]) -> List[bytes]:
    return [_render_association_ae_titles(step, args, result) for step in steps]


def _pdata_carries_last_fragment(step: bytes) -> bool:
    """True if a P-DATA-TF PDU closes at least one DIMSE message.

    Walks the PDV items (PS3.8 §9.3.5): each is a 4-byte length, a context ID,
    then a Message Control Header whose bit 1 is the last-fragment flag. A PDU
    carrying only ``is_last=0`` fragments leaves the DIMSE message incomplete,
    so the peer cannot have anything to answer yet.
    """
    offset = _PDU_HEADER_LEN
    while offset + 6 <= len(step):
        item_len = int.from_bytes(step[offset:offset + 4], 'big')
        if item_len < 2:
            break
        if step[offset + 5] & 0x02:
            return True
        offset += 4 + item_len
    return False


def _sequence_expectations(steps: List[bytes]) -> List[bool]:
    """Per-step "wait for a reply?" flags for :func:`deliver.send_sequence`.

    Only steps the DIMSE/DUL state machine *cannot* answer are marked no-wait,
    so nothing that would have produced a response is skipped and the
    request/response pairing never desyncs:

    * an A-ABORT we send, and every step after it — the association is dead;
    * a P-DATA-TF carrying only non-final fragments — the message is still
      incomplete, so no DIMSE response is due yet.

    Everything else keeps blocking. That matters for the multi-P-DATA DIMSE-N
    sequences, where each complete message draws its own N-xxx-RSP: skipping a
    read there would leave the reply queued and hand it to the *next* step.
    """
    expectations: List[bool] = []
    association_dead = False
    for step in steps:
        if association_dead or not step:
            expectations.append(False)
            continue
        pdu_type = step[0]
        if pdu_type == _ABORT_PDU_TYPE:
            association_dead = True
            expectations.append(False)
        elif pdu_type == _PDATA_PDU_TYPE and not _pdata_carries_last_fragment(step):
            expectations.append(False)
        else:
            expectations.append(True)
    return expectations


def _get_cstore_file_context(args) -> Optional[Carrier]:
    """Load ``--cstore-file`` as a byte-faithful carrier, cached on ``args``.

    The carrier is read once and never mutated: every attack takes an edit
    against the same immutable bytes, so no attack can leak state into the
    next one and the object the operator validated is the object each test
    starts from.
    """
    path = getattr(args, 'cstore_file', None)
    if not path:
        return None
    path = os.path.abspath(os.fspath(path))
    cached = getattr(args, '_cstore_file_context', None)
    if cached is not None and cached.path == path:
        return cached
    carrier = Carrier.from_file(path)
    args._cstore_file_context = carrier
    return carrier


def _cstore_file_payload_for_result(args, result: Optional[AttackResult]):
    """Render one attack onto ``--cstore-file``, or ``None`` without the flag.

    The rendering itself lives in :mod:`c_scare.overlay`; all this does is
    turn command-line options into its arguments.
    """
    carrier = _get_cstore_file_context(args)
    if carrier is None:
        return None
    return overlay.carry(
        carrier, result,
        transfer_syntax=getattr(args, 'store_transfer_syntax', None),
        store_sop=getattr(args, 'store_sop', None))



def _run_cstore_smoke(args, target) -> int:
    """Store one known-good object and report the DIMSE status.

    Run this before and after a catalog to separate "the SCP rejected this
    attack" from "the SCP stopped accepting anything" — a rejection only means
    something if the same channel accepts a valid object.
    """
    file_payload = _cstore_file_payload_for_result(args, None)
    if file_payload is not None:
        payload = file_payload.dataset
        sop_class = file_payload.sop_class_uid
        sop_instance = file_payload.sop_instance_uid
        transfer_syntax = file_payload.transfer_syntax
    else:
        sop_class = getattr(args, 'store_sop', None) or overlay.DEFAULT_STORE_SOP
        transfer_syntax = (getattr(args, 'store_transfer_syntax', None)
                           or overlay.DEFAULT_STORE_TRANSFER_SYNTAX)
        sop_instance = f"1.2.826.0.1.3680043.10.543.{int(time.time())}.3"
        payload = overlay.smoke_dataset(sop_class, sop_instance,
                                        transfer_syntax)
    print("C-STORE smoke: sending known-good dataset")
    if getattr(args, 'cstore_file', None):
        print(f"  File: {os.path.abspath(os.fspath(args.cstore_file))}")
    print(f"  SOP Class: {sop_class}")
    print(f"  Transfer Syntax: {transfer_syntax}")
    print(f"  Called AE: {getattr(args, 'ae_title', 'TARGET')}")
    print(f"  Calling AE: {getattr(args, 'calling_ae', 'ATTACKER')}")
    outcome = deliver.send_cstore_outcome(
        target, payload, sop_class, sop_instance,
        transfer_syntax=transfer_syntax,
        called_ae=getattr(args, 'ae_title', 'TARGET'),
        calling_ae=getattr(args, 'calling_ae', 'ATTACKER'),
        timeout=getattr(args, 'timeout', 5.0),
    )
    if outcome.status == 0x0000:
        print("C-STORE smoke: PASS status=0x0000")
        return 0
    if outcome.status is not None:
        print(f"C-STORE smoke: FAIL status=0x{outcome.status:04X}")
        return 1
    # This check exists to tell "the SCP rejected an attack" from "the SCP
    # stopped accepting anything", so naming the reason is the whole job — a
    # bare "association/C-STORE failed" leaves the operator with the same
    # question they ran the smoke test to answer.
    hint = _CSTORE_SMOKE_HINTS.get(str(outcome.reason).split(':')[0],
                                   f'({outcome.reason})')
    print(f"C-STORE smoke: FAIL {hint}")
    return 1


#: One implementation of "where does the Data Set start", shared with the
#: carrier and the retrieval path. Re-exported here because the delivery paths
#: and the delivery-safety tests have always called them by these names.
_dataset_from_part10 = carrier_mod.dataset_from_part10
is_part10 = carrier_mod.is_part10
_decode_uid_value = carrier_mod.decode_uid_value


is_part10 = carrier_mod.is_part10


def _delivery_kind(args, result: AttackResult) -> str:
    """Decide how to put ``result.payload`` on the wire: 'sequence' (multi-PDU
    state-machine attack), 'cstore' (dataset wrapped in a C-STORE association),
    or 'pdu' (single raw PDU). Honors ``--delivery``; 'auto' routes by the
    payload's own shape first, then by the catalog's metadata convention
    (``steps`` / ``delivery_hint`` / ``sop_class_uid``) and the dataset
    categories.

    Shape comes first because metadata is a convention and conventions get
    forgotten. A Part-10 file sent as a raw PDU puts its first byte where the
    PDU type belongs — ``M`` from an ``MZ`` preamble, ``\\x7f`` from an ELF
    one — so the peer's DUL provider rejects an unrecognised PDU type and the
    file parser under test never runs. The abort that comes back is a normal
    response, so the result reads clean for an attack that never happened.
    """
    has_steps = bool(result.metadata.get('steps'))
    has_sop = bool(result.metadata.get('sop_class_uid'))
    mode = getattr(args, 'delivery', 'auto')
    if mode == 'pdu':
        # An explicit operator override: send the bytes raw even when they are
        # a file. That is a legitimate thing to ask for against a DUL.
        return 'sequence' if has_steps else 'pdu'
    if mode == 'cstore':
        # Force C-STORE for anything dataset-shaped; multi-PDU sequences can't
        # be C-STORE-wrapped, so they stay sequences.
        if has_steps:
            return 'sequence'
        return 'cstore'
    # auto
    if has_steps:
        return 'sequence'
    if result.metadata.get('delivery_hint') == 'cstore':
        return 'cstore'
    if is_part10(result.payload):
        return 'cstore'
    if has_sop or result.category in DATASET_CATEGORIES:
        return 'cstore'
    return 'pdu'


class AssociationBudgetExceeded(Exception):
    """Raised when a run reaches its ``--max-associations`` budget."""


def _association_cost(kind: str, result: AttackResult) -> int:
    """Associations one delivery opens. Each 'pdu'/'cstore' delivery makes a
    single connection; a 'sequence' shares one connection across its steps,
    except ``sm_double_association``-style attacks whose steps each carry an
    A-ASSOCIATE-RQ."""
    if kind != 'sequence':
        return 1
    steps = result.metadata.get('steps') or []
    return max(1, sum(1 for s in steps if s and s[0] == _ASSOCIATE_RQ_PDU_TYPE))


def _charge_associations(args, count: int) -> None:
    """Charge ``count`` associations against the run budget.

    ``--max-associations`` is a whole-run budget, not a concurrency limit: the
    DAST loop is sequential, so it never holds two associations at once. What
    it bounds is total connection churn against a live PACS, which is the thing
    that actually shows up in an operations team's monitoring.
    """
    limit = getattr(args, 'max_associations', None)
    if not limit or getattr(args, 'dry_run', None):
        # A dry run opens no connections, so it spends no budget.
        return
    already = getattr(args, '_associations_used', 0)
    if already + count > limit:
        raise AssociationBudgetExceeded(
            f"association budget reached: {already}/{limit} used, next delivery "
            f"needs {count} more (raise or clear --max-associations to continue)")
    args._associations_used = already + count


def _dry_run_write(args, result: AttackResult, kind: str, payloads: List[bytes]) -> None:
    """Write what would have gone on the wire to the --dry-run directory."""
    out_dir = getattr(args, 'dry_run', None)
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    safe = re.sub(r'[^A-Za-z0-9_.-]', '_', result.name) or 'payload'
    ext = '.dcm' if kind == 'cstore' else '.bin'
    for i, blob in enumerate(payloads):
        suffix = f'.{i:02d}' if len(payloads) > 1 else ''
        path = os.path.join(out_dir, f'{safe}{suffix}{ext}')
        with open(path, 'wb') as fh:
            fh.write(blob or b'')
    result.metadata['dry_run_files'] = len(payloads)


def _deliver(args, result: AttackResult, target, timeout: float):
    """Deliver one (optionally mutated) payload by the chosen method. Returns
    ``(response, error)`` where response is bytes/None and error is a short
    ProtocolMonitor signal ('timeout'/'refused'/...) or None."""
    payload = result.payload
    mutate_modes = getattr(args, 'mutate', None)
    if mutate_modes:
        try:
            from .hostile import mutate_payload
            payload = mutate_payload(payload, str(mutate_modes).split(','),
                                     seed=len(result.name))
            result.metadata['mutation'] = mutate_modes
        except Exception as e:  # mutation must never abort a delivery
            result.metadata['mutation_error'] = str(e)

    kind = _delivery_kind(args, result)
    result.metadata['delivery'] = kind
    _charge_associations(args, _association_cost(kind, result))
    try:
        if kind == 'sequence':
            steps = _render_sequence_steps(args, result,
                                           list(result.metadata.get('steps') or [payload]))
            if getattr(args, 'dry_run', None):
                _dry_run_write(args, result, kind, steps)
                return None, 'dry_run'
            expectations = _sequence_expectations(steps)
            responses = deliver.send_sequence(target, steps, timeout=timeout,
                                              expect_response=expectations)
            # The verdict is the last reply the peer actually sent. Reading
            # responses[-1] would report 'timeout' for every sequence that ends
            # on a deliberately unanswerable step (a trailing A-ABORT, a
            # dangling fragment) even though the peer answered earlier steps.
            last = next((r for r in reversed(responses) if r is not None), None)
            return last, ('timeout' if last is None else None)
        if kind == 'cstore':
            carrier = _transport_for(args, target)
            file_payload = _cstore_file_payload_for_result(args, result)
            dry_run_blob = None
            if file_payload is not None:
                sop_class = file_payload.sop_class_uid
                sop_inst = file_payload.sop_instance_uid
                transfer_syntax = file_payload.transfer_syntax
                # STOW-RS posts complete instances; C-STORE carries a Data Set.
                cstore_payload = (file_payload.part10
                                  if carrier.carries_whole_file
                                  else file_payload.dataset)
                dry_run_blob = file_payload.part10
            elif carrier.carries_whole_file:
                # STOW-RS posts complete instances, so the Part-10 wrapper is
                # what goes up — stripping it here would throw away the
                # preamble this transport exists to carry.
                cstore_payload = payload
                _p10, part10_meta = _dataset_from_part10(payload)
                sop_class = result.metadata.get('sop_class_uid') \
                    or part10_meta.get('sop_class_uid') \
                    or getattr(args, 'store_sop', None) or overlay.DEFAULT_STORE_SOP
                sop_inst = result.metadata.get('sop_instance_uid') \
                    or part10_meta.get('sop_instance_uid') or '1.2.3.4.5'
                transfer_syntax = result.metadata.get('transfer_syntax') \
                    or part10_meta.get('transfer_syntax')
            else:
                cstore_payload, part10_meta = _dataset_from_part10(payload)
                sop_class = result.metadata.get('sop_class_uid') \
                    or part10_meta.get('sop_class_uid') \
                    or getattr(args, 'store_sop', None) or overlay.DEFAULT_STORE_SOP
                sop_inst = result.metadata.get('sop_instance_uid') \
                    or part10_meta.get('sop_instance_uid') or '1.2.3.4.5'
                transfer_syntax = result.metadata.get('transfer_syntax') \
                    or part10_meta.get('transfer_syntax') \
                    or getattr(args, 'store_transfer_syntax', None)
                if part10_meta.get('part10_stripped'):
                    result.metadata['cstore_stripped_part10'] = True
            if getattr(args, 'dry_run', None):
                # Write the whole file when there is one. A bare Data Set with
                # a .dcm name opens in nothing, and --dry-run exists so an
                # operator can look at what a run would send before it sends it.
                _dry_run_write(args, result, kind,
                               [dry_run_blob if dry_run_blob is not None
                                else cstore_payload])
                return None, 'dry_run'
            outcome = carrier.store(
                cstore_payload, sop_class_uid=sop_class,
                sop_instance_uid=sop_inst, transfer_syntax=transfer_syntax,
                study_instance_uid=result.metadata.get('study_instance_uid'),
                timeout=timeout)
            status = outcome.status
            result.metadata['transport'] = carrier.name
            result.metadata['cstore_status'] = status
            result.metadata['store_accepted'] = outcome.accepted
            if status is None:
                result.metadata['delivery_error'] = outcome.reason
                # A payload that never reached the target's parser supports no
                # conclusion about the target, so it is reported as undelivered
                # rather than as an absent response. Reasons that *are* target
                # behaviour (refused, reset, silence after the object was sent)
                # keep their existing ProtocolMonitor signals.
                if not outcome.delivered:
                    return None, f'undelivered:{outcome.reason}'
                reason = str(outcome.reason).split(':')[0]
                return None, reason if reason in ('refused', 'reset') else 'timeout'
            return bytes([(status >> 8) & 0xFF, status & 0xFF]), 'cstore_status'
        payload = _render_association_ae_titles(payload, args, result)
        if getattr(args, 'dry_run', None):
            _dry_run_write(args, result, kind, [payload])
            return None, 'dry_run'
        return deliver.send_pdu(target, payload, timeout=timeout), None
    except ConnectionRefusedError:
        return None, 'refused'
    except ConnectionResetError:
        return None, 'reset'


def _transport_for(args, target=None):
    """The transport this run uses, built once and cached on ``args``.

    ``target`` is the address the caller already resolved; it is passed
    through because the delivery paths are handed one explicitly and it is
    authoritative over anything on ``args``.
    """
    carrier = getattr(args, '_transport', None)
    if carrier is None:
        carrier = transport.for_args(args, target)
        args._transport = carrier
    return carrier


def _scorable_finding_on(args, result: AttackResult):
    """The payload's expectation, but only where the transport can honour it.

    A payload that keeps its content in the preamble asks "will you store an
    executable?", and over C-STORE the archive is never shown one — the
    preamble is not transmitted. Scoring acceptance there would report a
    finding against an archive that received an ordinary image. Over STOW-RS
    the same payload arrives whole, and the same question is answerable.

    So the expectation is passed through only when
    :func:`transport.survives` says the mechanism reached the far side.
    """
    finding_on = result.metadata.get('finding_on')
    if not finding_on:
        return None
    region = result.metadata.get('payload_region')
    if not transport.survives(region, _transport_for(args)):
        return None
    return finding_on


def _round_trip(args, result: AttackResult, target, timeout: float):
    """Fetch back what was just stored. Returns ``(sent, returned, reason)``.

    Only attempted when the store succeeded — retrieving an instance the
    archive refused would report ``stripped`` for an object that was never
    there, which is the false negative that mirrors every false positive
    fixed elsewhere in this file.
    """
    if not result.metadata.get('store_accepted'):
        return None, None, 'not_stored'
    sop_class = (result.metadata.get('sop_class_uid') or overlay.DEFAULT_STORE_SOP)
    sop_instance = result.metadata.get('sop_instance_uid')
    if not sop_instance:
        return None, None, 'no_sop_instance_uid'

    _charge_associations(args, 1)
    outcome = _transport_for(args, target).retrieve(
        sop_class_uid=sop_class, sop_instance_uid=sop_instance,
        study_instance_uid=result.metadata.get('study_instance_uid'),
        series_instance_uid=result.metadata.get('series_instance_uid'),
        transfer_syntax=result.metadata.get('transfer_syntax'),
        timeout=timeout)
    result.metadata['retrieve_reason'] = outcome.reason
    return result.payload, outcome.data, outcome.reason


def _run_monitored_test(args, result: AttackResult, target, timeout: float):
    """Send a payload and check all monitors for findings."""
    monitors = _get_monitors(args)
    if not monitors:
        return

    started_ns = time.time_ns()
    result.metadata['started_at'] = _timestamp_from_ns(started_ns)
    result.metadata['started_epoch_ns'] = started_ns

    for i, monitor in enumerate(monitors):
        monitor.pre_test(i)

    response, error = _deliver(args, result, target, timeout)
    result.response = response

    for monitor in monitors:
        if isinstance(monitor, ProtocolMonitor):
            monitor.set_response(
                response, error=error,
                finding_on=_scorable_finding_on(args, result),
                accepted=result.metadata.get('store_accepted'))
        elif isinstance(monitor, PipelineMonitor):
            monitor.set_round_trip(*_round_trip(args, result, target, timeout))

    if any(isinstance(m, SanitizerMonitor) for m in monitors):
        time.sleep(SANITIZER_FLUSH_DELAY)

    for monitor in monitors:
        report = monitor.post_test()
        result.monitor_reports.append(report)
        if report.detected:
            result.success = True

    ended_ns = time.time_ns()
    result.metadata['ended_at'] = _timestamp_from_ns(ended_ns)
    result.metadata['ended_epoch_ns'] = ended_ns
    result.metadata['duration_ms'] = round((ended_ns - started_ns) / 1_000_000, 3)

    proc = _get_process(args)
    if proc and not proc.is_alive():
        proc.restart()
        time.sleep(0.5)


def _sarif_fingerprint(result, detections) -> str:
    """Stable dedup key for a finding.

    Two crashes with the same finding types and top stack frame collapse to one
    SARIF result for the consumer (GitHub code scanning et al.), so a campaign
    that rediscovers the same bug a thousand times reports it once. Built from
    the finding types plus the first line of the first stack trace; falls back
    to category/name when there is no detection (e.g. a clean catalog delivery).
    """
    import hashlib

    parts = [f"{rpt.finding_type}" for rpt in detections]
    for rpt in detections:
        if rpt.evidence:
            parts.append(rpt.evidence.strip().splitlines()[0].strip())
            break
    if not parts:
        parts = [result.category, result.name]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


_SARIF_ERROR_FINDING_PREFIXES = (
    "asan:", "ubsan:", "msan:", "lsan:", "crash:",
    "protocol:accepted", "resource:", "canary:", "coredump:",
    "filesystem-canary", "target-coredump",
)
_SARIF_WARNING_FINDING_PREFIXES = ("network:", "protocol:unexpected_pdu")


def _sarif_level(result, detections) -> str:
    """Map evidence strength to SARIF severity without promoting transport noise."""
    finding_types = [report.finding_type or "" for report in detections]
    if any(kind.startswith(_SARIF_ERROR_FINDING_PREFIXES) for kind in finding_types):
        return "error"
    if any(kind.startswith(_SARIF_WARNING_FINDING_PREFIXES) for kind in finding_types):
        return "warning"
    if detections:
        return "warning"
    if result.success is None:
        return "note"
    return "error"


def write_sarif(results: list, filepath: str):
    """Write SARIF v2.1.0 report from AttackResult objects."""
    import json

    rules = {}
    sarif_results = []
    for r in results:
        rule_id = f"{r.category}/{r.name}"
        if rule_id not in rules:
            rule_def = {
                "id": rule_id,
                "shortDescription": {"text": r.name},
            }
            if r.cve:
                rule_def["helpUri"] = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={r.cve}"
            rules[rule_id] = rule_def

        detections = [rpt for rpt in r.monitor_reports if rpt.detected]
        # Transport failures alone are weak evidence because malformed inputs
        # commonly provoke resets/timeouts. Confirmed acceptance, crashes,
        # canaries, coredumps, sanitizer output, and resource growth are errors.
        level = _sarif_level(r, detections)
        result_obj = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": r.description},
            "partialFingerprints": {
                "cscareFinding/v1": _sarif_fingerprint(r, detections),
            },
            "properties": {
                "category": r.category,
                "expected_behavior": r.expected_behavior,
            },
        }
        # Grey-box triage results carry the crash/queue input path; surface it as
        # the result location so consumers can locate and dedup by artifact.
        crash_path = r.metadata.get("crash_path")
        if crash_path:
            result_obj["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": crash_path},
                },
            }]
        if r.cve:
            result_obj["properties"]["cve"] = r.cve
        for key in (
            "delivery", "mutation", "started_at", "ended_at",
            "started_epoch_ns", "ended_epoch_ns", "duration_ms",
        ):
            if r.metadata.get(key) is not None:
                result_obj["properties"][key] = r.metadata[key]
        if detections:
            result_obj["properties"]["monitors"] = [
                {
                    "finding_type": rpt.finding_type,
                    "description": rpt.description,
                    "evidence": rpt.evidence,
                }
                for rpt in detections
            ]
        sarif_results.append(result_obj)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "C-SCARE",
                        "informationUri": "https://github.com/tmart234/C-SCARE",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    with open(filepath, "w") as f:
        json.dump(sarif, f, indent=2)


def print_banner():
    """Print C-Scare banner."""
    banner = r"""
  ____     ____                     
 / ___|   / ___|  ___ __ _ _ __ ___ 
| |   ____\___ \ / __/ _` | '__/ _ \
| |__|_____|__) | (_| (_| | | |  __/
 \____|   |____/ \___\__,_|_|  \___|

    DICOM Security Testing Framework
"""
    print(banner)


def print_result(result: AttackResult, verbose: bool = False):
    """Print an attack result."""
    status = "OK" if result.success is True else ("FAIL" if result.success is False else "?")
    cve_tag = f" [{result.cve}]" if result.cve else ""

    detections = [r for r in result.monitor_reports if r.detected]
    if detections:
        detection_str = f" -> {detections[0].finding_type}"
    else:
        detection_str = ""

    print(f"{status} {result.name}{cve_tag}{detection_str}")
    if verbose:
        print(f"  Category: {result.category}")
        print(f"  Description: {result.description}")
        print(f"  Expected: {result.expected_behavior}")
        if result.metadata:
            print(f"  Metadata: {result.metadata}")
        print(f"  Payload size: {len(result.payload)} bytes")
        if result.response:
            print(f"  Response size: {len(result.response)} bytes")
        for report in result.monitor_reports:
            if report.detected:
                print(f"  Monitor: {report.finding_type} - {report.description}")
                if report.evidence:
                    for line in report.evidence.split('\n')[:5]:
                        print(f"    {line}")
        print()


def run_cve_attacks(args) -> int:
    """Run CVE-specific attack reproductions."""
    print("\n=== CVE Attack Patterns ===\n")

    all_results = []
    for i, result in enumerate(CVEAttacks.all()):
        _maybe_deliver(args, result, i)
        print_result(result, args.verbose)
        all_results.append(result)

    print(f"\nTotal CVE test cases: {len(all_results)}")
    _collect_results(args, all_results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in all_results:
            filepath = _save_corpus_file(result, args.output)
            if args.verbose:
                print(f"Saved: {filepath}")

    return 0


def run_fuzz_packets(args) -> int:
    """Test fuzzed DIMSE packets."""
    if not SCAPY_AVAILABLE:
        print("WARNING: Scapy not available - skipping fuzz packet tests")
        print("  (This is optional, install with: pip install scapy)")
        return 0  # Return success - Scapy is optional
    
    print("\n=== Fuzz Packet Tests ===\n")
    print("Testing: Fuzzed DIMSE packets with various malformations")
    print()
    
    # Try to import fuzz classes - they may not exist
    try:
        try:
            from .attacks import C_ECHO_RQ, C_STORE_RQ
            from scapy.packet import raw, fuzz
        except ImportError:
            from attacks import C_ECHO_RQ, C_STORE_RQ
            from scapy.packet import raw, fuzz
        
    except ImportError as e:
        print(f"ERROR: Could not import DIMSE classes: {e}")
        return 1
    
    count = args.count if hasattr(args, 'count') else 10
    results = []
    
    # Test 1: C_ECHO with various modifications
    print("1. C_ECHO_RQ with field variations")
    for i in range(min(5, count)):
        try:
            cmd = C_ECHO_RQ(message_id=i+1)
            
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_echo_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-ECHO-RQ test case #{i}",
                expected_behavior="Parser should handle malformed fields",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"FAIL Failed to create C_ECHO_RQ #{i}: {e}")
    
    # Test 2: C_STORE with variations
    print("\n2. C_STORE_RQ with field variations")
    for i in range(min(5, count)):
        try:
            cmd = C_STORE_RQ(
                    affected_sop_class_uid='1.2.840.10008.5.1.4.1.1.2',
                    affected_sop_instance_uid=f'1.2.3.4.5.6.{i}',
                    message_id=i+1
                )
            
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_store_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-STORE-RQ test case #{i}",
                expected_behavior="Parser should handle variations",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"FAIL Failed to create C_STORE_RQ #{i}: {e}")
    
    # Test 3: Generic Scapy fuzz()
    print("\n3. Generic Scapy fuzz()")
    for i in range(min(5, count)):
        try:
            cmd = fuzz(C_ECHO_RQ())
            payload = raw(cmd)
            result = AttackResult(
                name=f"c_echo_scapy_fuzz_{i}",
                category="fuzz",
                payload=payload,
                description=f"C-ECHO-RQ with Scapy fuzz() #{i}",
                expected_behavior="Parser should handle malformed fields",
            )
            print_result(result, args.verbose)
            results.append(result)
        except Exception as e:
            print(f"FAIL Failed to create fuzzed C_ECHO_RQ #{i}: {e}")
    
    print(f"\nTotal fuzz test cases: {len(results)}")
    _collect_results(args, results)

    # Save if output dir specified
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            filename = f"{result.name}.bin"
            filepath = os.path.join(args.output, filename)
            with open(filepath, 'wb') as f:
                f.write(result.payload)
            if args.verbose:
                print(f"Saved: {filepath}")
    
    return 0


def run_protocol_fuzzing(args) -> int:
    """Run live protocol fuzzing against a target."""
    if not SCAPY_AVAILABLE:
        print("WARNING: Scapy not available - skipping protocol fuzzing tests")
        print("  (This is optional, install with: pip install scapy)")
        return 0

    if not args.target:
        print("ERROR: --target required (format: host:port)")
        return 1

    print("\n=== Live Protocol Fuzzing ===\n")

    try:
        host, port = args.target.rsplit(':', 1)
        port = int(port)
        target = (host, port)
    except ValueError:
        print(f"ERROR: Invalid target format: {args.target}")
        print("Expected format: host:port (e.g., 192.168.1.100:11112)")
        return 1

    print(f"Target: {host}:{port}")
    print(f"Running {args.count} fuzzed A-ASSOCIATE-RQ packets against server")
    print()

    try:
        interesting_count = 0
        monitors = _get_monitors(args)
        all_results = []

        for i, result in enumerate(ProtocolFuzzer.fuzz_association(count=args.count)):
            if not result.payload:
                print(f"FAIL #{i+1}: {result.description}")
                continue

            if monitors:
                _run_monitored_test(args, result, target, args.timeout)
                detected = any(r.detected for r in result.monitor_reports)
                status = "!" if detected else "OK"
                print(f"{status} #{i+1}: {result.name}")
                if detected:
                    interesting_count += 1
                    if args.verbose:
                        for report in result.monitor_reports:
                            if report.detected:
                                print(f"  Monitor: {report.finding_type} - {report.description}")
            else:
                response, err = _deliver(args, result, target, args.timeout)
                interesting = err != 'dry_run' and (
                    response is None or
                    len(response) == 0 or
                    (response and response[0] not in (0x02, 0x03, 0x07))
                )
                status = "!" if interesting else "OK"
                print(f"{status} #{i+1}: {result.name}")
                if interesting:
                    interesting_count += 1
                    if args.verbose:
                        print(f"  Mutation: {result.metadata.get('mutation')}")
                        if response:
                            print(f"  Response: {len(response)} bytes")
                        else:
                            print(f"  Response: None (timeout or connection closed)")

            all_results.append(result)

        print(f"\nInteresting results: {interesting_count}/{args.count}")
        _collect_results(args, all_results)

    except AssociationBudgetExceeded:
        _collect_results(args, all_results)
        raise
    except Exception as e:
        print(f"ERROR: Fuzzing failed: {e}")
        return 1

    return 0


def _save_corpus_file(result: AttackResult, output_dir: str) -> str:
    """Save an AttackResult payload as a corpus file, return the path."""
    # Protocol-level payloads use .bin, dataset payloads use .dcm
    if result.category in ('protocol', 'state_machine', 'fuzzer'):
        ext = '.bin'
        file_data = result.payload
    else:
        ext = '.dcm'
        payload = result.payload or b''
        # A payload already carrying the Part 10 magic - a raw file (DICM at
        # offset 0) or a complete file with a 128-byte preamble (DICM at
        # offset 128, e.g. the CVE-2019-11687 polyglots) - must be written
        # verbatim. Re-wrapping a polyglot buries its executable preamble at
        # offset 132 and destroys the seed.
        if payload.startswith(DICM_PREFIX) or is_part10(payload):
            file_data = payload
        else:
            # A bare Data Set needs a File Meta group, not just the magic.
            # Preamble + DICM + data set is not a Part-10 file: PS3.10 §7.1
            # requires group 0002, and without (0002,0010) Transfer Syntax UID
            # a reader does not know how to decode what follows. dcmtk stops
            # at the header, so the malformation inside the seed never reaches
            # the parser it was written for.
            file_data = part10_file(
                standard_file_meta(
                    sop_class_uid=(result.metadata.get('sop_class_uid')
                                   or overlay.DEFAULT_STORE_SOP),
                    sop_instance_uid=(result.metadata.get('sop_instance_uid')
                                      or '1.2.3.4.5'),
                    transfer_syntax=(result.metadata.get('transfer_syntax')
                                     or EXPLICIT_VR_LE_UID)),
                dataset=payload)

    filepath = os.path.join(output_dir, f"{result.name}{ext}")
    with open(filepath, 'wb') as f:
        f.write(file_data)
    return filepath


def run_generate_corpus(args) -> int:
    """Generate fuzzing corpus files."""
    print("\n=== Generating Fuzzing Corpus ===\n")

    output_dir = args.output or tempfile.mkdtemp(prefix='c_scare_corpus_')
    os.makedirs(output_dir, exist_ok=True)

    print(f"Output directory: {output_dir}")
    print(f"Generating test cases...")
    print()

    categories = [
        ('Parser attacks', ParserAttacks),
        ('Memory attacks', MemoryAttacks),
        ('Logic attacks', LogicAttacks),
        ('Storage SCP abuse attacks', StorageSCPAbuseAttacks),
        ('Command injection attacks', CommandInjectionAttacks),
        ('Path traversal attacks', PathTraversalAttacks),
        ('CVE attacks', CVEAttacks),
        ('Protocol attacks', ProtocolAttacks),
        ('Negotiation attacks', NegotiationAttacks),
        ('DIMSE-N attacks', DimseNAttacks),
        ('State machine attacks', StateMachineAttacks),
    ]

    results = []
    for label, cls in categories:
        print(f"{label}...")
        for result in cls.all():
            try:
                filepath = _save_corpus_file(result, output_dir)
                filesize = len(result.payload)
                print(f"  {os.path.basename(filepath):30s} {filesize:>8} bytes  {result.description}")
                results.append(result)
            except Exception as e:
                print(f"  FAIL {result.name:30s}  SKIPPED  {e}")

    print(f"\nCorpus saved to: {output_dir}")
    print(f"Total files: {len(results)}")

    return 0


def _availability_blocked(args, category: str, label: str) -> bool:
    """True if ``category`` needs ``--allow-availability`` and did not get it.

    Gating here rather than by pruning ``run_all_tests``'s command list keeps
    the "``all`` runs every category" invariant intact — the category still
    runs, it just declines to deliver anything without the opt-in. A dry run
    sends nothing, so it is exempt.
    """
    if category not in AVAILABILITY_CATEGORIES:
        return False
    if getattr(args, 'allow_availability', False) or getattr(args, 'dry_run', None):
        return False
    print(f"\n=== {label} ===\n")
    print(f"SKIPPED: '{category}' can degrade target availability "
          f"(resource exhaustion / aborted associations).")
    print("Pass --allow-availability to run it, or --dry-run DIR to inspect "
          "the payloads without sending them.")
    return True


def _maybe_deliver(args, result: AttackResult, index: int):
    """Deliver the payload to a live target when monitors are active."""
    monitors = _get_monitors(args)
    if not monitors:
        return
    try:
        host, port = args.target.rsplit(':', 1)
        target = (host, int(port))
    except (ValueError, AttributeError):
        return
    _run_monitored_test(args, result, target, args.timeout)


def _print_undelivered(results: list) -> None:
    """Warn when payloads never reached the target.

    An undelivered payload produces no detection, which is shaped exactly like
    a payload the target handled correctly. Without this line a run against a
    misconfigured AE title, an unsupported SOP class or a host with no scapy
    prints a clean report for work it never did.
    """
    reasons = {}
    for result in results:
        if any(report.finding_type == 'delivery:not_delivered'
               for report in result.monitor_reports):
            reason = result.metadata.get('delivery_error') or 'unknown'
            reasons[reason] = reasons.get(reason, 0) + 1
    if not reasons:
        return
    total = sum(reasons.values())
    detail = ', '.join(f'{reason} ×{count}'
                       for reason, count in sorted(reasons.items()))
    print(f"WARNING: {total} of {len(results)} payloads were never delivered "
          f"({detail}).")
    print("         Those tests concluded nothing about the target.")


def _print_file_only(results: list, args=None) -> None:
    """Note payloads whose mechanism cannot survive an association.

    C-STORE carries a Data Set, so a payload whose foreign content lives in
    the 128-byte preamble or past the final Data Element arrives as an
    ordinary object — the archive is being asked a question the wire cannot
    put to it. Delivering them anyway is harmless, but reporting the result as
    if it meant something is not, so the run says which ones need a file path
    instead.
    """
    carrier = _transport_for(args) if args is not None else None
    if carrier is None or carrier.carries_whole_file:
        return
    unreached = [r for r in results
                 if r.metadata.get('payload_region') == transport.REGION_WHOLE_FILE
                 and r.metadata.get('delivery') in ('cstore', 'pdu')]
    if not unreached:
        return
    print(f"NOTE: {len(unreached)} payload(s) keep their content in the "
          "preamble or past the Data Set,")
    print(f"      which the {carrier.name} transport does not carry — it "
          "sends a Data Set, not a file.")
    print("      Reach them with --dicomweb-url (STOW-RS posts whole "
          "instances), or")
    print("      `c-scare corpus -o ./out` through media, a DICOMDIR or an "
          "import folder.")


def _run_catalog(args, catalog, label: str, note: Optional[str] = None) -> int:
    """Run one static attack catalog: deliver each payload to a monitored live
    target, print results, collect findings, and optionally write the payloads
    to ``args.output`` as corpus files.

    The 8 catalog categories differ only in *which* catalog and *which* label -
    file extension and Part-10 wrapping are decided per payload by
    :func:`_save_corpus_file` (keyed off ``result.category``), so this one helper
    serves them all. ``note`` prints an optional caveat after the totals."""
    print(f"\n=== {label} ===\n")

    results = []
    for i, result in enumerate(catalog.all()):
        try:
            _maybe_deliver(args, result, i)
            print_result(result, args.verbose)
            results.append(result)
        except AssociationBudgetExceeded:
            _collect_results(args, results)
            raise
        except Exception as e:
            print(f"FAIL {result.name}: {e}")

    print(f"\nTotal {label.lower()} tests: {len(results)}")
    _print_undelivered(results)
    _print_file_only(results, args)
    if note:
        print(note)
    _collect_results(args, results)

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        for result in results:
            _save_corpus_file(result, args.output)

    return 0


def run_parser_attacks(args) -> int:
    """Run parser attack tests."""
    return _run_catalog(args, ParserAttacks, "Parser Attacks")


def run_protocol_attacks(args) -> int:
    """Run protocol-level attack tests."""
    return _run_catalog(args, ProtocolAttacks, "Protocol Attacks")


def run_logic_attacks(args) -> int:
    """Run logic attack tests."""
    return _run_catalog(args, LogicAttacks, "Logic Attacks")


def run_storage_scp_abuse_attacks(args) -> int:
    """Run unauthenticated Storage SCP abuse tests."""
    if _availability_blocked(args, 'storage_abuse', "Storage SCP Abuse Attacks"):
        return 0
    return _run_catalog(args, StorageSCPAbuseAttacks, "Storage SCP Abuse Attacks")


def run_command_injection_attacks(args) -> int:
    """Run command-injection attack tests (storescp exec placeholders)."""
    return _run_catalog(
        args, CommandInjectionAttacks, "Command Injection Attacks",
        note="Note: confirming RCE needs a live storescp started with "
             "--exec-on-reception and a C-STORE (see deliver.send_cstore).")


def run_path_traversal_attacks(args) -> int:
    """Run path-traversal attack tests (storescp/SCU stored filenames)."""
    return _run_catalog(
        args, PathTraversalAttacks, "Path Traversal Attacks",
        note="Note: confirming the write primitive needs a live storescp (SCP, "
             "CVE-2022-2119) or a RawSCP rogue server feeding a client (SCU, "
             "CVE-2022-2120); inspect where the received file lands.")


def run_state_machine_attacks(args) -> int:
    """Run state machine attack tests."""
    if _availability_blocked(args, 'state_machine', "State Machine Attacks"):
        return 0
    if not args.target:
        print("ERROR: --target required for state machine attacks (format: host:port)")
        print("Example: python -m c_scare state_machine_attacks --target 127.0.0.1:4242")
        return 1

    print("\n=== State Machine Attacks ===\n")

    try:
        host, port = args.target.rsplit(':', 1)
        port = int(port)
        target = (host, port)
    except ValueError:
        print(f"ERROR: Invalid target format: {args.target}")
        print("Expected format: host:port (e.g., 192.168.1.100:11112)")
        return 1

    print(f"Target: {host}:{port}")
    print()

    results = []
    monitors = _get_monitors(args)

    for i, result in enumerate(StateMachineAttacks.all()):
        try:
            # Route through the shared delivery path rather than calling
            # deliver.* directly, so state-machine sequences get the same
            # --dry-run, --max-associations and per-step response handling as
            # every other category. This is the category most likely to
            # disturb a live PACS, so it must not be the one that bypasses
            # the guardrails.
            if monitors:
                _run_monitored_test(args, result, target, args.timeout)
            else:
                result.response, _err = _deliver(args, result, target, args.timeout)
                result.success = True
        except AssociationBudgetExceeded:
            _collect_results(args, results)
            raise
        except Exception as e:
            result.success = False
            result.description = f'Failed: {e}'

        print_result(result, args.verbose)
        results.append(result)

    print(f"\nTotal state machine attack tests: {len(results)}")
    _collect_results(args, results)
    return 0


def run_negotiation_attacks(args) -> int:
    """Run A-ASSOCIATE user-information sub-item attacks."""
    return _run_catalog(args, NegotiationAttacks, "Negotiation Attacks")


def run_dimse_n_attacks(args) -> int:
    """Run DIMSE-N normalized-service (MPPS / Storage Commitment) attacks."""
    return _run_catalog(args, DimseNAttacks, "DIMSE-N Attacks")


def run_memory_attacks(args) -> int:
    """Run memory corruption attack tests."""
    if _availability_blocked(args, 'memory', "Memory Attacks"):
        return 0
    return _run_catalog(args, MemoryAttacks, "Memory Attacks")


def run_all_tests(args) -> int:
    """Run every static attack category.

    This must stay in sync with the ``--category`` choices: a category the CLI
    accepts but ``all`` skips is silently missing coverage from every run that
    does not name it explicitly. ``test_runner_all_covers_every_category``
    enforces that.

    ``live_fuzz`` is the one deliberate omission. It is a randomized loop sized
    by ``--live-fuzz-count``, not a static catalog, so including it would make
    ``all`` nondeterministic and unbounded. Run it by name.
    """
    print_banner()

    # Run each test suite
    commands = [
        ('CVE Attacks', run_cve_attacks),
        ('Parser Attacks', run_parser_attacks),
        ('Protocol Attacks', run_protocol_attacks),
        ('Memory Attacks', run_memory_attacks),
        ('Logic Attacks', run_logic_attacks),
        ('Storage SCP Abuse Attacks', run_storage_scp_abuse_attacks),
        ('Command Injection Attacks', run_command_injection_attacks),
        ('Path Traversal Attacks', run_path_traversal_attacks),
        ('State Machine Attacks', run_state_machine_attacks),
        ('Negotiation Attacks', run_negotiation_attacks),
        ('DIMSE-N Attacks', run_dimse_n_attacks),
        ('Fuzz Packets', run_fuzz_packets),
    ]
    
    results = {}
    for name, func in commands:
        print(f"\n{'='*60}")
        print(f"Running: {name}")
        print('='*60)
        try:
            ret = func(args)
            results[name] = 'PASS' if ret == 0 else 'FAIL'
        except AssociationBudgetExceeded:
            results[name] = 'ABORTED'
            raise
        except Exception as e:
            print(f"\nERROR in {name}: {e}")
            results[name] = 'ERROR'
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print('='*60)
    for name, status in results.items():
        symbol = 'OK' if status == 'PASS' else 'FAIL'
        print(f"{symbol} {name}: {status}")
    
    return 0


def run_command(command: str, args) -> int:
    """Run a specific command."""
    commands = {
        'cve_attacks': run_cve_attacks,
        'fuzz_packets': run_fuzz_packets,
        'protocol_fuzzing': run_protocol_fuzzing,
        'protocol_attacks': run_protocol_attacks,
        'generate_corpus': run_generate_corpus,
        'parser_attacks': run_parser_attacks,
        'memory_attacks': run_memory_attacks,
        'logic_attacks': run_logic_attacks,
        'storage_scp_abuse_attacks': run_storage_scp_abuse_attacks,
        'command_injection_attacks': run_command_injection_attacks,
        'path_traversal_attacks': run_path_traversal_attacks,
        'negotiation_attacks': run_negotiation_attacks,
        'dimse_n_attacks': run_dimse_n_attacks,
        'state_machine_attacks': run_state_machine_attacks,
        'all': run_all_tests,
    }
    
    if command not in commands:
        print(f"ERROR: Unknown command: {command}")
        print(f"Available commands: {', '.join(commands.keys())}")
        return 1
    
    return commands[command](args)


def _cmd_corpus(argv: List[str]) -> int:
    """`corpus` subcommand: generate a seed corpus for AFL++/AFLNet."""
    p = argparse.ArgumentParser(
        prog='c-scare corpus',
        description='Generate a seed corpus (.dcm/.bin) for AFL++/AFLNet.')
    p.add_argument('-o', '--out', required=True, help='output directory')
    a = p.parse_args(argv)
    return run_generate_corpus(argparse.Namespace(output=a.out))


def _run_hostile_cget(a) -> int:
    """Run a WorkflowResponder that accepts associations and answers a C-GET
    with a malicious C-STORE sub-operation (hostile C-GET responder)."""
    try:
        from .responders import WorkflowResponder
    except Exception as e:  # pragma: no cover - scapy is a hard dependency
        print(f"ERROR: hostile C-GET responder requires scapy: {e}")
        return 1

    responder = WorkflowResponder(host=a.host, port=a.port, ae_title=a.ae_title,
                                  echo_roles=True)

    @responder.on_c_get
    def _get(resp, conn, ctx_id, cmd, data):
        print(f"[rogue] C-GET -> pushing hostile C-STORE sub-op ({a.cget})")
        resp.serve_cget_hostile(conn, ctx_id, cmd, mode=a.cget)
        return None

    print(f"[rogue] hostile C-GET responder ({a.cget}) on {a.host}:{a.port}"
          f"  (Ctrl-C to stop)")
    try:
        responder.start(blocking=True)
    except KeyboardInterrupt:
        print("\n[rogue] stopping")
        responder.stop()
    return 0


def _cmd_rogue(argv: List[str]) -> int:
    """`rogue` subcommand: SCU/client fuzzing via a rogue DICOM SCP."""
    p = argparse.ArgumentParser(
        prog='c-scare rogue',
        description='Run a rogue DICOM SCP that feeds malformed responses '
                    'to a connecting DICOM client (SCU/client fuzzing).')
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=11112)
    p.add_argument('--ae-title', dest='ae_title', default='C_SCARE')
    from .hostile import ROGUE_MALFORMATION_MODES, rogue_response
    p.add_argument('--mode',
                   choices=['malformed-ac', 'reject', 'abort']
                   + list(ROGUE_MALFORMATION_MODES),
                   default='malformed-ac',
                   help='response sent on A-ASSOCIATE-RQ (default: malformed-ac). '
                        'Beyond malformed-ac/reject/abort: '
                        + ', '.join(ROGUE_MALFORMATION_MODES))
    p.add_argument('--cget', choices=['oversized', 'path-traversal', 'malformed'],
                   default=None,
                   help='accept the association and, on a C-GET, push a '
                        'malicious C-STORE sub-operation of this kind at the '
                        'SCU client (hostile C-GET responder).')
    a = p.parse_args(argv)

    if a.cget:
        return _run_hostile_cget(a)

    from .server import RawSCP
    try:
        from .scapy_dicom import DICOM, A_ASSOCIATE_AC, A_ASSOCIATE_RJ, A_ABORT
        from scapy.packet import raw
    except Exception as e:  # pragma: no cover - scapy is a hard dependency
        print(f"ERROR: rogue server requires scapy: {e}")
        return 1

    def _response() -> bytes:
        if a.mode == 'reject':
            return raw(DICOM() / A_ASSOCIATE_RJ())
        if a.mode == 'abort':
            return raw(DICOM() / A_ABORT())
        if a.mode in ROGUE_MALFORMATION_MODES:
            return rogue_response(a.mode)
        return raw(DICOM() / A_ASSOCIATE_AC(protocol_version=0xFFFF))

    scp = RawSCP(host=a.host, port=a.port, ae_title=a.ae_title)

    @scp.on_connect
    def _on_connect(conn):
        print(f"[rogue] client connected: {conn.address}")

    @scp.on_associate_rq
    def _on_assoc(conn, pdu_bytes, pkt):
        print(f"[rogue] A-ASSOCIATE-RQ ({len(pdu_bytes)} bytes) -> {a.mode}")
        return _response()

    @scp.on_pdata
    def _on_pdata(conn, pdu_bytes, pkt):
        print(f"[rogue] P-DATA-TF ({len(pdu_bytes)} bytes)")
        return None

    print(f"[rogue] mode={a.mode}  listening on {a.host}:{a.port}  (Ctrl-C to stop)")
    try:
        scp.start()
    except KeyboardInterrupt:
        print("\n[rogue] stopping")
        scp.stop()
    return 0


def _parse_tag(text: str):
    """Parse a tag token 'gggg,eeee' or 'gggg,eeee,VR' into (g, e[, vr])."""
    parts = text.split(',')
    g = int(parts[0], 16)
    e = int(parts[1], 16)
    if len(parts) >= 3 and parts[2]:
        return (g, e, parts[2])
    return (g, e)


def _cmd_workflow(argv: List[str]) -> int:
    """`wf` subcommand: SCU-side attack workflows (issuer drivers).

    Shares DICOMSession with the black-box DAST path; use these to recon / brute
    a target and to feed discovered AE titles or credentials into a DAST run.
    """
    try:
        from . import workflows as wf
        from .client import DICOMSession
        from .scapy_dicom import DEFAULT_TRANSFER_SYNTAX_UID
    except Exception as e:  # pragma: no cover - scapy is a hard dependency
        print(f"ERROR: workflows require scapy: {e}")
        return 1

    p = argparse.ArgumentParser(
        prog='c-scare wf',
        description='DICOM attack workflows (SCU issuer drivers).')
    p.add_argument('--ip', default='127.0.0.1')
    p.add_argument('--port', type=int, default=11112)
    p.add_argument('--calling-ae', dest='calling_ae', default='C_SCARE')
    p.add_argument('--timeout', type=float, default=10.0)
    sub = p.add_subparsers(dest='wfcmd', required=True)

    ab = sub.add_parser('ae-brute', help='brute-force Called AE Titles (W1)')
    ab.add_argument('--aets', help='comma-separated AE titles')
    ab.add_argument('--aet-file', help='file with one AE title per line')

    rp = sub.add_parser('respond',
                        help='run an SCP that exercises a connecting SCU client')
    rp.add_argument('--host', default='0.0.0.0')
    rp.add_argument('--ae-title', dest='ae_title', default='C_SCARE')
    rp.add_argument('--impl-version', dest='impl_version',
                    help='Implementation Version Name to advertise (<=16 chars)')
    rp.add_argument('--user-id-response', dest='user_id_response',
                    help='Type 0x59 user-identity server response to return')

    cb = sub.add_parser('cred-brute', help='brute-force User Identity creds (W2)')
    cb.add_argument('--ae-title', dest='ae_title', required=True)
    cb.add_argument('--creds', help='comma-separated user:pass pairs')
    cb.add_argument('--cred-file', help='file with one user:pass per line')
    cb.add_argument('--no-stop', action='store_true',
                    help='try all creds even after a success')

    for verb, helptext in (('find', 'sculpted C-FIND (W3)'),
                           ('move', 'C-MOVE pivot (W5)'),
                           ('get', 'C-GET retrieval (W4)')):
        q = sub.add_parser(verb, help=helptext)
        q.add_argument('--ae-title', dest='ae_title', required=True)
        q.add_argument('--level', default='study',
                       choices=['patient', 'study', 'series', 'image'])
        q.add_argument('--model', default='study', choices=['patient', 'study'])
        q.add_argument('--return-key', action='append', default=[], dest='return_keys',
                       metavar='G,E[,VR]', help='tag to request back (repeatable)')
        q.add_argument('--match', action='append', default=[], dest='matches',
                       metavar='G,E[,VR]=VALUE', help='matching key (repeatable)')
        if verb == 'move':
            q.add_argument('--dest-ae', dest='dest_ae', required=True,
                           help='C-MOVE destination AE (the pivot target)')
        if verb == 'get':
            q.add_argument('--strict', action='store_true',
                           help='strict-peer mode: propose the storage SCP role '
                                '(0x54) and abort the C-GET if the peer does not '
                                'grant it, instead of accepting objects anyway')
            q.add_argument('--storage-sop', dest='storage_sops', action='append',
                           default=[], metavar='UID',
                           help='storage SOP class UID to propose scp_role=1 for '
                                '(repeatable; default: CT + Secondary Capture)')
            q.add_argument('--sarif', metavar='FILE',
                           help='write a SARIF v2.1.0 report of role-negotiation '
                                'findings')

    a = p.parse_args(argv)
    a.result_collector = []

    if a.wfcmd == 'respond':
        from .responders import WorkflowResponder
        responder = WorkflowResponder(
            host=a.host, port=a.port, ae_title=a.ae_title,
            implementation_version_name=a.impl_version,
            user_identity_response=a.user_id_response)
        print(f"[respond] WorkflowResponder on {a.host}:{a.port} "
              f"(accepts associations, answers C-ECHO/C-FIND)  Ctrl-C to stop")
        try:
            responder.start(blocking=True)
        except KeyboardInterrupt:
            print("\n[respond] stopping")
            responder.stop()
        return 0

    if a.wfcmd == 'ae-brute':
        aets: List[str] = []
        if a.aets:
            aets += [x.strip() for x in a.aets.split(',') if x.strip()]
        if a.aet_file:
            with open(a.aet_file) as fh:
                aets += [ln.strip() for ln in fh if ln.strip()]
        if not aets:
            print("ERROR: provide --aets or --aet-file")
            return 1
        results = wf.ae_brute(a.ip, a.port, aets, calling_ae=a.calling_ae,
                              timeout=a.timeout)
        for r in results:
            if r.error:
                # No DICOM answer at all. Printing this as a rejection would
                # let an unreachable host read as "no valid AE titles".
                print(f"[?] {r.aet}: NO ANSWER ({r.error}) - inconclusive")
            elif r.accepted:
                print(f"[+] {r.aet}: ACCEPTED  "
                      f"appctx={r.application_context_uid} "
                      f"impl_uid={r.implementation_class_uid} "
                      f"impl_ver={r.implementation_version_name}")
            elif r.aet_recognized:
                # Recognised AET that rejected for another reason (e.g. auth) -
                # the AET axis is solved; pursue the next axis (W2).
                print(f"[~] {r.aet}: RECOGNIZED but rejected ({r.reason}) "
                      f"- AET valid, another gate remains")
            else:
                print(f"[-] {r.aet}: rejected ({r.reason})")
        if results and all(r.error for r in results):
            print("\nNo AE title produced a DICOM response. Check host, port and "
                  "reachability before reading anything into this run.")
            return 1
        return 0

    if a.wfcmd == 'cred-brute':
        creds: List = []
        if a.creds:
            creds += [tuple(x.split(':', 1)) for x in a.creds.split(',') if ':' in x]
        if a.cred_file:
            with open(a.cred_file) as fh:
                creds += [tuple(ln.strip().split(':', 1)) for ln in fh
                          if ':' in ln]
        if not creds:
            print("ERROR: provide --creds or --cred-file (user:pass)")
            return 1
        results = wf.cred_brute(a.ip, a.port, a.ae_title, creds,
                                calling_ae=a.calling_ae,
                                stop_on_success=not a.no_stop, timeout=a.timeout)
        for r in results:
            label = 'baseline probe' if r.is_baseline else r.username
            if r.error:
                print(f"[?] {label}: NO ANSWER ({r.error}) - inconclusive")
            elif r.credential_verified:
                print(f"[+] {label}: VERIFIED  0x59={r.server_response!r}")
            elif r.accepted and r.identity_enforced is False:
                print(f"[~] {label}: association accepted, but the target "
                      f"accepts any identity - proves nothing")
            elif r.accepted:
                print(f"[~] {label}: association accepted (identity enforcement "
                      f"unconfirmed) 0x59={r.server_response!r}")
            elif r.aet_problem:
                print(f"[!] {label}: rejected ({r.reason}) - the Called AE "
                      f"Title is wrong, not the credential; fix --ae-title first")
            else:
                print(f"[-] {label}: rejected ({r.reason})")
        if any(r.identity_enforced is False for r in results):
            print("\nThis target accepted a credential it cannot know, so it is "
                  "not enforcing User Identity Negotiation. That is itself the "
                  "finding; no credential below it is evidence of anything.")
        return 0

    # find / move / get share the query-building path.
    return_keys = [_parse_tag(t) for t in a.return_keys]
    match_keys = {}
    for m in a.matches:
        key, _, value = m.partition('=')
        match_keys[_parse_tag(key)] = value
    query = wf.build_query(level=a.level, return_keys=return_keys,
                           match_keys=match_keys)
    find_uid, get_uid, move_uid = wf.QR_MODELS[a.model]

    with DICOMSession(a.ip, a.port, a.ae_title, a.calling_ae,
                     read_timeout=a.timeout) as sock:
        if a.wfcmd == 'find':
            if not sock.associate({find_uid: [DEFAULT_TRANSFER_SYNTAX_UID]}):
                print("ERROR: association failed")
                return 1
            responses = sock.c_find(query, sop_class_uid=find_uid)
            pending = [d for s, d in responses if d is not None]
            print(f"[+] {len(pending)} matching response(s)")
            for i, ds in enumerate(pending):
                print(f"--- response {i} ---")
                print(ds)
            return 0
        if a.wfcmd == 'move':
            if not sock.associate({move_uid: [DEFAULT_TRANSFER_SYNTAX_UID]}):
                print("ERROR: association failed")
                return 1
            out = sock.c_move(query, a.dest_ae, sop_class_uid=move_uid)
            print(f"[+] C-MOVE -> {a.dest_ae}: status=0x{(out['status'] or 0):04X} "
                  f"completed={out['completed']} failed={out['failed']}")
            print("    (objects delivered to the destination AE; "
                  "retrieve them out-of-band)")
            return 0
        if a.wfcmd == 'get':
            contexts = {get_uid: [DEFAULT_TRANSFER_SYNTAX_UID]}
            roles = None
            # `wf get` associates with no User Identity Negotiation, so any
            # role the peer grants here was granted to an anonymous SCU.
            authenticated = False
            storage_sops = a.storage_sops or [
                "1.2.840.10008.5.1.4.1.1.2",    # CT Image Storage
                "1.2.840.10008.5.1.4.1.1.7",    # Secondary Capture Image Storage
            ]
            if a.strict:
                # Propose a storage context AND scp_role=1 for each storage SOP
                # class, so the SCU can receive (and the peer can grant) the
                # Storage SCP role the C-GET sub-operations need.
                roles = {}
                for s in storage_sops:
                    contexts[s] = [DEFAULT_TRANSFER_SYNTAX_UID]
                    roles[s] = (0, 1)
            if not sock.associate(contexts, roles=roles):
                print("ERROR: association failed")
                return 1
            out = sock.c_get(query, sop_class_uid=get_uid,
                             strict_role=bool(a.strict))
            if out.get('aborted'):
                print(f"[!] C-GET aborted: {out.get('reason')} "
                      f"(negotiated roles: {out.get('negotiated_roles')})")
                for s in storage_sops:
                    if out.get('negotiated_roles', {}).get(s, (0, 0))[1] != 1:
                        rn = wf.RoleNegotiationResult(
                            sop_class_uid=s, requested_scp_role=1,
                            granted_scp_role=out.get(
                                'negotiated_roles', {}).get(s, (0, 0))[1],
                            aborted=True, authenticated=authenticated,
                            negotiated_roles=out.get('negotiated_roles', {}))
                        a.result_collector.append(rn.to_attack_result())
            else:
                print(f"[+] C-GET: status=0x{(out['status'] or 0):04X} "
                      f"objects={out['num_objects']}")
                if a.strict:
                    for s in storage_sops:
                        granted = out.get('negotiated_roles', {}).get(s, (0, 0))[1]
                        rn = wf.RoleNegotiationResult(
                            sop_class_uid=s, requested_scp_role=1,
                            granted_scp_role=granted, aborted=False,
                            authenticated=authenticated,
                            negotiated_roles=out.get('negotiated_roles', {}))
                        if rn.is_authz_bypass:
                            print(f"[!] {s}: storage SCP role granted without "
                                  f"authentication (authz bypass)")
                        a.result_collector.append(rn.to_attack_result())
            if a.sarif and a.result_collector:
                write_sarif(a.result_collector, a.sarif)
                print(f"[+] SARIF report written to: {a.sarif}")
            return 0
    return 0


def _cmd_greybox(argv: List[str]) -> int:
    """`greybox` subcommand: AFL++/AFLNet harness launch + crash triage."""
    from . import greybox

    p = argparse.ArgumentParser(
        prog='c-scare greybox',
        description='Grey-box bridge to the AFL++/AFLNet fuzzing engines.')
    sub = p.add_subparsers(dest='gbcmd', required=True)

    runp = sub.add_parser('run', help='launch an AFL++/AFLNet fuzz harness')
    runp.add_argument('target', choices=sorted(greybox.TARGETS))

    trp = sub.add_parser('triage', help='triage AFL/AFLNet crashes into SARIF')
    trp.add_argument('crashes', help='AFL/AFLNet output directory or crashes dir')
    trp.add_argument('--binary', action='append', default=[], dest='binaries',
                     metavar='PATH',
                     help='instrumented binary to replay crashes through. For '
                          'file targets: a SAND sanitizer worker (repeat for '
                          'several sanitizers). For --net: the instrumented '
                          'DICOM server.')
    trp.add_argument('--auto', action='store_true',
                     help='recover the replay command from AFL\'s own '
                          'cmdline/fuzzer_setup metadata in the output tree, '
                          'including any SAND worker the campaign used, '
                          'instead of naming --binary/--arg by hand')
    trp.add_argument('--sand', metavar='BINNAME',
                     help='auto-discover SAND sanitizer-worker binaries named '
                          'BINNAME under fuzz/build-san-*/ and triage through '
                          'each (scripts/build_dcmtk.sh SAND=1)')
    trp.add_argument('--net', metavar='TARGET', choices=greybox.NET_TARGETS,
                     help='AFLNet network triage: replay each input at a '
                          'freshly launched instrumented server via '
                          'aflnet-replay. TARGET ∈ ' +
                          ', '.join(greybox.NET_TARGETS))
    trp.add_argument('--arg', action='append', default=[], dest='args',
                     help='binary argument; use @@ for the crash file path '
                          '(file targets only)')
    trp.add_argument('--sarif', help='write a SARIF v2.1.0 report here')
    trp.add_argument('--timeout', type=float, default=10.0)
    trp.add_argument('--include-queue', action='store_true',
                     help='also triage queue inputs - required to catch '
                          'leak-class bugs, which do not crash')
    trp.add_argument('--include-hangs', action='store_true',
                     help='also triage AFL/AFLNet saved hangs by replaying '
                          'them with --timeout')
    a = p.parse_args(argv)

    if a.gbcmd == 'run':
        return greybox.run(a.target)

    if a.net:
        if not a.binaries:
            print("ERROR: --net triage needs --binary <instrumented server> "
                  "(e.g. fuzz/build-net/.../storescp)")
            return 1
        if a.sand:
            print("WARNING: --sand applies to file targets only; "
                  "ignored for --net")
        cmds = [[b] for b in a.binaries]
    else:
        cmds = [[b] + a.args for b in a.binaries]
        if a.auto:
            discovered = greybox.discover_replay_commands(a.crashes)
            if not discovered:
                print(f"WARNING: no AFL cmdline/fuzzer_setup metadata under "
                      f"{a.crashes} - pass --binary/--arg explicitly")
            for cmd in discovered:
                print(f"Discovered replay command: {' '.join(cmd)}")
            cmds += [cmd for cmd in discovered if cmd not in cmds]
        if a.sand:
            workers = greybox.find_san_workers(a.sand)
            if not workers:
                print(f"WARNING: no SAND workers named '{a.sand}' found under "
                      f"fuzz/build-san-*/ - run scripts/build_dcmtk.sh "
                      f"with SAND=1")
            for w in workers:
                print(f"SAND worker: {w}")
            cmds += [[w] + a.args for w in workers]
        cmds = cmds or None

    results = greybox.triage_to_sarif(
        a.crashes, cmds=cmds, net_target=a.net, sarif_path=a.sarif,
        timeout=a.timeout, include_queue=a.include_queue,
        include_hangs=a.include_hangs)
    detected = sum(1 for r in results if r.success)
    print(f"\nTriaged {len(results)} fuzz input(s); "
          f"{detected} reproduced a sanitizer/crash finding")
    for r in results:
        mark = '!' if r.success else ('.' if cmds else '?')
        print(f"  {mark} {r.name} ({r.metadata.get('size', 0)} bytes)")
        for report in r.monitor_reports:
            print(f"      {report.finding_type}: {report.description}")
    if a.sarif:
        print(f"\nSARIF report written to: {a.sarif}")
    return 0


def main(argv: Optional[List[str]] = None):
    """Main entry point."""
    if argv is None:
        argv = sys.argv[1:]

    # Matrix subcommands. With no subcommand, fall through to black-box DAST
    # mode (the --ip/--port/--category flag interface below).
    if argv and argv[0] in ('rogue', 'corpus', 'greybox', 'wf', 'dast'):
        sub = argv[0]
        if sub == 'rogue':
            return _cmd_rogue(argv[1:])
        if sub == 'corpus':
            return _cmd_corpus(argv[1:])
        if sub == 'greybox':
            return _cmd_greybox(argv[1:])
        if sub == 'wf':
            return _cmd_workflow(argv[1:])
        argv = argv[1:]  # 'dast' is the default mode: strip and continue

    parser = argparse.ArgumentParser(
        description='C-Scare DICOM Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Connection parameters (matching GitHub Actions workflow)
    parser.add_argument(
        '--ip',
        default='127.0.0.1',
        help='Target IP address (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=11112,
        help='Target port (default: 11112)'
    )
    
    parser.add_argument(
        '--ae-title',
        dest='ae_title',
        default='ANY-SCP',
        help='Called AE title (default: ANY-SCP)'
    )

    parser.add_argument(
        '--calling-ae',
        dest='calling_ae',
        default='ATTACKER',
        help='Calling AE title for association-based delivery (default: ATTACKER)'
    )
    
    # Test selection
    parser.add_argument(
        '--category',
        choices=['parser', 'protocol', 'memory', 'logic', 'storage_abuse',
             'command_injection', 'path_traversal', 'state_machine', 'cve',
             'negotiation', 'dimse_n', 'fuzz_packet', 'live_fuzz', 'all'],
        help='Test category to run (if not specified, runs all)'
    )
    
    # Additional options
    parser.add_argument(
        '-o', '--output',
        help='Output directory for generated files'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=10.0,
        help='Timeout for network operations (default: 10.0)'
    )
    
    parser.add_argument(
        '--live-fuzz-count',
        type=int,
        default=10,
        help='Number of live fuzz iterations (default: 10)'
    )
    
    parser.add_argument(
        '--generate-corpus',
        metavar='DIR',
        help='Generate fuzzing corpus in specified directory'
    )

    parser.add_argument(
        '--sarif',
        metavar='FILE',
        help='Write SARIF v2.1.0 report to file'
    )

    parser.add_argument(
        '--dicomweb-url',
        metavar='URL',
        help='Deliver over DICOMweb instead of DIMSE, e.g. '
             'http://host:8042/dicom-web. STOW-RS posts complete Part-10 '
             'instances as application/dicom, so the 128-byte preamble and '
             'anything past the Data Set cross the wire — which C-STORE '
             'cannot do. Retrieval uses WADO-RS.')
    parser.add_argument(
        '--dicomweb-token',
        metavar='TOKEN',
        help='Bearer token for the DICOMweb endpoint.')
    parser.add_argument(
        '--insecure',
        action='store_true',
        help='Skip TLS verification for --dicomweb-url. Clinical endpoints '
             'often present internal-CA certificates; this is opt-in so a '
             'run never silently downgrades.')
    parser.add_argument(
        '--verify-retrieval',
        action='store_true',
        help='After a successful C-STORE, fetch the instance back with C-GET '
             'and report what the archive did to the embedded content: '
             'returned intact, payload retained, altered, or stripped. '
             'Acceptance alone cannot tell a distribution channel from an '
             'archive that neutralised the object. Costs one extra '
             'association per stored payload and needs C-GET support.')
    parser.add_argument(
        '--delivery',
        choices=['auto', 'pdu', 'cstore'],
        default='auto',
        help='How to deliver a payload to the target (default: auto). '
             '"pdu" sends raw bytes straight to the listening port - a '
             'PDU-level attack that never reaches the dataset parser. '
             '"cstore" wraps the payload in a valid C-STORE association so '
             'dataset attacks (parser/memory/logic/storage_abuse/path_traversal) reach the SCP '
             'import/parse pass. "auto" routes by attack: payloads carrying a '
             'C-STORE SOP class (or in a dataset category) go via C-STORE, '
             'multi-step state-machine attacks go as a PDU sequence, and the '
             'rest go as a single raw PDU.'
    )

    parser.add_argument(
        '--store-sop',
        dest='store_sop',
        metavar='UID',
        default=None,
        help='Storage SOP Class UID to associate with for C-STORE delivery '
             'when an attack does not specify one (default: Secondary Capture).'
    )

    parser.add_argument(
        '--store-transfer-syntax',
        dest='store_transfer_syntax',
        metavar='UID',
        default=None,
        help='Transfer Syntax UID to request for C-STORE delivery when an attack '
             'does not specify one (default: Implicit VR Little Endian).'
    )

    parser.add_argument(
        '--cstore-smoke',
        action='store_true',
        help='Before malformed tests, send a known-good Secondary Capture '
             'C-STORE using --ae-title, --calling-ae, --store-sop, and '
             '--store-transfer-syntax. Abort the run if it is not accepted.'
    )

    parser.add_argument(
        '--cstore-file',
        metavar='FILE',
        default=None,
        help='Known-good Part-10 DICOM file to carry the catalog. Dataset-shaped '
             'attacks are overlaid on a copy of this object instead of riding a '
             'tiny synthetic dataset, so payloads survive an SCP that rejects '
             'objects missing device-specific required elements. Each delivered '
             'copy gets a fresh Study/Series/SOP Instance UID.'
    )


    parser.add_argument(
        '--mutate',
        metavar='MODE[,MODE...]',
        default=None,
        help='Mutate each payload on the wire before delivery. Comma-separated '
             'modes: bitflip (raw byte flip), vr (corrupt an element VR), '
             'length (lie about an element length). Records the mutation under '
             'the SARIF result\'s properties.mutation.'
    )

    # --- Clinical safety guardrails -------------------------------------
    # A PACS is often a live clinical system. These bound what a run can do to
    # it, and make the availability-affecting categories opt-in rather than
    # something you get by typing --category all.
    parser.add_argument(
        '--dry-run',
        dest='dry_run',
        metavar='DIR',
        default=None,
        help='Do not touch the network. Write each payload that would have '
             'been delivered into DIR (.dcm for C-STORE datasets, .bin for raw '
             'PDUs and sequence steps) and report every test as a non-finding. '
             'Use this to review a catalog before pointing it at a live PACS.'
    )

    parser.add_argument(
        '--max-associations',
        dest='max_associations',
        type=int,
        metavar='N',
        default=None,
        help='Abort the run once it has opened N associations against the '
             'target (default: unlimited). A whole-run budget on connection '
             'churn, not a concurrency cap — delivery is sequential.'
    )

    parser.add_argument(
        '--allow-availability',
        dest='allow_availability',
        action='store_true',
        help='Opt in to categories that can degrade target availability '
             f'({", ".join(sorted(AVAILABILITY_CATEGORIES))}): resource '
             'exhaustion, disk pressure, and state-machine sequences that '
             'abort associations. Without this flag they are skipped.'
    )

    parser.add_argument(
        '--asan-binary',
        metavar='PATH',
        help='Path to ASan-instrumented target binary (e.g., storescp compiled with -fsanitize=address,undefined). '
             'Enables SanitizerMonitor + ProcessMonitor + ProtocolMonitor for per-test detection.'
    )

    parser.add_argument(
        '--asan-port',
        type=int,
        default=None,
        help='Port for ASan-instrumented binary (default: same as --port)'
    )

    args = parser.parse_args(argv)

    # Build target string
    args.target = f"{args.ip}:{args.port}"
    args.count = args.live_fuzz_count

    # Map category to command
    category_map = {
        'parser': 'parser_attacks',
        'protocol': 'protocol_attacks',
        'memory': 'memory_attacks',
        'logic': 'logic_attacks',
        'storage_abuse': 'storage_scp_abuse_attacks',
        'command_injection': 'command_injection_attacks',
        'path_traversal': 'path_traversal_attacks',
        'negotiation': 'negotiation_attacks',
        'dimse_n': 'dimse_n_attacks',
        'state_machine': 'state_machine_attacks',
        'cve': 'cve_attacks',
        'fuzz_packet': 'fuzz_packets',
        # Not in run_all_tests: a randomized loop, not a static catalog.
        'live_fuzz': 'protocol_fuzzing',
        'all': 'all',
    }

    # Handle corpus generation
    if args.generate_corpus:
        args.output = args.generate_corpus
        return run_command('generate_corpus', args)

    # Determine command from category
    if args.category:
        command = category_map.get(args.category, 'all')
    else:
        command = 'all'

    # Set up result collector for JUnit XML output
    args.result_collector = []

    # Set up monitors if --asan-binary is specified
    args._monitors = []
    args._managed_process = None
    args._associations_used = 0

    # Load --cstore-file up front. A carrier that cannot be read is an
    # operator error, and finding out about it on the first delivery buries it
    # under a wall of per-attack output.
    if args.cstore_file:
        try:
            carrier = _get_cstore_file_context(args)
        except CarrierError as exc:
            print(f"ERROR: --cstore-file: {exc}")
            return 1
        print(f"Carrier: {carrier.path}")
        print(f"  Encoding: {carrier.transfer_syntax}"
              + ("  (sniffed - the file has no File Meta Information)"
                 if carrier.sniffed_encoding else ""))
        print(f"  Data Set: {len(carrier.dataset)} bytes, "
              f"{len(carrier.elements)} top-level elements")
        if carrier.has_tail:
            print(f"  WARNING: {len(carrier.dataset) - carrier.tail_offset} "
                  "trailing bytes did not parse as Data Elements; they are "
                  "delivered unchanged but no attack can be placed in them.")
        print()

    if args.dry_run:
        print(f"DRY RUN: writing payloads to {os.path.abspath(args.dry_run)} "
              f"(nothing is sent to {args.target})")
        print()
    if args.max_associations:
        print(f"Association budget: {args.max_associations}")
        print()

    if args.asan_binary:
        asan_port = args.asan_port or args.port
        cmd = [args.asan_binary, str(asan_port)]
        proc = InstrumentedProcess(cmd)
        proc.start()
        time.sleep(1.0)

        if not proc.is_alive():
            log = proc.get_full_log()
            print(f"ERROR: ASan binary failed to start: {log[:500]}")
            return 1

        args._managed_process = proc
        args._monitors = [
            SanitizerMonitor(proc),
            ProcessMonitor(proc),
            ProtocolMonitor(),
        ]
        if getattr(args, 'verify_retrieval', False):
            args._monitors.append(PipelineMonitor())
        args.target = f"{args.ip}:{asan_port}"
        print(f"Monitors: SanitizerMonitor, ProcessMonitor, ProtocolMonitor")
        print(f"Target: {args.target} (ASan-instrumented)")
        print()
    else:
        args._monitors = [ProtocolMonitor()]
        if getattr(args, 'verify_retrieval', False):
            args._monitors.append(PipelineMonitor())
        print("Monitors: " + ", ".join(type(m).__name__
                                       for m in args._monitors)
              + " (black-box)")
        print(f"Target: {args.target}")
        print()

    if args.cstore_smoke and not args.dry_run:
        host, port = args.target.rsplit(':', 1)
        _charge_associations(args, 1)
        smoke_rc = _run_cstore_smoke(args, (host, int(port)))
        print()
        if smoke_rc != 0:
            return smoke_rc

    try:
        ret = run_command(command, args)
    except AssociationBudgetExceeded as e:
        # Not a failure: the run stopped exactly where it was told to. Results
        # gathered so far are still collected and reported below.
        print(f"\nSTOPPED: {e}")
        ret = 0
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        ret = 130
    except Exception as e:
        print(f"\nERROR: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        ret = 1
    finally:
        if args._managed_process:
            args._managed_process.stop()
            for monitor in args._monitors:
                monitor.teardown()

    # Print monitor summary
    if args._monitors and args.result_collector:
        detected_count = sum(
            1 for r in args.result_collector
            if any(rpt.detected for rpt in r.monitor_reports)
        )
        total = len(args.result_collector)
        print(f"\n{'='*50}")
        print(f"Monitor Summary: {detected_count}/{total} tests triggered detections")
        print(f"{'='*50}")

    if args.sarif and args.result_collector:
        write_sarif(args.result_collector, args.sarif)
        print(f"\nSARIF report written to: {args.sarif}")

    return ret


if __name__ == '__main__':
    sys.exit(main())