"""
DICOM client / association session.

``DICOMSocket`` is C-SCARE's stateful SCU client: it opens the TCP connection,
drives A-ASSOCIATE negotiation, issues DIMSE-C/N operations (C-ECHO/STORE/
FIND/GET/MOVE), and parses the peer's responses. It builds on the pure
wire-format layer in :mod:`c_scare.scapy_dicom` (the declarative Scapy
``Packet`` definitions, which are upstreamable as a Scapy contrib module) and is
the part that *cannot* live in Scapy: it holds connection state and does socket
I/O.

``classify_reject`` / ``reject_is_called_aet_unrecognized`` interpret an
A-ASSOCIATE-RJ into pentest-recon semantics (distinguishing a wrong Called AE
Title from a bad credential) and live here alongside their workflow consumers,
not in the protocol layer.
"""

import logging
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from scapy.packet import Packet
from scapy.supersocket import StreamSocket

# The DICOM wire-format layer. DICOMSocket consumes a broad slice of it (PDUs,
# DIMSE classes, UID/status constants, builders), so import it wholesale.
from .scapy_dicom import *  # noqa: F401,F403
# Internal dissection helpers that are intentionally not part of
# scapy_dicom.__all__ but are used by the response parsers below.
from .scapy_dicom import (
    decode_uid,
    iter_user_info_subitems,
    iter_variable_items,
)

log = logging.getLogger("scapy.contrib.dicom")


def classify_reject(reject):
    # type: (Optional[Dict[str, int]]) -> Optional[str]
    """Map an A-ASSOCIATE-RJ ``{result, source, reason}`` to a canonical slug.

    This is what lets AE-title and credential brute force be run as *separate*
    axes: a wrong Called AE Title rejects with source 1 / reason 7
    (``called-AE-title-not-recognized``), whereas a bad credential rejects with
    a source 2 (ACSE) code — pynetdicom uses ``(2, 2, 1)`` per PS3.8 — so the
    two failure modes are distinguishable on the wire."""
    if not reject:
        return None
    source = reject.get("source")
    reason = reject.get("reason")
    table = {
        1: A_ASSOCIATE_RJ.REASON_USER,
        2: A_ASSOCIATE_RJ.REASON_ACSE,
        3: A_ASSOCIATE_RJ.REASON_PRESENTATION,
    }.get(source, {})
    return table.get(reason, "source%s-reason%s" % (source, reason))


def reject_is_called_aet_unrecognized(reject):
    # type: (Optional[Dict[str, int]]) -> bool
    """True iff the reject is specifically ``called-AE-title-not-recognized``
    (source 1, reason 7) — i.e. *this* Called AE Title is wrong. Any other
    reject means the AET was recognised and the problem lies elsewhere
    (commonly user-identity/auth), so the AET axis can be considered solved."""
    return bool(reject) and reject.get("source") == 1 and reject.get("reason") == 7


class DICOMSocket:
    """DICOM application-layer socket for associations and DIMSE operations."""

    def __init__(self, dst_ip, dst_port, dst_ae, src_ae="SCAPY_SCU", read_timeout=10):
        # type: (str, int, str, str, int) -> None
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_ae = dst_ae
        self.src_ae = src_ae
        self.sock = None  # type: Optional[socket.socket]
        self.stream = None  # type: Optional[StreamSocket]
        self.assoc_established = False
        self.accepted_contexts = {}  # type: Dict[int, Tuple[str, str]]
        self.read_timeout = read_timeout
        self._current_message_id_counter = int(time.time()) % 50000
        self._proposed_max_pdu = 16384
        self.max_pdu_length = 16384
        self._proposed_context_map = {}  # type: Dict[int, str]
        # Populated from the A-ASSOCIATE-AC so callers (fingerprinting, AE
        # brute, credential brute) can read the *payload* of what came back,
        # not just accept/reject.
        self.peer_info = {}  # type: Dict[str, str]
        self.user_identity_response = None  # type: Optional[bytes]
        self.last_reject = None  # type: Optional[Dict[str, int]]
        # SOP-class -> (scu_role, scp_role) granted by the peer in the AC's
        # Type 0x54 sub-items. A SOP class absent here was not role-negotiated.
        self.negotiated_roles = {}  # type: Dict[str, Tuple[int, int]]

    def __enter__(self):
        # type: () -> DICOMSocket
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # type: (Any, Any, Any) -> bool
        if self.assoc_established:
            try:
                self.release()
            except (socket.error, socket.timeout, OSError):
                pass
        self.close()
        return False

    def connect(self):
        # type: () -> bool
        try:
            self.sock = socket.create_connection(
                (self.dst_ip, self.dst_port),
                timeout=self.read_timeout,
            )
            self.stream = StreamSocket(self.sock, basecls=DICOM)
            return True
        except (socket.error, socket.timeout, OSError) as e:
            log.error("Connection failed: %s", e)
            return False

    def send(self, pkt):
        # type: (Packet) -> None
        self.stream.send(pkt)

    def recv(self):
        # type: () -> Optional[Packet]
        try:
            return self.stream.recv()
        except socket.timeout:
            return None
        except (socket.error, OSError) as e:
            log.error("Error receiving PDU: %s", e)
            return None

    def sr1(self, *args, **kargs):
        # type: (*Any, **Any) -> Optional[Packet]
        """Send one packet and receive one answer."""
        timeout = kargs.pop("timeout", self.read_timeout)
        try:
            return self.stream.sr1(*args, timeout=timeout, **kargs)
        except (socket.error, OSError) as e:
            log.error("Error in sr1: %s", e)
            return None

    def send_raw_bytes(self, raw_bytes):
        # type: (bytes) -> None
        self.sock.sendall(raw_bytes)

    def associate(self, requested_contexts=None, user_identity=None,
                  roles=None):
        # type: (Optional[Dict[str, List[str]]], Optional[Any], Optional[Dict[str, Tuple[int, int]]]) -> bool
        """Open an association.

        ``user_identity`` (a ``DICOMUserIdentity`` packet or a dict, see
        :func:`build_user_identity`) sends a Type 0x58 User Identity
        Negotiation sub-item. ``roles`` (``{sop_class_uid: (scu_role,
        scp_role)}``) sends Type 0x54 SCP/SCU Role Selection sub-items — needed
        for C-GET, where the requestor proposes ``scp_role=1`` for the storage
        SOP class so it may receive objects as Storage SCP. On a successful AC
        the AC payload is parsed into :attr:`peer_info` (application-context
        UID, implementation class UID, implementation version name), the
        granted roles into :attr:`negotiated_roles`, and any Type 0x59 server
        response into :attr:`user_identity_response`; on rejection the
        result/source/reason are stored in :attr:`last_reject`.
        """
        if not self.stream and not self.connect():
            return False

        if requested_contexts is None:
            requested_contexts = {
                VERIFICATION_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]
            }

        self._proposed_context_map = {}
        self.peer_info = {}
        self.user_identity_response = None
        self.last_reject = None
        self.negotiated_roles = {}

        variable_items = [
            DICOMVariableItem() / DICOMApplicationContext()
        ]  # type: List[Packet]

        ctx_id = 1
        for abs_syntax, trn_syntaxes in requested_contexts.items():
            self._proposed_context_map[ctx_id] = abs_syntax
            pctx = build_presentation_context_rq(ctx_id, abs_syntax, trn_syntaxes)
            variable_items.append(pctx)
            ctx_id += 2

        user_info = build_user_information(
            max_pdu_length=self._proposed_max_pdu,
            user_identity=user_identity,
            roles=roles,
        )
        variable_items.append(user_info)

        assoc_rq = DICOM() / A_ASSOCIATE_RQ(
            called_ae_title=self.dst_ae,
            calling_ae_title=self.src_ae,
            variable_items=variable_items,
        )

        # Use send + recv rather than sr1: the association response is not a
        # DIMSE message and scapy's sr1 answer-matching does not pair the AC/RJ
        # PDU with the RQ, so it would drop the reply.
        self.send(assoc_rq)
        response = self.recv()

        if response:
            if response.haslayer(A_ASSOCIATE_AC):
                self.assoc_established = True
                self._parse_accepted_contexts(response)
                self._parse_max_pdu_length(response)
                self._parse_peer_info(response)
                self._parse_user_identity_response(response)
                self._parse_negotiated_roles(response)
                return True
            elif response.haslayer(A_ASSOCIATE_RJ):
                rj = response[A_ASSOCIATE_RJ]
                self.last_reject = {
                    "result": rj.result,
                    "source": rj.source,
                    "reason": rj.reason_diag,
                }
                log.error(
                    "Association rejected: result=%d, source=%d, reason=%d",
                    rj.result, rj.source, rj.reason_diag,
                )
                return False

        log.error("Association failed: no valid response received")
        return False

    def _parse_peer_info(self, response):
        # type: (Packet) -> None
        """Read the AC payload — App Context UID + 0x52/0x55 sub-items — so an
        AE/recon workflow can report *what* a peer returned, not just that it
        accepted."""
        try:
            ac = response[A_ASSOCIATE_AC]
            for item in iter_variable_items(ac, 0x10):
                if item.haslayer(DICOMApplicationContext):
                    self.peer_info["application_context_uid"] = decode_uid(
                        item[DICOMApplicationContext].uid).strip()
            for sub in iter_user_info_subitems(ac, 0x52, DICOMImplementationClassUID):
                self.peer_info["implementation_class_uid"] = decode_uid(
                    sub[DICOMImplementationClassUID].uid).strip()
            for sub in iter_user_info_subitems(ac, 0x55, DICOMImplementationVersionName):
                # NB: the field is named "name", which collides with scapy's
                # Packet.name; read it via getfieldval.
                self.peer_info["implementation_version_name"] = decode_uid(
                    sub[DICOMImplementationVersionName].getfieldval("name")).strip()
        except (KeyError, IndexError, AttributeError):
            pass

    def _parse_user_identity_response(self, response):
        # type: (Packet) -> None
        """Capture the Type 0x59 User Identity server-response payload, which is
        only populated when identity negotiation succeeds (PS3.7 D.3.3.7)."""
        try:
            ac = response[A_ASSOCIATE_AC]
            for sub in iter_user_info_subitems(ac, 0x59, DICOMUserIdentityResponse):
                self.user_identity_response = bytes(
                    sub[DICOMUserIdentityResponse].server_response)
                return
        except (KeyError, IndexError, AttributeError):
            pass

    def _parse_negotiated_roles(self, response):
        # type: (Packet) -> None
        """Capture the Type 0x54 SCP/SCU Role Selection items the acceptor
        echoes in the AC (PS3.7 D.3.3.4) into :attr:`negotiated_roles`. An
        acceptor that declines a role may return ``scp_role=0`` *or* omit the
        item entirely; a SOP class absent from this map was not granted."""
        try:
            ac = response[A_ASSOCIATE_AC]
            for sub in iter_user_info_subitems(ac, 0x54, DICOMSCPSCURoleSelection):
                role = sub[DICOMSCPSCURoleSelection]
                self.negotiated_roles[decode_uid(role.sop_class_uid)] = (
                    int(role.scu_role), int(role.scp_role))
        except (KeyError, IndexError, AttributeError):
            pass

    def _parse_max_pdu_length(self, response):
        # type: (Packet) -> None
        try:
            ac = response[A_ASSOCIATE_AC]
            for sub in iter_user_info_subitems(ac, 0x51, DICOMMaximumLength):
                server_max = sub[DICOMMaximumLength].max_pdu_length
                self.max_pdu_length = min(self._proposed_max_pdu, server_max)
                return
        except (KeyError, IndexError, AttributeError):
            pass
        self.max_pdu_length = self._proposed_max_pdu

    def _parse_accepted_contexts(self, response):
        # type: (Packet) -> None
        for item in iter_variable_items(response[A_ASSOCIATE_AC], 0x21):
            if not item.haslayer(DICOMPresentationContextAC):
                continue
            pctx = item[DICOMPresentationContextAC]
            ctx_id = pctx.context_id

            if pctx.result != 0:
                continue

            abs_syntax = self._proposed_context_map.get(ctx_id)
            if abs_syntax is None:
                continue

            for sub_item in pctx.sub_items:
                if sub_item.item_type != 0x40:
                    continue
                if not sub_item.haslayer(DICOMTransferSyntax):
                    continue
                ts_uid = decode_uid(sub_item[DICOMTransferSyntax].uid)
                self.accepted_contexts[ctx_id] = (abs_syntax, ts_uid)
                break

    def _get_next_message_id(self):
        # type: () -> int
        self._current_message_id_counter += 1
        return self._current_message_id_counter & 0xFFFF

    def _find_accepted_context_id(self, sop_class_uid, transfer_syntax_uid=None):
        # type: (str, Optional[str]) -> Optional[int]
        for ctx_id, (abs_syntax, ts_syntax) in self.accepted_contexts.items():
            if abs_syntax == sop_class_uid:
                if transfer_syntax_uid is None or transfer_syntax_uid == ts_syntax:
                    return ctx_id
        return None

    def c_echo(self):
        # type: () -> Optional[int]
        if not self.assoc_established:
            log.error("Association not established")
            return None

        echo_ctx_id = self._find_accepted_context_id(VERIFICATION_SOP_CLASS_UID)
        if echo_ctx_id is None:
            log.error("No accepted context for Verification SOP Class")
            return None

        msg_id = self._get_next_message_id()
        dimse_rq = bytes(C_ECHO_RQ(message_id=msg_id))

        pdv_rq = PresentationDataValueItem(
            context_id=echo_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_rq = DICOM() / P_DATA_TF(pdv_items=[pdv_rq])

        response = self.sr1(pdata_rq)

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                return parse_dimse_status(pdv_rsp.data)
        return None

    def c_store(self, dataset_bytes, sop_class_uid, sop_instance_uid, transfer_syntax_uid):
        # type: (bytes, str, str, str) -> Optional[int]
        if not self.assoc_established:
            log.error("Association not established")
            return None

        store_ctx_id = self._find_accepted_context_id(
            sop_class_uid,
            transfer_syntax_uid,
        )
        if store_ctx_id is None:
            log.error(
                "No accepted context for SOP %s with TS %s",
                sop_class_uid,
                transfer_syntax_uid,
            )
            return None

        msg_id = self._get_next_message_id()

        dimse_rq = bytes(C_STORE_RQ(
            affected_sop_class_uid=sop_class_uid,
            affected_sop_instance_uid=sop_instance_uid,
            message_id=msg_id,
        ))

        cmd_pdv = PresentationDataValueItem(
            context_id=store_ctx_id,
            data=dimse_rq,
            is_command=1,
            is_last=1,
        )
        pdata_cmd = DICOM() / P_DATA_TF(pdv_items=[cmd_pdv])
        self.send(pdata_cmd)

        max_pdv_data = self.max_pdu_length - 12

        if len(dataset_bytes) <= max_pdv_data:
            data_pdv = PresentationDataValueItem(
                context_id=store_ctx_id,
                data=dataset_bytes,
                is_command=0,
                is_last=1,
            )
            pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
            self.send(pdata_data)
        else:
            offset = 0
            while offset < len(dataset_bytes):
                chunk = dataset_bytes[offset:offset + max_pdv_data]
                is_last = 1 if (offset + len(chunk) >= len(dataset_bytes)) else 0
                data_pdv = PresentationDataValueItem(
                    context_id=store_ctx_id,
                    data=chunk,
                    is_command=0,
                    is_last=is_last,
                )
                pdata_data = DICOM() / P_DATA_TF(pdv_items=[data_pdv])
                self.send(pdata_data)
                offset += len(chunk)

        response = self.recv()

        if response and response.haslayer(P_DATA_TF):
            pdv_items = response[P_DATA_TF].pdv_items
            if pdv_items:
                pdv_rsp = pdv_items[0]
                return parse_dimse_status(pdv_rsp.data)
        return None

    # ------------------------------------------------------------------
    # Query / retrieve flows (C-FIND / C-MOVE / C-GET).
    #
    # These build on the same association + P-DATA plumbing as c_store; they
    # add the request/response *stream* handling (Pending -> Success) and
    # dataset (de)serialisation that turns the existing packet classes into
    # usable operations.
    # ------------------------------------------------------------------

    def _ctx_is_implicit_vr(self, ctx_id):
        # type: (int) -> bool
        ts = self.accepted_contexts.get(ctx_id, (None, None))[1]
        # Implicit VR LE is the default; treat an unknown/empty TS as implicit.
        return ts in (None, "", IMPLICIT_VR_LITTLE_ENDIAN_UID)

    @staticmethod
    def _encode_query(query_ds, implicit_vr):
        # type: (Any, bool) -> bytes
        """Encode a query identifier dataset to bytes in the negotiated syntax.

        Accepts a c_scare ``Dataset`` (preferred — supports private tags and
        empty return keys), a pydicom ``Dataset``, or raw ``bytes``."""
        if isinstance(query_ds, (bytes, bytearray)):
            return bytes(query_ds)
        # c_scare Dataset
        if hasattr(query_ds, "encode"):
            try:
                return query_ds.encode(implicit_vr=implicit_vr, little_endian=True)
            except TypeError:
                pass
        # pydicom Dataset fallback
        try:
            from io import BytesIO
            from pydicom.filewriter import write_dataset
            from pydicom.filebase import DicomBytesIO
            buf = DicomBytesIO()
            buf.is_implicit_VR = implicit_vr
            buf.is_little_endian = True
            write_dataset(buf, query_ds)
            return buf.getvalue()
        except Exception:
            return b""

    @staticmethod
    def _decode_identifier(data_bytes, implicit_vr):
        # type: (Optional[bytes], bool) -> Any
        """Decode a returned identifier dataset to a pydicom Dataset (so the
        operator can read return keys, incl. private tags). Falls back to raw
        bytes if pydicom can't parse it."""
        if not data_bytes:
            return None
        try:
            from io import BytesIO
            from pydicom.filereader import read_dataset
            return read_dataset(
                BytesIO(data_bytes),
                is_implicit_VR=implicit_vr,
                is_little_endian=True,
            )
        except Exception:
            return data_bytes

    def _send_command_and_data(self, ctx_id, command_bytes, dataset_bytes=None):
        # type: (int, bytes, Optional[bytes]) -> None
        """Send a DIMSE command PDV followed by its (chunked) data PDVs."""
        cmd_pdv = PresentationDataValueItem(
            context_id=ctx_id, data=command_bytes, is_command=1, is_last=1,
        )
        self.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

        if not dataset_bytes:
            return

        max_pdv_data = self.max_pdu_length - 12
        offset = 0
        total = len(dataset_bytes)
        while offset < total:
            chunk = dataset_bytes[offset:offset + max_pdv_data]
            is_last = 1 if (offset + len(chunk) >= total) else 0
            data_pdv = PresentationDataValueItem(
                context_id=ctx_id, data=chunk, is_command=0, is_last=is_last,
            )
            self.send(DICOM() / P_DATA_TF(pdv_items=[data_pdv]))
            offset += len(chunk)

    def _recv_dimse(self):
        # type: () -> Tuple[Optional[int], Optional[bytes], Optional[bytes]]
        """Receive and reassemble one DIMSE message.

        Returns ``(context_id, command_bytes, dataset_bytes)``. ``dataset_bytes``
        is ``None`` when the command's Data Set Type is 0x0101 (no dataset).
        Returns ``(None, None, None)`` on timeout/abort/release."""
        cmd = b""
        data = b""
        ctx_id = None
        cmd_done = False
        data_done = False
        expect_data = None  # type: Optional[bool]

        while True:
            pdu = self.recv()
            if pdu is None:
                return (ctx_id, cmd or None, data or None)
            if pdu.haslayer(A_ABORT) or pdu.haslayer(A_RELEASE_RQ) or pdu.haslayer(A_RELEASE_RP):
                return (ctx_id, cmd or None, data or None)
            if not pdu.haslayer(P_DATA_TF):
                continue

            for pdv in pdu[P_DATA_TF].pdv_items:
                if ctx_id is None:
                    ctx_id = pdv.context_id
                if pdv.is_command:
                    cmd += bytes(pdv.data)
                    if pdv.is_last:
                        cmd_done = True
                else:
                    data += bytes(pdv.data)
                    if pdv.is_last:
                        data_done = True

            if cmd_done and expect_data is None:
                dst = parse_dimse_command_us(cmd, 0x0000, 0x0800)
                expect_data = dst is not None and dst != 0x0101

            if cmd_done and expect_data is False:
                return (ctx_id, cmd or None, None)
            if cmd_done and expect_data and data_done:
                return (ctx_id, cmd or None, data or None)

    def c_find(self, query_ds, sop_class_uid=PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
               priority=0x0002):
        # type: (Any, str, int) -> List[Tuple[Optional[int], Any]]
        """Issue a C-FIND and collect the Pending->Success response stream.

        Returns a list of ``(status, identifier)`` pairs — one per Pending
        C-FIND-RSP (with its decoded identifier dataset) plus a final terminal
        status (Success/failure, identifier ``None``). The caller controls the
        return-key set via ``query_ds``: include a key with an empty value to
        request it back, omit it to leave it out."""
        if not self.assoc_established:
            log.error("Association not established")
            return []
        ctx_id = self._find_accepted_context_id(sop_class_uid)
        if ctx_id is None:
            log.error("No accepted context for SOP %s", sop_class_uid)
            return []

        implicit = self._ctx_is_implicit_vr(ctx_id)
        q_bytes = self._encode_query(query_ds, implicit)
        msg_id = self._get_next_message_id()
        cmd = bytes(C_FIND_RQ(
            affected_sop_class_uid=sop_class_uid,
            message_id=msg_id,
            priority=priority,
            data_set_type=0x0001,  # != 0x0101 -> a dataset follows
        ))
        self._send_command_and_data(ctx_id, cmd, q_bytes)

        results = []  # type: List[Tuple[Optional[int], Any]]
        while True:
            _cid, rcmd, rdata = self._recv_dimse()
            if rcmd is None:
                break
            status = parse_dimse_status(rcmd)
            if status in (STATUS_PENDING, STATUS_PENDING_WARNINGS):
                results.append((status, self._decode_identifier(rdata, implicit)))
                continue
            results.append((status, self._decode_identifier(rdata, implicit)))
            break
        return results

    def c_move(self, query_ds, move_destination,
               sop_class_uid=PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID, priority=0x0002):
        # type: (Any, str, str, int) -> Dict[str, Any]
        """Issue a C-MOVE that redirects matched objects to ``move_destination``
        (a third AE). Returns the final status and sub-operation counts. The
        objects are delivered to the destination AE, *not* on this channel —
        that is the SSRF-adjacent primitive; retrieve them out-of-band."""
        if not self.assoc_established:
            log.error("Association not established")
            return {"status": None, "responses": []}
        ctx_id = self._find_accepted_context_id(sop_class_uid)
        if ctx_id is None:
            log.error("No accepted context for SOP %s", sop_class_uid)
            return {"status": None, "responses": []}

        implicit = self._ctx_is_implicit_vr(ctx_id)
        q_bytes = self._encode_query(query_ds, implicit)
        msg_id = self._get_next_message_id()
        dest = move_destination
        if isinstance(dest, str):
            dest = dest.encode("ascii", errors="replace")
        dest = dest[:16].ljust(16, b" ")
        cmd = bytes(C_MOVE_RQ(
            affected_sop_class_uid=sop_class_uid,
            message_id=msg_id,
            move_destination=dest,
            priority=priority,
            data_set_type=0x0001,
        ))
        self._send_command_and_data(ctx_id, cmd, q_bytes)

        responses = []  # type: List[Dict[str, Any]]
        final_status = None
        while True:
            _cid, rcmd, _rdata = self._recv_dimse()
            if rcmd is None:
                break
            status = parse_dimse_status(rcmd)
            counts = {
                "remaining": parse_dimse_command_us(rcmd, 0x0000, 0x1020),
                "completed": parse_dimse_command_us(rcmd, 0x0000, 0x1021),
                "failed": parse_dimse_command_us(rcmd, 0x0000, 0x1022),
                "warning": parse_dimse_command_us(rcmd, 0x0000, 0x1023),
            }
            responses.append({"status": status, **counts})
            if status not in (STATUS_PENDING, STATUS_PENDING_WARNINGS):
                final_status = status
                break
        last = responses[-1] if responses else {}
        return {
            "status": final_status,
            "completed": last.get("completed"),
            "failed": last.get("failed"),
            "warning": last.get("warning"),
            "responses": responses,
        }

    def c_get(self, query_ds, sop_class_uid=PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
              priority=0x0002, strict_role=False):
        # type: (Any, str, int, bool) -> Dict[str, Any]
        """Issue a C-GET and collect the objects the SCP pushes back as C-STORE
        sub-operations on *this* association.

        The caller must have associated with both the QR-GET SOP class and
        presentation context(s) for the storage SOP class(es) of the expected
        objects. When ``strict_role`` is ``True``, the storage SCP role must
        also have been granted (propose it via ``associate(roles=...)``): on the
        first inbound C-STORE sub-operation whose storage SOP class was *not*
        granted ``scp_role=1`` in :attr:`negotiated_roles`, the association is
        aborted and the returned dict carries ``aborted=True`` with
        ``reason="scp_role_not_granted"``. The default (``False``) preserves the
        lenient behavior: objects are collected regardless of role negotiation.

        Returns the final status, sub-op counts, the granted role map, and a
        list of decoded objects (pydicom Datasets) — parse both metadata *and*
        pixels from these."""
        def _result(status, objects, aborted=False, reason=None):
            # type: (Optional[int], List[Any], bool, Optional[str]) -> Dict[str, Any]
            out = {
                "status": status,
                "objects": objects,
                "num_objects": len(objects),
                "negotiated_roles": dict(self.negotiated_roles),
                "aborted": aborted,
            }
            if reason:
                out["reason"] = reason
            return out

        if not self.assoc_established:
            log.error("Association not established")
            return _result(None, [])
        ctx_id = self._find_accepted_context_id(sop_class_uid)
        if ctx_id is None:
            log.error("No accepted context for SOP %s", sop_class_uid)
            return _result(None, [])

        implicit = self._ctx_is_implicit_vr(ctx_id)
        q_bytes = self._encode_query(query_ds, implicit)
        msg_id = self._get_next_message_id()
        cmd = bytes(C_GET_RQ(
            affected_sop_class_uid=sop_class_uid,
            message_id=msg_id,
            priority=priority,
            data_set_type=0x0001,
        ))
        self._send_command_and_data(ctx_id, cmd, q_bytes)

        objects = []  # type: List[Any]
        final_status = None
        while True:
            cid, rcmd, rdata = self._recv_dimse()
            if rcmd is None:
                break
            command_field = parse_dimse_command_field(rcmd)
            if command_field == 0x0001:
                # Inbound C-STORE-RQ sub-operation: collect the object and ack.
                if strict_role:
                    storage_uid = self.accepted_contexts.get(cid, (None, None))[0]
                    granted = self.negotiated_roles.get(storage_uid, (0, 0))[1]
                    if granted != 1:
                        log.error(
                            "Strict role: storage SCP role not granted for %s "
                            "(negotiated=%r); aborting C-GET",
                            storage_uid, self.negotiated_roles)
                        self.send(DICOM() / A_ABORT())
                        self.close()
                        return _result(None, objects, aborted=True,
                                       reason="scp_role_not_granted")
                store_implicit = self._ctx_is_implicit_vr(cid) if cid else implicit
                objects.append(self._decode_identifier(rdata, store_implicit))
                self._send_cstore_rsp(cid, rcmd)
                continue
            # C-GET-RSP
            status = parse_dimse_status(rcmd)
            if status not in (STATUS_PENDING, STATUS_PENDING_WARNINGS):
                final_status = status
                break
        return _result(final_status, objects)

    def _send_cstore_rsp(self, ctx_id, store_rq_cmd):
        # type: (Optional[int], bytes) -> None
        """Acknowledge an inbound C-STORE sub-operation with a Success status."""
        if ctx_id is None:
            return
        sop_class = None
        sop_inst = None
        try:
            from io import BytesIO
            from pydicom.filereader import read_dataset
            cmd_ds = read_dataset(BytesIO(store_rq_cmd), is_implicit_VR=True,
                                  is_little_endian=True)
            sop_class = getattr(cmd_ds, "AffectedSOPClassUID", None)
            sop_inst = getattr(cmd_ds, "AffectedSOPInstanceUID", None)
            msg_id = int(getattr(cmd_ds, "MessageID", 1))
        except Exception:
            msg_id = 1
        rsp = C_STORE_RSP(message_id_responded=msg_id, status=STATUS_SUCCESS)
        if sop_class:
            rsp.affected_sop_class_uid = str(sop_class)
        if sop_inst:
            rsp.affected_sop_instance_uid = str(sop_inst)
        cmd_pdv = PresentationDataValueItem(
            context_id=ctx_id, data=bytes(rsp), is_command=1, is_last=1,
        )
        self.send(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))

    def release(self):
        # type: () -> bool
        if not self.assoc_established:
            return True

        release_rq = DICOM() / A_RELEASE_RQ()
        self.send(release_rq)
        response = self.recv()
        self.close()

        if response:
            return response.haslayer(A_RELEASE_RP)
        return False

    def close(self):
        # type: () -> None
        if self.stream:
            try:
                self.stream.close()
            except (socket.error, OSError):
                pass
        self.sock = None
        self.stream = None
        self.assoc_established = False
