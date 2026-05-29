# SPDX-License-Identifier: GPL-2.0-only
"""
DICOM attack workflows — SCP-side (responder) drivers.

The responder half of each workflow: act as an SCP to exercise a *client*
(SCU). Where the issuer drivers (workflows.py) drive ``DICOMSocket`` to test a
server, these build the server-side responses on top of ``RawSCP`` so the same
workflow can probe a connecting client.

The piece ``RawSCP`` was missing is a *valid* association acceptor — its stock
example returns a malformed AC (``protocol_version=0xFFFF``) that real clients
reject, so a client never reaches the DIMSE stage. :func:`accept_association`
parses the A-ASSOCIATE-RQ and builds a conformant AC (echoing the proposed
presentation contexts), which lets a real SCU associate and proceed — and lets
us inject the SCP-side payloads the workflows care about (a custom
Implementation Version Name, a Type 0x59 user-identity response, a sculpted /
malformed C-FIND-RSP stream, a chosen C-STORE-RSP status).

``WorkflowResponder`` wraps ``RawSCP``: it auto-accepts associations, reassembles
DIMSE messages across P-DATA PDUs, and dispatches by command field to handlers,
with sensible defaults (C-ECHO success).
"""

import struct
from typing import Any, Callable, Dict, List, Optional

from .scapy_dicom import (
    DICOM, A_ASSOCIATE_RQ, A_ASSOCIATE_AC, A_ASSOCIATE_RJ, A_RELEASE_RP,
    P_DATA_TF, PresentationDataValueItem,
    DICOMVariableItem, DICOMApplicationContext, DICOMUserInformation,
    DICOMMaximumLength, DICOMImplementationClassUID,
    DICOMImplementationVersionName, DICOMUserIdentity, DICOMUserIdentityResponse,
    DICOMPresentationContextAC, DICOMAbstractSyntax, DICOMTransferSyntax,
    C_ECHO_RSP, C_STORE_RQ, C_STORE_RSP, C_FIND_RSP, C_MOVE_RSP, C_GET_RSP,
    parse_dimse_command_us, parse_dimse_status,
    _uid_to_bytes,
    IMPLEMENTATION_CLASS_UID, DEFAULT_TRANSFER_SYNTAX_UID,
    IMPLICIT_VR_LITTLE_ENDIAN_UID, CT_IMAGE_STORAGE_SOP_CLASS_UID,
    STATUS_SUCCESS, STATUS_PENDING,
)
from .server import RawSCP, ConnectionState
from scapy.packet import raw

__all__ = [
    "accept_association",
    "reject_association",
    "parse_proposed_contexts",
    "parse_user_identity",
    "build_cecho_rsp",
    "build_cstore_rsp",
    "build_cfind_rsp",
    "build_cfind_rsp_stream",
    "build_cmove_rsp",
    "build_cget_rsp",
    "WorkflowResponder",
]

# DIMSE command fields (RQ side).
CMD_C_STORE_RQ = 0x0001
CMD_C_GET_RQ = 0x0010
CMD_C_FIND_RQ = 0x0020
CMD_C_MOVE_RQ = 0x0021
CMD_C_ECHO_RQ = 0x0030


def _parse_rq(rq_bytes):
    """Parse association RQ bytes into the A_ASSOCIATE_RQ layer, or None."""
    try:
        pkt = DICOM(rq_bytes)
        if pkt.haslayer(A_ASSOCIATE_RQ):
            return pkt[A_ASSOCIATE_RQ]
    except Exception:
        pass
    return None


def _proposed_contexts(rq):
    """Yield ``(context_id, [transfer_syntax_uid, ...])`` from an RQ."""
    for item in rq.variable_items:
        if item.item_type != 0x20:
            continue
        try:
            pctx = item.payload
            cid = pctx.context_id
            ts_uids = []
            for sub in pctx.sub_items:
                if sub.item_type == 0x40 and sub.haslayer(DICOMTransferSyntax):
                    ts = sub[DICOMTransferSyntax].uid
                    ts_uids.append(ts.rstrip(b"\x00").decode("ascii", "replace"))
            yield cid, ts_uids
        except Exception:
            continue


def parse_proposed_contexts(rq_bytes):
    # type: (bytes) -> Dict[str, Any]
    """Map ``abstract_syntax_uid -> (context_id, [transfer_syntax_uid, ...])``
    from an A-ASSOCIATE-RQ, so a responder knows which negotiated context to
    send a C-STORE sub-operation on (W4 C-GET)."""
    out = {}  # type: Dict[str, Any]
    rq = _parse_rq(rq_bytes)
    if rq is None:
        return out
    for item in rq.variable_items:
        if item.item_type != 0x20:
            continue
        try:
            pctx = item.payload
            cid = pctx.context_id
            abs_uid = None
            ts_uids = []
            for sub in pctx.sub_items:
                if sub.item_type == 0x30 and sub.haslayer(DICOMAbstractSyntax):
                    abs_uid = sub[DICOMAbstractSyntax].uid.rstrip(b"\x00").decode(
                        "ascii", "replace")
                elif sub.item_type == 0x40 and sub.haslayer(DICOMTransferSyntax):
                    ts_uids.append(sub[DICOMTransferSyntax].uid.rstrip(
                        b"\x00").decode("ascii", "replace"))
            if abs_uid:
                out[abs_uid] = (cid, ts_uids)
        except Exception:
            continue
    return out


def parse_user_identity(rq_bytes):
    # type: (bytes) -> Optional[Dict[str, Any]]
    """Extract the Type 0x58 User Identity sub-item from an A-ASSOCIATE-RQ.

    Returns ``{"type", "primary", "secondary", "positive_response_requested"}``
    or ``None`` if the RQ carried no identity — what a require-and-validate
    responder (W2) checks credentials against."""
    rq = _parse_rq(rq_bytes)
    if rq is None:
        return None
    for item in rq.variable_items:
        if item.item_type != 0x50 or not item.haslayer(DICOMUserInformation):
            continue
        for sub in item[DICOMUserInformation].sub_items:
            if sub.item_type == 0x58 and sub.haslayer(DICOMUserIdentity):
                ui = sub[DICOMUserIdentity]
                return {
                    "type": ui.user_identity_type,
                    "primary": bytes(ui.getfieldval("primary_field")),
                    "secondary": bytes(ui.getfieldval("secondary_field") or b""),
                    "positive_response_requested": ui.positive_response_requested,
                }
    return None


def accept_association(rq_bytes,
                       responding_ae=None,
                       implementation_version_name=None,
                       user_identity_response=None,
                       transfer_syntax=None):
    # type: (bytes, Optional[str], Optional[Any], Optional[bytes], Optional[str]) -> bytes
    """Build a conformant A-ASSOCIATE-AC for the given RQ.

    Accepts every proposed presentation context (result 0) and selects a
    transfer syntax (``transfer_syntax`` if proposed, else the first proposed,
    else Implicit VR LE). ``implementation_version_name`` and
    ``user_identity_response`` inject the SCP-side payloads the W1/W2 responders
    care about. Returns raw AC bytes; falls back to a minimal AC if the RQ
    can't be parsed."""
    rq = _parse_rq(rq_bytes)

    ctx_items = []  # type: List[Any]
    if rq is not None:
        for cid, ts_uids in _proposed_contexts(rq):
            chosen = transfer_syntax if (transfer_syntax and transfer_syntax in ts_uids) \
                else (ts_uids[0] if ts_uids else IMPLICIT_VR_LITTLE_ENDIAN_UID)
            ctx_items.append(
                DICOMVariableItem() / DICOMPresentationContextAC(
                    context_id=cid, result=0,
                    sub_items=[DICOMVariableItem() / DICOMTransferSyntax(
                        uid=_uid_to_bytes(chosen))],
                )
            )

    # User Information: max length + impl class UID + (optional) impl version
    # name + (optional) 0x59 user-identity server response.
    user_sub = [
        DICOMVariableItem() / DICOMMaximumLength(max_pdu_length=16384),
        DICOMVariableItem() / DICOMImplementationClassUID(
            uid=_uid_to_bytes(IMPLEMENTATION_CLASS_UID)),
    ]
    if implementation_version_name is not None:
        ver = implementation_version_name
        if isinstance(ver, str):
            ver = ver.encode("ascii", "replace")
        user_sub.append(
            DICOMVariableItem() / DICOMImplementationVersionName(name=ver))
    if user_identity_response is not None:
        resp = user_identity_response
        if isinstance(resp, str):
            resp = resp.encode("utf-8")
        user_sub.append(
            DICOMVariableItem() / DICOMUserIdentityResponse(server_response=resp))

    variable_items = [DICOMVariableItem() / DICOMApplicationContext()]
    variable_items.extend(ctx_items)
    variable_items.append(DICOMVariableItem() / DICOMUserInformation(sub_items=user_sub))

    called = rq.called_ae_title if rq is not None else b" " * 16
    calling = rq.calling_ae_title if rq is not None else b" " * 16
    if responding_ae is not None:
        called = responding_ae

    ac = DICOM() / A_ASSOCIATE_AC(
        called_ae_title=called,
        calling_ae_title=calling,
        variable_items=variable_items,
    )
    return raw(ac)


def reject_association(result=1, source=1, reason=7):
    # type: (int, int, int) -> bytes
    """Build an A-ASSOCIATE-RJ. Defaults to source 1 / reason 7
    (called-AE-title-not-recognized) for exercising a client's AE-title
    handling; pass (2, 2, 1) to mimic a user-identity rejection."""
    return raw(DICOM() / A_ASSOCIATE_RJ(result=result, source=source,
                                        reason_diag=reason))


def _pdata(ctx_id, dimse_bytes, dataset_bytes=None, max_pdv=16372):
    """Build P-DATA-TF PDU bytes: a command PDV then chunked data PDVs."""
    out = b""
    cmd_pdv = PresentationDataValueItem(
        context_id=ctx_id, data=dimse_bytes, is_command=1, is_last=1)
    out += raw(DICOM() / P_DATA_TF(pdv_items=[cmd_pdv]))
    if dataset_bytes:
        offset = 0
        total = len(dataset_bytes)
        while offset < total:
            chunk = dataset_bytes[offset:offset + max_pdv]
            is_last = 1 if offset + len(chunk) >= total else 0
            data_pdv = PresentationDataValueItem(
                context_id=ctx_id, data=chunk, is_command=0, is_last=is_last)
            out += raw(DICOM() / P_DATA_TF(pdv_items=[data_pdv]))
            offset += len(chunk)
    return out


def build_cecho_rsp(ctx_id, message_id, status=STATUS_SUCCESS):
    # type: (int, int, int) -> bytes
    cmd = bytes(C_ECHO_RSP(message_id_responded=message_id, status=status))
    return _pdata(ctx_id, cmd)


def build_cstore_rsp(ctx_id, message_id, status=STATUS_SUCCESS,
                     sop_class_uid=None, sop_instance_uid=None):
    # type: (int, int, int, Optional[str], Optional[str]) -> bytes
    rsp = C_STORE_RSP(message_id_responded=message_id, status=status)
    if sop_class_uid:
        rsp.affected_sop_class_uid = sop_class_uid
    if sop_instance_uid:
        rsp.affected_sop_instance_uid = sop_instance_uid
    return _pdata(ctx_id, bytes(rsp))


def _encode_ds(ds, implicit_vr=True):
    if ds is None:
        return None
    if isinstance(ds, (bytes, bytearray)):
        return bytes(ds)
    if hasattr(ds, "encode"):  # c_scare Dataset
        return ds.encode(implicit_vr=implicit_vr, little_endian=True)
    # pydicom Dataset
    try:
        from pydicom.filebase import DicomBytesIO
        from pydicom.filewriter import write_dataset
        buf = DicomBytesIO()
        buf.is_implicit_VR = implicit_vr
        buf.is_little_endian = True
        write_dataset(buf, ds)
        return buf.getvalue()
    except Exception:
        return b""


def build_cfind_rsp(ctx_id, message_id, status, identifier=None,
                    sop_class_uid=None, implicit_vr=True):
    # type: (int, int, int, Any, Optional[str], bool) -> bytes
    """One C-FIND-RSP. A Pending status (0xFF00/0xFF01) carries an identifier;
    a terminal status (Success/failure) carries none."""
    has_ds = identifier is not None
    rsp = C_FIND_RSP(
        message_id_responded=message_id, status=status,
        data_set_type=0x0001 if has_ds else 0x0101)
    if sop_class_uid:
        rsp.affected_sop_class_uid = sop_class_uid
    return _pdata(ctx_id, bytes(rsp), _encode_ds(identifier, implicit_vr) if has_ds else None)


def build_cfind_rsp_stream(ctx_id, message_id, identifiers,
                           sop_class_uid=None, implicit_vr=True,
                           final_status=STATUS_SUCCESS):
    # type: (int, int, List[Any], Optional[str], bool, int) -> List[bytes]
    """A full Pending* -> terminal C-FIND-RSP stream, one PDU group per match."""
    out = []
    for ds in identifiers:
        out.append(build_cfind_rsp(ctx_id, message_id, STATUS_PENDING, ds,
                                   sop_class_uid, implicit_vr))
    out.append(build_cfind_rsp(ctx_id, message_id, final_status, None,
                               sop_class_uid, implicit_vr))
    return out


def build_cmove_rsp(ctx_id, message_id, status=STATUS_SUCCESS,
                    remaining=0, completed=0, failed=0, warning=0,
                    sop_class_uid=None):
    # type: (int, int, int, int, int, int, int, Optional[str]) -> bytes
    """One C-MOVE-RSP carrying sub-operation counts (W5 responder)."""
    rsp = C_MOVE_RSP(
        message_id_responded=message_id, status=status, data_set_type=0x0101,
        num_remaining=remaining, num_completed=completed,
        num_failed=failed, num_warning=warning)
    if sop_class_uid:
        rsp.affected_sop_class_uid = sop_class_uid
    return _pdata(ctx_id, bytes(rsp))


def build_cget_rsp(ctx_id, message_id, status=STATUS_SUCCESS,
                   remaining=0, completed=0, failed=0, warning=0,
                   sop_class_uid=None):
    # type: (int, int, int, int, int, int, int, Optional[str]) -> bytes
    """One C-GET-RSP carrying sub-operation counts (W4 responder)."""
    rsp = C_GET_RSP(
        message_id_responded=message_id, status=status, data_set_type=0x0101,
        num_remaining=remaining, num_completed=completed,
        num_failed=failed, num_warning=warning)
    if sop_class_uid:
        rsp.affected_sop_class_uid = sop_class_uid
    return _pdata(ctx_id, bytes(rsp))


class WorkflowResponder:
    """An SCP that exercises a connecting SCU client.

    Auto-accepts associations with a conformant AC (optionally injecting a
    custom Implementation Version Name / 0x59 response), reassembles DIMSE
    messages across P-DATA PDUs, and dispatches by command field. Register
    handlers with the ``on_c_*`` decorators; each receives
    ``(responder, conn, ctx_id, command_bytes, dataset_bytes)`` and may return
    response bytes (sent as-is), a list of byte chunks (sent in order), or
    ``None``. The default C-ECHO handler returns Success.
    """

    def __init__(self, host="0.0.0.0", port=11112, ae_title="C_SCARE",
                 implementation_version_name=None, user_identity_response=None,
                 transfer_syntax=None, known_aets=None, require_identity=None):
        # ``known_aets`` (W1): {called_ae: {"implementation_version_name":...,
        #   "user_identity_response":...}}. If set, an AET not in the map is
        #   rejected with called-AE-title-not-recognized (1/1/7).
        # ``require_identity`` (W2): callable(ident_dict) -> (is_valid, response
        #   bytes or None). A bad credential is rejected with an ACSE 2/2/1.
        self.scp = RawSCP(host=host, port=port, ae_title=ae_title)
        self.implementation_version_name = implementation_version_name
        self.user_identity_response = user_identity_response
        self.transfer_syntax = transfer_syntax
        self.known_aets = known_aets
        self.require_identity = require_identity
        self._dimse_handlers = {}  # type: Dict[int, Callable]
        self._subop_id = 0
        self._wire()

    # -- handler registration ------------------------------------------------
    def on_c_echo(self, f):
        self._dimse_handlers[CMD_C_ECHO_RQ] = f
        return f

    def on_c_find(self, f):
        self._dimse_handlers[CMD_C_FIND_RQ] = f
        return f

    def on_c_store(self, f):
        self._dimse_handlers[CMD_C_STORE_RQ] = f
        return f

    def on_c_move(self, f):
        self._dimse_handlers[CMD_C_MOVE_RQ] = f
        return f

    def on_c_get(self, f):
        self._dimse_handlers[CMD_C_GET_RQ] = f
        return f

    # -- lifecycle -----------------------------------------------------------
    def start(self, blocking=False):
        return self.scp.start(blocking=blocking)

    def stop(self):
        self.scp.stop()

    # -- internals -----------------------------------------------------------
    def _wire(self):
        scp = self.scp

        @scp.on_associate_rq
        def _assoc(conn, pdu_bytes, pkt):
            # Record negotiated contexts so a C-GET can pick the storage context.
            conn._wf_contexts = parse_proposed_contexts(pdu_bytes)
            called = (getattr(conn, "called_ae", "") or "").strip()

            impl_ver = self.implementation_version_name
            uid_resp = self.user_identity_response

            # W1: AET-keyed acceptance.
            if self.known_aets is not None:
                if called not in self.known_aets:
                    return reject_association(result=1, source=1, reason=7)
                entry = self.known_aets[called] or {}
                impl_ver = entry.get("implementation_version_name", impl_ver)
                uid_resp = entry.get("user_identity_response", uid_resp)

            # W2: require + validate User Identity.
            if self.require_identity is not None:
                ident = parse_user_identity(pdu_bytes)
                if ident is None:
                    # Identity required but none offered.
                    return reject_association(result=1, source=1, reason=1)
                valid, resp = self.require_identity(ident)
                if not valid:
                    return reject_association(result=2, source=2, reason=1)
                if resp is not None:
                    uid_resp = resp

            return accept_association(
                pdu_bytes,
                responding_ae=self.scp.ae_title,
                implementation_version_name=impl_ver,
                user_identity_response=uid_resp,
                transfer_syntax=self.transfer_syntax,
            )

        @scp.on_release_rq
        def _release(conn, pdu_bytes, pkt):
            return raw(DICOM() / A_RELEASE_RP())

        @scp.on_pdata
        def _pdata_handler(conn, pdu_bytes, pkt):
            return self._handle_pdata(conn, pkt)

    def _handle_pdata(self, conn, pkt):
        # Per-connection reassembly state stashed on the Connection.
        if not hasattr(conn, "_wf_cmd"):
            conn._wf_cmd = b""
            conn._wf_data = b""
            conn._wf_ctx = None
            conn._wf_cmd_done = False
            conn._wf_data_done = False
            conn._wf_expect = None

        if pkt is None or not pkt.haslayer(P_DATA_TF):
            return None
        for pdv in pkt[P_DATA_TF].pdv_items:
            if conn._wf_ctx is None:
                conn._wf_ctx = pdv.context_id
            if pdv.is_command:
                conn._wf_cmd += bytes(pdv.data)
                if pdv.is_last:
                    conn._wf_cmd_done = True
            else:
                conn._wf_data += bytes(pdv.data)
                if pdv.is_last:
                    conn._wf_data_done = True

        if conn._wf_cmd_done and conn._wf_expect is None:
            dst = parse_dimse_command_us(conn._wf_cmd, 0x0000, 0x0800)
            conn._wf_expect = dst is not None and dst != 0x0101

        ready = conn._wf_cmd_done and (
            conn._wf_expect is False or conn._wf_data_done)
        if not ready:
            return None

        cmd = conn._wf_cmd
        data = conn._wf_data or None
        ctx_id = conn._wf_ctx
        # reset for the next message
        conn._wf_cmd = b""
        conn._wf_data = b""
        conn._wf_ctx = None
        conn._wf_cmd_done = False
        conn._wf_data_done = False
        conn._wf_expect = None

        return self._dispatch(conn, ctx_id, cmd, data)

    # -- C-GET sub-operation serving (W4 responder) --------------------------
    def _next_subop_id(self):
        self._subop_id = (self._subop_id + 1) & 0xFFFF
        return self._subop_id or 1

    def _storage_ctx_id(self, conn, sop_class_uid, default_ctx):
        ctxs = getattr(conn, "_wf_contexts", {}) or {}
        entry = ctxs.get(sop_class_uid)
        return entry[0] if entry else default_ctx

    def _read_status(self, conn):
        """Read one DIMSE response PDU from the client and return its status."""
        pdu = self.scp._recv_pdu(conn)
        if not pdu:
            return None
        try:
            p = DICOM(pdu)
            if p.haslayer(P_DATA_TF):
                for pdv in p[P_DATA_TF].pdv_items:
                    if pdv.is_command:
                        return parse_dimse_status(bytes(pdv.data))
        except Exception:
            pass
        return None

    def serve_cget(self, conn, ctx_id, command_bytes, objects):
        """Deliver ``objects`` to a C-GET SCU as inbound C-STORE sub-operations
        on the negotiated storage context, then send the final C-GET-RSP with
        the sub-op counts.

        ``objects``: list of ``(sop_class_uid, sop_instance_uid, dataset)``.
        Call this from an ``on_c_get`` handler and return ``None``."""
        msg_id = parse_dimse_command_us(command_bytes, 0x0000, 0x0110) or 1
        completed = 0
        failed = 0
        for sop_class, sop_inst, ds in objects:
            store_ctx = self._storage_ctx_id(conn, sop_class, ctx_id)
            rq = C_STORE_RQ(
                affected_sop_class_uid=sop_class,
                affected_sop_instance_uid=sop_inst,
                message_id=self._next_subop_id())
            conn.send(_pdata(store_ctx, bytes(rq), _encode_ds(ds)))
            if self._read_status(conn) == STATUS_SUCCESS:
                completed += 1
            else:
                failed += 1
        conn.send(build_cget_rsp(ctx_id, msg_id, STATUS_SUCCESS,
                                 completed=completed, failed=failed))

    def _dispatch(self, conn, ctx_id, cmd, data):
        command_field = parse_dimse_command_us(cmd, 0x0000, 0x0100)
        message_id = parse_dimse_command_us(cmd, 0x0000, 0x0110) or 1

        handler = self._dimse_handlers.get(command_field)
        if handler is not None:
            result = handler(self, conn, ctx_id, cmd, data)
            if isinstance(result, list):
                for chunk in result:
                    conn.send(chunk)
                return None
            return result

        # Defaults: answer C-ECHO with Success; otherwise a Success RSP so the
        # client's state machine completes cleanly.
        if command_field == CMD_C_ECHO_RQ:
            return build_cecho_rsp(ctx_id, message_id, STATUS_SUCCESS)
        if command_field == CMD_C_STORE_RQ:
            return build_cstore_rsp(ctx_id, message_id, STATUS_SUCCESS)
        if command_field == CMD_C_FIND_RQ:
            return build_cfind_rsp(ctx_id, message_id, STATUS_SUCCESS)
        if command_field == CMD_C_MOVE_RQ:
            return build_cmove_rsp(ctx_id, message_id, STATUS_SUCCESS)
        if command_field == CMD_C_GET_RQ:
            return build_cget_rsp(ctx_id, message_id, STATUS_SUCCESS)
        return None
