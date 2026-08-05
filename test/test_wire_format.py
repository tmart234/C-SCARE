# SPDX-License-Identifier: GPL-2.0-only
"""Wire-format conformance for `scapy_dicom`, checked against pynetdicom.

The attack catalog is only as good as its scaffolding. If C-SCARE's own
A-ASSOCIATE-RQ is subtly malformed, a target rejects it on framing and every
result downstream reads as "rejected" while proving nothing about the payload
under test. These tests use pynetdicom - an independent DICOM implementation -
as the oracle: it must decode what we encode, and re-encode to the same bytes.

That caught a real one: the User Identity sub-item omitted the mandatory
Secondary-Field-Length for every identity type except 2, so the whole
authentication surface was being probed with a sub-item a conformant peer
would reject on framing.
"""
import pytest

pytest.importorskip("pynetdicom")

from scapy.packet import raw  # noqa: E402

import c_scare.scapy_dicom as sd  # noqa: E402
from c_scare.scapy_dicom import (  # noqa: E402
    DICOM, DICOMVariableItem, DICOMApplicationContext,
    CT_IMAGE_STORAGE_SOP_CLASS_UID, DEFAULT_TRANSFER_SYNTAX_UID,
    build_presentation_context_rq, build_user_information,
)


def _roundtrip(data, pynetdicom_cls):
    """Decode with pynetdicom and re-encode; returns the re-encoded bytes."""
    item = pynetdicom_cls()
    item.decode(data)
    return item.encode()


class TestNegotiationSubItems:
    """Every A-ASSOCIATE sub-item must be byte-identical after a pynetdicom
    decode/encode round trip."""

    def _cases(self):
        from pynetdicom import pdu_items as pi
        return [
            ('MaximumLength',
             DICOMVariableItem() / sd.DICOMMaximumLength(max_pdu_length=16384),
             pi.MaximumLengthSubItem),
            ('ImplementationClassUID',
             DICOMVariableItem() / sd.DICOMImplementationClassUID(uid=b'1.2.3.4.5.6.7.8.9'),
             pi.ImplementationClassUIDSubItem),
            ('ImplementationVersionName',
             DICOMVariableItem() / sd.DICOMImplementationVersionName(name=b'C-SCARE_1'),
             pi.ImplementationVersionNameSubItem),
            ('AsynchronousOperationsWindow',
             DICOMVariableItem() / sd.DICOMAsyncOperationsWindow(
                 max_ops_invoked=2, max_ops_performed=3),
             pi.AsynchronousOperationsWindowSubItem),
            ('SCP_SCU_RoleSelection',
             DICOMVariableItem() / sd.DICOMSCPSCURoleSelection(
                 sop_class_uid=b'1.2.840.10008.5.1.4.1.1.2', scu_role=0, scp_role=1),
             pi.SCP_SCU_RoleSelectionSubItem),
            ('SOPClassExtendedNegotiation',
             DICOMVariableItem() / sd.DICOMSOPClassExtendedNegotiation(
                 sop_class_uid=b'1.2.840.10008.5.1.4.1.1.2',
                 service_class_application_information=b'\x01'),
             pi.SOPClassExtendedNegotiationSubItem),
            ('AbstractSyntax',
             DICOMVariableItem() / sd.DICOMAbstractSyntax(uid=b'1.2.840.10008.1.1'),
             pi.AbstractSyntaxSubItem),
            ('TransferSyntax',
             DICOMVariableItem() / sd.DICOMTransferSyntax(uid=b'1.2.840.10008.1.2'),
             pi.TransferSyntaxSubItem),
        ]

    def test_sub_items_round_trip_through_pynetdicom(self):
        for label, packet, cls in self._cases():
            data = raw(packet)
            assert _roundtrip(data, cls) == data, f'{label} is not wire-conformant'

    @pytest.mark.parametrize('identity_type', [1, 2, 3, 4, 5])
    def test_user_identity_always_carries_secondary_field_length(self, identity_type):
        """PS3.7 D.3.3.7 Table D.3-14 makes Secondary-Field-Length Type 1.

        It is on the wire for every identity type, carrying 0 when there is no
        passcode; only the Secondary-Field *content* is type-2-specific.
        """
        from pynetdicom.pdu_items import UserIdentitySubItemRQ

        secondary = b'passcode' if identity_type == 2 else b''
        data = raw(DICOMVariableItem() / sd.DICOMUserIdentity(
            user_identity_type=identity_type,
            positive_response_requested=1,
            primary_field=b'operator',
            secondary_field=secondary,
        ))
        assert _roundtrip(data, UserIdentitySubItemRQ) == data

        item = UserIdentitySubItemRQ()
        item.decode(data)
        assert item.primary_field == b'operator'
        assert item.secondary_field == secondary


class TestPDUs:
    """Whole PDUs must survive a pynetdicom round trip unchanged."""

    def test_release_and_abort(self):
        from pynetdicom.pdu import A_RELEASE_RQ, A_RELEASE_RP, A_ABORT_RQ

        for packet, cls in (
            (sd.A_RELEASE_RQ(), A_RELEASE_RQ),
            (sd.A_RELEASE_RP(), A_RELEASE_RP),
            (sd.A_ABORT(source=0, reason_diag=0), A_ABORT_RQ),
        ):
            data = raw(DICOM() / packet)
            assert _roundtrip(data, cls) == data, packet.name

    def test_p_data_tf_carries_a_real_dimse_command(self):
        """A command PDV must decode as a DIMSE command set, not filler."""
        from pynetdicom.pdu import P_DATA_TF

        pdv = sd.PresentationDataValueItem(
            context_id=1, is_last=1, is_command=1,
            data=raw(sd.C_ECHO_RQ(message_id=1)))
        data = raw(DICOM() / sd.P_DATA_TF(pdv_items=[pdv]))
        assert _roundtrip(data, P_DATA_TF) == data

        decoded = P_DATA_TF()
        decoded.decode(data)
        item = decoded.presentation_data_value_items[0]
        assert item.context_id == 1
        # Message control header: bit 0 = command, bit 1 = last fragment.
        assert item.data[0] == 0x03

    def test_associate_rq_is_accepted_by_a_live_pynetdicom_scp(self):
        """The end-to-end check: a real SCP must accept our baseline request.

        Everything the DAST catalog delivers over an association rides on this
        request being acceptable, so this is the assertion that keeps the whole
        C-STORE path honest.
        """
        import socket
        import time

        from pynetdicom import AE, evt, AllStoragePresentationContexts

        accepted = {}

        def on_accept(event):
            accepted['contexts'] = [
                (c.context_id, str(c.abstract_syntax))
                for c in event.assoc.accepted_contexts
            ]

        ae = AE(ae_title='PYNETSCP')
        ae.supported_contexts = AllStoragePresentationContexts
        server = ae.start_server(('127.0.0.1', 0), block=False,
                                 evt_handlers=[(evt.EVT_ACCEPTED, on_accept)])
        port = server.socket.getsockname()[1]
        try:
            time.sleep(0.5)
            pdu = raw(DICOM() / sd.A_ASSOCIATE_RQ(
                called_ae_title='PYNETSCP',
                calling_ae_title='C-SCARE',
                variable_items=[
                    DICOMVariableItem() / DICOMApplicationContext(),
                    build_presentation_context_rq(
                        1, CT_IMAGE_STORAGE_SOP_CLASS_UID,
                        [DEFAULT_TRANSFER_SYNTAX_UID]),
                    build_user_information(
                        max_pdu_length=16384,
                        implementation_class_uid='1.2.3.4.5.6.7.8.9'),
                ]))
            sock = socket.create_connection(('127.0.0.1', port), timeout=5)
            try:
                sock.sendall(pdu)
                response = sock.recv(4096)
            finally:
                sock.close()
            time.sleep(0.3)
        finally:
            server.shutdown()

        assert response[0] == 0x02, (
            f'expected A-ASSOCIATE-AC, got PDU type {response[0]:#x}')
        assert accepted.get('contexts') == [(1, CT_IMAGE_STORAGE_SOP_CLASS_UID)]


class TestUidPadding:
    """PS3.5 9.1 pads UIDs to even length. Inside a PDU item both the padded
    and unpadded forms occur in the wild and peers accept both, so the two
    helpers must stay distinct and both must resolve to the same UID."""

    def test_padded_and_unpadded_helpers_differ_only_in_padding(self):
        odd = CT_IMAGE_STORAGE_SOP_CLASS_UID  # 25 characters
        assert len(odd) % 2 == 1
        padded = sd._uid_to_bytes(odd)
        unpadded = sd._uid_to_bytes_raw(odd)
        assert padded == unpadded + b'\x00'
        assert padded.rstrip(b'\x00') == unpadded

    def test_padded_presentation_context_decodes_to_the_bare_uid(self):
        """A receiver must see the same abstract syntax either way - that is
        why the padded form is safe to keep as the default."""
        from pynetdicom.pdu_items import PresentationContextItemRQ

        data = raw(build_presentation_context_rq(
            1, CT_IMAGE_STORAGE_SOP_CLASS_UID, [DEFAULT_TRANSFER_SYNTAX_UID]))
        item = PresentationContextItemRQ()
        item.decode(data)
        assert str(item.abstract_transfer_syntax_sub_items[0].abstract_syntax_name) \
            == CT_IMAGE_STORAGE_SOP_CLASS_UID
