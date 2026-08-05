# SPDX-License-Identifier: GPL-2.0-only
"""Correctness of the pentest workflow drivers (W1-W5).

Recon output ends up in reports, so the failure that matters here is not a
crash - it is a confident wrong answer. Two shapes of that:

  * A target that never answered reading as a target that said no.
  * An association that was accepted reading as a credential that was checked,
    when User Identity Negotiation is optional and most SCPs ignore it.

Both are exercised against live pynetdicom servers rather than mocks, because
both depend on how a real peer behaves.
"""
import time

import pytest

pytest.importorskip("pynetdicom")

import c_scare.workflows as wf  # noqa: E402


@pytest.fixture
def quiet_logs():
    import logging
    logging.disable(logging.ERROR)
    yield
    logging.disable(logging.NOTSET)


def _server(ae_title, *, enforce_identity=False, evt_handlers=None):
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification

    ae = AE(ae_title=ae_title)
    ae.add_supported_context(Verification)
    if enforce_identity:
        ae.require_authentication = True
    server = ae.start_server(('127.0.0.1', 0), block=False,
                             evt_handlers=evt_handlers or [])
    time.sleep(0.4)
    return server, server.socket.getsockname()[1]


class TestBuildQuery:
    """W3/W4/W5 all ride on the identifier this builds."""

    def test_vrs_come_from_the_dicom_dictionary(self):
        """Guessing LO for every tag makes an explicit-VR identifier malformed
        and can break matching on a correctly-spelled value."""
        from pydicom.datadict import dictionary_VR

        query = wf.build_query(level='study', return_keys=[
            (0x0020, 0x000D),   # Study Instance UID  -> UI
            (0x0008, 0x0020),   # Study Date          -> DA
            (0x0010, 0x0010),   # Patient Name        -> PN
            (0x0008, 0x0061),   # Modalities in Study -> CS
        ])
        for tag in query._order:
            assert query._elements[tag].vr == dictionary_VR(tag), hex(tag)

    def test_explicit_vr_still_wins(self):
        query = wf.build_query(level='study', return_keys=[(0x0020, 0x000D, 'LO')])
        assert query._elements[0x0020000D].vr == 'LO'

    def test_private_tags_fall_back_to_lo(self):
        query = wf.build_query(level='study', return_keys=[(0x0009, 0x1001)])
        assert query._elements[0x00091001].vr == 'LO'

    def test_unknown_level_raises_instead_of_dropping_the_key(self):
        """A typo used to yield an identifier with no QueryRetrieveLevel, which
        an SCP answers with an empty result set - a silent dead end."""
        with pytest.raises(ValueError, match='unknown query level'):
            wf.build_query(level='studies')

    @pytest.mark.parametrize('level,expected', [
        ('study', 'STUDY'), ('PATIENT', 'PATIENT'),
        ('series', 'SERIES'), ('image', 'IMAGE')])
    def test_level_sets_query_retrieve_level(self, level, expected):
        query = wf.build_query(level=level)
        assert query._elements[0x00080052].value == expected


class TestAeBruteHonesty:
    """W1 must not turn an unreachable host into a verdict."""

    def test_unreachable_target_is_inconclusive_not_rejected(self, quiet_logs):
        results = wf.ae_brute('127.0.0.1', 1, ['PACS', 'ORTHANC'], timeout=1.0)
        assert len(results) == 2
        for result in results:
            assert result.error, 'transport failure must be recorded'
            assert not result.conclusive
            # The dangerous default: no reject PDU came back, so neither
            # "recognized" nor "not recognized" may be claimed.
            assert result.aet_recognized is False
            assert result.accepted is False

    def test_accepted_aet_is_conclusive_and_reads_the_ac_payload(self, quiet_logs):
        server, port = _server('REALSCP')
        try:
            results = wf.ae_brute('127.0.0.1', port, ['REALSCP'], timeout=5.0)
        finally:
            server.shutdown()
        result = results[0]
        assert result.accepted and result.aet_recognized and result.conclusive
        assert result.error is None
        # Reading the AC payload, not just accept/reject, is the point of W1.
        assert result.implementation_class_uid


class TestCredBruteCalibration:
    """W2's whole value depends on the target actually checking the credential."""

    def test_target_that_ignores_identity_verifies_nothing(self, quiet_logs):
        """The original failure: an SCP that never inspects the identity
        sub-item accepted the first credential, and stop_on_success reported
        it as valid."""
        server, port = _server('NOAUTHSCP')
        try:
            results = wf.cred_brute('127.0.0.1', port, 'NOAUTHSCP',
                                    [('admin', 'admin'), ('root', 'toor')],
                                    timeout=5.0)
        finally:
            server.shutdown()

        baseline = results[0]
        assert baseline.is_baseline
        assert baseline.accepted, 'this server accepts anything, including the probe'
        assert baseline.identity_enforced is False

        for result in results:
            assert result.identity_enforced is False
            assert not result.credential_verified, (
                f'{result.username} must not be reported as a valid credential')
        # The full list is still attempted so the pattern is visible.
        assert [r.username for r in results[1:]] == ['admin', 'root']

    def test_enforcing_target_verifies_only_the_real_credential(self, quiet_logs):
        from pynetdicom import evt

        def on_user_id(event):
            ok = (event.primary_field == b'realuser'
                  and event.secondary_field == b'realpass')
            return ok, (b'SERVER-OK' if ok else None)

        server, port = _server('AUTHSCP', enforce_identity=True,
                               evt_handlers=[(evt.EVT_USER_ID, on_user_id)])
        try:
            results = wf.cred_brute(
                '127.0.0.1', port, 'AUTHSCP',
                [('wrong', 'wrong'), ('realuser', 'realpass'), ('never', 'tried')],
                timeout=5.0)
        finally:
            server.shutdown()

        assert results[0].is_baseline
        assert results[0].identity_enforced is True

        verified = [r for r in results if r.credential_verified]
        assert [r.username for r in verified] == ['realuser']
        # stop_on_success must stop at a *verified* credential, not merely an
        # accepted association.
        assert 'never' not in [r.username for r in results]

    def test_unreachable_target_leaves_enforcement_unknown(self, quiet_logs):
        results = wf.cred_brute('127.0.0.1', 1, 'X', [('a', 'b')], timeout=1.0)
        for result in results:
            assert result.error
            assert result.identity_enforced is None, (
                'no answer means enforcement cannot be determined either way')
            assert not result.credential_verified

    def test_baseline_can_be_disabled(self, quiet_logs):
        server, port = _server('NOAUTHSCP')
        try:
            results = wf.cred_brute('127.0.0.1', port, 'NOAUTHSCP',
                                    [('admin', 'admin')], baseline=False,
                                    timeout=5.0)
        finally:
            server.shutdown()
        assert not any(r.is_baseline for r in results)
        # Without calibration the driver must not claim enforcement either way.
        assert results[0].identity_enforced is None
