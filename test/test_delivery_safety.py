# SPDX-License-Identifier: GPL-2.0-only
"""Socket-level delivery correctness and the clinical safety guardrails.

Two groups:

* **Transport** — PDU-framed reads, A-ABORT teardown, and the per-step
  response expectations that keep a state-machine sequence from either
  desyncing or stalling on a step the peer can never answer.
* **Guardrails** — ``--dry-run``, ``--max-associations`` and
  ``--allow-availability``, which bound what a run can do to a live PACS.

Everything here runs against a loopback stub server, so no real SCP is needed.
"""

import argparse
import socket
import struct
import threading
import time

import pytest

from c_scare import deliver, runner
from c_scare.attacks import AttackResult

ABORT_PDU = b"\x07\x00" + struct.pack("!I", 4) + b"\x00\x00\x00\x00"


def _pdu(pdu_type, body=b""):
    return bytes([pdu_type, 0]) + struct.pack("!I", len(body)) + body


def _pdata(payload=b"\x00\x00", ctx=1, is_command=1, is_last=1):
    """A P-DATA-TF PDU wrapping one PDV item."""
    mch = (is_command & 1) | ((is_last & 1) << 1)
    item = bytes([ctx, mch]) + payload
    body = struct.pack("!I", len(item)) + item
    return _pdu(0x04, body)


class StubSCP:
    """Loopback server that records what it receives and replies on script."""

    def __init__(self, replies=(), chunk_size=None):
        self.replies = list(replies)
        self.chunk_size = chunk_size
        self.received = b""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.address = self._sock.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        conn, _ = self._sock.accept()
        conn.settimeout(5.0)
        try:
            for reply in self.replies:
                if self.chunk_size:
                    # Dribble the PDU out in fragments so an unframed read
                    # would return a partial PDU.
                    for i in range(0, len(reply), self.chunk_size):
                        conn.sendall(reply[i:i + self.chunk_size])
                else:
                    conn.sendall(reply)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                self.received += chunk
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


@pytest.fixture
def stub():
    servers = []

    def _make(**kwargs):
        s = StubSCP(**kwargs)
        servers.append(s)
        return s

    yield _make
    for s in servers:
        s.close()


class TestPDUFraming:
    def test_send_pdu_reassembles_a_fragmented_response(self, stub):
        """A PDU split across TCP segments must come back whole."""
        body = b"\xAB" * 300
        server = stub(replies=[_pdu(0x02, body)], chunk_size=7)

        response = deliver.send_pdu(server.address, _pdu(0x01), timeout=5.0)

        assert response == _pdu(0x02, body)
        assert len(response) == 306

    def test_send_pdu_reads_exactly_one_pdu_when_several_arrive(self, stub):
        """Aggregated PDUs must not be returned as one blob."""
        server = stub(replies=[_pdu(0x02, b"\x01") + _pdu(0x07, b"\x00\x00\x00\x00")])

        response = deliver.send_pdu(server.address, _pdu(0x01), timeout=5.0)

        assert response == _pdu(0x02, b"\x01")

    def test_timeout_returns_none_not_empty_bytes(self, stub):
        """A silent peer is a timeout, not an empty response.

        ProtocolMonitor reports these as different findings, so collapsing
        them would turn every timeout into a false 'empty_response'.
        """
        server = stub(replies=[])

        response = deliver.send_pdu(server.address, _pdu(0x01), timeout=0.3)

        assert response is None


class TestGracefulTeardown:
    def test_send_pdu_aborts_before_closing(self, stub):
        server = stub(replies=[_pdu(0x02)])

        deliver.send_pdu(server.address, _pdu(0x01), timeout=1.0)
        server._thread.join(timeout=2.0)

        assert server.received.endswith(ABORT_PDU)

    def test_send_sequence_aborts_before_closing(self, stub):
        server = stub(replies=[_pdu(0x02)])

        deliver.send_sequence(server.address, [_pdu(0x01)], timeout=1.0)
        server._thread.join(timeout=2.0)

        assert server.received.endswith(ABORT_PDU)


class TestSequenceExpectations:
    def test_abort_and_everything_after_it_is_unanswerable(self):
        steps = [_pdu(0x01), ABORT_PDU, _pdata()]
        assert runner._sequence_expectations(steps) == [True, False, False]

    def test_non_final_fragments_expect_no_response(self):
        """A DIMSE message split across PDVs draws no reply until is_last=1."""
        steps = [_pdu(0x01), _pdata(is_last=0), _pdata(is_last=0), _pdata(is_last=1)]
        assert runner._sequence_expectations(steps) == [True, False, False, True]

    def test_complete_messages_all_keep_blocking(self):
        """Each complete P-DATA draws its own response.

        Skipping a read here would leave the reply queued and hand it to the
        next step — the desync this whole mechanism exists to avoid.
        """
        steps = [_pdu(0x01), _pdata(), _pdata(), _pdu(0x05)]
        assert runner._sequence_expectations(steps) == [True, True, True, True]

    def test_release_request_still_expects_a_reply(self):
        assert runner._sequence_expectations([_pdu(0x05)]) == [True]

    def test_dimse_n_catalog_never_skips_a_read(self):
        """Guards the catalog against a future desync regression."""
        from c_scare.attacks import DimseNAttacks
        for result in DimseNAttacks.all():
            steps = result.metadata.get("steps") or []
            assert all(runner._sequence_expectations(steps)), result.name

    def test_unanswerable_steps_are_not_waited_on(self, stub):
        """The wall-clock payoff: no timeout burned on a trailing abort.

        Without the expectations the two unanswerable steps would each block
        for the full timeout, so the elapsed time is the assertion that
        matters — the response list looks the same either way.
        """
        server = stub(replies=[_pdu(0x02)])
        steps = [_pdu(0x01), ABORT_PDU, _pdata()]

        started = time.monotonic()
        responses = deliver.send_sequence(
            server.address, steps, timeout=5.0,
            expect_response=runner._sequence_expectations(steps))
        elapsed = time.monotonic() - started

        assert responses == [_pdu(0x02), None, None]
        assert elapsed < 2.0, f"blocked on unanswerable steps ({elapsed:.1f}s)"

    def test_blocking_on_every_step_is_the_default(self, stub):
        """Callers that pass no expectations keep the old lock-step behavior."""
        server = stub(replies=[_pdu(0x02)])

        started = time.monotonic()
        responses = deliver.send_sequence(
            server.address, [_pdu(0x01), ABORT_PDU], timeout=0.4)
        elapsed = time.monotonic() - started

        assert responses[0] == _pdu(0x02)
        assert responses[1] is None
        assert elapsed >= 0.4  # it really did wait on the abort


class TestAssociationBudget:
    def _args(self, **kw):
        base = dict(delivery='auto', mutate=None, ae_title='PACS',
                    calling_ae='SCU', dry_run=None, max_associations=None)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_budget_allows_runs_under_the_limit(self):
        args = self._args(max_associations=3)
        runner._charge_associations(args, 1)
        runner._charge_associations(args, 1)
        assert args._associations_used == 2

    def test_budget_raises_when_exhausted(self):
        args = self._args(max_associations=2)
        runner._charge_associations(args, 2)
        with pytest.raises(runner.AssociationBudgetExceeded):
            runner._charge_associations(args, 1)

    def test_unset_budget_is_unlimited(self):
        args = self._args(max_associations=None)
        for _ in range(50):
            runner._charge_associations(args, 10)

    def test_dry_run_spends_no_budget(self):
        """A dry run opens no connections, so it must not exhaust the budget."""
        args = self._args(max_associations=1, dry_run='/tmp/x')
        for _ in range(20):
            runner._charge_associations(args, 5)

    def test_sequence_with_two_associate_rqs_costs_two(self):
        result = AttackResult(
            name='double-assoc', category='state_machine', payload=b'',
            description='d', expected_behavior='e',
            metadata={'steps': [_pdu(0x01), _pdu(0x01)]})
        assert runner._association_cost('sequence', result) == 2

    def test_single_association_sequence_costs_one(self):
        result = AttackResult(
            name='one-assoc', category='state_machine', payload=b'',
            description='d', expected_behavior='e',
            metadata={'steps': [_pdu(0x01), _pdata(), ABORT_PDU]})
        assert runner._association_cost('sequence', result) == 1


class TestDryRun:
    def _result(self, **meta):
        return AttackResult(
            name='probe/one', category='parser', payload=b'\x01\x02\x03',
            description='d', expected_behavior='e', metadata=dict(meta))

    def test_dry_run_writes_payload_and_sends_nothing(self, tmp_path, monkeypatch):
        def _explode(*a, **k):
            raise AssertionError("dry run must not touch the network")

        monkeypatch.setattr(runner.deliver, 'send_pdu', _explode)
        monkeypatch.setattr(runner.deliver, 'send_cstore', _explode)
        monkeypatch.setattr(runner.deliver, 'send_sequence', _explode)

        args = argparse.Namespace(delivery='pdu', mutate=None, ae_title='PACS',
                                  calling_ae='SCU', dry_run=str(tmp_path),
                                  max_associations=None)
        result = self._result()

        response, error = runner._deliver(args, result, ('127.0.0.1', 11112), 1.0)

        assert response is None and error == 'dry_run'
        written = list(tmp_path.iterdir())
        assert [p.name for p in written] == ['probe_one.bin']
        assert written[0].read_bytes() == b'\x01\x02\x03'

    def test_dry_run_writes_each_sequence_step(self, tmp_path, monkeypatch):
        monkeypatch.setattr(runner.deliver, 'send_sequence',
                            lambda *a, **k: pytest.fail("must not send"))
        args = argparse.Namespace(delivery='auto', mutate=None, ae_title='PACS',
                                  calling_ae='SCU', dry_run=str(tmp_path),
                                  max_associations=None)
        result = self._result(steps=[_pdu(0x01), ABORT_PDU])

        runner._deliver(args, result, ('127.0.0.1', 11112), 1.0)

        assert sorted(p.name for p in tmp_path.iterdir()) == [
            'probe_one.00.bin', 'probe_one.01.bin']

    def test_dry_run_is_not_reported_as_a_finding(self):
        """Otherwise every payload in a dry run looks like a timeout."""
        from c_scare.monitor import ProtocolMonitor
        monitor = ProtocolMonitor()
        monitor.set_response(None, error='dry_run')
        assert monitor.post_test().detected is False


class TestAvailabilityGate:
    def _args(self, **kw):
        base = dict(allow_availability=False, dry_run=None)
        base.update(kw)
        return argparse.Namespace(**base)

    @pytest.mark.parametrize('category', sorted(runner.AVAILABILITY_CATEGORIES))
    def test_availability_categories_need_opt_in(self, category, capsys):
        assert runner._availability_blocked(self._args(), category, 'L') is True
        assert 'SKIPPED' in capsys.readouterr().out

    @pytest.mark.parametrize('category', sorted(runner.AVAILABILITY_CATEGORIES))
    def test_opt_in_unblocks(self, category):
        args = self._args(allow_availability=True)
        assert runner._availability_blocked(args, category, 'L') is False

    def test_dry_run_is_exempt(self):
        """A dry run sends nothing, so there is no availability risk."""
        args = self._args(dry_run='/tmp/x')
        assert runner._availability_blocked(args, 'memory', 'L') is False

    def test_ordinary_categories_are_never_blocked(self):
        for category in ('parser', 'protocol', 'logic', 'cve', 'negotiation'):
            assert runner._availability_blocked(self._args(), category, 'L') is False

    def test_gate_does_not_prune_the_all_run(self):
        """`all` must still list every category; the gate works per-function.

        Pruning the command list instead would silently drop coverage from
        every run that does not name a category.
        """
        import inspect
        source = inspect.getsource(runner.run_all_tests)
        for name in ('run_memory_attacks', 'run_storage_scp_abuse_attacks',
                     'run_state_machine_attacks'):
            assert name in source


class TestNegotiatedTransferSyntaxMismatch:
    def test_payload_contradicts_the_negotiated_syntax(self):
        from c_scare.attacks import LogicAttacks

        result = LogicAttacks.negotiated_transfer_syntax_mismatch()

        # Negotiate Implicit VR...
        assert result.metadata['transfer_syntax'] == '1.2.840.10008.1.2'
        # ...but send Explicit VR bytes: a readable VR sits where Implicit VR
        # would put the low half of a 4-byte length.
        assert result.payload[4:6] == b'UI'
        assert result.metadata['encoded_transfer_syntax'] == '1.2.840.10008.1.2.1'

    def test_routes_over_a_real_association(self):
        """A wire-level mismatch only means something inside a C-STORE."""
        from c_scare.attacks import LogicAttacks

        result = LogicAttacks.negotiated_transfer_syntax_mismatch()
        args = argparse.Namespace(delivery='auto')

        assert result.metadata['delivery_hint'] == 'cstore'
        assert runner._delivery_kind(args, result) == 'cstore'

    def test_is_distinct_from_the_file_level_mismatch(self):
        from c_scare.attacks import LogicAttacks

        names = [r.name for r in LogicAttacks.all()]
        assert 'transfer_syntax_mismatch' in names
        assert 'negotiated_transfer_syntax_mismatch' in names


class TestUndeliveredIsNotAFinding:
    """A payload that never reached the target concludes nothing about it.

    Every one of these used to return a bare ``None`` status, which the runner
    reported as ``network:timeout`` — a detection. So pointing the tool at an
    SCP that declines the association, or running it on a host without scapy,
    produced a page of findings against a target that was never touched. The
    inverse is just as bad: a genuine silence after the object was sent has to
    stay a finding.
    """

    def _outcome_result(self, reason, status=None):
        """Run one C-STORE delivery whose outcome is fixed, and monitor it."""
        from c_scare import deliver as deliver_mod
        from c_scare.monitor import ProtocolMonitor

        result = AttackResult(
            name='probe', category='cve', payload=b'\x00' * 8,
            description='d', expected_behavior='e',
            metadata={'delivery_hint': 'cstore'})
        args = argparse.Namespace(
            delivery='cstore', mutate=None, ae_title='PACS', calling_ae='SCU',
            dry_run=None, max_associations=None, cstore_file=None,
            store_sop=None, store_transfer_syntax=None)

        original = runner.deliver.send_cstore_outcome
        runner.deliver.send_cstore_outcome = (
            lambda *a, **k: deliver_mod.CStoreOutcome(status, reason))
        try:
            _response, error = runner._deliver(
                args, result, ('127.0.0.1', 11112), 1.0)
        finally:
            runner.deliver.send_cstore_outcome = original

        monitor = ProtocolMonitor()
        monitor.pre_test(0)
        monitor.set_response(None, error=error)
        return result, error, monitor.post_test()

    @pytest.mark.parametrize('reason', ['rejected', 'no_context',
                                        'unavailable:scapy', 'error:ValueError'])
    def test_undelivered_reasons_are_not_detections(self, reason):
        result, error, report = self._outcome_result(reason)
        assert error == f'undelivered:{reason}'
        assert report.detected is False, (
            f'{reason} reported as a finding against a target it never reached')
        assert report.finding_type == 'delivery:not_delivered'
        assert result.metadata['delivery_error'] == reason

    @pytest.mark.parametrize('reason,expected', [
        ('refused', 'network:connection_refused'),
        ('reset', 'network:connection_reset'),
        ('timeout', 'network:timeout'),
        ('no_status', 'network:timeout'),
    ])
    def test_target_behaviour_stays_a_finding(self, reason, expected):
        """The fix must not silence the failures that are the target's doing."""
        _result, _error, report = self._outcome_result(reason)
        assert report.detected is True
        assert report.finding_type == expected

    def test_a_real_status_still_reports_the_status(self):
        result, error, report = self._outcome_result(None, status=0x0000)
        assert error == 'cstore_status'
        assert result.metadata['cstore_status'] == 0x0000
        assert 'delivery_error' not in result.metadata

    def test_undelivered_payloads_are_counted_in_the_summary(self, capsys):
        """Silence is the failure mode: an undelivered run must say so.

        Without this the run prints a clean report — no detections is exactly
        what a target that handled everything correctly looks like.
        """
        from c_scare.monitor import MonitorReport

        results = []
        for i in range(3):
            r = AttackResult(name=f'p{i}', category='cve', payload=b'x',
                             description='d', expected_behavior='e',
                             metadata={'delivery_error': 'rejected'})
            r.monitor_reports.append(MonitorReport(
                detected=False, finding_type='delivery:not_delivered',
                description='Not delivered (rejected)'))
            results.append(r)
        results.append(AttackResult(name='ok', category='cve', payload=b'x',
                                    description='d', expected_behavior='e'))

        runner._print_undelivered(results)
        out = capsys.readouterr().out
        assert '3 of 4 payloads were never delivered' in out
        assert 'rejected ×3' in out

    def test_a_fully_delivered_run_prints_no_warning(self, capsys):
        runner._print_undelivered([
            AttackResult(name='ok', category='cve', payload=b'x',
                         description='d', expected_behavior='e')])
        assert capsys.readouterr().out == ''


class TestCStoreOutcomeReasons:
    """``send_cstore_outcome`` has to name the cause, not just the symptom."""

    def test_missing_scapy_is_reported_as_unavailable(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def no_client(name, *a, **k):
            if 'client' in name:
                raise ImportError('boom', name='scapy')
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, '__import__', no_client)
        outcome = deliver.send_cstore_outcome(
            ('127.0.0.1', 1), b'x', '1.2.840.10008.5.1.4.1.1.7')
        assert outcome.status is None
        assert outcome.reason.startswith('unavailable')
        assert outcome.delivered is False

    def test_connection_refused_is_not_read_as_an_association_rejection(self):
        """Nothing listens on port 1, so this drives the real transport path.

        associate() catches the ConnectionRefusedError and returns False, the
        same as an A-ASSOCIATE-RJ. Reporting a dead port as "the SCP refused
        the association" sends an operator hunting for an AE title problem.
        """
        outcome = deliver.send_cstore_outcome(
            ('127.0.0.1', 1), b'x', '1.2.840.10008.5.1.4.1.1.7', timeout=1.0)
        assert outcome.status is None
        assert outcome.reason == 'refused'

    @pytest.mark.parametrize('last_reject,last_error,expected', [
        ({'result': 1, 'source': 1, 'reason': 7}, None, 'rejected'),
        (None, 'ConnectionRefusedError: [Errno 111]', 'refused'),
        (None, 'ConnectionResetError: [Errno 104]', 'reset'),
        (None, 'no response to A-ASSOCIATE-RQ (timeout or closed)', 'timeout'),
        (None, 'TimeoutError: timed out', 'timeout'),
        (None, 'OSError: [Errno 113] No route to host', 'unreachable:OSError'),
        (None, None, 'rejected'),
    ])
    def test_associate_failure_is_attributed_to_its_cause(
            self, last_reject, last_error, expected):
        """associate() returns one False for four outcomes; recover which."""
        session = argparse.Namespace(last_reject=last_reject,
                                     last_error=last_error)
        assert deliver._associate_failure_reason(session) == expected

    def test_send_cstore_keeps_its_status_only_contract(self, monkeypatch):
        """The published signature must not change under callers."""
        monkeypatch.setattr(
            deliver, 'send_cstore_outcome',
            lambda *a, **k: deliver.CStoreOutcome(0xA700, None))
        assert deliver.send_cstore(
            ('127.0.0.1', 11112), b'x', '1.2.3') == 0xA700

    def test_delivered_flag_splits_the_reasons(self):
        for reason in ('refused', 'reset', 'timeout', 'no_status'):
            assert deliver.CStoreOutcome(None, reason).delivered is True
        for reason in ('rejected', 'no_context', 'unavailable:scapy',
                       'error:ValueError'):
            assert deliver.CStoreOutcome(None, reason).delivered is False
        assert deliver.CStoreOutcome(0x0000, None).delivered is True
