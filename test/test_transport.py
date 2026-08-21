# SPDX-License-Identifier: GPL-2.0-only
"""The transport seam: what crosses the wire, and who decides.

Two protocols move DICOM objects, and they disagree about one thing that
matters here — whether the 128-byte preamble travels. C-STORE sends a Data
Set, so it does not; STOW-RS posts ``application/dicom`` instances, so it does.

That fact used to live on each payload as ``survives_cstore``, which stated a
transport property as a payload one: adding a second transport would have
meant a second flag, and two flags that must agree. A payload now says where
its content lives and a transport says what it carries, and ``survives()``
combines them. These tests pin that split, because the whole point is that
adding a transport does not touch the catalog.
"""

import io
import re
import struct
import threading
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("pydicom")
import pydicom  # noqa: E402

from c_scare import dicomweb, transport  # noqa: E402

#: The transfer syntax the catalog encodes its Part-10 payloads in.
EXPLICIT_VR_LE = '1.2.840.10008.1.2.1'

warnings.filterwarnings("ignore")


class TestRegionAndCarriage:
    """A payload declares where its content is; a transport what it moves."""

    DIMSE = transport.DimseTransport()
    WEB = transport.DicomWebTransport(base_url="http://x/dicom-web")

    def test_c_store_does_not_carry_whole_files(self):
        """PS3.10 puts the preamble outside the Data Set. Not a shortcoming."""
        assert self.DIMSE.carries_whole_file is False

    def test_stow_rs_does(self):
        assert self.WEB.carries_whole_file is True

    @pytest.mark.parametrize("region,dimse_ok,web_ok", [
        (transport.REGION_DATA_SET, True, True),
        (transport.REGION_WHOLE_FILE, False, True),
    ])
    def test_the_matrix(self, region, dimse_ok, web_ok):
        assert transport.survives(region, self.DIMSE) is dimse_ok
        assert transport.survives(region, self.WEB) is web_ok

    def test_an_untagged_payload_is_assumed_to_travel(self):
        """Most of the catalog is dataset-shaped; silence should not exclude."""
        assert transport.survives(None, self.DIMSE) is True

    def test_the_same_catalog_scores_differently_per_transport(self):
        """The property the split exists for, measured on the real catalog."""
        from c_scare.attacks import CVEAttacks
        family = [r for r in CVEAttacks.all()
                  if r.metadata.get("cve") == "CVE-2019-11687"]
        over_dimse = [r for r in family
                      if transport.survives(r.metadata["payload_region"],
                                            self.DIMSE)]
        over_web = [r for r in family
                    if transport.survives(r.metadata["payload_region"],
                                          self.WEB)]
        assert len(over_web) == len(family)
        assert 0 < len(over_dimse) < len(over_web), (
            "the two transports should not reach the same payload set — if "
            "they do, this catalog no longer exercises the difference")


class TestTransportSelection:
    def test_an_explicit_target_wins_over_args(self):
        """Delivery paths are handed a resolved address; it is authoritative.

        Reading the host from args instead sent every payload to the default
        port while reporting success against the one under test.
        """
        import argparse
        args = argparse.Namespace(target="10.0.0.1:104", dicomweb_url=None)
        carrier = transport.for_args(args, target=("127.0.0.1", 11112))
        assert (carrier.host, carrier.port) == ("127.0.0.1", 11112)

    def test_a_dicomweb_url_selects_the_http_transport(self):
        import argparse
        args = argparse.Namespace(dicomweb_url="http://h/dicom-web",
                                  dicomweb_token="abc", insecure=True)
        carrier = transport.for_args(args)
        assert isinstance(carrier, transport.DicomWebTransport)
        assert carrier.verify_tls is False
        assert carrier.headers["Authorization"] == "Bearer abc"

    def test_dimse_is_the_default(self):
        import argparse
        carrier = transport.for_args(argparse.Namespace(), target=("h", 1))
        assert isinstance(carrier, transport.DimseTransport)

    def test_wado_without_a_study_path_says_so(self):
        """WADO-RS addresses an instance by Study/Series/SOP. Guessing a URL
        would 404 and read like the archive dropped the object."""
        outcome = self.WEB_T.retrieve(sop_class_uid="1.2", sop_instance_uid="3")
        assert outcome.data is None
        assert outcome.reason == "no_study_series_uid"

    WEB_T = transport.DicomWebTransport(base_url="http://x/dicom-web")


class TestMultipart:
    """DICOM instances travel as multipart parts, byte for byte."""

    def test_round_trip_preserves_bytes_exactly(self):
        parts = [b"\x00" * 128 + b"DICM" + b"payload-one", b"\xff\xd8second"]
        body, boundary = dicomweb.build_multipart(parts)
        back = dicomweb.split_multipart(body, f'boundary="{boundary}"')
        assert back == parts, "a reshaped payload is no longer the payload"

    def test_binary_content_survives(self):
        """Every byte value, including the CRLF the framing itself uses."""
        blob = bytes(range(256)) * 4
        body, boundary = dicomweb.build_multipart([blob])
        assert dicomweb.split_multipart(body, f"boundary={boundary}") == [blob]

    def test_a_missing_boundary_does_not_raise(self):
        """The archive under test is not assumed to be well behaved."""
        assert dicomweb.split_multipart(b"raw", "") == [b"raw"]
        assert dicomweb.split_multipart(b"", "") == []

    def test_accepted_maps_the_stow_status_codes(self):
        """PS3.18: 200 all stored, 202 some stored. 409/400 are refusals."""
        for status in (200, 202):
            assert dicomweb.WebOutcome(status, None).accepted is True
        for status in (400, 409, 500, None):
            assert dicomweb.WebOutcome(status, "rejected").accepted is False


class _Archive(BaseHTTPRequestHandler):
    """A minimal STOW-RS/WADO-RS archive that stores instances verbatim."""

    store = {}
    strip_private = False

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        parts = dicomweb.split_multipart(self.rfile.read(length),
                                         self.headers["Content-Type"])
        for part in parts:
            if _Archive.strip_private:
                ds = pydicom.dcmread(io.BytesIO(part), force=True)
                for element in [e for e in ds if e.tag.group % 2 == 1]:
                    del ds[element.tag]
                ds.preamble = b"\x00" * 128
                buffer = io.BytesIO()
                ds.save_as(buffer, enforce_file_format=True)
                part = buffer.getvalue()
            ds = pydicom.dcmread(io.BytesIO(part), force=True)
            _Archive.store[(ds.StudyInstanceUID, ds.SeriesInstanceUID,
                            ds.SOPInstanceUID)] = part
        self.send_response(200)
        self.send_header("Content-Type", "application/dicom+json")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_GET(self):
        match = re.match(
            r"/dicom-web/studies/([^/]+)/series/([^/]+)/instances/([^/]+)",
            self.path)
        blob = _Archive.store.get(match.groups()) if match else None
        if not blob:
            self.send_response(404)
            self.end_headers()
            return
        body, boundary = dicomweb.build_multipart([blob])
        self.send_response(200)
        self.send_header(
            "Content-Type",
            f'multipart/related; type="application/dicom"; boundary={boundary}')
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def archive():
    _Archive.store = {}
    _Archive.strip_private = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Archive)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/dicom-web", _Archive
    server.shutdown()


class TestWholeFileRoundTrip:
    """The property that makes DICOMweb worth having: the preamble crosses."""

    def _payload(self):
        from c_scare.attacks import CVEAttacks
        return next(r for r in CVEAttacks.all()
                    if r.name == "cve_2019_11687_16_pe_in_storable_image")

    def test_the_preamble_survives_stow_and_wado(self, archive):
        from c_scare import polyglot
        base, _ = archive
        result = self._payload()
        carrier = transport.DicomWebTransport(base_url=base)

        stored = carrier.store(
            result.payload,
            sop_class_uid=result.metadata["sop_class_uid"],
            sop_instance_uid=result.metadata["sop_instance_uid"])
        assert stored.accepted is True and stored.status == 200

        back = carrier.retrieve(
            sop_class_uid=result.metadata["sop_class_uid"],
            sop_instance_uid=result.metadata["sop_instance_uid"],
            study_instance_uid=result.metadata["study_instance_uid"],
            series_instance_uid=result.metadata["series_instance_uid"])
        assert back.data is not None, back.reason

        # The whole point: still an MZ at offset 0 on the far side. A C-STORE
        # round trip cannot produce this, because the preamble never left.
        assert polyglot.executable_format(back.data) == "pe"
        verdict = polyglot.compare_after_pipeline(result.payload, back.data)
        assert verdict.outcome == polyglot.SURVIVED_INTACT

    def test_a_sanitising_archive_still_reads_as_stripped(self, archive):
        from c_scare import polyglot
        base, handler = archive
        handler.strip_private = True
        result = self._payload()
        carrier = transport.DicomWebTransport(base_url=base)
        carrier.store(result.payload,
                      sop_class_uid=result.metadata["sop_class_uid"],
                      sop_instance_uid=result.metadata["sop_instance_uid"])
        back = carrier.retrieve(
            sop_class_uid=result.metadata["sop_class_uid"],
            sop_instance_uid=result.metadata["sop_instance_uid"],
            study_instance_uid=result.metadata["study_instance_uid"],
            series_instance_uid=result.metadata["series_instance_uid"])
        verdict = polyglot.compare_after_pipeline(result.payload, back.data)
        assert verdict.outcome == polyglot.SURVIVED_STRIPPED

    def test_a_dead_endpoint_is_named_not_raised(self):
        carrier = transport.DicomWebTransport(
            base_url="http://127.0.0.1:1/dicom-web")
        outcome = carrier.store(b"x", sop_class_uid="1.2",
                                sop_instance_uid="3", timeout=2.0)
        assert outcome.accepted is False
        assert outcome.status is None
        assert outcome.reason in ("refused", "timeout") or \
            outcome.reason.startswith("unreachable")


class TestMonitorReadsAcceptanceNotADimseStatus:
    """A STOW-RS 200 is not a DIMSE 0x0000, and must not be read as one."""

    def _report(self, accepted, status):
        from c_scare.monitor import ProtocolMonitor
        monitor = ProtocolMonitor()
        monitor.pre_test(0)
        monitor.set_response(bytes([(status >> 8) & 0xFF, status & 0xFF]),
                             error="cstore_status",
                             finding_on=ProtocolMonitor.FINDING_ON_STORE,
                             accepted=accepted)
        return monitor.post_test()

    def test_an_http_200_is_a_finding_when_the_transport_says_accepted(self):
        """200 decodes as DIMSE 0x00C8, which is not a success status —
        deriving acceptance from it made every DICOMweb store read as a
        refusal."""
        assert self._report(True, 200).finding_type == "storage:payload_accepted"

    def test_an_http_409_is_not(self):
        assert self._report(False, 409).detected is False

    def test_the_dimse_derivation_still_applies_when_unset(self):
        from c_scare.monitor import ProtocolMonitor
        monitor = ProtocolMonitor()
        monitor.pre_test(0)
        monitor.set_response(b"\x00\x00", error="cstore_status",
                             finding_on=ProtocolMonitor.FINDING_ON_STORE)
        assert monitor.post_test().finding_type == "storage:payload_accepted"


class TestDimseRetrievalFidelity:
    """What ``--verify-retrieval`` reports about a DIMSE archive.

    ``retrieve_instance`` exists to answer one question: did the archive alter
    the payload? The framework can only answer it by leaving the payload alone
    on the way past. It used to parse the returned Data Set with pydicom and
    write it back with pydicom, which drops every retired group length -- so a
    payload parked in one came back as "the receiver removed the embedded
    content", a finding against a target that had done nothing.

    These tests run the render step with no archive in the loop: any verdict
    below the best one available is the framework accusing itself.
    """

    @staticmethod
    def _polyglot_payloads():
        """Catalog payloads with a private element the pipeline can track."""
        from c_scare import attacks, polyglot
        from c_scare.carrier import split_part10

        for result in attacks.CVEAttacks.all():
            if not result.payload:
                continue
            _pre, _meta, dataset, _els = split_part10(result.payload)
            if not dataset or not polyglot._private_values(result.payload):
                continue
            yield result, dataset

    def test_a_passthrough_archive_is_never_reported_as_sanitising(self):
        from c_scare import polyglot
        from c_scare.client import render_retrieved

        checked = 0
        for result, dataset in self._polyglot_payloads():
            back = render_retrieved(dataset, EXPLICIT_VR_LE)
            verdict = polyglot.compare_after_pipeline(result.payload, back)
            assert verdict.outcome != polyglot.SURVIVED_STRIPPED, result.name
            assert verdict.outcome != polyglot.SURVIVED_ALTERED, result.name
            checked += 1
        assert checked > 10, 'the polyglot corpus went missing'

    def test_a_payload_in_a_group_length_element_is_not_reported_stripped(self):
        """The case that used to fail, named.

        PS3.5 retires ``(gggg,0000)`` and pydicom's writer skips it. A payload
        that lives in one is invisible to a writer and perfectly visible to a
        parser, which is exactly why the catalog puts one there.
        """
        from c_scare import polyglot
        from c_scare.client import render_retrieved

        result, dataset = next(
            (r, d) for r, d in self._polyglot_payloads()
            if 'group_length_tag' in r.name)
        back = render_retrieved(dataset, EXPLICIT_VR_LE)
        verdict = polyglot.compare_after_pipeline(result.payload, back)
        assert verdict.outcome == polyglot.SURVIVED_PAYLOAD, verdict.detail
        assert verdict.carrier_bytes_returned == verdict.carrier_bytes_sent

    def test_the_render_returns_the_peers_data_set_byte_for_byte(self):
        from c_scare.carrier import split_part10
        from c_scare.client import render_retrieved

        for _result, dataset in self._polyglot_payloads():
            back = render_retrieved(dataset, EXPLICIT_VR_LE)
            _pre, _meta, returned, _els = split_part10(back)
            assert returned == dataset

    @pytest.mark.parametrize('transfer_syntax', [
        '1.2.840.10008.1.2', '1.2.840.10008.1.2.1', '1.2.840.10008.1.2.2',
    ], ids=['implicit_le', 'explicit_le', 'explicit_be'])
    def test_the_render_honours_the_negotiated_syntax(self, transfer_syntax):
        """The presentation context already said how the Data Set is encoded.

        Guessing here would misread a big-endian object as little-endian and
        turn the peer's bytes into nonsense before anything looked at them.
        """
        import pydicom

        from c_scare.client import render_retrieved
        from c_scare.element import Dataset, Element

        implicit = transfer_syntax == '1.2.840.10008.1.2'
        little = transfer_syntax != '1.2.840.10008.1.2.2'
        dataset = (Dataset()
                   / Element(0x0008, 0x0016, 'UI', '1.2.840.10008.5.1.4.1.1.7')
                   / Element(0x0008, 0x0018, 'UI', '1.2.3.4.5')
                   / Element(0x0010, 0x0010, 'PN', 'Real^Patient')
                   ).encode(implicit_vr=implicit, little_endian=little)

        back = render_retrieved(dataset, transfer_syntax)
        parsed = pydicom.dcmread(io.BytesIO(back), force=True)
        assert str(parsed.file_meta.TransferSyntaxUID) == transfer_syntax
        assert str(parsed.SOPInstanceUID) == '1.2.3.4.5'
        assert str(parsed.PatientName) == 'Real^Patient'

    def test_an_archive_that_really_strips_still_reads_as_stripped(self):
        """The fix must not have made every verdict optimistic."""
        from c_scare import polyglot
        from c_scare.carrier import Carrier
        from c_scare.client import render_retrieved

        result, dataset = next(iter(self._polyglot_payloads()))
        carrier = Carrier.from_dataset(dataset, EXPLICIT_VR_LE)
        edit = carrier.edit()
        for element in carrier.elements:
            if element.group % 2 == 1 and element.element != 0x0010:
                edit.delete(element.tag, 'sanitise')
        sanitised = render_retrieved(edit.to_bytes(), EXPLICIT_VR_LE)

        verdict = polyglot.compare_after_pipeline(result.payload, sanitised)
        assert verdict.outcome == polyglot.SURVIVED_STRIPPED

    def test_an_archive_that_rewrites_the_payload_reads_as_altered(self):
        from c_scare import polyglot
        from c_scare.carrier import Carrier
        from c_scare.client import render_retrieved

        result, dataset = next(iter(self._polyglot_payloads()))
        carrier = Carrier.from_dataset(dataset, EXPLICIT_VR_LE)
        edit = carrier.edit()
        for element in carrier.elements:
            if element.group % 2 == 1 and element.element != 0x0010:
                value = carrier.value_of(element.tag) or b''
                edit.set_value(element.tag, 'OB', b'\x00' * len(value),
                               'rewrite')
        rewritten = render_retrieved(edit.to_bytes(), EXPLICIT_VR_LE)

        verdict = polyglot.compare_after_pipeline(result.payload, rewritten)
        assert verdict.outcome == polyglot.SURVIVED_ALTERED

    def test_an_unconvertible_element_costs_that_element_not_the_verdict(self):
        """A retrieved object may be worse-formed than the one we sent.

        ``for element in dataset`` converts each raw element on the way past,
        and one value pydicom cannot convert used to raise straight out of the
        monitor -- no verdict at all for the payload most likely to produce one.
        """
        from c_scare import polyglot

        payload = (b'\x00' * 128 + b'DICM'
                   + _explicit(0x0002, 0x0010, b'UI',
                               b'1.2.840.10008.1.2.1\x00')
                   + _explicit(0x0009, 0x0010, b'LO', b'C-SCARE\x00')
                   + _explicit(0x0009, 0x1001, b'OB', b'MZ\x90\x00')
                   # A Sequence Delimitation Item with nothing to delimit:
                   # structurally present, semantically unconvertible.
                   + struct.pack('<HHI', 0xFFFE, 0xE0DD, 0))
        values = polyglot._private_values(payload)
        assert values.get(0x00091001) == b'MZ\x90\x00'


def _explicit(group, element, vr, value):
    """One explicit-VR little-endian element, long form for OB."""
    head = struct.pack('<HH', group, element) + vr
    if vr in (b'OB', b'OW', b'SQ', b'UN', b'UT'):
        return head + b'\x00\x00' + struct.pack('<I', len(value)) + value
    return head + struct.pack('<H', len(value)) + value
