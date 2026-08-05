#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 3: deterministic AFLNet seed serializer for DICOM DIMSE sessions.

Emits one .raw seed per canonical DIMSE flow under per-target seed dirs:

    fuzz/seeds/net-storescp/  — verification + C-STORE
    fuzz/seeds/net-dcmrecv/   — verification + C-STORE (storage SCP)
    fuzz/seeds/net-dcmqrscp/  — verification + C-FIND + C-MOVE + C-GET (Q/R SCP)

Each seed is concatenated raw PDU bytes:

    A-ASSOCIATE-RQ  ||  P-DATA-TF (DIMSE command set)  ||  A-RELEASE-RQ

AFLNet replays these byte streams against the live SCP, then mutates within
them. The DICOM PDU header (1B type + 1B reserved + 4B BE length) is the
natural message boundary for AFLNet's built-in `-P DICOM` parser.

The AE titles, presentation-context abstract syntaxes (SOP classes), transfer
syntaxes, and per-DIMSE flows are NOT hardcoded here — they come from the
declarative target profiles (``fuzz/targets/<target>.yaml``, see
``c_scare.profiles``). The same ``calling_ae`` / ``called_ae`` a profile feeds
into the A-ASSOCIATE-RQ is what scripts/fuzz_dcmqrscp.sh substitutes into
``dcmqrscp.cfg``, so the Q/R SCP recognises the peer.

Usage:
    seed_serializer.py [<target>]   # default: every net-scp profile

Determinism: a fixed seed (env C_SCARE_SERIALIZER_SEED, default 0xC5CA8E)
drives random.Random for message IDs. The seed is written to SEED.txt
alongside the .raw files so reruns are reproducible.
"""
import os
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import c_scare  # noqa: E402
from scapy.packet import raw  # noqa: E402

from c_scare import (  # noqa: E402
    A_ASSOCIATE_RQ,
    A_RELEASE_RQ,
    DICOM,
    DICOMApplicationContext,
    DICOMVariableItem,
    P_DATA_TF,
    PresentationDataValueItem,
    build_presentation_context_rq,
    build_user_information,
)
from c_scare.profiles import load_profile, load_profiles  # noqa: E402

SEEDS_ROOT = REPO_ROOT / "fuzz" / "seeds"
DEFAULT_SEED = 0xC5CA8E
_SPECIAL_DIMSE_KWARGS = {"dataset"}


def _associate_rq(profile, flow) -> bytes:
    variable_items = [
        DICOMVariableItem() / DICOMApplicationContext(),
        build_presentation_context_rq(
            context_id=1,
            abstract_syntax_uid=flow.abstract_syntax,
            transfer_syntax_uids=list(flow.transfer_syntaxes),
        ),
        build_user_information(max_pdu_length=profile.max_pdu_length),
    ]
    pkt = DICOM() / A_ASSOCIATE_RQ(
        called_ae_title=profile.called_ae,
        calling_ae_title=profile.calling_ae,
        variable_items=variable_items,
    )
    return bytes(raw(pkt))


def _p_data_command(dimse_pkt) -> bytes:
    pdv = PresentationDataValueItem(
        context_id=1,
        data=bytes(dimse_pkt),
        is_command=1,
        is_last=1,
    )
    return bytes(raw(DICOM() / P_DATA_TF(pdv_items=[pdv])))


def _p_data_command_and_dataset(dimse_pkt, dataset_bytes=None) -> bytes:
    pdv_items = [
        PresentationDataValueItem(
            context_id=1,
            data=bytes(dimse_pkt),
            is_command=1,
            is_last=1,
        )
    ]
    if dataset_bytes is not None:
        pdv_items.append(
            PresentationDataValueItem(
                context_id=1,
                data=dataset_bytes,
                is_command=0,
                is_last=1,
            )
        )
    return bytes(raw(DICOM() / P_DATA_TF(pdv_items=pdv_items)))


def _release_rq() -> bytes:
    return bytes(raw(DICOM() / A_RELEASE_RQ()))


def _dataset_encoding_flags(flow):
    from pydicom.uid import UID

    transfer_syntax = flow.transfer_syntaxes[0] if flow.transfer_syntaxes else c_scare.DEFAULT_TRANSFER_SYNTAX_UID
    uid = UID(transfer_syntax)
    implicit_vr = bool(uid.is_implicit_VR) if uid.is_implicit_VR is not None else (
        transfer_syntax == c_scare.IMPLICIT_VR_LITTLE_ENDIAN_UID
    )
    little_endian = bool(uid.is_little_endian) if uid.is_little_endian is not None else (
        transfer_syntax != c_scare.EXPLICIT_VR_BIG_ENDIAN_UID
    )
    return implicit_vr, little_endian


def _encode_dataset(dataset, flow) -> bytes:
    from pydicom.filebase import DicomBytesIO
    from pydicom.filewriter import write_dataset

    implicit_vr, little_endian = _dataset_encoding_flags(flow)
    dataset.is_implicit_VR = implicit_vr
    dataset.is_little_endian = little_endian
    buffer = DicomBytesIO()
    buffer.is_implicit_VR = implicit_vr
    buffer.is_little_endian = little_endian
    write_dataset(buffer, dataset)
    return buffer.getvalue()


def _cstore_dataset(profile, flow, spec):
    from pydicom.dataset import Dataset

    sop_instance_uid = str(
        spec.get("sop_instance_uid")
        or flow.dimse_kwargs.get("affected_sop_instance_uid")
        or "1.2.826.0.1.3680043.10.543.1.1"
    )
    study_uid = str(spec.get("study_instance_uid", "1.2.826.0.1.3680043.10.543.1"))
    series_uid = str(spec.get("series_instance_uid", "1.2.826.0.1.3680043.10.543.1.2"))
    rows = int(spec.get("rows", 2))
    columns = int(spec.get("columns", 2))
    bits_allocated = int(spec.get("bits_allocated", 16))
    samples_per_pixel = int(spec.get("samples_per_pixel", 1))
    bytes_per_sample = max(1, (bits_allocated + 7) // 8)

    dataset = Dataset()
    dataset.SOPClassUID = flow.abstract_syntax
    dataset.SOPInstanceUID = sop_instance_uid
    dataset.StudyInstanceUID = study_uid
    dataset.SeriesInstanceUID = series_uid
    dataset.PatientName = spec.get("patient_name", "C-SCARE^Seed")
    dataset.PatientID = spec.get("patient_id", "C-SCARE-0001")
    dataset.StudyID = spec.get("study_id", "1")
    dataset.StudyDate = spec.get("study_date", "20260722")
    dataset.StudyTime = spec.get("study_time", "120000")
    dataset.SeriesNumber = int(spec.get("series_number", 1))
    dataset.InstanceNumber = int(spec.get("instance_number", 1))
    dataset.Modality = spec.get("modality", "CT")
    dataset.Manufacturer = spec.get("manufacturer", "C-SCARE")
    dataset.ImageType = spec.get("image_type", ["ORIGINAL", "PRIMARY", "AXIAL"])
    dataset.Rows = rows
    dataset.Columns = columns
    dataset.SamplesPerPixel = samples_per_pixel
    dataset.PhotometricInterpretation = spec.get("photometric_interpretation", "MONOCHROME2")
    dataset.BitsAllocated = bits_allocated
    dataset.BitsStored = int(spec.get("bits_stored", bits_allocated))
    dataset.HighBit = int(spec.get("high_bit", dataset.BitsStored - 1))
    dataset.PixelRepresentation = int(spec.get("pixel_representation", 0))
    dataset.PixelSpacing = spec.get("pixel_spacing", ["1", "1"])
    dataset.SliceThickness = spec.get("slice_thickness", "1")
    dataset.RescaleIntercept = spec.get("rescale_intercept", "0")
    dataset.RescaleSlope = spec.get("rescale_slope", "1")
    dataset.PixelData = bytes((rows * columns * samples_per_pixel * bytes_per_sample))
    return dataset


def _qr_identifier_dataset(profile, flow, spec):
    from pydicom.dataset import Dataset

    dataset = Dataset()
    dataset.QueryRetrieveLevel = spec.get("query_retrieve_level", "STUDY")
    dataset.PatientID = spec.get("patient_id", "C-SCARE-0001")
    dataset.PatientName = spec.get("patient_name", "")
    dataset.StudyInstanceUID = spec.get("study_instance_uid", "1.2.826.0.1.3680043.10.543.1")
    dataset.StudyDate = spec.get("study_date", "")
    dataset.AccessionNumber = spec.get("accession_number", "")
    if dataset.QueryRetrieveLevel in ("SERIES", "IMAGE"):
        dataset.SeriesInstanceUID = spec.get("series_instance_uid", "")
    if dataset.QueryRetrieveLevel == "IMAGE":
        dataset.SOPInstanceUID = spec.get("sop_instance_uid", "")
    return dataset


def _flow_dataset_bytes(profile, flow):
    spec = flow.dimse_kwargs.get("dataset")
    if not spec:
        return None
    kind = spec.get("kind")
    if kind == "cstore-image":
        return _encode_dataset(_cstore_dataset(profile, flow, spec), flow)
    if kind in {"find-study", "move-study", "qr-study-identifier"}:
        return _encode_dataset(_qr_identifier_dataset(profile, flow, spec), flow)
    raise ValueError(f"unsupported dataset seed kind {kind!r} in flow {flow.name!r}")


def _build_dimse(flow, rng: random.Random):
    """Construct a DIMSE command packet for ``flow`` from the profile.

    ``affected_sop_class_uid`` defaults to the flow's presentation-context
    abstract syntax (the same UID for every flow today); per-flow extras
    (instance UID, priority, C-MOVE destination) come from ``dimse_kwargs``.
    """
    dimse_cls = getattr(c_scare, flow.dimse)
    kwargs = {"affected_sop_class_uid": flow.abstract_syntax}
    kwargs.update({
        key: value for key, value in flow.dimse_kwargs.items()
        if key not in _SPECIAL_DIMSE_KWARGS
    })
    kwargs["message_id"] = rng.randint(1, 0xFFFF)
    return dimse_cls(**kwargs)


def _flow_bytes(profile, flow, rng: random.Random) -> bytes:
    dimse_pkt = _build_dimse(flow, rng)
    return (
        _associate_rq(profile, flow)
        + _p_data_command_and_dataset(dimse_pkt, _flow_dataset_bytes(profile, flow))
        + _release_rq()
    )


def _write_target(profile, seed: int) -> None:
    out_dir = SEEDS_ROOT / profile.name
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)  # reset per-target so seeds are deterministic
    for flow in profile.flows:
        blob = _flow_bytes(profile, flow, rng)
        out = out_dir / f"{flow.name}.raw"
        out.write_bytes(blob)
        print(f"  wrote {out.relative_to(REPO_ROOT)} ({len(blob)} bytes)")
    (out_dir / "SEED.txt").write_text(f"{seed}\n")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    seed = int(os.environ.get("C_SCARE_SERIALIZER_SEED", str(DEFAULT_SEED)), 0)

    if argv:
        profiles = [load_profile(argv[0])]
    else:
        profiles = [p for p in load_profiles().values() if p.kind == "net-scp"]

    for profile in profiles:
        if profile.kind != "net-scp" or not profile.flows:
            continue
        _write_target(profile, seed)

    print(f"  serializer seed={hex(seed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
