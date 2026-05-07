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

from scapy.packet import raw  # noqa: E402

from c_scare import (  # noqa: E402
    A_ASSOCIATE_RQ,
    A_RELEASE_RQ,
    C_ECHO_RQ,
    C_FIND_RQ,
    C_GET_RQ,
    C_MOVE_RQ,
    C_STORE_RQ,
    CT_IMAGE_STORAGE_SOP_CLASS_UID,
    DEFAULT_TRANSFER_SYNTAX_UID,
    DICOM,
    DICOMApplicationContext,
    DICOMVariableItem,
    P_DATA_TF,
    PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
    PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
    PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
    PresentationDataValueItem,
    VERIFICATION_SOP_CLASS_UID,
    build_presentation_context_rq,
    build_user_information,
)

SEEDS_ROOT = REPO_ROOT / "fuzz" / "seeds"
DEFAULT_SEED = 0xC5CA8E
CALLING_AE = "C-SCARE-FZ"

# Q/R SCP requires the calling AE to match a known peer in its config; the
# dcmqrscp.cfg.template (fuzz/configs/) accepts CALLING_AE as a recognised peer.


def _associate_rq(called_ae: str, abstract_syntax_uid: str) -> bytes:
    variable_items = [
        DICOMVariableItem() / DICOMApplicationContext(),
        build_presentation_context_rq(
            context_id=1,
            abstract_syntax_uid=abstract_syntax_uid,
            transfer_syntax_uids=[DEFAULT_TRANSFER_SYNTAX_UID],
        ),
        build_user_information(max_pdu_length=16384),
    ]
    pkt = DICOM() / A_ASSOCIATE_RQ(
        called_ae_title=called_ae,
        calling_ae_title=CALLING_AE,
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


def _release_rq() -> bytes:
    return bytes(raw(DICOM() / A_RELEASE_RQ()))


def _flow(called_ae: str, abstract_syntax_uid: str, dimse_pkt) -> bytes:
    return (
        _associate_rq(called_ae, abstract_syntax_uid)
        + _p_data_command(dimse_pkt)
        + _release_rq()
    )


def _write_seeds(out_dir: Path, called_ae: str, flows, seed: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, abs_syntax, dimse in flows:
        blob = _flow(called_ae, abs_syntax, dimse)
        out = out_dir / f"{name}.raw"
        out.write_bytes(blob)
        print(f"  wrote {out.relative_to(REPO_ROOT)} ({len(blob)} bytes)")
    (out_dir / "SEED.txt").write_text(f"{seed}\n")


def seeds_storescp(rng: random.Random):
    return [
        ("echo", VERIFICATION_SOP_CLASS_UID,
         C_ECHO_RQ(message_id=rng.randint(1, 0xFFFF))),
        ("store", CT_IMAGE_STORAGE_SOP_CLASS_UID,
         C_STORE_RQ(
             message_id=rng.randint(1, 0xFFFF),
             affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
             affected_sop_instance_uid="1.2.3.4.5.6.7.8.9.10",
             priority=0x0000,
         )),
    ]


def seeds_dcmrecv(rng: random.Random):
    return [
        ("echo", VERIFICATION_SOP_CLASS_UID,
         C_ECHO_RQ(message_id=rng.randint(1, 0xFFFF))),
        ("store", CT_IMAGE_STORAGE_SOP_CLASS_UID,
         C_STORE_RQ(
             message_id=rng.randint(1, 0xFFFF),
             affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
             affected_sop_instance_uid="1.2.3.4.5.6.7.8.9.11",
             priority=0x0000,
         )),
    ]


def seeds_dcmqrscp(rng: random.Random):
    return [
        ("echo", VERIFICATION_SOP_CLASS_UID,
         C_ECHO_RQ(message_id=rng.randint(1, 0xFFFF))),
        ("find", PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
         C_FIND_RQ(
             message_id=rng.randint(1, 0xFFFF),
             affected_sop_class_uid=PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
             priority=0x0000,
         )),
        ("move", PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
         C_MOVE_RQ(
             message_id=rng.randint(1, 0xFFFF),
             affected_sop_class_uid=PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
             move_destination=CALLING_AE,
             priority=0x0000,
         )),
        ("get", PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
         C_GET_RQ(
             message_id=rng.randint(1, 0xFFFF),
             affected_sop_class_uid=PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
             priority=0x0000,
         )),
    ]


def main() -> int:
    seed = int(os.environ.get("C_SCARE_SERIALIZER_SEED", str(DEFAULT_SEED)), 0)

    targets = [
        ("net-storescp", "STORESCP", seeds_storescp),
        ("net-dcmrecv",  "DCMRECV",  seeds_dcmrecv),
        ("net-dcmqrscp", "DCMQRSCP", seeds_dcmqrscp),
    ]

    for sub, called_ae, builder in targets:
        rng = random.Random(seed)  # reset per-target so seeds are deterministic
        flows = builder(rng)
        out_dir = SEEDS_ROOT / sub
        _write_seeds(out_dir, called_ae, flows, seed)

    print(f"  serializer seed={hex(seed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
