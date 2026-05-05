#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Phase 3: deterministic AFLNet seed serializer for DICOM DIMSE sessions.

Emits one .raw seed per canonical DIMSE flow. Each seed is concatenated raw
PDU bytes:

    A-ASSOCIATE-RQ  ||  P-DATA-TF (DIMSE command set)  ||  A-RELEASE-RQ

AFLNet replays these byte streams against a live storescp / storescu, then
mutates within them. The DICOM PDU header (1B type + 1B reserved + 4B BE
length) is the natural message boundary even without a custom AFLNet
parser hook — that hook is Phase 5 work.

Determinism: a fixed seed (env C_SCARE_SERIALIZER_SEED, default 0xC5CARE)
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

OUT_DIR = REPO_ROOT / "fuzz" / "seeds" / "net"
DEFAULT_SEED = 0xC5CA8E
CALLING_AE = "C-SCARE-FZ"
CALLED_AE = "STORESCP"


def _associate_rq(abstract_syntax_uid: str) -> bytes:
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
        called_ae_title=CALLED_AE,
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


def _flow(abstract_syntax_uid: str, dimse_pkt) -> bytes:
    return _associate_rq(abstract_syntax_uid) + _p_data_command(dimse_pkt) + _release_rq()


def main() -> int:
    seed = int(os.environ.get("C_SCARE_SERIALIZER_SEED", str(DEFAULT_SEED)), 0)
    rng = random.Random(seed)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    flows = [
        ("echo", VERIFICATION_SOP_CLASS_UID, lambda: C_ECHO_RQ(message_id=rng.randint(1, 0xFFFF))),
        (
            "store",
            CT_IMAGE_STORAGE_SOP_CLASS_UID,
            lambda: C_STORE_RQ(
                message_id=rng.randint(1, 0xFFFF),
                affected_sop_class_uid=CT_IMAGE_STORAGE_SOP_CLASS_UID,
                affected_sop_instance_uid="1.2.3.4.5.6.7.8.9.10",
                priority=0x0000,
            ),
        ),
        (
            "find",
            PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
            lambda: C_FIND_RQ(
                message_id=rng.randint(1, 0xFFFF),
                affected_sop_class_uid=PATIENT_ROOT_QR_FIND_SOP_CLASS_UID,
                priority=0x0000,
            ),
        ),
        (
            "move",
            PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
            lambda: C_MOVE_RQ(
                message_id=rng.randint(1, 0xFFFF),
                affected_sop_class_uid=PATIENT_ROOT_QR_MOVE_SOP_CLASS_UID,
                move_destination=CALLING_AE,
                priority=0x0000,
            ),
        ),
        (
            "get",
            PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
            lambda: C_GET_RQ(
                message_id=rng.randint(1, 0xFFFF),
                affected_sop_class_uid=PATIENT_ROOT_QR_GET_SOP_CLASS_UID,
                priority=0x0000,
            ),
        ),
    ]

    for name, abs_syntax, build_dimse in flows:
        blob = _flow(abs_syntax, build_dimse())
        out = OUT_DIR / f"{name}.raw"
        out.write_bytes(blob)
        print(f"  wrote {out.relative_to(REPO_ROOT)} ({len(blob)} bytes)")

    (OUT_DIR / "SEED.txt").write_text(f"{seed}\n")
    print(f"  wrote {(OUT_DIR / 'SEED.txt').relative_to(REPO_ROOT)} (seed={hex(seed)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
