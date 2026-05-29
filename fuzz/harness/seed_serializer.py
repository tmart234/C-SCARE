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


def _release_rq() -> bytes:
    return bytes(raw(DICOM() / A_RELEASE_RQ()))


def _build_dimse(flow, rng: random.Random):
    """Construct a DIMSE command packet for ``flow`` from the profile.

    ``affected_sop_class_uid`` defaults to the flow's presentation-context
    abstract syntax (the same UID for every flow today); per-flow extras
    (instance UID, priority, C-MOVE destination) come from ``dimse_kwargs``.
    """
    dimse_cls = getattr(c_scare, flow.dimse)
    kwargs = {"affected_sop_class_uid": flow.abstract_syntax}
    kwargs.update(flow.dimse_kwargs)
    kwargs["message_id"] = rng.randint(1, 0xFFFF)
    return dimse_cls(**kwargs)


def _flow_bytes(profile, flow, rng: random.Random) -> bytes:
    return (
        _associate_rq(profile, flow)
        + _p_data_command(_build_dimse(flow, rng))
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
