# C-SCARE Agent Instructions

C-SCARE is a Python DICOM security testing framework for black-box DAST, scripted pentest workflows, and grey-box fuzzing support around AFL++/AFLNet. Before changing behavior, identify the role and method involved: SCP server vs SCU client, and DAST/workflow vs grey-box. Keep edits aligned with that boundary.

## Start Here

- Project overview and CLI examples: [README.md](README.md)
- Module map: [c_scare/README.md](c_scare/README.md)
- Black-box DAST and attack catalog: [docs/dast.md](docs/dast.md)
- Grey-box toolchain, target profiles, SAND, coverage, and device parity: [docs/fuzzing.md](docs/fuzzing.md)
- Pentest workflows: [docs/workflows.md](docs/workflows.md)
- Byte-level DICOM reference: [docs/protocol.md](docs/protocol.md)

## Setup And Verification

- Install core package: `pip install -e .`
- Install test extras: `pip install -e ".[test]"`
- Run Python tests with `pytest`. Use focused tests while iterating, then run the full suite for shared behavior.
- If you change target profiles or fuzz harness argv, run `scripts/check_profiles.sh` in a bash-capable environment.
- If you change grey-box build or harness scripts, the broader smoke path is `scripts/smoke.sh`; grey-box fuzzing itself is Linux/bash-oriented.
- Grey-box setup needs `git submodule update --init` and `scripts/build_dcmtk.sh`; do not start long AFL campaigns unless the user asks.

## CLI Surface

- Console entry point: `c-scare` maps to `c_scare.runner:main`; `python -m c_scare` is equivalent.
- Default DAST mode has no subcommand: `c-scare --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --category cve --sarif out.sarif`.
- Subcommands: `corpus`, `rogue`, `wf`, `greybox`, and alias-like `dast` for default DAST mode.
- `--cstore-file <known-good.dcm>` makes a real object the carrier for dataset-shaped attacks; the overlay in `runner.py` is metadata-driven, so never add attack-name special cases there.
- Workflow commands are `c-scare wf ae-brute`, `cred-brute`, `find`, `get`, `move`, and `respond`.
- Built-in grey-box targets are profile-derived: `file`, `parse`, `net-storescp`, `net-dcmrecv`, `net-dcmqrscp`, and experimental `scu`.

## Component Boundaries

- `element.py`, `corruptor.py`, `pixel.py`, and `file.py` own malformed DICOM dataset/file construction.
- `attacks.py` owns the static catalog; attack classes expose `all()` iterators of `AttackResult` objects. Placement of a payload on the wire is declared in `metadata`, never by attack name: `steps` means a multi-PDU sequence, `sop_class_uid`/`delivery_hint: cstore` means C-STORE delivery, and anything else is a single raw PDU. Negotiation payloads must not declare `sop_class_uid` — they *are* the association request.
- `scapy_dicom.py` owns DICOM PDU/DIMSE packet definitions, builders, dissection helpers, and low-level transport helpers. Scapy is a hard dependency — do not add `SCAPY_AVAILABLE` fallbacks, which are unreachable and drift from the real encoding. Two builder tiers: the Packet classes and `build_*` helpers for anything that must be well-formed (scapy keeps item, PDU and DIMSE group lengths in sync), and the `raw_*` builders for the one field a malformation test needs to lie about. `test/test_wire_format.py` holds scapy_dicom to pynetdicom as an independent oracle; keep it passing.
- `client.py` owns stateful SCU behavior through `DICOMSession`; `server.py` and `responders.py` own rogue/responder SCP behavior for client-facing tests.
- `deliver.py` and `runner.py` choose how payloads reach a live target; `monitor.py` owns sanitizer, protocol, and process-health detection.
- `scripts/dut_monitor.py` is the DUT-side half of DAST: dependency-free, runs on the device, and must stay device-agnostic — every deployment fact is a flag (`--proc-re`, `--log-dir`, `--watch-root`, `--peer-host`, `--activity-pattern`), never a constant.
- `greybox.py` is a thin bridge for launching harnesses and triaging AFL++/AFLNet outputs. AFL++/AFLNet own mutation loops and coverage feedback.
- `profiles.py` and `scripts/profile_lib.sh` own declarative target loading. `fuzz/targets/*.yaml` drives Python target maps, shell harness argv, network triage server argv, and seed-generation identity.
- `fuzz/harness/seed_serializer.py` emits AFLNet `.raw` DICOM message streams for network targets: `A-ASSOCIATE-RQ || P-DATA-TF || A-RELEASE-RQ`. A flow that declares `dimse_kwargs.dataset` in its profile also gets a data PDV (`cstore-image` for C-STORE, `qr-study-identifier` for C-FIND/C-MOVE/C-GET); without one the seed is command-only and mutations never reach the SCP's dataset parser or storage path. New dataset shapes go in `_flow_dataset_bytes`, not in per-target code.

## Reasoning Rules

- Prefer linking to the docs above instead of copying their tables into new files.
- For nontrivial work, trace the path from crafted bytes to delivery or triage before editing: file/dataset/PDU/DIMSE, target role, command path, monitor/report path, then tests.
- Keep target data declarative. `fuzz/targets/*.yaml` is the source of truth consumed by `c_scare/profiles.py` and `scripts/profile_lib.sh`; do not hardcode new target lists in `greybox.py`, `scripts/campaign.sh`, or seed generators. Adding a grey-box target means adding a profile plus a harness script if no existing harness shape fits.
- For AFLNet network targets, keep the canonical options from `scripts/aflnet_common.sh`, especially state-aware mode `-E` with `-q 3`.
- Network seeds and target configs must agree on AE titles, SOP classes, and transfer syntaxes. Check the target profile, `fuzz/harness/seed_serializer.py`, and any rendered `dcmqrscp.cfg` flow together. A DIMSE command whose semantics depend on a dataset (C-STORE, any Q/R) needs `dimse_kwargs.dataset` in its flow.
- Dataset-shaped categories such as parser, memory, path traversal, and command injection need C-STORE delivery to reach SCP import/parsing paths; raw PDU delivery is for PDU/state-machine attacks.
- File-target triage replays inputs as files through sanitizer binaries. Network-target triage uses `--net <target>` and AFLNet replay against a fresh instrumented server per input. Prefer `--auto`, which recovers the campaign's own argv (and SAND worker) from AFL's `cmdline`/`fuzzer_setup`; replaying through a different argv is the usual reason a saved crash does not reproduce.
- Leak-class bugs usually require `--include-queue`; they often live in AFL queue inputs rather than crash directories.
- Preserve SARIF v2.1.0 semantics when changing reports: rules are keyed by `category/name`, detections live under `properties.monitors`, and successful detections should not be confused with process success.

## Test Pitfalls

- Keep the Scapy IPv6 workaround at the top of [test/conftest.py](test/conftest.py), before any Scapy import.
- Tests that need `pynetdicom` should use `pytest.importorskip("pynetdicom")`; it is part of the test extra, not the core install contract.
- The bash scripts assume Unix tooling (`bash`, `awk`, `sed`, `mktemp`) and AFL/DCMTK builds. On Windows, prefer Python CLI/unit-test work unless running scripts through WSL or another bash-capable environment.
- When changing fuzz profiles, update or add focused `test/test_profiles.py` coverage and run `scripts/check_profiles.sh` where possible.
- When changing network seed generation, add focused coverage that parses the generated A-ASSOCIATE-RQ/P-DATA-TF bytes and proves the profile values actually reached the seed.