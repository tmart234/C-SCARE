# C-SCARE

**DICOM Security Testing Framework** — black-box DAST, grey-box fuzzing, and scripted pentest workflows for DICOM implementations.

C-SCARE surgically crafts malformed DICOM files, datasets, and network traffic to probe PACS servers, viewers, and medical-device software.

## Capabilities at a glance

C-SCARE is organised around *who* you test — a DICOM server (SCP) or a client (SCU) — and *how* you test it: three pillars, each documented in its own guide. The matrix below quantifies what ships today, which role each pillar targets (see **Targets**), and where each capability lives.

|                       | **Pentest workflows** | **DAST** (black-box) | **Fuzzing** (grey-box) |
|-----------------------|-----------------------|----------------------|------------------------|
| **What it does**      | Scripted recon → query/retrieve flows that reach a test's starting state | Deliver a static attack catalog at a live target, watch for anomalies | Coverage-guided mutation of instrumented binaries |
| **Quantified**        | **5** workflows (W1–W5) | **8** attack categories · **68** payloads · **13** CVEs | **6** targets · **2** engines · **3** sanitizers |
| **Targets**           | SCP and SCU | SCP (server) and SCU (client, via rogue server) | SCP (file/parser/network) and SCU (experimental) |
| **Instrumentation**   | None | None — works on real devices / prebuilt binaries | Required (recompiled, QEMU, or SAND) |
| **Engine**            | C-SCARE (`DICOMSocket`) | C-SCARE (catalog + monitors) | AFL++ / AFLNet (C-SCARE bridges + triages) |
| **CLI**               | `c-scare wf …` | `c-scare --ip … --category …` / `c-scare rogue …` | `c-scare greybox run / triage …` |
| **Output**            | Classified findings | SARIF v2.1.0 | SARIF v2.1.0 |
| **Guide**             | [docs/workflows.md](docs/workflows.md) | [docs/dast.md](docs/dast.md) | [docs/fuzzing.md](docs/fuzzing.md) |

## What C-SCARE is — and is not

**C-SCARE does not contain a fuzzing engine.** The mutation loop and coverage feedback belong to AFL++ (file targets) and AFLNet (network targets). C-SCARE supplies everything around them: crafting & corruption (`Corruptor` re-emits a real `.dcm` *invalid*, which pydicom alone cannot; `scapy_dicom` crafts malformed PDUs/DIMSE a compliant library refuses to send), the static attack catalog and its seed generators, the `RawSCP` rogue server for fuzzing clients, the grey-box bridge that drives AFL++/AFLNet and triages crashes, and sanitizer/protocol/process-health monitors emitting SARIF v2.1.0.

## Architecture

```mermaid
flowchart TD
    USER[Operator / Researcher]

    subgraph CRAFT [Crafting and corruption]
        ELEMENT[element.py]
        CORRUPTOR[corruptor.py]
        PIXEL[pixel.py]
        FILE[file.py]
        SCAPY[scapy_dicom.py - PDUs/DIMSE + DICOMSocket]
    end

    CATALOG[attacks.py - static attack catalog + seed generators]

    subgraph BLACKBOX [Black-box / DAST]
        DELIVER[deliver.py]
        SERVER[server.py - RawSCP]
    end

    subgraph WORKFLOWS [Attack workflows - role-agnostic]
        ISSUER[workflows.py - issuer: ae_brute / cred_brute / c_find / c_get / c_move - targets an SCP]
        RESPONDER[responders.py - WorkflowResponder - targets an SCU]
    end

    subgraph GREYBOX [Grey-box]
        AFL[AFL++ / AFLNet engines]
        GB[greybox.py - harness + crash triage]
    end

    MONITOR[monitor.py - sanitizer / process / protocol]
    SARIF[SARIF v2.1.0 report]

    USER --> CATALOG
    USER --> SERVER
    USER --> WORKFLOWS
    USER --> GB
    CATALOG --> CRAFT
    CRAFT --> CATALOG
    CATALOG -->|live delivery| DELIVER
    CATALOG -->|seed corpus| AFL
    ISSUER -->|acts as SCU| SCAPY
    RESPONDER -->|acts as SCP| SERVER
    DELIVER --> MONITOR
    AFL --> GB
    GB --> MONITOR
    SERVER --> MONITOR
    MONITOR --> SARIF
    WORKFLOWS -->|findings| SARIF
```

### Module reference

| Module | Purpose |
|--------|---------|
| `element.py` | Dataset/Element building with Scapy-style `/` chaining |
| `corruptor.py` | pydicom bridge — read with pydicom, re-emit *invalid* with our encoder |
| `pixel.py` | Encapsulated pixel data with fragment-level control + Scapy layers |
| `file.py` | Part 10 file handling (preamble, meta header, transfer syntax via `pydicom.uid.UID`) |
| `scapy_dicom.py` | DICOM crafting engine — PDUs, DIMSE-C/N, `DICOMSocket`; crafts malformed traffic |
| `server.py` | `RawSCP` rogue server for fuzzing clients (SCU) |
| `attacks.py` | Static attack catalog + seed generators — classes expose `all()` iterators of `AttackResult` |
| `workflows.py` | SCU-side attack workflows (issuer) — `ae_brute()`, `cred_brute()`, `build_query()`; query/retrieve flows (`c_find`/`c_get`/`c_move`) live on `DICOMSocket` |
| `responders.py` | SCP-side workflow responders (exercise an SCU client) — `accept_association()`, DIMSE RSP builders, `WorkflowResponder` |
| `deliver.py` | Black-box delivery — `send_pdu()`, `send_sequence()`, `send_cstore()` (optional `user_identity=` to authenticate first) |
| `greybox.py` | Grey-box bridge — launches AFL++/AFLNet harnesses, triages crashes to SARIF |
| `monitor.py` | Crash/anomaly detection — sanitizer, protocol and process-health monitors |
| `test_runner.py` | CLI (`c-scare` / `python -m c_scare`) |

## Quick start

C-SCARE is not published on PyPI — install it from source:

```bash
git clone https://github.com/tmart234/C-SCARE
cd C-SCARE
pip install -e .            # core install: pydicom + scapy
pip install -e ".[test]"    # also installs pytest + pynetdicom (test suite)
```

The grey-box fuzzing toolchain additionally needs the git submodules and a DCMTK build — see [docs/fuzzing.md](docs/fuzzing.md):

```bash
git submodule update --init   # AFL++, AFLNet, DCMTK
scripts/build_dcmtk.sh        # build DCMTK (AFL++ afl-clang-fast + AFLNet afl-gcc, ASan)
```

Then pick a pillar:

```bash
# DAST — run the attack catalog against a live server
c-scare --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --category cve --sarif cve.sarif

# Pentest workflow — brute Called AE Titles and read each accepted AET's AC payload (W1)
c-scare wf --ip 127.0.0.1 --port 4242 ae-brute --aets PACS,RADIOLOGY_BACKUP_2017

# Grey-box fuzzing — drive AFL++ against dcm2pnm
c-scare greybox run file
```

(`python -m c_scare …` is equivalent to the `c-scare` console command.)

## Documentation

| Guide | Contents |
|-------|----------|
| [docs/dast.md](docs/dast.md) | Black-box DAST — attack catalog (8 categories / 68 payloads / 13 CVEs), corruptor & scapy crafting, live delivery, rogue server |
| [docs/workflows.md](docs/workflows.md) | Pentest workflows — W1–W5 issuer drivers, SCP-side responders |
| [docs/fuzzing.md](docs/fuzzing.md) | Grey-box fuzzing — DCMTK toolchain, targets, device parity, SAND mode, coverage, campaigns |
| [docs/protocol.md](docs/protocol.md) | Byte-level DICOM structure (file format, data elements, PDUs, DIMSE, state machine) |

## License

GPL-2.0-only
