# Black-box DAST

DAST is the **black-box** half of the C-SCARE matrix: deliver a static catalog
of malformed DICOM files, datasets, and network traffic at a live target and
watch for protocol/health anomalies. No build access or instrumentation is
needed — it works against a real device, a container, or a vendor-prebuilt
binary.

Two delivery directions:

- **Against a server (SCP)** — `c-scare --ip … --port … --category …` sends the
  catalog live to a PACS server / viewer.
- **Against a client (SCU)** — the `RawSCP` rogue server (`c-scare rogue …`)
  feeds malformed responses to a connecting client, controlling exactly what
  bytes the server sends.

## Attack catalog

C-SCARE ships **8 attack categories** totalling **68 hand-built payloads** and
covering **13 unique CVEs**. The catalog is used two ways: delivered live for
black-box DAST, or written to disk as an AFL/AFLNet seed corpus
(`c-scare corpus -o ./corpus`) — see [Grey-box fuzzing](fuzzing.md).

| Category | Payloads | What it targets | Key class |
|----------|:--------:|----------------|-----------|
| **Parser** | 11 | VR fuzzing, length mismatches, sequence bombs, format strings | `ParserAttacks` |
| **Protocol** | 14 | PDU malformation, AE title overflow, missing items | `ProtocolAttacks` |
| **Memory** | 10 | Pixel dimension overflow, fragment bombs, LUT overflow | `MemoryAttacks` |
| **Logic** | 7 | Transfer syntax mismatch, SSRF via URI, file:// injection | `LogicAttacks` |
| **Command Injection** | 3 | Shell metacharacters in SOP/Study Instance UID & Patient Name that feed storescp's `--exec-on-reception` placeholders (DCMTK #1194 / CVE-2026-5663) | `CommandInjectionAttacks` |
| **Path Traversal** | 3 | `../` sequences in SOP/Study Instance UID & Patient Name that escape the storescp/SCU storage directory (CVE-2022-2119/2120) | `PathTraversalAttacks` |
| **State Machine** | 5 | Out-of-order PDUs (Sta1–Sta13 violations) | `StateMachineAttacks` |
| **CVE** | 15 | CVE-2023-32135, CVE-2024-24793/94, CVE-2024-33606, CVE-2019-11687, and more | `CVEAttacks` |

Each `*Attacks` class exposes an `all()` iterator of `AttackResult` objects.

### CVEs covered

`CVE-2019-11687`, `CVE-2022-2119`, `CVE-2022-2120`, `CVE-2023-32135`,
`CVE-2024-22100`, `CVE-2024-24793`, `CVE-2024-24794`, `CVE-2024-25578`,
`CVE-2024-28877`, `CVE-2024-33606`, `CVE-2024-34508`, `CVE-2024-34509`,
`CVE-2026-5663`.

## Crafting & corruption primitives

C-SCARE provides the parts around the attack catalog:

- **Crafting & corruption** — `Corruptor` parses a real `.dcm` with pydicom and
  re-emits it *invalid* (pydicom alone cannot write malformed files);
  `scapy_dicom` crafts malformed PDUs/DIMSE that a compliant library refuses to
  send.
- **Monitoring & reporting** — sanitizer / protocol / process-health monitors
  and SARIF v2.1.0 output.

### Corrupt a real DICOM file

```python
import pydicom
from c_scare import Corruptor

ds = pydicom.dcmread("ct_scan.dcm")
c = Corruptor(ds)
c.set_vr(0x00100010, 'XX')              # Invalid VR
c.set_length(0x00100020, 0xFFFFFFFF)     # Lie about length
c.duplicate(0x00100010)                  # Duplicate tag (UAF trigger)

with open("corrupted.dcm", "wb") as f:
    f.write(c.to_file())
```

### Fuzz the network protocol

```python
from c_scare.scapy_dicom import *
from scapy.packet import raw, fuzz

# Fuzzed association request
pdu = raw(fuzz(DICOM() / A_ASSOCIATE_RQ()))

# Full session
with DICOMSocket('192.168.1.100', 11112, 'PACS', 'ATTACKER') as sock:
    if sock.associate({CT_IMAGE_STORAGE_SOP_CLASS_UID: [DEFAULT_TRANSFER_SYNTAX_UID]}):
        sock.c_store(dataset_bytes, sop_class_uid, sop_instance_uid, transfer_syntax)
        sock.release()
```

## Run the catalog against a server (SCP)

```bash
# All categories against a live DICOM server
c-scare --ip 127.0.0.1 --port 4242 --ae-title ORTHANC

# A single category, with a SARIF report
c-scare --ip 127.0.0.1 --port 4242 --ae-title ORTHANC --category cve --sarif cve.sarif

# Generate an AFL++/AFLNet seed corpus
c-scare corpus -o ./corpus
```

(`python -m c_scare …` is equivalent to the `c-scare` console command.)

## Fuzz clients with a rogue server (SCU)

`RawSCP` fuzzes DICOM *clients* by controlling exactly what bytes the server
sends.

```python
from c_scare import RawSCP, ConnectionState
from c_scare.scapy_dicom import DICOM, A_ASSOCIATE_AC, A_ABORT
from scapy.packet import raw

scp = RawSCP(port=11112)

@scp.on_associate_rq
def handle(conn, pdu_bytes, pkt):
    return raw(DICOM() / A_ASSOCIATE_AC(protocol_version=0xFFFF))

@scp.on_state(ConnectionState.ASSOCIATED)
def on_associated(conn):
    conn.inject(raw(DICOM() / A_ABORT()))

scp.start()
```

## See also

- [Pentest workflows](workflows.md) — recon → query drivers that reach the
  state (discovered AE title, valid credential) a DAST run should start from.
- [Grey-box fuzzing](fuzzing.md) — feed the same catalog to AFL++/AFLNet as a
  seed corpus.
- [protocol.md](protocol.md) — byte-level DICOM structure.
