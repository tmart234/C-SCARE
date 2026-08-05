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

C-SCARE ships hand-built payloads across the attack categories below. The
catalog is used two ways: delivered live for black-box DAST, or written to disk
as an AFL/AFLNet seed corpus (`c-scare corpus -o ./corpus`) — see
[Grey-box fuzzing](fuzzing.md).

| Category | Payloads | What it targets | Key class |
|----------|:--------:|----------------|-----------|
| **Parser** | 11 | VR fuzzing, length mismatches, sequence bombs, format strings | `ParserAttacks` |
| **Protocol** | 18 | PDU malformation, AE title overflow, missing items, duplicate/even presentation contexts, tiny Max PDU negotiation | `ProtocolAttacks` |
| **Memory** | 10 | Pixel dimension overflow, fragment bombs, LUT overflow | `MemoryAttacks` |
| **Logic** | 7 | Transfer syntax mismatch, SSRF via URI, file:// injection | `LogicAttacks` |
| **Storage SCP Abuse** | 10 | Unauthenticated C-STORE import/storage abuse: empty identity, duplicate identity, command-vs-dataset mismatch, disk pressure, private-tag pressure, malformed C-STORE command/data sequences | `StorageSCPAbuseAttacks` |
| **Command Injection** | 13 | Shell metacharacters in SOP/Study Instance UID & Patient Name that feed storescp's `--exec-on-reception` placeholders (DCMTK #1194 / CVE-2026-5663) | `CommandInjectionAttacks` |
| **Path Traversal** | 23 | SOP/Study Instance UID, Patient Name, command-vs-dataset mismatches, file-meta confusion, Windows/POSIX absolute paths, UI padding/length/VM boundary cases, and attacker-controlled-extension plus NUL-byte suffix bypasses that escape storescp/SCU storage directories (CVE-2022-2119/2120) | `PathTraversalAttacks` |
| **State Machine** | 5 | Out-of-order PDUs (Sta1–Sta13 violations) | `StateMachineAttacks` |
| **CVE** | 59 | DCMTK, GDCM, Orthanc, pydicom, dcm4che/standard polyglot, and ICSMA-26-181-01 DCMTK cases | `CVEAttacks` |

Each `*Attacks` class exposes an `all()` iterator of `AttackResult` objects.

### CVE mapping (fidelity matters)

Each payload tags its CVE relationship honestly in `metadata`:

- **`metadata['cve']` — directly targeted / probed.** Twenty-five CVEs across
  DCMTK, GDCM, Orthanc, pydicom, and the standard-level polyglot — spanning
  parser NULL-derefs, codec OOB read/write, integer over/underflow, type
  confusion, path traversal, and command injection. The use-after-free entries
  (32135/24793/24794), the `DcmItem::read` recursion (10528), and the Philips
  PMSCT_RLE1 entry (5441) are *structural triggers / regression seeds* — a
  single static buffer cannot itself drive a heap use-after-free or guarantee a
  stack smash, so they steer a parser into the vulnerable code path rather than
  deterministically reproducing the bug. The full CVE coverage map (every CVE,
  every library, and its delivery vector) lives in
  [cve_coverage.md](cve_coverage.md).
- **`metadata['cve_related']` — inspired-by bug classes, not reproductions.**
  Generic length/overflow/recursion payloads modelled after `CVE-2024-22100`
  (heap overflow), `CVE-2024-25578` (out-of-bounds write) and
  `CVE-2024-28877` (stack overflow); these also carry a `bug_class` tag.
- **Config-file CVEs** for the grey-box dcmqrscp track live under
  `fuzz/configs/malformed/`: `CVE-2020-36855`, `CVE-2022-4981`.

The dcmnet sibling `CVE-2024-34508` is represented by AFLNet network-campaign
coverage rather than a static catalog CVE tag.

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
from c_scare import DICOMSession          # SCU client (c_scare.client)
from c_scare.scapy_dicom import *          # wire-format layer: PDUs, DIMSE, UIDs
from scapy.packet import raw, fuzz

# Fuzzed association request
pdu = raw(fuzz(DICOM() / A_ASSOCIATE_RQ()))

# Full session
with DICOMSession('192.168.1.100', 11112, 'PACS', 'ATTACKER') as sock:
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

### Start with a known-good C-STORE

Before interpreting malformed dataset results, prove that the same association
parameters can store a small valid object. `--cstore-smoke` sends a known-good
Secondary Capture object before the catalog and aborts the run if the SCP does
not return `0x0000`:

```bash
c-scare --ip 192.0.2.10 --port 104 \
  --ae-title PACS \
  --calling-ae MOVEDEST \
  --store-sop 1.2.840.10008.5.1.4.1.1.7 \
  --store-transfer-syntax 1.2.840.10008.1.2.1 \
  --cstore-smoke \
  --category storage_abuse \
  --delivery cstore \
  --timeout 10 \
  -v
```

### Carry the catalog on a real object

A synthetic Secondary Capture object is enough for a generic SCP, but a device
that requires modality-specific elements will reject it before the payload ever
reaches the code under test — every result then reads as "rejected" and proves
nothing. `--cstore-file` fixes that by making a known-good object from the
target itself the carrier:

```bash
c-scare --ip 192.0.2.10 --port 104 \
  --ae-title PACS \
  --calling-ae MOVEDEST \
  --cstore-file ./known-good.dcm \
  --cstore-smoke \
  --category storage_abuse \
  --delivery cstore \
  --timeout 10 \
  -v
```

C-SCARE reads the Part-10 file with pydicom, strips the file wrapper for network
C-STORE delivery, and takes the association baseline (SOP Class UID, Transfer
Syntax UID) from the file. Each dataset-shaped attack is then overlaid on its
own copy of that object, driven entirely by the attack's declared metadata:

| Attack declares | Overlay on the carrier |
|---|---|
| `target_field` + the matching value key | that one element is rewritten |
| `command_*_uid` / `dataset_*_uid` | the named half of the C-STORE is rewritten |
| `cstore_field_overrides` | the listed elements are rewritten |
| `coverage_scope: identity-validation` | Patient Name/ID are blanked |
| `coverage_scope: storage-quota-disk-pressure` | Pixel Data is replaced (see `CSCARE_CSTORE_RSS_PRESSURE_BYTES`) |
| none of the above | the attack's own dataset is appended to the carrier |

Every delivered copy gets a fresh Study/Series/SOP Instance UID and a
`C-SCARE^<attack>` Patient Name, so one attack's object cannot collide with or
overwrite another's, and a stored object can be traced back to the test that
sent it. Set `CSCARE_DAST_RUN_ID` to make those UIDs deterministic per run.

Raw PDU and state-machine attacks stay byte-level protocol tests; they have no
meaningful representation as a C-STORE object and are delivered unchanged.

The `--store-transfer-syntax` value should come from enumeration. For example,
if `dicom-enum` reports `Secondary Capture Image Storage - Explicit VR Little
Endian`, use `1.2.840.10008.1.2.1`. A `0xC000` or `0xA900` result on later
malformed payloads then means the target explicitly rejected the malformed
object, not that the baseline association was broken.

Raw PDU and multi-step sequence attacks are still byte-level protocol tests.
For live DAST, C-SCARE rewrites ordinary raw `A-ASSOCIATE-RQ` Called/Calling AE
fields from `--ae-title` and `--calling-ae`; tests that intentionally fuzz AE
titles keep their catalog bytes.

## Monitor DUT-side effects

Black-box DAST can see network-visible failures, but it cannot inspect the
device's filesystem, coredumps, kernel log, or service watchdog state. For live
device runs, copy `scripts/dut_monitor.py` to the DUT and run it while the DAST
catalog runs from the test host:

```bash
sudo python3 dut_monitor.py \
  --proc-re 'my-dicom-service' \
  --storage-port 104 \
  --log-dir /var/log/my-dicom-service \
  --watch-root /var/lib/my-dicom-service \
  --peer-host 192.0.2.50
```

Four flags carry everything device-specific; the rest of the tool is generic:

| Flag | What it needs | Why it matters |
|---|---|---|
| `--proc-re` | regex matching the DICOM service process | scopes crash/restart/resource detection to the target, not the whole host |
| `--log-dir` / `--dicom-log` | the service's log directory or files | crash signatures and reachability evidence the network cannot show |
| `--watch-root` | the DICOM storage root | a path-traversal write that escapes it is only visible if the root is watched |
| `--peer-host` | the address running C-SCARE | narrows the capture filter to the test traffic |

With no flags it still runs: it watches any `storescp`/`dcmrecv`/`dcmqrscp`/
`orthanc` process on port 104, scans `/tmp` and `/var/tmp` for canaries, and
captures all traffic on the monitored ports. That is enough for a stock SCP and
not enough for a real device — supply the flags above.

Whatever the configuration, each run:

- samples RSS, open file descriptors, and thread count for every matched PID
  into `process-resources.csv`;
- resets the `/tmp/c-scare-rce` and `c-scare-traversal*` markers, then rescans
  the watch roots so a canary write is attributable to this run;
- records target crash/OOM events and critical faults from dmesg, filtering
  unrelated kernel noise;
- polls coredumps for the matched processes; and
- writes `network.pcap`.

Log lines matching an association-received / association-ended / listener-started
shape are recorded as reachability evidence, not findings — they distinguish "no
crash" from "the payloads never arrived". Add `--activity-pattern NAME=REGEX`
for a device whose log wording differs. Generic `[ERROR]` lines are deliberately
not findings; most DICOM services emit them routinely during startup and
negotiation.

Each run uses a private, timestamped `/tmp/c-scare-monitor-*` directory. Read
`summary.txt` for the operator result, `summary.json` for automation, and
`dut-monitor.sarif` for DUT-side code-scanning ingestion. A
`security_finding=DETECTED` / `dut_observed_impact=FAIL` result means the run
observed a canary, target crash-class log entry, coredump, kernel fault,
process restart/loss, listener drop, or persistent resource growth. The default
growth thresholds are 128 MiB RSS, 64 file descriptors, or 32 threads above a
PID's baseline for three consecutive samples. `NONE_DETECTED` means no monitored
host impact was observed; check `coverage` and the raw resource CSV before
treating that as a clean DUT result. Use `--fail-on-finding` to return exit
status 1 for detected impact.

To correlate a filesystem canary with the triggering test, compare the canary's
`mtime_epoch_ns` or `ctime_epoch_ns` in `summary.json`, `evidence.jsonl`, or
`dut-monitor.sarif` against each host SARIF result's `started_epoch_ns` and
`ended_epoch_ns` window. The host and DUT clocks must be synchronized for this
to be exact. The console finding also includes a microsecond timestamp plus the
canary path, size, mtime, and ctime for quick triage.

SARIF severity follows evidence strength. A connection reset, refusal, timeout,
empty response, or unexpected PDU alone is a `warning`. Confirmed
`protocol:accepted`, sanitizer/crash/leak evidence, canary writes, coredumps, or
`resource:*` growth is an `error`. A delivered test with no finding remains a
`note`.

The pcap can contain DICOM payloads and PHI. The monitor restricts evidence file
permissions, but the output directory must still be handled as sensitive test
evidence. Useful overrides include `--qr-port 105`, `--duration 600`,
`--peer-host <ip>`, `--tcpdump-filter '<bpf>'`, `--rss-growth-mb`, `--fd-growth`,
`--thread-growth`, `--resource-consecutive`, `--no-tcpdump`,
`--no-reset-canaries`, and repeated `--dicom-log` values for a nonstandard
deployment. Set a resource threshold to `0` to disable that detector. Add
`--inotify` when `inotifywait` is installed and event-level filesystem evidence
is needed.

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
