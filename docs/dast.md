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
| **Parser** | 18 | VR fuzzing, length mismatches, sequence bombs, format strings, nesting-depth bomb, explicit/implicit VR and endianness confusion, group-length lies, odd-length values, private-block collision | `ParserAttacks` |
| **Protocol** | 18 | PDU malformation, AE title overflow, missing items, duplicate/even presentation contexts, tiny Max PDU negotiation | `ProtocolAttacks` |
| **Memory** | 10 | Pixel dimension overflow, fragment bombs, LUT overflow | `MemoryAttacks` |
| **Logic** | 7 | Transfer syntax mismatch, SSRF via URI, file:// injection | `LogicAttacks` |
| **Storage SCP Abuse** | 10 | Unauthenticated C-STORE import/storage abuse: empty identity, duplicate identity, command-vs-dataset mismatch, disk pressure, private-tag pressure, malformed C-STORE command/data sequences | `StorageSCPAbuseAttacks` |
| **Command Injection** | 13 | Shell metacharacters in SOP/Study Instance UID & Patient Name that feed storescp's `--exec-on-reception` placeholders (DCMTK #1194 / CVE-2026-5663) | `CommandInjectionAttacks` |
| **Path Traversal** | 26 | SOP/Study Instance UID, Patient Name, command-vs-dataset mismatches, file-meta confusion, Windows/POSIX absolute paths, UI padding/length/VM boundary cases, and attacker-controlled-extension plus NUL-byte suffix bypasses that escape storescp/SCU storage directories (CVE-2022-2119/2120) | `PathTraversalAttacks` |
| **State Machine** | 13 | Out-of-order PDUs (Sta1–Sta13), post-abort and post-release processing, release collision, acceptor PDUs sent by the requestor, DIMSE message-ordering and cross-context reassembly | `StateMachineAttacks` |
| **Negotiation** | 15 | A-ASSOCIATE User Information sub-items (PS3.7 D.3.3): User Identity authentication — empty credentials, length lies, Kerberos/SAML/JWT parser reachability, duplicate identity items — plus extended negotiation, role selection, async window | `NegotiationAttacks` |
| **DIMSE-N** | 11 | Normalized services: MPPS N-CREATE/N-SET state transitions and duplicate instances, Storage Commitment N-ACTION/N-EVENT-REPORT false and unsolicited results, N-GET attribute bombs, well-known-instance N-DELETE | `DimseNAttacks` |
| **CVE** | 77 | DCMTK, GDCM, Orthanc, pydicom, dcm4che/standard polyglot (five safe zones × six second formats, plus fragmented, entropy-shaped, storable-carrier and private-tag-container variants), and ICSMA-26-181-01 DCMTK cases | `CVEAttacks` |

Each `*Attacks` class exposes an `all()` iterator of `AttackResult` objects.

Two of these categories exist because the *packet* layer already spoke more
DICOM than the *catalog* did:

- **Negotiation** targets what is parsed before any DIMSE service runs and
  before most access control, so a defect there is reachable by a peer that
  never completes an association. User Identity types 3–5 hand attacker bytes
  straight to a Kerberos, XML, or JWT parser — and many deployments treat that
  sub-item as the authentication boundary. Each payload keeps the mandatory
  user-information items valid, so a rejection is attributable to the sub-item
  under test rather than to an unusable request.
- **DIMSE-N** targets the normalized services a PACS with worklist support
  also speaks. Unlike C-STORE, these mutate *workflow state*, so the
  interesting failures are logic failures: reopening a COMPLETED procedure
  step, committing storage for objects the SCP never received, or accepting an
  unsolicited commitment result from any peer that can reach the port.

### CVE mapping (fidelity matters)

Each payload tags its CVE relationship honestly in `metadata`:

- **`metadata['cve']` — directly targeted / probed.** Thirty CVEs across
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

### Safety guardrails for live clinical systems

A PACS in service is a clinical system, and part of this catalog is designed to
exhaust its resources. Three flags bound what a run can do:

| Flag | Effect |
|---|---|
| `--dry-run DIR` | Never touches the network. Writes every payload that *would* have been delivered into `DIR` (`.dcm` for C-STORE datasets, `.bin` for raw PDUs and sequence steps) and reports every test as a non-finding. |
| `--max-associations N` | Stops the run once it has opened `N` associations. Results collected up to that point are still printed and written to SARIF. |
| `--allow-availability` | Required to run the categories that can degrade availability — `memory`, `storage_abuse`, `state_machine`. Without it they are skipped with a notice, including under `--category all`. |

```bash
# Review what the catalog would send, without sending any of it
c-scare --ip 192.0.2.10 --port 104 --ae-title PACS \
  --category all --dry-run ./payloads

# A bounded probe of a production PACS: read-only categories, 50 associations
c-scare --ip 192.0.2.10 --port 104 --ae-title PACS \
  --category cve --max-associations 50 --sarif findings.sarif

# Opt in to the availability-affecting categories (lab targets)
c-scare --ip 127.0.0.1 --port 4242 --ae-title ORTHANC \
  --category memory --allow-availability
```

`--dry-run` implies the availability opt-in, since nothing is sent.

Delivery is sequential — one association at a time — so `--max-associations` is
a budget on total connection churn, not a concurrency cap.

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

C-SCARE reads the file as **bytes**, not as a parse. The Part-10 wrapper is
split off for network C-STORE delivery, the association baseline (SOP Class
UID, Transfer Syntax UID) is taken from the file, and each dataset-shaped
attack is then *spliced* into its own copy of the Data Set. Elements the attack
does not name come off the wire exactly as they went in.

That distinction is load-bearing. Reading with pydicom and writing with pydicom
looks equivalent and is not: pydicom is a conformant writer, and conformance
here is loss. It skips every retired `(gggg,0000)` Group Length element, emits
`sorted(dataset.keys())` rather than the order the object was written in,
re-reads a `UN` element holding an implicit-VR sequence as `SQ` and re-emits it
with different bytes, repairs truncated elements, resolves ambiguous VRs and
normalises padding. Every one of those is a difference between the object the
operator watched their target accept and the object the target is now asked to
parse — and the difference shows up as a rejection that reads like a clean
result.

Placement is driven entirely by the attack's declared metadata — the table
below is the whole contract, and it lives in
[`c_scare/overlay.py`](../c_scare/overlay.py) rather than in the CLI, because
none of it is command-line work. Adding an attack never means editing that
module; it means declaring, in the attack's metadata, where its payload
belongs.

| Attack declares | Overlay on the carrier |
|---|---|
| `target_field` + the matching value key | that one element is rewritten |
| `command_*_uid` / `dataset_*_uid` | the named half of the C-STORE is rewritten |
| `cstore_field_overrides` | the listed elements are rewritten |
| `coverage_scope: identity-validation` | Patient Name/ID are blanked |
| `coverage_scope: storage-quota-disk-pressure` | the image is *grown*, not replaced (see `CSCARE_CSTORE_RSS_PRESSURE_BYTES`) |
| none of the above | the attack's own elements are merged into the carrier in tag order |

Four properties the carrier path holds, each of which the run reports:

**The payload arrives as written.** A traversal path in a UID, an over-64-character
value, a backslash, an embedded NUL: no validation, no coercion to a
multi-value, no truncation. `cstore_file_mutation` names which overlay was
applied, and `cstore_file_refused` names any that could not be — an overlay
that silently does nothing would report an attack as delivered that the target
never saw.

**Attack elements go where a parser will read them.** They are merged into the
Data Set in tag order rather than appended behind Pixel Data, because an
appended Data Set makes the tags run backwards and a conformant SCP may stop
at the end of the object — so the parser under test never reaches the
malformation. `cstore_file_merged_elements` counts what was placed;
`cstore_file_appended_bytes` counts what could not be (a payload whose
malformation *is* the element stream — a truncated header, a delimiter with no
sequence — has no per-element position to occupy, and rides at the end).

**Merged elements are framed for the carrier's own encoding.** The catalog
writes explicit VR little endian; a carrier may be implicit VR, or big endian.
Only the header is re-framed — the declared length and the value bytes go
through untouched, so a length that lies still lies. Dropped in verbatim
instead, `(0010,0010) XX 0x000C` reads under implicit VR as a four-byte length
of 0x000C5858, and a VR test arrives as an accidental truncation error.

**The transfer syntax is the carrier's, unless the attack says otherwise.**
`--store-transfer-syntax` wins, then the attack's own declared
`transfer_syntax`, then the syntax the carrier is encoded in. The middle term
matters for the handful of attacks whose entire mechanism is a mismatch between
the negotiated syntax and the bytes on the wire.

The image itself is never collateral damage. Disk-pressure attacks grow the
volume the way a longer acquisition would — native Pixel Data gains whole
repeated frames with Number of Frames raised to match, so
`rows x columns x samples x bytes x frames` stays exactly consistent, and
encapsulated Pixel Data gains repeated fragments that each still decode.
Overwriting Pixel Data with filler instead leaves the geometry describing an
image that is no longer there, and the SCP answers with a validator rather than
a parser.

A carrier with no File Meta Information is read too: its encoding is recovered
by trying each candidate and keeping the one that reads furthest, and a minimal
group 0002 is synthesised for the Part-10 rendering that `--dry-run` and
STOW-RS need. Group 0002 is outside the Data Set and never crosses a C-STORE
association, so nothing the target parses changes.

Bytes that do not scan as Data Elements are kept as an opaque tail and
delivered unchanged — a carrier that is already malformed stays exactly as
malformed as the operator made it — and the run says how many
(`cstore_file_opaque_tail_bytes`), because those are also bytes no attack can
be spliced into.

#### Checking the carrier against real images

The carrier path is tested against real scanner-derived objects rather than a
synthetic stub, because every one of the defects it was rewritten to fix showed
up only on a real file: group lengths a scanner emitted, an implicit-VR object,
a big-endian one, a `UN` element holding a sequence, encapsulated Pixel Data
split across fragments, an acquisition truncated on the way to disk.

The default corpus is the set of objects pydicom ships inside the package, so
`pytest test/test_carrier.py test/test_cstore_carrier.py` runs offline and
deterministically and covers every transfer syntax that matters. pydicom also
indexes a larger set hosted in `pydicom/pydicom-data` — multi-frame colour
JPEG, enhanced CT, an ultrasound with a large private block. Those need the
network, so they are opt-in:

```bash
CSCARE_TEST_DOWNLOAD=1 pytest test/test_carrier.py test/test_cstore_carrier.py
```

Point it at your own objects by adding them to `BUNDLED_IMAGES` in
`test/dicom_corpus.py` — the corpus filters out anything the installed pydicom
does not have, so an entry that is not present shrinks the corpus rather than
breaking the suite.

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
