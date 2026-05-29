# DICOM Attack Workflows — build plan

> **Status:** design / gap-analysis. Records the workflows we extend C-SCARE
> with and how they slot into the existing role × method matrix.

This plan adds a set of **end-to-end DICOM attack workflows** to C-SCARE:
association fingerprinting → AE enumeration → identity negotiation → query →
retrieval → pivot → write. Today C-SCARE has the wire-format layer for all of
these (every DIMSE RQ/RSP packet class exists in `scapy_dicom.py`) but no
operational *flows* on top of it.

## Design rule: every workflow is role-agnostic (SCP **or** SCU)

A DIMSE operation is symmetric — it has a request side (SCU→SCP) and a response
side (SCP→SCU), and C-SCARE already defines both packets for every verb
(`C_FIND_RQ`/`C_FIND_RSP`, `C_GET_RQ`/`C_GET_RSP`, …). So each workflow ships as
**one module exposing two drivers**, sharing the same packet builders and
malformation hooks:

| Driver | C-SCARE role | What it exercises | Built on |
|--------|--------------|-------------------|----------|
| **issuer** | acts as SCU | a **server** (SCP target) — black-box DAST | `DICOMSocket` |
| **responder** | acts as SCP | a **client** (SCU target) — rogue server | `RawSCP` |

This mirrors the matrix the README already documents (SCP-DAST via
`deliver.py`, SCU-rogue via `RawSCP`). The win is that the malformed-input
catalog (`Corruptor`, scapy `fuzz()`, `attacks.py`) plugs into **both**
directions of every workflow — the same length-lie or out-of-spec field that
probes a server's RQ parser probes a client's RSP parser when served the other
way. Where a workflow only makes sense in one direction, the plan says so.

## Current state — what exists vs. what each workflow needs

| Layer | Today | Gap |
|-------|-------|-----|
| RQ/RSP packet classes (all DIMSE-C/N) | ✅ `scapy_dicom.py` | — |
| Association (RQ/AC/RJ), 0x52/0x55/0x58/0x59 sub-items | ✅ packets | per-direction *flow* logic |
| SCU socket: `associate`/`c_echo`/`c_store`/`release` | ✅ `DICOMSocket` | `c_find`/`c_get`/`c_move`, identity in `associate`, AC parsing helpers |
| Rogue server scaffolding (TCP, state machine, callbacks) | ✅ `RawSCP` | per-verb responders (serve RSP streams, parse RQ) |
| Malformed object / PDU crafting | ✅ `Corruptor`, `pixel.py`, `attacks.py`, scapy `fuzz()` | wire each into the new flows |
| Black-box delivery / monitoring / SARIF | ✅ `deliver.py`, `monitor.py` | route new workflows through it |

---

## Workflow catalog

Each workflow: **issuer** (SCU role → tests a server), **responder** (SCP role →
tests a client), **abuse/malformation angle**, **build**, **reuse**.

### W1 — Association fingerprinting & negotiation
- **Issuer:** associate, parse the AC's Implementation Class UID (0x52),
  Implementation Version Name (0x55), max-PDU, accepted contexts; report them.
- **Responder:** serve crafted ACs (custom 0x52/0x55, odd protocol version,
  context accept/reject patterns) to a connecting client; observe its handling.
- **Abuse angle:** protocol-version/PDU-size edge values, truncated/duplicate
  association, overlong/null AE titles (already in `ProtocolAttacks`).
- **Build:** `fingerprint()` issuer helper + AC-parse helpers on `DICOMSocket`;
  AC-builder responder on `RawSCP`.
- **Reuse:** `A_ASSOCIATE_*`, `DICOMImplementation*`, existing `ProtocolAttacks`.

### W2 — AE Title enumeration
- **Issuer:** loop Called AE Titles from a wordlist; classify accept vs. reject
  (parse `A_ASSOCIATE_RJ` reason) **and** parse the AC payload per accepted AET
  (some servers vary the AC by AET).
- **Responder:** present different ACs keyed on the requested Called AE Title to
  exercise a client's AET-handling / trust logic.
- **Abuse angle:** overlong/null AE titles, AET-confusion.
- **Build:** `ae_enum(wordlist)` issuer; AET-keyed responder map on `RawSCP`.
- **Reuse:** W1 association flow + reject-reason enum.

### W3 — User Identity negotiation (0x58 / 0x59)
- **Issuer:** attach a 0x58 sub-item to `associate(user_identity=…)` (types
  1–5: username/passcode, Kerberos, SAML, JWT) and read the 0x59 server
  response. Enables credential-spray / brute loops.
- **Responder:** require identity negotiation and emit 0x59 success/failure
  responses (incl. oversized ≤510-byte payloads) to exercise a client's
  parsing of the server response.
- **Abuse angle:** malformed/oversized primary/secondary fields, mismatched
  `positive_response_requested`, 0x59 payload overflow.
- **Build:** `user_identity=` param + 0x59 reader on `DICOMSocket.associate()`;
  identity-check responder on `RawSCP`.
- **Reuse:** `DICOMUserIdentity` / `DICOMUserIdentityResponse` packets.

### W4 — C-FIND query
- **Issuer:** send `C_FIND_RQ` with a sculpted **return-key set**, collect the
  Pending→Success `C_FIND_RSP` stream, return parsed datasets; handle paging.
- **Responder:** serve `C_FIND_RSP` streams (incl. malformed: wrong status
  transitions, bad counts, oversized identifiers) to a querying client.
- **Abuse angle:** wrong context id / invalid command field (in
  `ProtocolAttacks`), identifier injection (SSRF/URI, format strings), status
  confusion.
- **Build:** `c_find(query_ds, level)` issuer + return-key-set builder on
  `element.py`; `C_FIND_RSP`-stream responder on `RawSCP`.
- **Reuse:** `C_FIND_RQ/RSP`, `LogicAttacks` (URI/SSRF), `element.py`.

### W5 — C-GET object retrieval
- **Issuer:** send `C_GET_RQ`, receive inbound C-STORE sub-operations on the
  same association, collect + parse objects (metadata and pixel data).
- **Responder:** drive inbound C-STORE sub-ops at a requesting client with
  malformed/oversized objects (reuse `Corruptor`/`pixel.py`).
- **Abuse angle:** sub-op object malformation, count mismatch between
  RSP and delivered objects.
- **Build:** `c_get(query_ds)` issuer (handles sub-op C-STOREs); sub-op sender
  on `RawSCP`.
- **Reuse:** `C_GET_RQ/RSP`, `c_store` machinery, `Corruptor`, `pixel.py`.

### W6 — C-MOVE pivot (SSRF-adjacent)
- **Issuer:** send `C_MOVE_RQ` with an attacker-chosen `move_destination` AE,
  track sub-op status — the SSRF-adjacent primitive (you cause bytes to move to
  a third AE you don't directly receive on).
- **Responder:** as a rogue SCP, *act on* a received C-MOVE by opening an
  outbound association to the named destination (reuse
  `DICOMSocket.associate()+c_store()`) — exercises destination-trust logic and
  proves the pivot.
- **Abuse angle:** arbitrary/internal destination AE (SSRF), destination
  spoofing, sub-op flooding.
- **Build:** `c_move(query_ds, dest_ae)` issuer; outbound-sub-op responder on
  `RawSCP`.
- **Reuse:** `C_MOVE_RQ/RSP`, outbound `DICOMSocket`, `LogicAttacks` SSRF.

### W7 — C-STORE write
- **Issuer:** ✅ closest to ready today — `c_store()` + `Corruptor` already
  upload malformed objects (length lies, bad VR, duplicate tags), polyglots
  (`pixel.py`), command-injection / path-traversal payloads (`attacks.py`).
  Extend to drive the full catalog and capture the `C_STORE_RSP` status.
- **Responder:** serve crafted `C_STORE_RSP` statuses to a storing client; or,
  as the receiving SCP, exercise downstream handling of malformed/polyglot
  objects.
- **Abuse angle:** parser failure modes (Pixel Data length ≠ actual),
  polyglot DICOM/HTML, command injection / path traversal in UIDs & PatientName
  (CVE-2026-5663 / CVE-2022-2119/2120).
- **Build:** thin wrapper to iterate the catalog through `c_store` and record
  statuses; `C_STORE_RSP` responder on `RawSCP`.
- **Reuse:** `c_store`, `Corruptor`, `pixel.py`, `CommandInjectionAttacks`,
  `PathTraversalAttacks`.

---

## Stretch / out of scope

- **MWL (Modality Worklist) injection** — no SOP-class constants or query
  builders today; N-verb packets exist as raw material. Add only if a
  worklist-injection workflow is in scope.
- **ACSE deep negotiation walkthrough** — `A_ASSOCIATE_*` + `ConnectionState`
  Sta1–13 model exist; a dedicated module is separate work.

---

## Phasing

**Phase 0 — issuer helpers (SCU role).** Land `fingerprint()`, identity in
`associate()`, `c_find()`, `c_get()`, `c_move()`, `ae_enum()`. Prove them against
a real PACS (Orthanc / dcmqrscp container). Low risk, immediately useful for
black-box DAST against servers.

**Phase 1 — responder helpers (SCP role).** Per-verb responders on `RawSCP`
(serve RSP streams / parse RQ) so each workflow exercises a client too.

**Phase 2 — malformation wiring + reporting.** Route both directions of every
workflow through the existing catalog (`Corruptor`, `attacks.py`, scapy `fuzz()`)
and `monitor.py` → SARIF, so a workflow can run clean (recon) or hostile (fuzz).

## Open decisions

1. **Issuer-only first, or both drivers per workflow from the start?** Plan
   front-loads issuers (Phase 0) since they're the bigger immediate gap.
2. **Sub-op handling depth for W5/W6** — minimal (accept + parse) vs. full sub-op
   state tracking.
3. **CLI surface** — one verb per workflow (`c-scare find …`, `c-scare move …`)
   vs. extending the existing `--category` DAST entry point.
