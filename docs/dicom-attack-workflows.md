# DICOM Attack Workflows — build plan

> **Status:** design / gap-analysis. Records the workflows we extend C-SCARE
> with and how they slot into the existing role × method matrix.

This plan adds a set of **DICOM attack workflows** to C-SCARE: AE-title brute
force → credential brute force → query → retrieval → pivot → write. Today
C-SCARE has the wire-format layer for all of these (every DIMSE RQ/RSP packet
class exists in `scapy_dicom.py`) but no operational *flows* on top of it.

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

## The decisive capability: read the response, don't just classify

The recurring failure mode these workflows must beat is a shallow scan that
stops at accept/reject. Every workflow's **issuer** is only "done" when it
**parses and surfaces the response payload** to the operator — the AC's
Implementation Version Name and Application Context UID, the 0x59 server
response bytes, the C-FIND identifier datasets (incl. private tags), the
retrieved object's *metadata and pixels*, the sub-operation completion counts,
the C-STORE-RSP status word. Each workflow below carries an explicit **Solve
requirement** stating that decisive capability, and the acceptance scenarios at
the end validate the issuer side end-to-end against a reference walkthrough.

## Current state — what exists vs. what each workflow needs

| Layer | Today | Gap |
|-------|-------|-----|
| RQ/RSP packet classes (all DIMSE-C/N) | ✅ `scapy_dicom.py` | — |
| Association (RQ/AC/RJ), 0x52/0x55/0x58/0x59 sub-items | ✅ packets | per-direction *flow* logic |
| SCU socket: `associate`/`c_echo`/`c_store`/`release` | ✅ `DICOMSocket` | `c_find`/`c_get`/`c_move`, identity in `associate`, AC/RSP parsing helpers |
| Rogue server scaffolding (TCP, state machine, callbacks) | ✅ `RawSCP` | per-verb responders (serve RSP streams, parse RQ) |
| Object metadata parse (incl. private tags) | ✅ pydicom + `element.py` | wire into C-GET output |
| Pixel **rendering** (view burned-in text on a slice) | ⚠️ `pixel.py` parses/crafts; no render-to-image | render/extract step for C-GET |
| Malformed object / PDU crafting | ✅ `Corruptor`, `pixel.py`, `attacks.py`, scapy `fuzz()` | wire each into the new flows |
| Black-box delivery / monitoring / SARIF | ✅ `deliver.py`, `monitor.py` | route new workflows through it |

The shared primitive under W1/W2 is a clean association attempt that **parses
the AC/RJ result** (accept vs. reject, reject reason, and the full AC payload —
0x52/0x55 sub-items and the Application Context UID). That parse helper lands
with W1 and is reused everywhere downstream.

---

## Workflow catalog

Each workflow: **issuer** (SCU role → tests a server), **responder** (SCP role →
tests a client), **Solve requirement**, **abuse/malformation angle**, **build**,
**reuse**.

### W1 — AE Title brute force
- **Issuer:** drive an association attempt for each Called AE Title from a
  wordlist, **classify** the outcome — accepted (parse the returned AC) vs.
  rejected (parse `A_ASSOCIATE_RJ` reason, e.g. *called-AE-title-not-recognized*)
  — and for every accepted AET **extract the AC payload**: Application Context
  UID and Implementation Version Name (0x55). Throttle/concurrency controls so
  the loop is usable against a real server.
- **Solve requirement:** report, per accepted AET, the *contents* of its AC
  (App Context UID + 0x55), not merely "accepted". A brute that only diffs
  accept-vs-reject fails the scenario — the payoff lives in the AC payload that
  differs between a generic AET and a special one.
- **Responder:** present different ACs / reject reasons keyed on the requested
  Called AE Title, to exercise a client's AET-handling and trust logic.
- **Abuse angle:** overlong/null AE titles, AET confusion (already in
  `ProtocolAttacks`).
- **Build:** `ae_brute(wordlist, …)` issuer (association attempt + AC-payload
  extraction + classification loop); AET-keyed responder map on `RawSCP`.
- **Reuse:** `A_ASSOCIATE_*` packets, `DICOMImplementation*`, reject-reason enum,
  `ProtocolAttacks`.

### W2 — User Identity credential brute force (0x58 / 0x59)
- **Issuer:** attach a 0x58 sub-item to `associate(user_identity=…)` and **brute
  a credential list** — iterate username/passcode pairs (type 2), or feed
  Kerberos/SAML/JWT material (types 3–5), classifying each attempt by the 0x59
  server response / accept-vs-reject. Supports credential spray and per-target
  lists.
- **Solve requirement:** on success, **surface the raw 0x59 server-response
  bytes** (up to the 510-byte PS3.7 §D.3.3.7.4 limit) to the operator — that
  payload is the artifact, and it only appears when a valid credential is
  submitted. The workflow must send a real 0x58 sub-item (not just associate)
  and read 0x59 (not just observe accept/reject).
- **Responder:** require identity negotiation and emit 0x59 success/failure
  responses (incl. oversized payloads) to exercise a client's parsing.
- **Abuse angle:** malformed/oversized primary/secondary fields, mismatched
  `positive_response_requested`, 0x59 payload overflow.
- **Build:** `user_identity=` param + 0x59 reader on `DICOMSocket.associate()`,
  wrapped in a `cred_brute(creds, …)` loop; identity-check responder on `RawSCP`.
- **Reuse:** `DICOMUserIdentity` / `DICOMUserIdentityResponse` packets, W1
  association/classification primitive.

### W3 — C-FIND query (sculpted, and PHI-bearing)
- **Issuer:** send `C_FIND_RQ` with an operator-controlled **return-key set**,
  collect the Pending→Success `C_FIND_RSP` stream, return parsed identifier
  datasets; handle paging and **count** the responses. Covers both the
  no-PHI/sculpted query (e.g. `StudyDescription=""`, private tags) and the
  PHI-bearing query (`PatientName=""`, `PatientID`).
- **Solve requirement:** (a) the return-key set is precise — requesting exactly
  the keys asked for, including non-PHI fields and **private tags in a private
  creator group**, so a value planted in `StudyDescription` / a private tag is
  returned *only* when that key is in the set; (b) full stream enumeration with
  correct Pending→Success handling so a **response count** is reportable; (c)
  parse PHI-shaped values verbatim. A naive `PatientName=""`-only query must
  *not* surface a `StudyDescription` value — the return-key discipline is the
  capability being validated.
- **Responder:** serve `C_FIND_RSP` streams (incl. malformed: wrong status
  transitions, bad counts, oversized identifiers) to a querying client.
- **Abuse angle:** wrong context id / invalid command field (`ProtocolAttacks`),
  identifier injection (SSRF/URI, format strings), status confusion.
- **Build:** `c_find(query_ds, level)` issuer + return-key-set builder on
  `element.py`; `C_FIND_RSP`-stream responder on `RawSCP`.
- **Reuse:** `C_FIND_RQ/RSP`, `LogicAttacks` (URI/SSRF), `element.py`.

### W4 — C-GET object retrieval
- **Issuer:** send `C_GET_RQ`, receive inbound C-STORE sub-operations on the
  same association, collect the objects, and **extract both layers**: metadata
  (incl. private creator group + private tags) **and** rendered pixel data.
- **Solve requirement:** parse private-tag metadata *and* render the image so
  **burned-in text on the pixel slice is readable** — the metadata/pixel duality
  is the lesson, so a metadata-only parse is an incomplete solve. Rendering is a
  new step (`pixel.py` parses/crafts but does not render); add a
  render/extract-to-image path (pydicom + Pillow, or dcm2pnm).
- **Responder:** drive inbound C-STORE sub-ops at a requesting client with
  malformed/oversized objects (reuse `Corruptor`/`pixel.py`).
- **Abuse angle:** sub-op object malformation, count mismatch.
- **Build:** `c_get(query_ds)` issuer (handles sub-op C-STOREs) + pixel
  render/extract; sub-op sender on `RawSCP`.
- **Reuse:** `C_GET_RQ/RSP`, `c_store` machinery, `Corruptor`, `pixel.py`,
  pydicom metadata parse.

### W5 — C-MOVE pivot (SSRF-adjacent)
- **Issuer:** send `C_MOVE_RQ` with an **operator-chosen `move_destination` AE**
  and track the sub-operation status (remaining / completed / failed). The
  object is delivered to a *third* AE, not back on the operator's DIMSE channel.
- **Solve requirement:** the workflow must let the operator point the move at an
  arbitrary destination AE and confirm the sub-ops **completed** — that is the
  SSRF-adjacent primitive (you cause the bytes to move). Retrieving what landed
  at the destination is explicitly **out-of-band** (the operator reaches the
  destination AE / its side channel themselves); the issuer's job ends at
  "caused the move + confirmed completion." This is the one workflow whose solve
  artifact is *not* on the issuer's own channel, by design.
- **Responder:** as a rogue SCP, *act on* a received C-MOVE by opening an
  outbound association to the named destination (reuse
  `DICOMSocket.associate()+c_store()`) — exercises destination-trust logic and
  proves the pivot.
- **Abuse angle:** arbitrary/internal destination AE (SSRF), destination
  spoofing, sub-op flooding.
- **Build:** `c_move(query_ds, dest_ae)` issuer with sub-op status tracking;
  outbound-sub-op responder on `RawSCP`.
- **Reuse:** `C_MOVE_RQ/RSP`, outbound `DICOMSocket`, `LogicAttacks` SSRF.

### W6 — C-STORE write
- **Issuer:** ✅ closest to ready today — `c_store()` + `Corruptor` already
  upload malformed objects (length lies, bad VR, duplicate tags), polyglots
  (`pixel.py`), command-injection / path-traversal payloads (`attacks.py`).
  Extend to drive the full catalog and **capture the raw `C_STORE_RSP` status
  word**.
- **Solve requirement:** (a) build the *specific* malformed structure (e.g.
  Pixel Data element length ≠ actual length) — `Corruptor` already does this —
  and **surface the response Status field as raw bytes** so an instrumented
  server's status (decodable as ASCII) is visible to the operator, not swallowed
  by a success/failure boolean; (b) build a **polyglot DICOM/HTML** object and
  upload it, so a downstream viewer that renders it can be exercised end-to-end.
- **Responder:** serve crafted `C_STORE_RSP` statuses to a storing client; or,
  as the receiving SCP, exercise downstream handling of malformed/polyglot
  objects.
- **Abuse angle:** parser failure modes (Pixel Data length ≠ actual), polyglot
  DICOM/HTML, command injection / path traversal in UIDs & PatientName
  (CVE-2026-5663 / CVE-2022-2119/2120).
- **Build:** catalog-driven `c_store` wrapper that records raw RSP status;
  polyglot builder; `C_STORE_RSP` responder on `RawSCP`.
- **Reuse:** `c_store`, `Corruptor`, `pixel.py`, `CommandInjectionAttacks`,
  `PathTraversalAttacks`.

---

## Acceptance scenarios (issuer-side validation)

These reference scenarios validate that the **issuer** drivers actually *solve*
a recon→write walkthrough end-to-end against a server. They are the acceptance
tests for Phase 0 — not infrastructure this repo builds. Each row names the
decisive capability that separates a real solve from a shallow scan.

| Scenario | Workflow | Decisive capability the issuer must have |
|----------|----------|------------------------------------------|
| AE brute reveals a special AET | **W1** | Associate under each Called AET and **read its AC payload** (App Context UID + 0x55), not just accept/reject — the answer is in the AC of one specific AET. |
| Credential brute returns a server payload | **W2** | Send a real **0x58** username/passcode sub-item and **surface the 0x59** server-response bytes on success — neither association alone (no 0x58) nor AE brute (no auth) yields it. |
| Sculpted C-FIND, population only | **W3** | Precise **return-key set** (e.g. `StudyDescription=""` / a private tag) so the planted non-PHI value returns *only* when asked; full stream enumeration to report a **response count**. |
| PHI-bearing C-FIND | **W3** | `PatientName=""` / `PatientID` in the return keys; parse PHI-shaped values verbatim. Omitting these keys must *not* return them — tier boundary enforced by technique. |
| C-GET retrieval, metadata + pixels | **W4** | Parse **private-tag metadata** *and* **render the slice** so burned-in pixel text is readable — both layers required. |
| C-MOVE pivot to a third AE | **W5** | Set an arbitrary `move_destination` and confirm sub-ops **completed**; the artifact lands at the destination and is fetched **out-of-band**, not on the issuer's channel. |
| C-STORE malformed / polyglot write | **W6** | Upload a precisely malformed object (Pixel Data length mismatch) and **capture the raw RSP status word**; and/or upload a **DICOM/HTML polyglot** for downstream rendering. |

Note the **issuer-difficulty boundary** these encode: W1/W3/W4 are doable with
Nmap + dcmtk-style clients, whereas **W2, W5, W6** genuinely require
hand-crafted PDUs (C-SCARE / Scapy) — sending a 0x58 sub-item, redirecting a
move, and emitting a malformed C-STORE are exactly the cases a compliant client
won't do for you. The plan must keep that boundary honest.

---

## Stretch / out of scope

- **MWL (Modality Worklist) injection** — no SOP-class constants or query
  builders today; N-verb packets exist as raw material. Add only if a
  worklist-injection workflow is in scope.
- **ACSE deep negotiation walkthrough** — `A_ASSOCIATE_*` + `ConnectionState`
  Sta1–13 model exist; a dedicated module is separate work.

---

## Phasing

**Phase 0 — issuer helpers (SCU role).** Land the association/result-classify
primitive (with AC-payload extraction), then `ae_brute()`, `cred_brute()`
(identity in `associate()` + 0x59 reader), `c_find()` (return-key set + stream
count), `c_get()` (+ pixel render), `c_move()` (+ sub-op status). Prove them
against a real PACS (Orthanc / dcmqrscp container) and against the acceptance
scenarios above. Low risk, immediately useful for black-box DAST against servers.

**Phase 1 — responder helpers (SCP role).** Per-verb responders on `RawSCP`
(serve RSP streams / parse RQ) so each workflow exercises a client too.

**Phase 2 — malformation wiring + reporting.** Route both directions of every
workflow through the existing catalog (`Corruptor`, `attacks.py`, scapy `fuzz()`)
and `monitor.py` → SARIF, so a workflow can run clean (recon) or hostile (fuzz).

## Open decisions

1. **Issuer-only first, or both drivers per workflow from the start?** Plan
   front-loads issuers (Phase 0) since they're the bigger immediate gap.
2. **Sub-op handling depth for W4/W5** — minimal (accept + parse) vs. full sub-op
   state tracking.
3. **Pixel rendering dependency** — Pillow vs. shelling out to dcm2pnm for the
   W4 render-and-read-burned-in-text step.
4. **CLI surface** — one verb per workflow (`c-scare find …`, `c-scare move …`)
   vs. extending the existing `--category` DAST entry point.
5. **Brute-loop ergonomics** — wordlist/cred-list formats, concurrency, and
   rate-limiting shared between W1 and W2.
