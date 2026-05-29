# DICOM 201 — CTF Lab Build Plan

> **Status:** design / gap-analysis. No lab code exists yet. This document is the
> contract we build against; it is intentionally opinionated so the SCP design is
> locked before we write a server.
>
> **Vibe:** a repeatable, opinionated attack walkthrough (HTB-style) across seven
> tiers — recon → AE/credential brute → sculpted query → PHI query → object
> retrieval → C-MOVE pivot → C-STORE write. Flags are placed in the exact field
> each tier's technique teaches you to read.
>
> **Flag format:** `flag{tier_N_descriptive_slug}` (UUID-shaped also acceptable
> where lab infra prefers it).

---

## 1. The core mismatch (read this first)

C-SCARE today is an **attacker-side breaker**: it *crafts* malformed DICOM and
*fuzzes/DASTs* a target. The DICOM 201 lab needs two things C-SCARE is not yet:

1. **A flag-bearing SCP/PACS** (the *target*). The lab's flags live in **server
   responses and a server-held archive**. C-SCARE's only server, `RawSCP`
   (`c_scare/server.py`), is a *callback byte-control rogue server for fuzzing
   clients* — not a PACS with an archive or a query engine.
2. **Operational SCU helpers** (the *walkthrough tooling*). The packet classes
   for every DIMSE verb exist in `c_scare/scapy_dicom.py`, but `DICOMSocket`
   only exposes `associate()`, `c_echo()`, `c_store()`, `release()`. There is
   **no `c_find()`/`c_get()`/`c_move()`**, `associate()` does **not** attach a
   User Identity (0x58) sub-item, and there is no AE-title brute loop or
   fingerprint reader.

Everything below is sequenced around closing those two gaps. The good news:
the wire-format layer is essentially complete, so most work is *plumbing and
server logic*, not protocol implementation.

### What we reuse vs. build

| Need | Reuse (exists today) | Build |
|------|----------------------|-------|
| A-ASSOCIATE RQ/AC/RJ, 0x52/0x55/0x58/0x59 sub-items | ✅ `scapy_dicom.py` packet classes | per-AET AC negotiation logic |
| All DIMSE-C/N verbs as packets | ✅ `C_FIND_RQ`…`C_MOVE_RSP`, `N_*` | send/receive *flows* on the socket |
| Outbound association + C-STORE | ✅ `DICOMSocket.associate()/c_store()` | reuse for C-MOVE sub-ops + C-GET sub-ops |
| File/pixel/private-tag crafting for planted flags | ✅ `Corruptor`, `pixel.py`, `file.py`, `element.py` | flag-planting generator |
| Malformed C-STORE objects (length lies, bad VR) | ✅ `Corruptor`, `attacks.py` | Tier 7 instrumented status path |
| Rogue server scaffolding (TCP, state machine, callbacks) | ✅ `RawSCP` | grow into `CtfSCP` |
| Archive / query semantics / pagination | ❌ | C-FIND/C-GET/C-MOVE responder |
| User Identity auth check | ❌ (packets only) | credential table + 0x59 payload |
| AE-title brute, fingerprint reader, dicom-ping | ❌ | SCU operator helpers |
| MWL / Modality Worklist | ❌ (no SOP constants, no builders) | stretch goal only |

---

## 2. Architecture decision: how to build the SCP

The flags force **wire-level control** at the association layer (custom 0x55,
custom 0x59, malformed C-STORE-RSP status). A stock PACS (Orthanc, dcmqrscp)
**cannot** advertise a per-AET Implementation Version Name flag, return a custom
User-Identity server response, or emit a hand-crafted status field — those are
exactly the CTF hooks. So a stock PACS alone is disqualified.

**Decision: build `CtfSCP` on top of `RawSCP`, native to the C-SCARE stack.**

Rationale:
- Tiers **1, 2a, 2b, 7** are association/response-layer tricks → `RawSCP`'s byte
  control is the *right* tool and already crafts `A_ASSOCIATE_AC` with
  0x52/0x55/0x59 sub-items.
- Tiers **3, 4, 5, 6** need an archive + query responder. We do **not** need a
  real 3,142-study database — we synthesize C-FIND-RSP streams programmatically
  from a small planted dataset plus generated filler, and reuse
  `DICOMSocket.c_store()` to perform C-GET/C-MOVE sub-operations (open an
  outbound association and push objects). All primitives for this already exist.
- Keeping one stack means one wire-control surface, one place to plant flags,
  and no impedance mismatch between a proxy and a backing PACS.

**Rejected alternative — hybrid front-proxy over Orthanc:** realistic archive
semantics, but you lose control of 0x55/0x59/status (the flag carriers) and gain
a proxy-association-forwarding problem. Kept on the bench as an optional
"realism mode" for Tiers 3–6 only if synthesized C-FIND responses feel too
artificial in playtest.

`CtfSCP` will need, beyond today's `RawSCP`:
- A presentation-context **acceptor** (negotiate proposed contexts, return an AC
  with accepted/rejected results — today's `RawSCP` hands back raw bytes only).
- A **DIMSE dispatch loop** (reassemble P-DATA-TF PDVs → command + dataset,
  route by command field, emit responses). The parsing half largely exists in
  `scapy_dicom.py`; the server-side routing is new.
- A small **archive model** (in-memory list of planted + generated studies with
  queryable attributes).
- An **outbound sub-operation** path for C-GET/C-MOVE (reuse `DICOMSocket`).

---

## 3. SCU operator-tooling roadmap

These are the `findscu`/`getscu`/`movescu`/`dicom-brute`/`dicom-ping`
equivalents the walkthrough hands the operator. All build on existing packet
classes + `DICOMSocket`.

| Helper | Adds to | Unblocks | Difficulty |
|--------|---------|----------|------------|
| `fingerprint()` — associate, parse & report 0x52/0x55/max-PDU from the AC | `DICOMSocket` / new CLI verb | Tier 1 | low |
| User Identity in `associate(user_identity=…)` + read 0x59 from AC | `DICOMSocket.associate()` | Tier 2b | low |
| `ae_brute(wordlist)` — loop Called AE Titles, classify accept/reject, parse AC payload | new CLI verb | Tier 2a | low–med |
| `c_find(query_ds, level)` — send RQ, collect Pending→Success RSPs, return datasets | `DICOMSocket` | Tiers 3, 4 | med |
| `c_get(query_ds)` — RQ + receive inbound C-STORE sub-ops on same assoc, collect objects | `DICOMSocket` | Tier 5 | med |
| `c_move(query_ds, dest_ae)` — RQ with `move_destination`, track sub-op status | `DICOMSocket` | Tier 6 | med |
| return-key-set builder (sculpted queries) | `element.py` helper | Tiers 3, 4 | low |

Note the **Scapy-vs-Nmap difficulty knob** the lab is meant to teach: Tiers 1,
2a, 3 should be solvable with **Nmap + dcmtk** (`findscu`, `getscu`) by an
operator who *doesn't* use C-SCARE — these helpers are conveniences, not
requirements. Tiers **2b, 6, 7** should *require* hand-crafted PDUs (C-SCARE /
Scapy or equivalent). Design each tier so the "easy path" exists for the early
tiers and genuinely doesn't for the hard ones.

---

## 4. Tier-by-tier build plan

Each tier lists: **flag**, **where it lives**, **what to build (server)**,
**what to build (operator)**, **intended solve path**.

### Tier 1 — Recon (A-ASSOCIATE-AC fingerprinting)
- **Flag:** `flag{ctgan_369}`, embedded in the **Implementation Version Name
  (0x55)** of the AC — e.g. `OFFIS_DCMTK_369_flag{ctgan_369}`. Optionally also
  stuff the flag into the Implementation Class UID's free-form arc:
  `1.2.276.0.7230010.3.<flag-bytes-as-OID>`.
- **Server:** `CtfSCP` advertises the custom 0x55 in its AC for the default AET.
  (Trivial — `DICOMImplementationVersionName` packet already crafts this.)
- **Operator:** `fingerprint()` helper; also solvable via `nmap -sC`
  / Wireshark on the PDU.
- **Solve path:** associate, read the AC's 0x55. Teaches *parse the AC, don't
  just ping*. Nmap-doable.

### Tier 2a — AE Title brute
- **Flag:** `flag{stale_aet_revealed}` in the 0x55 of **one specific AET's** AC
  (e.g. `RADIOLOGY_BACKUP_2017`). Most AETs return generic ACs.
- **Server:** `CtfSCP` keyed on Called AE Title → returns a different AC per
  AET; one AET carries the flag.
- **Operator:** `ae_brute(wordlist)` — must *associate* and *parse the AC*, not
  just enumerate accept/reject.
- **Solve path:** brute Called AE Titles, read the winning AC payload.
  Nmap/dcmtk-doable. **Flag-chain:** this flag embeds the valid AET needed
  downstream.

### Tier 2b — User Identity credential brute (0x58 / 0x59)
- **Flag:** `flag{0x58_passed_2026}` returned in the **User Identity server
  response (0x59)** payload (PS3.7 §D.3.3.7.4 allows ≤510 bytes) on *successful*
  auth. Empty response otherwise.
- **Server:** `CtfSCP` requires User Identity Negotiation (username+passcode);
  on correct credential, populate 0x59 with the flag bytes.
- **Operator:** `associate(user_identity=…)` must attach a 0x58 sub-item and
  read 0x59. **Requires hand-crafted PDU** — neither Tier 1 nor 2a sends 0x58,
  so the flag is uniquely a 2b artifact.
- **Solve path:** Scapy/C-SCARE required. **Flag-chain:** flag embeds the
  credential set needed for Tier 3's query context.

### Tier 3 — Sculpted C-FIND (population, no PHI)
- **Flag:** `flag{sculpted_cfind_no_phi}` in a **non-PHI** field of one planted
  study (Study Description / Study ID / private tag). **Better variant:** make
  the flag the **count** — exactly `3142` studies, flag `flag{study_count_3142}`,
  submitted from response enumeration (teaches pagination + Pending/Success).
- **Server:** archive model with planted study + generated filler to hit the
  count; C-FIND responder honoring the **return-key set** (only returns
  StudyDescription when asked).
- **Operator:** `c_find()` + return-key-set builder.
- **Solve path:** sculpt `StudyDescription=""` into return keys. A naive
  `PatientName=""` query won't surface it; a "give me everything" query would —
  but that pulls PHI (Tier 4) and trips the tier's stop sign. Teaches *ask for
  exactly what you want*. Nmap/dcmtk `findscu`-doable.

### Tier 4 — PHI-bearing C-FIND
- **Flag:** PHI-shaped — `PatientName = FLAG^TIER4^CTF`,
  `PatientID = flag{phi_returned_via_cfind}` on one synthetic patient.
- **Server:** plant the synthetic patient in the archive.
- **Operator:** `c_find()` with `PatientName=""` in return keys.
- **Solve path:** the tier boundary is enforced by technique — a Tier 3 sculpted
  query that omits PatientName won't return it. Makes the legal-posture lesson
  (handle like real PHI: store, report, document, dispose) tangible.

### Tier 5 — C-GET object retrieval
- **Flag(s):** **Best variant — two flags:** `flag{tier5_metadata}` in a private
  tag (own a creator group: `(0099,0010)="FLAG_LAB"`, `(0099,1001)=flag`) **and**
  `flag{tier5_pixels}` burned into the rendered pixel data as visible text. Full
  credit only when both are extracted — teaches the metadata/pixel duality.
- **Server:** plant a DICOM object (use `Corruptor`/`element.py` for the private
  tag, `pixel.py` for burned-in text); C-GET responder performs inbound C-STORE
  sub-operations to deliver it.
- **Operator:** `c_get()` (receives sub-op C-STOREs on the same association),
  then parse metadata + view pixels.
- **Solve path:** retrieve + parse both layers. dcmtk `getscu`-doable for the
  fetch; pixel flag forces actually rendering the slice.

### Tier 6 — C-MOVE pivot (SSRF-adjacent) — **hardest infra**
- **Flag:** in the metadata of an object delivered to a **third-party AE**, not
  to the operator's own AE. Operator never sees it on their DIMSE channel.
- **Server:** **three-node lab** — operator client, the PACS (`CtfSCP`), and a
  trusted `RESEARCH_VIEWER` AE. Operator sends C-MOVE-RQ with
  `move_destination=RESEARCH_VIEWER`; PACS opens an **outbound** association to
  RESEARCH_VIEWER and C-STOREs the planted object. RESEARCH_VIEWER is a lab
  service that **displays what it receives via a web endpoint** the operator can
  reach.
- **Build:** PACS outbound sub-op path (reuse `DICOMSocket.associate()+c_store()`)
  + a minimal RESEARCH_VIEWER store-and-render web service. This is the most
  net-new infrastructure.
- **Operator:** `c_move(dest_ae=RESEARCH_VIEWER)` then retrieve via the web
  side-channel. **Requires hand-crafted PDU** + side-channel reasoning.
- **Solve path:** *you cause the bytes to move; you're not the one receiving
  them.* Maps C-MOVE's real SSRF-adjacent primitive.

### Tier 7 — C-STORE upload (write op)
- **Flag:** `flag{cstore_malformed_accepted}` decoded from the **C-STORE-RSP
  Status field** — returned only when a *specific malformed object* is uploaded
  (e.g. Pixel Data length field ≠ actual length, a real parser failure mode);
  the object lands in the archive anyway. **Better variant:** flag is a *side
  effect* — operator uploads a **polyglot DICOM/HTML** file; the lab's downstream
  viewer renders the HTML and the flag is in the rendered output (file-format-as-
  attack-surface, end-to-end).
- **Server:** `CtfSCP` accepts C-STORE for CT Image Storage; an instrumented
  error path detects the malformed structure and returns the flag-encoded status
  (and/or a viewer that renders the polyglot).
- **Operator:** `Corruptor` to build the malformed/polyglot object +
  `c_store()`. **Requires hand-crafted PDU.**
- **Solve path:** Scapy/C-SCARE required — a compliant client can't emit the
  malformed length.

---

## 5. Cross-tier design — flag-chain unlocks

Make each tier's flag carry something needed for the next, so operators must
*parse and use* flags rather than just collect them:

- **Tier 1** 0x55 flag → hint about which **SOP class** Tier 3 must sculpt for.
- **Tier 2a** flag → embeds the valid **AET** used in later associations.
- **Tier 2b** flag → embeds **credentials** needed for the Tier 3 query context.

Implementation: a small `flag_chain` map in the lab config so placements stay
consistent and we can validate the chain end-to-end in a smoke test.

---

## 6. Difficulty knob (which tiers require Scapy)

| Tier | Nmap + dcmtk solvable? | Requires hand-crafted PDU |
|------|------------------------|---------------------------|
| 1 Recon | ✅ (`nmap -sC`, Wireshark) | no |
| 2a AE brute | ✅ (`findscu`/assoc loop) | no |
| 2b User Identity | ❌ | **yes** |
| 3 Sculpted C-FIND | ✅ (`findscu`) | no |
| 4 PHI C-FIND | ✅ (`findscu`) | no |
| 5 C-GET | ✅ (`getscu`) | no |
| 6 C-MOVE pivot | partial (`movescu`) + side-channel | **yes** |
| 7 C-STORE malformed | ❌ | **yes** |

This maps the lab's curve to the "where Nmap ends and Scapy begins" boundary.
Validate during playtest that the easy tiers really are dcmtk-doable and the
hard tiers really aren't.

---

## 7. Phasing & milestones

**Phase 0 — SCU helpers (no server yet).** Land `fingerprint()`, User Identity
in `associate()`, `c_find()`, `c_get()`, `c_move()`, `ae_brute()`. Test against
a real PACS (Orthanc/dcmqrscp in a container) so the client side is proven
before the lab exists. *Low risk, immediately useful, unblocks everything.*

**Phase 1 — `CtfSCP` association layer + Tiers 1, 2a, 2b.** Grow `RawSCP` into
`CtfSCP` with a presentation-context acceptor and per-AET AC negotiation +
User Identity check. These three tiers need no archive. *First playable slice.*

**Phase 2 — Archive + query responder + Tiers 3, 4, 5.** In-memory archive,
C-FIND responder honoring return-key sets, C-GET sub-op delivery, flag-planting
generator (metadata + burned-in pixels).

**Phase 3 — Tier 6 (three-node pivot) + Tier 7 (C-STORE write).** Outbound
sub-op path + RESEARCH_VIEWER web service; instrumented C-STORE status / polyglot
viewer.

**Phase 4 — Flag-chain wiring, end-to-end smoke test, walkthrough writeup,
containerized lab (compose).**

**MVP option (if we want a fast first release):** ship Tiers **1, 3, 7** only —
one association-layer tier, one query tier, one write tier — deferring User
Identity, C-MOVE pivot, and the archive's full fidelity.

---

## 8. Stretch / out of scope (for now)

- **MWL (Modality Worklist) / RIS-gateway injection.** No SOP-class constants or
  query builders exist; belongs only if we add a worklist-injection workflow.
  N-verb packets exist as raw material.
- **ACSE deep UIN walkthrough.** A-ASSOCIATE RQ/AC/RJ + a `ConnectionState`
  Sta1–13 model exist; a dedicated ACSE-negotiation deep-dive is a separate
  module.

---

## 9. Open decisions (need a call before/within Phase 1–2)

1. **Synthesized vs. real archive for Tiers 3–6.** Plan assumes synthesized
   C-FIND responses + sub-op C-STORE from `CtfSCP`. If playtest finds this
   artificial, fall back to the Orthanc "realism mode" for those tiers (at the
   cost of the wire-level control the other tiers need elsewhere).
2. **Flag format:** `flag{...}` everywhere vs. UUID-shaped for the tiers where
   the flag is a count/status. Plan currently uses `flag{...}`.
3. **Tier 3 variant:** descriptive-slug flag vs. the `study_count_3142` count
   variant. Plan recommends the **count variant** (richer lesson: pagination +
   status transitions).
4. **Tier 5 / Tier 7 variants:** plan recommends the **two-flag** (Tier 5) and
   **polyglot** (Tier 7) "best" variants — confirm appetite for building the
   downstream viewer they require.
5. **Lab packaging:** docker-compose three-node topology vs. single-process
   multi-listener. Pivot tier (6) is cleaner as separate containers.
