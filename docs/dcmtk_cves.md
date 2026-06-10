# DCMTK CVE coverage map

DCMTK (OFFIS) is C-SCARE's primary parsing/network target — it backs the
grey-box `file` / `parse` / `net-*` fuzz targets and is the reference SCP/SCU
for DAST. This page maps **every known DCMTK CVE** to how C-SCARE exercises it,
and is honest about what is *not* covered and why.

Status legend:

- **catalog** — a hand-built payload in `c_scare/attacks.py` (`metadata['cve']`),
  delivered live (DAST) and written to the AFL/AFLNet seed corpus.
- **config** — a malformed `dcmqrscp` config under `fuzz/configs/malformed/`.
- **pixel-seed** — a grey-box seed from `fuzz/harness/gen_pixel_seeds.py` that
  steers the codec/image pipeline (AFL++ owns the mutation loop).
- **net-track** — reached at runtime by driving the instrumented `dcmqrscp`
  over the AFLNet `net-dcmqrscp` target (C-FIND/C-MOVE/storage), not a static
  file payload.
- **candidate** — applicable in principle but not yet built; reason noted.

## Covered

| CVE | Component / function | Class | How C-SCARE exercises it |
|-----|----------------------|-------|--------------------------|
| CVE-2015-8979 | dcmnet / DUL association fields | buffer overflow | **catalog** `cve_2015_8979_dul_string_overflow` (overlong AE title, oversized PDU length) |
| CVE-2019-1010228 | association handling | OOB write / DoS | **catalog** (sibling of 8979, same method) |
| CVE-2021-41689 | `DU_getStringDOElement` (dcmnet) | buffer overflow | **catalog** (DUL string family, same method) + **net-track** |
| CVE-2020-36855 | `parseQuota` (dcmqrscp config) | stack overflow | **config** `cve_2020_36855_*` |
| CVE-2022-4981 | `readPeerList` (dcmqrscp config) | NULL deref | **config** `cve_2022_4981_*` |
| CVE-2022-2119 | storescp/dcmrecv file naming | path traversal (SCP) | **catalog** `PathTraversalAttacks` |
| CVE-2022-2120 | movescu/getscu file naming | path traversal (SCU) | **catalog** (same payloads via `RawSCP`) |
| CVE-2022-2121 | dcmdata file parsing | NULL deref | **catalog** `cve_2022_2121_null_deref` |
| CVE-2024-34508 | dcmdata (invalid DIMSE) | segfault | **catalog** (sibling of 34509) |
| CVE-2024-34509 | dcmdata (invalid DIMSE) | segfault | **catalog** (Logic / DIMSE) |
| CVE-2024-47796 | `determineMinMax` (dcmimgle) | OOB write | **catalog** `cve_2024_47796_determine_minmax_oob` |
| CVE-2025-14607 | `DcmByteString::makeDicomByteString` | memory corruption | **catalog** `cve_2025_14607_bytestring_corruption` |
| CVE-2026-5663 | storescp `--exec-on-reception` | OS command injection | **catalog** `CommandInjectionAttacks` |
| CVE-2026-10528 | `DcmItem::read` (Orthanc/DCMTK) | stack overflow | **catalog** `cve_2026_10528_dcmitem_read_stack` (structural trigger) |
| CVE-2025-9732 | `diybrpxt.h` (YBR pixel) | memory corruption | **pixel-seed** `pixel_ybr_full_planar1_undersize` |
| CVE-2025-25474 | `diinpxt.h` (dcmimgle input pixel) | buffer overflow | **pixel-seed** `pixel_diinpxt_bits_mismatch` |
| CVE-2025-25475 | `dcrleccd.cc` (RLE decoder) | NULL deref | **pixel-seed** `pixel_rle_bad_header` |
| CVE-2025-2357 | `dcmjpls` (JPEG-LS decoder) | memory corruption | **pixel-seed** `pixel_jpegls_truncated` |

## Reached via the runtime net-track (not static payloads)

These live in `dcmqrdb` server logic and are reached by driving the
instrumented `dcmqrscp` over the AFLNet `net-dcmqrscp` target with
query/retrieve/storage traffic — there is no single malformed file that
reproduces them.

| CVE | Component / function | Class | Notes |
|-----|----------------------|-------|-------|
| CVE-2021-41687 | dcmqrdb (memory free) | improper free / DoS | C-FIND/C-MOVE to dcmqrscp |
| CVE-2021-41688 | dcmqrdb (memory free) | improper free / DoS | C-FIND/C-MOVE to dcmqrscp |
| CVE-2021-41690 | dcmqrdb (memory free) | improper free / DoS | C-FIND/C-MOVE to dcmqrscp |
| CVE-2025-14841 | `startFindRequest` / `startMoveRequest` | memory corruption | C-FIND/C-MOVE to dcmqrscp |
| CVE-2026-10194 | `deleteOldestImages` (quota cleanup) | memory corruption | storage that triggers quota eviction |

## Candidates (applicable, not yet built)

| CVE | Component / function | Class | Why not yet covered |
|-----|----------------------|-------|---------------------|
| CVE-2024-28130 | `DVPSSoftcopyVOI_PList::createFromImage` (dcmpstat) | type confusion → RCE | Needs a softcopy-presentation-state IOD seed (distinct object); candidate presentation-state seed |
| CVE-2024-27628 | `EctEnhancedCT` method | buffer overflow | Needs an Enhanced CT multi-frame IOD seed; candidate enhanced-object seed |
| CVE-2024-52333 | image handling | buffer overflow | Low public detail (Debian-tracked); candidate pixel seed once the path is confirmed |
| CVE-2025-25472 | dcmtk (DEV) | (under analysis) | Insufficient public detail to build a faithful trigger |

## Notes on fidelity

Several catalog entries are **structural triggers / regression seeds**, not
deterministic exploits: `cve_2026_10528_dcmitem_read_stack` (deep recursion
into `DcmItem::read`) and the use-after-free entries cannot guarantee a crash
from a single static buffer — they steer the parser into the vulnerable code
path so a live target or the grey-box mutator can finish the job. This is the
same honesty convention used throughout `attacks.py` (`metadata['cve']` for a
targeted probe vs `metadata['cve_related']` for an inspired-by bug class).

This map is best-effort as of 2026-06 and tracks the OFFIS DCMTK product CVE
list; new DCMTK CVEs should be added here with their delivery vector and
status when they land.
