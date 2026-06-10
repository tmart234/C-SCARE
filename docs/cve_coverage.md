# DICOM CVE coverage map

The single map of every CVE C-SCARE tests against, across the DICOM stacks it
targets: **DCMTK** (OFFIS), **GDCM** (Grassroots DICOM, embedded in many
viewers/PACS), **Orthanc**, **pydicom**, and **dcm4che** (the standard-level
polyglot CVE all Part-10 implementers share). Each CVE maps to the C-SCARE
delivery vector that exercises it.

Status legend:

- **catalog** — a hand-built payload in `c_scare/attacks.py` (`metadata['cve']`),
  delivered live for DAST and written to the AFL/AFLNet seed corpus.
- **pixel-seed** — a grey-box seed from `fuzz/harness/gen_pixel_seeds.py` that
  steers the codec/image pipeline.
- **file-seed** — a grey-box seed from `fuzz/harness/gen_file_seeds.py`.
- **config** — a malformed `dcmqrscp` config under `fuzz/configs/malformed/`.
- **net-track** — reached at runtime by driving the instrumented `dcmqrscp`
  over the AFLNet `net-dcmqrscp` target, not a static file payload.

CVE relationship is tagged honestly in each payload's `metadata`:
`metadata['cve']` is a targeted reproduction/probe; `metadata['cve_related']`
(with `metadata['bug_class']`) is a generic bug-class payload *inspired by* a
CVE. Some entries are **structural triggers / regression seeds** (noted below):
a single static buffer cannot itself drive a heap use-after-free or guarantee a
stack smash, so they steer a parser into the vulnerable code path for a live
target or the grey-box mutator to finish.

## DCMTK (OFFIS)

DCMTK backs the grey-box `file` / `parse` / `net-*` fuzz targets and is the
reference SCP/SCU for DAST.

| CVE | Component / function | Class | Vector |
|-----|----------------------|-------|--------|
| CVE-2015-8979 | dcmnet / DUL association fields | buffer overflow | **catalog** `cve_2015_8979_dul_string_overflow` (overlong AE title, oversized PDU) |
| CVE-2019-1010228 | association handling | OOB write / DoS | **catalog** (sibling of 8979) |
| CVE-2021-41689 | `DU_getStringDOElement` (dcmnet) | buffer overflow | **catalog** (DUL string family) + **net-track** |
| CVE-2022-2119 | storescp/dcmrecv file naming | path traversal (SCP) | **catalog** `PathTraversalAttacks` |
| CVE-2022-2120 | movescu/getscu file naming | path traversal (SCU) | **catalog** (same payloads via `RawSCP`) |
| CVE-2022-2121 | dcmdata file parsing | NULL deref | **catalog** `cve_2022_2121_null_deref` |
| CVE-2024-28130 | `DVPSSoftcopyVOI_PList::createFromImage` (dcmpstat) | type confusion → RCE | **catalog** `cve_2024_28130_dcmtk_voi_lut_type_confusion` ((0028,3010) emitted as non-SQ VR) |
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

DCMTK server-logic CVEs reached at runtime over the AFLNet `net-dcmqrscp`
target (query/retrieve/storage traffic, no single malformed file):

| CVE | Component / function | Class | Vector |
|-----|----------------------|-------|--------|
| CVE-2021-41687 | dcmqrdb (memory free) | improper free / DoS | **net-track** C-FIND/C-MOVE |
| CVE-2021-41688 | dcmqrdb (memory free) | improper free / DoS | **net-track** C-FIND/C-MOVE |
| CVE-2021-41690 | dcmqrdb (memory free) | improper free / DoS | **net-track** C-FIND/C-MOVE |
| CVE-2025-14841 | `startFindRequest` / `startMoveRequest` | memory corruption | **net-track** C-FIND/C-MOVE |
| CVE-2026-10194 | `deleteOldestImages` (quota cleanup) | memory corruption | **net-track** storage → quota eviction |
| CVE-2020-36855 | `parseQuota` (dcmqrscp config) | stack overflow | **config** `cve_2020_36855_*` |
| CVE-2022-4981 | `readPeerList` (dcmqrscp config) | NULL deref | **config** `cve_2022_4981_*` |

## GDCM (Grassroots DICOM)

GDCM underpins a long tail of viewers/PACS, so each crafted-`.dcm` payload is a
faithful GDCM reproduction *and* a probe for the same codec/length bug class in
software that embeds it (MicroDicom, Sante, MedDream — whose vendors publish no
element-level root cause; tagged via `metadata['related_cve']`).

| CVE | Component / function | Class | Vector |
|-----|----------------------|-------|--------|
| CVE-2015-8396 | `ImageRegionReader::ReadIntoBuffer` | integer overflow | **catalog** `cve_2015_8396_gdcm_imageregionreader_int_overflow` (geometry product wraps 32-bit) |
| CVE-2024-22373 | `JPEG2000Codec::DecodeByStreamsCommon` | OOB write | **catalog** `cve_2024_22373_gdcm_jpeg2000_oob` (SIZ dims > header Rows/Columns) |
| CVE-2024-22391 | `LookupTable::SetLUT` | heap overflow | **catalog** `cve_2024_22391_gdcm_lut_setlut` (Palette LUT Descriptor vs Data mismatch) |
| CVE-2024-25569 | `RAWCodec::DecodeBytes` | OOB read | **catalog** `cve_2024_25569_gdcm_rawcodec_oob` (geometry exceeds Pixel Data) |
| CVE-2025-48429 | `RLECodec::DecodeByStreams` | OOB read | **catalog** `cve_2025_48429_gdcm_rle_numsegments` (RLE header NumberOfSegments > 15) |
| CVE-2025-52582 | `Overlay::GrabOverlayFromPixelData` | OOB read | **catalog** `cve_2025_52582_gdcm_overlay_oob` (overlay dims exceed Pixel Data) |
| CVE-2025-11266 | encapsulated fragment / BOT handling | OOB write (integer underflow) | **catalog** `cve_2025_11266_gdcm_encapsulated_fragment_underflow` |
| CVE-2026-3650 | file-meta non-standard VR | memory-leak DoS | **catalog** `cve_2026_3650_gdcm_vr_memory_leak` |

## Orthanc

The crafted-DICOM members of the CERT/CC VU#536588 batch (CVE-2026-5437..5445,
fixed in 1.12.11), delivered live against an Orthanc SCP and seeded for the
grey-box parse track.

| CVE | Component / function | Class | Vector |
|-----|----------------------|-------|--------|
| CVE-2026-5437 | `DicomStreamReader` meta-header | OOB read | **catalog** `cve_2026_5437_meta_header_oob` |
| CVE-2026-5441 | `DicomImageDecoder::DecodePsmctRle1` (Philips PMSCT_RLE1) | OOB read | **catalog** `cve_2026_5441_5445_orthanc_image_decoder` (structural trigger) |
| CVE-2026-5442 | image decoder frame-size calc | integer overflow / heap overflow | **catalog** (Rows/Columns as VR UL not US) |
| CVE-2026-5443 | PALETTE COLOR processing | integer overflow → heap overflow | **catalog** (width×height 32-bit multiply wraps) |
| CVE-2026-5444 | embedded PAM image parsing | integer overflow → heap overflow | **catalog** (PAM WIDTH/HEIGHT overflow) |
| CVE-2026-5445 | `DicomImageDecoder::DecodeLookupTable` | OOB read | **catalog** (palette index past LUT size) |
| CVE-2026-10528 | `DcmItem::read` (Orthanc/DCMTK) | stack overflow | **catalog** `cve_2026_10528_dcmitem_read_stack` (structural trigger) |

## pydicom

| CVE | Component / function | Class | Vector |
|-----|----------------------|-------|--------|
| CVE-2026-32711 | `FileSet` / DICOMDIR (`RecordNode._file_id`) | path traversal (CWE-22) | **catalog** `cve_2026_32711_dicomdir_traversal` (Referenced File ID (0004,1500) escapes the File-set root) |

CVE-2026-32711 is the only published CVE across the pydicom ecosystem
(`pydicom`, `pynetdicom`, `pylibjpeg*`, `deid`); it is covered. The
library-agnostic Parser / Protocol / Memory / Logic catalog also delivers
against a `pynetdicom` SCP under DAST.

## dcm4che (and all Part-10 implementers)

| CVE | Component / function | Class | Vector |
|-----|----------------------|-------|--------|
| CVE-2019-11687 | DICOM Part-10 128-byte preamble | executable polyglot (CWE-20) | **catalog** `cve_2019_11687_polyglot` (PE/ELF/shell/batch/TIFF) + **file-seed** polyglot family |

CVE-2019-11687 is a property of the file format, so it applies to dcm4che,
pydicom, and DCMTK alike. The library-agnostic catalog (Parser / Protocol /
Path-Traversal / etc.) also delivers against a `dcm4chee-arc-light` SCP under
DAST.

## Logic / URI

| CVE | Component / function | Class | Vector |
|-----|----------------------|-------|--------|
| CVE-2024-33606 | URI-type VR handling (Retrieve URI) | SSRF / unsafe URI follow | **catalog** `LogicAttacks` (`uri_ssrf`, `file_uri_injection`, `unc_path_injection`, `data_uri_script`) |

## Inspired-by bug classes (`metadata['cve_related']`)

Generic length/overflow/recursion payloads modelled after a CVE's bug class but
not claiming a per-product reproduction. These also carry `metadata['bug_class']`
and double as probes for the viewer CVEs of the same class:

- CVE-2024-22100 — heap overflow → integer-overflow / oversized-value
- CVE-2024-25578 — out-of-bounds write → length-mismatch / oob-offset / lut-bounds
- CVE-2024-28877 — stack overflow → recursion-stack-exhaustion
- MicroDicom CVE-2025-35975 / CVE-2025-36521 and the GDCM-class RAW/LUT bugs —
  exercised by the GDCM dimension/length-mismatch catalog entries above.

## Notes on fidelity

`cve_2026_10528_dcmitem_read_stack`, the use-after-free entries (32135 / 24793 /
24794), and `cve_2026_5441` (PMSCT_RLE1) are **structural triggers / regression
seeds** — they steer the parser into the vulnerable code path rather than
deterministically reproducing the bug from a single static buffer.

This map is best-effort as of 2026-06; new DICOM CVEs should be added here with
their delivery vector and status when they land.
