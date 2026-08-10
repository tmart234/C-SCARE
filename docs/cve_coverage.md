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
| CVE-2019-11687 | DICOM Part-10 preamble + private Data Elements | executable polyglot (CWE-20) | **catalog** `cve_2019_11687_polyglot` (PE32/PE32+/ELF/Mach-O/shell/batch/TIFF across five safe zones, plus a fragmented and two entropy-shaped variants) + **file-seed** polyglot family |

CVE-2019-11687 is a property of the file format, so it applies to dcm4che,
pydicom, and DCMTK alike. The library-agnostic catalog (Parser / Protocol /
Path-Traversal / etc.) also delivers against a `dcm4chee-arc-light` SCP under
DAST.

The catalog varies four things independently. *Which second format* the file
also claims to be decides whether a scanner's magic table fires at all.
*Which safe zone* carries the foreign bytes decides whether the scanner ever
reads them — `metadata['zone']` names the region, and `c_scare.polyglot`
enumerates all five in any Part-10 file:

| Zone | Capacity | Reached by |
|------|----------|------------|
| Preamble DOS header (0x00–0x3F) | 58 bytes after the MZ magic and `e_lfanew` | every reader — it is the first thing on disk |
| Preamble DOS stub (0x40–0x7F) | 64 bytes | nothing: never executed in protected mode, never parsed as DICOM |
| Private (odd-group) `OB` element | 2³²−2 bytes | traversed, not inspected (PS3.5) |
| Padding tail of a Data Element | value-specific | covered by the declared length, past where the value ends |
| Space after the final Data Element | unbounded | never — Part-10 has no end marker, readers stop at the Data Set |

*Whether the payload is contiguous* decides whether a signature written over
a whole image can match it. `cve_2019_11687_11_fragmented_zones` cuts one PE
along its own structural seams and puts the headers in a private element,
section `.vend`'s data in an element's padding tail, and section `.tail`'s
data past the final Data Element, with the patient elements in between.
`PointerToRawData` was never required to point anywhere in particular, so the
loader reassembles the image while no contiguous run of the file contains it.
`metadata['fragments']` maps where each piece landed. The DOS stub is not one
of them, and that is a finding rather than an omission: a PE section must
start on a 512-byte `FileAlignment` boundary at or past `SizeOfHeaders`, and
preamble bytes 0x40–0x7F satisfy neither.

*What the bytes look like statistically* decides whether an entropy or
histogram triage step separates the file from a benign one before anything
parses it. Zero-filled sections are structurally correct and statistically
unmistakable, so `metadata['fill']` selects a content profile —
`polyglot.filler` offers `zeros` (0 bits/byte), `tabular` (~3), `strings`
(~4.9) and `packed` (~7.9). Payloads 14 and 15 are the same construction as
payload 1 with the low and high ends of that range, plus a conventional DOS
stub message in place of 64 NULs.

The three executable formats are built to their own rules rather than by
transposing the PE construction, because they do not relocate the same things:

| Format | Relocates | Pinned at offset 0 | Placement rule for the moved part |
|--------|-----------|--------------------|-----------------------------------|
| PE | headers, section table and all section data | 2-byte `MZ` magic, `e_lfanew` at 0x3C | `PointerToRawData` aligned to `FileAlignment` and at or past `SizeOfHeaders` |
| ELF | program header table and segment contents (`e_phoff`) | the whole 64-byte `Elf64_Ehdr` — there is no `e_lfanew` equivalent | `p_offset ≡ p_vaddr (mod p_align)`: a congruence, not a boundary |
| Mach-O | segment contents only (`fileoff`) | `mach_header_64` **and** all load commands, which must be contiguous behind it | segment `vmaddr`/`vmsize` aligned to the architecture page: 16 KiB on arm64, 4 KiB on x86-64 |

Two consequences are worth stating because they bound what the payloads prove.
A preamble-resident Mach-O gets `128 − 32 = 96` bytes of load-command room —
exactly one section-less `LC_SEGMENT_64` at 72 bytes, since a single
`section_64` adds 80 — so the Mach-O payload carries all the structure the
format permits there and no more. And arm64 macOS requires a valid code
signature before `execve` will touch an image, which cannot be synthesised
inertly; that payload therefore tests whether a scanner *recognises* an
embedded Mach-O, not whether the host would load one.

*What the payload rides on* decides whether an archive ever reads it. Payloads
1–15 build their own minimal Part-10 file, which establishes the structure and
stops there: a Secondary Capture with no Pixel Data, no Study or Series UID and
no image geometry is an incomplete object, so a PACS rejects it against the IOD
before any private element is parsed, and the result says nothing about whether
the archive would accept an executable. `metadata['carrier']` marks the
payloads that ride a complete Secondary Capture built with pydicom — full UID
chain, Image Pixel module, and Pixel Data whose length matches
`Rows × Columns × SamplesPerPixel × BitsAllocated / 8`. The embed lands in the
private group, which sorts ahead of `(7FE0,0010)`, so the object still renders
the image it rendered before and a refusal is attributable to the payload.

Those carriers also fix a conformance problem in the published construction.
Aguilar & Palmer §5.2 report the reference implementation using "group 0x0009,
element 0x0000, with a 12-byte Explicit VR (long form) header", and the V3GAS
slides show `(0009,0010)` for the SLDPLD container. Those are the Group Length
tag and the private creator slot; neither may hold an OB value, and neither is
preceded by a creator claiming a block — which Hetzel et al. §3.2 states a
vendor "must first define" before using private elements. C-SCARE emits a real
private block: an LO creator at `(0009,0010)` claiming block `10xx`, with the
carrier at `(0009,1001)`. A validator can reject the published shape for a
reason unrelated to what it is hiding; it cannot reject this one.

`cve_2019_11687_23_published_group_length_tag` reproduces the published shape
anyway, marked `conformance: non-conformant-by-design`. It is what the released
toolkit emits, pydicom parses it, and a detector tuned only against a proper
private block would miss the tool actually in circulation.

One figure differs deliberately. §5.1 of the paper gives "approximately 46"
usable bytes for the preamble DOS-header zone; `enumerate_safe_zones` reports
58. The 12-byte gap is the legacy block header PS3.10 cites as the reason the
preamble exists — reserving it is conservative, but a PE loader reads only
`e_magic` and `e_lfanew`, so 58 is what the format actually imposes on an
attacker. The zone's `note` records both numbers.

Alongside the executable polyglots, `metadata['container_format']` marks a
second embedding shape from the same talk: a length-prefixed blob —
`[magic 8B][size uint32 LE][body]` — in a private element after the File Meta
group and ahead of the pixel data. The framing is the durable signal, since the
talk states the magic string is regenerated per engagement, so the catalog
ships the same container under the published example magic and under a
different one. A detector keyed on the literal string catches one and misses
the other; a detector keyed on the structure catches both. The body is an inert
marker — this catalog builds detection tests, not loaders, so the shellcode and
the sideloaded-DLL execution chain that the talk pairs with the format are
deliberately absent.

### Which half survives the wire

Measured against a pynetdicom Storage SCP, not assumed. C-STORE carries a Data
Set; the 128-byte preamble is a *file* construct PS3.10 defines outside it, and
so is anything past the final Data Element. Neither is transmitted — the
receiving SCP writes its own zeroed preamble.

The consequence is worth stating plainly: **no executable polyglot survives
C-STORE as a loadable image.** `MZ`, `\x7fELF` and the Mach-O magic all sit at
offset 0, and `e_lfanew` at 0x3C. What does survive is whatever lives inside a
Data Element — the PE headers and section data in a private element, the
container blob, the padding-tail payload — and that arrives intact.

`metadata['survives_cstore']` records which is which, and only the payloads
whose mechanism actually arrives are scored on acceptance. Scoring the rest
over an association would report a finding against an archive that received an
ordinary image.

Those carry `delivery_scope: 'whole_file'` — not "undeliverable". **DICOMweb
STOW-RS posts complete Part-10 instances as `application/dicom`, preamble
included**, and that is the pathway Hetzel et al. §3.1 used to load polyglots
into Orthanc. Media, DICOMDIR and import folders carry the whole file too.
C-STORE is the outlier, because it alone sends a Data Set rather than a file.
C-SCARE has no STOW-RS client, so for now deliver those payloads with
`c-scare corpus -o ./out` and post them by whatever DICOMweb path the target
exposes.

| Zone | Reaches the archive over C-STORE |
|------|----------------------------------|
| Private (odd-group) `OB` element | yes — the value is a Data Element |
| Padding tail of a Data Element | yes — inside the declared length |
| Preamble DOS header / DOS stub | no — never transmitted |
| Space after the final Data Element | no — outside the Data Set |
| Fragmented across zones | no — the trailing piece is lost and the object fails to decode |

When a payload whose content *does* arrive is stored, `ProtocolMonitor` reports
`storage:payload_accepted` rather than a clean result. That inversion matters:
for most of the catalog an orderly answer is a pass, but here the archive
complying — keeping attacker-controlled bytes in a region conforming readers
never inspect — is the outcome the test exists to catch.

### Did it survive the pipeline?

Acceptance still cannot separate an archive that *distributes* the artifact
from one that neutralised it on ingest — both answer `0x0000`. `--verify-retrieval`
fetches the instance back with C-GET and compares, which is the S.P.I.C.Y.
Cascading property measured rather than assumed:

| Verdict | Finding | Meaning |
|---------|:-------:|---------|
| `pipeline:survived_intact` | yes | Retrieved copy is still valid in both formats. The archive is a distribution channel for the object. |
| `pipeline:payload_retained` | yes | Private-element bytes came back unchanged; the offset-0 header did not survive this pathway. Expected for C-STORE. |
| `pipeline:altered` | yes | Carrier returned but rewritten — check whether the change neutralises it. |
| `pipeline:stripped` | no | The archive removed the embedded content. The outcome a defender wants. |
| `retrieve:unavailable` | no | Could not fetch it back; the round trip concluded nothing. |

The retrieve is skipped when the store was refused — fetching an instance that
was never accepted would report `stripped` for an object that was never there.

**What this does not measure is execution, deliberately.** These images are
inert by construction — entry point 0, no `PF_X`, no `IMAGE_SCN_MEM_EXECUTE` —
and a polyglot never executes itself in any case. Activation is a separate
link in the chain that lives outside the file and depends on the environment:
Hetzel et al. Fig. 4 executes theirs by invoking it from a terminal, Aguilar &
Palmer §6.1 assume a separate prompting channel, and the SLDPLD format relies
on a sideloaded DLL to extract and run the blob. What lives in the bytes is
whether the artifact is still the artifact after the pipeline handled it, and
that is what these verdicts report.

C-GET rather than C-MOVE because it needs no inbound listener and no AE
registration on the target. The cost is that fewer archives implement it, and
the SCP must grant the Storage SCP role — without it the retrieve comes back
`0xA702 Refused: unable to perform sub-operations`.

The payloads are structurally complete on both sides — `validate_polyglot`
dispatches on the magic at offset 0 and confirms a loader can walk every
header (`validate_pe`, `validate_elf`, `validate_macho`) while pydicom reads
the same bytes as a Secondary Capture — and deliberately inert: read-only
sections carrying data rather than code, no entry point, no `PF_X`, no
`VM_PROT_EXECUTE`. What they test is whether an importer or scanner *looks*,
not whether a payload runs.

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
