# Malformed dcmqrscp config samples

Black-box test artifacts for the two DCMTK config-file-parsing CVEs. These
are **not** fuzzer seeds — C-SCARE's grey-box loop fuzzes DICOM file and
network input, not operator-controlled config files. They are hand-built
malformed `dcmqrscp.cfg` files that reproduce each bug's shape so a
`dcmqrscp` build can be probed directly.

`DcmQueryRetrieveConfig` parses the config before any network I/O, so each
crash fires at startup:

```bash
dcmqrscp -c fuzz/configs/malformed/<sample>.cfg 11114
```

Run against an ASan/UBSan-instrumented `dcmqrscp` (see `scripts/build_dcmtk.sh`)
to turn a latent crash into a clear sanitizer report.

| Sample | CVE | Function | Bug |
|--------|-----|----------|-----|
| `cve_2022_4981_undefined_peer.cfg` | CVE-2022-4981 | `readPeerList` | AETable peer list names a symbol absent from HostTable |
| `cve_2022_4981_empty_hosttable.cfg` | CVE-2022-4981 | `readPeerList` | Empty HostTable while the AETable still references a peer |
| `cve_2020_36855_oversized_quota_count.cfg` | CVE-2020-36855 | `parseQuota` | Oversized study-count token in the StorageQuota field |
| `cve_2020_36855_oversized_quota_size.cfg` | CVE-2020-36855 | `parseQuota` | Oversized byte-size token in the StorageQuota field |

Both CVEs require local control of the config file, so they sit outside
C-SCARE's DICOM-input threat model — these samples document the bug class
without adding a config-file fuzz target.
