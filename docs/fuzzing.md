# Grey-box fuzzing

This is the **grey-box** half of the C-SCARE matrix. The `fuzz/` tree and
`scripts/` shell harnesses run **AFL++** / **AFLNet** — the actual fuzzing
engines — against instrumented DCMTK binaries.

> **C-SCARE does not contain a fuzzing engine.** The mutation loop and
> coverage feedback belong to AFL++ (file targets) and AFLNet (network
> targets). C-SCARE supplies the seed corpus (`c-scare corpus`), the
> dictionary, the harnesses, and crash triage (`c-scare greybox triage`);
> AFL++/AFLNet own the mutation loop and coverage feedback.

## Toolchain setup

The grey-box toolchain needs the git submodules and a DCMTK build:

```bash
git submodule update --init   # AFL++, AFLNet, DCMTK
scripts/build_dcmtk.sh        # build DCMTK (AFL++ afl-clang-fast + AFLNet afl-gcc, ASan)
```

`build_dcmtk.sh` produces two builds, one per fuzzing track:

- `fuzz/build-llvm/` — AFL++ `afl-clang-fast`, LLVM mode (`dcm2pnm` / `dcmdump` / `storescu`)
- `fuzz/build-net/` — AFLNet `afl-gcc` (`storescp` / `dcmrecv` / `dcmqrscp`)

The two AFL forks' instrumentation is not interchangeable, so each track is
compiled with its own fuzzer's toolchain. Each build dir records a
`build_manifest.txt` (DCMTK SHA, compiler version, flags, AFL fork SHAs);
campaign reports (`scripts/campaign.sh`) embed the relevant manifest in
`run.json`.

## Targets

`scripts/campaign.sh <target>` / `c-scare greybox run <target>`:

| Target | Binary | Engine | Quadrant |
|--------|--------|--------|----------|
| `file` | `dcm2pnm` | AFL++ | SCP grey-box — file + pixel pipeline |
| `parse` | `dcmdump` | AFL++ | SCP grey-box — dataset/element parser |
| `net-storescp` | `storescp` | AFLNet | SCP grey-box — network |
| `net-dcmrecv` | `dcmrecv` | AFLNet | SCP grey-box — network |
| `net-dcmqrscp` | `dcmqrscp` | AFLNet | SCP grey-box — network |
| `scu` | `storescu` | AFL++ + desock | SCU grey-box — client response parser (experimental) |

## Running a campaign and triaging crashes

```bash
# Launch a fuzz harness (AFL++/AFLNet own the mutation loop)
c-scare greybox run file              # fuzz dcm2pnm via AFL++
c-scare greybox run net-storescp      # fuzz storescp via AFLNet

# Triage the crashes a campaign produced into a SARIF report
c-scare greybox triage fuzz/out/file \
    --binary fuzz/build-llvm/bin/dcm2pnm --arg @@ --arg /tmp/out.pnm \
    --sarif crashes.sarif

# Add --include-queue to also hunt leak-class bugs: a memory leak is not a
# crash, so its trigger sits in queue/, not crashes/. The triage replay is a
# clean one-shot process, so it forces detect_leaks=1 and LeakSanitizer's
# atexit scan reports the leak (works for file targets — dcm2pnm/dcmdump).
c-scare greybox triage fuzz/out/file \
    --binary fuzz/build-llvm/bin/dcm2pnm --arg @@ --arg /tmp/out.pnm \
    --include-queue --sarif findings.sarif

# Triage AFLNet network crashes. A network input is a DICOM message stream,
# not a file, so --net replays it at a freshly launched instrumented server
# with aflnet-replay and parses the server's own sanitizer output.
c-scare greybox triage fuzz/out/net-storescp --net net-storescp \
    --binary fuzz/build-net/bin/storescp --include-queue --sarif net.sarif
```

## Fuzzing a custom DICOM binary

The harnesses default to DCMTK's stock tools, but the framework targets any
DICOM binary:

- **Black-box** — point `c-scare --ip … --port …` (DAST) or `c-scare rogue`
  at your live service. No build access or instrumentation needed; works
  against a real device, a container, or a vendor-prebuilt binary. See
  [DAST](dast.md).
- **Grey-box** — coverage-guided fuzzing needs the target instrumented. Two
  ways to get that:
  - *Recompiled instrumentation (fast)* — build your binary **and its `.so`
    dependencies** with the AFL compiler wrappers (`$AFLPP_PATH/afl-clang-fast`
    or `afl-gcc`, see `scripts/install_afl.sh`). Fastest fuzzing; requires
    source/build access.
  - *QEMU mode (no recompile)* — `scripts/fuzz_qemu.sh <binary> [args…]` runs
    `afl-fuzz -Q`, instrumenting at runtime. It fuzzes vendor-prebuilt
    binaries — the official DCMTK 3.6.7 release, or your own `.so`-backed
    binaries — with **no recompilation**, ~2-5× slower. Use this when
    rebuilding the target is impractical.
  - *File / parser path*: if your binary has no standalone file mode, copy
    `fuzz/harness/parse_harness.c`, wire in your parse entry point, and fuzz
    it with AFL++.
  - *Network path*: AFLNet's `-P DICOM` parser drives any DICOM listener —
    adapt `scripts/fuzz_net.sh` to your binary's launch command.

## Device parity (READ THIS)

The fuzz build must match the device's DCMTK source rev and build flags or the
results don't reflect device behaviour. By default `scripts/build_dcmtk.sh`
uses the upstream submodule at `fuzz/dcmtk/`. Override these env vars to point
at the device build:

| Env var            | Purpose                                                                          |
|--------------------|----------------------------------------------------------------------------------|
| `DCMTK_SRC_DIR`    | Absolute path to operator-supplied DCMTK source. Submodule and `DCMTK_REF` ignored when set. |
| `DCMTK_REF`        | Git ref/tag/SHA inside the submodule. Default `DCMTK-3.6.7`. Ignored if `DCMTK_SRC_DIR` set. |
| `OPT_LEVEL`        | Compiler optimization (default `-O1`). Set to match the device build.            |
| `EXTRA_CFLAGS`     | Appended to `CFLAGS`/`CXXFLAGS` verbatim — match device defines.                  |
| `EXTRA_CMAKE_ARGS` | Extra `-D...` CMake args (whitespace-separated) — match device DCMTK feature flags. |
| `SANITIZERS`       | Comma list: `address,undefined,memory`. Default `address`.                       |
| `SAND`             | Set `SAND=1` for SAND decoupled sanitization — a native fuzz-loop binary plus one worker per sanitizer. See [SAND mode](#sand-mode-decoupled-sanitization). |

Worked example (matching a hypothetical device build):

```bash
DCMTK_SRC_DIR=/opt/device-src/dcmtk \
  OPT_LEVEL=-O2 \
  EXTRA_CFLAGS="-DCSCARE_DEVICE_PARITY=1" \
  EXTRA_CMAKE_ARGS="-DDCMTK_WITH_OPENSSL=ON -DDCMTK_ENABLE_LFS=lfs64" \
  SANITIZERS=address,undefined \
  scripts/build_dcmtk.sh
```

## SAND mode (decoupled sanitization)

[SAND](https://aflplus.plus/docs/sand/) decouples sanitization from the fuzz
loop: the loop drives a fast **native** binary and only the rare suspicious
inputs reach the **sanitizer worker** binaries. It keeps near-native throughput
while retaining sanitized-fuzzing bug detection, and lets one campaign combine
several sanitizers. SAND is opt-in — set `SAND=1`:

```bash
SAND=1 SANITIZERS=address,undefined scripts/build_dcmtk.sh
```

That builds the AFL++ file track three ways:

| Build dir | Role | Instrumentation |
|-----------|------|-----------------|
| `fuzz/build-llvm/` | native fuzz-loop binary | PCGUARD coverage, no sanitizer |
| `fuzz/build-san-address/` | ASan worker | `AFL_SAN_NO_INST=1` — forkserver only |
| `fuzz/build-san-undefined/` | UBSan worker | `AFL_SAN_NO_INST=1` — forkserver only |

`scripts/fuzz_file.sh` / `fuzz_parse.sh` auto-detect the `fuzz/build-san-*/`
worker trees and pass each to `afl-fuzz -w`; with no worker trees they run the
plain single-binary loop unchanged. The AFLNet network track has no `-w`
support, so it always builds with the sanitizers inline regardless of `SAND`.

Triage **is** the SAND sanitizer-worker stage — it replays crash/queue inputs
through the sanitizer worker(s) to get a verdict. `--sand <binary-name>`
discovers the `fuzz/build-san-*/` workers and triages an input through every
one in a single pass:

```bash
c-scare greybox triage fuzz/out/file --sand dcm2pnm \
    --arg @@ --arg /tmp/out.pnm --include-queue --sarif findings.sarif
```

`--binary <path>` (repeatable) names worker binaries explicitly instead. The
triage replay also forces a full one-shot sanitizer report — `symbolize=1`,
`detect_leaks=1`, and UBSan `print_stacktrace=1` — overriding the
throughput-tuned options a campaign runs with.

AFLNet network targets cannot use a SAND `-w` worker, so they are triaged a
different way: `--net <target>` replays each crash/queue input at a freshly
launched instrumented server with `aflnet-replay` and parses the **server's**
own sanitizer output. A fresh server per input keeps every finding
attributable to one input.

```bash
c-scare greybox triage fuzz/out/net-storescp --net net-storescp \
    --binary fuzz/build-net/bin/storescp --include-queue --sarif net.sarif
```

Crashes triage reliably this way; a leak is reported only if the server runs
its atexit LeakSanitizer scan on the triage shutdown signal, so file targets
stay the dependable path for leak-class bugs.

## Coverage measurement

A separate gcov-instrumented build replays the saturated corpus to produce an
lcov HTML report and per-file summary. Vanilla `gcc --coverage` (no AFL, no
ASAN) — AFL's forkserver instrumentation collides with `--coverage` flushing.

```bash
# Install lcov (preferred) or gcovr fallback:
apt-get install lcov          # primary
pip install gcovr             # fallback

scripts/build_dcmtk_cov.sh    # builds into fuzz/build-cov/
scripts/coverage.sh file      # replays fuzz/out/file/{queue,crashes}
# Report → fuzz/coverage/file/{lcov.info, summary.txt, html/index.html}
```

`coverage.sh` aborts if the gcov build SHA doesn't match the ASAN build SHA.

## Campaigns + saturation rule

`scripts/campaign.sh <target>` runs a fuzz harness to a documented stop rule
and emits `fuzz/runs/<target>/<UTC-timestamp>/run.json` with provenance and
metrics for the test report.

| Env var            | Default | Notes                                                          |
|--------------------|---------|----------------------------------------------------------------|
| `CAMPAIGN_HOURS`   | 24      | Hard wallclock cap. Sample range 24–72.                        |
| `SATURATION_HOURS` | 6       | Stop early if no new edges/paths for this long. Effective floor is `max(SATURATION_HOURS, CAMPAIGN_HOURS/10)`. |
| `POLL_SECONDS`     | 60      | Poll cadence on `fuzzer_stats`.                                 |

Targets: `file` (dcm2pnm), `parse` (dcmdump), `net-storescp`, `net-dcmrecv`,
`net-dcmqrscp`, `scu` (storescu, experimental).
