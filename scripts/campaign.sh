#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 7: run a fuzz harness to a documented stop rule and emit a
# fuzz/runs/<target>/<UTC-timestamp>/run.json artefact recording build
# provenance, fuzzer metadata, and run metrics for the device test report.
#
# Usage:
#   scripts/campaign.sh <target>
#       target ∈ {file, parse, net-storescp, net-dcmrecv, net-dcmqrscp, scu}
#
# Env knobs:
#   CAMPAIGN_HOURS   — wallclock cap (default 24, sample range 24–72)
#   SATURATION_HOURS — stop early if no new corpus entries for this long
#                      (default 6). Effective stop = max(SATURATION_HOURS,
#                      CAMPAIGN_HOURS/10) so deep parsers aren't cut short.
#   POLL_SECONDS     — fuzzer_stats poll cadence (default 60)
#
# Stop reasons (priority order):
#   timeout        — wallclock ≥ CAMPAIGN_HOURS
#   saturated      — seconds since last new corpus ≥ effective stop
#   crash_dominant — crash:corpus ratio > 0.5 over last hour (heuristic)
#   error          — fuzzer process died unexpectedly
#   killed         — operator sent SIGINT/SIGTERM
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target>"
    echo "  target ∈ {file, parse, net-storescp, net-dcmrecv, net-dcmqrscp, scu}"
    exit 2
fi

TARGET="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Resolve target → fuzz script + binary name + build dir. The file/SCU
# targets live in the AFL++ afl-clang-fast build (build-llvm); the network
# targets in the AFLNet afl-gcc build (build-net). See scripts/build_dcmtk.sh.
case "${TARGET}" in
    file)         FUZZ_SCRIPT=fuzz_file.sh    BIN_NAME=dcm2pnm  BUILD_SUBDIR=build-llvm ;;
    parse)        FUZZ_SCRIPT=fuzz_parse.sh   BIN_NAME=dcmdump  BUILD_SUBDIR=build-llvm ;;
    net-storescp) FUZZ_SCRIPT=fuzz_net.sh     BIN_NAME=storescp BUILD_SUBDIR=build-net  ;;
    net-dcmrecv)  FUZZ_SCRIPT=fuzz_dcmrecv.sh BIN_NAME=dcmrecv  BUILD_SUBDIR=build-net  ;;
    net-dcmqrscp) FUZZ_SCRIPT=fuzz_dcmqrscp.sh BIN_NAME=dcmqrscp BUILD_SUBDIR=build-net  ;;
    scu)          FUZZ_SCRIPT=fuzz_scu.sh     BIN_NAME=storescu BUILD_SUBDIR=build-llvm ;;
    *) echo "[campaign] unknown target '${TARGET}'"; exit 2 ;;
esac
BUILD_DIR="${REPO_ROOT}/fuzz/${BUILD_SUBDIR}"

CAMPAIGN_HOURS="${CAMPAIGN_HOURS:-24}"
SATURATION_HOURS="${SATURATION_HOURS:-6}"
POLL_SECONDS="${POLL_SECONDS:-60}"

# Convert to seconds in floating-point-aware way (awk, not bash arith).
CAMPAIGN_SECS=$(awk -v h="${CAMPAIGN_HOURS}" 'BEGIN{printf "%d", h*3600}')
SATURATION_SECS_RAW=$(awk -v h="${SATURATION_HOURS}" 'BEGIN{printf "%d", h*3600}')
SATURATION_FLOOR=$(awk -v s="${CAMPAIGN_SECS}" 'BEGIN{printf "%d", s/10}')
SATURATION_SECS=$(( SATURATION_SECS_RAW > SATURATION_FLOOR ? SATURATION_SECS_RAW : SATURATION_FLOOR ))

START_TS=$(date -u +%FT%TZ)
START_EPOCH=$(date +%s)
RUN_DIR="${REPO_ROOT}/fuzz/runs/${TARGET}/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${RUN_DIR}"

# Resolve binary + sha. Built before launching the fuzz script.
BIN_PATH="$(find "${BUILD_DIR}" -type f -name "${BIN_NAME}" -executable | head -1 || true)"
if [[ -z "${BIN_PATH}" ]]; then
    echo "[campaign] ${BIN_NAME} not found under ${BUILD_DIR} — run scripts/build_dcmtk.sh"
    exit 1
fi
BIN_SHA=$(sha256sum "${BIN_PATH}" | awk '{print $1}')

# Snapshot build manifest into the run dir.
if [[ -f "${BUILD_DIR}/build_manifest.txt" ]]; then
    cp "${BUILD_DIR}/build_manifest.txt" "${RUN_DIR}/build_manifest.txt"
fi

# Compute SHAs for inputs that affect the run (best-effort; missing → "").
DICT_SHA=""
[[ -f "${REPO_ROOT}/fuzz/dict/dicom.dict" ]] && \
    DICT_SHA=$(sha256sum "${REPO_ROOT}/fuzz/dict/dicom.dict" | awk '{print $1}')

SEEDS_DIR=""
case "${TARGET}" in
    file)         SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/file" ;;
    parse)        SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/file" ;;
    net-storescp) SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/net-storescp" ;;
    net-dcmrecv)  SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/net-dcmrecv" ;;
    net-dcmqrscp) SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/net-dcmqrscp" ;;
    scu)          SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/scu" ;;
esac
SEEDS_SHA=""
if [[ -d "${SEEDS_DIR}" ]]; then
    SEEDS_SHA=$(find "${SEEDS_DIR}" -maxdepth 1 -type f \( -name '*.raw' -o -name '*.dcm' \) -print0 \
        | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | awk '{print $1}')
fi

# Emit initial run.json. Rewritten on stop with end-of-run fields.
write_run_json() {
    local stop_reason="${1:-running}"
    local end_ts="${2:-}"
    local wall_s="${3:-0}"
    local cpu_s="${4:-0}"
    local corpus_count="${5:-0}"
    local edges_found="${6:-null}"
    local execs_done="${7:-0}"
    local peak_eps="${8:-0}"
    local mean_eps="${9:-0}"
    local last_new_path_at="${10:-}"
    local poll_samples="${11:-0}"

    cat >"${RUN_DIR}/run.json" <<JSON
{
  "schema": 1,
  "target": "${TARGET}",
  "binary": "${BIN_PATH}",
  "binary_sha256": "${BIN_SHA}",
  "build_manifest": "build_manifest.txt",
  "dictionary_sha256": "${DICT_SHA}",
  "seed_corpus_sha256": "${SEEDS_SHA}",
  "fuzz_script": "${FUZZ_SCRIPT}",
  "stop_rule": {
    "campaign_hours": ${CAMPAIGN_HOURS},
    "saturation_hours": ${SATURATION_HOURS},
    "saturation_seconds_effective": ${SATURATION_SECS},
    "poll_seconds": ${POLL_SECONDS}
  },
  "start_ts": "${START_TS}",
  "end_ts": "${end_ts}",
  "wall_time_s": ${wall_s},
  "cpu_time_s": ${cpu_s},
  "corpus_count": ${corpus_count},
  "edges_found": ${edges_found},
  "total_execs": ${execs_done},
  "peak_execs_per_sec": ${peak_eps},
  "mean_execs_per_sec": ${mean_eps},
  "last_new_path_at": "${last_new_path_at}",
  "poll_samples": ${poll_samples},
  "stop_reason": "${stop_reason}",
  "log": "fuzz.log",
  "poll_tsv": "poll.tsv"
}
JSON
}
write_run_json running

# poll.tsv header.
echo -e "ts\tcorpus_count\texecs_per_sec\texecs_done\tedges_found\tlast_find" \
    >"${RUN_DIR}/poll.tsv"

# Launch the fuzzer wrapped in /usr/bin/time -v for CPU accounting.
TIME_OUT="${RUN_DIR}/time.txt"
TIME_BIN="/usr/bin/time"
if [[ ! -x "${TIME_BIN}" ]]; then
    echo "[campaign] /usr/bin/time not found; CPU time will be unavailable"
    TIME_BIN=""
fi

echo "[campaign] target=${TARGET} run_dir=${RUN_DIR}"
echo "[campaign] stop rule: campaign=${CAMPAIGN_HOURS}h saturation=${SATURATION_HOURS}h (eff ${SATURATION_SECS}s)"

if [[ -n "${TIME_BIN}" ]]; then
    setsid "${TIME_BIN}" -v -o "${TIME_OUT}" \
        "${REPO_ROOT}/scripts/${FUZZ_SCRIPT}" \
        >"${RUN_DIR}/fuzz.log" 2>&1 &
else
    setsid "${REPO_ROOT}/scripts/${FUZZ_SCRIPT}" \
        >"${RUN_DIR}/fuzz.log" 2>&1 &
fi
FUZZ_PID=$!
echo "${FUZZ_PID}" >"${RUN_DIR}/fuzz.pid"

# stop_reason captured by the trap / poll loop.
STOP_REASON=""
cleanup() {
    if [[ -z "${STOP_REASON}" ]]; then
        STOP_REASON=killed
    fi
    if kill -0 "${FUZZ_PID}" 2>/dev/null; then
        # Kill the whole process group started by setsid.
        kill -TERM -"${FUZZ_PID}" 2>/dev/null || true
        for _ in $(seq 1 30); do
            kill -0 "${FUZZ_PID}" 2>/dev/null || break
            sleep 1
        done
        kill -KILL -"${FUZZ_PID}" 2>/dev/null || true
    fi
    wait "${FUZZ_PID}" 2>/dev/null || true
}
trap cleanup EXIT
trap 'STOP_REASON=killed; exit 130' INT TERM

# Locate the fuzzer_stats file (AFL++ uses default/, AFLNet uses root).
find_stats() {
    for fuzz_out in \
        "${REPO_ROOT}/fuzz/out/${TARGET}/default/fuzzer_stats" \
        "${REPO_ROOT}/fuzz/out/${TARGET}/fuzzer_stats" \
        "${REPO_ROOT}/fuzz/out/${TARGET}"/*/fuzzer_stats; do
        [[ -f "${fuzz_out}" ]] && { echo "${fuzz_out}"; return 0; }
    done
    return 1
}

last_corpus=0
last_new_path_epoch=${START_EPOCH}
last_new_path_iso="${START_TS}"
peak_eps=0
sum_eps=0
samples=0
final_corpus=0
final_edges_found=null
final_execs=0
last_crash_ratio_check=${START_EPOCH}
crash_count_at_check=0
corpus_count_at_check=0

while true; do
    sleep "${POLL_SECONDS}"
    now=$(date +%s)

    if ! kill -0 "${FUZZ_PID}" 2>/dev/null; then
        STOP_REASON=error
        break
    fi

    stats=$(find_stats || true)
    if [[ -z "${stats}" ]]; then
        # fuzzer hasn't created stats yet — keep waiting until wallclock runs out.
        if (( now - START_EPOCH >= CAMPAIGN_SECS )); then
            STOP_REASON=timeout
            break
        fi
        continue
    fi

    corpus=$(awk -F': *' '/^(corpus_count|paths_total)/ {print $2; exit}' "${stats}")
    eps=$(awk -F': *' '/^execs_per_sec/ {print $2; exit}' "${stats}")
    execs=$(awk -F': *' '/^execs_done/ {print $2; exit}' "${stats}")
    edges=$(awk -F': *' '/^edges_found/ {print $2; exit}' "${stats}")
    last_find=$(awk -F': *' '/^last_find/ {print $2; exit}' "${stats}")
    corpus="${corpus:-0}"
    eps="${eps:-0}"
    execs="${execs:-0}"

    # Detect new corpus entries → reset saturation timer.
    if (( ${corpus%.*} > last_corpus )); then
        last_corpus="${corpus%.*}"
        last_new_path_epoch=${now}
        last_new_path_iso=$(date -u -d "@${now}" +%FT%TZ 2>/dev/null \
            || date -u +%FT%TZ)
    fi

    # Running execs/sec stats.
    samples=$((samples + 1))
    sum_eps=$(awk -v a="${sum_eps}" -v b="${eps}" 'BEGIN{printf "%.2f", a+b}')
    peak_eps=$(awk -v a="${peak_eps}" -v b="${eps}" 'BEGIN{printf "%.2f", (a>b)?a:b}')

    final_corpus="${corpus%.*}"
    final_edges_found="${edges:-null}"
    [[ -z "${edges}" ]] && final_edges_found=null
    final_execs="${execs%.*}"

    printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$(date -u +%FT%TZ)" "${corpus}" "${eps}" "${execs}" "${edges:-}" "${last_find:-}" \
        >>"${RUN_DIR}/poll.tsv"

    # Stop conditions.
    if (( now - START_EPOCH >= CAMPAIGN_SECS )); then
        STOP_REASON=timeout
        break
    fi
    if (( now - last_new_path_epoch >= SATURATION_SECS )); then
        STOP_REASON=saturated
        break
    fi
    # crash_dominant heuristic: over a 1-hour window, crashes-found exceed
    # corpus-found. Only meaningful once we have both samples.
    if (( now - last_crash_ratio_check >= 3600 )); then
        crash_dirs=$(find "${REPO_ROOT}/fuzz/out/${TARGET}" -path '*/crashes/id:*' 2>/dev/null | wc -l)
        delta_crash=$((crash_dirs - crash_count_at_check))
        delta_corpus=$((${corpus%.*} - corpus_count_at_check))
        if (( delta_crash > 0 && delta_crash * 2 > delta_corpus )); then
            STOP_REASON=crash_dominant
            break
        fi
        last_crash_ratio_check=${now}
        crash_count_at_check=${crash_dirs}
        corpus_count_at_check=${corpus%.*}
    fi
done

trap - INT TERM
cleanup
trap - EXIT

END_TS=$(date -u +%FT%TZ)
END_EPOCH=$(date +%s)
WALL_S=$((END_EPOCH - START_EPOCH))

CPU_S=0
if [[ -f "${TIME_OUT}" ]]; then
    user_s=$(awk -F': ' '/User time \(seconds\)/ {print $2; exit}' "${TIME_OUT}" 2>/dev/null || echo 0)
    sys_s=$(awk -F': ' '/System time \(seconds\)/ {print $2; exit}' "${TIME_OUT}" 2>/dev/null || echo 0)
    CPU_S=$(awk -v u="${user_s:-0}" -v s="${sys_s:-0}" 'BEGIN{printf "%.2f", u+s}')
fi

mean_eps=0
if (( samples > 0 )); then
    mean_eps=$(awk -v sum="${sum_eps}" -v n="${samples}" 'BEGIN{printf "%.2f", sum/n}')
fi

write_run_json "${STOP_REASON}" "${END_TS}" "${WALL_S}" "${CPU_S}" \
    "${final_corpus}" "${final_edges_found}" "${final_execs}" \
    "${peak_eps}" "${mean_eps}" "${last_new_path_iso}" "${samples}"

echo "[campaign] stop_reason=${STOP_REASON} wall=${WALL_S}s cpu=${CPU_S}s corpus=${final_corpus} execs=${final_execs}"
echo "[campaign] artefact: ${RUN_DIR}/run.json"
