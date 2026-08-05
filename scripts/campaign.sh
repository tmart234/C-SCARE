#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 7: run a fuzz harness to a documented stop rule and emit a
# fuzz/runs/<target>/<UTC-timestamp>/run.json artefact recording build
# provenance, fuzzer metadata, and run metrics for the device test report.
#
# Usage:
#   scripts/campaign.sh <target>
#       target ∈ any profile under fuzz/targets/*.yaml
#
# Env knobs:
#   CAMPAIGN_HOURS   — wallclock cap (default 24, sample range 24–72)
#   SATURATION_HOURS — stop early if no new corpus entries for this long
#                      (default 6). Effective stop = max(SATURATION_HOURS,
#                      CAMPAIGN_HOURS/10) so deep parsers aren't cut short.
#   POLL_SECONDS     — fuzzer_stats poll cadence (default 60)
#   CAMPAIGN_WORKERS — AFL++ parallel workers for file-style targets
#                      (default 1; use "auto" for min(nproc/2, 12)).
#   CAMPAIGN_OUT_DIR — override the AFL output directory. In multicore mode,
#                      the default is <profile-output>-multicore-<UTC>.
#   AFL_TIMEOUT_MS   — optional AFL++ per-exec timeout passed as -t.
#   AFL_TMPDIR_BASE  — base directory for per-worker AFL_TMPDIR directories
#                      (default /dev/shm/c-scare-afl-$USER in multicore mode).
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
    echo "  target ∈ any profile under fuzz/targets/*.yaml"
    exit 2
fi

TARGET="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Resolve target → fuzz script + binary name + build dir + seeds dir from the
# declarative profile (fuzz/targets/<target>.yaml) via scripts/profile_lib.sh.
# No per-target case statement: adding a target is a matter of dropping in one
# YAML. The file/SCU targets live in the AFL++ afl-clang-fast build
# (build-llvm); the network targets in the AFLNet afl-gcc build (build-net).
# See scripts/build_dcmtk.sh.
# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
if ! load_profile "${TARGET}"; then
    echo "[campaign] unknown target '${TARGET}'"; exit 2
fi
FUZZ_SCRIPT="${HARNESS}"
BUILD_DIR="${REPO_ROOT}/fuzz/${BUILD_SUBDIR}"

CAMPAIGN_HOURS="${CAMPAIGN_HOURS:-24}"
SATURATION_HOURS="${SATURATION_HOURS:-6}"
POLL_SECONDS="${POLL_SECONDS:-60}"
CAMPAIGN_WORKERS="${CAMPAIGN_WORKERS:-${WORKERS:-1}}"
if [[ "${CAMPAIGN_WORKERS}" == "auto" ]]; then
    cores="$(nproc 2>/dev/null || echo 1)"
    CAMPAIGN_WORKERS=$(( cores / 2 ))
    [[ "${CAMPAIGN_WORKERS}" -lt 1 ]] && CAMPAIGN_WORKERS=1
    [[ "${CAMPAIGN_WORKERS}" -gt 12 ]] && CAMPAIGN_WORKERS=12
fi
if ! [[ "${CAMPAIGN_WORKERS}" =~ ^[0-9]+$ ]] || [[ "${CAMPAIGN_WORKERS}" -lt 1 ]]; then
    echo "[campaign] CAMPAIGN_WORKERS must be a positive integer or 'auto'" >&2
    exit 2
fi
CAMPAIGN_WORKER_COUNT="${CAMPAIGN_WORKERS}"
if (( CAMPAIGN_WORKER_COUNT > 1 )); then
    has_input_placeholder=false
    for arg in "${ARGV[@]}"; do
        [[ "${arg}" == "@@" ]] && has_input_placeholder=true
    done
    if [[ "${ENGINE}" != "aflpp" || "${has_input_placeholder}" != "true" ]]; then
        echo "[campaign] CAMPAIGN_WORKERS>1 is supported for AFL++ file targets with @@ argv only" >&2
        exit 2
    fi
    if [[ -z "${CAMPAIGN_OUT_DIR:-}" ]]; then
        OUT_DIR="${OUT_DIR}-multicore-$(date -u +%Y%m%dT%H%M%SZ)"
    fi
fi
if [[ -n "${CAMPAIGN_OUT_DIR:-}" ]]; then
    OUT_DIR="${CAMPAIGN_OUT_DIR}"
fi

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
if [[ -n "${CSCARE_TARGET_BINARY:-}" ]]; then
    BIN_PATH="${CSCARE_TARGET_BINARY}"
else
    BIN_PATH="$(find "${BUILD_DIR}" -type f -name "${BIN_NAME}" -executable | head -1 || true)"
fi
if [[ -z "${BIN_PATH}" ]]; then
    echo "[campaign] ${BIN_NAME} not found under ${BUILD_DIR}"
    echo "[campaign] set CSCARE_TARGET_BINARY=/path/to/${BIN_NAME} for external builds, or run the target build first"
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

# SEEDS_DIR was set from the profile by load_profile above.
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
    "workers": ${CAMPAIGN_WORKER_COUNT},
    "afl_timeout_ms": "${AFL_TIMEOUT_MS:-}",
    "output_dir": "${OUT_DIR}",
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
export CSCARE_PROFILE="${TARGET}"

FUZZ_PIDS=()
launch_parallel_aflpp() {
    source_afl
    mkdir -p "${OUT_DIR}"
    if [[ ! -d "${SEEDS_DIR}" || -z "$(find "${SEEDS_DIR}" -maxdepth 1 -type f -print -quit)" ]]; then
        echo "[campaign] generating seed corpus"
        run_seed_generators
    fi
    if [[ -n "${DICT_PATH}" && ! -f "${DICT_PATH}" && -n "${DICT_GENERATOR}" ]]; then
        echo "[campaign] building dictionary"
        bash -c "${DICT_GENERATOR}"
    fi

    local tmp_base="${AFL_TMPDIR_BASE:-/dev/shm/c-scare-afl-${USER:-user}}"
    mkdir -p "${tmp_base}"
    if [[ "${tmp_base}" == /dev/shm/c-scare-afl-* ]]; then
        rm -rf "${tmp_base:?}/"*
    fi

    export TERM="${TERM:-xterm-256color}"
    export AFL_FAST_CAL="${AFL_FAST_CAL:-1}"
    export AFL_IMPORT_FIRST="${AFL_IMPORT_FIRST:-1}"
    export AFL_SHUFFLE_QUEUE="${AFL_SHUFFLE_QUEUE:-1}"

    local worker name mode tmp_dir log_file input_arg
    for ((worker = 0; worker < CAMPAIGN_WORKER_COUNT; worker++)); do
        if (( worker == 0 )); then
            name="main"
            mode="-M"
        else
            name="sec${worker}"
            mode="-S"
        fi
        tmp_dir="${tmp_base}/${name}"
        mkdir -p "${tmp_dir}"
        log_file="${RUN_DIR}/fuzz-${name}.log"
        input_arg="${SEEDS_DIR}"
        if [[ -f "${OUT_DIR}/${name}/fuzzer_stats" ]]; then
            input_arg="-"
        fi
        (
            export AFL_TMPDIR="${tmp_dir}"
            export TMPDIR="${tmp_dir}"
            exec "${AFLPP_PATH}/afl-fuzz" \
                "${mode}" "${name}" \
                -i "${input_arg}" \
                -o "${OUT_DIR}" \
                ${DICT_PATH:+-x "${DICT_PATH}"} \
                ${AFL_TIMEOUT_MS:+-t "${AFL_TIMEOUT_MS}"} \
                -m none \
                -- "${BIN_PATH}" "${ARGV[@]}"
        ) >"${log_file}" 2>&1 &
        FUZZ_PIDS+=("$!")
    done
}

if (( CAMPAIGN_WORKER_COUNT > 1 )); then
    launch_parallel_aflpp
    FUZZ_PID="${FUZZ_PIDS[0]}"
    printf '%s\n' "${FUZZ_PIDS[@]}" >"${RUN_DIR}/fuzz.pid"
elif [[ -n "${TIME_BIN}" ]]; then
    setsid "${TIME_BIN}" -v -o "${TIME_OUT}" \
        bash "${REPO_ROOT}/scripts/${FUZZ_SCRIPT}" \
        >"${RUN_DIR}/fuzz.log" 2>&1 &
else
    setsid bash "${REPO_ROOT}/scripts/${FUZZ_SCRIPT}" \
        >"${RUN_DIR}/fuzz.log" 2>&1 &
fi
if (( CAMPAIGN_WORKER_COUNT == 1 )); then
    FUZZ_PID=$!
    FUZZ_PIDS=("${FUZZ_PID}")
    echo "${FUZZ_PID}" >"${RUN_DIR}/fuzz.pid"
fi

# stop_reason captured by the trap / poll loop.
STOP_REASON=""
cleanup() {
    if [[ -z "${STOP_REASON}" ]]; then
        STOP_REASON=killed
    fi
    local pid
    for pid in "${FUZZ_PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            if (( CAMPAIGN_WORKER_COUNT > 1 )); then
                kill -TERM "${pid}" 2>/dev/null || true
            else
                # Kill the whole process group started by setsid.
                kill -TERM -"${pid}" 2>/dev/null || true
            fi
        fi
    done
    for _ in $(seq 1 30); do
        local alive=0
        for pid in "${FUZZ_PIDS[@]}"; do
            kill -0 "${pid}" 2>/dev/null && alive=1
        done
        (( alive == 0 )) && break
        sleep 1
    done
    for pid in "${FUZZ_PIDS[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            if (( CAMPAIGN_WORKER_COUNT > 1 )); then
                kill -KILL "${pid}" 2>/dev/null || true
            else
                kill -KILL -"${pid}" 2>/dev/null || true
            fi
        fi
        wait "${pid}" 2>/dev/null || true
    done
}
trap cleanup EXIT
trap 'STOP_REASON=killed; exit 130' INT TERM

# Locate the fuzzer_stats file(s) (AFL++ uses default/ or worker dirs;
# AFLNet uses root).
find_stats_files() {
    for fuzz_out in \
        "${REPO_ROOT}/fuzz/out/${TARGET}/default/fuzzer_stats" \
        "${REPO_ROOT}/fuzz/out/${TARGET}/fuzzer_stats" \
        "${OUT_DIR}/default/fuzzer_stats" \
        "${OUT_DIR}/fuzzer_stats" \
        "${OUT_DIR}"/*/fuzzer_stats \
        "${REPO_ROOT}/fuzz/out/${TARGET}"/*/fuzzer_stats; do
        [[ -f "${fuzz_out}" ]] && echo "${fuzz_out}"
    done
}

sum_stats_field() {
    local field="$1"
    shift
    awk -F': *' -v field="${field}" '
        $1 == field {sum += $2 + 0}
        END {printf "%.2f", sum + 0}
    ' "$@"
}

max_stats_field() {
    local field="$1"
    shift
    awk -F': *' -v field="${field}" '
        $1 == field {if (!seen || $2 + 0 > max) max = $2 + 0; seen = 1}
        END {if (seen) printf "%.0f", max; else printf ""}
    ' "$@"
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

    alive=0
    for pid in "${FUZZ_PIDS[@]}"; do
        kill -0 "${pid}" 2>/dev/null && alive=1
    done
    if (( alive == 0 )); then
        STOP_REASON=error
        break
    fi

    mapfile -t stats_files < <(find_stats_files)
    if (( ${#stats_files[@]} == 0 )); then
        # fuzzer hasn't created stats yet — keep waiting until wallclock runs out.
        if (( now - START_EPOCH >= CAMPAIGN_SECS )); then
            STOP_REASON=timeout
            break
        fi
        continue
    fi

    corpus=$(sum_stats_field corpus_count "${stats_files[@]}")
    if [[ "${corpus%.*}" == "0" ]]; then
        corpus=$(sum_stats_field paths_total "${stats_files[@]}")
    fi
    eps=$(sum_stats_field execs_per_sec "${stats_files[@]}")
    execs=$(sum_stats_field execs_done "${stats_files[@]}")
    edges=$(max_stats_field edges_found "${stats_files[@]}")
    last_find=$(max_stats_field last_find "${stats_files[@]}")
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
        crash_dirs=$(find "${OUT_DIR}" -path '*/crashes/id:*' 2>/dev/null | wc -l)
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
