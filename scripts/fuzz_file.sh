#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Generic AFL++ file-target runner for profiles with engine=aflpp and kind=file.
# Per-target values (binary, dirs, dictionary, env, argv) come from
# fuzz/targets/<profile>.yaml via scripts/profile_lib.sh.
#
# Usage:
#   scripts/fuzz_file.sh                 # profile: file
#   scripts/fuzz_file.sh parse           # profile: parse
#   CSCARE_PROFILE=<profile> scripts/fuzz_file.sh
#
# For external/product harnesses whose binary is not under fuzz/<build_subdir>:
#   CSCARE_TARGET_BINARY=/path/to/harness
#
# Optional:
#   CSCARE_CMPLOG_BINARY=/path/to/cmplog-helper
#   CSCARE_AUTO_DICT=/path/to/auto.dict
#   CSCARE_REQUIRE_CMPLOG=1              # fail if CmpLog helper is absent
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_NAME="${CSCARE_PROFILE:-${1:-file}}"

# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
load_profile "${PROFILE_NAME}"
source_afl

if [[ "${ENGINE}" != "aflpp" || "${KIND}" != "file" ]]; then
    echo "[fuzz_file] profile ${PROFILE_NAME} is ${ENGINE}/${KIND}, expected aflpp/file" >&2
    exit 2
fi

if [[ -n "${CSCARE_TARGET_BINARY:-}" ]]; then
    BIN_PATH="${CSCARE_TARGET_BINARY}"
elif [[ -n "${CSCARE_PRINT_ARGV:-}" ]]; then
    BIN_PATH="${BUILD_DIR}/${BIN_NAME}"
else
    find_binary fuzz_file
fi

if [[ -z "${CSCARE_PRINT_ARGV:-}" && ! -x "${BIN_PATH}" ]]; then
    echo "[fuzz_file] target not executable: ${BIN_PATH}" >&2
    echo "[fuzz_file] set CSCARE_TARGET_BINARY=/path/to/${BIN_NAME}" >&2
    exit 1
fi

if [[ -z "${CSCARE_PRINT_ARGV:-}" && ( ! -d "${SEEDS_DIR}" || -z "$(ls -A "${SEEDS_DIR}" 2>/dev/null)" ) ]]; then
    echo "[fuzz_file] generating seed corpus for ${PROFILE_NAME}"
    run_seed_generators
fi
if [[ -z "${CSCARE_PRINT_ARGV:-}" && -n "${DICT_PATH}" && ! -f "${DICT_PATH}" && -n "${DICT_GENERATOR}" ]]; then
    echo "[fuzz_file] building dictionary"
    bash -c "${DICT_GENERATOR}"
fi

mkdir -p "${OUT_DIR}"
# load_profile exported ASAN_OPTIONS/DCMDICTPATH/AFL_* from the profile.

# Resume if a prior session exists; else start fresh.
if [[ -f "${OUT_DIR}/fuzzer_stats" || -f "${OUT_DIR}/default/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_file] resuming ${PROFILE_NAME} campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_file] starting fresh ${PROFILE_NAME} campaign in ${OUT_DIR}"
fi

# SAND mode (scripts/build_dcmtk.sh SAND=1): when sanitizer-worker trees
# exist under fuzz/build-san-*/, route suspicious inputs to them via -w —
# the target is then the fast native loop binary. No workers → the plain
# single-binary loop, unchanged. See https://aflplus.plus/docs/sand/.
SAND_ARGS=()
if [[ "${SAND_ENABLED}" == "true" ]]; then
    for wdir in "${REPO_ROOT}"/fuzz/build-san-*/; do
        [[ -d "${wdir}" ]] || continue
        worker="$(find "${wdir}" -type f -name "${BIN_NAME}" -executable | head -1)"
        if [[ -n "${worker}" ]]; then
            SAND_ARGS+=(-w "${worker}")
            echo "[fuzz_file] SAND worker: ${worker}"
        fi
    done
fi

DICT_ARG=()
if [[ -n "${DICT_PATH}" ]]; then
    USE_DICT="${DICT_PATH}"
    if [[ -n "${CSCARE_AUTO_DICT:-}" && -f "${CSCARE_AUTO_DICT}" && -f "${DICT_PATH}" ]]; then
        USE_DICT="${OUT_DIR}/${PROFILE_NAME}.combined.dict"
        cat "${DICT_PATH}" "${CSCARE_AUTO_DICT}" >"${USE_DICT}"
        echo "[fuzz_file] using combined dictionary ${USE_DICT}"
    fi
    DICT_ARG=(-x "${USE_DICT}")
fi

CMPLOG_ARG=()
if [[ -n "${CSCARE_CMPLOG_BINARY:-}" ]]; then
    if [[ -n "${CSCARE_PRINT_ARGV:-}" || -x "${CSCARE_CMPLOG_BINARY}" ]]; then
        CMPLOG_ARG=(-c "${CSCARE_CMPLOG_BINARY}")
    elif [[ "${CSCARE_REQUIRE_CMPLOG:-0}" == "1" ]]; then
        echo "[fuzz_file] CmpLog binary not executable: ${CSCARE_CMPLOG_BINARY}" >&2
        exit 1
    else
        echo "[fuzz_file] CmpLog binary missing; continuing without -c: ${CSCARE_CMPLOG_BINARY}" >&2
    fi
fi

afl_exec "${AFLPP_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    "${DICT_ARG[@]}" \
    "${CMPLOG_ARG[@]}" \
    -m none \
    "${SAND_ARGS[@]}" \
    -- "${BIN_PATH}" "${ARGV[@]}"
