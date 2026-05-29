#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 2: launch afl-fuzz against dcm2pnm with the DICOM dictionary loaded.
# Re-run safely: if fuzz/out/file already exists, AFL resumes via -i-.
#
# Per-target values (binary, dirs, dictionary, env, argv) come from the
# declarative profile fuzz/targets/file.yaml via scripts/profile_lib.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
load_profile file
source_afl

find_binary fuzz_file

if [[ -z "${CSCARE_PRINT_ARGV:-}" && ( ! -d "${SEEDS_DIR}" || -z "$(ls -A "${SEEDS_DIR}" 2>/dev/null)" ) ]]; then
    echo "[fuzz_file] generating seed corpus"
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
    echo "[fuzz_file] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_file] starting fresh campaign in ${OUT_DIR}"
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

afl_exec "${AFLPP_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -x "${DICT_PATH}" \
    -m none \
    "${SAND_ARGS[@]}" \
    -- "${BIN_PATH}" "${ARGV[@]}"
