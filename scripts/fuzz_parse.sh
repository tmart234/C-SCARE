#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Grey-box file fuzzing of the DICOM *parser* via dcmdump. dcmdump reads and
# fully parses a DICOM file with no pixel-rendering pipeline, so it is a
# tighter target for the dataset/element parser than dcm2pnm.
# Re-run safely: if fuzz/out/parse exists, AFL resumes via -i-.
#
# Per-target values come from the profile fuzz/targets/parse.yaml.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
load_profile parse
source_afl

find_binary fuzz_parse

if [[ -z "${CSCARE_PRINT_ARGV:-}" && ( ! -d "${SEEDS_DIR}" || -z "$(ls -A "${SEEDS_DIR}" 2>/dev/null)" ) ]]; then
    echo "[fuzz_parse] generating seed corpus"
    run_seed_generators
fi
if [[ -z "${CSCARE_PRINT_ARGV:-}" && -n "${DICT_PATH}" && ! -f "${DICT_PATH}" && -n "${DICT_GENERATOR}" ]]; then
    echo "[fuzz_parse] building dictionary"
    bash -c "${DICT_GENERATOR}"
fi

mkdir -p "${OUT_DIR}"
# load_profile exported ASAN_OPTIONS/DCMDICTPATH/AFL_* from the profile.

if [[ -f "${OUT_DIR}/fuzzer_stats" || -f "${OUT_DIR}/default/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_parse] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_parse] starting fresh campaign in ${OUT_DIR}"
fi

# SAND mode (scripts/build_dcmtk.sh SAND=1): route suspicious inputs to the
# sanitizer-worker trees under fuzz/build-san-*/ via -w. See
# https://aflplus.plus/docs/sand/.
SAND_ARGS=()
if [[ "${SAND_ENABLED}" == "true" ]]; then
    for wdir in "${REPO_ROOT}"/fuzz/build-san-*/; do
        [[ -d "${wdir}" ]] || continue
        worker="$(find "${wdir}" -type f -name "${BIN_NAME}" -executable | head -1)"
        if [[ -n "${worker}" ]]; then
            SAND_ARGS+=(-w "${worker}")
            echo "[fuzz_parse] SAND worker: ${worker}"
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
