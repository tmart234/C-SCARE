#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 2: launch afl-fuzz against dcm2pnm with the DICOM dictionary loaded.
# Re-run safely: if fuzz/out/file already exists, AFL resumes via -i-.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/fuzz/build-llvm"
SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/file"
DICT_PATH="${REPO_ROOT}/fuzz/dict/dicom.dict"
OUT_DIR="${REPO_ROOT}/fuzz/out/file"

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

DCM2PNM="$(find "${BUILD_DIR}" -type f -name dcm2pnm -executable | head -1)"
[[ -n "${DCM2PNM}" ]] || { echo "[fuzz_file] dcm2pnm not built"; exit 1; }

if [[ ! -d "${SEEDS_DIR}" || -z "$(ls -A "${SEEDS_DIR}" 2>/dev/null)" ]]; then
    echo "[fuzz_file] generating seed corpus"
    python3 "${REPO_ROOT}/fuzz/harness/gen_file_seeds.py"
    python3 "${REPO_ROOT}/fuzz/harness/gen_pixel_seeds.py"
fi
if [[ ! -f "${DICT_PATH}" ]]; then
    echo "[fuzz_file] building dictionary"
    python3 "${REPO_ROOT}/fuzz/harness/build_dict.py"
fi

mkdir -p "${OUT_DIR}"
export ASAN_OPTIONS="abort_on_error=1:symbolize=0:detect_leaks=0:halt_on_error=1"
export DCMDICTPATH="${REPO_ROOT}/fuzz/dcmtk/dcmdata/data/dicom.dic"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

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
# DCM2PNM is then the fast native loop binary. No workers → the plain
# single-binary loop, unchanged. See https://aflplus.plus/docs/sand/.
SAND_ARGS=()
for wdir in "${REPO_ROOT}"/fuzz/build-san-*/; do
    [[ -d "${wdir}" ]] || continue
    worker="$(find "${wdir}" -type f -name dcm2pnm -executable | head -1)"
    if [[ -n "${worker}" ]]; then
        SAND_ARGS+=(-w "${worker}")
        echo "[fuzz_file] SAND worker: ${worker}"
    fi
done

exec "${AFLPP_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -x "${DICT_PATH}" \
    -m none \
    "${SAND_ARGS[@]}" \
    -- "${DCM2PNM}" @@ /tmp/cscare-fuzz-out.pnm
