#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Grey-box file fuzzing of the DICOM *parser* via dcmdump. dcmdump reads and
# fully parses a DICOM file with no pixel-rendering pipeline, so it is a
# tighter target for the dataset/element parser than dcm2pnm.
# Re-run safely: if fuzz/out/parse exists, AFL resumes via -i-.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/fuzz/build-llvm"
SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/file"
DICT_PATH="${REPO_ROOT}/fuzz/dict/dicom.dict"
OUT_DIR="${REPO_ROOT}/fuzz/out/parse"

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

DCMDUMP="$(find "${BUILD_DIR}" -type f -name dcmdump -executable | head -1)"
[[ -n "${DCMDUMP}" ]] || { echo "[fuzz_parse] dcmdump not built — run scripts/build_dcmtk.sh"; exit 1; }

if [[ ! -d "${SEEDS_DIR}" || -z "$(ls -A "${SEEDS_DIR}" 2>/dev/null)" ]]; then
    echo "[fuzz_parse] generating seed corpus"
    python3 "${REPO_ROOT}/fuzz/harness/gen_file_seeds.py"
    python3 "${REPO_ROOT}/fuzz/harness/gen_pixel_seeds.py"
fi
if [[ ! -f "${DICT_PATH}" ]]; then
    echo "[fuzz_parse] building dictionary"
    python3 "${REPO_ROOT}/fuzz/harness/build_dict.py"
fi

mkdir -p "${OUT_DIR}"
export ASAN_OPTIONS="abort_on_error=1:symbolize=0:detect_leaks=0:halt_on_error=1"
export DCMDICTPATH="${REPO_ROOT}/fuzz/dcmtk/dcmdata/data/dicom.dic"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

if [[ -f "${OUT_DIR}/fuzzer_stats" || -f "${OUT_DIR}/default/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_parse] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_parse] starting fresh campaign in ${OUT_DIR}"
fi

# SAND mode (scripts/build_dcmtk.sh SAND=1): when sanitizer-worker trees
# exist under fuzz/build-san-*/, route suspicious inputs to them via -w —
# DCMDUMP is then the fast native loop binary. No workers → the plain
# single-binary loop, unchanged. See https://aflplus.plus/docs/sand/.
SAND_ARGS=()
for wdir in "${REPO_ROOT}"/fuzz/build-san-*/; do
    [[ -d "${wdir}" ]] || continue
    worker="$(find "${wdir}" -type f -name dcmdump -executable | head -1)"
    if [[ -n "${worker}" ]]; then
        SAND_ARGS+=(-w "${worker}")
        echo "[fuzz_parse] SAND worker: ${worker}"
    fi
done

exec "${AFLPP_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -x "${DICT_PATH}" \
    -m none \
    "${SAND_ARGS[@]}" \
    -- "${DCMDUMP}" @@
