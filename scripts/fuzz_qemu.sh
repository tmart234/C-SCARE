#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Grey-box fuzzing of an UNINSTRUMENTED binary via AFL++ QEMU mode (-Q).
#
# QEMU mode instruments the target at runtime, so it fuzzes prebuilt /
# vendor-shipped binaries - the official DCMTK 3.6.7 release, or your own
# .so-backed binaries - with NO recompilation. It is ~2-5x slower than
# compiled instrumentation; use it when rebuilding the target is impractical.
#
# Usage:
#   scripts/fuzz_qemu.sh <binary> [args...]
#       Put @@ where the input file goes; if omitted it is appended.
#
# Example - fuzz a prebuilt DCMTK 3.6.7 dcm2pnm:
#   scripts/fuzz_qemu.sh /opt/dcmtk-3.6.7/bin/dcm2pnm @@ /tmp/out.pnm
#
# Env: SEEDS_DIR (default fuzz/seeds/file), OUT_DIR (default fuzz/out/qemu).
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <binary> [args...]   (@@ = input file)"
    exit 2
fi

TARGET_BIN="$1"; shift
TARGET_ARGS=("$@")
[[ ${#TARGET_ARGS[@]} -eq 0 ]] && TARGET_ARGS=("@@")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEEDS_DIR="${SEEDS_DIR:-${REPO_ROOT}/fuzz/seeds/file}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/fuzz/out/qemu}"

command -v "${TARGET_BIN}" >/dev/null 2>&1 || [[ -x "${TARGET_BIN}" ]] || {
    echo "[fuzz_qemu] target not found / not executable: ${TARGET_BIN}"
    exit 1
}

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

# QEMU mode needs afl-qemu-trace, built once via AFL++'s helper script.
if [[ ! -x "${AFLPP_PATH}/afl-qemu-trace" ]]; then
    echo "[fuzz_qemu] building AFL++ QEMU mode (one-time, ~10 min)"
    ( cd "${AFLPP_PATH}/qemu_mode" && ./build_qemu_support.sh )
fi
[[ -x "${AFLPP_PATH}/afl-qemu-trace" ]] || {
    echo "[fuzz_qemu] afl-qemu-trace missing — QEMU mode build failed"
    exit 1
}

if [[ ! -d "${SEEDS_DIR}" || -z "$(ls -A "${SEEDS_DIR}" 2>/dev/null)" ]]; then
    echo "[fuzz_qemu] generating seed corpus"
    python3 "${REPO_ROOT}/fuzz/harness/gen_file_seeds.py"
fi

mkdir -p "${OUT_DIR}"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

if [[ -f "${OUT_DIR}/fuzzer_stats" || -f "${OUT_DIR}/default/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_qemu] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_qemu] starting fresh campaign in ${OUT_DIR}"
fi

echo "[fuzz_qemu] QEMU-mode fuzzing (no instrumentation needed): ${TARGET_BIN}"
exec "${AFLPP_PATH}/afl-fuzz" \
    -Q \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -m none \
    -- "${TARGET_BIN}" "${TARGET_ARGS[@]}"
