#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 4 (variant): launch AFLNet against the ASAN-instrumented dcmrecv.
#
# dcmrecv is a C-STORE SCP (storage receiver). Same AFLNet flag set as
# fuzz_net.sh — only the binary, port, and seed dir differ.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/fuzz/build-net"
SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/net-dcmrecv"
OUT_DIR="${REPO_ROOT}/fuzz/out/net-dcmrecv"
STORAGE_DIR="${REPO_ROOT}/fuzz/storage/dcmrecv"
PORT="${DICOM_PORT:-11113}"

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

DCMRECV="$(find "${BUILD_DIR}" -type f -name dcmrecv -executable | head -1)"
[[ -n "${DCMRECV}" ]] || { echo "[fuzz_dcmrecv] dcmrecv not built"; exit 1; }

if [[ ! -d "${SEEDS_DIR}" || -z "$(find "${SEEDS_DIR}" -maxdepth 1 -name '*.raw' -print -quit 2>/dev/null)" ]]; then
    echo "[fuzz_dcmrecv] generating network seeds"
    python3 "${REPO_ROOT}/fuzz/harness/seed_serializer.py"
fi

mkdir -p "${OUT_DIR}" "${STORAGE_DIR}"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:halt_on_error=1"
export DCMDICTPATH="${REPO_ROOT}/fuzz/dcmtk/dcmdata/data/dicom.dic"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

if [[ -f "${OUT_DIR}/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_dcmrecv] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_dcmrecv] starting fresh campaign in ${OUT_DIR}"
fi

# dcmrecv writes received instances under --output-directory. Point it at a
# scratch dir so AFLNet's per-execution storms don't fill the repo tree.
exec "${AFL_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -N "tcp://127.0.0.1/${PORT}" \
    -P DICOM \
    -D 10000 \
    -W 30 \
    -m none \
    -E \
    -q 3 \
    -- "${DCMRECV}" "${PORT}" --output-directory "${STORAGE_DIR}" --eostudy-timeout 1
