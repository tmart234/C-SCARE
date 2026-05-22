#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 4: launch AFLNet against the ASAN-instrumented storescp.
#
# AFLNet at this commit ships a built-in DICOM parser (-P DICOM) that
# segments seeds on the PDU header (1B type + 1B reserved + 4B BE length).
# This is what Phase 5 of the plan called for — already done upstream, so
# we use it from day one.
#
# storescp is launched by AFL inside the harness (we DON'T run a separate
# server). AFL spawns it per-execution; --eostudy-timeout/--single-process
# keep it bounded.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/fuzz/build-net"
SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/net-storescp"
OUT_DIR="${REPO_ROOT}/fuzz/out/net-storescp"
PORT="${DICOM_PORT:-11112}"

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

STORESCP="$(find "${BUILD_DIR}" -type f -name storescp -executable | head -1)"
[[ -n "${STORESCP}" ]] || { echo "[fuzz_net] storescp not built"; exit 1; }

if [[ ! -d "${SEEDS_DIR}" || -z "$(find "${SEEDS_DIR}" -maxdepth 1 -name '*.raw' -print -quit 2>/dev/null)" ]]; then
    echo "[fuzz_net] generating network seeds"
    python3 "${REPO_ROOT}/fuzz/harness/seed_serializer.py"
fi

mkdir -p "${OUT_DIR}"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:halt_on_error=1"
export DCMDICTPATH="${REPO_ROOT}/fuzz/dcmtk/dcmdata/data/dicom.dic"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

# Resume if a prior session exists; else start fresh.
if [[ -f "${OUT_DIR}/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_net] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_net] starting fresh campaign in ${OUT_DIR}"
fi

# AFLNet flags:
#   -N tcp://...    target socket address (informs AFLNet, not bound by it)
#   -D 10000        wait (us) for the SCP to initialize before the first request
#   -W 30           wait (ms) for response after sending each message
#   -m none         no memory limit (ASAN needs ample VM)
#   -E              state-aware mode: build the IPSM from server responses.
#                   Required — AFLNet defaults the seed schedule to IPSM
#                   (-h 2), which afl-fuzz rejects unless -E is set.
#   -q 3            state selection algorithm: FAVOR. Only takes effect in
#                   state-aware mode.
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
    -- "${STORESCP}" "${PORT}" --eostudy-timeout 1
