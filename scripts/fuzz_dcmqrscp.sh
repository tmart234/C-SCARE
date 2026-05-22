#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 4 (variant): launch AFLNet against the ASAN-instrumented dcmqrscp.
#
# dcmqrscp is a Q/R SCP — accepts C-FIND / C-MOVE / C-GET in addition to
# verification. It requires a config file naming the AE titles and storage
# area; we generate it from fuzz/configs/dcmqrscp.cfg.template at launch.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/fuzz/build-net"
SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/net-dcmqrscp"
OUT_DIR="${REPO_ROOT}/fuzz/out/net-dcmqrscp"
STORAGE_DIR="${REPO_ROOT}/fuzz/storage/dcmqrscp"
CFG_TEMPLATE="${REPO_ROOT}/fuzz/configs/dcmqrscp.cfg.template"
CFG_RUNTIME="${REPO_ROOT}/fuzz/configs/dcmqrscp.cfg"
PORT="${DICOM_PORT:-11114}"

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"
# shellcheck source=scripts/aflnet_common.sh
source "${REPO_ROOT}/scripts/aflnet_common.sh"

DCMQRSCP="$(find "${BUILD_DIR}" -type f -name dcmqrscp -executable | head -1)"
[[ -n "${DCMQRSCP}" ]] || { echo "[fuzz_dcmqrscp] dcmqrscp not built"; exit 1; }

if [[ ! -d "${SEEDS_DIR}" || -z "$(find "${SEEDS_DIR}" -maxdepth 1 -name '*.raw' -print -quit 2>/dev/null)" ]]; then
    echo "[fuzz_dcmqrscp] generating network seeds"
    python3 "${REPO_ROOT}/fuzz/harness/seed_serializer.py"
fi

mkdir -p "${OUT_DIR}" "${STORAGE_DIR}"

# Substitute repo-relative paths into the config so it works on any host.
sed "s|@REPO_ROOT@|${REPO_ROOT}|g" "${CFG_TEMPLATE}" > "${CFG_RUNTIME}"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:halt_on_error=1"
export DCMDICTPATH="${REPO_ROOT}/fuzz/dcmtk/dcmdata/data/dicom.dic"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

if [[ -f "${OUT_DIR}/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_dcmqrscp] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_dcmqrscp] starting fresh campaign in ${OUT_DIR}"
fi

# AFLNet options come from scripts/aflnet_common.sh (shared, includes -E).
exec "${AFL_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -N "tcp://127.0.0.1/${PORT}" \
    "${AFLNET_FUZZ_OPTS[@]}" \
    -- "${DCMQRSCP}" -c "${CFG_RUNTIME}" "${PORT}"
