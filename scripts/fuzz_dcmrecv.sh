#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 4 (variant): launch AFLNet against the ASAN-instrumented dcmrecv.
#
# dcmrecv is a C-STORE SCP (storage receiver). Same AFLNet flag set as
# fuzz_net.sh — only the binary, port, and seed dir differ, all of which come
# from the declarative profile fuzz/targets/net-dcmrecv.yaml.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
load_profile net-dcmrecv
source_afl
# shellcheck source=scripts/aflnet_common.sh
source "${REPO_ROOT}/scripts/aflnet_common.sh"

find_binary fuzz_dcmrecv

if [[ -z "${CSCARE_PRINT_ARGV:-}" && ( ! -d "${SEEDS_DIR}" || -z "$(find "${SEEDS_DIR}" -maxdepth 1 -name "${SEEDS_GLOB}" -print -quit 2>/dev/null)" ) ]]; then
    echo "[fuzz_dcmrecv] generating network seeds"
    run_seed_generators
fi

mkdir -p "${OUT_DIR}" "${STORAGE_DIR}"
# load_profile exported ASAN_OPTIONS/DCMDICTPATH/AFL_* from the profile.
# symbolize=0 is mandatory: AFLNet's afl-fuzz check_asan_opts() FATALs on a
# custom ASAN_OPTIONS that omits it. Crash traces are symbolized at triage
# time instead (see c_scare/greybox.py).

if [[ -f "${OUT_DIR}/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_dcmrecv] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_dcmrecv] starting fresh campaign in ${OUT_DIR}"
fi

# dcmrecv writes received instances under --output-directory (profile argv
# {{STORAGE}}). AFLNet options come from scripts/aflnet_common.sh (includes -E).
afl_exec "${AFL_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -N "tcp://127.0.0.1/${PORT}" \
    "${AFLNET_FUZZ_OPTS[@]}" \
    -- "${BIN_PATH}" "${ARGV[@]}"
