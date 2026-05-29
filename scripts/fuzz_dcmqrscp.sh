#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 4 (variant): launch AFLNet against the ASAN-instrumented dcmqrscp.
#
# dcmqrscp is a Q/R SCP — accepts C-FIND / C-MOVE / C-GET in addition to
# verification. It requires a config file naming the AE titles and storage
# area; we render it from fuzz/configs/dcmqrscp.cfg.template at launch using
# the AE titles from the profile fuzz/targets/net-dcmqrscp.yaml — the SAME AE
# titles the seed A-ASSOCIATE-RQ carries, so the SCP recognises the peer.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
load_profile net-dcmqrscp
source_afl
# shellcheck source=scripts/aflnet_common.sh
source "${REPO_ROOT}/scripts/aflnet_common.sh"

find_binary fuzz_dcmqrscp

if [[ -z "${CSCARE_PRINT_ARGV:-}" && ( ! -d "${SEEDS_DIR}" || -z "$(find "${SEEDS_DIR}" -maxdepth 1 -name "${SEEDS_GLOB}" -print -quit 2>/dev/null)" ) ]]; then
    echo "[fuzz_dcmqrscp] generating network seeds"
    run_seed_generators
fi

mkdir -p "${OUT_DIR}" "${STORAGE_DIR}"

# Substitute repo-relative paths + AE titles into the config so it works on any
# host and agrees with the seed association. @CALLING_AE@/@CALLED_AE@ come from
# the profile (see fuzz/configs/dcmqrscp.cfg.template).
if [[ -z "${CSCARE_PRINT_ARGV:-}" ]]; then
    sed -e "s|@REPO_ROOT@|${REPO_ROOT}|g" \
        -e "s|@CALLING_AE@|${CALLING_AE}|g" \
        -e "s|@CALLED_AE@|${CALLED_AE}|g" \
        "${CFG_TEMPLATE}" > "${CFG_RUNTIME}"
fi

# load_profile exported ASAN_OPTIONS/DCMDICTPATH/AFL_* from the profile.
# symbolize=0 is mandatory: AFLNet's afl-fuzz check_asan_opts() FATALs on a
# custom ASAN_OPTIONS that omits it. Crash traces are symbolized at triage
# time instead (see c_scare/greybox.py).

if [[ -f "${OUT_DIR}/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_dcmqrscp] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_dcmqrscp] starting fresh campaign in ${OUT_DIR}"
fi

# AFLNet options come from scripts/aflnet_common.sh (shared, includes -E).
# The profile argv carries {{CONFIG}} {{PORT}} -> -c <cfg> <port>.
afl_exec "${AFL_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -N "tcp://127.0.0.1/${PORT}" \
    "${AFLNET_FUZZ_OPTS[@]}" \
    -- "${BIN_PATH}" "${ARGV[@]}"
