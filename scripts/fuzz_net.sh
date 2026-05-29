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
#
# Per-target values (binary, port, seeds/out dirs, env, argv) come from the
# declarative profile fuzz/targets/net-storescp.yaml via scripts/profile_lib.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
load_profile net-storescp
source_afl
# shellcheck source=scripts/aflnet_common.sh
source "${REPO_ROOT}/scripts/aflnet_common.sh"

find_binary fuzz_net

if [[ -z "${CSCARE_PRINT_ARGV:-}" && ( ! -d "${SEEDS_DIR}" || -z "$(find "${SEEDS_DIR}" -maxdepth 1 -name "${SEEDS_GLOB}" -print -quit 2>/dev/null)" ) ]]; then
    echo "[fuzz_net] generating network seeds"
    run_seed_generators
fi

mkdir -p "${OUT_DIR}"
# load_profile exported ASAN_OPTIONS/DCMDICTPATH/AFL_* from the profile.
# symbolize=0 is mandatory: AFLNet's afl-fuzz check_asan_opts() FATALs on a
# custom ASAN_OPTIONS that omits it. Crash traces are symbolized at triage
# time instead (see c_scare/greybox.py).

# Resume if a prior session exists; else start fresh.
if [[ -f "${OUT_DIR}/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_net] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_net] starting fresh campaign in ${OUT_DIR}"
fi

# AFLNet options (-P/-D/-W/-m/-E/-q) come from scripts/aflnet_common.sh so
# every network harness shares one definition; -E (state-aware mode) is
# mandatory — see that file.
afl_exec "${AFL_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -N "tcp://127.0.0.1/${PORT}" \
    "${AFLNET_FUZZ_OPTS[@]}" \
    -- "${BIN_PATH}" "${ARGV[@]}"
