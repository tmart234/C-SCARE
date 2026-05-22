#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Quadrant 4 - SCU (client) grey-box fuzzing.   *** EXPERIMENTAL ***
#
# AFLNet fuzzes servers; to fuzz a *client* the fuzzer must instead supply
# the bytes the client receives. This harness instruments storescu (DCMTK's
# DICOM SCU) and preloads a desocket shim so the client's socket reads are
# served from AFL's input. AFL then mutates the *server-response* stream
# with coverage feedback over storescu's response-parsing code.
#
# Needs a desocket shim beyond the standard build. AFL++ ships one in
# utils/libdesock; preeny's desock.so also works. Point DESOCK_SO at it, or
# let this script try to build AFL++'s libdesock.
#
# This is the most experimental of the four quadrants - validate a real run
# before relying on it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/fuzz/build-llvm"
SEEDS_DIR="${REPO_ROOT}/fuzz/seeds/scu"
FILE_SEEDS="${REPO_ROOT}/fuzz/seeds/file"
OUT_DIR="${REPO_ROOT}/fuzz/out/scu"

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

STORESCU="$(find "${BUILD_DIR}" -type f -name storescu -executable | head -1)"
[[ -n "${STORESCU}" ]] || { echo "[fuzz_scu] storescu not built — run scripts/build_dcmtk.sh"; exit 1; }

# --- resolve a desocket shim -------------------------------------------------
DESOCK_SO="${DESOCK_SO:-}"
if [[ -z "${DESOCK_SO}" ]]; then
    for cand in \
        "${AFLPP_PATH}/utils/libdesock/libdesock.so" \
        "${AFLPP_PATH}/utils/libdesock/build/libdesock.so"; do
        [[ -f "${cand}" ]] && DESOCK_SO="${cand}" && break
    done
fi
if [[ -z "${DESOCK_SO}" && -x "${AFLPP_PATH}/utils/libdesock/build.sh" ]]; then
    echo "[fuzz_scu] building AFL++ libdesock"
    ( cd "${AFLPP_PATH}/utils/libdesock" && ./build.sh ) || true
    for cand in \
        "${AFLPP_PATH}/utils/libdesock/libdesock.so" \
        "${AFLPP_PATH}/utils/libdesock/build/libdesock.so"; do
        [[ -f "${cand}" ]] && DESOCK_SO="${cand}" && break
    done
fi
if [[ -z "${DESOCK_SO}" || ! -f "${DESOCK_SO}" ]]; then
    echo "[fuzz_scu] no desocket shim found."
    echo "[fuzz_scu] build AFL++ libdesock (fuzz/aflplusplus/utils/libdesock)"
    echo "[fuzz_scu] or preeny, then re-run with DESOCK_SO=/path/to/desock.so"
    exit 1
fi
echo "[fuzz_scu] desock shim: ${DESOCK_SO}"

# --- seed corpus: server-response streams ------------------------------------
# Seeds are what storescu *receives*. C-SCARE crafts the starting points;
# AFL mutates from there.
if [[ ! -d "${SEEDS_DIR}" || -z "$(ls -A "${SEEDS_DIR}" 2>/dev/null)" ]]; then
    echo "[fuzz_scu] generating SCU response seeds via c_scare"
    mkdir -p "${SEEDS_DIR}"
    python3 - "${SEEDS_DIR}" <<'PY'
import sys
from c_scare.scapy_dicom import DICOM, A_ASSOCIATE_AC, A_ABORT
from scapy.packet import raw
out = sys.argv[1]
with open(f"{out}/assoc_ac.raw", "wb") as f:
    f.write(raw(DICOM() / A_ASSOCIATE_AC()))
with open(f"{out}/abort.raw", "wb") as f:
    f.write(raw(DICOM() / A_ABORT()))
PY
fi

# --- a DICOM object for storescu to "send" (writes discarded by desock) ------
if [[ ! -f "${FILE_SEEDS}/baseline_explicit_le.dcm" ]]; then
    python3 "${REPO_ROOT}/fuzz/harness/gen_file_seeds.py"
fi
SEND_FILE="${FILE_SEEDS}/baseline_explicit_le.dcm"

mkdir -p "${OUT_DIR}"
export ASAN_OPTIONS="abort_on_error=1:symbolize=0:detect_leaks=0:halt_on_error=1"
export DCMDICTPATH="${REPO_ROOT}/fuzz/dcmtk/dcmdata/data/dicom.dic"
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
# desock routes storescu's socket reads to AFL's stdin input.
export AFL_PRELOAD="${DESOCK_SO}"

if [[ -f "${OUT_DIR}/fuzzer_stats" || -f "${OUT_DIR}/default/fuzzer_stats" ]]; then
    INPUT_ARG="-"
    echo "[fuzz_scu] resuming campaign in ${OUT_DIR}"
else
    INPUT_ARG="${SEEDS_DIR}"
    echo "[fuzz_scu] starting fresh campaign in ${OUT_DIR}"
fi

# storescu connects to peer:port (faked by desock) and sends SEND_FILE; the
# bytes it reads back - the server responses - are fuzzed by AFL via stdin.
exec "${AFLPP_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -m none \
    -- "${STORESCU}" -aec ANY-SCP 127.0.0.1 11112 "${SEND_FILE}"
