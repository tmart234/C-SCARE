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
# let this script try to build AFL++'s libdesock (candidates/builder come from
# the desock block of fuzz/targets/scu.yaml).
#
# This is the most experimental of the four quadrants - validate a real run
# before relying on it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"
load_profile scu
source_afl

find_binary fuzz_scu

# --- resolve a desocket shim (candidates/builder from the profile) -----------
# Expand {{AFLPP_PATH}} (known only here) on top of profile_lib's substitution.
_scu_expand() { local s="${1//\{\{AFLPP_PATH\}\}/${AFLPP_PATH}}"; printf '%s' "${s//\{\{REPO_ROOT\}\}/${REPO_ROOT}}"; }
mapfile -t DESOCK_CANDIDATES < <(yq -r '.desock.candidates[]?' "${PROFILE_FILE}" 2>/dev/null || true)
DESOCK_BUILDER="$(_scu_expand "$(yq -r '.desock.builder // ""' "${PROFILE_FILE}" 2>/dev/null || true)")"

DESOCK_SO="${DESOCK_SO:-}"
if [[ -z "${DESOCK_SO}" ]]; then
    for cand in "${DESOCK_CANDIDATES[@]}"; do
        cand="$(_scu_expand "${cand}")"
        [[ -f "${cand}" ]] && DESOCK_SO="${cand}" && break
    done
fi
if [[ -z "${DESOCK_SO}" && -n "${DESOCK_BUILDER}" && -x "${DESOCK_BUILDER}" ]]; then
    echo "[fuzz_scu] building AFL++ libdesock"
    ( cd "$(dirname "${DESOCK_BUILDER}")" && ./"$(basename "${DESOCK_BUILDER}")" ) || true
    for cand in "${DESOCK_CANDIDATES[@]}"; do
        cand="$(_scu_expand "${cand}")"
        [[ -f "${cand}" ]] && DESOCK_SO="${cand}" && break
    done
fi
if [[ -z "${DESOCK_SO}" || ! -f "${DESOCK_SO}" ]]; then
    if [[ -z "${CSCARE_PRINT_ARGV:-}" ]]; then
        echo "[fuzz_scu] no desocket shim found."
        echo "[fuzz_scu] build AFL++ libdesock (fuzz/aflplusplus/utils/libdesock)"
        echo "[fuzz_scu] or preeny, then re-run with DESOCK_SO=/path/to/desock.so"
        exit 1
    fi
    DESOCK_SO="__DESOCK_SO__"   # placeholder for golden argv
fi
echo "[fuzz_scu] desock shim: ${DESOCK_SO}"

# --- seed corpus: server-response streams ------------------------------------
# Seeds are what storescu *receives*. C-SCARE crafts the starting points;
# AFL mutates from there.
if [[ -z "${CSCARE_PRINT_ARGV:-}" ]]; then
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

    # --- a DICOM object for storescu to "send" (writes discarded by desock) ---
    if [[ ! -f "${SEND_FILE}" ]]; then
        python3 "${REPO_ROOT}/fuzz/harness/gen_file_seeds.py" file
    fi
fi

mkdir -p "${OUT_DIR}"
# load_profile exported ASAN_OPTIONS/DCMDICTPATH/AFL_* from the profile.
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
# Profile argv: -aec <called_ae> <peer_host> <peer_port> {{SENDFILE}}.
afl_exec "${AFLPP_PATH}/afl-fuzz" \
    -i "${INPUT_ARG}" \
    -o "${OUT_DIR}" \
    -m none \
    -- "${BIN_PATH}" "${ARGV[@]}"
