#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Replay an AFLNet seed (or a mutated/crashing input from out/net/) against
# any DICOM target — local or remote, instrumented or production.
#
# This is the bridge between the local fuzzing toolchain and a real DICOM
# device. Same .raw seed bytes; only the target endpoint changes.
#
# Usage:
#   scripts/replay_seed.sh <seed.raw> [host] [port]
#
# Examples:
#   scripts/replay_seed.sh fuzz/seeds/net/echo.raw            # localhost:11112
#   scripts/replay_seed.sh fuzz/out/net/default/crashes/id... 10.0.1.42 104
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "Usage: $0 <seed.raw> [host=127.0.0.1] [port=11112]"
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED="$1"
HOST="${2:-127.0.0.1}"
PORT="${3:-11112}"

[[ -f "${SEED}" ]] || { echo "[replay] seed not found: ${SEED}"; exit 1; }

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

REPLAY="${AFL_PATH}/aflnet-replay"
[[ -x "${REPLAY}" ]] || { echo "[replay] aflnet-replay missing"; exit 1; }

echo "[replay] sending $(wc -c <"${SEED}") bytes from ${SEED} to ${HOST}:${PORT}"
"${REPLAY}" "${SEED}" DICOM "${PORT}" "${HOST}"
