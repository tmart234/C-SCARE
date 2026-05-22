#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Bootstrap both AFL forks under fuzz/ and expose their toolchains.
#
# AFLNet is network-only at this commit (afl-fuzz FATALs without -N/-P), so
# we use it strictly for the network campaigns (Phase 4): storescp /
# dcmrecv / dcmqrscp. As an AFL-2.x fork it only drives afl-as/afl-gcc
# instrumentation, so scripts/build_dcmtk.sh builds those targets with its
# afl-gcc into fuzz/build-net.
#
# AFL++ is the file-fuzzing fuzzer (Phase 1-2 dcm2pnm campaign): modern
# mutators, dictionary support (-x), and ASAN integration via its own
# afl-clang-fast. scripts/build_dcmtk.sh uses afl-clang-fast (LLVM mode)
# for the file/SCU targets into fuzz/build-llvm.
#
# Exports:
#   AFL_PATH      — AFLNet directory (also the conventional AFL env var,
#                   used by afl-as when invoked from afl-gcc).
#   AFLPP_PATH    — AFL++ directory.
#
# Usage:
#   source scripts/install_afl.sh   # exports paths for the parent shell
#   ./scripts/install_afl.sh        # idempotent build, then exit
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AFLNET_DIR="${REPO_ROOT}/fuzz/aflnet"
AFLNET_PIN="96032f8"
AFLPP_DIR="${REPO_ROOT}/fuzz/aflplusplus"
AFLPP_PIN="v4.40c"

if [[ ! -d "${AFLNET_DIR}/.git" && ! -f "${AFLNET_DIR}/Makefile" ]]; then
    echo "[install_afl] AFLNet submodule not initialized at ${AFLNET_DIR}"
    echo "[install_afl] run: git submodule update --init fuzz/aflnet"
    return 1 2>/dev/null || exit 1
fi

if [[ ! -d "${AFLPP_DIR}/.git" && ! -f "${AFLPP_DIR}/Makefile" ]]; then
    echo "[install_afl] AFL++ submodule not initialized at ${AFLPP_DIR}"
    echo "[install_afl] run: git submodule update --init fuzz/aflplusplus"
    return 1 2>/dev/null || exit 1
fi

# AFLNet (network-only): afl-gcc / afl-fuzz / aflnet-replay via afl-as.
# llvm_mode intentionally skipped — it doesn't build against LLVM 14+.
if [[ ! -x "${AFLNET_DIR}/afl-fuzz" ]]; then
    echo "[install_afl] building AFLNet at ${AFLNET_DIR} (pin: ${AFLNET_PIN})"
    pushd "${AFLNET_DIR}" >/dev/null
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        current="$(git rev-parse --short HEAD)"
        if [[ "${current}" != "${AFLNET_PIN}"* ]]; then
            echo "[install_afl] WARNING: AFLNet at ${current}, expected ${AFLNET_PIN}"
        fi
    fi
    make clean all
    popd >/dev/null
fi

# AFL++: file-fuzzing toolchain. afl-clang-fast / afl-fuzz / afl-cmin / etc.
if [[ ! -x "${AFLPP_DIR}/afl-fuzz" || ! -x "${AFLPP_DIR}/afl-clang-fast" ]]; then
    echo "[install_afl] building AFL++ at ${AFLPP_DIR} (pin: ${AFLPP_PIN})"
    pushd "${AFLPP_DIR}" >/dev/null
    make all
    popd >/dev/null
fi

export AFL_PATH="${AFLNET_DIR}"
export AFLPP_PATH="${AFLPP_DIR}"
# Intentionally NOT prepending these to $PATH. AFLNet's directory contains
# an 'as' symlink (afl-as wrapper); putting it on PATH causes gcc's 'as'
# invocation to recursively resolve to afl-as → infinite loop. Scripts
# must invoke AFL tools via "${AFL_PATH}/..." or "${AFLPP_PATH}/..." .

echo "[install_afl] AFL_PATH=${AFL_PATH}    (AFLNet, network track)"
echo "[install_afl] AFLPP_PATH=${AFLPP_PATH}  (AFL++, file track)"
for tool in afl-gcc afl-g++ afl-fuzz aflnet-replay; do
    [[ -x "${AFL_PATH}/${tool}" ]] && echo "[install_afl]   ${tool}: ok" \
        || echo "[install_afl]   ${tool}: MISSING"
done
for tool in afl-fuzz afl-clang-fast afl-cmin afl-tmin; do
    [[ -x "${AFLPP_PATH}/${tool}" ]] && echo "[install_afl]   aflpp/${tool}: ok" \
        || echo "[install_afl]   aflpp/${tool}: MISSING"
done
