#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 1: Build DCMTK with afl-clang-fast + ASAN.
#
# Pinned to DCMTK-3.6.8. Out-of-tree build under fuzz/build-asan/.
# Targets dcm2pnm (primary fuzz target — exercises parser + pixel pipeline)
# and dcmconv (smoke test). storescp is also built for Phase 4 network fuzzing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DCMTK_SRC="${REPO_ROOT}/fuzz/dcmtk"
BUILD_DIR="${REPO_ROOT}/fuzz/build-asan"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

if [[ ! -f "${DCMTK_SRC}/CMakeLists.txt" ]]; then
    echo "[build_dcmtk] DCMTK submodule not initialized at ${DCMTK_SRC}"
    echo "[build_dcmtk] run: git submodule update --init fuzz/dcmtk"
    exit 1
fi

# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/install_afl.sh"

if [[ ! -x "${AFL_PATH:-}/afl-gcc" ]]; then
    echo "[build_dcmtk] AFL_PATH/afl-gcc missing — install_afl.sh did not export AFL_PATH"
    exit 1
fi

# Use afl-gcc / afl-g++ via absolute path. Modern clang's integrated
# assembler bypasses afl-as so afl-clang doesn't instrument; system gcc
# still spawns external 'as' and works correctly with AFL's wrapper.
# afl-clang-fast (LLVM pass) would be faster but doesn't build against
# LLVM 14+ on this AFLNet pin — see install_afl.sh.
export CC="${AFL_PATH}/afl-gcc"
export CXX="${AFL_PATH}/afl-g++"
export AFL_USE_ASAN=1
export AFL_QUIET=1
# AFL_HARDEN intentionally unset — mutually exclusive with AFL_USE_ASAN.
export CFLAGS="-g -O1 -fno-omit-frame-pointer"
export CXXFLAGS="${CFLAGS}"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake "${DCMTK_SRC}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_APPS=ON \
    -DDCMTK_WITH_TIFF=OFF \
    -DDCMTK_WITH_PNG=OFF \
    -DDCMTK_WITH_OPENSSL=OFF \
    -DDCMTK_WITH_SNDFILE=OFF \
    -DDCMTK_WITH_ICONV=OFF \
    -DDCMTK_WITH_ICU=OFF \
    -DDCMTK_WITH_XML=OFF \
    -DDCMTK_WITH_ZLIB=ON \
    -DDCMTK_ENABLE_PRIVATE_TAGS=ON \
    -DDCMTK_ENABLE_CHARSET_CONVERSION=OFF \
    -DDCMTK_WITH_THREADS=ON

cmake --build . --parallel "${JOBS}" --target dcm2pnm dcmconv storescp

echo "[build_dcmtk] built:"
for bin in dcm2pnm dcmconv storescp; do
    path=$(find "${BUILD_DIR}" -type f -name "${bin}" -executable | head -1)
    if [[ -n "${path}" ]]; then
        echo "  ${path}"
    else
        echo "  ${bin}: MISSING"
    fi
done
