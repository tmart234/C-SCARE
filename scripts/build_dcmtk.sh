#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 1: Build DCMTK with afl-gcc + sanitizers.
#
# Source resolution (device-build parity):
#   DCMTK_SRC_DIR  — absolute path to operator-supplied DCMTK tree.
#                    When set, the submodule and DCMTK_REF are ignored.
#   DCMTK_REF      — git ref/tag/SHA to check out inside the submodule.
#                    Ignored if DCMTK_SRC_DIR is set.
#
# Compile flags:
#   OPT_LEVEL       — defaults to -O1 (ASAN-friendly).
#   EXTRA_CFLAGS    — appended to CFLAGS / CXXFLAGS verbatim.
#   EXTRA_CMAKE_ARGS — extra CMake -D args (whitespace-separated).
#   SANITIZERS      — comma list. Recognised: address, undefined, memory.
#                    Default: address.
#
# Out-of-tree build dir: fuzz/build-asan/. Records provenance to
# build_manifest.txt (consumed by scripts/campaign.sh run.json).
#
# Targets dcm2pnm / dcmdump (file + parser fuzz), dcmconv (smoke),
# storescu (SCU/client fuzz), storescp / dcmrecv / dcmqrscp (network fuzz).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DCMTK_SRC="${DCMTK_SRC_DIR:-${REPO_ROOT}/fuzz/dcmtk}"
BUILD_DIR="${REPO_ROOT}/fuzz/build-asan"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
USING_SUBMODULE=0
[[ "${DCMTK_SRC}" == "${REPO_ROOT}/fuzz/dcmtk" ]] && USING_SUBMODULE=1

if [[ ! -f "${DCMTK_SRC}/CMakeLists.txt" ]]; then
    if [[ "${USING_SUBMODULE}" == 1 ]]; then
        echo "[build_dcmtk] DCMTK submodule not initialized at ${DCMTK_SRC}"
        echo "[build_dcmtk] run: git submodule update --init fuzz/dcmtk"
    else
        echo "[build_dcmtk] DCMTK_SRC_DIR='${DCMTK_SRC}' has no CMakeLists.txt"
    fi
    exit 1
fi

# DCMTK_REF only honoured for the submodule; never touch an operator-supplied tree.
if [[ "${USING_SUBMODULE}" == 1 && -n "${DCMTK_REF:-}" ]]; then
    if [[ -d "${DCMTK_SRC}/.git" ]]; then
        echo "[build_dcmtk] checking out DCMTK ref ${DCMTK_REF}"
        git -C "${DCMTK_SRC}" fetch --tags --quiet
        git -C "${DCMTK_SRC}" checkout --quiet "${DCMTK_REF}"
    else
        echo "[build_dcmtk] DCMTK_REF set but ${DCMTK_SRC} is not a git checkout"
        exit 1
    fi
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
export AFL_QUIET=1

# SANITIZERS → AFL_USE_* env vars. AFL_HARDEN intentionally never set;
# it's mutually exclusive with the sanitizers.
SANITIZERS="${SANITIZERS:-address}"
unset AFL_USE_ASAN AFL_USE_UBSAN AFL_USE_MSAN
IFS=',' read -ra _SAN <<<"${SANITIZERS}"
for s in "${_SAN[@]}"; do
    case "${s// /}" in
        address)   export AFL_USE_ASAN=1 ;;
        undefined) export AFL_USE_UBSAN=1 ;;
        memory)    export AFL_USE_MSAN=1 ;;
        "")        ;;
        *)         echo "[build_dcmtk] unknown sanitizer '${s}'"; exit 1 ;;
    esac
done

OPT_LEVEL="${OPT_LEVEL:--O1}"
export CFLAGS="-g ${OPT_LEVEL} -fno-omit-frame-pointer ${EXTRA_CFLAGS:-}"
export CXXFLAGS="${CFLAGS}"

EXTRA_ARGS=()
if [[ -n "${EXTRA_CMAKE_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    read -ra EXTRA_ARGS <<<"${EXTRA_CMAKE_ARGS}"
fi

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
    -DDCMTK_WITH_THREADS=ON \
    "${EXTRA_ARGS[@]}"

TARGETS=(dcm2pnm dcmconv dcmdump storescu storescp dcmrecv dcmqrscp)
cmake --build . --parallel "${JOBS}" --target "${TARGETS[@]}"

# Provenance manifest — consumed by scripts/campaign.sh.
MANIFEST="${BUILD_DIR}/build_manifest.txt"
{
    echo "build_timestamp_utc=$(date -u +%FT%TZ)"
    echo "dcmtk_src=${DCMTK_SRC}"
    if [[ -d "${DCMTK_SRC}/.git" ]]; then
        echo "dcmtk_sha=$(git -C "${DCMTK_SRC}" rev-parse HEAD 2>/dev/null || echo unknown)"
        echo "dcmtk_describe=$(git -C "${DCMTK_SRC}" describe --tags --always --dirty 2>/dev/null || echo unknown)"
    else
        echo "dcmtk_sha=unknown"
        echo "dcmtk_describe=unknown"
    fi
    echo "compiler=${CC}"
    echo "compiler_version=$("${CC}" --version 2>/dev/null | head -1)"
    echo "cflags=${CFLAGS}"
    echo "cxxflags=${CXXFLAGS}"
    echo "opt_level=${OPT_LEVEL}"
    echo "sanitizers=${SANITIZERS}"
    echo "extra_cmake_args=${EXTRA_CMAKE_ARGS:-}"
    if [[ -d "${REPO_ROOT}/fuzz/aflnet/.git" ]]; then
        echo "aflnet_sha=$(git -C "${REPO_ROOT}/fuzz/aflnet" rev-parse HEAD)"
    fi
    if [[ -d "${REPO_ROOT}/fuzz/aflplusplus/.git" ]]; then
        echo "aflpp_sha=$(git -C "${REPO_ROOT}/fuzz/aflplusplus" rev-parse HEAD)"
        echo "aflpp_describe=$(git -C "${REPO_ROOT}/fuzz/aflplusplus" describe --tags --always 2>/dev/null || echo unknown)"
    fi
    echo "build_variant=asan"
} >"${MANIFEST}"

echo "[build_dcmtk] manifest: ${MANIFEST}"
echo "[build_dcmtk] built:"
for bin in "${TARGETS[@]}"; do
    path=$(find "${BUILD_DIR}" -type f -name "${bin}" -executable | head -1)
    if [[ -n "${path}" ]]; then
        echo "  ${path}"
    else
        echo "  ${bin}: MISSING"
    fi
done
