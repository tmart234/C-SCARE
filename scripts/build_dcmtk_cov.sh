#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 6: build a gcov-instrumented DCMTK for coverage replay.
#
# Vanilla gcc + --coverage + -O0. Deliberately NO AFL forkserver and NO
# ASAN — afl-as instrumentation munges control flow and ASAN's _exit
# handlers race the gcov .gcda flush, so a separate non-AFL build is
# required for clean lcov data. Inputs are replayed by scripts/coverage.sh
# from the saturated AFL corpus.
#
# Same source-resolution env vars as build_dcmtk.sh:
#   DCMTK_SRC_DIR, DCMTK_REF, EXTRA_CFLAGS, EXTRA_CMAKE_ARGS, OPT_LEVEL
# (OPT_LEVEL default differs: -O0 for line-accurate coverage.)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DCMTK_SRC="${DCMTK_SRC_DIR:-${REPO_ROOT}/fuzz/dcmtk}"
BUILD_DIR="${REPO_ROOT}/fuzz/build-cov"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
USING_SUBMODULE=0
[[ "${DCMTK_SRC}" == "${REPO_ROOT}/fuzz/dcmtk" ]] && USING_SUBMODULE=1

if [[ ! -f "${DCMTK_SRC}/CMakeLists.txt" ]]; then
    if [[ "${USING_SUBMODULE}" == 1 ]]; then
        echo "[build_dcmtk_cov] DCMTK submodule not initialized at ${DCMTK_SRC}"
        echo "[build_dcmtk_cov] run: git submodule update --init fuzz/dcmtk"
    else
        echo "[build_dcmtk_cov] DCMTK_SRC_DIR='${DCMTK_SRC}' has no CMakeLists.txt"
    fi
    exit 1
fi

if [[ "${USING_SUBMODULE}" == 1 && -n "${DCMTK_REF:-}" ]]; then
    if [[ -d "${DCMTK_SRC}/.git" ]]; then
        echo "[build_dcmtk_cov] checking out DCMTK ref ${DCMTK_REF}"
        git -C "${DCMTK_SRC}" fetch --tags --quiet
        git -C "${DCMTK_SRC}" checkout --quiet "${DCMTK_REF}"
    else
        echo "[build_dcmtk_cov] DCMTK_REF set but ${DCMTK_SRC} is not a git checkout"
        exit 1
    fi
fi

OPT_LEVEL="${OPT_LEVEL:--O0}"
export CC=gcc
export CXX=g++
export CFLAGS="-g ${OPT_LEVEL} --coverage -fprofile-arcs -ftest-coverage -fno-omit-frame-pointer ${EXTRA_CFLAGS:-}"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="--coverage"

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

TARGETS=(dcm2pnm dcmconv storescp dcmrecv dcmqrscp)
cmake --build . --parallel "${JOBS}" --target "${TARGETS[@]}"

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
    echo "sanitizers=none"
    echo "extra_cmake_args=${EXTRA_CMAKE_ARGS:-}"
    echo "build_variant=coverage"
} >"${MANIFEST}"

echo "[build_dcmtk_cov] manifest: ${MANIFEST}"
echo "[build_dcmtk_cov] built:"
for bin in "${TARGETS[@]}"; do
    path=$(find "${BUILD_DIR}" -type f -name "${bin}" -executable | head -1)
    if [[ -n "${path}" ]]; then
        echo "  ${path}"
    else
        echo "  ${bin}: MISSING"
    fi
done
