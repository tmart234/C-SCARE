#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 1: Build DCMTK twice, once per fuzzing track.
#
# The file/SCU track is driven by AFL++ and the network track by AFLNet —
# two AFL forks whose instrumentation is not interchangeable, so each gets
# its own self-contained build:
#
#   fuzz/build-llvm — AFL++ afl-clang-fast. LLVM mode: PCGUARD edge
#                     coverage, CMPLOG-ready, faster than afl-as. Targets
#                     dcm2pnm / dcmdump (file + parser fuzz), storescu
#                     (SCU/client fuzz), dcmconv (smoke).
#   fuzz/build-net  — AFLNet afl-gcc. AFLNet is an AFL-2.x fork and can
#                     only drive afl-as/afl-gcc instrumentation. Targets
#                     storescp / dcmrecv / dcmqrscp (network fuzz).
#
# Source resolution (device-build parity):
#   DCMTK_SRC_DIR  — absolute path to operator-supplied DCMTK tree.
#                    When set, the submodule and DCMTK_REF are ignored.
#   DCMTK_REF      — git ref/tag/SHA to check out inside the submodule.
#                    Defaults to DCMTK-3.6.7. Ignored if DCMTK_SRC_DIR is set.
#
# Compile flags (applied to both builds):
#   OPT_LEVEL        — defaults to -O1 (ASAN-friendly).
#   EXTRA_CFLAGS     — appended to CFLAGS / CXXFLAGS verbatim.
#   EXTRA_CMAKE_ARGS — extra CMake -D args (whitespace-separated).
#   SANITIZERS       — comma list. Recognised: address, undefined, memory.
#                      Default: address.
#   SAND             — when set (SAND=1), build the AFL++ file track the
#                      SAND way (https://aflplus.plus/docs/sand/): the fuzz
#                      loop drives a native (sanitizer-free) build-llvm for
#                      speed, and one sanitizer-only worker tree per entry
#                      in SANITIZERS is built under fuzz/build-san-<san>/
#                      with AFL_SAN_NO_INST=1 (forkserver, no PC instr).
#                      scripts/fuzz_file.sh routes suspicious inputs to
#                      those workers via afl-fuzz -w; triage replays
#                      through them (c-scare greybox triage --sand).
#                      The AFLNet network track has no -w support, so it is
#                      always built with the sanitizers inline.
#
# Each build dir records provenance to build_manifest.txt (consumed by
# scripts/campaign.sh and scripts/coverage.sh).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DCMTK_SRC="${DCMTK_SRC_DIR:-${REPO_ROOT}/fuzz/dcmtk}"
LLVM_BUILD_DIR="${REPO_ROOT}/fuzz/build-llvm"
NET_BUILD_DIR="${REPO_ROOT}/fuzz/build-net"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
USING_SUBMODULE=0
[[ "${DCMTK_SRC}" == "${REPO_ROOT}/fuzz/dcmtk" ]] && USING_SUBMODULE=1

# A submodule (or linked worktree) checkout carries a .git *file* gitlink,
# not a .git directory, so a plain `-d .git` test wrongly rejects it.
is_git_worktree() { git -C "$1" rev-parse --is-inside-work-tree >/dev/null 2>&1; }

if [[ ! -f "${DCMTK_SRC}/CMakeLists.txt" ]]; then
    if [[ "${USING_SUBMODULE}" == 1 ]]; then
        echo "[build_dcmtk] DCMTK submodule not initialized at ${DCMTK_SRC}"
        echo "[build_dcmtk] run: git submodule update --init fuzz/dcmtk"
    else
        echo "[build_dcmtk] DCMTK_SRC_DIR='${DCMTK_SRC}' has no CMakeLists.txt"
    fi
    exit 1
fi

# DCMTK_REF only honoured for the submodule; never touch an operator-supplied
# tree. Default to the 3.6.7 release tag so the submodule build matches the
# commonly deployed DCMTK version; override DCMTK_REF for device parity.
if [[ "${USING_SUBMODULE}" == 1 ]]; then
    DCMTK_REF="${DCMTK_REF:-DCMTK-3.6.7}"
fi
if [[ "${USING_SUBMODULE}" == 1 && -n "${DCMTK_REF:-}" ]]; then
    if is_git_worktree "${DCMTK_SRC}"; then
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

# install_afl.sh points AFL_PATH at the AFLNet fork; capture it before the
# per-build subshells override AFL_PATH for the toolchain they invoke.
AFLNET_PATH="${AFL_PATH:-}"

if [[ ! -x "${AFLNET_PATH}/afl-gcc" || ! -x "${AFLNET_PATH}/afl-g++" ]]; then
    echo "[build_dcmtk] AFLNet afl-gcc/afl-g++ missing — install_afl.sh did not export AFL_PATH"
    exit 1
fi
if [[ ! -x "${AFLPP_PATH:-}/afl-clang-fast" || ! -x "${AFLPP_PATH:-}/afl-clang-fast++" ]]; then
    echo "[build_dcmtk] AFL++ afl-clang-fast(++) missing — install_afl.sh did not build AFL++"
    exit 1
fi

# SANITIZERS → AFL_USE_* env vars. AFL_HARDEN intentionally never set;
# it's mutually exclusive with the sanitizers. afl-gcc and afl-clang-fast
# both honour these AFL_USE_* vars.
SANITIZERS="${SANITIZERS:-address}"
SAND="${SAND:-}"
declare -a SAN_LIST=()
IFS=',' read -ra _SAN_RAW <<<"${SANITIZERS}"
for s in "${_SAN_RAW[@]}"; do
    case "${s// /}" in
        address|undefined|memory) SAN_LIST+=("${s// /}") ;;
        "")        ;;
        *)         echo "[build_dcmtk] unknown sanitizer '${s}'"; exit 1 ;;
    esac
done

# Set AFL_USE_* from a sanitizer-name list ($@). Clears all three first, so
# it can be called repeatedly to retarget each build_track invocation.
apply_san_env() {
    unset AFL_USE_ASAN AFL_USE_UBSAN AFL_USE_MSAN
    local s
    for s in "$@"; do
        case "${s}" in
            address)   export AFL_USE_ASAN=1 ;;
            undefined) export AFL_USE_UBSAN=1 ;;
            memory)    export AFL_USE_MSAN=1 ;;
        esac
    done
}

OPT_LEVEL="${OPT_LEVEL:--O1}"
export CFLAGS="-g ${OPT_LEVEL} -fno-omit-frame-pointer ${EXTRA_CFLAGS:-}"
export CXXFLAGS="${CFLAGS}"
export AFL_QUIET=1

EXTRA_ARGS=()
if [[ -n "${EXTRA_CMAKE_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    read -ra EXTRA_ARGS <<<"${EXTRA_CMAKE_ARGS}"
fi

CMAKE_COMMON_ARGS=(
    -DCMAKE_BUILD_TYPE=Debug
    -DBUILD_SHARED_LIBS=OFF
    -DBUILD_APPS=ON
    -DDCMTK_WITH_TIFF=OFF
    -DDCMTK_WITH_PNG=OFF
    -DDCMTK_WITH_OPENSSL=OFF
    -DDCMTK_WITH_SNDFILE=OFF
    -DDCMTK_WITH_ICONV=OFF
    -DDCMTK_WITH_ICU=OFF
    -DDCMTK_WITH_XML=OFF
    -DDCMTK_WITH_ZLIB=ON
    -DDCMTK_ENABLE_PRIVATE_TAGS=ON
    -DDCMTK_ENABLE_CHARSET_CONVERSION=OFF
    -DDCMTK_WITH_THREADS=ON
)

# Provenance manifest — consumed by scripts/campaign.sh and scripts/coverage.sh.
write_manifest() {
    local build_dir="$1" cc="$2" variant="$3"
    local manifest="${build_dir}/build_manifest.txt"
    {
        echo "build_timestamp_utc=$(date -u +%FT%TZ)"
        echo "dcmtk_src=${DCMTK_SRC}"
        if is_git_worktree "${DCMTK_SRC}"; then
            echo "dcmtk_sha=$(git -C "${DCMTK_SRC}" rev-parse HEAD 2>/dev/null || echo unknown)"
            echo "dcmtk_describe=$(git -C "${DCMTK_SRC}" describe --tags --always --dirty 2>/dev/null || echo unknown)"
        else
            echo "dcmtk_sha=unknown"
            echo "dcmtk_describe=unknown"
        fi
        echo "compiler=${cc}"
        echo "compiler_version=$("${cc}" --version 2>/dev/null | head -1)"
        echo "cflags=${CFLAGS}"
        echo "cxxflags=${CXXFLAGS}"
        echo "opt_level=${OPT_LEVEL}"
        # Effective sanitizers for *this* track, read from the AFL_USE_* env
        # set just before build_track — accurate for a SAND native build
        # (none) and per-sanitizer worker trees alike.
        local eff_san=""
        [[ -n "${AFL_USE_ASAN:-}" ]]  && eff_san+="address,"
        [[ -n "${AFL_USE_UBSAN:-}" ]] && eff_san+="undefined,"
        [[ -n "${AFL_USE_MSAN:-}" ]]  && eff_san+="memory,"
        echo "sanitizers=${eff_san%,}"
        echo "afl_san_no_inst=${AFL_SAN_NO_INST:-0}"
        echo "extra_cmake_args=${EXTRA_CMAKE_ARGS:-}"
        if is_git_worktree "${REPO_ROOT}/fuzz/aflnet"; then
            echo "aflnet_sha=$(git -C "${REPO_ROOT}/fuzz/aflnet" rev-parse HEAD)"
        fi
        if is_git_worktree "${REPO_ROOT}/fuzz/aflplusplus"; then
            echo "aflpp_sha=$(git -C "${REPO_ROOT}/fuzz/aflplusplus" rev-parse HEAD)"
            echo "aflpp_describe=$(git -C "${REPO_ROOT}/fuzz/aflplusplus" describe --tags --always 2>/dev/null || echo unknown)"
        fi
        echo "build_variant=${variant}"
    } >"${manifest}"
    echo "[build_dcmtk] manifest: ${manifest}"
}

# Configure + build one track. AFL_PATH is scoped to the subshell so the
# chosen compiler resolves its own instrumentation runtime (afl-as for
# afl-gcc, afl-compiler-rt for afl-clang-fast).
build_track() {
    local build_dir="$1" cc="$2" cxx="$3" afl_root="$4" variant="$5"
    shift 5
    local targets=("$@")

    echo "[build_dcmtk] === ${variant} track → ${build_dir}"
    echo "[build_dcmtk]     CC=${cc}"
    mkdir -p "${build_dir}"
    (
        cd "${build_dir}"
        export CC="${cc}" CXX="${cxx}" AFL_PATH="${afl_root}"
        cmake "${DCMTK_SRC}" "${CMAKE_COMMON_ARGS[@]}" "${EXTRA_ARGS[@]}"
        cmake --build . --parallel "${JOBS}" --target "${targets[@]}"
    )
    write_manifest "${build_dir}" "${cc}" "${variant}"

    echo "[build_dcmtk] ${variant} built:"
    for bin in "${targets[@]}"; do
        local path
        path=$(find "${build_dir}" -type f -name "${bin}" -executable | head -1)
        if [[ -n "${path}" ]]; then
            echo "  ${path}"
        else
            echo "  ${bin}: MISSING"
        fi
    done
}

# File / parser / SCU track — AFL++ afl-clang-fast (LLVM mode).
if [[ -n "${SAND}" ]]; then
    echo "[build_dcmtk] SAND mode: native loop binary + ${#SAN_LIST[@]} sanitizer worker tree(s)"
    # Loop binary: native (no sanitizer), normal PCGUARD instrumentation.
    apply_san_env
    unset AFL_SAN_NO_INST
    build_track "${LLVM_BUILD_DIR}" \
        "${AFLPP_PATH}/afl-clang-fast" "${AFLPP_PATH}/afl-clang-fast++" \
        "${AFLPP_PATH}" llvm-native \
        dcm2pnm dcmdump storescu dcmconv
    # Worker trees: one per sanitizer, forkserver only (AFL_SAN_NO_INST=1
    # disables PC instrumentation — the loop binary owns coverage feedback).
    for san in "${SAN_LIST[@]}"; do
        apply_san_env "${san}"
        export AFL_SAN_NO_INST=1
        build_track "${REPO_ROOT}/fuzz/build-san-${san}" \
            "${AFLPP_PATH}/afl-clang-fast" "${AFLPP_PATH}/afl-clang-fast++" \
            "${AFLPP_PATH}" "san-${san}" \
            dcm2pnm dcmdump storescu
    done
    unset AFL_SAN_NO_INST
else
    apply_san_env "${SAN_LIST[@]}"
    build_track "${LLVM_BUILD_DIR}" \
        "${AFLPP_PATH}/afl-clang-fast" "${AFLPP_PATH}/afl-clang-fast++" \
        "${AFLPP_PATH}" llvm \
        dcm2pnm dcmdump storescu dcmconv
fi

# Network track — AFLNet afl-gcc (afl-as classic instrumentation). AFLNet
# has no -w worker support, so the sanitizers stay inline even under SAND.
apply_san_env "${SAN_LIST[@]}"
build_track "${NET_BUILD_DIR}" \
    "${AFLNET_PATH}/afl-gcc" "${AFLNET_PATH}/afl-g++" \
    "${AFLNET_PATH}" aflnet \
    storescp dcmrecv dcmqrscp
