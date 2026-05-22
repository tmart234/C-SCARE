#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Phase 6: replay the saturated AFL corpus through the gcov-instrumented
# DCMTK build and produce an lcov HTML report + per-file summary.
#
# Usage:
#   scripts/coverage.sh <target>
#       target ∈ {file, net-storescp, net-dcmrecv, net-dcmqrscp}
#
# Outputs:
#   fuzz/coverage/<target>/lcov.info       — raw coverage data
#   fuzz/coverage/<target>/summary.txt     — per-file line/function summary
#   fuzz/coverage/<target>/html/index.html — browsable HTML
#
# Aborts if the ASAN build and coverage build disagree on DCMTK SHA, since
# replaying queue/crashes against a different code rev is meaningless.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target>"
    echo "  target ∈ {file, net-storescp, net-dcmrecv, net-dcmqrscp}"
    exit 2
fi

TARGET="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COV_BUILD="${REPO_ROOT}/fuzz/build-cov"
OUT_BASE="${REPO_ROOT}/fuzz/out"
COV_OUT="${REPO_ROOT}/fuzz/coverage/${TARGET}"
GCOV_DATA="${COV_OUT}/gcov-data"

# Resolve target → binary, fuzz output dir, mode, instrumented build dir.
# The instrumented build is split by fuzzer track (see scripts/build_dcmtk.sh):
# file → build-llvm (AFL++), net-* → build-net (AFLNet).
case "${TARGET}" in
    file)         BIN_NAME=dcm2pnm  FUZZ_OUT="${OUT_BASE}/file"          MODE=file INSTR_SUBDIR=build-llvm ;;
    net-storescp) BIN_NAME=storescp FUZZ_OUT="${OUT_BASE}/net-storescp"  MODE=net  PORT=11212 INSTR_SUBDIR=build-net ;;
    net-dcmrecv)  BIN_NAME=dcmrecv  FUZZ_OUT="${OUT_BASE}/net-dcmrecv"   MODE=net  PORT=11213 INSTR_SUBDIR=build-net ;;
    net-dcmqrscp) BIN_NAME=dcmqrscp FUZZ_OUT="${OUT_BASE}/net-dcmqrscp"  MODE=net  PORT=11214 INSTR_SUBDIR=build-net ;;
    *) echo "[coverage] unknown target '${TARGET}'"; exit 2 ;;
esac
INSTR_BUILD="${REPO_ROOT}/fuzz/${INSTR_SUBDIR}"

[[ -d "${COV_BUILD}" ]] || { echo "[coverage] coverage build missing — run scripts/build_dcmtk_cov.sh"; exit 1; }
[[ -d "${FUZZ_OUT}" ]]  || { echo "[coverage] fuzz output missing: ${FUZZ_OUT}"; exit 1; }

# Verify build parity. Both manifests must agree on dcmtk_sha; otherwise
# replays are meaningless.
instr_sha=$(awk -F= '/^dcmtk_sha=/{print $2}' "${INSTR_BUILD}/build_manifest.txt" 2>/dev/null || echo "")
cov_sha=$(awk -F= '/^dcmtk_sha=/{print $2}' "${COV_BUILD}/build_manifest.txt" 2>/dev/null || echo "")
if [[ -z "${instr_sha}" || -z "${cov_sha}" || "${instr_sha}" != "${cov_sha}" ]]; then
    echo "[coverage] DCMTK SHA mismatch:"
    echo "  instrumented build: ${instr_sha:-<missing manifest>}"
    echo "  coverage    build: ${cov_sha:-<missing manifest>}"
    echo "[coverage] rebuild with the same DCMTK_SRC_DIR/DCMTK_REF on both sides"
    exit 1
fi

BIN="$(find "${COV_BUILD}" -type f -name "${BIN_NAME}" -executable | head -1)"
[[ -n "${BIN}" ]] || { echo "[coverage] ${BIN_NAME} not built in ${COV_BUILD}"; exit 1; }

mkdir -p "${COV_OUT}" "${GCOV_DATA}"

# Wipe stale .gcda counters so this run reflects only the corpus we replay.
find "${COV_BUILD}" -name '*.gcda' -delete

# GCOV_PREFIX redirects .gcda writes; matters when the binary was built in
# a different layout. Here build-cov *is* the build dir, so leave the
# default and let counters land alongside the .gcno files.
export DCMDICTPATH="${REPO_ROOT}/fuzz/dcmtk/dcmdata/data/dicom.dic"

inputs=()
for sub in queue crashes; do
    while IFS= read -r -d '' f; do
        inputs+=("$f")
    done < <(find "${FUZZ_OUT}" -path "*/${sub}/id:*" -print0 2>/dev/null)
done
[[ ${#inputs[@]} -gt 0 ]] || { echo "[coverage] no queue/crashes inputs under ${FUZZ_OUT}"; exit 1; }

echo "[coverage] target=${TARGET} binary=${BIN}"
echo "[coverage] replaying ${#inputs[@]} inputs"

if [[ "${MODE}" == "file" ]]; then
    for f in "${inputs[@]}"; do
        timeout 10s "${BIN}" "$f" /tmp/cscare-cov.pnm >/dev/null 2>&1 || true
    done
else
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/scripts/install_afl.sh"
    REPLAY="${AFL_PATH}/aflnet-replay"
    [[ -x "${REPLAY}" ]] || { echo "[coverage] aflnet-replay missing"; exit 1; }

    SCP_LOG="${COV_OUT}/scp.log"
    case "${TARGET}" in
        net-storescp) "${BIN}" "${PORT}" --eostudy-timeout 1 >"${SCP_LOG}" 2>&1 & ;;
        net-dcmrecv)
            STORAGE="${REPO_ROOT}/fuzz/storage/cov-dcmrecv"
            mkdir -p "${STORAGE}"
            "${BIN}" "${PORT}" --output-directory "${STORAGE}" --eostudy-timeout 1 \
                >"${SCP_LOG}" 2>&1 & ;;
        net-dcmqrscp)
            CFG="${REPO_ROOT}/fuzz/configs/dcmqrscp.cfg.cov"
            mkdir -p "${REPO_ROOT}/fuzz/storage/dcmqrscp"
            sed "s|@REPO_ROOT@|${REPO_ROOT}|g" \
                "${REPO_ROOT}/fuzz/configs/dcmqrscp.cfg.template" >"${CFG}"
            "${BIN}" -c "${CFG}" "${PORT}" >"${SCP_LOG}" 2>&1 & ;;
    esac
    SCP_PID=$!
    trap 'kill -TERM ${SCP_PID} 2>/dev/null || true; wait ${SCP_PID} 2>/dev/null || true' EXIT
    sleep 1

    for f in "${inputs[@]}"; do
        timeout 10s "${REPLAY}" "$f" DICOM "${PORT}" 127.0.0.1 >/dev/null 2>&1 || true
    done

    # Send TERM so the SCP flushes .gcda before exit.
    kill -TERM "${SCP_PID}" 2>/dev/null || true
    wait "${SCP_PID}" 2>/dev/null || true
    trap - EXIT
fi

# Capture coverage. Prefer lcov; fall back to gcovr.
LCOV_INFO="${COV_OUT}/lcov.info"
SUMMARY="${COV_OUT}/summary.txt"
HTML_DIR="${COV_OUT}/html"

if command -v lcov >/dev/null 2>&1; then
    lcov --capture --directory "${COV_BUILD}" --output-file "${LCOV_INFO}" \
        --rc lcov_branch_coverage=1 --quiet
    lcov --list "${LCOV_INFO}" >"${SUMMARY}" 2>/dev/null || true
    if command -v genhtml >/dev/null 2>&1; then
        genhtml --output-directory "${HTML_DIR}" --branch-coverage --quiet "${LCOV_INFO}"
        echo "[coverage] html: ${HTML_DIR}/index.html"
    else
        echo "[coverage] genhtml not found; skipping HTML"
    fi
elif command -v gcovr >/dev/null 2>&1; then
    echo "[coverage] lcov not found; using gcovr fallback"
    mkdir -p "${HTML_DIR}"
    gcovr -r "${REPO_ROOT}/fuzz/dcmtk" \
        --object-directory "${COV_BUILD}" \
        --html --html-details \
        --output "${HTML_DIR}/index.html" \
        --txt "${SUMMARY}" \
        --lcov "${LCOV_INFO}" 2>/dev/null || true
    echo "[coverage] html: ${HTML_DIR}/index.html"
else
    echo "[coverage] FAIL: neither lcov nor gcovr installed"
    echo "[coverage]   apt-get install lcov   # primary"
    echo "[coverage]   pip install gcovr      # fallback"
    exit 1
fi

echo "[coverage] summary: ${SUMMARY}"
echo "[coverage] lcov:    ${LCOV_INFO}"
