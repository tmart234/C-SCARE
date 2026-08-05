#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Profile consistency check (no DCMTK build / AFL needed). Asserts that the
# declarative profiles fuzz/targets/*.yaml, loaded through scripts/profile_lib.sh,
# resolve to exactly the values the grey-box harnesses used to hardcode, and
# that each harness's profile-driven afl-fuzz invocation (CSCARE_PRINT_ARGV
# golden mode) is byte-identical to the pre-refactor command line. Run in CI
# alongside the python test suite.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/profile_lib.sh
source "${REPO_ROOT}/scripts/profile_lib.sh"

fail() { echo "[check_profiles] FAIL: $*" >&2; exit 1; }

# --- (1) scalar values match the historical hardcoded constants --------------
declare -A want_bin=(
    [file]=dcm2pnm [parse]=dcmdump [net-storescp]=storescp
    [net-dcmrecv]=dcmrecv [net-dcmqrscp]=dcmqrscp [scu]=storescu)
declare -A want_sub=(
    [file]=build-llvm [parse]=build-llvm [net-storescp]=build-net
    [net-dcmrecv]=build-net [net-dcmqrscp]=build-net [scu]=build-llvm)
declare -A want_script=(
    [file]=fuzz_file.sh [parse]=fuzz_file.sh [net-storescp]=fuzz_net.sh
    [net-dcmrecv]=fuzz_dcmrecv.sh [net-dcmqrscp]=fuzz_dcmqrscp.sh
    [scu]=fuzz_scu.sh)

for t in file parse net-storescp net-dcmrecv net-dcmqrscp scu; do
    load_profile "${t}" || fail "could not load profile ${t}"
    [[ "${BIN_NAME}" == "${want_bin[$t]}" ]]   || fail "${t} binary=${BIN_NAME}"
    [[ "${BUILD_SUBDIR}" == "${want_sub[$t]}" ]] || fail "${t} build=${BUILD_SUBDIR}"
    [[ "${HARNESS}" == "${want_script[$t]}" ]] || fail "${t} harness=${HARNESS}"
    [[ "${SEEDS_DIR}" == "${REPO_ROOT}/fuzz/seeds/"* ]] || fail "${t} seeds=${SEEDS_DIR}"
done
echo "[check_profiles] (1) scalar values OK"

# Env strings and argv for representative targets.
load_profile file
[[ "${PROFILE_ENV[ASAN_OPTIONS]}" == "abort_on_error=1:symbolize=0:detect_leaks=0:halt_on_error=1" ]] \
    || fail "file ASAN_OPTIONS drift: ${PROFILE_ENV[ASAN_OPTIONS]}"
[[ "${ARGV[*]}" == "@@ /tmp/cscare-fuzz-out.pnm" ]] || fail "file argv: ${ARGV[*]}"
load_profile net-storescp
[[ "${PROFILE_ENV[ASAN_OPTIONS]}" == "detect_leaks=0:abort_on_error=1:symbolize=0:halt_on_error=1" ]] \
    || fail "net ASAN_OPTIONS drift: ${PROFILE_ENV[ASAN_OPTIONS]}"
echo "[check_profiles] (2) env + argv OK"

# --- (3) golden afl-fuzz argv: profile-driven == pre-refactor ----------------
# AFL paths are placeholders in print mode; binaries need not exist.
gold() { env -u CSCARE_AUTO_DICT -u CSCARE_CMPLOG_BINARY CSCARE_PRINT_ARGV=1 bash "${REPO_ROOT}/scripts/$1" 2>/dev/null | grep afl-fuzz; }
gold_profile() { env -u CSCARE_AUTO_DICT -u CSCARE_CMPLOG_BINARY CSCARE_PROFILE="$1" CSCARE_PRINT_ARGV=1 bash "${REPO_ROOT}/scripts/$2" 2>/dev/null | grep afl-fuzz; }
check_gold() {
    local got want
    got="$(gold "$1")"
    want="$2"
    [[ "${got}" == "${want}" ]] || fail "golden argv for $1:
  got:  ${got}
  want: ${want}"
}
R="${REPO_ROOT}"
check_gold fuzz_file.sh \
"__AFLPP_PATH__/afl-fuzz -i ${R}/fuzz/seeds/file -o ${R}/fuzz/out/file -x ${R}/fuzz/dict/dicom.dict -m none -- ${R}/fuzz/build-llvm/dcm2pnm @@ /tmp/cscare-fuzz-out.pnm "
got="$(gold_profile parse fuzz_file.sh)"
want="__AFLPP_PATH__/afl-fuzz -i ${R}/fuzz/seeds/file -o ${R}/fuzz/out/parse -x ${R}/fuzz/dict/dicom.dict -m none -- ${R}/fuzz/build-llvm/dcmdump @@ "
[[ "${got}" == "${want}" ]] || fail "golden argv for parse:
    got:  ${got}
    want: ${want}"
check_gold fuzz_net.sh \
"__AFL_PATH__/afl-fuzz -i ${R}/fuzz/seeds/net-storescp -o ${R}/fuzz/out/net-storescp -N tcp://127.0.0.1/11112 -P DICOM -D 10000 -W 30 -m none -E -q 3 -K -- ${R}/fuzz/build-net/storescp 11112 "
check_gold fuzz_dcmrecv.sh \
"__AFL_PATH__/afl-fuzz -i ${R}/fuzz/seeds/net-dcmrecv -o ${R}/fuzz/out/net-dcmrecv -N tcp://127.0.0.1/11113 -P DICOM -D 10000 -W 30 -m none -E -q 3 -K -- ${R}/fuzz/build-net/dcmrecv 11113 --output-directory ${R}/fuzz/storage/dcmrecv --eostudy-timeout 1 "
check_gold fuzz_dcmqrscp.sh \
"__AFL_PATH__/afl-fuzz -i ${R}/fuzz/seeds/net-dcmqrscp -o ${R}/fuzz/out/net-dcmqrscp -N tcp://127.0.0.1/11114 -P DICOM -D 10000 -W 30 -m none -E -q 3 -K -- ${R}/fuzz/build-net/dcmqrscp -c ${R}/fuzz/configs/dcmqrscp.cfg 11114 "
check_gold fuzz_scu.sh \
"__AFLPP_PATH__/afl-fuzz -i ${R}/fuzz/seeds/scu -o ${R}/fuzz/out/scu -m none -- ${R}/fuzz/build-llvm/storescu -aec ANY-SCP 127.0.0.1 11112 ${R}/fuzz/seeds/file/baseline_explicit_le.dcm "
echo "[check_profiles] (3) golden afl-fuzz argv OK"

echo "[check_profiles] PASS"
