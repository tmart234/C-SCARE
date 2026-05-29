#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Shared loader for the declarative target profiles (fuzz/targets/<name>.yaml).
# Sourced by scripts/campaign.sh and every scripts/fuzz_*.sh harness so the
# per-target binary / dirs / port / env / argv come from one YAML file instead
# of hardcoded shell case statements. See c_scare/profiles.py for the Python
# side and the schema.
#
# Parser: the `yq` here is kislyuk/yq (a Python jq-wrapper), so `-r` is
# mandatory for raw (unquoted) scalars and the filter language is jq. A missing
# profile file makes yq exit non-zero, so load_profile checks the file first.
#
# load_profile <target> sets (in the caller's scope):
#   PROFILE_FILE BIN_NAME BUILD_SUBDIR ENGINE HARNESS PORT
#   SEEDS_DIR SEEDS_GLOB OUT_DIR STORAGE_DIR DICT_PATH DICT_GENERATOR
#   SAND_ENABLED CFG_TEMPLATE CFG_RUNTIME CALLING_AE CALLED_AE
#   PEER_HOST PEER_PORT SEND_FILE
#   ARGV=()                 # target argv after `-- <binary>`, tokens expanded
#   SEEDS_GENERATORS=()     # seed-generator command lines, {{REPO_ROOT}} expanded
#   PROFILE_ENV (associative) and exports each env var
#
# REPO_ROOT must be set by the caller before sourcing/calling.
#
# shellcheck disable=SC2034  # vars below are consumed by the sourcing harness

if ! command -v yq >/dev/null 2>&1; then
    echo "[profile_lib] 'yq' not found — install it (kislyuk/yq: pip install yq)" >&2
    # shellcheck disable=SC2317
    return 1 2>/dev/null || exit 1
fi

PROFILE_DIR="${REPO_ROOT}/fuzz/targets"

# _pf_get <jq-path> [default] — raw scalar with null/empty -> default.
_pf_get() {
    local val
    val="$(yq -r "${1} // \"\"" "${PROFILE_FILE}" 2>/dev/null || true)"
    if [[ -z "${val}" || "${val}" == "null" ]]; then
        val="${2:-}"
    fi
    printf '%s' "${val}"
}

# _pf_subst <string> — expand placeholder tokens (no eval). PORT/STORAGE_DIR/
# CFG_RUNTIME/SEND_FILE must already be resolved when expanding argv.
_pf_subst() {
    local s="$1"
    s="${s//\{\{REPO_ROOT\}\}/${REPO_ROOT}}"
    s="${s//\{\{PORT\}\}/${PORT:-}}"
    s="${s//\{\{STORAGE\}\}/${STORAGE_DIR:-}}"
    s="${s//\{\{CONFIG\}\}/${CFG_RUNTIME:-}}"
    s="${s//\{\{SENDFILE\}\}/${SEND_FILE:-}}"
    printf '%s' "${s}"
}

load_profile() {
    local target="$1"
    PROFILE_FILE="${PROFILE_DIR}/${target}.yaml"
    if [[ ! -f "${PROFILE_FILE}" ]]; then
        echo "[profile_lib] no target profile: ${PROFILE_FILE}" >&2
        return 2
    fi

    # Pass 1 — scalars. Path-like fields get {{REPO_ROOT}} expanded.
    BIN_NAME="$(_pf_get '.binary')"
    BUILD_SUBDIR="$(_pf_get '.build_subdir')"
    BUILD_DIR="${REPO_ROOT}/fuzz/${BUILD_SUBDIR}"
    ENGINE="$(_pf_get '.engine')"
    HARNESS="$(_pf_get '.harness')"
    PORT="$(_pf_get '.port')"
    SEEDS_DIR="$(_pf_subst "$(_pf_get '.seeds.dir')")"
    SEEDS_GLOB="$(_pf_get '.seeds.glob' '*')"
    OUT_DIR="$(_pf_subst "$(_pf_get '.output.dir')")"
    STORAGE_DIR="$(_pf_subst "$(_pf_get '.output.storage_dir')")"
    DICT_PATH="$(_pf_subst "$(_pf_get '.dictionary.path')")"
    DICT_GENERATOR="$(_pf_subst "$(_pf_get '.dictionary.generator')")"
    SAND_ENABLED="$(_pf_get '.sand.enabled' 'false')"
    CFG_TEMPLATE="$(_pf_subst "$(_pf_get '.config.template')")"
    CFG_RUNTIME="$(_pf_subst "$(_pf_get '.config.runtime')")"
    CALLING_AE="$(_pf_get '.association.calling_ae')"
    CALLED_AE="$(_pf_get '.association.called_ae')"
    PEER_HOST="$(_pf_get '.association.peer_host')"
    PEER_PORT="$(_pf_get '.association.peer_port')"
    SEND_FILE="$(_pf_subst "$(_pf_get '.desock.send_file')")"

    # Pass 2 — env map. Split on FIRST '=' so values with ':'/'=' survive
    # (e.g. ASAN_OPTIONS=detect_leaks=0:abort_on_error=1).
    declare -gA PROFILE_ENV=()
    local kv key val
    while IFS= read -r kv; do
        [[ -z "${kv}" ]] && continue
        key="${kv%%=*}"
        val="$(_pf_subst "${kv#*=}")"
        PROFILE_ENV["${key}"]="${val}"
        export "${key}=${val}"
    done < <(yq -r '.env // {} | to_entries[] | .key + "=" + .value' \
                 "${PROFILE_FILE}" 2>/dev/null || true)

    # Pass 3 — argv array (newline-delimited; elements may contain spaces).
    ARGV=()
    local raw line
    mapfile -t raw < <(yq -r '.argv[]?' "${PROFILE_FILE}" 2>/dev/null || true)
    for line in "${raw[@]}"; do
        ARGV+=("$(_pf_subst "${line}")")
    done

    # Seed-generator command lines ({{REPO_ROOT}} expanded; run via run_seed_generators).
    SEEDS_GENERATORS=()
    mapfile -t raw < <(yq -r '.seeds.generators[]?' "${PROFILE_FILE}" 2>/dev/null || true)
    for line in "${raw[@]}"; do
        SEEDS_GENERATORS+=("$(_pf_subst "${line}")")
    done
}

# run_seed_generators — run each declared seed-generator command line.
run_seed_generators() {
    local g
    for g in "${SEEDS_GENERATORS[@]}"; do
        [[ -z "${g}" ]] && continue
        bash -c "${g}"
    done
}

# source_afl — bring in the AFL toolchain paths (AFL_PATH / AFLPP_PATH). In
# golden-argv print mode the real toolchain need not exist, so use stable
# placeholder paths and skip the (submodule-dependent) install_afl.sh.
source_afl() {
    if [[ -n "${CSCARE_PRINT_ARGV:-}" ]]; then
        : "${AFL_PATH:=__AFL_PATH__}"
        : "${AFLPP_PATH:=__AFLPP_PATH__}"
    else
        # shellcheck source=scripts/install_afl.sh
        source "${REPO_ROOT}/scripts/install_afl.sh"
    fi
}

# find_binary <tag> — locate the instrumented target binary under BUILD_DIR,
# setting BIN_PATH. In print mode a placeholder path is used so the golden
# argv can be emitted without a real build.
find_binary() {
    BIN_PATH="$(find "${BUILD_DIR}" -type f -name "${BIN_NAME}" -executable 2>/dev/null | head -1 || true)"
    if [[ -z "${BIN_PATH}" ]]; then
        if [[ -n "${CSCARE_PRINT_ARGV:-}" ]]; then
            BIN_PATH="${BUILD_DIR}/${BIN_NAME}"
        else
            echo "[${1:-fuzz}] ${BIN_NAME} not built — run scripts/build_dcmtk.sh" >&2
            exit 1
        fi
    fi
}

# afl_exec <cmd...> — exec the assembled fuzzer command, or, when
# CSCARE_PRINT_ARGV is set, print it (quoted) and exit. The print mode is the
# golden test hook that proves the profile-driven argv is byte-identical to the
# pre-refactor invocation (see scripts/smoke.sh / test).
afl_exec() {
    if [[ -n "${CSCARE_PRINT_ARGV:-}" ]]; then
        printf '%q ' "$@"
        printf '\n'
        exit 0
    fi
    exec "$@"
}
