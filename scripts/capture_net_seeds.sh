#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Harvest "good" AFLNet seeds from a real DICOM exchange.
#
# AFLNet mutates within whatever request streams you hand it, so seed
# quality bounds campaign quality. The synthetic serializer
# (fuzz/harness/seed_serializer.py) only emits the flows we hand-code;
# this script instead captures a *live* DCMTK conversation — a full
# association negotiation plus a real C-ECHO and a real C-STORE carrying
# an actual dataset — and converts the capture into .raw seeds via
# fuzz/harness/pcap_to_seeds.py.
#
# A plain (uninstrumented) apt storescp is the capture peer; the client
# bytes it elicits are what AFLNet later replays against the *instrumented*
# storescp from scripts/build_dcmtk.sh.
#
# Requirements: dcmtk (storescp/storescu/echoscu), tcpdump, python3 + scapy.
#
# Output: <seeds-dir>/pcap_*.raw   (default fuzz/seeds/net-storescp)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEEDS_DIR="${1:-${REPO_ROOT}/fuzz/seeds/net-storescp}"
WORK_DIR="${REPO_ROOT}/fuzz/out/net-seeds"
PCAP="${WORK_DIR}/capture.pcap"
PORT="${CAPTURE_PORT:-11120}"
AET="${CAPTURE_AET:-CAPTURE_SCP}"
CALLING_AE="${CAPTURE_CALLING_AE:-C-SCARE-CAP}"

for tool in storescp storescu echoscu tcpdump python3; do
    command -v "${tool}" >/dev/null 2>&1 \
        || { echo "[capture_net_seeds] missing required tool: ${tool}"; exit 1; }
done

# tcpdump needs root for the capture socket; the SCP/SCU processes do not.
SUDO=""
[[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

mkdir -p "${WORK_DIR}" "${SEEDS_DIR}"
STORE_OUT="$(mktemp -d -t cscare-capture.XXXXXX)"
rm -f "${PCAP}"

cleanup() {
    [[ -n "${TCPDUMP_PID:-}" ]] && ${SUDO} kill "${TCPDUMP_PID}" 2>/dev/null || true
    [[ -n "${SCP_PID:-}" ]] && kill "${SCP_PID}" 2>/dev/null || true
    rm -rf "${STORE_OUT}"
}
trap cleanup EXIT

wait_port() {
    python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 30
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            sys.exit(0)
    except OSError:
        time.sleep(0.5)
sys.exit(1)
PY
}

# A real Part 10 file for the C-STORE; gen_file_seeds.py builds one.
DICOM_FILE="${REPO_ROOT}/fuzz/seeds/file/baseline_explicit_le.dcm"
if [[ ! -f "${DICOM_FILE}" ]]; then
    echo "[capture_net_seeds] generating a baseline DICOM file"
    python3 "${REPO_ROOT}/fuzz/harness/gen_file_seeds.py" >/dev/null
fi

echo "[capture_net_seeds] starting capture SCP (storescp) on port ${PORT}"
storescp -od "${STORE_OUT}" -aet "${AET}" "${PORT}" >/dev/null 2>&1 &
SCP_PID=$!
if ! wait_port "${PORT}"; then
    echo "[capture_net_seeds] storescp never came up on ${PORT}"
    exit 1
fi

echo "[capture_net_seeds] capturing tcp port ${PORT} -> ${PCAP}"
# Loopback interface: the whole exchange is 127.0.0.1<->127.0.0.1, and `lo`
# yields an Ethernet link type scapy parses without SLL/SLL2 ambiguity.
${SUDO} tcpdump -i lo -s 0 -w "${PCAP}" "tcp port ${PORT}" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2  # let tcpdump open its capture socket

# Drive a real exchange. || true: a partial capture (e.g. just the C-ECHO)
# still yields usable seeds, and the next run should not abort the campaign.
echo "[capture_net_seeds] driving C-ECHO + C-STORE against ${AET}"
echoscu  -aet "${CALLING_AE}" -aec "${AET}" 127.0.0.1 "${PORT}" || true
storescu -aet "${CALLING_AE}" -aec "${AET}" 127.0.0.1 "${PORT}" "${DICOM_FILE}" || true
sleep 2  # let the last PDUs land in the capture

${SUDO} kill "${TCPDUMP_PID}" 2>/dev/null || true
TCPDUMP_PID=""
sleep 2  # let tcpdump flush and close the pcap

if [[ ! -s "${PCAP}" ]]; then
    echo "[capture_net_seeds] capture produced no pcap data"
    exit 1
fi

echo "[capture_net_seeds] converting capture into AFLNet seeds"
python3 "${REPO_ROOT}/fuzz/harness/pcap_to_seeds.py" \
    "${PCAP}" --port "${PORT}" --out "${SEEDS_DIR}" --prefix pcap

count="$(find "${SEEDS_DIR}" -maxdepth 1 -name 'pcap_*.raw' | wc -l)"
echo "[capture_net_seeds] ${count} pcap-derived seed(s) in ${SEEDS_DIR}"
[[ "${count}" -ge 1 ]] \
    || { echo "[capture_net_seeds] no seeds harvested"; exit 1; }
