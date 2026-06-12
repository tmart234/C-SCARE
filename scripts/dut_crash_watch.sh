#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# dut_crash_watch.sh — run ON the device-under-test (DUT) as root while
# C-SCARE delivers payloads from the laptop. It turns a black-box DAST run
# into a crash oracle without needing an ASan rebuild: it timestamps every
# kernel fault and every systemd-coredump so you can line them up against the
# per-payload send log on the laptop (run c-scare with --verbose).
#
# What this CAN catch (faulting corruption):
#   - NULL deref            -> SIGSEGV  (e.g. CVE-2022-2121 on DCMTK <= 3.6.6)
#   - wild pointer reads/writes that hit an unmapped page -> SIGSEGV
#   - stack smashing caught by the stack protector -> SIGABRT
#   The kernel "error 4/6" code tells you read(4) vs write(6); the "in
#   libdcmdata.so..." tail tells you which library faulted.
#
# What this CANNOT catch (silent corruption): a small out-of-bounds read that
# stays inside a mapped page, or a heap overflow that scribbles an adjacent
# live object without faulting. Those need an ASan build (see
# scripts/build_dcmtk.sh + `c-scare --asan-binary`).
#
# Usage (on the DUT):
#   sudo sh scripts/dut_crash_watch.sh [process-name]
# default process-name is "storescp". Ctrl-C to stop and print a summary.

set -eu

PROC="${1:-storescp}"
START_UTC="$(date -u '+%Y-%m-%d %H:%M:%S')"

echo "=== C-SCARE DUT crash watch ==="
echo "watching process : ${PROC}"
echo "start (UTC)      : ${START_UTC}"
echo "laptop clock?    : run 'date -u' on the laptop now and note any offset"
echo

# --- pre-flight: make sure faults are actually captured -----------------------
echo "core_pattern     : $(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo '?')"
if command -v coredumpctl >/dev/null 2>&1; then
    echo "coredumpctl      : present"
else
    echo "coredumpctl      : MISSING — install systemd-coredump or set a core_pattern"
fi
PIDS="$(pgrep -x "${PROC}" 2>/dev/null | tr '\n' ' ' || true)"
echo "${PROC} pids     : ${PIDS:-<not running>}"
echo
echo "If ${PROC} is launched single-process (storescp default on Linux), a"
echo "crash kills the listener and the laptop's next association is REFUSED."
echo "If launched with --fork (or dcmqrscp), only the child dies — the listener"
echo "survives, so coredumpctl below is your real oracle, not connection drops."
echo
echo "--- live (Ctrl-C to stop) ----------------------------------------------"

# --- live stream: kernel faults OR systemd-coredump notifications --------------
# journalctl "A + B" is an OR of matchers; -n0 skips history, -f follows.
journalctl -f -n0 _TRANSPORT=kernel + SYSLOG_IDENTIFIER=systemd-coredump 2>/dev/null \
  | grep --line-buffered -Ei \
      'segfault|general protection|stack-protector|dumped core|trap |gpf|protection fault' \
  | while IFS= read -r line; do
        printf '[%s UTC] >>> %s\n' "$(date -u '+%H:%M:%S')" "$line"
    done &
WATCH_PID=$!

# --- on exit: summarise new cores since START --------------------------------
trap 'echo; echo "--- cores since ${START_UTC} ---";
      coredumpctl list --since="${START_UTC}" --no-pager 2>/dev/null || echo "(none / no coredumpctl)";
      echo;
      echo "To map a core to a function (which CVE):";
      echo "  coredumpctl info  <PID|index>     # signal, exe, faulting lib";
      echo "  coredumpctl gdb   <PID|index>     # then: bt";
      kill "${WATCH_PID}" 2>/dev/null || true;
      exit 0' INT TERM

wait "${WATCH_PID}"
