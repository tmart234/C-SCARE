#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Canonical AFLNet afl-fuzz options, shared by every network harness
# (fuzz_net.sh / fuzz_dcmrecv.sh / fuzz_dcmqrscp.sh). Defining the option
# set once stops the harnesses from drifting apart — drift caused a real
# CI abort when one harness was launched without -E:
#
#   [-] PROGRAM ABORT : Seed schedule 2 is only supported in state-aware mode
#                       (afl-fuzz.c:9180)
#
# AFLNet's afl-fuzz defaults seed_schedule_type to IPSM_SCHEDULE (2) — the
# state-machine-guided seed schedule — and FATALs at startup on any seed
# schedule > 1 unless state-aware mode is on:
#
#   if (seed_schedule_type > 1 && !state_aware_mode) FATAL(...)
#
# so -E (enable state-aware mode) is MANDATORY for these harnesses, not
# optional. Every network harness depends on -E staying in this array.
#
# Sourced by the harnesses; defines AFLNET_FUZZ_OPTS only, uses no other
# variables. The per-harness flags (-i / -o / -N and the target argv)
# stay in each harness because their values differ.

# shellcheck disable=SC2034  # consumed by the harness that sources this file
AFLNET_FUZZ_OPTS=(
    -P DICOM        # AFLNet's built-in DICOM PDU parser segments the seeds
    -D 10000        # wait (us) for the SCP to initialize before first request
    -W 30           # wait (ms) for a response after each message
    -m none         # no memory cap — ASan needs a large virtual address space
    -E              # state-aware mode — MANDATORY, see header
    -q 3            # state selection: FAVOR (enum RANDOM=1 ROUND_ROBIN=2 FAVOR=3)
)
