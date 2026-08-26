#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Dump a core from a running process without ending it.
#
# Attaching stops the process, so the window between attach and detach is time
# the dataplane is not forwarding.  Keep the command list to the dump itself.

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    >&2 echo "usage: ${0##*/} <pid> [core-file]"
    exit 2
fi

declare -r pid="$1"
declare -r core="${2:-/tmp/dataplane.core}"

if [[ ! "${pid}" =~ ^[0-9]+$ ]]; then
    >&2 echo "${0##*/}: '${pid}' is not a pid"
    exit 2
fi

if [ ! -d "/proc/${pid}" ]; then
    >&2 echo "${0##*/}: no process ${pid}"
    exit 1
fi

# ptrace across uids needs CAP_SYS_PTRACE, and a dataplane does not run as you.
# Checking here turns a confusing gdb error into a clear one.
if [ "$(id -u)" -ne 0 ]; then
    >&2 echo "${0##*/}: must run as root to attach to ${pid}"
    exit 1
fi

# The static gdb is the point of this script: prefer one sitting beside it, so
# that scp'ing the pair to a machine with no nix store is enough.
declare gdb="${GDB:-}"
if [ -z "${gdb}" ]; then
    if [ -x "$(dirname -- "$(readlink -f -- "$0")")/gdb" ]; then
        gdb="$(dirname -- "$(readlink -f -- "$0")")/gdb"
    else
        gdb="$(command -v gdb || true)"
    fi
fi
declare -r gdb
if [ -z "${gdb}" ]; then
    >&2 echo "${0##*/}: no gdb; set GDB, or put one next to this script"
    exit 1
fi

# `--nx` because an operator's ~/.gdbinit must not decide what a core contains,
# and `auto-load off` because the only thing gdb would auto-load here is
# libthread_db, which it does not need: threads are enumerated from /proc, and
# a static gdb cannot dlopen it anyway.  Without this it prints a paragraph of
# safe-path advice on every run.
"${gdb}" --nx --quiet --batch \
    -iex 'set auto-load off' \
    -ex "generate-core-file ${core}" \
    -ex detach \
    -p "${pid}"

if [ ! -s "${core}" ]; then
    >&2 echo "${0##*/}: gdb wrote no core to ${core}"
    exit 1
fi

# `detach` resumes, but say so from the process's own state rather than from
# gdb's exit status: a core you can open is worthless if the dataplane is still
# sitting in ptrace-stop.  't' is TASK_TRACED.
# The comm field is parenthesised and may contain spaces, so cut past the last
# ')' rather than counting whitespace-separated fields.
declare state
state="$(sed -e 's/^.*) //' -e 's/ .*//' "/proc/${pid}/stat" 2>/dev/null || echo gone)"
declare -r state
case "${state}" in
    t) >&2 echo "${0##*/}: ${pid} is still stopped; detach it by hand"; exit 1 ;;
    gone) >&2 echo "${0##*/}: ${pid} did not survive"; exit 1 ;;
esac

echo "${0##*/}: ${core} ($(stat -c %s -- "${core}") bytes), ${pid} running (${state})"
