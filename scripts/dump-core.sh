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

# A core is the whole address space -- configuration, keys, packets in flight --
# and this runs as root.  Two things follow for the default path.
#
# It must not be a fixed name in a world-writable directory: `generate-core-file`
# does not open with O_NOFOLLOW, so an unprivileged user who plants a symlink
# there first gets root's gdb to write through it.  `mktemp -d` gives a fresh
# directory nobody else can have pre-created.
#
# And it must not be readable by anyone who happens to be on the box.  The umask
# covers both the directory and the file gdb creates inside it.
umask 077
declare core="${2:-}"
if [ -z "${core}" ]; then
    core="$(mktemp -d -t dataplane-core-XXXXXX)/dataplane.core"
elif [ -L "${core}" ]; then
    # An explicit path is the caller's business, but a symlink is never what was
    # meant and is how the attack above is written.
    >&2 echo "${0##*/}: refusing to write a core through the symlink '${core}'"
    exit 2
fi
declare -r core

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
# 't' is TASK_TRACED -- gdb did not let go.  'T' is TASK_STOPPED: it did, but the
# process is sitting on a signal, which for an operator asking "is it forwarding
# again" is the same answer.
case "${state}" in
    t) >&2 echo "${0##*/}: ${pid} is still in ptrace-stop; detach it by hand"; exit 1 ;;
    T) >&2 echo "${0##*/}: ${pid} is stopped on a signal; SIGCONT it"; exit 1 ;;
    gone) >&2 echo "${0##*/}: ${pid} did not survive"; exit 1 ;;
esac

echo "${0##*/}: ${core} ($(stat -c %s -- "${core}") bytes), ${pid} running (${state})"
