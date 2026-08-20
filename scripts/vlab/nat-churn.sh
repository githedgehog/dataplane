#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Drive masquerade address churn from a vlab server.
#
# The masquerade allocator destroys a public address when the last flow using it ends, so the
# interesting states are the boundaries: address released, address re-created. A DNS reply tears
# its flow down immediately (see nat/src/masquerade/protocol.rs), which makes one request/response
# exchange one full create/destroy cycle.
#
# Streams run WITHOUT a barrier between them, which is the point. Waiting on a batch before
# starting the next one serialises release and re-allocation -- the next allocation then arrives
# a whole process spawn after the previous address was handed back, and never overlaps it.
# Independent streams drift out of phase and overlap on their own.
#
# Concurrency is a trade-off rather than a "more is better" knob: too many streams and some flow
# always holds the address, so it never drops to zero and the boundary never happens at all.

set -euo pipefail

declare -r target="${1:?usage: nat-churn.sh <ip:port> [seconds] [streams]}"
declare -r seconds="${2:-120}"
declare -r streams="${3:-3}"

declare -r host="${target%:*}"
declare -r port="${target##*:}"

stream() {
    local -i n=0
    local -ri end=$((SECONDS + seconds))
    while ((SECONDS < end)); do
        echo probe | timeout 2 socat -T1 - "UDP4:${host}:${port}" >/dev/null 2>&1 || true
        ((n += 1))
    done
    echo "${n}"
}

declare -a pids=()
declare -r tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

for i in $(seq 1 "${streams}"); do
    stream > "${tmp}/${i}" &
    pids+=("$!")
    # Stagger the starts so the streams do not all begin -- and so not all end -- together.
    sleep 0.1
done

for pid in "${pids[@]}"; do
    wait "${pid}" || true
done

declare -i total=0
for i in $(seq 1 "${streams}"); do
    total=$((total + $(cat "${tmp}/${i}")))
done
echo "cycles=${total} streams=${streams} seconds=${seconds}"
