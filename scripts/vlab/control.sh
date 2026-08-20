#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euo pipefail

if [ -z "$*" ]; then
    declare -r cmd="k9s --namespace fab --command pod"
else
    declare -r cmd="$(printf '%q ' "$@")"
fi

# Allocate a tty only when there is one to allocate. Unconditional `-it` makes this usable by
# hand and unusable from anything else -- `just vlab-patch-dataplane` runs a kubectl patch through
# here, and docker refuses with "cannot attach stdin to a TTY-enabled container" the moment stdin
# is not a terminal.
declare -a docker_flags=(--interactive)
declare -a ssh_flags=()
if [ -t 0 ]; then
    docker_flags+=(--tty)
    ssh_flags+=(-t)
fi

docker exec "${docker_flags[@]}" vlab \
    ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${ssh_flags[@]}" \
        -p 22000 \
        -i /vlab/vlab/sshkey \
        core@localhost "export PATH=\"/usr/bin:/bin:/opt/bin\"; $cmd"
