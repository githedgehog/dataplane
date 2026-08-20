#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euo pipefail

if [ -z "$*" ]; then
    declare -r cmd="k9s --namespace fab --command pod"
else
    declare -r cmd="$(printf '%q ' "$@")"
fi

docker exec -it vlab \
    ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -t \
        -p 22000 \
        -i /vlab/vlab/sshkey \
        core@localhost "export PATH=\"/usr/bin:/bin:/opt/bin\"; $cmd"
