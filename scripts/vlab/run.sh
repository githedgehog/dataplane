#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euo pipefail

declare SOURCE_DIR
SOURCE_DIR="$(readlink -e "$(dirname "${BASH_SOURCE[0]}")")"
declare -r SOURCE_DIR

pushd "${SOURCE_DIR}"

docker stop vlab || true
docker rm vlab || true
docker network rm zot || true

# /31 has exactly two addresses (192.168.19.0 and .1).  Pin .0 as the bridge
# gateway explicitly, so docker cannot flip the assignment and claim .1 for
# itself; the vlab container then pins --ip 192.168.19.1 at docker run time.
# zot binds to .1 (via its config) and in-container clients resolve zot.loc
# to .1 via --add-host, so both ends of the handshake must land on .1
# deterministically.
docker network create \
    --attachable \
    --driver bridge \
    --ip-range 192.168.19.0/31 \
    --subnet 192.168.19.0/31 \
    --gateway 192.168.19.0 \
    zot

docker volume create vlab-secrets >/dev/null

# Provision ghcr.io credentials if the vlab-secrets volume doesn't already
# hold a valid token. The provision step is interactive: the user pastes a
# classic PAT with the read:packages scope, which the entrypoint stores as
# creds.json inside the root-owned docker volume.
if ! docker run \
    --rm \
    --mount type=volume,source=vlab-secrets,target=/var/lib/vlab \
    vlab check
then
    docker run \
        --rm \
        --interactive \
        --tty \
        --mount type=volume,source=vlab-secrets,target=/var/lib/vlab \
        vlab provision
fi

docker run \
    --network zot \
    --ip 192.168.19.1 \
    --privileged \
    --mount type=volume,source=vlab-secrets,target=/var/lib/vlab \
    --mount type=tmpfs,destination=/etc/zot/certs,tmpfs-mode=0700 \
    --mount type=tmpfs,destination=/run/vlab,tmpfs-mode=0755 \
    --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
    --mount type=volume,source=vlab,target=/vlab \
    --mount type=volume,source=zot,target=/zot \
    --env DOCKER_HOST="unix:///var/run/docker.sock" \
    --name vlab \
    --add-host zot:192.168.19.1 \
    --add-host zot.loc:192.168.19.1 \
    --rm \
    --interactive \
    --tty \
    --detach \
    vlab

### part 2 (in container)

# docker run --detach returns as soon as the container starts; the entrypoint
# is still running gen_certs (RSA-4096 keygen takes a few seconds) and has not
# yet written the CA bundle that SSL_CERT_FILE points at.  Any docker exec
# issued before the bundle lands fails with curl error 77 (bad CA file).
# Block on the bundle appearing, with a generous timeout for slow hosts.
timeout 60 bash -c '
  until docker exec vlab test -s /run/vlab/ca-bundle.pem 2>/dev/null; do
    sleep 0.2
  done
'

# Pin hhfab to the short revision carried by the fabricator npins pin, so
# `just bump pins` also updates the hhfab version we install at startup.
declare fabricator_rev
fabricator_rev="$(jq --raw-output '.pins.fabricator.revision' "${SOURCE_DIR}/../../npins/sources.json" | cut -c 1-9)"
declare -r fabricator_rev

docker exec vlab /bin/bash -c \
    "curl -fsSL 'https://i.hhdev.io/hhfab' | USE_SUDO=false INSTALL_DIR=. VERSION=v0-master-${fabricator_rev} bash"
docker exec vlab /vlab/hhfab init \
    --dev \
    --registry-repo 192.168.19.1:30000 \
    --gateway \
    --import-host-upstream \
    --force \
    --gateways=2
docker exec vlab mv fab.yaml fab.orig.yaml
docker exec vlab bash -euxo pipefail -c "
  yq . fab.orig.yaml \
    | jq --slurp '
      . as \$input |
      \$input |
      ([\$input[0] | setpath([\"spec\", \"config\", \"registry\", \"upstream\", \"noTLSVerify\"]; true)] +  \$input[1:])
    ' \
    | yq -y '.[]' \
    | tee fab.yaml
"
docker exec vlab /vlab/hhfab vlab gen \
     --externals-static=1 \
     --externals-bgp=1 \
     --external-orphan-connections=1 \
     --mclag-leafs-count=0 \
     --orphan-leafs-count=2
docker exec vlab /vlab/hhfab vlab up \
    -v \
    --controls-restricted=false \
    -m=manual \
    --recreate \


popd
