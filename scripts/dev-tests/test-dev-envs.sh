#!/usr/bin/env bash

#
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
#

set -euo pipefail


declare script_dir
script_dir="$(readlink -e "$(dirname "${0}")")"
declare -r script_dir

declare project_dir
project_dir="$(readlink -e "${script_dir}/../..")"
declare -r project_dir

get_docker_sock() {
  declare -r DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
  declare -r without_unix="${DOCKER_HOST##unix://}"
  if [ -S "${without_unix}" ]; then
    printf -- '%s' "${without_unix}"
  elif [ -S /run/docker/docker.sock ]; then
    printf -- '%s' "/run/docker/docker.sock"
  elif [ -S /var/run/docker.sock ]; then
    printf -- '%s' "/var/run/docker.sock"
  fi
}

for distro in \
  "archlinux:latest" \
  "ubuntu:25.04" \
  "ubuntu:24.04" \
  "ubuntu:22.04" \
  "debian:bookworm-slim" \
  "debian:bullseye-slim" \
  "fedora:43" \
  "fedora:42" \
  "fedora:41" \
  "alpine:edge" \
  "alpine:3.22" \
  "alpine:3.21"; do
  base="${distro/:*/}"
  version="${distro/*:/}"
  docker build \
    --tag "dataplane-dev-env/${base}-${version}" \
    --build-arg _USER="$(id -un)" \
    --build-arg _GROUP="$(id -gn)" \
    --build-arg UID="$(id -u)" \
    --build-arg GID="$(id -g)" \
    --build-arg BASE="${base}" \
    --build-arg VERSION="${version}" \
    --file "${script_dir}/Dockerfile" \
    --target rustup \
    .

  docker run \
    --rm \
    --mount "type=bind,source=${project_dir},target=${project_dir},readonly=false,bind-propagation=private" \
    --mount "type=bind,source=$(get_docker_sock),target=$(get_docker_sock),readonly=false,bind-propagation=rprivate" \
    --mount "type=bind,source=/nix,target=/nix,readonly=true,bind-propagation=rprivate" \
    --tmpfs "/run/netns:noexec,nosuid,uid=$(id -u),gid=$(id -g)" \
    --tmpfs "/var/run/netns:noexec,nosuid,uid=$(id -u),gid=$(id -g)" \
    --tmpfs "/tmp,uid=$(id -u),gid=$(id -g)" \
    --user="$(id -u):$(id -g)" \
    --group-add="$(getent group docker | cut -d: -f3)" \
    --workdir="${project_dir}" \
    --env DOCKER_HOST="unix://$(get_docker_sock)" \
    --cap-drop ALL \
    --cap-add SETUID \
    --cap-add SETGID \
    --cap-add SETFCAP \
    --cap-add DAC_OVERRIDE \
    --cap-add AUDIT_WRITE \
    --interactive \
    --tty \
    "dataplane-dev-env/${base}-${version}" \
    "just cargo clean && just cargo nextest run"

done
