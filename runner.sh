#!/usr/bin/env bash

set -euo pipefail

declare script_dir
script_dir="$(dirname "$(readlink --canonicalize-existing "$(dirname "${BASH_SOURCE[0]}")")")"
declare -r script_dir

declare -r project_dir="${script_dir}"

exec docker run \
  --rm \
  -it \
  --privileged \
  --network=host \
  --name dataplane-runner \
  -v "${project_dir}:${project_dir}" \
  -v "/etc/passwd:/etc/passwd:ro" \
  --user "$(id -u):$(id -g)" \
  -w "${project_dir}" \
  ghcr.io/githedgehog/dataplane/development-environment:debug \
  "${@}"
