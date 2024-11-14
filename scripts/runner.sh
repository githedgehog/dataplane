#!/bin/bash

set -euo pipefail

# this is a workaround for PATH getting set in config.toml
export PATH="${PATH}:/usr/bin:/bin:/sbin"

declare -r CAPS="cap_net_raw,cap_net_admin,cap_sys_rawio"

if [ -x "${1}" ]; then
  sudo setcap "${CAPS}=+ep" "${1}"
  # shellcheck disable=SC2064
  trap "sudo setcap ${CAPS}=-ep ${1}" EXIT
else
  >&2 echo "${1} not executable"
  exit 1
fi
exec "${@}"
