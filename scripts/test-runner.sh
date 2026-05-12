#!/usr/bin/env bash

set -euo pipefail
set -o allexport

declare host_machine
host_machine="$(uname --machine)"
declare -r host_machine

declare host_kernel_name
host_kernel_name="$(uname --kernel-name)"
host_kernel_name="${host_kernel_name,,}" # convert to lower case
declare -r host_kernel_name

declare -r target_machine="${1}"
shift

if [ "${host_machine}" = "${target_machine}" ] && [ "${host_kernel_name}" = "linux" ]; then
    exec "${@}"
else
    exec "qemu-${target_machine}" "${@}"
fi
