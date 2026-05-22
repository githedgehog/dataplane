#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euo pipefail
set -o allexport

if [ -n "${MIRI_SYSROOT:-}" ]; then
    declare miri_wrapper
    miri_wrapper="$(dirname "${CARGO:-cargo}")/.cargo-miri-wrapped"
    declare -r miri_wrapper
    if [ -x "${miri_wrapper}" ]; then
        exec "${miri_wrapper}" runner "${@}"
    else
        echo "test-runner.sh: MIRI_SYSROOT is set but ${miri_wrapper} is not an executable file" >&2
        exit 1
    fi
fi

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
