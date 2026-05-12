#!/usr/bin/env bash

set -euo pipefail
set -o allexport

# Under `cargo miri`, delegate to .cargo-miri-wrapped (which sits next
# to the invoking cargo, exposed via $CARGO).  Without this branch, an
# explicit-triple runner entry in .cargo/config.toml would win over
# cargo-miri's `--config target.cfg(all()).runner` injection on hosts
# where target == host (e.g. `just miri miri::cpu=x86_64`), silently
# bypassing the miri interpreter.
#
# We gate on MIRI_SYSROOT (set only by cargo-miri's machinery) rather
# than MIRIFLAGS (which the miri recipe sets in env and a careless
# shell export could leak); the wrapper-exists check guards against a
# misconfigured toolchain where MIRI_SYSROOT is set but the wrapper
# isn't where we expect.
if [ -n "${MIRI_SYSROOT:-}" ]; then
    declare -r miri_wrapper="$(dirname "${CARGO:-cargo}")/.cargo-miri-wrapped"
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
