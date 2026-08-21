#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Shared setup for the `debug` and `debug-list` recipes.
#
# Sourced rather than run: both functions change or end the calling shell.

# Put the dev toolchain on PATH, or say so before anything expensive happens.
#
# These recipes run `cargo nextest` against an archive. The workspace assumes the nix dev shell
# provides cargo, and outside that shell a bare `cargo` reaches rustup and fails -- which, once
# the archive build has already run, arrives about ninety seconds after the mistake was made.
# `just setup-roots` puts a complete toolchain in `devroot`, so prefer that and fail at once when
# there is nothing to use.
debug_toolchain() {
    if [ -x ./devroot/bin/cargo ]; then
        PATH="$(pwd)/devroot/bin:${PATH}"
        export PATH
    fi
    # Run it rather than look for it. A rustup shim is on PATH on most developer machines and
    # satisfies `command -v` while failing on use, with "could not choose a version of cargo" --
    # which is the failure this is here to get ahead of.
    if ! cargo --version >/dev/null 2>&1; then
        >&2 echo "no usable cargo: run \`just setup-roots\`, or start the nix dev shell"
        exit 1
    fi
}

# Resolve a package argument to the nix attribute that builds its test archive.
#
# The attribute set is keyed by workspace directory (`nat`), but cargo, nextest, and the test IDs
# `just debug-list` prints all say `dataplane-nat`. Both are accepted. Checking here rather than
# letting nix fail turns an internal "attribute not found" into the list of names that work.
resolve_suite() {
    if [ "${1}" = "tests.all" ]; then
        printf 'tests.all\n'
        return 0
    fi
    local dir="${1}"
    [ -f "${dir}/Cargo.toml" ] || dir="${1#dataplane-}"
    if [ ! -f "${dir}/Cargo.toml" ]; then
        >&2 echo "no workspace package '${1}'; expected one of:"
        local manifest
        for manifest in */Cargo.toml; do
            >&2 printf '  %s\n' "${manifest%/Cargo.toml}"
        done
        return 1
    fi
    printf 'tests.pkg.%s\n' "${dir}"
}
