#!/usr/bin/env bash

set -euo pipefail
export LD_LIBRARY_PATH="$(pwd)/compile-env/sysroot/${1}/debug/lib"
shift
exec "${@}"
