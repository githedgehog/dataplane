#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
#
# Capture a module's memory as test fixtures: each half page the decoder may read, plus what
# `ethtool --json -m` makes of the same module, to check the decoder against.
#
#   capture.sh <netdev> <fixture directory>
#
# Pages a module does not implement are still captured if the read succeeds (many modules answer
# every page with page 00h); the decoder is expected to ignore pages the module does not advertise.

set -euo pipefail

declare -r dev="${1:?netdev}"
declare -r out="${2:?fixture directory}"
mkdir -p "${out}"

read_half() {
    local file="$1"
    shift
    if ! ethtool -m "${dev}" "$@" raw on >"${out}/${file}" 2>/dev/null; then
        rm -f "${out}/${file}"
    fi
}

read_half lower.bin page 0 offset 0 length 128
for page in 00 01 02 03 10 11 13 14; do
    read_half "page-${page}.bin" page "0x${page}" bank 0 offset 128 length 128
done
# SFF-8472 diagnostics live behind a second bus address.
read_half a2-lower.bin i2c 0x51 page 0 offset 0 length 128
ethtool --json -m "${dev}" >"${out}/ethtool.json"
