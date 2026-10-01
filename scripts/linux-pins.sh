#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Pin the kernel.org source tarball for `linux-fancy` at the newest release of one longterm series, as an npins
# tarball pin.
#
# npins can hash a URL but cannot discover a kernel release, so this script picks the version from kernel.org's
# release index. The series is fixed on purpose: the config fragments in nix/pkgs/linux/fragments are written against
# it, and merge_config.sh warns about and drops a symbol the kernel does not know, so a renamed CONFIG_* across series
# would silently disable a feature. Moving to another series is a deliberate edit of `series` below.
#
# The tarball is checked against the SHA256 kernel.org publishes in `sha256sums.asc` before it is pinned. The pin
# itself records the hash of the unpacked tree, which is what fetchTarball wants.
#
# Run from the repository root (gen-pins.sh and bump.sh both do). The pin is frozen so that `npins update` leaves it
# alone; rerun this script to move it.

set -euo pipefail

series="6.18"

version="$(
  curl --fail --silent --show-error --location https://www.kernel.org/releases.json |
    jq --exit-status --raw-output --arg series "${series}" '
      .releases[]
      | select(.moniker == "longterm" and (.version | startswith($series + ".")))
      | .version
    '
)"
dir="https://cdn.kernel.org/pub/linux/kernel/v${version%%.*}.x"
tarball="linux-${version}.tar.xz"

published="$(
  curl --fail --silent --show-error --location "${dir}/sha256sums.asc" |
    awk -v tarball="${tarball}" '$2 == tarball && !found { print $1; found = 1 }'
)"
if [ -z "${published}" ]; then
  echo "no SHA256 for ${tarball} in ${dir}/sha256sums.asc" >&2
  exit 1
fi

fetched="$(nix hash convert --hash-algo sha256 --to base16 "$(nix-prefetch-url --type sha256 "${dir}/${tarball}")")"
if [ "${fetched}" != "${published}" ]; then
  echo "${dir}/${tarball} does not match its published SHA256 (got ${fetched}, published ${published})" >&2
  exit 1
fi

npins add tarball --name linux-fancy "${dir}/${tarball}" --frozen
