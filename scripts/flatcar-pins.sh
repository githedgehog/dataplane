#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Pin the newest Flatcar stable release's kernel and PXE image as npins `url` pins.
#
# npins can hash a URL but cannot discover a new Flatcar release, so this script picks the version from Flatcar's
# release index and pins the two artifacts at that release's versioned CDN path (never `current/`, which moves at
# every release and would break the pinned hash). Both pins come from one version: the modules in the PXE image are
# vermagic-matched to the kernel and refuse to load against a different build.
#
# Each artifact is checked against the SHA512 Flatcar publishes in the `.DIGESTS` file beside it before it is pinned,
# so a pin always matches upstream's own digest rather than whatever the first download returned.
#
# Run from the repository root (gen-pins.sh and bump.sh both do). The pins are frozen so that `npins update` leaves
# them alone; rerun this script to move them.

set -euo pipefail

channel="stable"
releases="https://www.flatcar.org/releases-json/releases-${channel}.json"

version="$(
  curl --fail --silent --show-error --location "${releases}" |
    jq --exit-status --raw-output '
      keys
      | map(select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$")))
      | sort_by(split(".") | map(tonumber))
      | last
    '
)"
base="https://flatcar.cdn.cncf.io/${channel}/amd64-usr/${version}"

pin() {
  local name="$1" artifact="$2"
  local url="${base}/${artifact}"

  local published
  published="$(
    curl --fail --silent --show-error --location "${url}.DIGESTS" |
      awk -v artifact="${artifact}" '
        /^# SHA512 HASH/ { sha512 = 1; next }
        /^#/ { sha512 = 0 }
        sha512 && $2 == artifact && !found { print $1; found = 1 }
      '
  )"
  if [ -z "${published}" ]; then
    echo "no SHA512 for ${artifact} in ${url}.DIGESTS" >&2
    exit 1
  fi

  local fetched
  fetched="$(nix hash convert --hash-algo sha512 --to base16 "$(nix-prefetch-url --type sha512 "${url}")")"
  if [ "${fetched}" != "${published}" ]; then
    echo "${url} does not match its published SHA512 (got ${fetched}, published ${published})" >&2
    exit 1
  fi

  npins add url --name "${name}" "${url}" --frozen
}

pin flatcar-vmlinuz flatcar_production_pxe.vmlinuz
pin flatcar-pxe-image flatcar_production_pxe_image.cpio.gz
