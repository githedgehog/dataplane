#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Pin the newest Ubuntu generic kernel in one suite as npins `url` pins: the unsigned image, the modules and the
# buildinfo (which carries the config) packages.
#
# npins can hash a URL but cannot discover a kernel upload, so this script reads the suite's `Packages` index, picks
# the newest `linux-image-unsigned-<release>-generic`, and pins the three packages of that build at their pool paths.
# All three come from one build: the modules are vermagic-matched to the kernel, and a config from another build would
# describe a kernel we are not running.
#
# Each pin is checked against the SHA256 the index publishes for the package, and removed again if it does not match.
#
# Run from the repository root (gen-pins.sh and bump.sh both do). The pins are frozen so that `npins update` leaves
# them alone; rerun this script to move them.

set -euo pipefail

suite="resolute-updates"
flavour="generic"
archive="https://archive.ubuntu.com/ubuntu"

index="$(curl --fail --silent --show-error --location "${archive}/dists/${suite}/main/binary-amd64/Packages.gz" | gzip -dc)"

# One `<field>\t<value>` line per field of the named package's stanza.
stanza() {
  printf '%s\n' "${index}" | awk -v package="$1" '
    /^Package: / { in_stanza = ($2 == package) }
    in_stanza && /^(Version|Filename|SHA256): / { sub(/: /, "\t"); print }
  '
}

release="$(
  printf '%s\n' "${index}" |
    sed -n "s/^Package: linux-image-unsigned-\(.*-${flavour}\)$/\1/p" |
    sort --version-sort |
    tail --lines=1
)"
if [ -z "${release}" ]; then
  echo "no linux-image-unsigned-*-${flavour} in ${suite}" >&2
  exit 1
fi

pin() {
  local name="$1" package="$2"
  local filename published
  filename="$(stanza "${package}" | awk -F '\t' '$1 == "Filename" { print $2 }')"
  published="$(stanza "${package}" | awk -F '\t' '$1 == "SHA256" { print $2 }')"
  if [ -z "${filename}" ] || [ -z "${published}" ]; then
    echo "${package} is missing from ${suite}, or has no Filename/SHA256" >&2
    exit 1
  fi

  npins add url --name "${name}" "${archive}/${filename}" --frozen

  local pinned
  pinned="$(jq --exit-status --raw-output --arg name "${name}" '.pins[$name].hash' "${NPINS_DIRECTORY:-npins}/sources.json")"
  if [ "${pinned}" != "$(nix hash convert --hash-algo sha256 --to sri "${published}")" ]; then
    npins remove "${name}"
    echo "${archive}/${filename} does not match its published SHA256 ${published}" >&2
    exit 1
  fi
}

pin ubuntu-kernel-image "linux-image-unsigned-${release}"
pin ubuntu-kernel-modules "linux-modules-${release}"
pin ubuntu-kernel-buildinfo "linux-buildinfo-${release}"
