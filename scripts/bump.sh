#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euxo pipefail

pushd "$(dirname "${BASH_SOURCE[0]}")/.."

# update all the (non-frozen) pins
npins update

# Refresh the opengrep release-asset content hash.  The pin only tracks the
# release tag; the raw binary is hashed into nix/pkgs/opengrep/binary.sri,
# which the derivation reads at eval time.  Idempotent: the URL content
# doesn't change for a given tag, so re-running is a no-op unless the
# opengrep pin has moved during `npins update` above, or upstream has
# mutated the asset.
opengrep_version="$(jq --exit-status --raw-output '.pins.opengrep.version' npins/sources.json)"
opengrep_url="https://github.com/opengrep/opengrep/releases/download/${opengrep_version}/opengrep_manylinux_x86"
nix-hash --to-sri --type sha256 \
    "$(nix-prefetch-url --type sha256 "$opengrep_url")" \
    > nix/pkgs/opengrep/binary.sri

# Refresh the zot release-asset content hash on the same contract as opengrep
# above: the pin tracks the tag, the raw binary hash lives in
# nix/pkgs/zot/binary.sri.
zot_version="$(jq --exit-status --raw-output '.pins.zot.version' npins/sources.json)"
zot_url="https://github.com/project-zot/zot/releases/download/${zot_version}/zot-linux-amd64"
nix-hash --to-sri --type sha256 \
    "$(nix-prefetch-url --type sha256 "$zot_url")" \
    > nix/pkgs/zot/binary.sri

./scripts/update-doc-headers.sh
