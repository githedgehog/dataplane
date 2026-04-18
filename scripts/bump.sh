#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euxo pipefail

pushd "$(dirname "${BASH_SOURCE[0]}")/.."

# update all the (non-frozen) pins
npins update

./scripts/update-doc-headers.sh
