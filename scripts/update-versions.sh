#!/usr/bin/env bash

set -euxo pipefail

pushd "$(dirname "${BASH_SOURCE[0]}")"

declare -rx DPDK_SYS_BRANCH="${1:-main}"

declare dpdk_sys
dpdk_sys="$(mktemp -d  --suffix=".dpdk-sys")"
declare -r dpdk_sys

git clone \
  --filter=blob:none \
  --no-checkout \
  --single-branch \
  --branch="${DPDK_SYS_BRANCH}" \
  --depth=1 \
  "https://github.com/githedgehog/dpdk-sys.git" \
  "${dpdk_sys}"
pushd "${dpdk_sys}"
declare DPDK_SYS_COMMIT
DPDK_SYS_COMMIT="$(git rev-parse HEAD)"
declare -rx DPDK_SYS_COMMIT
popd
rm -fr "${dpdk_sys}"
envsubst < ./templates/dpdk-sys.env.template > ./dpdk-sys.env
