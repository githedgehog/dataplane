#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors


set -euxo pipefail

pushd "$(dirname "${BASH_SOURCE[0]}")/.."

# rm -fr ./npins
npins init --bare
npins add channel --name nixpkgs nixpkgs-unstable # Floats on pin bump
npins add github oxalica rust-overlay --branch master # Floats on pin bump, rustc pinned pinned by rust-toolchain.toml
npins add github ipetkov crane # Will pick highest tag on pin bump
npins add github githedgehog gateway # Will pick highest tagged version on pin bump
npins add github githedgehog rdma-core --branch fix-lto-61.0 # Floats with branch on pin bump
npins add github githedgehog dpdk --branch pr/daniel-noland/cross-compile-fix # Floats with branch on pin bump
npins add github linux-rdma perftest --branch master # Project does not cut releases.  Ever.  Float with master :shrug:
npins add github kube-rs kopium # Will pick highest tag on pin bump
npins add github rust-lang rust # will bump on rust releases
