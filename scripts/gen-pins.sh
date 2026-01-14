#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors


set -euxo pipefail

pushd "$(dirname "${BASH_SOURCE[0]}")/.."

npins init --bare

# Floats on pin bump with the "unstable" version of the channel.
# NOTE: "unstable" does not refer to package stability but package version instability.
npins add channel --name nixpkgs nixpkgs-unstable

# This is just here to get an official source for the current version of rust.
# The version of rust will automatically bump with pin updates on rust releases.
# NOTE: this is in no way the same thing as saying the "stable" branch.
# If you walk the git history back in time then the rust version will walk back as well (as it should).
npins add github rust-lang rust

# oxalica (aka oxa) maintains an excellent overlay which lets us break away from the (potentially quite old) version of
# rust shipped with nixpkgs.
# The overlay itself floats on pin bumps.
# Note that rustc is pinned by rust-lang/rust, so all that really changes with the pin bump is the mechanics of the
# overlay itself.
npins add github oxalica rust-overlay --branch master

# Tool which is very helpful in building rust artifacts from nix.  It is designed to cooperate with oxa's overlay.
# Will pick highest tag / release on pin bump.
npins add github ipetkov crane

# rdma-core has a trivially side-stepped problem with LTO due to symbol versioning in shared libraries.
# You can work around it using `-ffat-lto-objects` but I consider that an obnoxious hack and avoid it wherever possible.
# The much easier option is to simply apply a patch to the current version of rdma-core.
# Thus, we keep rdma-core pinned to a version branch in our fork.
npins add github githedgehog rdma-core --branch fix-lto-61.0 # Floats with branch on pin bump

# dpdk has a trivially side-stepped problem with cross compilation (it fails to identify the correct version of ar when
# cross compiling due to a bug in their meson.build).  I hope to submit the fix to DPDK soon, at which point we can
# pin to the official dpdk github instead of our fork / branch.
npins add github githedgehog dpdk --branch pr/daniel-noland/cross-compile-fix

# Project does not cut releases or tags. Float with master on pin bump.
# Normally I would say that is not reasonable, but we only use this in testing and it is still technically pinned so
# :shrug:
npins add github linux-rdma perftest --branch master

# Kopium is needed for our build to generate rust data structures from CRDs.
# Will pick highest tag on pin bump.
npins add github kube-rs kopium

# The gateway is needed to define the CRD we use for code generation at build time.
# The gateway should be pinned to a specific an manually changed version, the best way to reach this goal is to pin the
# release and freeze it with npins. Then you can manually update with `npins update --frozen` instead of repeatedly
# editing the script or otherwise fighting the update process.
npins add github githedgehog gateway # Will pick highest tagged version on pin bump
npins freeze gateway
