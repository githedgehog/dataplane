# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  overlay ? "dataplane",
  platform ? "x86-64-v3",
  libc ? "gnu",
  prof ? "debug",
  instrumentation ? "none",
  sanitize ? "address",
}:
let
  d = import ./default.nix {
    inherit
      overlay
      platform
      libc
      prof
      instrumentation
      sanitize
      ;
  };
  pkgs = import <nixpkgs> {};
in
(d.pkgs-super.buildPackages.buildFHSEnv {
  name = "dataplane-dev";
  targetPkgs =
    pkgs: with pkgs; [
      stdenv.cc.libc.dev
      stdenv.cc.libc.out
      # libmd.dev
      # libmd.static
      libbsd.dev
      # libbsd.static
      numactl.dev
      # numactl.static
      rdma-core.dev
      # rdma-core.static
      # dpdk.dev
      # dpdk.static
      # dpdk-wrapper.dev
      # dpdk-wrapper.out
    ];
  # (with pkgs.buildPackages; [
  #   # dev tools
  #   bash
  #   direnv
  #   just
  #   nil
  #   nixd
  #   npins
  #   wget
  #   llvmPackages.bintools
  #   llvmPackages.clang
  #   llvmPackages.libclang.lib
  #   llvmPackages.lld
  # ]);
}).env
