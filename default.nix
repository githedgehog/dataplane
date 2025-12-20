# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  overlay ? "dataplane",
  platform ? "x86-64-v3",
  libc ? "gnu",
  prof ? "debug",
  instrumentation ? "none",
  sanitize ? "",
}:
let
  lib = (import sources.nixpkgs { }).lib;
  platform' = (import ./nix/machine.nix lib.recursiveUpdate).${platform};
  target = "${platform'.arch}-unknown-linux-${libc}";
  arch =
    {
      "x86_64-unknown-linux-gnu" = {
        target = "x86_64-unknown-linux-gnu";
        machine = "x86_64";
        nixarch = "gnu64";
        libc = "gnu";
      };
      "x86_64-unknown-linux-musl" = {
        target = "x86_64-unknown-linux-musl";
        machine = "x86_64";
        nixarch = "musl64";
        libc = "musl";
      };
      "aarch64-unknown-linux-gnu" = {
        target = "aarch64-unknown-linux-gnu";
        machine = "aarch64";
        nixarch = "aarch64-multiplatform";
        libc = "glibc";
      };
      "aarch64-unknown-linux-musl" = {
        target = "aarch64-unknown-linux-musl";
        machine = "aarch64";
        nixarch = "aarch64-multiplatform-musl";
        libc = "musl";
      };
    }
    .${target};
  # helper method to work around nix's contrived builtin string split function.
  split-str = split: str: builtins.filter (elm: builtins.isString elm) (builtins.split split str);
  sanitizers = split-str ",+" sanitize;
  sources = import ./npins;
  profile = import ./nix/profiles.nix {
    inherit prof sanitizers instrumentation;
    arch = arch.machine;
  };
  overlays = import ./nix/overlays {
    inherit sources sanitizers;
    env = profile;
  };
  pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.${overlay}
      ];
    }).pkgsCross.${arch.nixarch};
in
pkgs.lib.fix (final: {
  inherit
    pkgs
    sources
    profile
    target
    arch
    ;
  platform = platform';
  sysroot-list = with final.pkgs; [
    libc.static
    libc.out
    libmd.static
    libbsd.static
    libnl.out
    numactl.dev
    numactl.static
    rdma-core.static
    dpdk.dev
    dpdk.out
    dpdk.static
    dpdk-wrapper.dev
    dpdk-wrapper.out
  ];
  sysroot = pkgs.symlinkJoin {
    name = "sysroot";
    paths = final.sysroot-list;
  };
})
