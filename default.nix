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
  # helper method to work around nix's contrived builtin string split function.
  split-str = split: str: builtins.filter (elm: builtins.isString elm) (builtins.split split str);
  sanitizers =  if sanitize == "" then [] else split-str ",+" sanitize;
  sources = import ./npins;
  target = import ./nix/target.nix {
    inherit lib platform libc;
  };
  profile = import ./nix/profiles.nix {
    inherit prof sanitizers instrumentation;
    arch = target.platform.arch;
  };
  overlays = import ./nix/overlays {
    inherit sources sanitizers target profile;
  };
  pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.${overlay}
      ];
    }).pkgsCross.${target.info.nixarch};
in
pkgs.lib.fix (final: {
  inherit
    pkgs
    sources
    profile
    target
    ;
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
