# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  platform ? "x86-64-v3",
  libc ? "gnu",
  prof ? "debug",
  instrumentation ? "none",
  sanitize ? "",
}:
let
  lib = (import sources.nixpkgs { }).lib;
  # helper method to work around nix's contrived builtin string split function.
  split-str =
    split: str:
    if str == "" then [ ] else builtins.filter (elm: builtins.isString elm) (builtins.split split str);
  sanitizers = split-str ",+" sanitize;
  sources = import ./npins;
  platform' = import ./nix/platforms.nix {
    inherit lib platform libc;
  };
  profile = import ./nix/profiles.nix {
    inherit prof sanitizers instrumentation;
    arch = platform'.arch;
  };
  overlays = import ./nix/overlays {
    inherit
      sources
      sanitizers
      profile
      ;
    platform = platform';
  };
  dataplane-dev-pkgs = import sources.nixpkgs {
    overlays = [
      overlays.dataplane-dev
    ];
  };
  dataplane-pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.dataplane
      ];
    }).pkgsCross.${platform'.info.nixarch};
  sysroot = dataplane-pkgs.symlinkJoin {
    name = "sysroot";
    paths = with dataplane-pkgs; [
      stdenv'.cc.libc.dev
      stdenv'.cc.libc.out
      libmd.dev
      libmd.static
      libbsd.dev
      libbsd.static
      libnl.dev
      libnl.static
      numactl.dev
      numactl.static
      rdma-core.dev
      rdma-core.static
      dpdk.dev
      dpdk.static
      dpdk-wrapper.dev
      dpdk-wrapper.out
    ];
  };
  clangd-config = dataplane-pkgs.writeTextFile {
    name = ".clangd";
    text = ''
      CompileFlags:
        Add:
          - "-I${sysroot}/include"
          - "-I${dataplane-pkgs.dpdk.dev}/include"
          - "-Wno-deprecated-declarations"
    '';
    executable = false;
    destination = "/.clangd";
  };
  dev-tools = dataplane-pkgs.symlinkJoin {
    name = "dataplane-dev-shell";
    paths = [
      clangd-config
    ]
    ++ (with dataplane-pkgs.pkgsBuildHost.llvmPackages; [
      bintools
      clang
      libclang.lib
      lld
    ])
    ++ (with dataplane-dev-pkgs; [
      bash
      cargo-bolero
      cargo-deny
      cargo-depgraph
      cargo-llvm-cov
      cargo-nextest
      direnv
      just
      npins
    ]);
  };
in
{
  inherit
    dataplane-dev-pkgs
    dataplane-pkgs
    dev-tools
    profile
    sources
    sysroot
    ;
  platform = platform';
}
