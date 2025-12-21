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
  split-str =
    split: str:
    if str == "" then [ ] else builtins.filter (elm: builtins.isString elm) (builtins.split split str);
  sanitizers = split-str ",+" sanitize;
  sources = import ./npins;
  target = import ./nix/target.nix {
    inherit lib platform libc;
  };
  profile = import ./nix/profiles.nix {
    inherit prof sanitizers instrumentation;
    arch = target.platform.arch;
  };
  overlays = import ./nix/overlays {
    inherit
      sources
      sanitizers
      target
      profile
      ;
  };
  pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.${overlay}
      ];
    }).pkgsCross.${target.info.nixarch};

  sysroot-list = with pkgs; [
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
  build-tools-list =
    with pkgs.buildPackages;
    [
      llvmPackages.bintools
      llvmPackages.clang
      llvmPackages.libclang.lib
      llvmPackages.lld
    ]
    ++ [
      npins
    ];
in
pkgs.lib.fix (final: {
  inherit
    pkgs
    sources
    profile
    target
    ;
  sysroot =
    with final.pkgs;
    symlinkJoin {
      name = "sysroot";
      paths = sysroot-list;
    };
  clangd = pkgs.writeTextFile {
    name = ".clangd";
    text = ''
      CompileFlags:
        Add:
          - "-I${final.sysroot}/include"
          - "-I${final.pkgs.dpdk.dev}/include"
          - "-Wno-deprecated-declarations"
    '';
    executable = false;
    destination = "/.clangd";
  };
  build-tools =
    with final.pkgs.buildPackages;
    symlinkJoin {
      name = "build-tools";
      paths = build-tools-list ++ [ final.clangd ];
    };
  dev-shell = final.pkgs.symlinkJoin {
    name = "dataplane-dev-shell";
    paths = sysroot-list ++ build-tools-list;
  };
})
