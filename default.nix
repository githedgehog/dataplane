# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  platform ? "x86-64-v3",
  libc ? "gnu",
  profile ? "debug",
  instrumentation ? "none",
  sanitize ? "",
}:
let
  sources = import ./npins;
  # helper method to work around nix's contrived builtin string split function.
  split-str =
    split-on: string:
    if string == "" then
      [ ]
    else
      builtins.filter (elm: builtins.isString elm) (builtins.split split-on string);
  lib = (import sources.nixpkgs { }).lib;
  platform' = import ./nix/platforms.nix {
    inherit lib platform libc;
  };
  sanitizers = split-str ",+" sanitize;
  profile' = import ./nix/profiles.nix {
    inherit sanitizers instrumentation profile;
    inherit (platform') arch;
  };
  cargo-profile =
    {
      "debug" = "dev";
      "release" = "release";
    }
    .${profile};
  overlays = import ./nix/overlays {
    inherit
      sources
      sanitizers
      ;
    profile = profile';
    platform = platform';
  };
  dev-pkgs = import sources.nixpkgs {
    overlays = [
      overlays.rust
      overlays.llvm
      overlays.dataplane-dev
    ];
  };
  pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.rust
        overlays.llvm
        overlays.dataplane
      ];
    }).pkgsCross.${platform'.info.nixarch};
  sysroot = pkgs.pkgsHostHost.symlinkJoin {
    name = "sysroot";
    paths = with pkgs.pkgsHostHost; [
      pkgs.pkgsHostHost.libc.dev
      pkgs.pkgsHostHost.libc.out
      fancy.dpdk-wrapper.dev
      fancy.dpdk-wrapper.out
      fancy.dpdk.dev
      fancy.dpdk.static
      fancy.hwloc.dev
      fancy.hwloc.static
      fancy.libbsd.dev
      fancy.libbsd.static
      fancy.libmd.dev
      fancy.libmd.static
      fancy.libnl.dev
      fancy.libnl.static
      fancy.libunwind.out
      fancy.numactl.dev
      fancy.numactl.static
      fancy.rdma-core.dev
      fancy.rdma-core.static
    ];
  };
  clangd-config = pkgs.writeTextFile {
    name = ".clangd";
    text = ''
      CompileFlags:
        Add:
          - "-I${sysroot}/include"
          - "-Wno-deprecated-declarations"
          - "-Wno-quoted-include-in-framework-header"
    '';
    executable = false;
    destination = "/.clangd";
  };
in
{
  inherit
    dev-pkgs
    pkgs
    sources
    sysroot
    ;
  profile = profile';
  platform = platform';
}
