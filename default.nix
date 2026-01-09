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
  crane = import sources.crane { pkgs = pkgs; };
  craneLib = crane.craneLib.overrideToolchain pkgs.rust-toolchain;
  devroot = pkgs.symlinkJoin {
    name = "dataplane-dev-shell";
    paths = [
      clangd-config
    ]
    ++ (with pkgs.pkgsBuildHost.llvmPackages'; [
      bintools
      clang
      libclang.lib
      lld
    ])
    ++ (with dev-pkgs; [
      bash
      cargo-bolero
      cargo-deny
      cargo-depgraph
      cargo-llvm-cov
      cargo-nextest
      direnv
      gateway-crd
      just
      kopium
      llvmPackages'.clang # you need the host compiler in order to link proc macros
      npins
      pkg-config
      rust-toolchain
    ]);
  };
  devenv = pkgs.mkShell {
    name = "dataplane-dev-shell";
    packages = [ devroot ];
    inputsFrom = [ sysroot ];
    shellHook = ''
      export RUSTC_BOOTSTRAP=1
    '';
  };
  markdownFilter = p: _type: builtins.match ".*\.md$" p != null;
  cHeaderFilter = p: _type: builtins.match ".*\.h$" p != null;
  outputsFilter = p: _type: (p != "target") && (p != "sysroot") && (p != "devroot") && (p != ".git");
  src = pkgs.lib.cleanSourceWith {
    filter =
      p: t:
      (markdownFilter p t)
      || (cHeaderFilter p t)
      || ((outputsFilter p t) && (craneLib.filterCargoSources p t));
    src = ./.;
  };
  cargoVendorDir = craneLib.vendorMultipleCargoDeps {
    cargoLockList = [
      ./Cargo.lock
      "${pkgs.rust-toolchain.passthru.availableComponents.rust-src}/lib/rustlib/src/rust/library/Cargo.lock"
    ];
  };
  target = pkgs.stdenv'.targetPlatform.rust.rustcTarget;
  is-cross-compile = dev-pkgs.stdenv.hostPlatform.rust.rustcTarget != target;
  cc = if is-cross-compile then "${target}-clang" else "clang";
  strip = if is-cross-compile then "${target}-strip" else "strip";
  objcopy = if is-cross-compile then "${target}-objcopy" else "objcopy";
in
{
  inherit
    dev-pkgs
    devroot
    devenv
    pkgs
    sources
    sysroot
    ;
  profile = profile';
  platform = platform';
}
