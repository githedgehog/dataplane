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
      overlays.llvm
      overlays.dataplane-dev
    ];
  };
  dataplane-pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.llvm
        overlays.dataplane
      ];
    }).pkgsCross.${platform'.info.nixarch};
  sysroot = dataplane-pkgs.pkgsHostHost.symlinkJoin {
    name = "sysroot";
    paths = with dataplane-pkgs.pkgsHostHost; [
      dataplane-pkgs.pkgsHostHost.libc.dev
      dataplane-pkgs.pkgsHostHost.libc.out
      fancy.libmd.dev
      fancy.libmd.static
      fancy.libbsd.dev
      fancy.libbsd.static
      fancy.libnl.dev
      fancy.libnl.static
      fancy.numactl.dev
      fancy.numactl.static
      fancy.rdma-core.dev
      fancy.rdma-core.static
      dpdk.dev
      dpdk.static
      dpdk-wrapper.dev
      dpdk-wrapper.out
      hwloc.dev
      hwloc
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
  crane-base = import sources.crane { pkgs = dataplane-pkgs; };
  crane = crane-base.craneLib.overrideToolchain dataplane-pkgs.rust-toolchain;
  devroot = dataplane-pkgs.symlinkJoin {
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
      gateway-crd
      just
      kopium
      npins
      rust-toolchain
    ]);
  };
  dataplane-src = crane.cleanCargoSource ./.;

  # Common arguments can be set here to avoid repeating them later
  commonArgs = {
    src = dataplane-src;
    strictDeps = true;
    CARGO_PROFILE = "release";

    nativeBuildInputs = [
      dataplane-dev-pkgs.pkg-config
      # dataplane-pkgs.libclang.lib
    ];
    buildInputs = [
      dataplane-pkgs.hwloc
    ];

    env = {
      LIBCLANG_PATH = "${dataplane-pkgs.pkgsBuildHost.llvmPackages.libclang.lib}/lib";
      C_INCLUDE_PATH = "${sysroot}/include";
      LIBRARY_PATH = "${sysroot}/lib";
      PKG_CONFIG_PATH = "${sysroot}/lib/pkgconfig";
      GW_CRD_PATH = "${dataplane-dev-pkgs.gateway-crd}/src/gateway/config/crd/bases";
    };
  };
  # Build *just* the cargo dependencies (of the entire workspace),
  # so we can reuse all of that work (e.g. via cachix) when running in CI
  # It is *highly* recommended to use something like cargo-hakari to avoid
  # cache misses when building individual top-level-crates
  cargoArtifacts = crane.buildDepsOnly commonArgs;
  individualCrateArgs = commonArgs // {
    inherit cargoArtifacts;
    inherit (crane.crateNameFromCargoToml { src = dataplane-src; }) version;
    # NB: we disable tests since we'll run them all via cargo-nextest
    doCheck = false;
  };
  fileSetForCrate =
    crate:
    lib.fileset.toSource {
      root = ./.;
      fileset = lib.fileset.unions [
        ./.
      ];
    };
  package-list = builtins.fromJSON (
    builtins.readFile (
      dataplane-pkgs.runCommandLocal "package-list"
        {
          TOMLQ = "${dataplane-dev-pkgs.yq}/bin/tomlq";
          JQ = "${dataplane-dev-pkgs.jq}/bin/jq";
        }
        ''
          $TOMLQ -r '.workspace.members | sort[]' ${./.}/Cargo.toml | while read -r p; do
              $TOMLQ --arg p "$p" -r '{ ($p): .package.name }' ${./.}/$p/Cargo.toml
          done | $JQ --sort-keys --slurp 'add' > $out
        ''
    )
  );
  packages = builtins.mapAttrs (
    p: pname:
    (
      let
        package-expr =
          {
            pkg-config,
            kopium,
            llvmPackages,
          }:
          crane.buildPackage (
            individualCrateArgs
            // {
              inherit pname;
              cargoExtraArgs = "--package ${pname}";
              src = fileSetForCrate (./. + p);
              nativeBuildInputs = [
                pkg-config
                kopium
                llvmPackages.clang
                llvmPackages.lld
              ];
            }
          );
      in
      dataplane-pkgs.callPackage package-expr {
        inherit (dataplane-dev-pkgs) pkg-config kopium;
        inherit (dataplane-dev-pkgs) llvmPackages;
      }
    )
  ) package-list;

  package.rekon = crane.buildPackage (
    individualCrateArgs
    // {
      pname = "dataplane-rekon";
      cargoExtraArgs = "--package dataplane-rekon";
      src = fileSetForCrate ./rekon;
    }
  );
  package.net = crane.buildPackage (
    individualCrateArgs
    // {
      pname = "dataplane-net";
      cargoExtraArgs = "--package dataplane-net";
      src = fileSetForCrate ./net;
    }
  );
  package.cli = crane.buildPackage (
    individualCrateArgs
    // {
      pname = "dataplane-cli";
      cargoExtraArgs = "--package dataplane-cli";
      src = fileSetForCrate ./cli;
    }
  );
  package.dpdk-sysroot-helper = crane.buildPackage (
    individualCrateArgs
    // {
      pname = "dataplane-dpdk-sysroot-helper";
      cargoExtraArgs = "--package dataplane-dpdk-sysroot-helper";
      src = fileSetForCrate ./dpdk-sysroot-helper;
    }
  );
  package.dpdk-sys = crane.buildPackage (
    individualCrateArgs
    // {
      pname = "dataplane-dpdk-sys";
      cargoExtraArgs = "--package dataplane-dpdk-sys";
      src = fileSetForCrate ./dpdk-sys;
    }
  );
  package.pdpdk = crane.buildPackage (
    individualCrateArgs
    // {
      pname = "dataplane-dpdk";
      cargoExtraArgs = "--package dataplane-dpdk";
      src = fileSetForCrate ./dpdk;
    }
  );
  package.dataplane =
    let
      expr =
        {
          pkg-config,
          kopium,
          llvmPackages,
        }:
        crane.buildPackage (
          individualCrateArgs
          // {
            pname = "dataplane";
            cargoExtraArgs = "--package dataplane";
            src = fileSetForCrate ./dataplane;
            nativeBuildInputs = [
              pkg-config
              kopium
              # llvmPackages.libclang.lib
              # llvmPackages.clang
              # llvmPackages.lld
            ];
            buildInputs = [ ];
          }
        );
    in
    dataplane-pkgs.callPackage expr {
      # stdenv = dataplane-pkgs.stdenv';
      inherit (dataplane-dev-pkgs) pkg-config kopium;
      inherit (dataplane-pkgs) llvmPackages;
    };

in
{
  inherit
    cargoArtifacts
    commonArgs
    crane
    dataplane-dev-pkgs
    dataplane-pkgs
    devroot
    package
    package-list
    packages
    profile
    sources
    sysroot
    ;

  inherit (package)
    rekon
    net
    cli
    dataplane-dpdk-sysroot-helper
    dpdk-sys
    pdpdk
    dataplane
    ;
  platform = platform';
}
