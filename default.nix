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
  lib = (import sources.nixpkgs { }).lib;
  # helper method to work around nix's contrived builtin string split function.
  split-str =
    split-on: string:
    if string == "" then
      [ ]
    else
      builtins.filter (elm: builtins.isString elm) (builtins.split split-on string);
  sanitizers = split-str ",+" sanitize;
  sources = import ./npins;
  platform' = import ./nix/platforms.nix {
    inherit lib platform libc;
  };
  profile' = import ./nix/profiles.nix {
    inherit sanitizers instrumentation profile;
    arch = platform'.arch;
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
      # overlays.dataplane-dev
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
      hwloc.static
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
    ++ (with pkgs.pkgsBuildHost.llvmPackages; [
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
      llvmPackages.clang # yes, you do actually need the host compiler in order to link proc macros
      npins
      pkg-config
      rust-toolchain
    ]);
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
  package-list = builtins.fromJSON (
    builtins.readFile (
      pkgs.runCommandLocal "package-list"
        {
          TOMLQ = "${dev-pkgs.yq}/bin/tomlq";
          JQ = "${dev-pkgs.jq}/bin/jq";
        }
        ''
          $TOMLQ -r '.workspace.members | sort[]' ${src}/Cargo.toml | while read -r p; do
            $TOMLQ --arg p "$p" -r '{ ($p): .package.name }' ${src}/$p/Cargo.toml
          done | $JQ --sort-keys --slurp 'add' > $out
        ''
    )
  );
  version = (craneLib.crateNameFromCargoToml { inherit src; }).version;
  cargo-cmd-prefix = builtins.concatStringsSep " " [
    "--profile=${cargo-profile}"
    "-Zunstable-options"
    "-Zbuild-std=compiler_builtins,std,panic_unwind,sysroot"
    "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
    "--target=${target}"
  ];
  package-expr-builder =
    {
      cargoArtifacts ? null,
      pname ? null,
    }:
    {
      pkg-config,
      kopium,
      llvmPackages,
      hwloc,
    }:
    craneLib.buildPackage {
      inherit
        src
        version
        pname
        cargoArtifacts
        cargoVendorDir
        ;

      doCheck = false;
      strictDeps = true;
      dontStrip = true;

      nativeBuildInputs = [
        pkg-config
        kopium
        llvmPackages.clang
        llvmPackages.lld
      ];

      buildInputs = [
        hwloc.static
      ];

      env = {
        CARGO_PROFILE = cargo-profile;
        DATAPLANE_SYSROOT = "${sysroot}";
        LIBCLANG_PATH = "${pkgs.pkgsBuildHost.llvmPackages.libclang.lib}/lib";
        C_INCLUDE_PATH = "${sysroot}/include";
        LIBRARY_PATH = "${sysroot}/lib";
        PKG_CONFIG_PATH = "${sysroot}/lib/pkgconfig";
        GW_CRD_PATH = "${dev-pkgs.gateway-crd}/src/gateway/config/crd/bases";
        RUSTC_BOOTSTRAP = "1";
        CARGO_BUILD_RUSTFLAGS = "";
        RUSTFLAGS = builtins.concatStringsSep " " (
          profile'.RUSTFLAGS
          ++ [
            "--cfg=tokio_unstable"
            "-Clink-arg=--ld-path=${devroot}/bin/ld.lld"
            "-Clinker=${devroot}/bin/${cc}"
          ]
        );
      };

      cargoBuildCommand = builtins.concatStringsSep " " (
        [
          "cargo"
          "build"
        ]
        ++ cargo-cmd-prefix
      );
      cargoExtraArgs = (if pname != null then "--package=${pname} " else "") + "--target=${target}";
    };
  cli =
    let
      pkgs-expr = package-expr-builder {
        pname = "dataplane-cli";
      };
    in
    (pkgs.callPackage pkgs-expr {
      inherit (dev-pkgs) kopium;
    }).overrideAttrs
      (orig: {
        # I'm not 100% sure if I would call it a bug in crane or a bug in cargo, but there is no easy way to distinguish
        # RUSTFLAGS intended for the build-time dependencies from the RUSTFLAGS intended for the runtime dependencies.
        # One unfortunate conseqnence of this is that is you set platform specific RUSTFLAGS then the postBuild hook
        # malfunctions in the cross compile.  Fortunately, the "fix" is easy: just unset RUSTFLAGS before the postBuild
        # hook actually runs.
        postBuild = ''
          unset RUSTFLAGS;
        ''
        + (orig.postBuild or "");
      });
in
{
  inherit
    # cargoArtifacts
    pkgs
    dev-pkgs
    devroot
    package-list
    sources
    sysroot
    cli
    ;
  crane = craneLib;
  profile = profile';
  platform = platform';
}
