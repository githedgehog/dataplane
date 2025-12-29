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
  rust-overlay = import sources.rust-overlay;
  dataplane-dev-pkgs = import sources.nixpkgs {
    overlays = [
      rust-overlay
      overlays.llvm
      overlays.dataplane-dev
    ];
  };
  dataplane-pkgs =
    (import sources.nixpkgs {
      overlays = [
        rust-overlay
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
      hwloc.static
    ];
  };
  clangd-config = dataplane-pkgs.writeTextFile {
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
  crane = import sources.crane { pkgs = dataplane-pkgs; };
  craneLib = crane.craneLib.overrideToolchain dataplane-pkgs.rust-toolchain;
  _devpkgs = [
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
    llvmPackages.clang # yes, you do actually need the host compiler in order to link proc macros
    npins
    pkg-config
    rust-toolchain
  ]);
  devroot = dataplane-pkgs.symlinkJoin {
    name = "dataplane-dev-shell";
    paths = _devpkgs;
  };
  shell = dataplane-pkgs.mkShell {
    packages = _devpkgs;
    env = {
      RUSTDOCFLAGS = "-D warnings";
    };
  };
  markdownFilter = p: _type: builtins.match ".*\.md$" p != null;
  cHeaderFilter = p: _type: builtins.match ".*\.h$" p != null;
  dataplane-src = dataplane-pkgs.lib.cleanSourceWith {
    name = "dataplane-source";
    src = ./.;
    filter =
      p: type:
      (craneLib.filterCargoSources p type) || (markdownFilter p type) || (cHeaderFilter p type);
  };

  cargoVendorDir = craneLib.vendorMultipleCargoDeps {
    cargoLockList = [
      ./Cargo.lock
      "${dataplane-pkgs.rust-toolchain.passthru.availableComponents.rust-src}/lib/rustlib/src/rust/library/Cargo.lock"
    ];
  };
  commonArgs = {
    src = dataplane-src;
    strictDeps = true;
    CARGO_PROFILE = cargo-profile;

    cargoBuildCommand = builtins.concatStringsSep " " [
      "cargo"
      "build"
      "--profile=${cargo-profile}"
      "-Zunstable-options"
      "-Zbuild-std=compiler_builtins,core,alloc,std,panic_unwind,proc_macro,sysroot"
      "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
      "--target=x86_64-unknown-linux-gnu"
    ];
    inherit cargoVendorDir;
    inherit (craneLib.crateNameFromCargoToml { src = dataplane-src; }) version;
    doCheck = false;

    env =
      let
        target = dataplane-pkgs.stdenv'.targetPlatform.rust.rustcTarget;
        isCross = dataplane-dev-pkgs.stdenv.hostPlatform.rust.rustcTarget != target;
        clang = if isCross then "${target}-clang" else "clang";
      in
      {
        DATAPLANE_SYSROOT = "${sysroot}";
        LIBCLANG_PATH = "${dataplane-pkgs.pkgsBuildHost.llvmPackages.libclang.lib}/lib";
        C_INCLUDE_PATH = "${sysroot}/include";
        LIBRARY_PATH = "${sysroot}/lib";
        PKG_CONFIG_PATH = "${sysroot}/lib/pkgconfig";
        GW_CRD_PATH = "${dataplane-dev-pkgs.gateway-crd}/src/gateway/config/crd/bases";
        RUSTC_BOOTSTRAP = "1";
        CARGO_BUILD_RUSTFLAGS = "";
        RUSTFLAGS = builtins.concatStringsSep " " (
          profile'.RUSTFLAGS
          ++ [
            "-Cdebuginfo=0"
            "-Ccodegen-units=1"
            "--cfg=tokio_unstable"
            "-Clink-arg=--ld-path=${devroot}/bin/ld.lld"
            "-Clinker=${devroot}/bin/${clang}"
          ]
        );
      };
  };
  # # Build *just* the cargo dependencies (of the entire workspace),
  # # so we can reuse all of that work (e.g. via cachix) when running in CI
  # # It is *highly* recommended to use something like cargo-hakari to avoid
  # # cache misses when building individual top-level-crates
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
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
  packages =
    let
      package-expr =
        {
          pkg-config,
          kopium,
          llvmPackages,
          hwloc,
          pname,
        }:
        craneLib.buildPackage (
          commonArgs
          // {
            # inherit pname cargoArtifacts;
            inherit pname;
            # TODO: remove target spec or make dynamic
            cargoExtraArgs = "--package=${pname} --target=x86_64-unknown-linux-gnu";
            nativeBuildInputs = [
              pkg-config
              kopium
              llvmPackages.clang
              llvmPackages.lld
            ];
            buildInputs = [
              hwloc.static
            ];
          }
        );
    in
    builtins.mapAttrs (
      _: pname:
      (dataplane-pkgs.callPackage package-expr {
        inherit (dataplane-dev-pkgs) kopium;
        inherit pname;
      })
    ) package-list;
    lints =
      let
        package-expr =
          {
            pkg-config,
            kopium,
            llvmPackages,
            hwloc,
            pname,
          }:
          craneLib.cargoClippy {
            inherit pname cargoArtifacts;
            inherit (commonArgs) version src env;
            cargoExtraArgs = "--package=${pname}";
            nativeBuildInputs = [
              pkg-config
              kopium
              llvmPackages.clang
              llvmPackages.lld
            ];
            buildInputs = [
              hwloc.static
            ];
          };
      in
      builtins.mapAttrs (
        _: pname:
        (dataplane-pkgs.callPackage package-expr {
            inherit pname;
            inherit (dataplane-dev-pkgs) kopium;
        })
      ) package-list;
in
{
  inherit
    # cargoArtifacts
    commonArgs

    dataplane-dev-pkgs
    dataplane-pkgs
    devroot
    package-list
    packages
    sources
    sysroot
    _devpkgs
    shell
    lints
    ;
  crane = craneLib;
  profile = profile';
  platform = platform';
}
