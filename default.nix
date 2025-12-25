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
  overlays = import ./nix/overlays {
    inherit
      sources
      sanitizers
      ;
    profile = profile';
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
    CARGO_PROFILE = "dev";

    nativeBuildInputs = [
      dataplane-dev-pkgs.pkg-config
      # dataplane-pkgs.libclang.lib
    ];
    buildInputs = [
      dataplane-pkgs.hwloc
    ];

    env = {
      PATH = "${devroot}/bin";
      LIBCLANG_PATH = "${dataplane-pkgs.pkgsBuildHost.llvmPackages.libclang.lib}/lib";
      C_INCLUDE_PATH = "${sysroot}/include";
      LIBRARY_PATH = "${sysroot}/lib";
      PKG_CONFIG_PATH = "${sysroot}/lib/pkgconfig";
      GW_CRD_PATH = "${dataplane-dev-pkgs.gateway-crd}/src/gateway/config/crd/bases";
      RUSTC_BOOTSTRAP = "1";
      # RUSTFLAGS = "potato";
      RUSTFLAGS = "--cfg=tokio_unstable -Ccodegen-units=64 -Cdebug-assertions=on -Cdebuginfo=full -Cdwarf-version=5 -Clink-arg=-fuse-ld=lld -Clink-arg=--ld-path=${devroot}/bin/ld.lld -Clinker=${devroot}/bin/clang -Copt-level=0 -Coverflow-checks=on -Ctarget-cpu=generic";
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
  # TODO: this is hacky nonsense, clean up the fileset call
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
        src = fileSetForCrate (./. + p);
        package-expr =
          {
            pkg-config,
            kopium,
            llvmPackages,
          }:
          crane.buildPackage (
            individualCrateArgs
            // {
              inherit pname src;
              cargoExtraArgs = "-Z unstable-options -Z build-std --package ${pname}";
              cargoVendorDir = crane.vendorMultipleCargoDeps {
                inherit (crane.findCargoFiles src) cargoConfigs;
                cargoLockList = [
                  ./Cargo.lock

                  # Unfortunately this approach requires IFD (import-from-derivation)
                  # otherwise Nix will refuse to read the Cargo.lock from our toolchain
                  # (unless we build with `--impure`).
                  #
                  # Another way around this is to manually copy the rustlib `Cargo.lock`
                  # to the repo and import it with `./path/to/rustlib/Cargo.lock` which
                  # will avoid IFD entirely but will require manually keeping the file
                  # up to date!
                  "${dataplane-dev-pkgs.rust-bin.passthru.availableComponents.rust-src}/lib/rustlib/src/rust/library/Cargo.lock"
                ];
              };
              # RUSTC_BOOTSTRAP = "1";
              # env = {
              #   RUSTC_BOOTSTRAP = "1";
              # };
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
        inherit (dataplane-dev-pkgs) pkg-config kopium llvmPackages;
      }
    )
  ) package-list;
in
{
  inherit
    cargoArtifacts
    commonArgs
    crane
    dataplane-dev-pkgs
    dataplane-pkgs
    devroot
    package-list
    packages
    sources
    sysroot
    ;
  profile = profile';
  platform = platform';
}
