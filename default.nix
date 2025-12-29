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
  craneLibCrossEnv = crane.craneLib.mkCrossToolchainEnv (p: p.stdenv');
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
      p: type: (craneLib.filterCargoSources p type) || (markdownFilter p type) || (cHeaderFilter p type);
  };

  cargoVendorDir = craneLib.vendorMultipleCargoDeps {
    cargoLockList = [
      ./Cargo.lock
      "${dataplane-pkgs.rust-toolchain.passthru.availableComponents.rust-src}/lib/rustlib/src/rust/library/Cargo.lock"
    ];
  };
  target = dataplane-pkgs.stdenv'.targetPlatform.rust.rustcTarget;
  isCross = dataplane-dev-pkgs.stdenv.hostPlatform.rust.rustcTarget != target;
  cc = if isCross then "${target}-clang" else "clang";
  commonArgs = {
    src = dataplane-src;
    strictDeps = true;
    CARGO_PROFILE = cargo-profile;

    cargoBuildCommand = builtins.concatStringsSep " " [
      "cargo"
      "build"
      "--profile=${cargo-profile}"
      "-Zunstable-options"
      "-Zbuild-std=compiler_builtins,std,panic_unwind,sysroot"
      "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
      "--target=${target}"
    ];
    inherit cargoVendorDir;
    inherit (craneLib.crateNameFromCargoToml { src = dataplane-src; }) version;
    doCheck = false;
    dontStrip = true;

    env = {
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
          "--cfg=tokio_unstable"
          "-Clink-arg=--ld-path=${devroot}/bin/ld.lld"
          "-Clinker=${devroot}/bin/${cc}"
        ]
      );
    };
  };

  commonArgs-nextest = {
    src = dataplane-src;
    strictDeps = true;
    CARGO_PROFILE = cargo-profile;

    cargoBuildCommand = builtins.concatStringsSep " " [
      "cargo"
      "nextest"
      "archive"
      "--profile=${cargo-profile}"
      "-Zunstable-options"
      "-Zbuild-std=compiler_builtins,std,panic_unwind,sysroot"
      "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
      "--target=${target}"
    ];
    inherit cargoVendorDir;
    inherit (craneLib.crateNameFromCargoToml { src = dataplane-src; }) version;
    doCheck = false;
    dontStrip = true;

    env = {
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
          "--cfg=tokio_unstable"
          "-Clink-arg=--ld-path=${devroot}/bin/ld.lld"
          "-Clinker=${devroot}/bin/${cc}"
        ]
      );
    };
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
  package-expr =
    {
      operation,
      cargoArtifacts ? null,
      pname ? null,
    }:
    {
      pkg-config,
      kopium,
      llvmPackages,
      hwloc,
    }:
    craneLib.${operation} (
      commonArgs
      // {
        inherit pname cargoArtifacts;
        cargoExtraArgs = (if pname != null then "--package=${pname} " else "") + "--target=${target}";
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
  nextest-expr =
    {
      cargoArtifacts ? null,
      pname ? null,
    }:
    dataplane-pkgs.callPackage (
      {
        stdenv',
        pkg-config,
        kopium,
        cargo-nextest,
        llvmPackages,
        hwloc,
        rust-toolchain,
      }:
      stdenv'.mkDerivation (
        commonArgs-nextest
        // {
          inherit pname cargoArtifacts;
          buildCommand = builtins.concatStringsSep " " [
            "cd $src;"
            "cargo"
            "nextest"
            "archive"
            "--profile=${cargo-profile}"
            "-Zunstable-options"
            "-Zbuild-std=compiler_builtins,std,panic_unwind,sysroot"
            "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
            (
              "--target=${target} "
              + (
                if pname != null then
                  "--package=${pname} --archive-file $out/${pname}.tar.zst "
                else
                  "--archive-file $out/nextest.tar.zst "
              )
            )
          ];
          nativeBuildInputs = [
            pkg-config
            kopium
            llvmPackages.clang
            llvmPackages.lld
            rust-toolchain
            cargo-nextest
          ];
          buildInputs = [
            hwloc.static
          ];
        }
      )
    );
  craneOp =
    {
      operation ? "buildPackage",
      cargoArtifacts ? null,
      pname ? null,
    }@inputs:
    (dataplane-pkgs.callPackage (package-expr (inputs // { inherit pname; })) {
      inherit (dataplane-dev-pkgs) kopium;
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
  nextestOp =
    {
      cargoArtifacts ? null,
      pname ? null,
    }@inputs:
    (
      ((nextest-expr (inputs // { inherit pname; })) {
        inherit (dataplane-dev-pkgs) kopium cargo-nextest;
      })
    ).overrideAttrs
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
  cargo.build = builtins.mapAttrs (
    _: pname:
    craneOp {
      operation = "buildPackage";
      inherit pname;
    }
  ) package-list;
  cargo.clippy = craneOp {
    operation = "cargoClippy";
    cargoArtifacts = cargo.build.dataplane;
  };
  cargo.nextest = builtins.mapAttrs (
    package: pname:
    (nextest-expr {
      cargoArtifacts = cargo.build.${package};
      inherit pname;
    })
      {
        inherit (dataplane-dev-pkgs) kopium cargo-nextest;
      }
  ) package-list;
  cargo.doctest = craneOp {
    operation = "cargoDocTest";
    cargoArtifacts = cargo.build.dataplane;
  };
in
{
  inherit
    # cargoArtifacts
    commonArgs

    dataplane-dev-pkgs
    dataplane-pkgs
    devroot
    package-list
    sources
    sysroot
    _devpkgs
    shell
    craneLibCrossEnv
    cargo
    ;
  crane = craneLib;
  profile = profile';
  platform = platform';
}
