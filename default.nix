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
  cargo-cmd-prefix = [
    "-Zunstable-options"
    "-Zbuild-std=compiler_builtins,core,alloc,std,panic_unwind,panic_abort,sysroot,unwind"
    "--target=${target}"
  ]
  ++ (
    if builtins.elem "thread" sanitizers then
      [
        "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
      ]
    else
      [
        "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem,llvm-libunwind"
      ]
  );
  invoke =
    {
      builder,
      args ? {
        pname = null;
        cargoArtifacts = null;
      },
      cargo-nextest,
      hwloc,
      llvmPackages',
      pkg-config,
    }:
    (builder (
      {
        inherit
          src
          version
          cargoVendorDir
          ;

        doCheck = false;
        strictDeps = true;
        dontStrip = true;
        doRemapPathPrefix = false; # TODO: this setting may be wrong, test with debugger
        doNotRemoveReferencesToRustToolchain = true;
        doNotRemoveReferencesToVendorDir = true;
        separateDebugInfo = true;

        nativeBuildInputs = [
          (dev-pkgs.kopium)
          cargo-nextest
          llvmPackages'.clang
          llvmPackages'.lld
          pkg-config
        ];

        buildInputs = [
          hwloc
        ];

        env = {
          CARGO_PROFILE = cargo-profile;
          DATAPLANE_SYSROOT = "${sysroot}";
          LIBCLANG_PATH = "${pkgs.pkgsBuildHost.llvmPackages'.libclang.lib}/lib";
          C_INCLUDE_PATH = "${sysroot}/include";
          LIBRARY_PATH = "${sysroot}/lib";
          PKG_CONFIG_PATH = "${sysroot}/lib/pkgconfig";
          GW_CRD_PATH = "${dev-pkgs.gateway-crd}/src/gateway/config/crd/bases";
          RUSTC_BOOTSTRAP = "1";
          RUSTFLAGS = builtins.concatStringsSep " " (
            profile'.RUSTFLAGS
            ++ [
              "-Clinker=${pkgs.pkgsBuildHost.llvmPackages'.clang}/bin/${cc}"
              "-Clink-arg=--ld-path=${pkgs.pkgsBuildHost.llvmPackages'.lld}/bin/ld.lld"
              "-Clink-arg=-L${sysroot}/lib"
              # NOTE: this is basically a trick to make our source code available to debuggers.
              # Normally remap-path-prefix takes the form --remap-path-prefix=FROM=TO where FROM and TO are directories.
              # This is intended to map source code paths to generic, relative, or redacted paths.
              # We are sorta using that mechanism in reverse here in that the empty FROM in the next expression maps our
              # source code in the debug info from the current working directory to ${src} (the nix store path where we
              # have copied our source code).
              #
              # This is nice in that it should allow us to include ${src} in a container with gdb / lldb + the debug files
              # we strip out of the final binaries we cook and include a gdbserver binary in some
              # debug/release-with-debug-tools containers.  Then, connecting from the gdb/lldb container to the
              # gdb/lldbserver container should allow us to actually debug binaries deployed to test machines.
              "--remap-path-prefix==${src}"
            ]
            ++ (
              if ((builtins.elem "thread" sanitizers) || (builtins.elem "safe-stack" sanitizers)) then
                [
                  # "-Zexternal-clangrt"
                  # "-Clink-arg=--rtlib=compiler-rt"
                ]
              else
                [ ]
            )
          );
        };
      }
      // args
    )).overrideAttrs
      (orig: {
        separateDebugInfo = true;

        # I'm not 100% sure if I would call it a bug in crane or a bug in cargo, but cross compile is tricky here.
        # There is no easy way to distinguish RUSTFLAGS intended for the build-time dependencies from the RUSTFLAGS
        # intended for the runtime dependencies.
        # One unfortunate consequence of this is that if you set platform specific RUSTFLAGS then the postBuild hook
        # malfunctions.  Fortunately, the "fix" is easy: just unset RUSTFLAGS before the postBuild hook actually runs.
        # We don't need to set any optimization flags for postBuild tooling anyway.
        postBuild = (orig.postBuild or "") + ''
          unset RUSTFLAGS;
        '';
        postInstall = (orig.postInstall or "") + ''
          mkdir -p $debug/bin
          for f in $out/bin/*; do
            mv "$f" "$debug/bin/$(basename "$f")"
            ${strip} --strip-debug "$debug/bin/$(basename "$f")" -o "$f"
            ${objcopy} --add-gnu-debuglink="$debug/bin/$(basename "$f")" "$f"
          done
        '';
        postFixup = (orig.postFixup or "") + ''
          rm -f $out/target.tar.zst
        '';
      });
  package-builder =
    {
      pname ? null,
      cargoArtifacts ? null,
    }:
    pkgs.callPackage invoke {
      builder = craneLib.buildPackage;
      args = {
        inherit pname cargoArtifacts;
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          [
            "cargoBuildLog=$(mktemp cargoBuildLogXXXX.json);"
            "cargo"
            "build"
            "--package=${pname}"
            "--profile=${cargo-profile}"
          ]
          ++ cargo-cmd-prefix
          ++ [
            "--message-format json-render-diagnostics > $cargoBuildLog"
          ]
        );
      };
    };

  workspace = builtins.mapAttrs (
    dir: pname:
    package-builder {
      inherit pname;
    }
  ) package-list;

  test-builder =
    {
      pname ? null,
      cargoArtifacts ? null,
    }:
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      args = {
        inherit pname cargoArtifacts;
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          [
            "mkdir -p $out;"
            "cargo"
            "nextest"
            "archive"
            "--archive-file"
            "$out/${pname}.tar.zst"
            "--cargo-profile=${cargo-profile}"
            "--package=${pname}"
          ]
          ++ cargo-cmd-prefix
        );
      };
    };

  tests = builtins.mapAttrs (
    dir: pname:
    test-builder {
      inherit pname;
    }
  ) package-list;

  clippy-builder =
    {
      pname ? null,
    }:
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      args = {
        inherit pname;
        cargoArtifacts = null;
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          [
            "cargo"
            "clippy"
            "--profile=${cargo-profile}"
            "--package=${pname}"
          ]
          ++ cargo-cmd-prefix
          ++ [
            "--"
            "-D warnings"
          ]
        );
      };
    };

  clippy = builtins.mapAttrs (
    dir: pname:
    clippy-builder {
      inherit pname;
    }
  ) package-list;

in
{
  inherit
    dev-pkgs
    devroot
    devenv
    pkgs
    sysroot
    tests
    workspace
    ;
  profile = profile';
  platform = platform';

}
