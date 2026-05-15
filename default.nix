# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  platform ? "x86-64-v3",
  libc ? "gnu",
  profile ? "debug",
  instrumentation ? "none",
  sanitize ? "",
  features ? "",
  default-features ? "true",
  kernel ? "linux",
  tag ? "dev",
  nightly ? "false",
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
  extra-platforms =
    if platform == "all" then
      let
        triples = import ./nix/triples.nix;
        # Flatten triples.nix into a list of records carrying arch, os,
        # libc plus the leaf fields (target, machine, nixarch, ...).
        options = lib.flatten (
          lib.mapAttrsToList (
            arch: oses:
            lib.mapAttrsToList (
              os: libcs:
              lib.mapAttrsToList (libc: leaf: leaf // { inherit arch os libc; }) libcs
            ) oses
          ) triples
        );
        # One canonical hardware name per arch.  hardware.nix carries
        # SOC-specific march tuning (zen*, bluefield*, x86-64-v4, ...),
        # but the cargo target triple is arch-determined, not
        # march-determined -- so for "support every target" we only
        # need one hardware per arch.  To exercise SOC tuning, invoke
        # platform=<specific-name> directly.
        canonical-hardware = {
          x86_64 = "x86-64-v3";
          aarch64 = "aarch64";
          wasm32 = "wasm32-wasip1";
        };
      in
      map (
        option:
        import ./nix/platforms.nix {
          inherit lib;
          platform = canonical-hardware.${option.arch};
          kernel = option.os;
          libc = option.libc;
        }
      ) options
    else
      [ ];
  # Matrix presets for the `cross` CI job.  Pure data: each entry is
  # `{ platform, libc }` (kernel is implied by the arch -- `linux` for
  # x86_64/aarch64, `wasip1` for wasm32 which is already covered by the
  # `wasm` CI job and therefore omitted from cross).  Consumed by
  # `.github/workflows/dev.yml` via `nix eval --json -f default.nix
  # 'cross-matrix.<preset>'`.
  cross-matrix =
    let
      hardware = import ./nix/hardware.nix { inherit lib; };
      triples = import ./nix/triples.nix;
      # Every hardware in hardware.nix × every valid libc for that
      # hardware's arch per triples.nix.  Skips wasm32 because the
      # `wasm` CI job already covers it and the build path is materially
      # different anyway.
      all-linux-targets = lib.concatMap (
        hw:
        let
          arch = hardware.${hw}.arch;
        in
        if arch == "wasm32" then
          [ ]
        else
          lib.mapAttrsToList (libc: _: { platform = hw; inherit libc; }) triples.${arch}.linux
      ) (builtins.attrNames hardware);
    in
    {
      # Today's hand-picked default set: aarch64 + bluefield3 × gnu + musl.
      # Exercises the SOC-specific cross paths most likely to catch a
      # regression without the cost of building every variant.
      default = [
        {
          platform = "aarch64";
          libc = "gnu";
        }
        {
          platform = "aarch64";
          libc = "musl";
        }
        {
          platform = "bluefield3";
          libc = "gnu";
        }
        {
          platform = "bluefield3";
          libc = "musl";
        }
      ];
      # Rare full-suite mode: every hardware × every valid libc.
      # Currently 16 records (8 hardware × 2 libcs each, wasm32-wasip1
      # excluded).  Triggered by the `ci:+full-cross` PR label or
      # `cross_scope=full` on workflow_dispatch.
      full = all-linux-targets;
      # Explicit opt-out: produces no cross legs.
      skip = [ ];
    };
  platform' = import ./nix/platforms.nix {
    inherit
      lib
      libc
      kernel
      ;
    platform = (if platform == "all" then "x86-64-v3" else platform);
  };
  sanitizers = split-str ",+" sanitize;
  cargo-features = split-str ",+" features;
  profile' = import ./nix/profiles.nix {
    inherit
      sanitizers
      instrumentation
      profile
      cargo-features
      ;
    inherit (platform') arch;
  };
  # Test archives run on the host (e.g. `cargo nextest run --archive-file`)
  # rather than in the nix build sandbox, so panics in fixtures must
  # unwind for cleanup (netns / caps) to run.  See `test-utils/src/lib.rs`.
  profile-tests' = import ./nix/profiles.nix {
    inherit
      sanitizers
      instrumentation
      profile
      cargo-features
      ;
    inherit (platform') arch;
    for-tests = true;
  };
  cargo-profile =
    {
      "debug" = "dev";
      "release" = "release";
      "fuzz" = "fuzz";
    }
    .${profile};
  overlays = import ./nix/overlays {
    inherit
      extra-platforms
      libc
      nightly
      sanitizers
      sources
      ;
    profile = profile';
    platform = platform';
  };
  pkgs =
    let
      over = import sources.nixpkgs {
        overlays = [
          overlays.rust
          overlays.llvm
          overlays.dataplane
          overlays.dataplane-dev
          overlays.frr
        ];
      };
    in
    if platform != "wasm32-wasip1" then over.pkgsCross.${platform'.info.nixarch} else over;
  sysroot =
    if platform != "wasm32-wasip1" then
      pkgs.symlinkJoin {
        name = "sysroot";
        paths = with pkgs.pkgsHostHost; [
          pkgs.pkgsHostHost.libc.dev # fully qualified: bare `libc` resolves to the "gnu" function argument, not pkgs.pkgsHostHost.libc
          pkgs.pkgsHostHost.libc.out # (same as above)
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
      }
    else
      pkgs.symlinkJoin {
        name = "sysroot";
        paths = with pkgs.pkgsHostHost; [
          fancy.hwloc.dev
          fancy.hwloc.static
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
  crane = import sources.crane { inherit pkgs; };
  craneLib = crane.craneLib.overrideToolchain pkgs.rust-toolchain;
  devroot = pkgs.symlinkJoin {
    name = "dataplane-dev-shell";
    paths = [
      clangd-config
    ]
    # pkgsBuildBuild (not pkgsBuildHost): dev-shell tools run on, and target,
    # the build host.  pkgsBuildHost is "runs on build, targets host", which
    # under a cross pkgs (e.g. libc=musl, platform=bluefield3) installs only
    # target-prefixed binaries (e.g. x86_64-unknown-linux-musl-pkg-config) --
    # cargo build scripts that invoke `pkg-config`/`clang` unprefixed then fail
    # to find them in PATH.
    ++ (with pkgs.pkgsBuildBuild.llvmPackages'; [
      bintools
      clang
      libclang.lib
      lld
    ])
    ++ (with pkgs.pkgsBuildBuild; [
      actionlint
      bash
      cargo-bolero
      cargo-deny
      cargo-depgraph
      cargo-edit
      cargo-llvm-cov
      cargo-nextest
      direnv
      gateway-crd
      gettext
      jq
      just
      kopium
      llvmPackages'.clang # you need the host compiler in order to link proc macros
      llvmPackages'.llvm # needed for coverage
      npins
      opengrep
      openssl
      oras
      pkg-config
      python3Packages.pyflakes
      qemu-user
      rust-toolchain
      shellcheck
      skopeo
      wasmtime
      wget
      yq
    ]);
  };
  devenv = pkgs.mkShell {
    name = "dataplane-dev-shell";
    packages = [ devroot ];
    inputsFrom = [ sysroot ];
    env = {
      RUSTC_BOOTSTRAP = "1";
      DATAPLANE_SYSROOT = "${sysroot}";
      C_INCLUDE_PATH = "${sysroot}/include";
      LIBRARY_PATH = "${sysroot}/lib";
      PKG_CONFIG_PATH = "${sysroot}/lib/pkgconfig";
      LIBCLANG_PATH = "${devroot}/lib";
      GW_CRD_PATH = "${pkgs.pkgsBuildHost.gateway-crd}/src/fabric/config/crd/bases";
      # Pin native cargo invocations (cargo build/clippy/test --doc) to the
      # same target the dev sysroot is built for.  Without this, cargo defaults
      # to the build-host triple while LIBRARY_PATH/PKG_CONFIG_PATH point at
      # cross-target libs, and the link picks up a libc that doesn't match the
      # rust-std it's compiling against (e.g. glibc rust-std + musl libc =
      # undefined `open64`/`fstat64`/...).
      CARGO_BUILD_TARGET = rustc-target;
      # Rust's pkg-config crate refuses cross-target builds by default; opt in
      # since our PKG_CONFIG_PATH already points at the matching cross sysroot.
      PKG_CONFIG_ALLOW_CROSS = "1";
    };
  };
  justfileFilter = p: _type: builtins.match ".*\.justfile$" p != null;
  markdownFilter = p: _type: builtins.match ".*\.md$" p != null;
  jsonFilter = p: _type: builtins.match ".*\.json$" p != null;
  cHeaderFilter = p: _type: builtins.match ".*\.h$" p != null;
  outputsFilter = p: _type: (p != "target") && (p != "sysroot") && (p != "devroot") && (p != ".git");
  src = pkgs.lib.cleanSourceWith {
    filter =
      full-path: t:
      let
        p = baseNameOf full-path;
      in
      (justfileFilter p t)
      || (markdownFilter p t)
      || (jsonFilter p t)
      || (cHeaderFilter p t)
      || ((outputsFilter p t) && (craneLib.filterCargoSources full-path t));
    src = lib.cleanSource ./.;
    name = "source";
  };
  cargoVendorDir = craneLib.vendorMultipleCargoDeps {
    cargoLockList = [
      ./Cargo.lock
      "${pkgs.rust-toolchain.passthru.availableComponents.rust-src}/lib/rustlib/src/rust/library/Cargo.lock"
    ];
  };
  # For wasm32, pkgs is the host nixpkgs (no pkgsCross), so ctarget resolves to the
  # host platform (e.g. x86_64-unknown-linux-gnu).  That means is-cross-compile is
  # false for wasm, which is intentional: we don't want native cross-compilation
  # tooling (strip, objcopy, prefixed clang) — cargo + rustc handle wasm natively.
  # rustc-target is the actual --target we pass to cargo, which diverges from ctarget
  # only for wasm.
  ctarget = pkgs.stdenv'.targetPlatform.rust.rustcTarget;
  rustc-target =
    if platform == "wasm32-wasip1" then
      "wasm32-wasip1"
    else
      pkgs.stdenv'.targetPlatform.rust.rustcTarget;
  is-cross-compile = pkgs.stdenv'.buildPlatform.rust.rustcTarget != ctarget;
  cxx = if is-cross-compile then "${ctarget}-clang++" else "clang++";
  strip = if is-cross-compile then "${ctarget}-strip" else "strip";
  objcopy = if is-cross-compile then "${ctarget}-objcopy" else "objcopy";
  package-list = builtins.fromJSON (
    builtins.readFile (
      pkgs.runCommandLocal "package-list"
        {
          TOMLQ = "${pkgs.pkgsBuildHost.yq}/bin/tomlq";
          JQ = "${pkgs.pkgsBuildHost.jq}/bin/jq";
        }
        (
          if platform == "wasm32-wasip1" then
            ''
              $TOMLQ -r '.workspace as $ws | [$ws.members[] | select($ws.metadata.package[.].wasm != false) as $p | { ($p): $ws.dependencies[$p].package }] | add' ${src}/Cargo.toml > $out
            ''
          else
            ''
              $TOMLQ -r '.workspace.members | sort[]' ${src}/Cargo.toml | while read -r p; do
                  $TOMLQ --arg p "$p" -r '{ ($p): .package.name }' ${src}/$p/Cargo.toml
              done | $JQ --sort-keys --slurp 'add' > $out
            ''
        )
    )
  );
  version = (craneLib.crateNameFromCargoToml { inherit src; }).version;
  # The `loom` and `shuttle` features require `panic = "unwind"` (see
  # nix/profiles.nix), as do test builds.  The sysroot needs the matching
  # panic runtime and std feature, so we build two cargo command prefixes:
  # `cargo-cmd-prefix` for production code and `cargo-cmd-prefix-tests`
  # for the nextest archives.
  mk-needs-unwind =
    for-tests:
    for-tests || builtins.elem "loom" cargo-features || builtins.elem "shuttle" cargo-features;
  needs-unwind = mk-needs-unwind false;
  needs-unwind-tests = mk-needs-unwind true;
  mk-cargo-cmd-prefix =
    unwind:
    [
      "-Zunstable-options"
      "-Zbuild-std=std,${if unwind then "panic_unwind" else "panic_abort"}"
      # note: retention of libunwind on non-glibc is correct in spite of the panic=abort; `backtrace` needs a stack
      # walker even when panic=abort.  In the case of glibc, libgcc_s.so fills that role.  You can't escape libgcc_s.so
      # regardless: it is linked to glibc's libc.so anyway.
      (
        "-Zbuild-std-features=backtrace"
        + (if unwind then ",panic-unwind" else "")
        + (if libc != "gnu" then ",system-llvm-libunwind" else "")
      )
      "--target=${rustc-target}"
    ]
    ++ (if default-features == "false" then [ "--no-default-features" ] else [ ])
    ++ (
      if cargo-features != [ ] then
        [ "--features=${builtins.concatStringsSep "," cargo-features}" ]
      else
        [ ]
    );
  cargo-cmd-prefix = mk-cargo-cmd-prefix needs-unwind;
  cargo-cmd-prefix-tests = mk-cargo-cmd-prefix needs-unwind-tests;
  invoke =
    {
      builder,
      args ? {
        pname = null;
        cargoArtifacts = null;
      },
      profile,
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
        removeReferencesToRustToolchain = true;
        removeReferencesToVendorDir = true;

        nativeBuildInputs = [
          (pkgs.pkgsBuildHost.kopium)
          cargo-nextest
          llvmPackages'.clang
          llvmPackages'.lld
          pkg-config
        ];

        buildInputs = [
          hwloc
        ];

        env = {
          VERSION = tag;
          CARGO_PROFILE = cargo-profile;
          DATAPLANE_SYSROOT = "${sysroot}";
          LIBCLANG_PATH = "${pkgs.pkgsBuildHost.llvmPackages'.libclang.lib}/lib";
          C_INCLUDE_PATH = "${sysroot}/include";
          LIBRARY_PATH = "${sysroot}/lib";
          PKG_CONFIG_PATH = "${sysroot}/lib/pkgconfig";
          GW_CRD_PATH = "${pkgs.pkgsBuildHost.gateway-crd}/src/fabric/config/crd/bases";
          RUSTC_BOOTSTRAP = "1";
          RUSTFLAGS =
            if rustc-target != "wasm32-wasip1" then
              builtins.concatStringsSep " " (
                profile.RUSTFLAGS
                ++ [
                  "-Clinker=${pkgs.pkgsBuildHost.llvmPackages'.clang}/bin/${cxx}"
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
              )
            else
              "";
        };
      }
      // args
    )).overrideAttrs
      (orig: {
        # Source-volatile: tag with a distinctive prefix so the CI
        # cachix pushFilter can exclude every cargo-derived path in
        # one regex, and disable substitute attempts so a cold runner
        # doesn't waste a roundtrip asking the cache for a path that
        # always misses (it would always miss because the source
        # revision is in the input closure).
        name = "dataplane-cargo-${orig.pname}-${orig.version}";
        allowSubstitutes = false;
        preferLocalBuild = true;

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
        postInstall =
          (orig.postInstall or "")
          + (
            if rustc-target != "wasm32-wasip1" then
              ''
                mkdir -p $debug/bin
                for f in $out/bin/*; do
                  mv "$f" "$debug/bin/$(basename "$f")"
                  ${strip} --strip-debug "$debug/bin/$(basename "$f")" -o "$f"
                  ${objcopy} --add-gnu-debuglink="$debug/bin/$(basename "$f")" "$f"
                done
              ''
            else
              ''
                mkdir -p $debug/bin
                for f in $out/bin/*; do
                  mv "$f" "$debug/bin/$(basename "$f")"
                  ${pkgs.pkgsBuildHost.binaryen}/bin/wasm-opt "$debug/bin/$(basename "$f")" --strip-debug -O4 -o "$f"
                  # sadly there is no equivalent of gnu-debuglink in wasm world yet
                done
              ''
          );
        postFixup = (orig.postFixup or "") + ''
          rm -f $out/target.tar.zst
        '';
      });
  workspace-builder =
    {
      pname ? null,
      cargoArtifacts ? null,
    }:
    pkgs.callPackage invoke {
      builder = craneLib.buildPackage;
      profile = profile';
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
    workspace-builder {
      inherit pname;
    }
  ) package-list;

  workspace-check =
    {
      pname ? null,
      cargoArtifacts ? null,
    }:
    pkgs.callPackage invoke {
      builder = craneLib.buildPackage;
      profile = profile';
      args = {
        inherit pname cargoArtifacts;
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          [
            "cargoBuildLog=$(mktemp cargoBuildLogXXXX.json);"
            "cargo"
            "check"
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

  check = builtins.mapAttrs (
    dir: pname:
    workspace-check {
      inherit pname;
    }
  ) package-list;

  test-builder =
    {
      package ? null,
      cargoArtifacts ? null,
    }:
    let
      pname = if package != null then package else "all";
    in
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      profile = profile-tests';
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
          ]
          ++ (if package != null then [ "--package=${pname}" ] else [ ])
          ++ cargo-cmd-prefix-tests
        );
      };
    };

  tests = {
    all = test-builder { };
    pkg = builtins.mapAttrs (
      dir: package:
      test-builder {
        inherit package;
      }
    ) package-list;
  };

  clippy-builder =
    {
      pname ? null,
    }:
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      profile = profile';
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

  docs-builder =
    {
      package ? null,
    }:
    let
      pname = if package != null then package else "all";
    in
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      profile = profile';
      args = {
        inherit pname;
        cargoArtifacts = null;
        RUSTDOCFLAGS = "-D warnings";
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          [
            "cargo"
            "doc"
            "--profile=${cargo-profile}"
            "--no-deps"
          ]
          ++ (if package != null then [ "--package=${pname}" ] else [ ])
          ++ cargo-cmd-prefix
        );
      };
    };

  docs = {
    all = docs-builder { };
    pkg = builtins.mapAttrs (
      dir: package:
      docs-builder {
        inherit package;
      }
    ) package-list;
  };

  dataplane.tar = pkgs.stdenv'.mkDerivation {
    name = "dataplane-cargo-tar-${version}";
    # Source-volatile: see comment on `invoke` for why we opt out of
    # cachix push/substitute on the cargo-derived surface.
    allowSubstitutes = false;
    preferLocalBuild = true;
    dontUnpack = true;
    src = null;
    dontPatchShebangs = true;
    dontFixup = true;
    dontPatchElf = true;
    buildPhase =
      let
        # `libc-pkg` and not `libc` so the outer function-arg `libc` (the
        # string "gnu" / "musl" / "none") stays visible inside this scope
        # for the conditional below.
        libc-pkg = pkgs.pkgsHostHost.libc;
        # libgcc_s.so.1 is consumed by glibc-dynamic Rust binaries for
        # unwinding.  musl Rust targets static-link musl + Rust's
        # compiler-builtins, so libgcc has no consumer; bundling it would
        # waste closure space and pull in glibc-targeted build outputs that
        # are wrong for a musl container.
        #
        # IMPORTANT: must be the path baked into the matching ld-linux's
        # compiled-in search list, which is `pkgs.pkgsHostHost.glibc.libgcc`
        # (the `xgcc-...-libgcc` / cross `libgcc-<triple>-...` derivation).
        # `pkgs.stdenv.cc.cc.lib` ships the same `libgcc_s.so.1` content but
        # at a different store path that ld-linux doesn't search, so the
        # binary can't find it at runtime even though the file exists in
        # the tar.
        libgcc-tar-input = if libc == "gnu" then "${pkgs.pkgsHostHost.glibc.libgcc}" else "";
        # libc.out is needed by anything dynamically linked in the tar,
        # regardless of libc choice.  The Rust binaries on musl are
        # statically linked and don't need it, but busybox (bundled below
        # for `/bin/*` shell utilities) is dynamically linked against
        # whichever libc its pkgset uses.  Omitting libc.out on musl leaves
        # busybox applets referencing a `ld-musl-*.so.1` / `libc.so` that
        # isn't present in the image.
        libc-tar-input = "${libc-pkg.out}";
      in
      ''
        tmp="$(mktemp -d)"
        mkdir -p "$tmp/"{bin,lib,var,etc,run/dataplane,run/frr/hh,run/netns,home,tmp}
        ln -s /run "$tmp/var/run"
        for f in "${pkgs.pkgsHostHost.dockerTools.fakeNss}/etc/"* ; do
          cp --archive "$(readlink -e "$f")" "$tmp/etc/$(basename "$f")"
        done
        cd "$tmp"
        ln -s "${workspace.dataplane}/bin/dataplane" "$tmp/bin/dataplane"
        ln -s "${workspace.cli}/bin/cli" "$tmp/bin/cli"
        ln -s "${workspace.init}/bin/dataplane-init" "$tmp/bin/dataplane-init"
        for i in "${pkgs.pkgsHostHost.busybox}/bin/"*; do
            ln -s "${pkgs.pkgsHostHost.busybox}/bin/busybox" "$tmp/bin/$(basename "$i")"
        done
        ln -s "${workspace.dataplane}/bin/dataplane" "$tmp/dataplane"
        ln -s "${workspace.init}/bin/dataplane-init" "$tmp/dataplane-init"
        ln -s "${workspace.cli}/bin/cli" "$tmp/dataplane-cli"
        # we take some care to make the tar file reproducible here
        tar \
          --create \
          \
          --sort=name \
          \
          --clamp-mtime \
          --mtime=0 \
          \
          --format=posix \
          --numeric-owner \
          --owner=0 \
          --group=0 \
          \
          `# anybody editing the files shipped in the container image is up to no good, block all of that.` \
          `# More, we expressly forbid setuid / setgid anything.` \
          --mode='ugo-sw' \
          \
          `# acls / setcap / selinux isn't going to be reliably copied into the image; skip to make more reproducible` \
          --no-acls \
          --no-xattrs \
          --no-selinux \
          \
          `# we already copied this stuff in to /etc directly, no need to copy it into the store again.` \
          --exclude '${libc-pkg}/etc' \
          \
          `# There are a few components of glibc which have absolutely nothing to do with our goals and present` \
          `# material and trivially avoided hazards just by their presence.  Thus, we filter them out here.` \
          `# None of this applies to musl (if we ever decide to ship with musl).  That said, these filters will` \
          `# just not do anything in that case. ` \
           \
          `# Anybody even trying to access the glibc audit functionality in our container environment is ` \
          `# 100% up to no good.` \
          `# Intercepting and messing with dynamic library loading is _absolutely_ not on our todo list, and this ` \
          `# stuff has a history of causing security issues (arbitrary code execution).  Just disarm this.` \
          `# Go check out this one, it is a classic: ` \
          `# https://www.exploit-db.com/exploits/18105 ` \
          \
          --exclude '${libc-pkg}/lib/audit*' \
          \
          `# The glibc character set conversion code is not only useless to us, is is an increasingly common attack ` \
          `# vector (see CVE-2024-2961 for example).  We are 100% unicode only, so all of these legacy character ` \
          `# conversion algorithms can and should be excluded.  We wouldn't run on (e.g.) old MAC hardware anyway.` \
          `# More, we have zero need or desire (or meaningful ability) to change glibc locales in the container ` \
          `# and it wouldn't be respected by rust's core/std libs anyway. ` \
          `# This is also how fedora packages glibc, and for the same basic reasons.` \
          `# See https://fedoraproject.org/wiki/Changes/Gconv_package_split_in_glibc` \
          --exclude '${libc-pkg}/lib/gconv*' \
          --exclude '${libc-pkg}/share/i18n*' \
          --exclude '${libc-pkg}/share/locale*' \
          \
          `# getconf isn't even shipped in the container so this is useless.  You couldn't change limits in the ` \
          `# container like this anyway.  Even if we needed to and could, we wouldn't use setconf et al.` \
          --exclude '${libc-pkg}/libexec*' \
          \
          --verbose \
          --file "$out" \
          \
          . \
          ${libc-tar-input} \
          ${libgcc-tar-input} \
          ${workspace.dataplane} \
          ${workspace.init} \
          ${workspace.cli} \
          ${pkgs.pkgsHostHost.busybox}
      '';
  };

  containers.dataplane = (pkgs.dockerTools.buildLayeredImage {
    name = "ghcr.io/githedgehog/dataplane";
    inherit tag;
    contents = pkgs.buildEnv {
      name = "dataplane-env";
      pathsToLink = [
        "/bin"
        "/etc"
        "/var"
        "/lib"
      ];
      paths = [
        pkgs.pkgsHostHost.dockerTools.fakeNss
        pkgs.pkgsHostHost.busybox
        pkgs.pkgsHostHost.dockerTools.usrBinEnv
        workspace.cli
        workspace.dataplane
        workspace.init
      ];
    };
    config.Entrypoint = [ "/bin/dataplane" ];
  }).overrideAttrs (_: {
    # Source-volatile: see comment on `invoke`.  Push-filtered by name
    # in the cachix workflow; flag both knobs so a cold runner doesn't
    # query cachix either.  Set on the underlying derivation rather
    # than the buildLayeredImage args because buildLayeredImage's
    # arg-set doesn't accept these.
    allowSubstitutes = false;
    preferLocalBuild = true;
  });

  containers.dataplane-debugger = (pkgs.dockerTools.buildLayeredImage {
    name = "ghcr.io/githedgehog/dataplane/debugger";
    inherit tag;
    contents = pkgs.buildEnv {
      name = "dataplane-debugger-env";
      pathsToLink = [
        "/bin"
        "/etc"
        "/var"
        "/lib"
      ];
      paths = [
        pkgs.pkgsBuildHost.gdb
        pkgs.pkgsBuildHost.rr
        pkgs.pkgsBuildHost.coreutils
        pkgs.pkgsBuildHost.bashInteractive
        pkgs.pkgsBuildHost.iproute2
        pkgs.pkgsBuildHost.ethtool
        pkgs.pkgsHostHost.dockerTools.usrBinEnv

        pkgs.pkgsHostHost.libc.debug
        workspace.cli.debug
        workspace.dataplane.debug
        workspace.init.debug
      ];
    };
  }).overrideAttrs (_: {
    allowSubstitutes = false;
    preferLocalBuild = true;
  });

  debug-tools =
    pkgs:
    [
      ## Packages which might be helpful for debugging but aren't enabled by default.
      ## Uncomment them as needed, but be mindful of container size please.
      # pkgs.dmidecode
      # pkgs.emacs
      # pkgs.gdb # TODO: consider a way to let the user pick gdb' from dev-pkgs (works better in vm)
      # pkgs.neovim
      # pkgs.rr
      # pkgs.valgrind
      # pkgs.wireshark-cli

      pkgs.bashInteractive
      pkgs.coreutils
      pkgs.curl
      pkgs.debianutils
      pkgs.dockerTools.usrBinEnv
      pkgs.ethtool
      pkgs.findutils
      pkgs.gawk
      pkgs.gnugrep
      pkgs.gnused
      pkgs.gnutar
      pkgs.gzip
      pkgs.htop
      pkgs.iproute2
      pkgs.iptables
      pkgs.iputils
      pkgs.jq
      pkgs.less
      pkgs.libc.bin
      pkgs.libc.out
      pkgs.man
      pkgs.nano
      pkgs.procps
      pkgs.tcpdump
      pkgs.util-linux
      pkgs.vim
      pkgs.wget
      pkgs.yq
      pkgs.zstd
    ]
    ++ lib.optionals (libc == "gnu") [
      pkgs.pkgsHostHost.glibc.libgcc
    ];

  containers.debug-tools = pkgs.dockerTools.buildLayeredImage {
    name = "debug-tools";
    tag = "dev"; # don't push or tag this with anything that might end up in the production repo
    contents = pkgs.buildEnv {
      name = "debug-tools-env";
      pathsToLink = [
        "/bin"
        "/etc"
        "/lib"
        "/libexec"
        "/share"
        "/tmp"
        "/usr"
        "/var"
      ];
      paths = debug-tools pkgs;
    };

    fakeRootCommands = ''
      #!${pkgs.bash}/bin/bash
      set -euo pipefail
      mkdir -p /{bin,lib,var,etc,run/dataplane,run/frr/hh,run/netns,home,tmp}
      ln -s /run /var/run
      # symlinks to help imitate the real image
      ln -s /bin/dataplane /dataplane
      ln -s /bin/cli /dataplane-cli
      ln -s /bin/dataplane-init /dataplane-init
    '';

    enableFakechroot = true;

  };

  containers.frr.dataplane = (pkgs.dockerTools.buildLayeredImage {
    name = "ghcr.io/githedgehog/dataplane/frr";
    inherit tag;
    contents = pkgs.buildEnv {
      name = "dataplane-frr-env";
      pathsToLink = [
        "/bin"
        "/etc"
        "/lib"
        "/libexec"
        "/share"
        "/usr"
        "/var"
      ];
      paths = with pkgs; [
        bash
        coreutils
        dockerTools.usrBinEnv
        fancy.dplane-plugin
        fancy.dplane-rpc
        fancy.frr-agent
        fancy.frr-config
        fancy.frr.dataplane
        findutils
        gnugrep
        iproute2
        jq
        prometheus-frr-exporter
        python3Minimal
        tini
      ];
    };

    fakeRootCommands = ''
      #!${pkgs.bash}/bin/bash
      set -euxo pipefail
      mkdir /tmp
      mkdir -p /run/frr/hh
      chown -R frr:frr /run/frr
      mkdir -p /var
      ln -s /run /var/run
      chown -R frr:frr /var/run/frr
      rm /etc/passwd /etc/group
      cp ${pkgs.fancy.frr-config}/etc/passwd /etc/passwd
      cp ${pkgs.fancy.frr-config}/etc/group /etc/group
    '';

    enableFakechroot = true;

    config.Entrypoint = [
      "/bin/tini"
      "--"
    ];
    config.Cmd = [ "/libexec/frr/docker-start" ];
  }).overrideAttrs (_: {
    # Bundles frr-agent (Rust); source-volatile.
    allowSubstitutes = false;
    preferLocalBuild = true;
  });

  containers.frr.host = pkgs.dockerTools.buildLayeredImage {
    name = "ghcr.io/githedgehog/dataplane/frr-host";
    inherit tag;
    contents = pkgs.buildEnv {
      name = "dataplane-frr-host-env";
      pathsToLink = [
        "/bin"
        "/etc"
        "/lib"
        "/libexec"
        "/share"
        "/usr"
        "/var"
      ];
      paths = with pkgs; [
        bash
        coreutils
        dockerTools.usrBinEnv
        # TODO: frr-config's docker-start launches /bin/frr-agent which is not
        # present in the host container.  A host-specific entrypoint script may
        # be needed once this container is actively deployed.
        fancy.frr-config
        fancy.frr.host
        findutils
        gnugrep
        iproute2
        jq
        prometheus-frr-exporter
        python3Minimal
        tini
      ];
    };
    fakeRootCommands = ''
      #!${pkgs.bash}/bin/bash
      set -euxo pipefail
      mkdir /tmp
      mkdir -p /run/frr/hh
      chown -R frr:frr /run/frr
      mkdir -p /var
      ln -s /run /var/run
      chown -R frr:frr /var/run/frr
      rm /etc/passwd /etc/group
      cp ${pkgs.fancy.frr-config}/etc/passwd /etc/passwd
      cp ${pkgs.fancy.frr-config}/etc/group /etc/group
    '';

    enableFakechroot = true;

    config.Entrypoint = [
      "/bin/tini"
      "--"
    ];
    config.Cmd = [ "/libexec/frr/docker-start" ];
  };

in
{
  inherit
    check
    clippy
    containers
    dataplane
    devenv
    devroot
    docs
    package-list
    pkgs
    sources
    sysroot
    tests
    workspace
    extra-platforms
    cross-matrix
    ;
  profile = profile';
  platform = platform';
}
