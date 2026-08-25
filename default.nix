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
  host-arch = (import sources.nixpkgs { }).stdenv.hostPlatform.parsed.cpu.name;
  platform' = import ./nix/platforms.nix {
    inherit
      lib
      platform
      libc
      kernel
      ;
  };
  as-set = str: lib.sort (a: b: a < b) (lib.unique (split-str ",+" str));
  sanitizers = as-set sanitize;
  instrumentations = as-set instrumentation;
  cargo-features = split-str ",+" features;
  profile' = import ./nix/profiles.nix {
    inherit
      sanitizers
      instrumentations
      profile
      cargo-features
      host-arch
      ;
    inherit (platform') arch;
  };
  # Test archives run on the host (e.g. `cargo nextest run --archive-file`)
  # rather than in the nix build sandbox, so panics in fixtures must
  # unwind for cleanup (netns / caps) to run.  See `test-utils/src/lib.rs`.
  profile-tests' = import ./nix/profiles.nix {
    inherit
      sanitizers
      instrumentations
      profile
      cargo-features
      host-arch
      ;
    inherit (platform') arch;
    for-tests = true;
  };
  cargo-profile =
    {
      "debug" = "dev";
      "release" = "release";
      "checked" = "checked";
    }
    .${profile};
  overlays = import ./nix/overlays {
    inherit
      libc
      nightly
      sanitizers
      instrumentations
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
  sysroot-stamp = ''
    printf '%s' '${builtins.concatStringsSep "," sanitizers}' > "$out/.sanitize"
    printf '%s' '${builtins.concatStringsSep "," instrumentations}' > "$out/.instrumentation"
  '';
  sysroot =
    if platform != "wasm32-wasip1" then
      pkgs.symlinkJoin {
        name = "sysroot";
        postBuild = sysroot-stamp;
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
        postBuild = sysroot-stamp;
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
      cargo-expand
      cargo-llvm-cov
      cargo-mutants
      cargo-nextest
      cargo-show-asm
      commitlint-rs
      deno
      direnv
      duvet
      gateway-crd
      gettext
      iai-callgrind-runner
      jq
      just
      kopium
      llvmPackages'.clang # you need the host compiler in order to link proc macros
      llvmPackages'.llvm # needed for coverage
      markdownlint-cli2
      nixfmt
      npins
      opengrep
      openssl
      oras
      pinact
      pkg-config
      python3Packages.pyflakes
      qemu-user
      rust-toolchain
      shellcheck
      skopeo
      static-web-server
      valgrind
      wasmtime
      wget
      yq
      zizmor
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
  # Nix escaping made the old regexes match unrelated .sh and .patch files.
  cHeaderFilter = p: _type: lib.hasSuffix ".h" p;
  # Prose lives at the repository root, under `development/`, and under
  # `.github/`; Markdown anywhere else is either compiled into a crate's docs by
  # `include_str!` or sits beside code that is. Excluding by location rather
  # than listing the `include_str!` targets keeps a new one from having to be
  # registered here -- the worst case becomes an unnecessary rebuild instead of
  # a build that cannot find its README.
  markdownFilter =
    rel: _type:
    lib.hasSuffix ".md" rel
    && lib.hasInfix "/" rel
    && !(lib.hasPrefix "development/" rel)
    && !(lib.hasPrefix ".github/" rel);
  # `.cargo/config.toml` names this script, so include it deliberately.
  shellFilter = p: _type: lib.hasSuffix ".sh" p;
  # `cleanSource` does not read gitignore, so `results` needs excluding by hand
  # or every developer who has built carries a private `src` hash.
  outputsFilter =
    p: _type:
    (p != "target") && (p != "sysroot") && (p != "devroot") && (p != "results") && (p != ".git");
  # `builtins.path` and friends hand the filter an absolute path; the markdown
  # allowlist is written relative to the repository, so strip the root off.
  src-root = toString ./.;
  src = pkgs.lib.cleanSourceWith {
    filter =
      full-path: t:
      let
        p = baseNameOf full-path;
        rel = lib.removePrefix (src-root + "/") (toString full-path);
      in
      (markdownFilter rel t)
      || (cHeaderFilter p t)
      || (shellFilter p t)
      || ((outputsFilter p t) && (craneLib.filterCargoSources full-path t));
    src = lib.cleanSource ./.;
    name = "source";
  };
  # Keep dependency fingerprints independent of the source store path.
  # Consumers resolve this relative prefix from the workspace root.
  src-prefix = ".";

  # Hash every git dependency so crane uses cacheable fixed-output derivations
  # instead of cloning whole repositories during evaluation. Keys must match
  # Cargo.lock sources after percent-decoding branch names: a wrong hash fails
  # when `vendor-cargo-deps` is realised, but a key that stops matching -- which
  # a branch rename does -- only warns and silently falls back to the
  # evaluation-time clone this is meant to avoid.
  cargoVendorDir = craneLib.vendorMultipleCargoDeps {
    cargoLockList = [
      ./Cargo.lock
      "${pkgs.rust-toolchain.passthru.availableComponents.rust-src}/lib/rustlib/src/rust/library/Cargo.lock"
    ];
    outputHashes = {
      "git+https://github.com/githedgehog/bolero.git?rev=2fa595633a72e9b30721f9d37f0014a6ae8f77d4#2fa595633a72e9b30721f9d37f0014a6ae8f77d4" =
        "sha256-ipue/XsDxOeO4lThRcIdpQsztC5AbAkgwUHDYWTH9qY=";
      "git+https://github.com/githedgehog/dplane-rpc.git?branch=pr/daniel-noland/bumps#6c84b7aff35abb4e94fbb0d09870a0b4a2322913" =
        "sha256-YOCcWOynWN49KKY17KfP31QBK1ZM6x6Xl4/tdfNwgIs=";
      "git+https://github.com/githedgehog/fixin?branch=main#5e0de31606466b17372f8a2cff090cc0461d572c" =
        "sha256-GfBnaL6ke3ekm+HbV34yXdF4ArYHismxbPHF5/M94yk=";
      "git+https://github.com/githedgehog/left-right.git?branch=fredi/fix-writehandle-drop#765813aa25c8328746e93a7a5ccc75deb57b1d80" =
        "sha256-GVP11hLRmHip5+MH9U1bD4bANxDpdnkN9cvMo6RDFfY=";
      "git+https://github.com/githedgehog/netlink-packet-route.git?branch=pr/daniel-noland/swing6#9a257c60e25bc5db50a1cd14aa493d6ec294c23d" =
        "sha256-w5dK1IfqR1kJDa4ugbvEC4VIASwGlKU6oxEd9USUwMw=";
      "git+https://github.com/githedgehog/rtnetlink.git?branch=hh/tc-actions4#c6b8d9865858c458e7f27fa67469f2171e1644a4" =
        "sha256-u14ugCKWU4nwXkQdlleThJLYU4Ft/LJNTKywMUlwxPM=";
      "git+https://github.com/githedgehog/testn.git?tag=v0.0.10#e49aba8400beb2cb117a3f542b114080cf572283" =
        "sha256-XwEKLdc2Y7fteSKKOERgjKTdxELy7K/wOVuB/SSj3ng=";
    };
  };
  # Rename per-revision images so the CI push filter keeps them out of Cachix;
  # each is built once and shipped through GHCR. Not applied to workspace
  # builds, which are worth substituting.
  source-volatile = orig: {
    name = "dataplane-volatile-${orig.name or "${orig.pname}-${orig.version}"}";
    allowSubstitutes = false;
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
      (pkgs.runCommandLocal "package-list"
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
      ).overrideAttrs
        source-volatile
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
      # Dependency builds retain reusable Cargo artifacts rather than binaries.
      for-deps ? false,
      # Skip the binary strip/split step for derivations that produce none.
      no-bins ? false,
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
          # Dependencies do not read VERSION, so keep their derivation stable
          # while workspace consumers receive the per-commit tag.
          VERSION = if for-deps then "dependencies" else tag;
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
                  # Keep debug paths stable across revisions. Source readers
                  # must resolve this relative prefix from the workspace root.
                  "--remap-path-prefix==${src-prefix}"
                ]
              )
            else
              "";
        };
      }
      // args
    )).overrideAttrs
      (
        orig:
        if for-deps || no-bins then
          {
            # Only dependency builds should retain crane's target archive.
            doInstallCargoArtifacts = for-deps;
            postBuild = (orig.postBuild or "") + ''
              unset RUSTFLAGS;
            '';
          }
        else
          {
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
          }
      );

  # Share one manifest-based dependency build per flag set across workspace
  # packages and revisions. Production and tests remain separate because their
  # unwind and development-dependency fingerprints differ.
  mk-cargo-artifacts =
    {
      for-tests,
      cmd-prefix,
      deps-profile,
    }:
    pkgs.callPackage invoke {
      builder = craneLib.buildDepsOnly;
      profile = deps-profile;
      for-deps = true;
      args = {
        pname = if for-tests then "dataplane-tests" else "dataplane";
        cargoArtifacts = null;
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          # Include dev-dependencies required by nextest archives.
          (
            if for-tests then
              [
                "cargo"
                "test"
                "--no-run"
                "--profile=${cargo-profile}"
              ]
            else
              [
                "cargo"
                "build"
                "--profile=${cargo-profile}"
              ]
          )
          # Use the consumer package set so excluded members cannot pull native
          # dependencies that fail to compile for wasm32-wasip1.
          ++ (map (pname: "--package=${pname}") (builtins.attrValues package-list))
          ++ cmd-prefix
        );
      };
    };

  cargo-artifacts = mk-cargo-artifacts {
    for-tests = false;
    cmd-prefix = cargo-cmd-prefix;
    deps-profile = profile';
  };

  cargo-artifacts-tests = mk-cargo-artifacts {
    for-tests = true;
    cmd-prefix = cargo-cmd-prefix-tests;
    deps-profile = profile-tests';
  };

  workspace-builder =
    {
      pname ? null,
      cargoArtifacts ? cargo-artifacts,
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
      cargoArtifacts ? cargo-artifacts,
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
      cargoArtifacts ? cargo-artifacts-tests,
    }:
    let
      pname = if package != null then package else "all";
    in
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      profile = profile-tests';
      args = {
        inherit pname cargoArtifacts;
        buildPhaseCargoCommand =
          (builtins.concatStringsSep " " (
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
          ))
          # Record the remapped source root without changing normal archives.
          + (
            if builtins.elem "coverage" instrumentations then
              "; echo -n '${src-prefix}' > $out/source-prefix"
            else
              ""
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

  # Build criterion bench binaries without running them.
  bench-builder =
    {
      package ? null,
      cargoArtifacts ? cargo-artifacts-tests,
    }:
    let
      pname = if package != null then package else "all";
    in
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      profile = profile-tests';
      args = {
        inherit pname cargoArtifacts;
        buildPhaseCargoCommand =
          (builtins.concatStringsSep " " (
            [
              "mkdir -p $out/bin;"
              "cargoBenchLog=$(mktemp cargoBenchLogXXXX.json);"
              "cargo"
              "bench"
              "--no-run"
              "--profile=${cargo-profile}"
            ]
            ++ (if package != null then [ "--package=${pname}" ] else [ ])
            ++ cargo-cmd-prefix-tests
            ++ [ "--message-format=json-render-diagnostics > $cargoBenchLog;" ]
          ))
          + ''
            for exe in $(grep -E '"kind":\["bench"\]' "$cargoBenchLog" | grep -oE '"executable":"[^"]+"' | sed -E 's/"executable":"//; s/"$//'); do
              cp "$exe" "$out/bin/$(basename "$exe" | sed -E 's/-[0-9a-f]{16}$//')"
            done
          '';
      };
    };

  benches = bench-builder { };

  # Preserve all-target linting, using the test profile and dependency artifacts
  # required by test and benchmark targets.
  clippy-builder =
    {
      package ? null,
    }:
    let
      pname = if package != null then package else "all";
    in
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      profile = profile-tests';
      args = {
        inherit pname;
        cargoArtifacts = cargo-artifacts-tests;
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          [
            "cargo"
            "clippy"
            "--all-targets"
            "--profile=${cargo-profile}"
          ]
          # The platform-aware list excludes members that cannot build for WASI.
          ++ (
            if package != null then
              [ "--package=${pname}" ]
            else
              map (p: "--package=${p}") (builtins.attrValues package-list)
          )
          ++ cargo-cmd-prefix-tests
          ++ [
            "--"
            "-D warnings"
          ]
        );
      };
    };

  # Workspace source invalidates every package together, so share one artifact
  # unpack instead of paying the fixed cost per package.
  clippy = {
    all = clippy-builder { };
    pkg = builtins.mapAttrs (dir: package: clippy-builder { inherit package; }) package-list;
  };

  # Cargo cannot build doctests without running them, so execute them in the
  # sandbox instead of trying to archive them for the host.
  doctest-builder =
    {
      package ? null,
    }:
    let
      pname = if package != null then package else "all";
    in
    pkgs.callPackage invoke {
      builder = craneLib.mkCargoDerivation;
      profile = profile-tests';
      no-bins = true;
      args = {
        inherit pname;
        cargoArtifacts = cargo-artifacts-tests;
        # `cargo test --doc` runs rustdoc, which does not inherit rustc's
        # registered cfg declarations either.
        RUSTDOCFLAGS = "-D warnings --check-cfg=cfg(emulated) --check-cfg=cfg(instrumented)";
        # The sandbox cannot resolve the runner's `/usr/bin/env bash` shebang.
        preBuild = "patchShebangs scripts/test-runner.sh";
        buildPhaseCargoCommand = builtins.concatStringsSep " " (
          [
            "cargo"
            "test"
            "--doc"
            "--profile=${cargo-profile}"
          ]
          ++ (if package != null then [ "--package=${pname}" ] else [ ])
          ++ cargo-cmd-prefix-tests
        );
      };
    };

  doctests = {
    all = doctest-builder { };
    pkg = builtins.mapAttrs (dir: package: doctest-builder { inherit package; }) package-list;
  };

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
        cargoArtifacts = cargo-artifacts;
        # Rustdoc does not inherit rustc's registered cfg declarations.
        RUSTDOCFLAGS = "-D warnings --check-cfg=cfg(emulated) --check-cfg=cfg(instrumented)";
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

  dataplane.tar =
    (pkgs.stdenv'.mkDerivation {
      pname = "dataplane.tar";
      inherit version;
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
    }).overrideAttrs
      source-volatile;

  containers.dataplane =
    (pkgs.dockerTools.buildLayeredImage {
      name = "ghcr.io/githedgehog/dataplane";
      inherit tag;
      contents =
        (pkgs.buildEnv {
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
        }).overrideAttrs
          source-volatile;
      config.Entrypoint = [ "/bin/dataplane" ];
    }).overrideAttrs
      source-volatile;

  containers.dataplane-debugger =
    (pkgs.dockerTools.buildLayeredImage {
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
    }).overrideAttrs
      source-volatile;

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

  containers.debug-tools =
    (pkgs.dockerTools.buildLayeredImage {
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

    }).overrideAttrs
      source-volatile;

  containers.frr.dataplane =
    (pkgs.dockerTools.buildLayeredImage {
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
    }).overrideAttrs
      source-volatile;

  containers.frr.host =
    (pkgs.dockerTools.buildLayeredImage {
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
    }).overrideAttrs
      source-volatile;

in
{
  inherit
    benches
    check
    clippy
    containers
    dataplane
    devenv
    devroot
    doctests
    docs
    package-list
    pkgs
    sources
    src
    sysroot
    tests
    workspace
    ;
  profile = profile';
  platform = platform';
}
