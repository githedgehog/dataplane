# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  platform ? "x86-64-v3",
  libc ? "gnu",
  profile ? "debug",
  instrumentation ? "none",
  sanitize ? "",
  tag ? "dev",
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
      "fuzz" = "fuzz";
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
  frr-pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.rust
        overlays.llvm
        overlays.dataplane
        overlays.frr
      ];
    }).pkgsCross.${platform'.info.nixarch};
  sysroot = pkgs.pkgsHostHost.symlinkJoin {
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
      llvmPackages'.llvm # needed for coverage
      npins
      pkg-config
      rust-toolchain
      skopeo
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
      GW_CRD_PATH = "${dev-pkgs.gateway-crd}/src/gateway/config/crd/bases";
    };
  };
  justfileFilter = p: _type: builtins.match ".*\.justfile$" p != null;
  markdownFilter = p: _type: builtins.match ".*\.md$" p != null;
  jsonFilter = p: _type: builtins.match ".*\.json$" p != null;
  cHeaderFilter = p: _type: builtins.match ".*\.h$" p != null;
  outputsFilter = p: _type: (p != "target") && (p != "sysroot") && (p != "devroot") && (p != ".git");
  src = pkgs.lib.cleanSourceWith {
    filter =
      p: t:
      (justfileFilter p t)
      || (markdownFilter p t)
      || (jsonFilter p t)
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
  cxx = if is-cross-compile then "${target}-clang++" else "clang++";
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
    "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
    "--target=${target}"
  ];
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
        removeReferencesToRustToolchain = true;
        removeReferencesToVendorDir = true;

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
          VERSION = tag;
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
  workspace-builder =
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
    workspace-builder {
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
          ++ cargo-cmd-prefix
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
    pname = "dataplane.tar";
    inherit version;
    dontUnpack = true;
    src = null;
    dontPatchShebangs = true;
    dontFixup = true;
    dontPatchElf = true;
    buildPhase =
      let
        libc = pkgs.pkgsHostHost.libc;
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
          --exclude '${libc}/etc' \
          \
          `# There are a few components of glibc which have absolutely nothing to do with our goals and present` \
          `# material and trivially avoided hazzards just by their presence.  Thus, we filter them out here.` \
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
          --exclude '${libc}/lib/audit*' \
          \
          `# The glibc character set conversion code is not only useless to us, is is an increasingly common attack ` \
          `# vector (see CVE-2024-2961 for example).  We are 100% unicode only, so all of these legacy character ` \
          `# conversion algorithms can and should be excluded.  We wouldn't run on (e.g.) old MAC hardware anyway.` \
          `# More, we have zero need or desire (or meaningful ability) to change glibc locales in the container ` \
          `# and it wouldn't be respected by rust's core/std libs anyway. ` \
          `# This is also how fedora packages glibc, and for the same basic reasons.` \
          `# See https://fedoraproject.org/wiki/Changes/Gconv_package_split_in_glibc` \
          --exclude '${libc}/lib/gconv*' \
          --exclude '${libc}/share/i18n*' \
          --exclude '${libc}/share/locale*' \
          \
          `# getconf isn't even shipped in the container so this is useless.  You couldn't change limits in the ` \
          `# container like this anyway.  Even if we needed to and could, we wouldn't use setconf et al.` \
          --exclude '${libc}/libexec*' \
          \
          --verbose \
          --file "$out" \
          \
          . \
          ${libc.out} \
          ${pkgs.pkgsHostHost.glibc.libgcc} \
          ${workspace.dataplane} \
          ${workspace.init} \
          ${workspace.cli} \
          ${pkgs.pkgsHostHost.busybox}
      '';
  };

  containers.dataplane = pkgs.dockerTools.buildLayeredImage {
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
  };

  containers.dataplane-debugger = pkgs.dockerTools.buildLayeredImage {
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
  };

  containers.frr.dataplane = pkgs.dockerTools.buildLayeredImage {
    name = "ghcr.io/githedgehog/dpdk-sys/frr";
    inherit tag;
    contents = pkgs.buildEnv {
      name = "dataplane-frr-env";
      pathsToLink = [ "/" ];
      paths = with frr-pkgs; [
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
      #!${frr-pkgs.bash}/bin/bash
      set -euxo pipefail
      mkdir /tmp
      mkdir -p /run/frr/hh
      chown -R frr:frr /run/frr
      mkdir -p /var
      ln -s /run /var/run
      chown -R frr:frr /var/run/frr
    '';

    enableFakechroot = true;

    config.Entrypoint = [
      "/bin/tini"
      "--"
    ];
    config.Cmd = [ "/libexec/frr/docker-start" ];
  };

  containers.frr.host = pkgs.dockerTools.buildLayeredImage {
    name = "ghcr.io/githedgehog/dpdk-sys/frr-host";
    inherit tag;
    contents = pkgs.buildEnv {
      name = "dataplane-frr-host-env";
      pathsToLink = [
        "/"
      ];
      paths = with frr-pkgs; [
        bash
        coreutils
        dockerTools.fakeNss
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
      #!${frr-pkgs.bash}/bin/bash
      set -euxo pipefail
      mkdir /tmp
      mkdir -p /run/frr/hh
      chown -R frr:frr /run/frr
      mkdir -p /var
      ln -s /run /var/run
      chown -R frr:frr /var/run/frr
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
    clippy
    containers
    dev-pkgs
    devenv
    devroot
    docs
    frr-pkgs
    dataplane
    package-list
    pkgs
    sources
    sysroot
    tests
    workspace
    ;
  profile = profile';
  platform = platform';
}
