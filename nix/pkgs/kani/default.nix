# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
#
# Kani, the Rust model checker, built from source.
#
# Kani is a rustc driver, so it is tied to the exact nightly named in its own rust-toolchain.toml,
# not to the toolchain the workspace builds with.  We read that file rather than restating the
# date here, so moving the `kani` pin moves the toolchain with it.
#
# libexec/kani has the layout of a Kani release bundle (what `cargo kani setup` would unpack into
# ~/.kani), so kani-driver runs in "release" mode and never tries to download anything.  It is kept
# out of the top level so that a symlinkJoin (the dev shell) does not merge kani's std rlibs into
# lib/rustlib next to the workspace toolchain's.  Only bin/kani and bin/cargo-kani are exposed.
#
#   bin/            kani-driver and kani-compiler
#   lib/            the kani + std rlibs compiled by kani-compiler (the verification sysroot)
#   playback/lib/   the same, built for concrete playback
#   no_core/lib/    kani_core for no_core crates
#   library/        kani's library sources (kani_lib.c is read at verification time)
#   toolchain       the nightly kani was built against; kani-driver runs its cargo
{
  lib,
  stdenv,
  src,
  charon-src,
  crane,
  rust-bin,
  makeWrapper,
  removeReferencesTo,
  cbmc,
  kissat,
}:
let
  toolchain-file = (builtins.fromTOML (builtins.readFile "${src}/rust-toolchain.toml")).toolchain;
  toolchain = rust-bin.fromRustupToolchain {
    profile = "minimal";
    inherit (toolchain-file) channel;
    components = toolchain-file.components ++ [
      "cargo"
      "rustc"
      "rust-std"
    ];
  };
  # What kani-driver runs at verification time (its `toolchain` symlink): cargo, plus the rustc
  # whose librustc_driver kani-compiler loads.  Same channel, so the same librustc_driver, but
  # without the ~1.8 GiB of rustc-dev, llvm-tools and rustfmt that only building kani needs.
  runtime-toolchain = rust-bin.fromRustupToolchain {
    profile = "minimal";
    inherit (toolchain-file) channel;
    components = [
      "cargo"
      "rustc"
      "rust-std"
    ];
  };
  craneLib = crane.overrideToolchain toolchain;
  # Kani's own dependencies, plus std's: building the verification sysroot uses -Zbuild-std, which
  # resolves std's dependencies from rust-src's lockfile.
  cargoVendorDir = craneLib.vendorMultipleCargoDeps {
    cargoLockList = [
      "${src}/Cargo.lock"
      "${toolchain}/lib/rustlib/src/rust/library/Cargo.lock"
    ];
    outputHashes = {
      # charon's tracing fork (charon is a path dependency of kani-compiler)
      "git+https://github.com/Nadrieril/tracing-tree#841286bfffd3c2200810244506cd127013dbeff9" =
        "sha256-YjkXsOn/aLEYxvys9TFZjTyUMPxk3WsI6bbJsbwSiKY=";
    };
  };
  version = (builtins.fromTOML (builtins.readFile "${src}/Cargo.toml")).package.version;
in
stdenv.mkDerivation {
  pname = "kani";
  inherit version src;

  nativeBuildInputs = [
    toolchain
    makeWrapper
    removeReferencesTo
  ];

  # charon is a git submodule; kani-compiler only needs it behind the `llbc` feature, but cargo
  # loads every path dependency's manifest to resolve the lockfile.
  postUnpack = ''
    rmdir "$sourceRoot/charon"
    cp -r ${charon-src} "$sourceRoot/charon"
    chmod -R u+w "$sourceRoot/charon"
  '';

  env = {
    # Recorded into the binaries with env!(); kani-driver uses it to name the toolchain.
    RUSTUP_TOOLCHAIN = toolchain-file.channel;
    CARGO_NET_OFFLINE = "true";
    # kani-compiler links librustc_driver dynamically and runs during the build (it compiles the
    # sysroot libraries).
    LD_LIBRARY_PATH = "${toolchain}/lib";
  };

  configurePhase = ''
    runHook preConfigure
    export CARGO_HOME="$TMPDIR/cargo-home"
    mkdir -p "$CARGO_HOME"
    cp ${cargoVendorDir}/config.toml "$CARGO_HOME/config.toml"
    # kani-compiler's build script rpaths $RUSTUP_HOME/toolchains/$RUSTUP_TOOLCHAIN/lib, and also
    # $ORIGIN/../toolchain/lib, which is what the installed binary uses.  Give it a rustup-shaped
    # home pointing at our toolchain; installPhase replaces the rpath.
    export RUSTUP_HOME="$TMPDIR/rustup"
    mkdir -p "$RUSTUP_HOME/toolchains"
    ln -s ${toolchain} "$RUSTUP_HOME/toolchains/$RUSTUP_TOOLCHAIN"
    runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild
    cargo build-dev -- --release
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    bundle=$out/libexec/kani
    mkdir -p $bundle/bin $bundle/library $bundle/playback $bundle/no_core $out/bin
    cp target/kani/bin/kani-driver target/kani/bin/kani-compiler $bundle/bin/
    # Drop the build-time rustup rpath in favour of the runtime toolchain's librustc_driver.
    patchelf --set-rpath ${runtime-toolchain}/lib $bundle/bin/kani-compiler
    cp -r target/kani/lib $bundle/lib
    cp -r target/kani/playback/lib $bundle/playback/lib
    cp -r target/kani/no_core/lib $bundle/no_core/lib
    cp -r library/kani library/kani_macros library/std $bundle/library/
    echo -n ${toolchain-file.channel} > $bundle/rust-toolchain-version
    ln -s ${runtime-toolchain} $bundle/toolchain

    # kani-driver picks its personality from argv[0], and finds cbmc, goto-cc, goto-instrument
    # and kissat on PATH.
    for entry in kani cargo-kani; do
      makeWrapper $bundle/bin/kani-driver $out/bin/$entry \
        --argv0 $entry \
        --prefix PATH : ${
          lib.makeBinPath [
            cbmc
            kissat
          ]
        }
    done
    runHook postInstall
  '';

  # The binaries and rlibs name source files (panic locations, debug info, rlib metadata) in the
  # vendored crates and in the build toolchain.  Those are strings, not dependencies: left alone,
  # they would pull every vendored crate and rustc-dev into the runtime closure.
  postFixup = ''
    refs=$(grep -raoh '/nix/store/[a-z0-9]\{32\}-\(cargo-package\|cargo-src\|cargo-git\|vendor\|linkLockedDeps\)[^/"]*' $out | sort -u)
    for ref in $refs ${toolchain}; do
      find $out -type f -exec remove-references-to -t "$ref" {} +
    done
  '';

  passthru = { inherit toolchain runtime-toolchain; };

  meta = {
    description = "Kani Rust Verifier (bit-precise model checker for Rust)";
    homepage = "https://github.com/model-checking/kani";
    license = with lib.licenses; [
      asl20
      mit
    ];
    mainProgram = "cargo-kani";
  };
}
