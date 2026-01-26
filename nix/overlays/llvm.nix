# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  platform,
  profile,
  ...
}:
final: prev:
let
  helpers.addToEnv =
    new: orig:
    orig
    // (
      with builtins; (mapAttrs (var: val: (toString (orig.${var} or "")) + " " + (toString val)) new)
    );
  adapt = final.stdenvAdapters;
  bintools = final.pkgsBuildHost.llvmPackages'.bintools;
  lld = final.pkgsBuildHost.llvmPackages'.lld;
  added-to-env = helpers.addToEnv platform.override.stdenv.env profile;
  stdenv' = adapt.addAttrsToDerivation (orig: {
    doCheck = false;
    # separateDebugInfo = true;
    env = helpers.addToEnv added-to-env (orig.env or { });
    nativeBuildInputs = (orig.nativeBuildInputs or [ ]) ++ [
      bintools
      lld
    ];
  }) final.llvmPackages'.stdenv;
  # note: rust-bin comes from oxa's overlay, not nixpkgs.  This overlay only works if you have a rust overlay as well.
  rust-toolchain = final.rust-bin.fromRustupToolchain {
    channel = sources.rust.version;
    components = [
      "rustc"
      "cargo"
      "rust-std"
      "rust-docs"
      "rustfmt"
      "clippy"
      "rust-analyzer"
      "rust-src"
    ];
    targets = [
      platform.info.target
    ];
  };
  rustPlatform' = final.makeRustPlatform {
    stdenv = stdenv';
    cargo = rust-toolchain;
    rustc = rust-toolchain;
  };
  rustPlatform'-dev = final.makeRustPlatform {
    stdenv = final.llvmPackages'.stdenv;
    cargo = rust-toolchain;
    rustc = rust-toolchain;
  };
  # It is essential that we always use the same version of llvm that our rustc is backed by.
  # To minimize maintenance burden, we explicitly compute the version of LLVM we need by asking rustc
  # which version it is using.
  # This is significantly less error prone than hunting around for all versions of pkgs.llvmPackages_${version}
  # every time rust updates.
  # Unfortunately, this is also IFD, so it slows down the nix build a bit :shrug:
  llvm-version = builtins.readFile (
    final.runCommand "llvm-version-for-our-rustc"
      {
        RUSTC = "${rust-toolchain.out}/bin/rustc";
        GREP = "${final.pkgsBuildHost.gnugrep}/bin/grep";
        SED = "${final.pkgsBuildHost.gnused}/bin/sed";
      }
      ''
        $RUSTC --version --verbose | \
          $GREP '^LLVM version:' | \
          $SED -z 's|LLVM version: \([0-9]\+\)\.[0-9]\+\.[0-9]\+\n|\1|' > $out
      ''
  );
in
{
  inherit
    rust-toolchain
    rustPlatform'
    rustPlatform'-dev
    stdenv'
    ;
  llvmPackages' = prev."llvmPackages_${llvm-version}";
}
