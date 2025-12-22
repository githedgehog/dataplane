# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
}:
let
  fenix = import sources.fenix { };
  rust-toolchain = fenix.fromToolchainFile {
    file = ../../rust-toolchain.toml;
    sha256 = (builtins.fromJSON (builtins.readFile ../.rust-toolchain.manifest-lock.json)).hash.sha256;
  };
in
final: prev:
let
  rustPlatform = final.makeRustPlatform {
    stdenv = final.llvmPackages.stdenv;
    cargo = rust-toolchain;
    rustc = rust-toolchain;
  };
in
{
  inherit rust-toolchain rustPlatform;
  llvmPackages = final.llvmPackages_21;
  kopium = import ../pkgs/kopium {
    src = sources.kopium;
    inherit rustPlatform;
  };
  cargo-bolero = prev.cargo-bolero.override { inherit rustPlatform; };
  cargo-deny = prev.cargo-deny.override { inherit rustPlatform; };
  cargo-pciutils = prev.cargo-deny.override { inherit rustPlatform; };
  cargo-llvm-cov = prev.cargo-deny.override { inherit rustPlatform; };
  cargo-nextest = prev.cargo-deny.override { inherit rustPlatform; };
  just = prev.cargo-deny.override { inherit rustPlatform; };
  npins = prev.cargo-deny.override { inherit rustPlatform; };
}
