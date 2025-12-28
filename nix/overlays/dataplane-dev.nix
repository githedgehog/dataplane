# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
}:
final: prev:
let
  rust-toolchain = final.rust-bin.fromRustupToolchainFile  ../../rust-toolchain.toml;
  rustPlatform = final.makeRustPlatform {
    stdenv = final.llvmPackages.stdenv;
    cargo = rust-toolchain;
    rustc = rust-toolchain;
  };
in
{
  inherit rust-toolchain;
  rustPlatform' = rustPlatform;

  kopium = import ../pkgs/kopium {
    src = sources.kopium;
    inherit rustPlatform;
  };
  cargo-bolero = prev.cargo-bolero.override { inherit rustPlatform; };
  cargo-deny = prev.cargo-deny.override { inherit rustPlatform; };
  cargo-llvm-cov = prev.cargo-llvm-cov.override { inherit rustPlatform; };
  cargo-nextest = prev.cargo-nextest.override { inherit rustPlatform; };
  just = prev.just.override { inherit rustPlatform; };
  npins = prev.npins.override { inherit rustPlatform; };
  gateway-crd =
    let
      p = "config/crd/bases/gwint.githedgehog.com_gatewayagents.yaml";
    in
    final.writeTextFile {
      name = "gateway-crd";
      text = builtins.readFile "${sources.gateway}/${p}";
      executable = false;
      destination = "/src/gateway/${p}";
    };
}
