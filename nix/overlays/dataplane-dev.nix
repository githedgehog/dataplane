# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  ...
}:
final: prev:
let
  override-packages = {
    stdenv = final.llvmPackages.stdenv;
    rustPlatform = final.rustPlatform'-dev;
  };
in
{
  kopium = import ../pkgs/kopium (
    override-packages
    // {
      src = sources.kopium;
    }
  );
  cargo-bolero = prev.cargo-bolero.override { inherit (override-packages) rustPlatform; };
  cargo-deny = prev.cargo-deny.override { inherit (override-packages) rustPlatform; };
  cargo-llvm-cov = prev.cargo-llvm-cov.override override-packages;
  cargo-nextest = prev.cargo-nextest.override override-packages;
  just = prev.just.override override-packages;
  npins = prev.npins.override { inherit (override-packages) rustPlatform; };
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
