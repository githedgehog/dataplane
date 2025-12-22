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
final: prev: {
  # llvmPackages = final.llvmPackages_21;

  # # TODO: doc this
  # rustPlatform = final.makeRustPlatform {
  #   stdenv = final.llvmPackages.stdenv;
  #   cargo = rust-toolchain;
  #   rustc = rust-toolchain;
  # };

  kopium = import ../pkgs/kopium {
    src = sources.kopium;
    inherit (final) rustPlatform;
  };
}
