# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  ...
}:
final: prev:
let
  # Build a rust toolchain with the wasm32-wasip1 target.
  # Note: rust-bin comes from oxalica's rust-overlay, so this overlay requires the rust overlay.
  rust-toolchain = final.rust-bin.fromRustupToolchain {
    channel = sources.rust.version;
    components = [
      "rustc"
      "cargo"
      "rust-std"
      "rustfmt"
      "clippy"
      "rust-src"
    ];
    targets = [
      "wasm32-wasip1"
    ];
  };
  rustPlatform = final.makeRustPlatform {
    cargo = rust-toolchain;
    rustc = rust-toolchain;
  };
in
{
  wasm32 = {
    inherit
      rust-toolchain
      rustPlatform
      ;
  };
}
