# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
inputs@{
  sources,
  ...
}:
{
  rust = import sources.rust-overlay;
  llvm = import ./llvm.nix inputs; # requires rust
  wasm32 = import ./wasm32.nix inputs; # requires rust
  dataplane-dev = import ./dataplane-dev.nix inputs; # requires llvm
  dataplane = import ./dataplane.nix inputs; # requires llvm
  frr = import ./frr.nix inputs; # requires dataplane
}
