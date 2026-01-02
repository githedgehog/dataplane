# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
inputs@{
  sources,
  ...
}:
{
  rust = import sources.rust-overlay;
  llvm = import ./llvm.nix inputs; # requires rust
  dataplane = import ./dataplane.nix inputs; # requires llvm
  dataplane-dev = import ./dataplane-dev.nix inputs; # requires llvm
}
