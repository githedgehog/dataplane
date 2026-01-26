# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
inputs@{
  sources,
  platform,
  profile,
  sanitizers,
  ...
}:
{
  llvm = import ./llvm.nix inputs; # requires rust
  dataplane-dev = import ./dataplane-dev.nix inputs; # requires llvm
  dataplane = import ./dataplane.nix inputs; # requires llvm
  frr = import ./frr.nix inputs; # requires dataplane
}
