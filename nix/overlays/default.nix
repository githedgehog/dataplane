# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
inputs@{
  sources,
  platform,
  profile,
  ...
}:
{
  llvm = import ./llvm.nix inputs; # requires rust
  dataplane-dev = import ./dataplane-dev.nix inputs; # requires llvm
}
