# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
inputs@{
  platform,
  profile,
  ...
}:
{
  llvm = import ./llvm.nix inputs; # requires rust
}
