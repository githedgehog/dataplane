# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  sanitizers,
  target,
  profile,
}:
{
  dataplane = import ./dataplane.nix {
    inherit
      sources
      sanitizers
      target
      profile
      ;
  };
}
