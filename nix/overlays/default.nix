# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  sanitizers,
  platform,
  profile,
}:
{
  llvm = import ./llvm.nix {
    inherit sources;
  };

  dataplane = import ./dataplane.nix {
    inherit
      sources
      sanitizers
      platform
      profile
      ;
  };

  dataplane-dev = import ./dataplane-dev.nix {
    inherit sources;
  };
}
