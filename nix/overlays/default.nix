# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  env ? { },
}:
{
  dataplane = import ./dataplane.nix {
    inherit sources env;
  };
}
