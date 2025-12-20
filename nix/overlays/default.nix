# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  sources,
  sanitizers,
  env,
}:
{
  dataplane = import ./dataplane.nix {
    inherit sources sanitizers env;
  };
}
