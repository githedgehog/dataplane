# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  platform ? "x86-64-v3",
  libc ? "gnu",
  profile ? "debug",
  instrumentation ? "none",
  sanitize ? "",
  tag ? "latest",
}@inputs:
(import ./default.nix inputs).devenv
