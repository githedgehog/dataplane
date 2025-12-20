# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  overlay ? "dataplane",
  target ? "x86_64-unknown-linux-gnu",
  prof ? "debug",
  instrumentation ? "none",
  sanitize ? "",
  sources ? import ./npins,
  pkgs ? import <nixpkgs> { },
}:
(pkgs.buildFHSEnv {
  name = "dataplane-shell";
  targetPkgs =
    pkgs:
    (with pkgs; [
      # dev tools
      bash
      direnv
      just
      nil
      nixd
      npins
      wget
    ]);
}).env
