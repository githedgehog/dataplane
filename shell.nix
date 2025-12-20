# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
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
