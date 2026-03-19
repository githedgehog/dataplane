# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
inputs@{ ... }:
let
  # Only forward arguments that default.nix accepts, ignoring extras injected by nix-shell.
  filtered = builtins.intersectAttrs (builtins.functionArgs (import ./default.nix)) inputs;
in
(import ./default.nix filtered).devenv
