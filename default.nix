# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  platform ? "x86-64-v3",
  libc ? "gnu",
  profile ? "debug",
  instrumentation ? "none",
  sanitize ? "",
}:
let
  sources = import ./npins;
  # helper method to work around nix's contrived builtin string split function.
  split-str =
    split-on: string:
    if string == "" then
      [ ]
    else
      builtins.filter (elm: builtins.isString elm) (builtins.split split-on string);
  lib = (import sources.nixpkgs { }).lib;
  platform' = import ./nix/platforms.nix {
    inherit lib platform libc;
  };
  sanitizers = split-str ",+" sanitize;
  profile' = import ./nix/profiles.nix {
    inherit sanitizers instrumentation profile;
    inherit (platform') arch;
  };
  cargo-profile =
    {
      "debug" = "dev";
      "release" = "release";
    }
    .${profile};
  overlays = import ./nix/overlays {
    inherit
      sources
      sanitizers
      ;
    profile = profile';
    platform = platform';
  };
  dev-pkgs = import sources.nixpkgs {
    overlays = [
      overlays.rust
      overlays.llvm
      overlays.dataplane-dev
    ];
  };
  pkgs =
    (import sources.nixpkgs {
      overlays = [
        overlays.rust
        overlays.llvm
        overlays.dataplane
      ];
    }).pkgsCross.${platform'.info.nixarch};
in
{
  profile = profile';
  platform = platform';

}
