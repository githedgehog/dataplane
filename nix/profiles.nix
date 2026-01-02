# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  profile,
}:
let
  combine-profiles =
    features:
    builtins.foldl' (
      acc: element: acc // (builtins.mapAttrs (var: val: (acc.${var} or [ ]) ++ val) element)
    ) { } features;
  profile-map = {
    debug = combine-profiles [
    ];
    release = combine-profiles [
    ];
  };
in
combine-profiles [
  profile-map."${profile}"
]
