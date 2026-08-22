# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  fetchCrate,
  rustPlatform,
  version,
  ...
}:
rustPlatform.buildRustPackage (final: {
  pname = "iai-callgrind-runner";
  inherit version;
  src = fetchCrate {
    inherit (final) pname version;
    hash = "sha256-wJTwaqAz8GWCJ/l9GRXYBVBkpPYrWxN4VQ7GdRFXmzM=";
  };
  cargoHash = "sha256-4N7P23bCeeJee/Cm3sSORByh+HzflOENqYqpu629mpA=";
  doCheck = false;
})
