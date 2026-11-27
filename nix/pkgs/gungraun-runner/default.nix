# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  fetchCrate,
  rustPlatform,
  version,
  ...
}:
rustPlatform.buildRustPackage (final: {
  pname = "gungraun-runner";
  inherit version;
  src = fetchCrate {
    inherit (final) pname version;
    hash = "sha256-XZHnq0t5XI/lSAdtP0UYxcaaV/YVZOmT/E7YQWX7jOU=";
  };
  cargoHash = "sha256-nYOFsVAuLw13XObUO4mS4edlv5N/BSHRYPPS1N7y0Os=";
  doCheck = false;
})
