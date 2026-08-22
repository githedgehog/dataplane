# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
#
# The binary half of iai-callgrind: the `#[library_benchmark]` harness in a bench target shells
# out to this to drive valgrind and read the results back.
#
# `version` must equal the `iai-callgrind` version in `Cargo.toml`. The library refuses to run
# against a runner of a different version, and says so clearly, so a mismatch is loud rather than
# subtly wrong -- but it is still a second place to edit when bumping.
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
  # The runner's own test suite wants a valgrind install and sample outputs it does not ship.
  doCheck = false;
})
