# duvet: specification compliance coverage.
#
# Parses a specification into its individual requirements and matches them against citations left
# in the source -- `//= <url>` followed by the requirement's text, quoted -- so that a requirement
# with no implementation, or an implementation with no test, becomes visible.
#
# It answers the question neither bolero nor cargo-mutants can. Bolero says a property holds;
# cargo-mutants says enough properties exist that nothing goes unasserted; neither can say the
# properties are the ones the specification asked for. See development/code/mutation-testing.md.
#
# Built from our fork's `v0.4.3-hh` branch: upstream's v0.4.3 release commit plus the `Cargo.lock`
# that tree ignores. Upstream ships a lockfile in the published crate and nowhere else, and
# `buildRustPackage` needs one in the tree, so a crate pin was the only way to build this without
# the branch -- and a crate pin is a plain URL, which npins can neither discover nor update. The
# branch puts duvet under the same pin discipline as every other fork we build; see
# scripts/gen-pins.sh.
{
  src,
  rustPlatform,
  pkg-config,
  openssl,
  ...
}:
rustPlatform.buildRustPackage (final: {
  pname = "duvet";
  # Read rather than repeated: the branch name already says which release this is, and a second
  # copy of the version is a second thing to keep true.
  version = (builtins.fromTOML (builtins.readFile "${final.src}/duvet/Cargo.toml")).package.version;
  src = src.outPath;
  cargoLock.lockFile = "${final.src}/Cargo.lock";
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];
  # The workspace also holds `xtask`, which is upstream's test driver and reaches the network.
  cargoBuildFlags = [
    "--package"
    "duvet"
  ];
  # Upstream's tests reach the network to fetch the specifications they exercise.
  doCheck = false;
  # `report/html.rs` pulls `duvet/www/public/script.js` in with `include_str!`, and that file is a
  # node build product kept out of git, so the crate will not compile without something at that
  # path. Nothing else in duvet reads it -- `--json`, the snapshot and lcov are written by their
  # own code -- so a stub costs the browsable report and no measurement.
  preBuild = ''
    mkdir -p duvet/www/public
    cp ${./viewer-stub.js} duvet/www/public/script.js
  '';
})
