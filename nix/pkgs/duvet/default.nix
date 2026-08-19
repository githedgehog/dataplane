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
# Taken from the published crate rather than the git tag, deliberately. duvet embeds
# `www/public/script.js` with `include_str!`, and that file is a JavaScript build product: it is
# absent from the git tree and present in the crate. Building from the tag would mean carrying a
# node toolchain and a second lockfile to produce a file the crate already ships. The crate also
# carries the `Cargo.lock` the git tree omits, so the dependency set is pinned upstream instead of
# by us.
#
# The cost of that choice is that the pin is a plain URL, so npins cannot discover new versions:
# bumping duvet means editing the version in npins/sources.json by hand.
{
  src,
  rustPlatform,
  pkg-config,
  openssl,
  ...
}:
rustPlatform.buildRustPackage (final: {
  pname = "duvet";
  version = "0.4.2";
  src = src.outPath;
  cargoLock.lockFile = "${final.src}/Cargo.lock";
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];
  # Upstream's tests reach the network to fetch the specifications they exercise.
  doCheck = false;
})
