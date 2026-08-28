# The fork adds the Cargo.lock required by buildRustPackage; update it through scripts/gen-pins.sh.
{
  src,
  rustPlatform,
  pkg-config,
  openssl,
  ...
}:
rustPlatform.buildRustPackage (final: {
  pname = "duvet";
  version = (builtins.fromTOML (builtins.readFile "${final.src}/duvet/Cargo.toml")).package.version;
  src = src.outPath;
  cargoLock.lockFile = "${final.src}/Cargo.lock";
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];
  # Exclude xtask: its test driver requires network access.
  cargoBuildFlags = [
    "--package"
    "duvet"
  ];
  # Upstream tests fetch specifications from the network.
  doCheck = false;
  # The stub satisfies an include_str! for an untracked Node artifact. It disables the HTML viewer;
  # JSON, snapshot, and LCOV reports are unaffected.
  preBuild = ''
    mkdir -p duvet/www/public
    cp ${./viewer-stub.js} duvet/www/public/script.js
  '';
})
