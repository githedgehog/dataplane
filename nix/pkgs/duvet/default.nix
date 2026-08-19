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
  cargoBuildFlags = [
    "--package"
    "duvet"
  ];
  doCheck = false;
  preBuild = ''
    mkdir -p duvet/www/public
    cp ${./viewer-stub.js} duvet/www/public/script.js
  '';
})
