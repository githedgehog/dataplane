{
  src,
  rustPlatform,
}:
rustPlatform.buildRustPackage (final: {
  pname = "kopium";
  version = src.version;
  src = src.outPath;
  cargoLock.lockFile = "${final.src}/Cargo.lock";
  doCheck = false;
})
