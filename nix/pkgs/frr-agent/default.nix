{
  sources,
  rustPlatform,
  ...
}:
rustPlatform.buildRustPackage (final: {
  pname = "frr-agent";
  version = sources.frr-agent.revision;
  src = sources.frr-agent.outPath;
  cargoLock = {
    lockFile = final.src + "/Cargo.lock";
  };
})
