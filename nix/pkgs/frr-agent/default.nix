{
  sources,
  rustPlatform,
  nukeReferences,
  libgcc,
  stdenv,
  ...
}:
rustPlatform.buildRustPackage (final: {
  pname = "frr-agent";
  version = sources.frr-agent.revision;
  src = sources.frr-agent.outPath;
  nativeBuildInputs = [ nukeReferences ];
  cargoLock = {
    lockFile = final.src + "/Cargo.lock";
  };
  fixupPhase = ''
    find "$out" -exec nuke-refs -e "$out" -e "${stdenv.cc.libc}" -e "${libgcc.lib}" '{}' +;
  '';
})
