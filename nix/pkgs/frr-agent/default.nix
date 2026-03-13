{
  sources,
  rustPlatform',
  nukeReferences,
  libgcc,
  stdenv,
  ...
}:
rustPlatform'.buildRustPackage (final: {
  pname = "frr-agent";
  version = sources.frr-agent.revision;
  src = sources.frr-agent.outPath;
  nativeBuildInputs = [ nukeReferences ];
  cargoLock = {
    lockFile = final.src + "/Cargo.lock";
  };
  env = {
    RUSTC_BOOTSTRAP = "1";
  };
  cargoBuildFlags = [
    "-Zunstable-options"
    "-Zbuild-std=compiler_builtins,core,alloc,std,panic_unwind,panic_abort,sysroot,unwind"
    "-Zbuild-std-features=backtrace,panic-unwind,mem,compiler-builtins-mem"
  ];
  fixupPhase = ''
    find "$out" -exec nuke-refs -e "$out" -e "${stdenv.cc.libc}" -e "${libgcc.lib}" '{}' +;
  '';
})
