# Install a prebuilt opengrep binary from upstream GitHub releases.  The
# project ships statically-linked musllinux / manylinux binaries per release;
# we fetch the manylinux build and patch its interpreter so it runs in our
# dev shell and CI environments.
#
# Versioning: the tag name (e.g. "v1.19.0") comes from the npins `opengrep`
# pin. The release asset is a raw ELF binary (no archive), which npins' tarball
# pin type rejects, so the binary's content hash is carried in ./binary.sri and
# is refreshed by scripts/bump.sh on every `just bump pins`.
#
# The pin is currently frozen at v1.33.1: v2.0.0 renamed the release assets
# (no more manylinux build), and its Rust parser fails on syntax we use (async
# closures, &raw pointers, associated type bounds), silently skipping parts of
# the affected files. Unfreeze with `npins unfreeze opengrep`.
{
  stdenvNoCC,
  fetchurl,
  autoPatchelfHook,
  lib,
  src,
}:
stdenvNoCC.mkDerivation {
  pname = "opengrep";
  # src.version carries the tag (e.g. "v1.19.0"); strip the leading "v" so
  # the derivation name reads as a plain version.
  version = lib.removePrefix "v" src.version;

  src = fetchurl {
    url = "https://github.com/opengrep/opengrep/releases/download/${src.version}/opengrep_manylinux_x86";
    hash = lib.removeSuffix "\n" (builtins.readFile ./binary.sri);
  };

  dontUnpack = true;
  dontStrip = true;
  dontConfigure = true;
  dontBuild = true;

  nativeBuildInputs = [ autoPatchelfHook ];

  installPhase = ''
    runHook preInstall
    install -Dm755 $src $out/bin/opengrep
    runHook postInstall
  '';

  meta = {
    description = "Open-source fork of Semgrep for pattern-based static analysis";
    homepage = "https://github.com/opengrep/opengrep";
    license = lib.licenses.lgpl21;
    mainProgram = "opengrep";
    platforms = [ "x86_64-linux" ];
  };
}
